# ResupplyPair exchangeRate=0 Undercollateralized Stablecoin Borrowing ACT

## Incident Overview TL;DR

An unprivileged EOA on Ethereum mainnet exploited a lending pair built on top of an ERC4626 vault and a BasicVaultOracle by forcing the pair’s stored exchange rate to zero and then borrowing 10,000,000 units of a Stablecoin against only one vault share of collateral. The attacker immediately swapped the minted Stablecoin through Curve and Uniswap into USDC and WETH, draining protocol and LP liquidity and leaving a large, persistently undercollateralized Stablecoin debt position on-chain.

The root cause is a protocol-level oracle and solvency bug in the ResupplyPair + Vault system. BasicVaultOracle::getPrices(Vault) can return a price (2e36 in the observed trace) that causes ResupplyPair._updateExchangeRate() to compute `exchangeRate = 1e36 / price = 0` via integer division. The ResupplyPair isSolvent check then uses this zero exchange rate in its LTV calculation, which always reports borrowers as solvent regardless of their actual collateral. This design allows any unprivileged user to borrow arbitrarily large amounts of Stablecoin against minimal vault-share collateral whenever the oracle output drives the exchangeRate computation to zero.

This behavior is realized as a concrete anyone-can-take (ACT) opportunity at Ethereum mainnet block 22,785,461. The attacker’s three-transaction sequence b consists of one contract-creation seed transaction and two follow-up swap transactions, all sent from the same EOA, and yields a net profit of 1,209.292485673373040194 ETH (after gas) plus 2,616,156.705369 USDC, while victim pools lose 2,421.550032848028703971 ETH and 9,806,396.552565 USDC.

## Key Background

The protocol under analysis is a Resupply lending pair deployed on Ethereum mainnet, integrated with an ERC4626 vault, an external BasicVaultOracle, a ResupplyRegistry, and an externally traded Stablecoin:

- **ResupplyPair 0x6e90c85a495d54c6d7E1f3400FEF1f6e59f86bd6**  
  Verified Solidity source (ResupplyPair.sol and ResupplyPairCore.sol) shows a lending pair that accepts collateral either as vault shares (`addCollateralVault(uint256,address)`) or as underlying tokens (`addCollateral(uint256,address)`), and allows borrowing via `borrow(uint256,uint256,address)`. Borrowing mints Stablecoin through `IResupplyRegistry.mint` and is guarded by an `isSolvent` modifier that relies on a stored exchange rate `exchangeRateInfo.exchangeRate` to compute an LTV-style solvency metric.

- **Vault 0x01144442fba7adccb5c9dc9cf33dd009d50a9e1d**  
  A Vyper ERC4626-style vault (“Vault”) used as collateral. Its implementation includes standard protections such as DEAD_SHARES and MIN_ASSETS in `deposit`, `mint`, `convertToShares`, and `convertToAssets`. These are designed to prevent trivial first-deposit inflation attacks inside the vault itself. In this incident, the vault behaves correctly and its internal invariants are not broken; instead, the lending pair misinterprets vault shares via an external oracle.

- **BasicVaultOracle configuration**  
  ResupplyPair’s `exchangeRateInfo.oracle` is configured to point at a BasicVaultOracle that prices the collateral vault. In the seed transaction trace, `BasicVaultOracle::getPrices(Vault)` returns a very large price of approximately 2e36. ResupplyPair `_updateExchangeRate()` then computes `exchangeRate = 1e36 / price` using integer division. With price = 2e36, the result is `exchangeRate = 0`. The pair emits an `UpdateExchangeRate(exchangeRate: 0)` event and writes `exchangeRateInfo.exchangeRate = 0` to storage immediately before the borrow.

- **Solvency check via `isSolvent`**  
  In ResupplyPairCore, `_isSolvent` and the `isSolvent` modifier compute a borrower’s LTV using `exchangeRateInfo.exchangeRate`. When this exchange rate is zero, the computed LTV becomes zero for any non-zero borrower amount and collateral, so the solvency check always passes as long as `maxLTV` is non-zero. The design assumes that the oracle-derived exchange rate will be a meaningful, non-zero representation of collateral value and does not guard against the zero case.

- **Stablecoin and ResupplyRegistry**  
  The Stablecoin 0x57ab1e0003f623289cd798b1824be09a793e4bec is minted via `ResupplyRegistry::mint` on behalf of ResupplyPair borrowers and is transferrable and freely tradable on-chain. In the seed transaction, ResupplyRegistry mints exactly `1e25` Stablecoin (10,000,000 units) to the attacker’s helper contract, which then routes these tokens through Curve and Uniswap pools into USDC and WETH addresses controlled by the adversary cluster.

The pre-state σ_B is defined as Ethereum mainnet (chainid 1) immediately before block 22,785,461, reconstructed from QuickNode `debug_traceTransaction` PrestateTracer outputs for the seed transaction and associated balance diffs. Evidence includes:

- `artifacts/root_cause/seed/1/0xffbbd4.../metadata.json`
- `artifacts/root_cause/seed/1/0xffbbd4.../trace.cast.log`
- `artifacts/root_cause/data_collector/iter_1/state_diff/1/0xffbbd4.../prestateTracer_diff.json`
- `artifacts/root_cause/data_collector/iter_1/state_diff/1/0xffbbd4.../prestateTracer_focus.json`
- `artifacts/root_cause/data_collector/iter_1/balance_diff/1/0xffbbd4.../balance_diff_prestate.json`

All ACT reasoning is grounded in this reconstructed pre-state and these on-chain artifacts.

## Vulnerability Analysis

### Core Bug: Oracle-Driven Zero Exchange Rate

The central vulnerability is in how ResupplyPair computes and uses its collateral exchange rate. ResupplyPairCore implements `_updateExchangeRate()` as:

```solidity
function _updateExchangeRate()
    internal
    returns (uint256 _exchangeRate)
{
    // Pull from storage to save gas and set default return values
    ExchangeRateInfo memory _exchangeRateInfo = exchangeRateInfo;

    // Get the latest exchange rate from the oracle
    // convert price of collateral as debt is priced in terms of collateral amount (inverse)
    _exchangeRate = 1e36 / IOracle(_exchangeRateInfo.oracle).getPrices(address(collateral));

    // skip storage writes if value doesnt change
    if (_exchangeRate != _exchangeRateInfo.exchangeRate) {
        _exchangeRateInfo.lastTimestamp = uint96(block.timestamp);
        _exchangeRateInfo.exchangeRate = _exchangeRate;
        exchangeRateInfo = _exchangeRateInfo;
        emit UpdateExchangeRate(_exchangeRate);
    }
}
```

There is no guard against the oracle returning a price that makes `1e36 / price` truncate to zero. In the incident, BasicVaultOracle returns a price of approximately `2e36`, so the computed exchange rate is exactly zero and is persisted to storage and emitted via `UpdateExchangeRate`.

The solvency check uses this stored exchange rate:

```solidity
function _isSolvent(address _borrower, uint256 _exchangeRate) internal view returns (bool) {
    uint256 _maxLTV = maxLTV;
    if (_maxLTV == 0) return true;
    uint256 _borrowerAmount = totalBorrow.toAmount(_userBorrowShares[_borrower], true);
    if (_borrowerAmount == 0) return true;

    uint256 _collateralAmount = _userCollateralBalance[_borrower];
    if (_collateralAmount == 0) return false;

    uint256 _ltv = ((_borrowerAmount * _exchangeRate * LTV_PRECISION) / EXCHANGE_PRECISION) / _collateralAmount;
    return _ltv <= _maxLTV;
}

modifier isSolvent(address _borrower) {
    _syncUserRedemptions(_borrower);
    _;
    ExchangeRateInfo memory _exchangeRateInfo = exchangeRateInfo;

    if (!_isSolvent(_borrower, _exchangeRateInfo.exchangeRate)) {
        revert Insolvent(
            totalBorrow.toAmount(_userBorrowShares[_borrower], true),
            _userCollateralBalance[_borrower],
            _exchangeRateInfo.exchangeRate
        );
    }
}
```

With `_exchangeRate = 0`, the LTV `_ltv` becomes zero for any positive `_borrowerAmount` and `_collateralAmount`, so the `isSolvent` check cannot fail as long as `maxLTV` is non-zero. In other words, any borrower appears solvent, regardless of how large their debt is relative to their collateral.

### Vulnerable Components

The vulnerable components identified in the analysis are:

- **ResupplyPair lending pair 0x6e90c85a495d54c6d7E1f3400FEF1f6e59f86bd6**  
  Specifically, `_updateExchangeRate` and `isSolvent` in ResupplyPairCore.sol, which compute `exchangeRateInfo.exchangeRate = 1e36 / price` from BasicVaultOracle and then use this value directly in `_isSolvent` without checking for zero.

- **BasicVaultOracle configuration for Vault 0x01144442fba7adccb5c9dc9cf33dd009d50a9e1d**  
  The oracle returns a price of roughly `2e36` in the observed trace (`getPrices(Vault)`), which makes `1e36 / price` truncate to zero when evaluated as integer division inside the pair.

- **ResupplyRegistry and Stablecoin 0x57ab1e0003f623289cd798b1824be09a793e4bec**  
  These contracts mint and distribute 10,000,000 Stablecoin to the attacker’s helper contract when `borrow(1e25, 0, helper)` is called, relying solely on ResupplyPair’s `isSolvent` check and not enforcing independent collateral or risk limits.

- **Vault–lending pair integration**  
  The lending pair assumes that an oracle-derived exchange rate will always be non-zero and economically sensible, and it does not protect against the case where the oracle output leads to a zero exchange rate. The vault itself correctly enforces its own invariants (e.g., MIN_ASSETS, DEAD_SHARES), but the integration layer fails to verify collateral value before allowing large borrows.

### Security Principles Violated

The incident violates several key security principles:

- **Lending solvency and collateralization invariants**: The system permits a borrower with only one vault share (backed by approximately 2e18 units of the underlying) to incur a 10,000,000 Stablecoin debt because the solvency check uses an exchange rate of zero derived from the oracle.

- **Oracle safety and range-checking**: The integration assumes that `BasicVaultOracle::getPrices(Vault)` will return a value that yields a meaningful, non-zero `exchangeRate` when used in `1e36 / price`, but never enforces bounds or handles the truncation-to-zero case.

- **Defense-in-depth around collateral valuation**: ResupplyPair depends entirely on a single oracle-derived exchange rate and does not implement fallback checks such as minimum absolute collateral, per-asset borrowing caps, or explicit rejection when `exchangeRateInfo.exchangeRate` is zero.

- **Separation of responsibilities between vaults and lending pairs**: The Vault enforces local invariants correctly; the bug arises because the lending pair treats vault shares as collateral without independently verifying their economic value, exposing a cross-contract risk surface that the attacker exploits.

## Detailed Root Cause Analysis

### Contract and Trace Evidence

The seed transaction is:

- **Seed tx (b[1])**: `0xffbbd492e0605a8bb6d490c3cd879e87ff60862b0684160d08fd5711e7a872d3`  
  - Chain: Ethereum mainnet (chainid 1)  
  - Block: 22,785,461  
  - Type: Adversary-crafted contract-creation transaction from EOA 0x6d9f6e900ac2ce6770fd9f04f98b7b0fc355e2ea (nonce 0), which deploys helper contract 0xf90da523a7c19a0a3d8d4606242c46f1ee459dc7.

The seed trace (`trace.cast.log`) shows the following critical sequence inside the helper:

```text
... BasicVaultOracle::getPrices(Vault: [0x01144442fba7aDccB5C9DC9cF33dd009D50A9e1D]) ...
    └─ ← [Return] 2000000000000000000001998001998001998 [2e36]
    └─ ← [Return] 2000000000000000000001998001998001998 [2e36]
    └─ ← [Return] 2000000000000000000001998001998001998 [2e36]
├─ emit UpdateExchangeRate(exchangeRate: 0)
```

This confirms that BasicVaultOracle returns a value on the order of 2e36, and `_updateExchangeRate()` computes and stores `exchangeRate = 1e36 / 2e36 = 0`, emitting an `UpdateExchangeRate(exchangeRate: 0)` event.

The trace and vault source code also show:

- A deposit of `2e18` units of the Vault’s underlying asset into Vault 0x0114..., minting exactly one share.
- `ResupplyPair.addCollateralVault(1, helper)` being called to register that single share as collateral.
- `ResupplyPair.borrow(1e25, 0, helper)` being called shortly after `_updateExchangeRate()` has set `exchangeRateInfo.exchangeRate = 0`.
- `ResupplyRegistry::mint` minting `1e25` Stablecoin (10,000,000 units) to the helper contract.

The Vault Vyper source (`source_code.txt`) confirms a standard ERC4626 design with MIN_ASSETS and DEAD_SHARES protecting against trivial first-deposit inflation; the observed 2e18-deposit-for-1-share behavior is consistent with those invariants and is not itself exploitative.

### Sequence of Events in the Seed Transaction

Within the seed transaction, the helper contract executes:

1. **Vault deposit and share minting**  
   - Deposits `2e18` units of underlying into Vault 0x0114..., minting exactly one vault share.  
   - Emits a `Deposit` event from the Vault with `assets = 2000000000000000001 [2e18]` and `shares = 1`.

2. **Adding collateral to ResupplyPair**  
   - Calls `ResupplyPair.addCollateralVault(1, helper)`, which:
     - Syncs interest and reward state, then
     - Calls internal `_addCollateral(msg.sender, 1, helper)`, increasing `_userCollateralBalance[helper]` by 1 share and staking the underlying.

3. **Exchange rate update via oracle**  
   - Just before borrowing, ResupplyPair calls `_updateExchangeRate()`, which invokes `BasicVaultOracle::getPrices(Vault)`.  
   - The oracle returns a price of approximately `2e36`. `_updateExchangeRate()` computes `exchangeRate = 1e36 / price = 0`, updates `exchangeRateInfo.exchangeRate = 0`, and emits `UpdateExchangeRate(exchangeRate: 0)`.

4. **Borrowing Stablecoin with exchangeRate=0**  
   - The helper calls `ResupplyPair.borrow(1e25, 0, helper)`.  
   - The `borrow` function is defined as:

     ```solidity
     function borrow(
         uint256 _borrowAmount,
         uint256 _underlyingAmount,
         address _receiver
     ) external nonReentrant isSolvent(msg.sender) returns (uint256 _shares) {
         if (_receiver == address(0)) revert InvalidReceiver();
         _addInterest();
         _updateExchangeRate();
         if (_underlyingAmount > 0) { ... }
         _shares = _borrow(_borrowAmount.toUint128(), _receiver);
     }
     ```

   - Because `_updateExchangeRate()` has set `exchangeRateInfo.exchangeRate` to zero, the `isSolvent(msg.sender)` modifier reads this zero exchange rate and calls `_isSolvent`. As shown above, `_isSolvent` computes LTV as:

     \[
     \text{ltv} = \frac{\text{borrowerAmount} \times \text{exchangeRate} \times \text{LTV\_PRECISION}}{\text{EXCHANGE\_PRECISION} \times \text{collateralAmount}}
     \]

     With `exchangeRate = 0`, `ltv = 0` for any borrowerAmount and collateralAmount > 0, so the check passes regardless of how large `_borrowAmount` is.

   - `_borrow` then calls `IResupplyRegistry(registry).mint(_receiver, _borrowAmount);`, minting `1e25` Stablecoin to the helper contract.

5. **Swapping Stablecoin into USDC and WETH**  
   - The helper routes the freshly minted 10,000,000 Stablecoin through the configured Curve pool and Uniswap V3 pool.  
   - PrestateTracer `balance_diff_prestate.json` for the seed transaction records:
     - WETH9 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 losing `2,421.550032848028703971` ETH.
     - Curve pool 0x4dece678ceceb27446b35c672dc7d61f30bad69e losing `9,806,396.552565` USDC (6 decimals).
     - Attacker EOA 0x6d9f6e9... and profit-recipient EOAs 0x886f78... and 0xdadb0d... gaining large amounts of ETH and USDC.

### ACT Opportunity Conditions

The ACT opportunity arises whenever the following on-chain conditions hold:

1. **Oracle returns a large enough price**  
   BasicVaultOracle returns a price for the Vault such that `1e36 / price`, computed with integer division in `_updateExchangeRate()`, equals zero (for example, price ≈ `2e36` as in the seed trace).

2. **Unprivileged access to collateral and borrow functions**  
   Any EOA or helper contract can:
   - Acquire at least one vault share by depositing underlying into Vault 0x0114..., and  
   - Call `addCollateralVault(uint256,address)` on ResupplyPair 0x6e90... to register those shares as collateral, then
   - Call `borrow(uint256,uint256,address)` on ResupplyPair (with `_underlyingAmount` optionally zero) after `_updateExchangeRate()` has set `exchangeRateInfo.exchangeRate = 0`.

3. **Solvency check relies solely on exchangeRate**  
   ResupplyPair’s `isSolvent` modifier uses `exchangeRateInfo.exchangeRate` and does not implement independent sanity checks that would reject borrowing when the exchange rate is zero.

4. **Liquid Stablecoin markets**  
   The Stablecoin minted via `ResupplyRegistry::mint` is liquid on-chain and can be swapped into other assets (USDC and WETH) via public Curve and Uniswap pools, enabling an immediate and realizable profit for any unprivileged actor who exploits the zero exchange rate.

Together, these conditions create a reusable, permissionless ACT opportunity: any unprivileged adversary with only on-chain data and public contract interfaces can replicate the sequence and obtain undercollateralized debt and profit.

## Adversary Flow Analysis

### High-Level Strategy

The adversary uses a three-transaction sequence b:

1. A helper-orchestrated seed transaction that creates an undercollateralized 10,000,000 Stablecoin debt position by exploiting `exchangeRate = 0` in ResupplyPair, and immediately swaps the minted Stablecoin into USDC and WETH, draining liquidity from victim pools.
2. Two follow-up aggregator swaps, sent directly from the attacker EOA, that convert USDC profits into additional ETH and consolidate the attacker’s on-chain gains.

All three transactions are standard Ethereum transactions with ordinary gas and fee parameters; no special inclusion rules, whitelists, or privileged roles are involved.

### Transaction Sequence b

The ACT transaction sequence b is:

1. **b[1] – Seed contract-creation tx (helper deployment and exploit)**  
   - Index: 1  
   - Chainid: 1 (Ethereum mainnet)  
   - Tx hash: `0xffbbd492e0605a8bb6d490c3cd879e87ff60862b0684160d08fd5711e7a872d3`  
   - Type: Adversary-crafted  
   - Inclusion feasibility: An unprivileged EOA on Ethereum mainnet can deploy an arbitrary helper contract that calls public functions on:
     - Vault 0x01144442fba7adccb5c9dc9cf33dd009d50a9e1d  
     - ResupplyPair 0x6e90c85a495d54c6d7E1f3400FEF1f6e59f86bd6  
     - CurveStableSwapNG 0xc522a6606bba746d7960404f22a3db936b6f4f50  
     - Uniswap V3 0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640  
     by sending a contract-creation transaction with sufficient gas and fee. The seed transaction is an ordinary contract-creation tx from 0x6d9f6e9... with nonce 0; no special permissions or inclusion rules are required.
   - Mechanism (notes):  
     - Deploy helper contract 0xf90da5... from the attacker EOA.  
     - Inside the helper, deposit `2e18` units of Vault underlying into Vault 0x0114..., minting exactly one share.  
     - Call `ResupplyPair.addCollateralVault(1, helper)` to register this single share as collateral.  
     - Trigger `ResupplyPair._updateExchangeRate()` such that `BasicVaultOracle::getPrices(Vault)` returns ~`2e36` and `exchangeRateInfo.exchangeRate` is set to 0.  
     - Call `ResupplyPair.borrow(1e25, 0, helper)`, minting 10,000,000 Stablecoin to the helper.  
     - Swap the newly minted Stablecoin through Curve and Uniswap routes into USDC and WETH, draining liquidity from WETH9 and the Curve pool.

2. **b[2] – First follow-up aggregator swap (USDC → ETH)**  
   - Index: 2  
   - Chainid: 1  
   - Tx hash: `0x3bbe4c5218ce7ec7690bc0fec8f738aadb3882db01e38f1544127acc4755c91d`  
   - Type: Adversary-crafted  
   - Inclusion feasibility: The attacker EOA 0x6d9f6e9... sends a routed swap transaction through an on-chain aggregator. The transaction pays standard gas and interacts only with public ERC20 approve and swap functions. It appears in Etherscan txlists with ordinary gas and fee parameters and is consistent with typical aggregator flows.
   - Mechanism (notes):  
     - Converts part of the attacker’s USDC into additional ETH.  
     - PrestateTracer `balance_diff_prestate.json` for 0x3bbe4c52... shows:
       - Attacker EOA native balance increasing by `203.312642192789875876` ETH.  
       - Attacker EOA USDC balance decreasing by `500,000` USDC (6 decimals).  
     - These values match a profitable USDC→ETH trade funded by the earlier Stablecoin mint.

3. **b[3] – Second follow-up aggregator swap (USDC → ETH)**  
   - Index: 3  
   - Chainid: 1  
   - Tx hash: `0x86fbf64a8633139d0a1a886be50d15e7df3af9e38482cd1d6f45d3455d08b57c`  
   - Type: Adversary-crafted  
   - Inclusion feasibility: Another routed swap sent by the attacker EOA through a public aggregator contract. Gas and fee parameters are standard; any unprivileged searcher could send an identical transaction once the state created by the seed tx is known.
   - Mechanism (notes):  
     - Further converts the attacker’s USDC into ETH.  
     - PrestateTracer `balance_diff_prestate.json` for 0x86fbf64a... shows:
       - Attacker EOA native balance increasing by `202.432959776886285839` ETH.  
       - Attacker EOA USDC balance decreasing by an additional `500,000` USDC.  
     - Together with the seed transaction, these swaps complete a deterministic 3-step ACT sequence.

### Adversary-Related Accounts

The adversary cluster consists of the following addresses:

- **Attacker EOA – 0x6d9f6e900ac2ce6770fd9f04f98b7b0fc355e2ea**  
  - Chain: Ethereum mainnet (chainid 1)  
  - EOA (is_eoa = true, is_contract = false)  
  - Sender of the seed transaction 0xffbbd4... and both follow-up swaps 0x3bbe4c52... and 0x86fbf64a....  
  - PrestateTracer balance diffs across the three transactions show this EOA gaining `1,209.292485673373040194` ETH and `2,616,156.705369` USDC.  
  - Etherscan txlists confirm it pays gas and directly interacts with the helper contract and swap aggregators.

- **Helper contract – 0xf90da523a7c19a0a3d8d4606242c46f1ee459dc7**  
  - Chain: Ethereum mainnet (chainid 1)  
  - Contract (is_eoa = false, is_contract = true)  
  - Deployed by the attacker EOA in the seed transaction.  
  - Executes `Vault.deposit`, `ResupplyPair.addCollateralVault`, `ResupplyPair.borrow`, `ResupplyRegistry.mint`, and subsequent swaps.  
  - Holds no special privileges beyond being the borrower and caller of public entrypoints; it is an adversary-controlled orchestrator contract.

- **Profit-recipient EOA – 0x886f786618623fffb2be59830a47661ae6492e16**  
  - Chain: Ethereum mainnet (chainid 1)  
  - EOA (is_eoa = true, is_contract = false)  
  - PrestateTracer native_balance_deltas for the seed transaction show:
    - `before_wei = 0`  
    - `after_wei = 1,607.700021898685802647` ETH  
    - `delta_wei = 1,607.700021898685802647` ETH  
  - This ETH is funded by WETH9’s `-2,421.550032848028703971` ETH delta.  
  - The address appears in the attacker’s helper contract storage and receives a large ETH transfer during the exploit. Txlist inspection over the incident window shows no unrelated activity. It is therefore treated as an immediate profit-recipient address within the adversary cluster.

- **Profit-recipient EOA – 0xdadb0d80178819f2319190d340ce9a924f783711**  
  - Chain: Ethereum mainnet (chainid 1)  
  - EOA (is_eoa = true, is_contract = false)  
  - PrestateTracer native_balance_deltas show:
    - `+10.29742425` ETH delta in the seed transaction, funded by WETH9.  
    - An additional small positive ETH delta in the first follow-up swap 0x3bbe4c52....  
  - It does not appear as a protocol or infrastructure contract in the collected artifacts. Based on these direct exploit-related value flows, it is classified as an adversary profit-recipient address within the attack cluster.

### Victim Candidates

The victim-side ecosystem includes:

- **ResupplyPair lending pair**  
  - Chain: Ethereum mainnet (chainid 1)  
  - Address: 0x6e90c85a495d54c6d7E1f3400FEF1f6e59f86bd6  
  - Verified source: true  
  - Lending pair whose solvency logic is exploited through `exchangeRateInfo.exchangeRate = 0`.

- **Vault (ERC4626 collateral)**  
  - Chain: Ethereum mainnet (chainid 1)  
  - Address: 0x01144442fba7adccb5c9dc9cf33dd009d50a9e1d  
  - is_verified: unknown (verification status on explorers is not used in the root-cause reasoning; behavior is established from retrieved source).

- **Stablecoin minted via ResupplyRegistry**  
  - Chain: Ethereum mainnet (chainid 1)  
  - Address: 0x57ab1e0003f623289cd798b1824be09a793e4bec  
  - Verified source: true  
  - Minted in the amount of `1e25` units to the helper contract during the exploit.

- **Curve crvUSD-related pool draining USDC**  
  - Chain: Ethereum mainnet (chainid 1)  
  - Address: 0x4dece678ceceb27446b35c672dc7d61f30bad69e  
  - Verified source: true  
  - Loses `9,806,396.552565` USDC during the seed transaction.

- **WETH9**  
  - Chain: Ethereum mainnet (chainid 1)  
  - Address: 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2  
  - Verified source: true  
  - Loses `2,421.550032848028703971` ETH during the seed transaction.

### Adversary Lifecycle Stages

The analysis decomposes the adversary flow into three stages:

1. **Stage 1 – Helper deployment and undercollateralized borrow**  
   - Tx: 0xffbbd4... (seed) at block 22,785,461, mechanism `contract_deploy_and_borrow`.  
   - Actions:
     - Attacker EOA deploys helper contract 0xf90da5....  
     - Helper deposits `2e18` units of Vault underlying to mint one share.  
     - Helper calls `ResupplyPair.addCollateralVault(1, helper)` to add that share as collateral.  
     - ResupplyPair calls `_updateExchangeRate()`, `BasicVaultOracle::getPrices(Vault)` returns ~2e36, and `exchangeRateInfo.exchangeRate` is set to 0, emitting `UpdateExchangeRate(exchangeRate: 0)`.  
     - Helper calls `ResupplyPair.borrow(1e25, 0, helper)`; `isSolvent` passes because the exchange rate is zero, and the protocol mints 10,000,000 Stablecoin to the helper.  
     - Helper immediately swaps the minted Stablecoin through Curve and Uniswap pools, leading to large USDC and WETH outflows from victim pools and large inflows to EOA and profit addresses in the adversary cluster.  
   - Evidence:
     - `artifacts/root_cause/seed/1/0xffbbd4.../trace.cast.log`  
     - ResupplyPairCore.sol and Vault source code  
     - `artifacts/root_cause/data_collector/iter_1/balance_diff/1/0xffbbd4.../balance_diff_prestate.json`

2. **Stage 2 – First follow-up swap (USDC to ETH)**  
   - Tx: 0x3bbe4c5218ce7ec7690bc0fec8f738aadb3882db01e38f1544127acc4755c91d at block 22,785,473, mechanism `swap`.  
   - Actions:
     - Attacker EOA uses a swap aggregator to convert 500,000 USDC into additional ETH.  
   - Evidence:
     - `artifacts/root_cause/data_collector/iter_2/tx/1/0x3bbe4c52.../trace.cast.log`  
     - `artifacts/root_cause/data_collector/iter_2/balance_diff/1/0x3bbe4c52.../balance_diff_prestate.json`, which shows:
       - Attacker EOA ETH balance increasing by `203.312642192789875876` ETH.  
       - Attacker EOA USDC balance decreasing by `500,000` USDC.

3. **Stage 3 – Second follow-up swap (USDC to ETH)**  
   - Tx: 0x86fbf64a8633139d0a1a886be50d15e7df3af9e38482cd1d6f45d3455d08b57c at block 22,785,503, mechanism `swap`.  
   - Actions:
     - Attacker EOA performs another aggregator swap, converting an additional 500,000 USDC into ETH.  
   - Evidence:
     - `artifacts/root_cause/data_collector/iter_2/tx/1/0x86fbf64a.../trace.cast.log`  
     - `artifacts/root_cause/data_collector/iter_2/balance_diff/1/0x86fbf64a.../balance_diff_prestate.json`, which shows:
       - Attacker EOA ETH balance increasing by `202.432959776886285839` ETH.  
       - Attacker EOA USDC balance decreasing by `500,000` USDC.

## Impact & Losses

### On-Chain Profit in ETH (Reference Asset)

The ACT success predicate is defined as a profit condition for the attacker EOA in ETH:

- **Reference asset**: ETH  
- **Adversary address**: 0x6d9f6e900ac2ce6770fd9f04f98b7b0fc355e2ea  

From the PrestateTracer artifacts:

- **Value before** (`value_before_in_reference_asset`):  
  - The attacker’s pre-seed native ETH balance is derived from `before_wei` in `native_balance_deltas` for the address 0x6d9f6e9... in `artifacts/root_cause/data_collector/iter_1/balance_diff/1/0xffbbd4.../balance_diff_prestate.json`.  
  - This corresponds to `0.993291946878350000` ETH.

- **Value delta** (`value_delta_in_reference_asset`):  
  - The sum of ETH native-balance deltas for 0x6d9f6e9... across the three adversary-crafted transactions:
    - Seed tx 0xffbbd4...: `+803.546883703696878479` ETH  
    - First follow-up 0x3bbe4c52...: `+203.312642192789875876` ETH  
    - Second follow-up 0x86fbf64a...: `+202.432959776886285839` ETH  
  - Total: `1,209.292485673373040194` ETH.

- **Value after** (`value_after_in_reference_asset`):  
  - `value_after_in_reference_asset = value_before + value_delta = 0.993291946878350000 + 1,209.292485673373040194 = 1,210.285777620251390194` ETH.

- **Fees paid** (`fees_paid_in_reference_asset`):  
  - Gas fees for the three transactions are computed from `gasUsed * gasPrice` using Etherscan txlist data for the attacker EOA in `artifacts/root_cause/data_collector/iter_2/address/1/0x6d9f6e900ac2ce6770fd9f04f98b7b0fc355e2ea/txlist_22770000-22790000.json`.  
  - The sum is `314,826,573,343,496,077` wei, which is `0.314826573343496077` ETH.

The net ETH profit over the 3-transaction sequence is strictly positive and is already reflected in `value_delta_in_reference_asset`, which incorporates gas payments. The attacker’s ETH holdings increase by `1,209.292485673373040194` ETH while victim pools lose ETH as detailed below.

### Additional Profit in USDC

Beyond ETH, the attacker EOA gains substantial USDC:

- PrestateTracer `erc20_balance_deltas` for the seed and follow-up transactions show that the attacker EOA 0x6d9f6e9... gains a net `2,616,156.705369` USDC (6 decimals).  
- This USDC gain is a direct consequence of the attacker swapping minted Stablecoin into USDC and then partially converting USDC into ETH in follow-up swaps.  
- These USDC profits are not converted into the ETH reference-asset calculation but represent additional on-chain profit.

### Losses to Protocol and Liquidity Providers

The primary victim-side losses, as measured by PrestateTracer balance diffs, are:

- **WETH9 (0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2)**  
  - Native balance delta in the seed transaction: `-2,421.550032848028703971` ETH.

- **Curve crvUSD-related pool (0x4dece678ceceb27446b35c672dc7d61f30bad69e)**  
  - USDC balance delta in the seed transaction: `-9,806,396.552565` USDC.

These losses represent liquidity drained from WETH and USDC pools as the attacker converts undercollateralized Stablecoin into more liquid assets.

The on-chain state also records a large undercollateralized Stablecoin debt:

- The helper’s position in ResupplyPair holds only one vault share as collateral (approximately 2e18 units of the underlying), yet is associated with a 10,000,000 Stablecoin debt minted during the exploit.  
- Because `exchangeRateInfo.exchangeRate` is zero, subsequent solvency checks (in the absence of manual intervention) treat this position as solvent, leaving the protocol with an effectively unbacked debt exposure.

Together, these facts confirm that the incident’s impact is a substantial transfer of value from protocol/LP pools to the attacker cluster, with a large toxic debt position left behind.

## References

- **Seed transaction and pre-state reconstruction**  
  - Seed transaction metadata: `artifacts/root_cause/seed/1/0xffbbd4.../metadata.json`  
  - Seed transaction trace (cast -vvvvv): `artifacts/root_cause/seed/1/0xffbbd4.../trace.cast.log`  
  - PrestateTracer state-diff outputs:
    - `artifacts/root_cause/data_collector/iter_1/state_diff/1/0xffbbd4.../prestateTracer_diff.json`  
    - `artifacts/root_cause/data_collector/iter_1/state_diff/1/0xffbbd4.../prestateTracer_focus.json`  
  - PrestateTracer balance diffs:
    - `artifacts/root_cause/data_collector/iter_1/balance_diff/1/0xffbbd4.../balance_diff_prestate.json`

- **Follow-up transactions and balance diffs**  
  - First swap tx trace: `artifacts/root_cause/data_collector/iter_2/tx/1/0x3bbe4c52.../trace.cast.log`  
  - First swap balance diffs: `artifacts/root_cause/data_collector/iter_2/balance_diff/1/0x3bbe4c52.../balance_diff_prestate.json`  
  - Second swap tx trace: `artifacts/root_cause/data_collector/iter_2/tx/1/0x86fbf64a.../trace.cast.log`  
  - Second swap balance diffs: `artifacts/root_cause/data_collector/iter_2/balance_diff/1/0x86fbf64a.../balance_diff_prestate.json`

- **Attacker EOA tx history and gas costs**  
  - Etherscan-style txlist for attacker EOA 0x6d9f6e9...:  
    - `artifacts/root_cause/data_collector/iter_2/address/1/0x6d9f6e900ac2ce6770fd9f04f98b7b0fc355e2ea/txlist_22770000-22790000.json`

- **Contract source code**  
  - ResupplyPair and ResupplyPairCore (verified Solidity source):  
    - `artifacts/root_cause/data_collector/iter_1/contract/1/0x6e90c85a495d54c6d7e1f3400fef1f6e59f86bd6/source/src/protocol/ResupplyPair.sol`  
    - `artifacts/root_cause/data_collector/iter_1/contract/1/0x6e90c85a495d54c6d7e1f3400fef1f6e59f86bd6/source/src/protocol/pair/ResupplyPairCore.sol`
  - Vault Vyper ERC4626 implementation (collateral vault 0x0114...):  
    - `artifacts/root_cause/data_collector/iter_2/contract/1/0x01144442fba7adccb5c9dc9cf33dd009d50a9e1d/source_code.txt`
  - Additional protocol and pool contracts used as context:
    - crvUSD Controller and Stablecoin: `artifacts/root_cause/data_collector/iter_2/contract/1/0x89707721927d7aaeeee513797a8d6cbbd0e08f41/source_code.txt` and related files  
    - Stablecoin and registry ABIs from `artifacts/root_cause/seed/1/0x57ab1e0003f623289cd798b1824be09a793e4bec/out/*.json`

These references together support the mechanical exploit reconstruction, the ACT classification, and all quantitative impact and profit figures reported above.

