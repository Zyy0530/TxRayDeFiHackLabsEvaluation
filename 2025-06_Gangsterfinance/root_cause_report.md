# Gangster Finance TokenVault Flash-Swap Accounting Exploit (BSC)

## 1. Incident Overview TL;DR

On BSC (chainid 56), an adversary-controlled helper and strategy stack executed two flash-swap-assisted transactions that drained BTCB and BUSD from Gangster Finance TokenVaults. The contracts abused a donate/depositTo/resolve/harvest accounting flaw so that the vaults treated flash-borrowed liquidity as real earnings and principal, then harvested more underlying than any genuine at-risk deposits and routed the net ERC20 profits to EOA `0xc49f2938327aa2cdc3f2f89ed17b54b3671f05de`.

The root cause was a protocol-level accounting bug in the Gangster Finance TokenVault contract. When flash-borrowed tokens were donated and deposited in a single transaction, the vault double-counted them in both the earnings pool and the share-minting logic, allowing harvest to pull out more BTCB or BUSD than the vault's true backing for existing depositors.

This exploit is ACT-positive: the adversary constructed deterministic, unprivileged transactions that realized profit by exploiting a concrete bug in the live protocol code without relying on non-deterministic off-chain behavior.

## 2. Key Background

**Protocol and contracts.** Gangster Finance deployed TokenVault contracts on BSC to manage BTCB and BUSD deposits using a share-based accounting design:
- **BTCB TokenVault** at `0xe968D2E4ADc89609773571301aBeC3399D163c3b`.
- **BUSD TokenVault** at `0xd920Fa5D50a970698bcEA8dD5A9c25b4e62EfaB3`.

The vaults expose the following core functions to external callers:
- `donate(uint _amount)` – move tokens into the vault's drip/earnings pool.
- `depositTo(address _user, uint _amount)` – deposit tokens on behalf of a user and mint vault shares.
- `resolve(uint256 _amount)` – "unstake" vault shares and update internal accounting.
- `harvest()` – realize earnings and withdraw underlying tokens to the caller.

These functions operate on a share-based accounting system: internal `balanceOf_` tracks staked shares, `currentTotalStaked` tracks total shares, `profitPerShare_` encodes cumulative rewards, and the drip pool plus fees feed into per-share earnings.

**Flash swaps on PancakeSwap.** On BSC, PancakeSwap pairs enable flash swap style operations: a caller can take a one-sided borrow of an ERC20 token as part of a `swap` call (with `data` set) and is required to return the borrowed amount plus fees within the same transaction via the callback.

In this incident, the adversary used:
- BTCB pair `0x0b32Ea94DA1F6679b11686eAD47AA4C6bF38cd59` (WBNB/BTCB).
- BUSD pair `0x58f876857a02d6762e0101bb5c46a8c1ed44dc16` (WBNB/BUSD).

**Adversary stack.** The adversary operated:
- EOA `0xc49f2938327aa2cdc3f2f89ed17b54b3671f05de` (sender of both exploit transactions and ultimate profit recipient).
- Helper contracts:
  - `0x982769c5e5dd77f8308E3CD6Eec37dA9d8237dc6` (BTCB exploit helper).
  - `0x95A850fc5377c16CFcd20FD9FaeB907631bb92ab` (BUSD exploit helper).
- Strategy contract `0x268D1581a34FB63dC46C92f07cB0D739517ca51C` (BTCB exploit strategy; an analogous pattern is used in the BUSD path).

The helpers are created in contract-creation transactions from the adversary EOA and immediately deploy and invoke the strategy contract. The strategy is wired to specific vault and pair addresses and encodes the full flash-swap and vault call sequence.

**Pre-state and ACT opportunity.**
- Block height **B** is `51782713` on BSC.
- **Pre-state** \(σ_B\) is the canonical chain state at block `51782712`, immediately before the seed exploit transaction `0xf34e59e4fe2c9b454d2b73a1a3f3aaf07d484a0c71ff8278b1c068cdedc4b64d`.
- Pre-state evidence:
  - Seed index: `artifacts/root_cause/seed/index.json`.
  - Seed metadata: `artifacts/root_cause/seed/56/0xf34e...b64d/metadata.json`.
  - Adversary normal transaction history: `artifacts/root_cause/data_collector/iter_1/address/56/0xc49f...05de/normal_txlist_51780000-51786000.json`.

The exploit transactions are straightforward to include in a canonical chain: they use standard gas and nonce progression, touch only publicly deployed contracts, and operate entirely within the constraints of BSC block `51782713` and `51784234` chain state.

## 3. Vulnerability Analysis

### 3.1 TokenVault accounting behavior

The verified BTCB TokenVault source (`artifacts/root_cause/data_collector/iter_1/contract/56/0xe968...c3b/source/src/Contract.sol`) defines the core write functions as follows (excerpt):

```solidity
// Dividend Sauce, for everyone!
// This is how you drop tokens directly into the Drip Pool balance
function donate(uint _amount) checkBlock(startBlock) public returns (uint256) {
    // Move the tokens from the caller's wallet to this contract.
    require(token.transferFrom(msg.sender, address(this), _amount));

    // Add the tokens to the drip pool balance
    dripPoolBalance += _amount;

    emit onDonate(msg.sender, _amount, block.timestamp);
    return dripPoolBalance;
}

// DepositTo: Put tokens into the vault for another address, to save.
// The deposited amount incurs a 10% fee, which is split 80:20 to the Daily Drip, and instant divs.
function depositTo(address _user, uint _amount) checkBlock(startBlock) public returns (uint256)  {
    require(token.transferFrom(msg.sender, address(this), _amount));
    totalDeposits += _amount;
    uint amount = _depositTokens(msg.sender, _user, _amount);
    distribute();
    return amount;
}

function resolve(uint256 _amount) checkBlock(startBlock) onlyHolders public {
    address _user = msg.sender;
    require(_amount <= balanceOf_[_user]);
    uint256 _undividedDividends = SafeMath.mul(_amount, divsFee) / 100;
    uint256 _taxedTokens = SafeMath.sub(_amount, _undividedDividends);
    currentTotalStaked = SafeMath.sub(currentTotalStaked, _amount);
    balanceOf_[_user] = SafeMath.sub(balanceOf_[_user], _amount);
    int256 _updatedPayouts = (int256) (profitPerShare_ * _amount + (_taxedTokens * magnitude));
    payoutsTo_[_user] -= _updatedPayouts;
    allocateFees(_undividedDividends);
    emit onResolve(_user, _amount, _taxedTokens, block.timestamp);
    distribute();
}

function harvest() checkBlock(startBlock) onlyEarners public {
    address _user = msg.sender;
    uint256 _dividends = myEarnings();
    payoutsTo_[_user] += (int256) (_dividends * magnitude);
    token.transfer(_user,_dividends);
    accountOf_[_user].withdrawn = SafeMath.add(accountOf_[_user].withdrawn, _dividends);
    accountOf_[_user].xWithdrawn += 1;
    totalTxs += 1;
    totalClaims += _dividends;
    emit onWithdraw(_user, _dividends, block.timestamp);
    distribute();
}
```

Key properties:
- `donate` immediately increases `dripPoolBalance`, which feeds into `profitPerShare_` via `distribute` and fee allocation.
- `depositTo` both transfers tokens into the contract and calls `_depositTokens`, which mints shares and updates `profitPerShare_`-based accounting.
- `resolve` reduces `currentTotalStaked` and the caller's `balanceOf_`, allocates fees to the drip pool, and adjusts payouts.
- `harvest` pays out `myEarnings()` (derived from `profitPerShare_` and `payoutsTo_`) and transfers underlying tokens directly to the caller.

Crucially, the code does not distinguish between long-lived deposits and flash-borrowed liquidity that exists only within a single transaction. Any tokens transferred in via `donate` or `depositTo` inflate the vault's apparent balance and earnings for as long as they remain in the contract, even if the same transaction later removes them.

### 3.2 Vulnerability summary

The vulnerability can be summarized as:
- When the strategy uses a PancakeSwap flash swap to borrow BTCB or BUSD and routes the borrowed tokens through `donate` and `depositTo`, the vault:
  - Treats the borrowed tokens as genuine principal for share minting.
  - Credits earnings based on the temporarily inflated `dripPoolBalance` and balances used in `distribute`.
- After this, a `resolve` and `harvest` sequence is able to withdraw more underlying tokens than the net economic contribution of the strategy, because the earnings and share allocation are computed on a base that includes flash-borrowed tokens that will later be repaid to the DEX, not retained by the vault.

This breaks conservation of value between vault shares and underlying assets and lets an unprivileged caller systematically extract profits at the expense of existing depositors.

### 3.3 Exploit conditions

The exploit relies on the following conditions, all satisfied in the observed incident:
- The BTCB and BUSD TokenVault contracts accept external `donate`, `depositTo`, `resolve`, and `harvest` calls and compute share prices and earnings using total token balances inclusive of short-lived flash-borrowed deposits.
- PancakeSwap pairs `0x0b32Ea94DA1F6679b11686eAD47AA4C6bF38cd59` and `0x58f876857a02d6762e0101bb5c46a8c1ed44dc16` provide sufficient BTCB/BUSD liquidity for the required flash swaps.
- The adversary EOA can deploy helper and strategy contracts that orchestrate the exact sequence of flash swap, `donate`, `depositTo`, `resolve`, and `harvest` calls and then route profits back to the EOA.

### 3.4 Security principles violated

The bug violates several core security principles:
- **Conservation of value:** Vault shares and harvested rewards exceed the vaults' true net asset value within the exploit transactions.
- **Separation of transient vs. durable capital:** Flash-borrowed tokens donated and deposited in a single transaction are treated as long-term contributors to the earnings pool and share price.
- **Assumptions about unprivileged callers:** The protocol assumed that unprivileged external callers could not force the TokenVault to send out more BTCB or BUSD than the vaults' genuine backing for existing depositors; the exploit shows this assumption is false.

## 4. Detailed Root Cause Analysis

### 4.1 Strategy contract behavior

The strategy contract `0x268D1581a34FB63dC46C92f07cB0D739517ca51C` is analyzed in `artifacts/root_cause/data_collector/iter_2/contract/56/0x268D...51C/analysis_summary.txt`. It is wired via its constructor to:
- WBNB `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095`.
- BTCB token `0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c`.
- BTCB TokenVault `0xe968D2E4ADc89609773571301aBeC3399D163c3b`.
- PancakeSwap pair `0x0b32Ea94DA1F6679b11686eAD47AA4C6bF38cd59`.

The analysis shows two primary entrypoints:
- Selector `0x6dfe6196` (primary exploit entrypoint in the seed transaction) constructs a call to `PancakePair::swap` to flash-borrow BTCB and sets `data` so that the pair will call back into the contract.
- Selector `0x84800812` is used in the callback path to chain external calls using selectors that match `approve`, `balanceOf`, `transfer`, and non-standard selectors corresponding to TokenVault `donate`, `depositTo`, `resolve`, and `harvest`.

From the analysis summary (excerpt):

```text
1) The constructor of 0x9827… deploys 0x268D… and immediately calls 0x6dfe6196().
2) 0x6dfe6196 constructs a call to PancakePair::swap(1020000000000000000, 0, 0x268D…, 0x01),
   causing the pair to send 1.02e18 BEP20Token to 0x268D… and call back into pancakeCall(data).
3) In the PancakeCallee callback, 0x268D…:
   - approves the TokenVault to pull BEP20Token (approve),
   - calls TokenVault::donate(1e18) and TokenVault::depositTo(0x268D…, 0.01572e18),
   - then calls TokenVault::resolve(0.014148e18) and TokenVault::harvest().
4) As a result, the TokenVault transfers 1.174165734101992050e18 BEP20Token to 0x268D….
5) 0x268D… returns 1.02e18 BEP20Token to the Pancake pair to settle the flash swap and uses
   an ERC-20 transfer to send the remaining ~1.5579e17 BEP20Token profit to the EOA
   0xc49f…. The balance-diff tooling on the seed tx confirms the net gain for the EOA.
```

The contract's storage layout fixes the vault, pair, token, and profit recipient addresses at deployment, so the strategy always targets the same TokenVault and routes profits to the same EOA.

### 4.2 Seed exploit transaction: BTCB TokenVault drain

Seed transaction:
- Chain: BSC (56).
- Tx hash: `0xf34e59e4fe2c9b454d2b73a1a3f3aaf07d484a0c71ff8278b1c068cdedc4b64d`.
- Block: `51782713`.
- Type: adversary-crafted contract creation from EOA `0xc49f2938327aa2cdc3f2f89ed17b54b3671f05de`.

The trace (`artifacts/root_cause/seed/56/0xf34e...b64d/trace.cast.log`) shows:
- The helper contract `0x9827...` is created.
- The helper deploys the strategy `0x268D...` and invokes its exploit entrypoint.
- The strategy calls `PancakePair::swap` on `0x0b32Ea...cd59` to borrow BTCB.
- The callback path invokes TokenVault `donate`, `depositTo`, `resolve`, and `harvest` on `0xe968D...c3b`.
- The vault transfers `1.174165734101992050e18` BTCB-like tokens to the strategy.
- The strategy repays `1.02e18` BTCB to the pair and transfers the remaining `155793734101992050` BTCB units to the adversary EOA.

The corresponding balance diff (`artifacts/root_cause/seed/56/0xf34e...b64d/balance_diff.json`) confirms the accounting:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c",
      "holder": "0xe968d2e4adc89609773571301abec3399d163c3b",
      "before": "158778100854484792",
      "after": "332366752492742",
      "delta": "-158445734101992050",
      "contract_name": "BEP20Token"
    },
    {
      "token": "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c",
      "holder": "0xc49f2938327aa2cdc3f2f89ed17b54b3671f05de",
      "before": "59934684708878",
      "after": "155853668786700928",
      "delta": "155793734101992050",
      "contract_name": "BEP20Token"
    }
  ]
}
```

The vault loses `158445734101992050` BTCB units, while the adversary EOA gains `155793734101992050` BTCB units in the same token, with the difference corresponding to protocol fees and flash swap cost. Native BNB deltas show gas paid by the EOA.

This matches the narrative in `root_cause.json`: the strategy inflates the vault's state with borrowed BTCB via `donate` and `depositTo`, then uses `resolve` and `harvest` to withdraw more underlying than its genuine principal and routes the net BTCB profit to the EOA.

### 4.3 Repeat exploit transaction: BUSD TokenVault drain

Repeat transaction:
- Chain: BSC (56).
- Tx hash: `0x00e5c8e39eece020ad21d965402d2f9248f0a6ab62030830b12f9823c2b6d763`.
- Block: `51784234`.
- Type: adversary-crafted contract creation from the same EOA.

The trace (`artifacts/root_cause/data_collector/iter_2/tx/56/0x00e5...763/trace.cast.log`) shows an analogous pattern:
- Helper `0x95A8...92ab` is created and deploys a strategy wired to:
  - BUSD TokenVault `0xd920Fa5D50a970698bcEA8dD5A9c25b4e62EfaB3`.
  - Pancake pair `0x58f876857a02d6762e0101bb5c46a8c1ed44dc16`.
- The strategy flash-borrows BUSD from the pair.
- It donates and deposits the borrowed BUSD into the vault, then resolves and harvests.
- The vault sends out more BUSD than the net contributed principal, the pair is repaid, and the remaining BUSD is forwarded to the EOA via an ERC20 transfer.

The BUSD balance diff (`artifacts/root_cause/data_collector/iter_2/tx/56/0x00e5...763/balance_diff.json`) records:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0xe9e7cea3dedca5984780bafc599bd69add087d56",
      "holder": "0xd920fa5d50a970698bcea8dd5a9c25b4e62efab3",
      "before": "1422270169586026083991",
      "after": "4523837315413278777",
      "delta": "-1417746332270612805214",
      "contract_name": "BEP20Token"
    },
    {
      "token": "0xe9e7cea3dedca5984780bafc599bd69add087d56",
      "holder": "0xc49f2938327aa2cdc3f2f89ed17b54b3671f05de",
      "before": "46474821659738262175",
      "after": "1460061153930351067389",
      "delta": "1413586332270612805214",
      "contract_name": "BEP20Token"
    }
  ]
}
```

The BUSD TokenVault loses `1417746332270612805214` BUSD units, while the adversary EOA gains `1413586332270612805214` BUSD units, again with the difference accounted for by protocol fees and DEX repayment.

### 4.4 Profit and ACT success predicate

The ACT success predicate is profit-based:
- The adversary pays BNB gas:
  - `1262220000000000` wei in the seed BTCB transaction.
  - `1245074000000000` wei in the repeat BUSD transaction.
- From the balance diffs, the EOA ends with:
  - `+155793734101992050` BTCB units in the seed transaction.
  - `+1413586332270612805214` BUSD units in the repeat transaction.
- The vaults lose exactly the corresponding amounts:
  - `-158445734101992050` BTCB units for the BTCB TokenVault.
  - `-1417746332270612805214` BUSD units for the BUSD TokenVault.

`root_cause.json` explicitly states that absolute pre-exploit portfolio valuations were not computed; instead, profit is evaluated from token and BNB deltas, which are fully determined by the on-chain traces and the balance diff outputs.

Combining both transactions, the adversary ends with a strictly positive ERC20 token position after subtracting gas fees, and the vaults suffer matching losses. This satisfies the ACT success predicate.

## 5. Adversary Flow Analysis

### 5.1 Adversary-related accounts

`root_cause.json` identifies the adversary cluster and victim contracts as follows:

- **Adversary cluster** (all on BSC chainid 56):
  - `0xc49f2938327aa2cdc3f2f89ed17b54b3671f05de` – EOA sender of both exploit transactions and direct recipient of BTCB and BUSD profits.
  - `0x982769c5e5dd77f8308E3CD6Eec37dA9d8237dc6` – helper contract deployed in the seed transaction; its constructor deploys the strategy and invokes the BTCB exploit path.
  - `0x268D1581a34FB63dC46C92f07cB0D739517ca51C` – strategy contract that coordinates the PancakeSwap flash swap and TokenVault `donate`, `depositTo`, `resolve`, and `harvest` calls.
  - `0x95A850fc5377c16CFcd20FD9FaeB907631bb92ab` – helper contract used in the repeat transaction targeting the BUSD TokenVault.

- **Victim contracts**:
  - Gangster Finance BTCB TokenVault `0xe968D2E4ADc89609773571301aBeC3399D163c3b` (verified source).
  - Gangster Finance BUSD TokenVault `0xd920Fa5D50a970698bcEA8dD5A9c25b4e62EfaB3` (same codebase and behavior).

The clustering is supported by:
- Deployment relationships in traces (helpers deploying strategies wired to the vaults and pairs).
- Constructor parameters fixing the profit recipient to the EOA.
- Balance diff evidence showing net BTCB/BUSD gains at the EOA address.

### 5.2 Lifecycle stages

**Stage 1 – Seed exploit: BTCB TokenVault drain**

- Tx: `0xf34e59e4fe2c9b454d2b73a1a3f3aaf07d484a0c71ff8278b1c068cdedc4b64d` (BSC, block `51782713`).
- Mechanism: PancakeSwap flash swap against BTCB pair `0x0b32Ea94DA1F6679b11686eAD47AA4C6bF38cd59`.
- Flow:
  1. EOA `0xc49f...05de` sends a contract-creation transaction that deploys helper `0x9827...`.
  2. The helper's constructor deploys strategy `0x268D...` and calls its exploit entrypoint.
  3. The strategy calls `PancakePair::swap` to borrow `1.02e18` BTCB-like tokens, encoded as a flash swap.
  4. In the callback, the strategy:
     - Approves the BTCB TokenVault to pull BTCB.
     - Calls `TokenVault::donate` and `TokenVault::depositTo` to push borrowed BTCB into the vault, inflating balances and earnings.
     - Calls `TokenVault::resolve` and `TokenVault::harvest` to realize earnings and withdraw underlying BTCB back to itself.
  5. The vault transfers `1.174165734101992050e18` BTCB-like tokens to the strategy.
  6. The strategy repays the `1.02e18` BTCB flash swap.
  7. The remaining `155793734101992050` BTCB units are transferred to the adversary EOA via an ERC20 `transfer`.

This sequence is fully visible in `trace.cast.log` and matches the TokenVault and strategy code behavior.

**Stage 2 – Repeat exploit: BUSD TokenVault drain**

- Tx: `0x00e5c8e39eece020ad21d965402d2f9248f0a6ab62030830b12f9823c2b6d763` (BSC, block `51784234`).
- Mechanism: PancakeSwap flash swap against BUSD pair `0x58f876857a02d6762e0101bb5c46a8c1ed44dc16`.
- Flow:
  1. EOA `0xc49f...05de` sends a second contract-creation transaction that deploys helper `0x95A8...92ab`.
  2. The helper deploys a strategy instance wired to BUSD TokenVault `0xd920F...FaB3` and Pancake pair `0x58f8...dc16`.
  3. The strategy flash-borrows BUSD from the pair.
  4. It calls the BUSD TokenVault's `donate` and `depositTo` functions with the borrowed BUSD, inflating balances and earnings.
  5. It calls `resolve` and `harvest` to pull out more BUSD than the net contributed principal.
  6. The vault loses `1417746332270612805214` BUSD units; the strategy repays the pair and transfers `1413586332270612805214` BUSD units to the EOA.

Both stages share identical logic: a flash swap injects transient liquidity into the vault, the vault's accounting misinterprets this as durable capital, and a carefully ordered `resolve`/`harvest` sequence extracts excess underlying tokens.

### 5.3 Transaction sequence and feasibility

`root_cause.json` lists the relevant transactions as:

- `0xf34e59e4fe2c9b454d2b73a1a3f3aaf07d484a0c71ff8278b1c068cdedc4b64d` – seed exploit (BTCB vault).
- `0x00e5c8e39eece020ad21d965402d2f9248f0a6ab62030830b12f9823c2b6d763` – repeat exploit (BUSD vault).
- `0x3de562f2fdaeb379ccbe8d244a56189db2a0f91410cd0f464274e51e4518e555` – related (non-exploit) reference.

The inclusion feasibility descriptions in `root_cause.json` are consistent with the traces and balance diffs: the adversary uses ordinary gas and nonce values, relies only on public contracts and DEX liquidity available in σ_B and subsequent states, and does not depend on any privileged role or off-chain coordination.

## 6. Impact & Losses

`root_cause.json` quantifies the impact based on balance diff artifacts:

- **BTCB TokenVault loss:** `158445734101992050` BTCB units lost from `0xe968D2E4ADc89609773571301aBeC3399D163c3b`.
- **BUSD TokenVault loss:** `1417746332270612805214` BUSD units lost from `0xd920Fa5D50a970698bcEA8dD5A9c25b4e62EfaB3`.

Adversary profits:
- EOA `0xc49f2938327aa2cdc3f2f89ed17b54b3671f05de` gains:
  - `155793734101992050` BTCB units in the seed transaction.
  - `1413586332270612805214` BUSD units in the repeat transaction.

These figures match the ERC20 deltas in the balance diff JSONs. The residual differences between vault losses and EOA gains are accounted for by protocol fees and flash swap costs.

Gas costs:
- Seed transaction gas fee: `1262220000000000` wei of BNB.
- Repeat transaction gas fee: `1245074000000000` wei of BNB.

Net effect:
- The adversary's ERC20 portfolio increases by the amounts above, and the vaults' backing for existing shares is permanently reduced by the BTCB and BUSD losses, satisfying the ACT profit success predicate.

## 7. References

The following on-disk artifacts back this analysis and were directly inspected:

1. **Seed exploit transaction trace and balance diff (BTCB TokenVault)**  
   - Path: `artifacts/root_cause/seed/56/0xf34e59e4fe2c9b454d2b73a1a3f3aaf07d484a0c71ff8278b1c068cdedc4b64d`  
   - Contains `trace.cast.log` and `balance_diff.json` showing the `CREATE → flash swap → donate/depositTo/resolve/harvest → repay → profit transfer` sequence and BTCB deltas.

2. **Repeat exploit transaction trace and balance diff (BUSD TokenVault)**  
   - Path: `artifacts/root_cause/data_collector/iter_2/tx/56/0x00e5c8e39eece020ad21d965402d2f9248f0a6ab62030830b12f9823c2b6d763`  
   - Contains `trace.cast.log` and `balance_diff.json` for the BUSD flash swap and TokenVault exploit.

3. **Gangster Finance BTCB TokenVault verified source**  
   - Path: `artifacts/root_cause/data_collector/iter_1/contract/56/0xe968D2E4ADc89609773571301aBeC3399D163c3b/source/src/Contract.sol`  
   - Provides the full TokenVault implementation, including `donate`, `depositTo`, `resolve`, `harvest`, and internal accounting logic.

4. **Strategy contract 0x268D1581a34FB63dC46C92f07cB0D739517ca51C disassembly and analysis**  
   - Path: `artifacts/root_cause/data_collector/iter_2/contract/56/0x268D1581a34FB63dC46C92f07cB0D739517ca51C`  
   - Contains disassembly and `analysis_summary.txt` documenting the flash-swap orchestration and TokenVault call sequence.

Together, these artifacts confirm that the incident was an ACT-qualified exploit of a deterministic accounting bug in the Gangster Finance TokenVault design, carried out through two adversary-crafted transactions that drained BTCB and BUSD from the vaults into an adversary-owned EOA.
