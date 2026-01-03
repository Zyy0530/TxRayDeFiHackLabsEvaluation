# FIRST BNB IRYS Tax-Wallet Helper Liquidity Drain (Non-ACT, Operator-Controlled)

## Incident Overview & TL;DR

In BSC block 49994892, the operator of FIRST BNB IRYS (StandardToken `0x746727fc8212ed49510a2cb81ab0486ee6954444`, “IRYSAI”) configured an external owner-controlled helper contract `0x6233a81bbecb355059da9983d9fc9dfb86d7119f` as the token’s tax wallet. Immediately afterward, the helper’s owner-only functions were used to pull IRYSAI from the IRYSAI/WBNB PancakeSwap pair `0xeb703ed8c1a3b1d7e8e29351a1fe5e625e2efe04`, swap it for WBNB/BNB, and forward BNB to EOA `0x20bb82f7c5069c2588fa900ed438fefd2ae36827`, which then consolidated the funds to EOA `0x16bde0cec88b1f17c22b39491a86abf563a004db`.

The core root cause is an intentionally privileged combination of:
- `StandardToken::setTaxWallet` and `StandardToken::transferFrom` semantics in IRYSAI; and
- an owner-only helper at `0x6233...` whose functions `sc()` and `burn()` are callable only by its owner EOA `0x20bb...`.

This design enables an operator-controlled liquidity drain path that **cannot** be executed by an unprivileged, permissionless adversary. Under the ACT adversary model, which restricts attention to anyone-can-take opportunities, this incident is **non-ACT** and is instead an operator-controlled rug via privileged roles.

## Key Background

### Protocol and Token

FIRST BNB IRYS (IRYSAI) is an Ownable ERC20-style token deployed on BSC as `StandardToken` at:
- Token contract: `0x746727fc8212ed49510a2cb81ab0486ee6954444`
- Symbol/name (on-chain): `IRYSAI` / `FIRST BNB IRYS`

The token integrates with PancakeSwap via a standard router/factory pair and creates a liquidity pool against WBNB (`0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`). The primary liquidity pool relevant to the incident is the IRYSAI/WBNB pair:
- IRYSAI/WBNB pair: `0xeb703ed8c1a3b1d7e8e29351a1fe5e625e2efe04`

The contract is Ownable and deployer-controlled, with the deploying EOA `0xc4ce1e4a8cd2ba980646e855817252c7aa9c4ae8` acting as the initial owner and tax wallet.

#### StandardToken Tax Wallet and Transfer Semantics

The IRYSAI token implements a tax wallet and custom `transferFrom` behavior. The relevant excerpts from the verified source (`CA.sol`) show:

```solidity
// Collected StandardToken source (CA.sol)
// Key fields and constructor
address payable private _taxWallet;
mapping(address => bool) private _excludedFromFee;

constructor() payable {
    _taxWallet = payable(_msgSender());
    _czWallet = _taxWallet;

    _balances[_czWallet] = _tTotal * 60 / 100;
    _balances[address(this)] = _tTotal * 40 / 100;

    _excludedFromFee[address(this)] = true;
    _excludedFromFee[_taxWallet] = true;
}
```

*Caption: StandardToken constructor sets the deployer as `_taxWallet`, seeds balances, and marks only `address(this)` and `_taxWallet` as `_excludedFromFee`.*

The tax wallet can be reassigned only by callers already in `_excludedFromFee`:

```solidity
// Collected StandardToken source (CA.sol)
function setTaxWallet(address payable newWallet) external {
    require(_excludedFromFee[msg.sender]);
    _taxWallet = newWallet;
}
```

*Caption: `setTaxWallet` is a privileged function; only addresses marked `_excludedFromFee`—initially the deployer’s tax wallet and the token contract itself—can change `_taxWallet`.*

`transferFrom` is implemented with a special branch that skips allowance accounting entirely when the caller is the tax wallet:

```solidity
// Collected StandardToken source (CA.sol)
function transferFrom(
    address sender,
    address recipient,
    uint256 amount
) public override returns (bool) {
    _transfer(sender, recipient, amount);

    if (
        msg.sender != _taxWallet &&
        (sender == uniswapV2Pair || recipient != address(0xdead))
    )
        _approve(
            sender,
            _msgSender(),
            _allowances[sender][_msgSender()].sub(
                amount,
                "ERC20: transfer amount exceeds allowance"
            )
        );
    return true;
}
```

*Caption: For `msg.sender == _taxWallet`, `transferFrom` performs the balance move but **does not** check or reduce allowances, enabling `_taxWallet` to pull tokens from arbitrary holders (including the LP pair) without prior approval.*

The internal `_transfer` simply moves balances after basic sanity checks and tax accounting, with no separate allowance enforcement.

### Helper Contract and Owner-Only Functions

The helper contract at `0x6233a81bbecb355059da9983d9fc9dfb86d7119f` is decompiled from bytecode. The decompilation shows an Ownable structure with several owner-only methods that configure the router, the target token (`coin`), and perform swaps and drains.

Key elements from the Heimdall decompilation:

```solidity
// Heimdall decompiled contract for 0x6233...
contract DecompiledContract {
    address public owner;
    address public coin;
    address store_c;  // router-like address

    // sc(address): set coin and approve router
    function sc(address arg0) public {
        require(address(owner / 0x01) == (address(msg.sender)),
                "Ownable: caller is not the owner");
        coin = (address(arg0) * 0x01) | (uint96(coin));
        // approve router (store_c) for max allowance on coin
        (bool success, bytes memory ret0) =
            address(coin / 0x01).Unresolved_095ea7b3(address(store_c / 0x01));
    }

    // burn(): locate pair, pull tokens, swap to BNB
    function burn() public {
        require(address(owner / 0x01) == (address(msg.sender)),
                "Ownable: caller is not the owner");
        // router.factory(), router.WETH(), pair discovery, balanceOf(pair),
        // token transferFrom from pair, sync, swapExactTokensForETH, and
        // forwarding ETH to the owner are orchestrated here.
    }
}
```

*Caption: Helper contract 0x6233... exposes `sc()` and `burn()` as owner-only functions; `sc()` chooses the token and approves a router, while `burn()` orchestrates transfer-from-pair, sync, and swap-to-BNB, forwarding proceeds to the owner.*

The decompilation also includes `drain(uint256)` and `dust()` as additional owner-only mechanisms for extracting value, but the core incident path uses `sc()` and `burn()`.

### ACT Adversary Model Context

The ACT adversary model focuses on **permissionless** exploitation: an arbitrary unprivileged account, without access to privileged keys, must be able to execute the opportunity. Under this model:
- Privileged functions gated by `onlyOwner` or by private allowlists (e.g., `_excludedFromFee`) are **out of scope** as exploit entry points for ACT.
- To classify an incident as ACT, there must exist a reproducible, anyone-can-take transaction sequence that yields profit without requiring private key control of privileged operators.

In this incident, both the tax wallet reconfiguration and the helper’s execution path are **explicitly gated** by on-chain privilege checks. Therefore, any exploit that depends on these privileged calls is not ACT.

## Vulnerability & Root Cause Analysis

### High-Level Vulnerability

The combination of IRYSAI’s `StandardToken` implementation and the external helper contract creates an **operator-controlled liquidity drain path**:
- Once the helper `0x6233...` is set as `_taxWallet`, it can call `StandardToken::transferFrom` as `msg.sender == _taxWallet`.
- In this privileged context, `transferFrom` performs balance updates but skips allowance checks.
- The helper’s `burn()` function uses this to pull IRYSAI out of the IRYSAI/WBNB pair and then swap those tokens to BNB, forwarding funds to the operator’s EOA.

This is not a bug in the sense of an unintended external exploit; it is a **designed-in backdoor** combining tax wallet semantics and an owner-only helper.

### Detailed Root Cause Path

1. **Privileged Tax Wallet Role**: IRYSAI’s tax wallet is a privileged role:
   - Only addresses with `_excludedFromFee[msg.sender] == true` can call `setTaxWallet`.
   - Initially, `_excludedFromFee` includes only `address(this)` and the deployer-owned `_taxWallet`.
   - No public function adds arbitrary addresses to `_excludedFromFee`.

2. **Tax Wallet’s Special `transferFrom` Behavior**:
   - The `transferFrom` implementation first calls `_transfer(sender, recipient, amount)` which directly updates balances.
   - Only **after** `_transfer` does it attempt to decrement the spender’s allowance, and only if `msg.sender != _taxWallet` and `(sender == uniswapV2Pair || recipient != address(0xdead))`.
   - When `msg.sender == _taxWallet`, this allowance logic is skipped entirely, meaning `_taxWallet` can move tokens from any holder, including the LP pair, with no prior approval.

3. **Helper Configuration via `sc()` and `burn()`**:
   - The helper contract at `0x6233...` is owned by EOA `0x20bb...` and exposes owner-only functions:
     - `sc(address coin)` sets the target token and calls `approve(router, type(uint256).max)` on `coin`.
     - `burn()` uses the router to:
       - identify the IRYSAI/WBNB pair,
       - query the pair’s IRYSAI balance,
       - call `StandardToken::transferFrom(pair, 0x6233..., amount)` as `_taxWallet`,
       - call the pair’s `sync()` to update reserves,
       - and execute a token-for-ETH (BNB) swap, ultimately forwarding BNB to the owner.

4. **Ownership and Privilege Gating**:
   - The helper’s `sc()` and `burn()` functions are guarded by `require(owner == msg.sender, "Ownable: caller is not the owner")`, so only the helper’s owner EOA `0x20bb...` can invoke them.
   - `setTaxWallet` is similarly gated via `_excludedFromFee`, accessible only to the deployer/tax wallet and the token contract.

The combination of these design choices produces a closed, operator-only path that drains liquidity from the IRYSAI/WBNB pool without any permissionless entry point.

### Code Evidence for the Drain Mechanism

The seed transaction trace for the main drain transaction confirms the described behavior.

```bash
# Seed transaction trace for tx 0xe9a66b... (burn() call)
# Origin: 0x20bb82f7c5069c2588fa900ed438fefd2ae36827 → 0x6233...
```

```text
# Seed trace (cast run -vvvvv style) for tx 0xe9a66bad...
# Originating from EOA 0x20bb... to helper 0x6233...
[226075] 0x6233...::burn()
  ├─ PancakeRouter::factory()  → PancakeFactory 0xcA143C...
  ├─ PancakeRouter::WETH()     → WBNB 0xbb4CdB...
  ├─ PancakeFactory::getPair(StandardToken 0x7467..., WBNB 0xbb4C...) → Pair 0xeb703E...
  ├─ StandardToken::balanceOf(Pair 0xeb703E...) → 104117356083062476
  ├─ StandardToken::transferFrom(Pair 0xeb703E..., 0x6233..., 104106944347454170)
  │   ├─ emit Transfer(Pair → 0x6233..., 104106944347454170)
  │   └─ storage change for allowance slot shows `_taxWallet`-style behavior
  ├─ PancakePair::sync() with updated reserves
  ├─ PancakeRouter::swapExactTokensForETHSupportingFeeOnTransferTokens(...)
  │   ├─ StandardToken::transferFrom(0x6233..., Pair, 104106944347454170)
  │   ├─ PancakePair::swap(0, 107462996233504225783, Router, ...)
  │   │   ├─ WBNB::transfer(Pair → Router, 107462996233504225783)
  │   │   ├─ emit Sync and Swap with the drained amounts
  │   ├─ WBNB::withdraw(107462996233504225783)
  │   └─ Router receives BNB, then forwards it to 0x6233...
  ├─ 0x6233... fallback{value: 107462996233504225783}()
  └─ 0x20bb... fallback{value: 107462996233504225783}()
```

*Caption: Seed trace for tx 0xe9a66bad... shows helper `burn()` pulling IRYSAI from the pair via `StandardToken::transferFrom`, syncing reserves, swapping to WBNB/BNB, and forwarding BNB to the owner’s EOA `0x20bb...`.*

### On-Chain Balance Evidence

A prestateTracer balance diff for tx `0xe9a66bad8975f2a7b68c74992054c84d6d80ac4c543352e23bf23740b8858645` quantifies the value transfer.

```json
// QuickNode prestateTracer balance diff for tx 0xe9a66bad...
{
  "chainid": 56,
  "txhash": "0xe9a66bad8975f2a7b68c74992054c84d6d80ac4c543352e23bf23740b8858645",
  "native_balance_deltas": [
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "before_wei": "1380752811536374644235390",
      "after_wei": "1380645348540141140009607",
      "delta_wei": "-107462996233504225783"
    },
    {
      "address": "0x20bb82f7c5069c2588fa900ed438fefd2ae36827",
      "before_wei": "99996795228763783",
      "after_wei": "107562973134832989566",
      "delta_wei": "107462976339604225783"
    }
  ],
  "erc20_balance_deltas": [],
  "errors": []
}
```

*Caption: The prestateTracer diff shows WBNB `0xbb4c...` losing ~107.463 BNB-equivalent while EOA `0x20bb...` gains ~107.463 BNB, confirming the profit realization path described in the analysis.*

### Why This Is Non-ACT

Given the code and traces, the drain path depends on **two distinct privileged steps**:

1. **Tax wallet reconfiguration**:
   - Only `_excludedFromFee` addresses (initially the deployer-controlled tax wallet and the token contract) can set `_taxWallet`.
   - The incident sequence includes a transaction where `0xc4ce...` calls `setTaxWallet(0x6233...)`, making the helper the new tax wallet. This is documented in the analysis and supported by the trace for tx `0x8c637fc98ad84b922e6301c0b697167963eee53bbdc19665f5d122ae55234ca6`.

2. **Owner-only helper operations**:
   - The helper’s `sc()` and `burn()` functions are strictly `onlyOwner`.
   - The tx history for `0x6233...` shows that all `sc()`/`burn()` invocations originate from EOA `0x20bb...`, which passes the owner check.

There is **no code path** by which an unprivileged EOA can:
- call `setTaxWallet` to point `_taxWallet` at an arbitrary helper they control; or
- call `sc()`/`burn()` on `0x6233...` without controlling its owner key.

Therefore, the opportunity exploited in this incident is **not** an open, anyone-can-take ACT opportunity. It is an operator-controlled backdoor used by the token’s own privileged actors.

### Vulnerable Components

The analysis identifies the following components as central to the incident:

- `StandardToken 0x746727fc8212ed49510a2cb81ab0486ee6954444 :: transferFrom(address,address,uint256)`
- `StandardToken 0x746727fc8212ed49510a2cb81ab0486ee6954444 :: setTaxWallet(address)`
- `Helper contract 0x6233a81bbecb355059da9983d9fc9dfb86d7119f :: sc(address)`
- `Helper contract 0x6233a81bbecb355059da9983d9fc9dfb86d7119f :: burn()`

### Exploit Preconditions

The liquidity drain requires the following on-chain conditions:

1. An address in `_excludedFromFee` (initially the StandardToken deployer/tax wallet `0xc4ce...`) must call `setTaxWallet(0x6233...)`, assigning the helper contract as `_taxWallet`.
2. The owner of the helper contract (`0x20bb...`) must:
   - call `sc(0x7467...)` on `0x6233...` to set `coin = IRYSAI` and approve the Pancake router to spend IRYSAI from `0x6233...`; and
   - subsequently call `burn()` to execute the `transferFrom` / `sync` / `swap` drain path.
3. The IRYSAI/WBNB Pancake pair must hold sufficient IRYSAI and WBNB reserves such that the transfer-from-pair and subsequent swap produces meaningful BNB proceeds.

All of these steps were observed on-chain in the incident block sequence.

### Security Principles Violated

The design and use of this mechanism violate several fundamental security and trust principles:

- **Trust minimization for LPs**: Liquidity providers implicitly rely on token and pool designs not embedding an operator-only rug path. Here, the token and helper were explicitly structured to enable such a path.
- **Principle of least privilege**: The tax wallet’s effective authority—especially when pointed at an owner-only helper—is far broader than necessary, enabling it to pull LP-held tokens without allowance.
- **Transparency**: The interaction between a configurable tax wallet and an external helper with owner-only drain logic creates a de facto backdoor not obvious from the token’s standard ERC20 interface. Surface-level inspection of transfers alone does not make this risk clear to typical users.

## Adversary Flow Analysis

### Adversary Strategy Summary

A centrally controlled cluster of privileged addresses orchestrates a short sequence of transactions that reconfigures the tax wallet and then drains liquidity:

1. The StandardToken deployer/owner `0xc4ce...` points `_taxWallet` at the helper contract `0x6233...`.
2. The helper’s owner EOA `0x20bb...` calls `sc(0x7467...)` to bind the helper to IRYSAI and approve the router.
3. The same EOA `0x20bb...` calls `burn()` to pull IRYSAI from the IRYSAI/WBNB pair, swap to BNB, and receive the proceeds.
4. EOA `0x20bb...` forwards the BNB to EOA `0x16bde...` for consolidation.

At no point is any step accessible to an arbitrary unprivileged address.

### Adversary-Related Accounts

The analysis identifies the following adversary-related accounts:

- `0xc4ce1e4a8cd2ba980646e855817252c7aa9c4ae8` (EOA, BSC chainid 56)
  - Deployer and owner of `StandardToken` (`0x7467...`).
  - Privileged tax wallet address that successfully calls `setTaxWallet(0x6233...)` in tx `0x8c637fc9...`.

- `0x6233a81bbecb355059da9983d9fc9dfb86d7119f` (contract, BSC chainid 56)
  - Owner-only helper whose `sc()` and `burn()` functions—invoked from `0x20bb...`—execute the IRYSAI/WBNB drain and route proceeds to the owner.

- `0x20bb82f7c5069c2588fa900ed438fefd2ae36827` (EOA, BSC chainid 56)
  - Controls the helper (passes `onlyOwner` checks).
  - Sends the `sc()` and `burn()` txs to `0x6233...`.
  - Receives ~107.46 BNB profit in tx `0xe9a66bad...`.
  - Forwards ~107.56 BNB to `0x16bde...` in tx `0xfed12db...`.

- `0x16bde0cec88b1f17c22b39491a86abf563a004db` (EOA, BSC chainid 56)
  - Immediate BNB recipient of 107.5629 BNB from `0x20bb...` in tx `0xfed12db...`.
  - Acts as a consolidation address for the drained funds.

### Victim Candidates

The main victim-side entities are:

- **FIRST BNB IRYS token contract**: `0x746727fc8212ed49510a2cb81ab0486ee6954444`
  - Verified source, standard ERC20-like interface, but with specialized tax and transferFrom logic.

- **IRYSAI/WBNB PancakeSwap pair**: `0xeb703ed8c1a3b1d7e8e29351a1fe5e625e2efe04`
  - Holds IRYSAI and WBNB liquidity provided by users.
  - Its reserves are directly drained by the privileged `transferFrom` and swap sequence.

### Adversary Lifecycle Stages

#### Stage 1 – Privilege Configuration (Tax Wallet Pointing)

- Transaction: `0x8c637fc98ad84b922e6301c0b697167963eee53bbdc19665f5d122ae55234ca6`
- Chain: BSC, chainid 56
- Block: 49994892
- From: `0xc4ce1e4a8cd2ba980646e855817252c7aa9c4ae8`
- To: `0x746727fc8212ed49510a2cb81ab0486ee6954444` (StandardToken)

Effect:
- `StandardToken::setTaxWallet(0x6233...)` is invoked by the deployer EOA.
- `_taxWallet` is changed from the original deployer address `0xc4ce...` to the helper contract `0x6233...`.

Trace evidence (human label): seed trace for tx 0x8c637fc9... showing `setTaxWallet(0x6233...)` and storage update of the `_taxWallet` slot.

#### Stage 2 – Helper Configuration for IRYSAI

- Transaction: `0x1e4305159146e99c633f50b224e321e2c7e281e3cc37d750e8241e853b3f8c86`
- Chain: BSC, chainid 56
- Block: 49994892
- From: `0x20bb82f7c5069c2588fa900ed438fefd2ae36827`
- To: `0x6233a81bbecb355059da9983d9fc9dfb86d7119f`
- Input: `0x37a25dc2...` (function selector `sc(address)`)

Effect:
- Helper owner `0x20bb...` calls `sc(0x7467...)` on `0x6233...`.
- `coin` is set to the IRYSAI token address `0x7467...`.
- The helper approves the configured router (`store_c`) for maximum allowance on IRYSAI.

Code evidence:
- Heimdall decompilation of `0x6233...` shows `sc(address)` as an owner-only function that stores `coin` and issues `approve(router, max)` on the token.

#### Stage 3 – Liquidity Drain and Profit Realization

- Primary drain transaction: `0xe9a66bad8975f2a7b68c74992054c84d6d80ac4c543352e23bf23740b8858645`
  - Chain: BSC, chainid 56
  - Block: 49994892
  - From: `0x20bb82f7c5069c2588fa900ed438fefd2ae36827`
  - To: `0x6233a81bbecb355059da9983d9fc9dfb86d7119f`
  - Function: `burn()` (owner-only)

Effect:
- Helper `0x6233...`, now set as `_taxWallet`, executes:
  1. Discover the IRYSAI/WBNB pair using the router’s `factory()` and `getPair()`.
  2. Query the pair’s IRYSAI balance via `StandardToken::balanceOf`.
  3. Call `StandardToken::transferFrom(pair, 0x6233..., amount)` as `_taxWallet`, pulling IRYSAI from the pair **without any allowance**.
  4. Call `PancakePair::sync()` with reduced IRYSAI and existing WBNB, updating reserves.
  5. Call `swapExactTokensForETHSupportingFeeOnTransferTokens`, transferring IRYSAI from `0x6233...` back to the pair and receiving WBNB → BNB.
  6. Forward BNB through the router to `0x6233...`, then to owner EOA `0x20bb...` via a payable fallback.

Trace evidence:
- The seed `trace.cast.log` lists the full internal call tree, including `StandardToken::transferFrom` from the pair, `PancakePair::sync`, `PancakePair::swap`, `WBNB::withdraw`, and the final value transfer to `0x20bb...`.

Balance evidence:
- The prestateTracer diff (shown earlier) confirms that WBNB `0xbb4c...` loses ~107.463 BNB-equivalent and EOA `0x20bb...` gains ~107.463 BNB, quantifying the profit.

- Follow-up consolidation transaction: `0xfed12dbccf338e63cc4b87164c27e428ef3b270f2a24ee100bda134b7b645d93`
  - Chain: BSC, chainid 56
  - Block: 49995162
  - From: `0x20bb82f7c5069c2588fa900ed438fefd2ae36827`
  - To: `0x16bde0cec88b1f17c22b39491a86abf563a004db`
  - Value: `107.5629` BNB

Effect:
- `0x20bb...` forwards the drained BNB (slightly more than the prestateTracer’s delta due to additional local funds) to `0x16bde...`.

### Transaction Sequence B (Adversary-Crafted)

The root cause analysis defines the adversary-crafted transaction sequence `transaction_sequence_b` as:

1. **Index 1** – Tax wallet reconfiguration
   - Chainid: 56 (BSC)
   - Txhash: `0x8c637fc98ad84b922e6301c0b697167963eee53bbdc19665f5d122ae55234ca6`
   - Type: adversary-crafted
   - Inclusion feasibility: standard BSC L1 transaction from privileged EOA `0xc4ce...` (StandardToken deployer/tax wallet) calling `setTaxWallet` on `0x7467...`. Feasible only for an address already marked in `_excludedFromFee`, not for arbitrary unprivileged EOAs.
   - Notes: configures `StandardToken::_taxWallet = 0x6233...`, granting `0x6233...` special treatment in `transferFrom()`.

2. **Index 2** – Helper configuration (`sc()`)
   - Chainid: 56
   - Txhash: `0x1e4305159146e99c633f50b224e321e2c7e281e3cc37d750e8241e853b3f8c86`
   - Type: adversary-crafted
   - Inclusion feasibility: standard BSC transaction from `0x20bb...` (owner of `0x6233...`) calling `sc(0x7467...)` on `0x6233...`; feasible only for the contract owner because `sc()` is gated by an `onlyOwner` check.
   - Notes: sets `coin = 0x7467...` and approves the configured router to spend IRYSAI from `0x6233...`.

3. **Index 3** – Liquidity drain (`burn()`)
   - Chainid: 56
   - Txhash: `0xe9a66bad8975f2a7b68c74992054c84d6d80ac4c543352e23bf23740b8858645`
   - Type: adversary-crafted
   - Inclusion feasibility: standard BSC transaction from the same owner EOA `0x20bb...` calling `burn()` on `0x6233...`; feasible only for the contract owner due to the `onlyOwner` check.
   - Notes: executes the `transferFrom`/`sync`/`swap` path that drains IRYSAI from the Pancake pair into BNB forwarded to `0x20bb...`.

## Impact & Losses

### Quantified Loss

The analysis focuses on BNB-denominated losses arising from the IRYSAI/WBNB pool drain.

- Token: BNB (native)
- Amount: `107.462976339604225783` BNB (net profit to `0x20bb...` after gas, per prestateTracer diff)

The IRYSAI/WBNB PancakeSwap pool is effectively drained of IRYSAI value:
- WBNB reserves fall by approximately `107.462996233504225783` BNB-equivalent.
- Approximately `107.462976339604225783` BNB is consolidated to the adversary cluster before consolidation to `0x16bde...` in the subsequent tx.

### Affected Parties

- **IRYSAI holders**: Holders suffer as the token’s primary on-chain liquidity is removed by the operator, impairing exit liquidity and price stability.
- **LP providers**: Providers of IRYSAI/WBNB liquidity directly lose value as reserves are drained via the operator-controlled backdoor rather than a permissionless arbitrage or market-driven process.

## References

Below are the key artifacts used in the analysis, labeled in human-readable form:

1. **StandardToken (FIRST BNB IRYS) source code – CA.sol**
   - Origin: Collected and verified contract source for `0x7467...`.
   - Local path: `artifacts/root_cause/seed/56/0x746727fc8212ed49510a2cb81ab0486ee6954444/src/CA.sol`

2. **Helper contract 0x6233... Heimdall decompilation**
   - Origin: Heimdall decompiler output for helper contract `0x6233...`.
   - Local path: `artifacts/root_cause/data_collector/iter_1/contract/56/0x6233a81bbecb355059da9983d9fc9dfb86d7119f/decompile/0x6233a81bbecb355059da9983d9fc9dfb86d7119f-decompiled.sol`

3. **0x6233... transaction history (Etherscan normal txlist)**
   - Origin: Etherscan-normalized tx history for helper contract `0x6233...`, including multiple `sc()` and `burn()` invocations from `0x20bb...`.
   - Local path: `artifacts/root_cause/data_collector/iter_1/address/56/0x6233a81bbecb355059da9983d9fc9dfb86d7119f/txlist_normal_etherscan_v2_full.json`

4. **EOA 0x20bb... transaction history around the incident**
   - Origin: Etherscan-normalized tx history for EOA `0x20bb...`, including `sc()`/`burn()` calls to `0x6233...` and consolidation transfer to `0x16bde...`.
   - Local path: `artifacts/root_cause/data_collector/iter_1/address/56/0x20bb82f7c5069c2588fa900ed438fefd2ae36827/txlist_normal_etherscan_v2_window.json`

5. **QuickNode prestateTracer diff and native balance changes for tx 0xe9a66bad...**
   - Origin: QuickNode’s `debug_traceTransaction` with `prestateTracer diffMode` capturing native balance changes.
   - Local path: `artifacts/root_cause/data_collector/iter_1/tx/56/0xe9a66bad8975f2a7b68c74992054c84d6d80ac4c543352e23bf23740b8858645/balance_diff_prestate_tracer.json`

6. **Seed cast trace for tx 0xe9a66bad...**
   - Origin: `cast run -vvvvv`-style execution trace capturing internal calls during the `burn()` transaction.
   - Local path: `artifacts/root_cause/seed/56/0xe9a66bad8975f2a7b68c74992054c84d6d80ac4c543352e23bf23740b8858645/trace.cast.log`

## All Relevant Transactions

For completeness, the analysis enumerates all relevant transactions:

- `0x8c637fc98ad84b922e6301c0b697167963eee53bbdc19665f5d122ae55234ca6` (BSC, chainid 56; role: related)
  - `StandardToken::setTaxWallet(0x6233...)` called by `0xc4ce...`.

- `0x1e4305159146e99c633f50b224e321e2c7e281e3cc37d750e8241e853b3f8c86` (BSC, chainid 56; role: related)
  - `sc(0x7467...)` called by `0x20bb...` on helper `0x6233...`.

- `0xe9a66bad8975f2a7b68c74992054c84d6d80ac4c543352e23bf23740b8858645` (BSC, chainid 56; role: seed)
  - `burn()` called by `0x20bb...` on helper `0x6233...`, executing the drain.

- `0xfed12dbccf338e63cc4b87164c27e428ef3b270f2a24ee100bda134b7b645d93` (BSC, chainid 56; role: related)
  - `0x20bb...` forwards 107.5629 BNB to `0x16bde...`.

