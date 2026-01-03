# BSC Vollar/BEP20USDT Flash-Loan Drain via Helper Mis-Accounting

## Incident Overview TL;DR

This report analyzes an ACT-class exploit on BSC against the Vollar/BEP20USDT PancakePair, where an adversary-controlled EOA and manager contract combine a Moolah flash loan, a publicly deployed helper contract, and taxed Vollar token transfers to drain 11,136,138,946,295,503,963,408 BEP20USDT from the pool. The root cause is a protocol-level logic flaw in helper contract `0x6ce69d7146dbaae18c11c36d8d94428623b29d5a` and its integration with the taxed Vollar token `0x4ec93ee81f25da3c8e49f01533cfb734545190a8` and the Vollar/BEP20USDT PancakePair `0x7b63B359A9B614fa8A40ED40C7766366e89f6845`. An attacker-controlled manager contract `0x383794a0c68e5c8c050f8f361b26a22b3f60eccf`, administered by EOA `0xa3e18e6028b1ca09433157cd6a5e807ffe705350`, routes Vollar through the helper’s `deposit`, `min3Amount`, `balanceOf`, and transfer flows in a way that mis-accounts the net Vollar movement against the AMM reserves and enables a deterministic flash-loan-assisted drain of BEP20USDT.

The analysis is ACT-conformant: it starts from the publicly reconstructible BSC state immediately before block `54252254`, precisely specifies the adversary-crafted transaction sequence, and defines a concrete profit-based success predicate in BEP20USDT. The root cause category is `protocol_bug`.

## Key Background

- **Protocol and tokens**
  - The affected protocol is the Vollar/BEP20USDT PancakePair on BSC, pairing Vollar `0x4ec93ee81f25da3c8e49f01533cfb734545190a8` with BEP20USDT `0x55d398326f99059ff775485246999027b3197955` in PancakePair `0x7b63B359A9B614fa8A40ED40C7766366e89f6845`.
  - Vollar is an ERC20-style token with a fixed supply minted in the constructor and configurable transfer taxes; BEP20USDT is a standard USDT-like token on BSC.

- **Vollar token economics**
  - Verified source for Vollar shows a fixed supply of `21,000,000 * 10^decimals` minted in the constructor and no external mint function.
  - Vollar applies configurable transfer taxes (`transferTax`, `transferFromTax`, `reflowRate`, `technologyRate`) whenever tokens move between non-whitelisted addresses.
  - Fees are routed to specific fee addresses (`contractAres`, `communityAdres`, `technologyAdres`), with owner-gated controls over configuration and whitelists.

- **Relevant Vollar code (taxed transfers)**

  *Snippet: Vollar transfer and transferFrom logic (verified source for `0x4ec9…` on BSC), illustrating taxed transfers and fee routing:*

  ```solidity
  // Vollar token (0x4ec93ee81f25da3c8e49f01533cfb734545190a8)
  contract Vollar is ERC20 {
      address public owner;
      address public contractAres;
      address public communityAdres;
      address public technologyAdres;
      uint256 public transferTax = 1000;
      uint256 public transferFromTax = 1000;
      uint256 public reflowRate = 1000;
      uint256 public technologyRate = 0;
      uint256 public totalRewardsDistributed;

      mapping(address => bool) public whitelist;
      mapping(address => bool) public whitelistA;

      IERC20 public TokenML;
      address public pancakeSwapPair;

      function transfer(address to, uint256 value) public virtual override returns (bool) {
          if (whitelistA[msg.sender]) {
              _transfer(msg.sender, to, value);
          } else {
              _processStandardTransfer(msg.sender, to, value);
          }
          if (to == pancakeSwapPair) {
              IPancakePair(pancakeSwapPair).sync();
              totalRewardsDistributed += value;
          }
          return true;
      }

      function transferFrom(address from, address to, uint256 value) public virtual override returns (bool) {
          uint256 currentAllowance = allowance(from, msg.sender);
          require(currentAllowance >= value, "ERC20: transfer amount exceeds allowance");
          require(balanceOf(from) >= value, "ERR: 10");
          if (whitelist[from] || whitelist[to]) {
              _transfer(from, to, value);
          } else {
              _processStandardTransferFrom(from, to, value);
          }
          _approve(from, msg.sender, currentAllowance - value);
          return true;
      }
  }
  ```

- **Helper contract and shared infrastructure**
  - Helper contract `0x6ce69d7146dbaae18c11c36d8d94428623b29d5a` exposes functions including `deposit(address pair,uint256 amount)`, `withDrawA(address pair,uint256 amount)`, `min3Amount()`, and `balanceOf(address)`, along with utility functions for interacting with Vollar and the Vollar/BEP20USDT pair.
  - On-chain traces show the helper is publicly callable and used by many unrelated EOAs, making it shared infrastructure rather than an attacker-only contract.

- **Adversary-controlled components**
  - Attacker manager contract `0x383794a0c68e5c8c050f8f361b26a22b3f60eccf` and related manager `0x1dfd6a84bb35c589cd64cdd120fbe36ce934bb6e` are deployed and administered by EOA `0xa3e18e6028b1ca09433157cd6a5e807ffe705350`.
  - These contracts expose owner-gated `setAddr` and withdrawal functions that allow the adversary to configure helper addresses and later withdraw accumulated ERC20 balances to the EOA.
  - The flash-loan provider is a Moolah proxy `0x8F73b65B4caAf64FBA2aF91cC5D4a2A1318E5D8C` with implementation `0x75C42E94dcF40e57AC267FfD4DABF63F97059686`.

## Vulnerability Analysis

The core vulnerability is a protocol-level logic flaw in helper contract `0x6ce69d7146dbaae18c11c36d8d94428623b29d5a` and its integration with the taxed Vollar token and the Vollar/BEP20USDT AMM.

- Helper `0x6ce6…` sits between user contracts and the Vollar/BEP20USDT pair, providing `deposit`, `withDrawA`, `min3Amount`, `balanceOf`, and token transfer utilities.
- Vollar applies transfer taxes on non-whitelisted transfers, altering the effective amounts that move between addresses and the AMM reserves.
- The helper internally accounts for deposited Vollar amounts and uses `min3Amount()` and related logic to track balances, but this accounting assumes standard (non-taxed) ERC20 behavior.
- When taxed Vollar transfers interact with the helper and AMM swaps, the helper’s internal accounting becomes inconsistent with the actual Vollar movement and AMM reserves, allowing the attacker to extract more BEP20USDT than is correctly backed by the pool’s Vollar side.

The vulnerable components are:

- Helper contract `0x6ce69d7146dbaae18c11c36d8d94428623b29d5a` on BSC, which mis-accounts taxed Vollar deposits and withdrawals in the presence of AMM swaps.
- The Vollar/BEP20USDT PancakePair `0x7b63B359A9B614fa8A40ED40C7766366e89f6845`, whose reserves are manipulated through the helper’s flawed accounting.
- Attacker-managed manager contracts `0x383794a0c68e5c8c050f8f361b26a22b3f60eccf` and `0x1dfd6a84bb35c589cd64cdd120fbe36ce934bb6e`, which expose owner-only configuration and withdrawal functions that tie the helper into the exploit path but rely on the helper’s publicly exploitable logic.

The main security principles violated are:

- **Invariant preservation of AMM reserves**: the helper’s logic fails to preserve the intended constant-product or reserve-balance invariants when interacting with a taxed token.
- **Robust handling of taxed tokens**: the system assumes standard ERC20 behavior for Vollar inside helper and AMM interactions, but Vollar’s transfer-tax semantics invalidate this assumption and allow reserve mis-accounting.
- **Least privilege for helper integration**: attacker-owned manager contracts can freely configure helper endpoints without additional safeguards, enabling a flawed shared helper to be connected into a high-value liquidity pair.

## Detailed Root Cause Analysis

### ACT opportunity and pre-state

- **Block and state**
  - ACT pre-state `σ_B` is defined as the publicly reconstructible BSC state immediately before block `54252254`.
  - In this state, the following contracts and accounts already exist with their on-chain code and storage:
    - Vollar token `0x4ec93ee81f25da3c8e49f01533cfb734545190a8`.
    - BEP20USDT token `0x55d398326f99059ff775485246999027b3197955`.
    - Vollar/BEP20USDT PancakePair `0x7b63B359A9B614fa8A40ED40C7766366e89f6845`.
    - Moolah flash-loan proxy `0x8F73b65B4caAf64FBA2aF91cC5D4DABF63F97059686` with implementation `0x75C42E94dcF40e57AC267FfD4DABF63F97059686`.
    - Helper contract `0x6ce69d7146dbaae18c11c36d8d94428623b29d5a`.
    - Attacker manager contracts `0x383794a0c68e5c8c050f8f361b26a22b3f60eccf` and `0x1dfd6a84bb35c589cd64cdd120fbe36ce934bb6e`.
    - Adversary EOA `0xa3e18e6028b1ca09433157cd6a5e807ffe705350`.
- **Pre-state evidence**
  - `artifacts/root_cause/seed/56/0x0e01fd8798f970fd689014cb215e622aca8b7c8c243176c5b504e0043402e31f/metadata.json`.
  - `artifacts/root_cause/data_collector/iter_1/address/56/0xa3e18e6028b1ca09433157cd6a5e807ffe705350/txlist.json`.
  - `artifacts/root_cause/data_collector/iter_1/contract/56/0x75C42E94dcF40e57AC267FfD4DABF63F97059686/source/src`.
  - `artifacts/root_cause/seed/56/0x4ec93ee81f25da3c8e49f01533cfb734545190a8/src/AVD(2025-7-3) (BSC).sol`.
  - `artifacts/root_cause/seed/56/0x55d398326f99059ff775485246999027b3197955/src/Contract.sol`.

### Success predicate

- **Type**: Profit, denominated in BEP20USDT.
- **Reference asset**: BEP20USDT (`0x55d398326f99059ff775485246999027b3197955`) on BSC.
- **Adversary address (cluster)**: EOA `0xa3e18e6028b1ca09433157cd6a5e807ffe705350` plus attacker contract `0x383794a0c68e5c8c050f8f361b26a22b3f60eccf`.
- **Quantitative values in BEP20USDT**:
  - Value before sequence `b`: `0`.
  - Value after sequence `b`: `11136138946295503963408`.
  - Value delta: `11136138946295503963408`.
  - Fees paid in reference asset: `0` (gas is paid in BNB and intentionally tracked separately).
- **Valuation notes**
  - Using the combined balance diffs for the exploit and profit transactions, the adversary-controlled cluster holds `0` BEP20USDT immediately before sequence `b` and `11,136,138,946,295,503,963,408` BEP20USDT afterward, all sourced from the Vollar/BEP20USDT PancakePair `0x7b63…`.
  - Total gas paid by the EOA across the priming tx `0x5eaa8d…`, exploit tx `0x0e01fd…`, and profit tx `0x7ed3da…` is exactly `88,415,100,000,000` wei of BNB, as shown in the native balance diffs.
  - Because gas is paid in BNB rather than BEP20USDT, `fees_paid_in_reference_asset` is deterministically set to `0` and gas costs are tracked separately in BNB.
  - Net profit in the BEP20USDT reference asset is therefore a strict increase of `11,136,138,946,295,503,963,408` units.

*Snippet: Seed transaction balance diff for tx `0x0e01fd…`, showing BEP20USDT drained from the PancakePair and accumulated on the attacker contract (balance_diff.json):*

```json
{
  "chainid": 56,
  "txhash": "0x0e01fd8798f970fd689014cb215e622aca8b7c8c243176c5b504e0043402e31f",
  "native_balance_deltas": [
    {
      "address": "0xa3e18e6028b1ca09433157cd6a5e807ffe705350",
      "before_wei": "91044220700000000",
      "after_wei": "90965842500000000",
      "delta_wei": "-78378200000000"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x383794a0c68e5c8c050f8f361b26a22b3f60eccf",
      "before": "0",
      "after": "11136138946295503963408",
      "delta": "11136138946295503963408",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x7b63b359a9b614fa8a40ed40c7766366e89f6845",
      "before": "57274279651527723560361",
      "after": "46138140705232219596953",
      "delta": "-11136138946295503963408",
      "contract_name": "BEP20USDT"
    }
  ]
}
```

### Root cause mechanism

- Vollar has a fixed supply and applies transfer taxes when tokens move between non-whitelisted addresses. The Vollar/BEP20USDT PancakePair holds reserves of both tokens and follows standard constant-product AMM logic.
- Helper `0x6ce6…` provides a `deposit(address pair,uint256 amount)` function that transfers Vollar in taxed form from the attacker manager contract to the helper and/or the pair, while maintaining internal balances and `min3Amount()` thresholds that assume untaxed behavior.
- Disassembly and traces for the exploit transaction `0x0e01fd8798f970fd689014cb215e622aca8b7c8c243176c5b504e0043402e31f` show the following high-level pattern:
  - The attacker contract `0x3837…` obtains a flash loan of `20,000` BEP20USDT via Moolah.
  - The attacker swaps BEP20USDT for Vollar via the PancakeRouter and Vollar/BEP20USDT PancakePair, receiving Vollar while altering the pool’s reserves.
  - The attacker approves helper `0x6ce6…` to spend Vollar, then calls `deposit` and related helper functions, pushing Vollar through taxed transfers and internal accounting.
  - Due to mis-accounting between taxed Vollar transfers, helper balances, and AMM reserves, the sequence over-credits BEP20USDT to the attacker and under-accounts the pair’s Vollar liability.
  - The flash loan is repaid, and the attacker contract ends the exploit transaction holding `11,136,138,946,295,503,963,408` BEP20USDT drained from the pool.

*Snippet: Seed transaction trace (cast run -vvvvv) for exploit tx `0x0e01fd…`, showing the flash loan, swaps, helper deposit, and taxed Vollar transfers:*

```text
[890294] 0x383794A0C68e5c8C050F8F361B26A22B3f60eccf::0dc4a70f(...)
  ├─ [24562] BEP20USDT::approve(0x8F73b65B4caAf64FBA2aF91cC5D4a2A1318E5D8C, ...)
  ├─ [851822] 0x8F73b65B4caAf64FBA2aF91cC5D4A2A1318E5D8C::flashLoan(BEP20USDT, 20000000000000000000000, ...)
  │   ├─ [846991] 0x75C42E94dcF40e57AC267FfD4DABF63F97059686::flashLoan(...)
  │   │   ├─ BEP20USDT::transfer(0x383794A0C68e5c8C050F8F361B26A22B3f60eccf, 20000000000000000000000)
  │   │   ├─ 0x383794A0C68e5c8C050F8F361B26A22B3f60eccf::onMoolahFlashLoan(...)
  │   │   │   ├─ BEP20USDT::approve(PancakeRouter, 20000000000000000000000)
  │   │   │   ├─ PancakeRouter::swapExactTokensForTokensSupportingFeeOnTransferTokens(...)
  │   │   │   │   ├─ BEP20USDT::transferFrom(0x3837…, PancakePair, 20000000000000000000000)
  │   │   │   │   ├─ PancakePair::swap(..., to: 0x3837…)
  │   │   │   │   │   ├─ Vollar::transfer(PancakePair → 0x3837…, 69282157129)
  │   │   │   ├─ Vollar::approve(0x6ce69d7146dbaae18c11c36d8D94428623B29D5A, 69282157129)
  │   │   │   ├─ 0x6ce69d7146dbaae18c11c36d8D94428623B29D5A::deposit(..., 69282157129)
  │   │   │   │   ├─ Vollar::transferFrom(0x3837…, 0x6ce6…, 69282157129)  // taxed transfer
```

This trace, combined with the Vollar source and balance diffs, shows that:

- The helper receives Vollar via taxed `transferFrom` calls.
- The AMM reserves and helper internal accounting diverge, allowing the pool’s BEP20USDT reserves to decrease by a large amount while the attacker contract accumulates an equal BEP20USDT balance.
- No privileged minting occurs in Vollar, and all admin-only setters remain owner-gated on attacker-owned contracts; the drain is purely due to mis-accounting between helper `0x6ce6…`, Vollar’s tax logic, and the AMM reserves.

### Exploit preconditions and replayability

The exploit depends on the following ACT exploit conditions:

- Vollar, BEP20USDT, the Vollar/BEP20USDT PancakePair, helper contract `0x6ce6…`, and the Moolah flash-loan provider are all deployed and accessible on BSC.
- An unprivileged adversary can deploy and configure attacker-managed contracts like `0x3837…` and `0x1dfd6a…` to point at helper `0x6ce6…` via owner-gated `setAddr` calls, which the adversary controls.
- The adversary can obtain a flash loan of BEP20USDT from Moolah and route Vollar and BEP20USDT through helper `0x6ce6…` and the PancakePair using public functions (`deposit`, `balanceOf`, transfers, swaps) in the specific order used in tx `0x0e01fd…`, reproducing the same reserve-draining effect.
- Gas fees in BNB are small compared to the BEP20USDT profit, so the net profit predicate remains strictly positive in the BEP20USDT reference asset after accounting for all gas payments.

Given these conditions and the publicly observable pre-state `σ_B`, the exploit can be deterministically replayed by any party with knowledge of the transaction sequence and parameters.

## Adversary Flow Analysis

### All relevant transactions

The analysis considers the following relevant BSC transactions (chainid `56`):

- `0x0e01fd8798f970fd689014cb215e622aca8b7c8c243176c5b504e0043402e31f` — seed exploit transaction.
- `0x5eaa8de1d0b35f75433406bfba1367f2ae15c87614a60c779a138bcf315f82e1` — adversary-crafted priming transaction (admin config).
- `0x7ed3da98a5ffe6960c65f01c1e52ad52c9581b2dce38d2ba034ddf1a68740a62` — adversary-crafted profit realization transaction.
- `0x3d6a38df3d76fba5f4f19da0e12dbf8f6109992557d3d00873364d86e7c505a5` — related configuration transaction.
- `0xe5f04a5cf6a50a6f6cac4c38eb9d7ac5f8e1b66c7168945fd78732ecc0f30a3f` — related contract deployment transaction.

### Transaction sequence b (ACT framing)

ACT transaction sequence `b` consists of three adversary-crafted transactions:

1. **Priming admin transaction**
   - `index`: 1  
   - `txhash`: `0x5eaa8de1d0b35f75433406bfba1367f2ae15c87614a60c779a138bcf315f82e1`  
   - `type`: adversary-crafted  
   - **Inclusion feasibility**: Standard BSC type-2 transaction submitted and signed by unprivileged EOA `0xa3e18e6028b1ca09433157cd6a5e807ffe705350`, calling owner-gated `setAddr` on attacker contract `0x383794a0c68e5c8c050f8f361b26a22b3f60eccf` with gas and nonce chosen by the adversary; no special privileges or consensus control are required.
   - **Effect**: Configures attacker contract `0x3837…` to point at helper `0x6ce6…` before the flash-loan exploit.

2. **Flash-loan exploit transaction**
   - `index`: 2  
   - `txhash`: `0x0e01fd8798f970fd689014cb215e622aca8b7c8c243176c5b504e0043402e31f`  
   - `type`: adversary-crafted  
   - **Inclusion feasibility**: Standard BSC type-2 transaction from the same unprivileged EOA `0xa3e18e…` to attacker contract `0x3837…` that invokes the public flash-loan hook (selector `0x0dc4a70f`), which borrows `20,000` BEP20USDT via Moolah and orchestrates swaps and helper calls; the adversary controls gas price and nonce and needs only the publicly visible pre-state `σ_B`.
   - **Effect**: Drains `11,136,138,946,295,503,963,408` BEP20USDT from the Vollar/BEP20USDT PancakePair into attacker contract `0x3837…` via helper `0x6ce6…` and taxed Vollar transfers.

3. **Profit realization transaction**
   - `index`: 3  
   - `txhash`: `0x7ed3da98a5ffe6960c65f01c1e52ad52c9581b2dce38d2ba034ddf1a68740a62`  
   - `type`: adversary-crafted  
   - **Inclusion feasibility**: Standard BSC transaction from unprivileged EOA `0xa3e18e…` to attacker contract `0x3837…` that calls `withdrawERC20` to transfer BEP20USDT profit from the contract to the EOA; execution depends only on attacker-controlled contract state created by earlier transactions in sequence `b`.
   - **Effect**: Moves the drained BEP20USDT from attacker contract `0x3837…` to the adversary EOA `0xa3e18e…`, finalizing profit.

### Lifecycle stages

The adversary flow can be segmented into three lifecycle stages:

1. **Adversary contract deployment and configuration**
   - **Transactions**
     - `0xe5f04a5cf6a50a6f6cac4c38eb9d7ac5f8e1b66c7168945fd78732ecc0f30a3f` — deployment of manager contract.
     - `0x5eaa8de1d0b35f75433406bfba1367f2ae15c87614a60c779a138bcf315f82e1` — owner-gated `setAddr` on `0x3837…`.
     - `0x3d6a38df3d76fba5f4f19da0e12dbf8f6109992557d3d00873364d86e7c505a5` — configuration transaction for `0x1dfd6a…`.
   - **Effect**
     - EOA `0xa3e18e…` deploys manager contract `0x3837…` and configures both `0x3837…` and `0x1dfd6a…` to reference helper `0x6ce6…` via owner-gated `setAddr` calls, preparing the environment in which the helper’s mis-accounting can be exploited.
   - **Evidence**
     - `artifacts/root_cause/data_collector/iter_1/address/56/0xa3e18e6028b1ca09433157cd6a5e807ffe705350/txlist.json`.
     - `artifacts/root_cause/data_collector/iter_3/tx/56/0x3d6a38df3d76fba5f4f19da0e12dbf8f6109992557d3d00873364d86e7c505a5/trace.cast.log`.

2. **Flash-loan exploit execution**
   - **Transaction**
     - `0x0e01fd8798f970fd689014cb215e622aca8b7c8c243176c5b504e0043402e31f` (block `54252254`, mechanism `flashloan_and_swap`).
   - **Effect**
     - EOA `0xa3e18e…` calls attacker contract `0x3837…` to invoke the flash-loan hook, which:
       - Borrows `20,000` BEP20USDT through Moolah.
       - Routes Vollar through helper `0x6ce6…` and the Vollar/BEP20USDT pair using `deposit`, `min3Amount`, `balanceOf`, transfer, and swap calls.
       - Repays the flash loan.
       - Leaves `0x3837…` with `11,136,138,946,295,503,963,408` BEP20USDT taken from the PancakePair.
   - **Evidence**
     - `artifacts/root_cause/seed/56/0x0e01fd8798f970fd689014cb215e622aca8b7c8c243176c5b504e0043402e31f/trace.cast.log`.
     - `artifacts/root_cause/seed/56/0x0e01fd8798f970fd689014cb215e622aca8b7c8c243176c5b504e0043402e31f/balance_diff.json`.

3. **Profit withdrawal to EOA**
   - **Transaction**
     - `0x7ed3da98a5ffe6960c65f01c1e52ad52c9581b2dce38d2ba034ddf1a68740a62` (block `54253380`, mechanism `withdraw`).
   - **Effect**
     - EOA `0xa3e18e…` calls `withdrawERC20` on `0x3837…`, transferring the `11,136,138,946,295,503,963,408` BEP20USDT balance from the contract to the EOA and finalizing the profit.
   - **Evidence**
     - `artifacts/root_cause/data_collector/iter_3/tx/56/0x7ed3da98a5ffe6960c65f01c1e52ad52c9581b2dce38d2ba034ddf1a68740a62/receipt.json`.
     - `artifacts/root_cause/data_collector/iter_3/tx/56/0x7ed3da98a5ffe6960c65f01c1e52ad52c9581b2dce38d2ba034ddf1a68740a62/balance_diff.json`.

*Snippet: Profit withdrawal balance diff for tx `0x7ed3da…`, showing BEP20USDT moving from attacker contract to EOA (balance_diff.json):*

```json
{
  "chainid": 56,
  "txhash": "0x7ed3da98a5ffe6960c65f01c1e52ad52c9581b2dce38d2ba034ddf1a68740a62",
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x383794a0c68e5c8c050f8f361b26a22b3f60eccf",
      "before": "11136138946295503963408",
      "after": "0",
      "delta": "-11136138946295503963408"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xa3e18e6028b1ca09433157cd6a5e807ffe705350",
      "before": "0",
      "after": "11136138946295503963408",
      "delta": "11136138946295503963408"
    }
  ]
}
```

### Roles of victim and adversary

- **Victim**
  - The primary victim is the Vollar/BEP20USDT PancakePair `0x7b63B359A9B614fa8A40ED40C7766366e89f6845`, which loses a large quantity of BEP20USDT reserves due to the helper’s mis-accounting when interacting with taxed Vollar.
- **Adversary**
  - The adversary EOA is `0xa3e18e6028b1ca09433157cd6a5e807ffe705350`.
  - The EOA deploys and administers manager contracts `0x3837…` and `0x1dfd6a…`, configures helper references, triggers the flash-loan exploit, and withdraws profit.
  - Adversary-related contracts are identified via transaction histories and traces that show deployment, configuration, and subsequent calls.

## Impact & Losses

- **Quantitative impact**
  - `11,136,138,946,295,503,963,408` BEP20USDT are drained from the Vollar/BEP20USDT PancakePair `0x7b63…` and ultimately controlled by the adversary EOA `0xa3e18e…`.
  - The adversary’s BEP20USDT holdings (attacker contract + EOA) increase from `0` before sequence `b` to `11,136,138,946,295,503,963,408` after sequence `b`.
  - Total gas paid by the adversary in BNB across the priming, exploit, and profit transactions is `88,415,100,000,000` wei, but this does not reduce the BEP20USDT-denominated profit.
  - In the BEP20USDT reference asset, `fees_paid_in_reference_asset` is exactly `0`, and the net profit is `11,136,138,946,295,503,963,408` units.

- **Qualitative impact**
  - The Vollar/BEP20USDT PancakePair loses a large amount of BEP20USDT liquidity, causing a permanent shift in pool pricing and damaging liquidity providers.
  - The exploit demonstrates that shared helper infrastructure, when combined with taxed tokens and AMM pairs, can create systemic vulnerabilities if accounting is not carefully aligned with token mechanics.

## References

The following artifacts and sources underpin this analysis:

- **Exploit transaction trace and balance diff**  
  - `artifacts/root_cause/seed/56/0x0e01fd8798f970fd689014cb215e622aca8b7c8c243176c5b504e0043402e31f`
- **WithdrawERC20 profit transaction receipt and balance diff**  
  - `artifacts/root_cause/data_collector/iter_3/tx/56/0x7ed3da98a5ffe6960c65f01c1e52ad52c9581b2dce38d2ba034ddf1a68740a62`
- **Vollar token verified source**  
  - `artifacts/root_cause/seed/56/0x4ec93ee81f25da3c8e49f01533cfb734545190a8/src/AVD(2025-7-3) (BSC).sol`
- **BEP20USDT token verified source**  
  - `artifacts/root_cause/seed/56/0x55d398326f99059ff775485246999027b3197955/src/Contract.sol`
- **Helper contract disassembly and traces for 0x6ce6…**  
  - `artifacts/root_cause/data_collector/iter_1/contract/56/0x6ce69d7146dbaae18c11c36d8d94428623b29d5a`

