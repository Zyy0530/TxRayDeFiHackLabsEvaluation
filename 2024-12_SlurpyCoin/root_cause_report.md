# SlurpyCoin BNB Drain via Public BuyOrSell Swap Trigger

## Incident Overview & TL;DR

On BNB Chain (chainid 56), externally owned account (EOA) `0x132d9bbdbe718365af6cc9e43bac109a9a53b138` deployed a custom helper contract `0x051e057ea275caf9a73578a97af6e8965e5a2349`, then used it in a flash‑loan transaction to abuse SlurpyCoin’s `BuyOrSell` logic. By forcing SlurpyCoin to execute oversized swaps against its PancakeSwap WBNB pair, the adversary drained BNB from the SlurpyCoin contract into the helper. In a later transaction, the helper’s BNB balance was withdrawn back to the EOA, realizing a deterministic profit.

The exploit path relies entirely on publicly accessible functionality:
- A permissionless DODO flash loan from `0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476`.
- Public PancakeRouter swaps on the SlurpyCoin/WBNB pair `0x76A5a2Ef4AE2DdEAD0c8D5b704808637B414113C`.
- SlurpyCoin’s own fee and auto‑swap logic, which can be triggered by arbitrary callers.

Across the attack sequence, the SlurpyCoin contract loses `10.615940170989016157` BNB. After paying all gas costs, the adversary cluster `{EOA, helper}` realizes a net profit of `7.078058669305118343` BNB, with the remaining BNB (`3.204135968683897814` BNB) ending up inside the WBNB contract.

## ACT Opportunity and Transaction Sequence b

### ACT Opportunity (pre‑state σ_B)

- **Chain:** BNB Chain (`chainid = 56`).
- **Block height B:** `44990635`.
- **Pre‑state σ_B definition:** The state of BNB Chain immediately before processing block `44990635`, which contains both the helper deployment and the seed flash‑loan transaction. This pre‑state is reconstructed from RPC transaction metadata, verified contract sources, and prestateTracer‑based balance diffs for the seed transaction.

Key contracts and addresses present in σ_B:
- SlurpyCoin token and treasury contract: `0x72c114A1A4abC65BE2Be3E356eEde296Dbb8ba4c`.
- WBNB (wrapped BNB): `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`.
- DODO Private Pool (flash‑loan source): `0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476` (delegatecalling into `0x85351262f7474Ebe23FfAcD633cf20a491f1325d`).
- PancakeSwap V2 SlurpyCoin/WBNB pair: `0x76A5a2Ef4AE2DdEAD0c8D5b704808637B414113C`.
- PancakeRouter: `0x10ED43C718714eb63d5aA57B78B54704E256024E`.
- Adversary EOA: `0x132d9bbdbe718365af6cc9e43bac109a9a53b138` (funded in prior blocks).

**Seed transaction metadata (σ_B context):**

```json
// Seed tx metadata for 0x6c729ee7…9051 (BNB Chain)
{
  "from": "0x132d9bbdbe718365af6cc9e43bac109a9a53b138",
  "to": "0x051e057ea275caf9a73578a97af6e8965e5a2349",
  "blockNumber": "44990635",
  "gas": "50057598",
  "gasPrice": "10000000000",
  "value": "0",
  "txreceipt_status": "1"
}
```

*Caption: Seed transaction call from the adversary EOA to the helper contract in block 44990635; it pays only gas and no upfront BNB value.*

### Transaction Sequence b

The ACT opportunity is instantiated by the following three‑transaction sequence `b` on BNB Chain:

1. **Helper deployment**  
   - **Index:** 1  
   - **Tx hash:** `0x68e787a40f3da4a70c09c7cff47aaabd842d55a26deae5945c7fe24f40e19d71`  
   - **From:** `0x132d9bbdbe718365af6cc9e43bac109a9a53b138`  
   - **To:** contract creation (no `to` address)  
   - **Type:** adversary‑crafted  
   - **Inclusion feasibility:** Standard type‑0 contract deployment with sufficient balance and gas at block `44990635`; no privileged permissions required.  
   - **Effect:** Deploys helper contract `0x051e057ea275caf9a73578a97af6e8965e5a2349`. The decompiled helper shows owner‑guarded entrypoints that are restricted to the deploying EOA.

2. **Flash‑loan seed transaction (exploit execution)**  
   - **Index:** 2  
   - **Tx hash:** `0x6c729ee778332244de099ba0cb68808fcd7be4a667303fcdf2f54dd4b3d29051`  
   - **From:** `0x132d9bbdbe718365af6cc9e43bac109a9a53b138`  
   - **To:** `0x051e057ea275caf9a73578a97af6e8965e5a2349`  
   - **Type:** adversary‑crafted  
   - **Inclusion feasibility:** Standard type‑0 call from the EOA to the helper in block `44990635`, paying gas in BNB and invoking a public entrypoint. The DODO flash‑loan and PancakeRouter interactions are fully permissionless.

   **High‑level effect:**
   - The helper obtains a 40 WBNB flash loan from the DODO Private Pool.  
   - It routes the borrowed WBNB through PancakeRouter against the SlurpyCoin/WBNB pair.  
   - By manipulating SlurpyCoin’s internal token balance and repeatedly triggering `BuyOrSell`, the helper causes SlurpyCoin to perform oversized swaps that transfer BNB out of the SlurpyCoin contract.  
   - After repaying the flash loan, the helper ends the transaction with `7.411804202305118343` BNB, all sourced from SlurpyCoin and the EOA’s gas payments.

   **Key trace snippet (seed tx call tree):**

```bash
# Cast trace for seed tx 0x6c729ee7…9051
0x051e057E…2349::8f66e655(...)
  ├─ DODO Pool 0x6098A563…B476::flashLoan(40 WBNB, …)
  │   ├─ WBNB::transfer(0x051e057E…2349, 40 WBNB)
  │   └─ 0x051e057E…2349::DPPFlashLoanCall(...)
  │       ├─ WBNB::approve(PancakeRouter, 2^256-1)
  │       ├─ PancakeRouter::swapExactTokensForETHSupportingFeeOnTransferTokens(... SlurpyCoin/WBNB pair ...)
  │       ├─ SlurpyCoin::transfer(SlurpyCoin, 1e23)
  │       ├─ repeated SlurpyCoin::transfer(… , 1) calls
  │       └─ WBNB::withdraw(...) → BNB flows to SlurpyCoin and then to helper
```

*Caption: Seed transaction trace showing the DODO flash loan, PancakeRouter swap on the SlurpyCoin/WBNB pair, SlurpyCoin transfers, and WBNB withdrawals that collectively move BNB out of SlurpyCoin and into the helper.*

3. **Profit realization (withdrawal)**  
   - **Index:** 3  
   - **Tx hash:** `0x2f68bf2f12afb5e0ab536d15fae862de17a9600902fe5800192fe480f445026c`  
   - **From:** `0x132d9bbdbe718365af6cc9a43bac109a9a53b138`  
   - **To:** `0x051e057ea275caf9a73578a97af6e8965e5a2349`  
   - **Type:** adversary‑crafted  
   - **Inclusion feasibility:** Standard type‑0 call in block `45035059` invoking `withdraw()` on the helper. No privileged access is required.

   **Effect:** The helper transfers nearly all of its BNB balance to the EOA, converting the on‑contract gains from the seed tx into realized profit at the EOA level.

   **Balance diff snippet (withdraw tx):**

```json
// prestateTracer native balance deltas for 0x2f68bf2f…026c
{
  "native_balance_deltas": [
    {
      "address": "0x132d9bbdbe718365af6cc9e43bac109a9a53b138",
      "delta_wei": "7411775989305118343"
    },
    {
      "address": "0x051e057ea275caf9a73578a97af6e8965e5a2349",
      "delta_wei": "-7411804202305118343"
    }
  ]
}
```

*Caption: Withdraw transaction balance changes showing ~7.4118 BNB moving from the helper contract back to the adversary EOA, with a small difference consumed as gas.*

## Exploit Predicate and Profit Calculation

### Profit‑Based Exploit Predicate

- **Exploit type:** Profit  
- **Reference asset:** BNB (native token of BNB Chain)  
- **Adversary address (cluster root):** `0x132d9bbdbe718365af6cc9e43bac109a9a53b138`  

The exploit predicate is satisfied because, across sequence `b`, the adversary cluster ends with strictly more BNB (net of fees) than it had before, without any compensating losses elsewhere in the cluster.

### Fee‑Aware Profit Computation

Using prestateTracer balance diffs for the seed and withdraw transactions:

1. **Seed flash‑loan transaction (`0x6c729ee7…9051`):**
   - SlurpyCoin contract `0x72c114A1…ba4c`: `-10.615940170989016157` BNB  
   - Helper contract `0x051e057e…2349`: `+7.411804202305118343` BNB  
   - WBNB contract `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`: `+3.204135968683897814` BNB  
   - EOA `0x132d9bbd…b138`: `-0.33371732` BNB (gas cost)

2. **Withdraw transaction (`0x2f68bf2f…026c`):**
   - Helper contract: `-7.411804202305118343` BNB  
   - EOA: `+7.411775989305118343` BNB  
   - Implied gas cost for withdraw: `0.000028213` BNB

3. **Aggregated net profit:**
   - Total gas fees paid by the EOA:  
     - Seed tx: `0.33371732` BNB  
     - Withdraw tx: `0.000028213` BNB  
     - **Total fees:** `0.333745533` BNB
   - Gross BNB captured by the helper: `7.411804202305118343` BNB  
   - Net profit to the adversary cluster:  
     - `7.411804202305118343 BNB − 0.333745533 BNB = 7.078058669305118343 BNB`

Because these values are derived directly from on‑chain prestateTracer diffs, the profit calculation is deterministic and reproducible.

```json
// Seed tx prestateTracer native balance deltas (abridged)
{
  "native_balance_deltas": [
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "delta_wei": "3204135968683897814"
    },
    {
      "address": "0x051e057ea275caf9a73578a97af6e8965e5a2349",
      "delta_wei": "7411804202305118343"
    },
    {
      "address": "0x72c114a1a4abc65be2be3e356eede296dbb8ba4c",
      "delta_wei": "-10615940170989016157"
    },
    {
      "address": "0x132d9bbdbe718365af6cc9e43bac109a9a53b138",
      "delta_wei": "-333717320000000000"
    }
  ]
}
```

*Caption: Seed transaction prestateTracer deltas showing BNB leaving SlurpyCoin and the EOA and ending up on the helper and inside WBNB; these values drive the profit computation.*

## Vulnerability & Root Cause Analysis

### SlurpyCoin Design Summary

SlurpyCoin (`0x72c114A1…ba4c`) is an ERC‑20 token with transfer fees and automatic market‑making logic. It charges fees on transfers and accumulates tokens in the contract’s own balance. Once the internal token balance exceeds a threshold, the `BuyOrSell` mechanism can trigger swaps via PancakeRouter to create “slurpable dips” and distribute fees.

Key characteristics from the verified source:
- Uses `SafeMath` and standard ERC‑20 patterns.  
- Maintains an internal token balance on the contract itself.  
- Implements an auto‑swap mechanism that, when conditions are met, calls PancakeRouter functions (such as `swapExactTokensForETHSupportingFeeOnTransferTokens`) to trade tokens in the SlurpyCoin/WBNB pair.  
- Can receive BNB via a payable `receive` function and then re‑route value through swaps and internal logic.

```solidity
// Excerpt from SlurpyCoin Contract.sol (simplified)
function _transfer(address from, address to, uint256 amount) internal {
    // ... fee logic and balance updates ...
    if (from != uniswapV2Pair && overMinTokenBalance) {
        BuyOrSell();
    }
}
```

*Caption: Simplified SlurpyCoin transfer logic showing that any non‑pair sender who causes the contract’s internal token balance to exceed a threshold can trigger `BuyOrSell()` via a standard transfer.*

### Core Bug: Publicly Triggerable BuyOrSell with Unbounded Swap Size

The root cause is a **protocol bug** in SlurpyCoin’s `BuyOrSell` and transfer logic:

- The contract allows **any** non‑pair sender to trigger `BuyOrSell()` simply by calling `_transfer(from, to, amount)` with `from != uniswapV2Pair` and `overMinTokenBalance == true`.  
- `BuyOrSell()` uses the contract’s accumulated token balance to perform swaps via PancakeRouter, without properly constraining the effective swap size relative to the triggering transfer amount.  
- An attacker can first load the contract’s internal token balance (e.g., by transferring a large amount of SlurpyCoin into the contract) and then repeatedly trigger `BuyOrSell()` with tiny transfers, causing each small transfer to induce a large token‑for‑BNB swap at manipulated prices.

The helper contract exploits exactly this pattern:
- It receives SlurpyCoin tokens and moves them into the SlurpyCoin contract’s internal balance.  
- It then sends repeated “1 token” transfers from the helper to SlurpyCoin, satisfying `from != uniswapV2Pair` and `overMinTokenBalance`.  
- Each 1‑token transfer triggers a full `BuyOrSell()` cycle, causing oversized swaps that move disproportionate amounts of BNB from SlurpyCoin into the helper.

### On‑Chain Evidence of the Bug in Action

The cast trace for the seed transaction shows the helpers’s interactions with SlurpyCoin and the pair:

```bash
# Selected SlurpyCoin‑related calls in 0x6c729ee7…9051
SlurpyCoin::balanceOf(Pair 0x76A5a2Ef…13C)
SlurpyCoin::balanceOf(SlurpyCoin)
SlurpyCoin::transfer(SlurpyCoin, 100000000000000000000000)   # load internal balance
SlurpyCoin::transfer(0x051e057E…2349, 1)                     # repeated tiny transfers
PancakeRouter::swapExactTokensForETHSupportingFeeOnTransferTokens(...)
WBNB::withdraw(...)
SlurpyCoin::receive{value: ...}()
```

*Caption: SlurpyCoin call sequence where the helper first loads the contract’s internal token balance, then repeatedly triggers `BuyOrSell()` via 1‑token transfers, leading to large swaps and BNB extraction.*

Because the helper is an unprivileged contract and all interactions use public interfaces (DODO flash loans, PancakeRouter swaps, SlurpyCoin transfers and auto‑swap), any EOA capable of deploying such a helper can reproduce this exploit as long as similar contract state conditions hold.

## Adversary Flow Analysis

### Adversary Cluster and Control

The adversary cluster consists of:
- **EOA:** `0x132d9bbdbe718365af6cc9e43bac109a9a53b138`  
- **Helper contract:** `0x051e057ea275caf9a73578a97af6e8965e5a2349`

Evidence for clustering:
- The helper is deployed directly by the EOA in tx `0x68e787a4…e19d71`.  
- The EOA calls the helper both in the seed tx (`0x6c729ee7…9051`) and in the withdraw tx (`0x2f68bf2f…026c`).  
- The decompiled helper enforces owner‑only restrictions keyed to the deploying EOA.

```solidity
// Excerpt from helper decompilation (DecompiledContract)
function Unresolved_8f66e655(...) public {
    require(0x132d9bbdbe718365af6cc9e43bac109a9a53b138 == msg.sender);
    // orchestrates flash loan and swaps
}

function Unresolved_7ed1f1dd(...) public {
    require(0x6098a5638d8d7e9ed2f952d35b2b67c34ec6b476 == msg.sender);
    // DODO callback implementing the exploit logic
}
```

*Caption: Helper contract decompilation showing owner‑only entrypoints and the DODO flash‑loan callback used to execute the exploit.*

### Lifecycle Stages

1. **Preparation and funding**  
   - Prior to block `44990635`, the EOA is funded via standard transfers (no special privileges).  
   - The helper is deployed in `0x68e787a4…e19d71`, making its owner‑only entrypoints callable only by the EOA.

2. **Exploit execution (seed tx)**  
   - The EOA calls the helper, triggering a DODO flash loan for 40 WBNB.  
   - Inside the DODO callback, the helper:
     - Approves PancakeRouter to spend WBNB.  
     - Swaps WBNB for SlurpyCoin and back via the SlurpyCoin/WBNB pair.  
     - Uses SlurpyCoin’s transfer/`BuyOrSell` logic to cause repeated large swaps, moving BNB out of SlurpyCoin and into the helper.  
   - At the end of the transaction, the flash loan is repaid and the helper holds `7.411804202305118343` BNB.

3. **Profit realization (withdraw)**  
   - In block `45035059`, the EOA calls `withdraw()` on the helper.  
   - The helper sends almost all BNB to the EOA, with a small amount spent on gas.  
   - The adversary cluster’s net profit is `7.078058669305118343` BNB, as detailed in the profit calculation.

Throughout this lifecycle, there are no privileged or governance operations, and all calls are consistent with the standard ACT adversary model.

## Impact & Losses

### Quantitative Impact

- **Victim asset:** BNB (native) held by the SlurpyCoin contract.  
- **Total loss from SlurpyCoin contract:** `10.615940170989016157` BNB.  
- **Adversary net profit after fees:** `7.078058669305118343` BNB.  
- **Residual BNB inside WBNB contract:** `3.204135968683897814` BNB.

These figures are directly supported by prestateTracer balance diffs for the seed and withdraw transactions.

### Qualitative Impact

- The economic harm is concentrated on SlurpyCoin’s contract and, by extension, its holders who relied on the BNB treasury backing the token’s tokenomics.  
- DODO’s pool and the PancakeSwap pair end the sequence in consistent states, indicating that the exploit targets SlurpyCoin’s internal fee/auto‑swap design rather than the AMM or flash‑loan infrastructure.

## References

- **[1] Seed transaction metadata 0x6c729ee7…9051** – RPC‑derived tx metadata for the flash‑loan seed tx on BNB Chain.  
- **[2] Seed transaction prestateTracer balance diff 0x6c729ee7…9051** – Native and ERC‑20 balance changes showing BNB leaving SlurpyCoin and the EOA and arriving on the helper and WBNB.  
- **[3] Withdraw transaction prestateTracer balance diff 0x2f68bf2f…026c** – Native balance changes confirming BNB movement from the helper to the EOA.  
- **[4] SlurpyCoin source 0x72c114A1…ba4c** – Verified contract source including `BuyOrSell`, transfer, and fee logic used in the exploit.  
- **[5] Helper contract decompilation 0x051e057e…2349** – Heimdall decompilation showing owner‑only entrypoints and the DODO callback logic that orchestrates the exploit.  
- **[6] DODO Private Pool source 0x6098A563…B476** – Verified source for the flash‑loan contract providing 40 WBNB.  
- **[7] PancakeSwap V2 pair source 0x76A5a2Ef…13C** – Verified pool contract for the SlurpyCoin/WBNB pair targeted by the exploit.  
- **[8] SlurpyCoin txlist** – Full transaction history for the SlurpyCoin contract, corroborating that the exploit uses public operations without special privileges.
