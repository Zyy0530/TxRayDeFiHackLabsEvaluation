## HORS/WBNB Helper LP Withdrawal on BNB Chain

### Incident Overview & TL;DR

- **Chain / Block:** BNB Chain (chainid 56), block `45587949`
- **Seed transaction:** `0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7`
- **Adversary EOA:** `0x8efb9311700439d70025d2b372fb54c61a60d5df`
- **Router contract (adversary-controlled):** `0x75ff620ff0e63243e86b99510cdbad1d5e76524e`
- **Helper contract:** `0x6f3390c6c200e9be81b32110ce191a293dc0eaba`
- **HORS token:** `0x1bb30f2ad8ff43bcd9964a97408b74f1bc6c8bc0`
- **WBNB token:** `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`
- **HORS/WBNB PancakePair:** `0xd5868b2e2b510a91964abafc2d683295586a8c70`

EOA `0x8efb…5df` first deploys router contract `0x75ff62…24e` and then, in the seed transaction `0xc857…fed7`, uses it to execute a PancakeV3 WBNB flash loan, call helper contract `0x6f3390…eaba`, transfer the entire HORS/WBNB LP position held by the helper to the router, and burn that LP via `PancakeRouter::removeLiquidity`. The LP burn yields a large amount of HORS and WBNB to the router, which repays the flash loan and forwards the remaining WBNB to `0x8efb…5df`, resulting in a net positive WBNB balance change for the EOA.

**Root cause and classification:**  
The HORS/WBNB LP burned in the seed transaction was minted from helper-held HORS and WBNB in an earlier transaction and remained under helper control until its removal. The contracts involved (HORS token, WBNB token, PancakePair, PancakeRouter, PancakeV3Pool) behave according to their standard logic in the collected traces. There is no code-level protocol bug, no transfer or burn of third-party LP, and no ACT opportunity under the defined adversary model. This incident is therefore classified as a **non-ACT, helper-owned LP withdrawal with profit to the helper’s controller**.

### Key Background

#### Pre-state and Relevant Contracts

At block height `45587949`, immediately before inclusion of the seed transaction, the relevant pre-state includes:

- The HORS token at `0x1bb30f2ad8ff43bcd9964a97408b74f1bc6c8bc0`
- The WBNB token at `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`
- The HORS/WBNB PancakePair at `0xd5868b2e2b510a91964abafc2d683295586a8c70`
- Helper contract `0x6f3390c6c200e9be81b32110ce191a293dc0eaba`
- Router contract `0x75ff620ff0e63243e86b99510cdbad1d5e76524e`
- EOA `0x8efb9311700439d70025d2b372fb54c61a60d5df`

The collected contract sources show:

- **HORS token (`0x1bb3…8bc0`)** is an ERC20-style token with fixed total supply minted to a master address, standard `transfer` and `approve/transferFrom` functions, and no nonstandard hooks or embedded AMM-specific logic.
- **HORS/WBNB pair (`0xd5868…8c70`)** is a standard PancakePair implementation with `mint`, `burn`, `swap`, `skim`, and `sync`, using SafeMath and UQ112x112-style accounting to track reserves and LP supply.
- **WBNB (`0xbb4c…095c`)** is the canonical Wrapped BNB implementation used by PancakeSwap, with standard `deposit`, `withdraw`, and ERC20 transfer semantics.
- **Helper contract (`0x6f3390…eaba`)** exposes function `f78283c7`, which orchestrates approvals to PancakeRouter and calls `addLiquidity` for specified token pairs.
- **Router contract (`0x75ff62…24e`)** is deployed by EOA `0x8efb…5df` and coordinates the PancakeV3 flash loan, helper call, LP transfers, `removeLiquidity`, flash-loan repayment, and WBNB forwarding to the EOA, as shown in the traces.

#### ACT Opportunity Framing

The ACT opportunity analysis defines:

- **Block height B:** `45587949` (BNB Chain)
- **Pre-state σ_B:** state of the HORS token, WBNB token, HORS/WBNB PancakePair `0xd5868…8c70`, helper `0x6f3390…eaba`, router `0x75ff62…24e`, and EOA `0x8efb…5df` immediately before the seed tx `0xc857…fed7`, after the helper has minted and held the LP position in tx `0x4df5…b826`.

Evidence for this pre-state comes from:

- Seed transaction metadata for `0xc857…fed7`
- Address histories for helper `0x6f3390…eaba` and the pair `0xd5868…8c70`
- The helper LP-creation trace for `0x4df5…b826`

The analysis concludes there is no missing or uncertain ACT checklist item: the LP lifecycle is fully accounted for and there is no unmodeled opportunity for an alternate, strictly-better adversary strategy.

#### Adversary Lifecycle Stages

The incident is structured around three lifecycle stages.

1. **Helper LP Creation (tx `0x4df582ed2cb6783a37096c5e204c2f8759d2e7fcbf7db9bce925457d2cdab826`, block `7336781`)**
   - **Caller:** EOA `0x6298194afa16862870521908caa7e9d138360858`
   - **Callee:** helper `0x6f3390c6c200e9be81b32110ce191a293dc0eaba::f78283c7`
   - **Mechanism:** `PancakeRouter::addLiquidity`
   - **Effect:**  
     - Helper starts with `1e33` HORS and `1e19` WBNB.  
     - It transfers `5e32` HORS to `0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8`.  
     - It approves PancakeRouter to spend `5e32` HORS and `1e19` WBNB.  
     - `PancakeRouter::addLiquidity` creates the HORS/WBNB pair `0xd5868B2e2B510A91964AbaFc2D683295586A8C70` and mints `70,710,678,118,654,752,440,083,436` LP tokens to the helper.  
     - Immediately after this mint, the pair’s reserves are `5e32` HORS and `1e19` WBNB, with no prior liquidity observed in address histories.

   **Trace snippet – helper mints LP from its own balances (tx 0x4df5…b826):**

   ```text
   # Helper LP creation trace for tx 0x4df582ed2cb6783a37096c5e204c2f8759d2e7fcbf7db9bce925457d2cdab826
   0x6f3390c6C200e9bE81b32110CE191a293dc0eaba::f78283c7(...)
     HORS::balanceOf(helper) → 1e33
     HORS::transfer(0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8, 5e32)
     HORS::approve(PancakeRouter, 5e32)
     WBNB::balanceOf(helper) → 1e19
     WBNB::approve(PancakeRouter, 1e19)
     PancakeRouter::addLiquidity(WBNB, HORS, 1e19, 5e32, ...)
       PancakeFactory::createPair(WBNB, HORS) → PancakePair 0xd5868B2e2B510A91964AbaFc2D683295586A8C70
       PancakePair::mint(helper)
         emit Mint(... amount0 = 5e32, amount1 = 1e19)
         emit Transfer(... value = 70710678118654752440083436)
   ```

   *Caption: Helper-owned LP creation using helper-held HORS and WBNB, from the helper LP creation trace for tx 0x4df5…b826.*

2. **Adversary Router Deployment (tx `0x9e498d3b1943c1778d7a41136446f83942405c4a24ebc9fb23c5f05a191a087a`, block `45587949`)**
   - **Caller:** EOA `0x8efb9311700439d70025d2b372fb54c61a60d5df`
   - **Effect:**  
     - Deploys router contract `0x75ff620ff0e63243e86b99510cdbad1d5e76524e` using a standard contract-creation transaction that satisfies normal gas and fee rules on BNB Chain.  
     - This router is controlled by the same EOA that later sends the seed transaction, establishing adversary control over the coordinator contract.

3. **Flash-Loan-Assisted LP Burn and Profit Realization (seed tx `0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7`, block `45587949`)**
   - **Caller:** EOA `0x8efb…5df` (zero-value tx to router `0x75ff62…24e`)
   - **High-level flow:**
     - Router initiates a PancakeV3Pool flash loan of `0.1` WBNB.
     - In `pancakeV3FlashCallback`, router calls helper `f78283c7` with HORS, PancakeRouter, and the HORS/WBNB pair.
     - Inside the callback path, the helper approves the router to spend its HORS/WBNB LP balance; the router pulls the entire helper-held LP via `PancakePair::transferFrom`.
     - The router approves PancakeRouter to spend its LP, then calls `PancakeRouter::removeLiquidity` to burn the LP.
     - `PancakePair::burn` destroys the LP and sends the underlying HORS and WBNB to the router.
     - Router repays the flash loan (`0.10001` WBNB) to the PancakeV3Pool and transfers the remaining WBNB (`14.799349453861436868`) to EOA `0x8efb…5df`.

   **Trace snippet – LP burn and WBNB profit (tx 0xc857…fed7):**

   ```text
   # Seed transaction trace for tx 0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7
   0x75ff620FF0e63243e86b99510cDbaD1D5e76524E::d090a11e(...)
     PancakeV3Pool::flash( ..., amount1 = 0.1 WBNB )
       WBNB::transfer(router, 0.1 WBNB)
       router::pancakeV3FlashCallback(...)
         0x6f3390c6C200e9bE81b32110CE191a293dc0eaba::f78283c7(...)
           PancakePair::balanceOf(helper) → 70,710,678,118,654,752,440,083,436
           PancakePair::transferFrom(helper, router, 70,710,678,118,654,752,440,083,436)
           PancakeRouter::removeLiquidity(WBNB, HORS, 70,710,678,118,654,752,440,083,436, ...)
             PancakePair::burn(to = router)
               emit Burn(amount0 = 347,242,535,196,129,895,429,273,744,913,820 HORS,
                         amount1 = 14,799,359,453,861,436,868 WBNB)
         WBNB::transfer(PancakeV3Pool, 0.10001 WBNB)   # flash-loan repayment
         WBNB::transfer(0x8Efb9311700439d70025d2B372fb54c61a60d5DF,
                        14.799349453861436868 WBNB)
   ```

   *Caption: Seed transaction flow showing flash loan, transfer and burn of helper-owned LP, and WBNB profit paid to EOA 0x8efb…5df, from the seed transaction cast trace for tx 0xc857…fed7.*

### Vulnerability & Root Cause Analysis

There is no protocol vulnerability exploited in this incident. Instead, the traces and address histories show a closed LP lifecycle entirely controlled by the helper and the adversary’s router:

- Helper `0x6f3390…eaba` receives HORS and WBNB balances and, in tx `0x4df5…b826`, uses `PancakeRouter::addLiquidity` to create the HORS/WBNB pair and mint LP tokens **to itself**.
- The HORS/WBNB pair shows no prior liquidity; the initial reserves (`5e32` HORS and `1e19` WBNB) match the helper’s contributions, and the entire observed LP supply is minted to the helper.
- In the seed tx `0xc857…fed7`, the router pulls the helper-held LP from the helper, burns it via `removeLiquidity`, and receives the underlying tokens, which are then used to repay the flash loan and pay profit to EOA `0x8efb…5df`.
- No LP owned by external liquidity providers is transferred or burned in this sequence, and the behavior of HORS, WBNB, PancakePair, PancakeRouter, and PancakeV3Pool matches their standard verified implementations.

From the ACT viewpoint:

- The adversary’s profit (`~14.7978` WBNB net) is fully explained by fees and the helper-owned LP withdrawal.
- There is no alternative, strictly better strategy that would exploit a protocol bug or mispricing; the helper’s LP is simply removed under its controller’s direction.
- The ACT gap analysis explicitly notes that no checklist items remain unresolved and that the incident is a helper-owned LP withdrawal with no ACT opportunity.

### Adversary Flow Analysis

#### Key Actors

- **EOA / Adversary:** `0x8efb9311700439d70025d2b372fb54c61a60d5df`  
  - Sends the router deployment tx `0x9e49…087a`.  
  - Sends the seed tx `0xc857…fed7`.  
  - Receives the final WBNB profit from the router.

- **Router contract (adversary-controlled):** `0x75ff620ff0e63243e86b99510cdbad1d5e76524e`  
  - Deployed by `0x8efb…5df`.  
  - Orchestrates the flash loan, helper call, LP transfer, LP burn, flash-loan repayment, and profit transfer.

- **Helper contract:** `0x6f3390c6c200e9be81b32110ce191a293dc0eaba`  
  - Holds the HORS and WBNB balances used to create the LP.  
  - Holds the LP until the seed transaction.  
  - Provides approvals that allow the router to move and burn its LP.

- **AMM components:**  
  - HORS token `0x1bb3…8bc0`  
  - WBNB token `0xbb4c…095c`  
  - HORS/WBNB PancakePair `0xd5868…8c70`  
  - PancakeRouter `0x10ed43c718714eb63d5aa57b78b54704e256024e`  
  - PancakeV3Pool `0x172fcd41e0913e95784454622d1c3724f546f849`

#### Transaction Sequence B (Adversary-Crafted)

The ACT framing uses a two-transaction sequence, both authored by the adversary EOA:

1. **Index 1 – Router Deployment**
   - **Tx:** `0x9e498d3b1943c1778d7a41136446f83942405c4a24ebc9fb23c5f05a191a087a`
   - **Type:** adversary-crafted
   - **Inclusion feasibility:** standard contract-creation tx on BNB Chain, with normal gas/fee parameters.
   - **Role:** Establishes `0x75ff62…24e` as an adversary-controlled router to coordinate the subsequent seed tx actions.

2. **Index 2 – Seed Transaction**
   - **Tx:** `0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7`
   - **Type:** adversary-crafted
   - **Inclusion feasibility:** zero-value tx to `0x75ff62…24e` with calldata encoding a PancakeV3 flash loan and helper call; gas usage and fee payment are normal and require no privileged permissions.
   - **Role:** Executes the flash-loan-assisted LP burn that converts helper-owned LP into WBNB profit.

#### Profit Predicate

The incident is classified under a **profit-based exploit predicate**, with:

- **Reference asset:** WBNB
- **Adversary address:** `0x8efb9311700439d70025d2b372fb54c61a60d5df`
- **Fees paid (reference asset):** `0.001545609` BNB (gas across deployment and seed transactions)
- **Value before / after (reference asset):** not directly computed from full portfolio; fields are marked `"unknown"` in the JSON for those absolute quantities.
- **Reference-asset delta:** `14.797803844861436868` WBNB, representing the net change in the BNB/WBNB reference asset for the adversary across the deployment + seed sequence.

The WBNB inflow to the adversary is measured directly from the WBNB `Transfer` events and balance diffs, and the gas costs are derived from the transaction metadata. This supports a deterministic calculation of the adversary’s net profit.

### Impact & Losses

#### Token-Level Impact

The analysis reports the following aggregate impact in the WBNB reference asset:

- **Total WBNB profit (adversary net gain):** `14.797803844861436868` WBNB  
  - EOA `0x8efb…5df` receives `14.799349453861436868` WBNB from router `0x75ff62…24e`.  
  - Across the deployment and seed transactions, the EOA pays `0.001545609` BNB in gas.  
  - The net change in the reference asset is therefore approximately `+14.797803844861436868` units.

From the pool’s perspective:

- The HORS/WBNB pair `0xd5868…8c70` experiences a large reduction in HORS and WBNB reserves corresponding to the burned helper-held LP:
  - `347,242,535,196,129,895,429,273,744,913,820` HORS
  - `14,799,359,453,861,436,868` WBNB
- The on-chain liquidity available in this pool decreases accordingly because a substantial portion of the LP supply (entire helper-held position) is burned.

Importantly, this reduction is attributable to a **legitimate withdrawal of helper-owned liquidity**:

- The LP burned in the seed transaction was minted in tx `0x4df5…b826` using helper-held HORS and WBNB balances.
- Address histories for the helper and pair do not show other addresses minting HORS/WBNB LP that later becomes part of this burned balance.
- No evidence appears in collected traces or diffs of third-party LP being seized or burned.

### References

The analysis and this report are supported by the following collected artifacts and evidence:

1. **Seed transaction metadata and trace for `0xc857…fed7`**  
   - Used to reconstruct the flash loan, helper callback, LP transfer, LP burn, flash-loan repayment, and WBNB profit flow to `0x8efb…5df`.

2. **Helper LP creation trace for `0x4df5…b826`**  
   - Shows helper `0x6f3390…eaba` creating the HORS/WBNB pair and minting LP from its own HORS and WBNB balances, with no prior liquidity.

3. **Verified sources for HORS, WBNB, and the HORS/WBNB PancakePair**  
   - Confirm that these contracts implement standard ERC20 and PancakeSwap logic without nonstandard hooks or vulnerabilities exercised in this incident.

4. **Pre-incident helper and pair address histories**  
   - Provide the context that helper `0x6f3390…eaba` and pair `0xd5868…8c70` do not receive third-party LP that is later burned in the seed transaction.

### Final Classification

Based on the end-to-end transaction traces, contract source review, and ACT checklist:

- The incident is **not an ACT exploit**.  
- The LP position burned in the seed transaction is **helper-owned** and was minted from helper-held HORS and WBNB.  
- The adversary’s profit is a result of withdrawing helper-provided liquidity and structuring the withdrawal via a flash loan to optimize capital usage, not from abusing a protocol bug or expropriating third-party funds.

The finalized classification is therefore:

> **Non-ACT, helper-owned HORS/WBNB LP withdrawal on BNB Chain, with ~14.7978 WBNB profit to EOA 0x8efb…5df via a flash-loan-assisted liquidity removal.**

