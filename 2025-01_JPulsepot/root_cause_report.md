## FortuneWheel BNBP/Link Price-Manipulation Fee Drain on BSC

### 1. Incident Overview & TL;DR

**Protocol and context.** The FortuneWheel contract on BSC is a casino-style game that maintains per-casino liquidity in BNBP, BNB, and other ERC20 tokens. It uses Chainlink VRF for randomness and periodically swaps accumulated fees into BNBP and LINK to fund the game and its VRF subscription.

**High-level incident summary.** In block **45640246** on BSC (chainid 56), an unprivileged adversary EOA `0xf1e73123594cb0f3655d40e4dd6bde41fa8806e8` deployed a helper contract, took a large **WBNB flash loan** from a Pancake V3 pool, and **temporarily distorted AMM prices** in the WBNB–BEP20LINK and BNBP–WBNB pools. While these pools were manipulated, the helper contract externally called **`FortuneWheel.swapProfitFees()`** on `0x384b9fb6E42dab87F3023D87ea1575499A69998E`. Because this function relies directly on **PancakeRouter spot prices** (`getAmountsIn` / `getAmountsOut`) and can draw additional casino liquidity when fees are insufficient, it **over-consumed FortuneWheel’s BNBP and BNB liquidity** under the attacker-chosen price configuration. The subsequent swaps and VRF funding flows left the adversary’s helper contract with a large **net WBNB surplus**; **30.968 WBNB** was immediately forwarded to the EOA, and the remainder stayed on the helper.

**Root cause (brief).** The fundamental bug is **protocol-level price manipulation in a public fee-swap routine**. `swapProfitFees()`:
- Is **publicly callable** (no owner or role gating).
- Uses **manipulable AMM spot prices** via `PancakeRouter.getAmountsIn` / `getAmountsOut` to compute how much token value is needed to fund LINK.
- Is allowed to **draw from casino principal liquidity** when fee balances are insufficient to cover LINK costs.

Under a flash-loan-induced price distortion, an adversary can deterministically force FortuneWheel to swap an attacker-chosen amount of its liquidity into LINK and BNB in a way that ultimately increases the adversary’s WBNB holdings.

### 2. Key Background

**FortuneWheel design.**
- FortuneWheel tracks per-casino state in a `tokenIdToCasino` mapping, including `liquidity`, `roundLiquidity`, `locked`, `fee`, `profit`, and LINK consumption via `linkSpent[tokenId]`.
- Players place bets in BNBP/BNB/other tokens; outcomes are selected using Chainlink VRF and winnings are paid out, updating casino profit and liquidity.
- To periodically fund Chainlink VRF and route game fees, the contract exposes `swapProfitFees()`, which:
  - Computes the **available profit** for each casino.
  - Splits that profit into a **game fee** and a **LINK funding portion** based on `linkSpent` and PancakeRouter prices.
  - If necessary, draws from **casino liquidity** when fee balances are insufficient to cover LINK costs.
  - Swaps non-BNB/non-BNBP tokens to BNB, then BNB into LINK and BNBP.
  - Bridges LINK via PegSwap into ERC677 LINK and funds the Chainlink VRF coordinator.

**Helper contract role.**
- The helper contract `0x818CD70bE0C9DEC3B0bc52eFAACEb06469Ce587F` is **not** a public protocol component. Its decompiled source shows:
  - Generic call/withdraw primitives gated by a single privileged owner (`tx.origin` check).
  - A `claimToken(address token)` function that transfers the **entire token balance** of `token` to the owner.
- This design makes `0x818C…` an **adversary-controlled vault** for aggregating profits from attack scripts.

**AMM environment.**
- Relevant on-chain liquidity comes from:
  - **Pancake V3 pool** `0x172fcD41E0913e95784454622d1c3724f546f849` (WBNB-based).
  - **WBNB–BEP20LINK V2 pair** `0x824eb9faDFb377394430d2744fa7C42916DE3eCe`.
  - **BNBP–WBNB V2 pair** `0x4C736d24d72D874cc2465553500c1Ff3Fc7b3BDA`.
- Their reserves can be **manipulated intra-block** using flash loans and large swaps. Because FortuneWheel relies on PancakeRouter spot prices from these pools, reserve manipulation directly affects LINK and fee accounting.

**Code evidence – FortuneWheel fee-swap and price usage.**

The FortuneWheel source (verified and collected) shows `swapProfitFees()` as a public function with no access control, and price helpers that rely on PancakeRouter:

```solidity
// FortuneWheel fee-swap and price helpers (FortuneWheel.sol)
function getTokenAmountForLink(address tokenAddr, uint256 linkAmount) public view returns (uint256) {
    IPancakeRouter02 router = IPancakeRouter02(pancakeRouterAddr);
    address[] memory path;
    if (tokenAddr == address(0) || tokenAddr == wbnbAddr) {
        path = new address[](2);
        path[0] = wbnbAddr;
        path[1] = linkTokenAddr;
    } else {
        path = new address[](3);
        path[0] = tokenAddr;
        path[1] = wbnbAddr;
        path[2] = linkTokenAddr;
    }
    return router.getAmountsIn(linkAmount, path)[0];
}

function getLinkAmountForToken(address tokenAddr, uint256 tokenAmount) public view returns (uint256) {
    IPancakeRouter02 router = IPancakeRouter02(pancakeRouterAddr);
    address[] memory path;
    bool isBNB = tokenAddr == address(0) || tokenAddr == wbnbAddr;
    if (isBNB) {
        path = new address[](2);
        path[0] = wbnbAddr;
        path[1] = linkTokenAddr;
    } else {
        path = new address[](3);
        path[0] = tokenAddr;
        path[1] = wbnbAddr;
        path[2] = linkTokenAddr;
    }
    return router.getAmountsOut(tokenAmount, path)[isBNB ? 1 : 2];
}
```

*Snippet origin: Collected FortuneWheel source for contract `0x384b9f…`, demonstrating direct reliance on PancakeRouter AMM spot prices.*

### 3. ACT Opportunity: Pre-State, Transaction, and Profit Predicate

**Pre-state σ_B at block 45640246.**
- Pre-state definition: BSC mainnet state immediately before inclusion of the exploit transaction:
  - FortuneWheel contract: `0x384b9fb6E42dab87F3023D87ea1575499A69998E`.
  - Helper contract: `0x818CD70bE0C9DEC3B0bc52eFAACEb06469Ce587F`.
  - Pancake V3 pool: `0x172fcD41E0913e95784454622d1c3724f546f849`.
  - Pancake V2 pairs: `0x824eb9faDFb377394430d2744fa7C42916DE3eCe` (WBNB–BEP20LINK), `0x4C736d24d72D874cc2465553500c1Ff3Fc7b3BDA` (BNBP–WBNB).
  - PegSwap: `0x1FCc3B22955e76Ca48bF025f1A6993685975Bb9e`.
  - Chainlink LINK/VRF contracts: BEP20LINK `0xF8A0BF9cF54Bb92F17374d9e9A321E6a111a51bD`, LINK677 `0x404460C6A5EdE2D891e8297795264fDe62ADBB75`, VRF coordinator `0xc587d9053cd1118f25F645F9E08BB98c9712A4EE`.
  - Attacker EOA: `0xf1e73123594cb0f3655d40e4dd6bde41fa8806e8`.
- This pre-state is reconstructed from:
  - Tx metadata.
  - Full execution trace.
  - Balance diffs.
  - `prestateTracer`-based state diff for FortuneWheel.

**Transaction sequence B.**
- There is a single relevant transaction:
  - Chain: BSC (56).
  - Hash: `0xd6ba15ecf3df9aaae37450df8f79233267af41535793ee1f69c565b50e28f7da`.
  - Role: **adversary-crafted**.
  - Inclusion feasibility:
    - Standard EIP-1559-style tx from the unprivileged EOA `0xf1e7…`.
    - Deploys an attack helper/entry contract and calls **only public interfaces**:
      - Pancake V3/V2 pools.
      - WBNB, BNBP, BEP20LINK.
      - FortuneWheel `swapProfitFees()`.
      - PegSwap and Chainlink LINK/VRF contracts.
    - No admin keys or whitelists are required; gas price and limit are within normal ranges.
  - High-level notes:
    1. Borrow a large WBNB flash loan from Pancake V3 pool `0x172f…`.
    2. Manipulate WBNB–BEP20LINK and BNBP–WBNB reserves via swaps.
    3. Call `FortuneWheel.swapProfitFees()` while prices are distorted so it over-consumes casino liquidity and LINK reserves.
    4. Unwind positions and route the resulting WBNB surplus through helper `0x818C…` back to the EOA.

**Exploit predicate (profit).**
- Type: **profit-based ACT**.
- Reference asset: **WBNB**.
- Adversary address: EOA `0xf1e73123594cb0f3655d40e4dd6bde41fa8806e8`, jointly analyzed with helper `0x818C…` as an adversary cluster.
- Fees paid in reference asset:
  - Flash-loan fee of **4.3e17 WBNB** repaid to Pancake V3 pool `0x172f…` (difference between 4.3e21 WBNB borrowed and 4.30043e21 WBNB repaid).
  - Approximately **0.001770583 BNB** spent on gas by the EOA, as shown by native balance diffs.
- Portfolio value before/after:
  - `value_before_in_reference_asset`: **unknown** (the initial WBNB holdings of the cluster are not fully reconstructed).
  - `value_after_in_reference_asset`: **unknown** for the same reason.
- Deterministic value delta:
  - The **net WBNB change per transaction** is deterministically computed from WBNB `Transfer` logs involving either:
    - EOA `0xf1e7…`, or
    - Helper `0x818C…`.
  - There are **exactly six WBNB::transfer events** touching this cluster in the trace:
    - Flash loan from V3 pool to helper.
    - Swap-related WBNB flows into/out of the helper via router and WBNB–LINK pair.
    - Flash-loan repayment to the V3 pool.
    - Final WBNB payout from helper to EOA.
  - Aggregating external inflows and outflows (treating helper + EOA as a single cluster), the **net cluster inflow is**:
    - `+4.314136937387847602508e21 wei` = **+4314.136937387847602508 WBNB**.
  - Native gas is paid in BNB and is several orders of magnitude smaller than this delta, so the **adversary’s WBNB-denominated portfolio value strictly increases** in this transaction.

**Trace evidence – WBNB flows.**

```text
// Key WBNB transfers touching the adversary cluster (cast trace)
WBNB::transfer(0x818C…, 4300000000000000000000 [4.3e21])            // flash-loan in from V3 pool
WBNB::transfer(PancakeRouter: 0x10ED…, 16831183026189930161)        // helper -> router during swaps
WBNB::transfer(0x818C…, 4331398120414037532669 [4.331e21])          // WBNB–LINK pair -> helper
WBNB::transfer(PancakeV3Pool: 0x172f…, 4300430000000000000000)      // helper -> pool (principal + fee)
WBNB::transfer(0xf1e7…, 30968120414037532669 [3.096e19])            // helper -> EOA payout
```

*Snippet origin: Seed transaction trace (`trace.cast.log`) for tx `0xd6ba15…`, highlighting WBNB flows to and from the adversary cluster.*

### 4. Vulnerability & Root Cause Analysis

**Vulnerability brief.**  
`swapProfitFees()` is a **public** fee-swap routine that:
- Uses **spot AMM prices** from PancakeRouter (`getAmountsIn` / `getAmountsOut`) as an on-chain oracle for how much token value is needed for LINK funding.
- Can **draw from principal casino liquidity** when accumulated profit alone does not cover the computed LINK cost.

Under flash-loan manipulation of the underlying AMM pools, this logic allows an adversary to **force an oversized conversion of FortuneWheel’s liquidity into LINK and BNB**, generating a deterministic profit in WBNB for an adversary-controlled account.

**Detailed root-cause mechanics.**

1. **Per-casino profit and fee computation.**
   - For each `tokenId` in `tokenIdToCasino`:
     - `availableProfit` is `max(casino.profit, 0)` but capped at `casino.liquidity`.
     - `gameFee` starts as `availableProfit * casino.fee / 100`.
     - `amountForLinkFee` is computed via `getTokenAmountForLink(casino.tokenAddress, linkSpent[i])`, which uses PancakeRouter spot prices.

2. **Liquidity top-up when fees are insufficient.**
   - If `gameFee < amountForLinkFee`, the function **directly draws the shortfall from `casino.liquidity`**:
     - If liquidity is insufficient, it can effectively **zero out the casino’s liquidity** for that token.
     - Otherwise, liquidity is reduced by `(amountForLinkFee - gameFee)`.
   - `_updateProfitInfo()` then adjusts `casino.liquidity`, `casino.profit`, and `lastSwapTime`, while `_updateLinkConsumptionInfo()` uses `getLinkAmountForToken()` to adjust `linkSpent`.

3. **Swapping casino tokens into BNB, LINK, and BNBP.**
   - For non-BNB tokens:
     - `swapProfitFees()` approves PancakeRouter and calls `swapExactTokensForETH(gameFee + amountForLinkFee, ...)` using a `[token, WBNB]` path.
     - The resulting BNB is conceptually split between:
       - **Game fees** (`totalBNBForGame`).
       - **LINK funding** (`totalBNBForLink`).
   - After processing all casinos:
     - If `totalBNBForLink > 0`, it calls `swapExactETHForTokens` on path `[WBNB, LINK]` to buy LINK, then:
       - Approves PegSwap.
       - Calls PegSwap to convert BEP20LINK into ERC677 LINK.
       - Calls `LinkTokenInterface(link677TokenAddr).transferAndCall(coordinatorAddr, linkAmount, ...)` to fund the Chainlink VRF subscription.
     - If `totalBNBForGame > 0`, it swaps BNB into BNBP and passes the resulting BNBP into a tokenomics pool via `addAdminTokenValue`.

4. **Public exposure and oracle misuse.**
   - `swapProfitFees()` is declared `external` and has **no `onlyOwner` or `onlyCasinoOwner` modifier**, making it **publicly callable by any account** at any time.
   - `getTokenAmountForLink()` and `getLinkAmountForToken()` use **current AMM reserves** (via PancakeRouter) without TWAPs, sanity bounds, or manipulation checks.
   - The function **does not distinguish** between protocol-owned fee reserves and user or LP principal; when LINK funding appears expensive under manipulated prices, it is willing to **burn casino liquidity** to meet perceived LINK obligations.

5. **How this becomes exploitable.**
   - An adversary with access to flash loans can:
     1. Borrow WBNB from a deep pool (Pancake V3).
     2. Use large swaps through WBNB–LINK and BNBP–WBNB pairs to **skew reserves**.
     3. Call `swapProfitFees()` while pool prices are skewed, so `amountForLinkFee` is calculated under attacker-chosen prices.
     4. Cause `swapProfitFees()` to:
        - Pull substantial liquidity from FortuneWheel.
        - Swap it via manipulated pools.
        - Fund LINK and BNBP as usual, but leave a **residual WBNB surplus** along the attack path.
     5. Repay the flash loan and keep the leftover WBNB as profit.

**Evidence from the seed transaction.**
- The collected trace for tx `0xd6ba15…` shows:
  - A **flash loan** of `4.3e21` WBNB from Pancake V3 pool `0x172f…` to helper `0x818C…`.
  - Swaps via PancakeRouter and the WBNB–BEP20LINK pair `0x824e…` that significantly distort pool reserves.
  - An external call to **`FortuneWheel.swapProfitFees()`** from the helper contract.
  - Within `swapProfitFees()`:
    - BNBP approval and a transfer of **`3.659785525e22` BNBP** from FortuneWheel into the BNBP–WBNB pair `0x4C736d…`.
    - Swaps that convert this BNBP into WBNB and eventually into BEP20LINK.
    - A **17.6004 BNB** outflow from FortuneWheel to the WBNB contract, used to buy additional LINK for VRF funding.
  - LINK is bridged through PegSwap to ERC677 LINK and supplied to the VRF coordinator, while FortuneWheel’s internal LINK accounting (`linkSpent` and related storage slots) is updated accordingly.

### 5. Adversary Flow Analysis

**Adversary strategy summary.**  
A **single-transaction** attack using:
- A WBNB flash loan to gain temporary deep buying power.
- Price manipulation of WBNB–LINK and BNBP–WBNB AMM pools.
- A public, oracle-driven fee-swap (`swapProfitFees()`) that trusts these manipulated prices.
- An adversary-controlled helper contract to aggregate profits and forward them to the EOA.

**Adversary-related accounts.**
- **EOA (attacker origin):**
  - Address: `0xf1e73123594cb0f3655d40e4dd6bde41fa8806e8`.
  - Role:
    - Originator of the seed transaction.
    - Pays gas (native balance delta: `-0.001770583 BNB`).
    - Deploys the helper/entry contract.
    - Receives **`3.0968120414037532669e19` wei (~30.968 WBNB)** as a direct payout at the end of the tx.
- **Helper contract (adversary vault):**
  - Address: `0x818CD70bE0C9DEC3B0bc52eFAACEb06469Ce587F`.
  - Role in the trace:
    - Receives the **4.3e21 WBNB flash loan**.
    - Interacts with PancakeRouter and AMM pairs to manipulate prices and route swaps.
    - Accumulates a **net inflow of +4.314136937387847602508e21 WBNB** from all external addresses.
    - Transfers `3.0968120414037532669e19` WBNB to the EOA, with no WBNB outflows from the EOA.
  - Decompiled behavior:
    - Owner-gated `claimToken(token)` that transfers full token balances to a privileged address.
    - Generic call/withdraw primitives that allow the owner to script arbitrary token movements.
    - Confirms the contract is an **adversary-controlled vault**, not a user-facing protocol component.

**Victim candidates.**
- **FortuneWheel casino contract:**
  - Address: `0x384b9fb6E42dab87F3023D87ea1575499A69998E`.
  - Verified source and ABI collected.
  - Loses BNBP and BNB liquidity through `swapProfitFees()` under manipulated prices.
- **BNBP–WBNB Pancake V2 pair:**
  - Address: `0x4C736d24d72D874cc2465553500c1Ff3Fc7b3BDA`.
  - Receives **`3.659785525e22` BNBP** from FortuneWheel and swaps it into WBNB.
- **WBNB–BEP20LINK Pancake V2 pair:**
  - Address: `0x824eb9faDFb377394430d2744fa7C42916DE3eCe`.
  - Loses **`1.6278878565747828785e19` BEP20LINK**, which is routed via PegSwap into ERC677 LINK.
- **PegSwap / Chainlink infrastructure:**
  - PegSwap: `0x1FCc3B22955e76Ca48bF025f1A6993685975Bb9e`.
  - LINK677: `0x404460C6A5EdE2D891e8297795264fDe62ADBB75`.
  - VRF coordinator: `0xc587d9053cd1118f25F645F9E08BB98c9712A4EE`.
  - Receive LINK funding as part of normal VRF operations; they are system components, not adversary-controlled.

**Lifecycle stages of the exploit.**

1. **Flash loan and price priming.**
   - The helper contract invokes **Pancake V3 flash** to borrow `4.3e21` WBNB from pool `0x172f…`.
   - Using PancakeRouter `swapExactTokensForTokensSupportingFeeOnTransferTokens`, the helper routes WBNB through the WBNB–BEP20LINK pair `0x824e…`, distorting the spot price and reserves.
   - This setup skews the inputs to `getTokenAmountForLink()` and `getLinkAmountForToken()` that will be used by `swapProfitFees()`.
   - Evidence:
     - `trace.cast.log` shows the flash loan, WBNB transfers, and WBNB–LINK swaps.
     - WBNB pre/post storage entries reflect the transient WBNB movements.

2. **`swapProfitFees()` execution under manipulated prices.**
   - With AMM reserves distorted, the helper triggers `FortuneWheel.swapProfitFees()`:
     - The function calls `getTokenAmountForLink()` and `getLinkAmountForToken()` against manipulated AMM reserves.
     - For at least one BNBP-based casino, it computes a **large `amountForLinkFee`**, then:
       - Invokes `_updateProfitInfo()` to reduce `casino.liquidity` and `casino.profit`.
       - Invokes `_updateLinkConsumptionInfo()` to adjust `linkSpent`.
     - Approves **`3.659785525e22` BNBP** to PancakeRouter and swaps it into WBNB via the BNBP–WBNB pair `0x4C736d…`.
     - Uses the resulting WBNB plus **17.6004 BNB** of FortuneWheel’s own BNB (sent to WBNB) to buy LINK and bridge it for VRF funding.
   - State diffs show:
     - Decreases in `casino.liquidity` and related fields.
     - Updates at LINK-related storage keys (`linkSpent` and VRF funding counters).

3. **Unwind, repayment, and profit realization.**
   - After `swapProfitFees()`:
     - The helper repays the flash loan principal plus fee (**4.30043e21 WBNB**) to the V3 pool.
     - It retains a substantial residual WBNB balance arising from:
       - The manipulated casino fee-swap.
       - AMM price differences between manipulated and unmanipulated states.
     - It transfers **`3.0968120414037532669e19` wei (~30.968 WBNB)** to the EOA `0xf1e7…`.
   - Across all WBNB transfers touching the cluster, the net external inflow is **+4314.136937387847602508 WBNB**, even after subtracting the flash-loan fee.
   - No WBNB `Transfer` events show outflows from the EOA, so the **cluster’s WBNB position strictly increases**.

### 6. Impact & Losses

**Token-level loss overview (per transaction 0xd6ba15…).**
- **WBNB:** net gain of **4314.136937387847602508 WBNB** for the adversary cluster (helper + EOA), computed from WBNB `Transfer` logs and prestate-based accounting.
- **BNBP:** FortuneWheel sends **`3.659785525e22` BNBP** into the BNBP–WBNB pair `0x4C736d…`, corresponding to **36,597.85525 BNBP** when expressed in token units.
- **BEP20LINK / LINK (BEP20 → ERC677):**
  - The WBNB–BEP20LINK pair `0x824e…` loses **`1.6278878565747828785e19` BEP20LINK**.
  - This LINK is routed via PegSwap and ends up as ERC677 LINK at the VRF coordinator.
  - The total LINK bridged and supplied is **16.278878565747828785 LINK**.

**Qualitative impact.**
- Within the single exploit transaction:
  - The adversary cluster’s WBNB holdings increase by **~4,314.13 WBNB**, net of flash-loan fees and gas.
  - FortuneWheel’s casino state shows:
    - Reduced `liquidity` and `profit` entries for affected casinos.
    - A **17.6004 BNB** outflow to WBNB used for LINK purchases.
  - The BNBP–WBNB AMM pair sees a **large BNBP inflow** from FortuneWheel that is immediately swapped into WBNB.
  - The WBNB–BEP20LINK pair loses LINK that is bridged to the Chainlink VRF ecosystem.
- **Loss attribution.**
  - The precise economic split between:
    - FortuneWheel protocol stakeholders (casino owners / treasury), and
    - External liquidity providers (BNBP–WBNB and WBNB–LINK LPs),
    depends on off-chain information (e.g., who supplied which liquidity and current fiat prices).
  - However, on-chain data is sufficient to conclude that:
    - **Protocol-controlled casino liquidity and AMM liquidity were consumed** in a way that made the adversary cluster strictly wealthier in WBNB terms.

### 7. References

- **[1] Seed transaction trace.**  
  Full `cast`-style execution trace for tx `0xd6ba15ecf3df9aaae37450df8f79233267af41535793ee1f69c565b50e28f7da` on BSC, including all internal calls, events, and storage changes for FortuneWheel, WBNB, BNBP, BEP20LINK, AMM pools, PegSwap, and Chainlink VRF.

- **[2] FortuneWheel source and ABI.**  
  Verified Solidity source and ABI for `0x384b9fb6E42dab87F3023D87ea1575499A69998E`, showing the implementation of `swapProfitFees()`, `getTokenAmountForLink()`, `getLinkAmountForToken()`, casino accounting structures, and LINK consumption tracking.

- **[3] FortuneWheel prestateTracer state diff.**  
  Pre/post state diff for FortuneWheel in the seed transaction, highlighting changes in `liquidity`, `profit`, LINK-related storage slots (`linkSpent`), and VRF funding counters.

- **[4] Extended prestate-based balance diff.**  
  Per-address balance diffs (including WBNB and other tokens) around tx `0xd6ba15…`, used to cross-check WBNB and LINK movements and native BNB gas expenditure.

- **[5] Helper contract decompiled source.**  
  Heimdall decompilation of helper contract `0x818C…`, demonstrating its owner-gated `claimToken` function and generic call/withdraw capabilities, confirming its role as a private adversary vault rather than a public protocol contract.

