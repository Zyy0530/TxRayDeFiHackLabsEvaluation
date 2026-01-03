# Peapods WeightedIndex/PEAS MEV Arbitrage at Block 21800591

## 1. Incident Overview & TL;DR

- **Protocol:** Peapods WeightedIndex (index token `0x88e0…1ca4`) with TokenRewards module `0x7d48…bf9Eb` and PEAS token `0x02f9…2f875`.
- **Block:** Ethereum mainnet block **21800591**.
- **Adversary EOA:** `0xedee6379fE90bD9B85d8d0B767d4a6deB0DC9dcF`.
- **Helper/router contract:** `0x21B1b6D675aAE57684139200650c81a3686F5fc4`.
- **Core AMM venues:**
  - Uniswap V2 pair `0x80e9C48e…1608` (WeightedIndex / PAIRED_LP_TOKEN).
  - Uniswap V3 pool `0x5207BC61…dF02E` (WeightedIndex / PEAS).

At block 21800591, the EOA `0xedee…` used helper contract `0x21B1…` to execute a flash-like arbitrage between the Peapods WeightedIndex/PAIRED_LP Uniswap V2 pair and the WeightedIndex/PEAS Uniswap V3 pool. The seed transaction:

- Flash-borrowed **9.42e21** WeightedIndex from the V2 pair.
- Swapped WeightedIndex → PEAS → WeightedIndex through the V3 pool.
- Repaid the V2 pair and left a **residual 141.113923030647830889 WeightedIndex** at `0x21B1…`.
- Transferred this residual to the caller `0xedee…` as arbitrage profit.

A same-block funding transaction from `0x9522…bafe5` to `0xedee…` provides additional ETH, giving the EOA a net ETH gain as well. All interactions are with public AMM and protocol contracts; there is **no invariant break or access-control failure** in Peapods contracts. The root cause is a **permissionless MEV arbitrage ACT opportunity**, not a protocol bug.

## 2. Key Background

### 2.1 Peapods WeightedIndex

- **WeightedIndex token (`0x88e0…1ca4`)** is an ERC20-based index fund implemented in `DecentralizedIndex.sol` and `WeightedIndex.sol`.
- It maintains a primary Uniswap V2 pair against a **PAIRED_LP_TOKEN** (`0x80e9…1608`).
- Fees on index operations are accumulated at the index contract and periodically converted via Uniswap V2 into PAIRED_LP_TOKEN, which is then routed into the rewards module.

### 2.2 TokenRewards (Rewards Module)

- **TokenRewards contract (`0x7d48…bf9Eb`)** is configured with:
  - `trackingToken = WeightedIndex`.
  - `rewardsToken = PEAS`.
  - `PAIRED_LP_TOKEN` as the intermediate asset from the index fund.
- When fees accrue, `TokenRewards.depositFromPairedLpToken`:
  - Swaps PAIRED_LP_TOKEN to PEAS through a Uniswap V3 pool using TWAP utilities.
  - Burns a portion of the PEAS as protocol yield.
  - Deposits the remainder as claimable rewards for WeightedIndex holders.

Relevant reward-handling logic:

```solidity
// TokenRewards.sol — rewards deposition and burn
function _depositRewards(uint256 _amountTotal) internal {
  if (_amountTotal == 0) {
    return;
  }
  if (totalShares == 0) {
    _burnRewards(_amountTotal);
    return;
  }

  uint256 _depositAmount = _amountTotal;
  (, uint256 _yieldBurnFee) = _getYieldFees();
  if (_yieldBurnFee > 0) {
    uint256 _burnAmount = (_amountTotal * _yieldBurnFee) /
      PROTOCOL_FEE_ROUTER.protocolFees().DEN();
    if (_burnAmount > 0) {
      _burnRewards(_burnAmount);
      _depositAmount -= _burnAmount;
    }
  }
  rewardsDeposited += _depositAmount;
  rewardsDepMonthly[beginningOfMonth(block.timestamp)] += _depositAmount;
  _rewardsPerShare += (PRECISION * _depositAmount) / totalShares;
  emit DepositRewards(_msgSender(), _depositAmount);
}
```

*Caption: TokenRewards logic showing PEAS burns and distribution to WeightedIndex holders; the arbitrage interacts with this flow but does not break it.*

### 2.3 AMM Pools and Helper Router

- **Uniswap V2 pair `0x80e9…1608`** holds liquidity for the WeightedIndex/PAIRED_LP pair.
- **Uniswap V3 pool `0x5207…dF02E`** holds liquidity for WeightedIndex/PEAS.
- Prices on these pools can diverge under normal trading.
- **Helper contract `0x21B1…5fc4`** is an unverified router that:
  - Initiates a flash-like swap from the V2 pair.
  - Routes tokens through Uniswap V3 swaps.
  - Interacts with WeightedIndex and TokenRewards to structure multi-step trades.

## 3. ACT Opportunity & Root Cause Analysis

### 3.1 ACT Metadata

- **is_act:** `"true"` — this is an ACT-style opportunity.
- **root_cause_category:** `"mev"` — opportunity arises from MEV-style arbitrage.
- **Block height σ₍ᴮ₎:** `21800591`.

The relevant pre-state includes:

- WeightedIndex token `0x88e0…1ca4`.
- TokenRewards/index contract `0x7d48…bf9Eb`.
- Helper/router `0x21B1…5fc4`.
- Uniswap V2 pair `0x80e9…1608` (WeightedIndex/PAIRED_LP).
- Uniswap V3 pool `0x5207…dF02E` (WeightedIndex/PEAS).
- PEAS token `0x02f9…2f875`.

This state is inferred from:

- Seed tx metadata and iter_1 seed trace (`cast run`).
- Extended prestate balance diffs for the seed tx.
- Verified sources for WeightedIndex, TokenRewards, and PEAS.

### 3.2 Transaction Sequence b

Sequence **b** consists of two Ethereum mainnet transactions in block 21800591:

1. **Seed (adversary-crafted) transaction**
   - **Tx hash:** `0x2c1a1998…86cc5`.
   - **Type:** EIP-1559 (type-2) tx from EOA `0xedee…` to helper `0x21B1…`.
   - **Inclusion feasibility:** Standard public call to a router; no special privileges required; any EOA can submit such a tx using the same parameters and public contracts.
   - **Behavior (high level):**
     - Flash-borrows WeightedIndex from the V2 pair `0x80e9…`.
     - Swaps WeightedIndex → PEAS in the V3 pool `0x5207…`.
     - Swaps PEAS → WeightedIndex in the same pool.
     - Routes PEAS into TokenRewards `0x7d48…` for burning and rewards.
     - Repays the V2 pair and leaves a residual **141.1139** WeightedIndex at `0x21B1…`, which is then sent to `0xedee…`.

2. **Funding (victim-observed) transaction**
   - **Tx hash:** `0xf003685f…8dbe8`.
   - **From:** high-activity address `0x95222290dd7278aa3ddd389cc1e1d165cc4bafe5`.
   - **To:** `0xedee…`.
   - **Type:** Simple ETH transfer with no calldata.
   - **Effect:** Sends `3,513,546,707,507,229` wei to `0xedee…` in the same block.
   - **Net ETH P/L for `0xedee…` across b:** `+2,856,208,385,972,661` wei after accounting for gas in both txs.

The funding tx is not required to realize the WeightedIndex arbitrage profit but contributes to the overall ETH P/L of the adversary.

### 3.3 Exploit Predicate (Profit)

The ACT exploit predicate is purely **profit-based**:

- **Type:** `profit`.
- **Reference asset:** `PEAS`.
- **Adversary address:** `0xedee…`.
- **Value before / after (in PEAS-equivalent):** Not fully reconstructed from all holdings; instead, the analysis computes a rigorous **lower bound** on ΔP/L.

#### 3.3.1 PEAS-Denominated Profit Lower Bound

From the seed tx trace, we observe a SwapRouter `exactInputSingle`:

- **Input:** `9.42e21` WeightedIndex.
- **Output:** `1.7022705134013541201301e22` PEAS.

This implies a contemporaneous spot price:

- **Price:** ≈ `1.7751476082569814388` PEAS per WeightedIndex.

Later in the same transaction, the helper contract receives:

- `9.589458958135963778733e21` WeightedIndex from the V3 pool.
- It repays `9.448345035105315947844e21` WeightedIndex to the V2 pair.
- The difference, **`141.113923030647830889` WeightedIndex**, remains at `0x21B1…` and is then transferred to `0xedee…`.

Valuing this residual at the observed price gives:

- **Adversary WeightedIndex profit:**  
  `141.113923030647830889` WI ≈ `2.50498042959614266673e20` PEAS-equivalent.

In addition:

- `0xedee…` has a net ETH gain of **`+2,856,208,385,972,661` wei** across sequence b.
- This ETH component is not converted into PEAS units in the report but is strictly positive in any reasonable valuation.

Thus, the exploit predicate is satisfied with:

- **ΔP/L (reference PEAS):** ≥ `2.50498042959614266673e20` PEAS-equivalent from WeightedIndex alone, plus positive ETH.

#### 3.3.2 Seed Tx Trace Evidence

The critical token transfer to the adversary is visible in the seed transaction trace:

```text
// Seed transaction trace (cast run) for tx 0x2c1a1998...86cc5
├─ [601] WeightedIndex::balanceOf(0x21B1b6D675aAE57684139200650c81a3686F5fc4)
│   └─ ← [Return] 141113923030647830889 [1.411e20]
├─ [26599] WeightedIndex::transfer(0xeDee6379fE90bD9B85d8d0B767d4a6deB0DC9dcF, 141113923030647830889 [1.411e20])
│   ├─ emit Transfer(from: 0x21B1b6D675aAE57684139200650c81a3686F5fc4, to: 0xeDee6379fE90bD9B85d8d0B767d4a6deB0DC9dcF, value: 141113923030647830889 [1.411e20])
│   ├─  storage changes:
│   │   @ 0x37c16e86ce...: 0 → 0x000000...000007a6595d57bf93f969
│   │   @ 0xd35f40257c...: 0x000000...000007a6595d57bf93f969 → 0
│   └─ ← [Return] true
```

*Caption: Seed transaction trace showing 141.1139 WeightedIndex transferred from helper `0x21B1…` to EOA `0xedee…`, establishing the core arbitrage profit.*

### 3.4 Token Flow Reconstruction & P/L Consistency

Using the iter_1 trace together with the extended prestate balance diffs, the analysis reconstructs the full token flow.

#### 3.4.1 Extended Balance Diffs (Seed Tx)

The extended QuickNode prestate balance diff for the seed tx shows the key ERC20 balance changes:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x88e08adb69f2618adf1a3ff6cc43c671612d1ca4",
      "holder": "0x80e9c48ec41af7a0ed6cf4f3ac979f3538021608",
      "delta": "28345035105315947844"
    },
    {
      "token": "0x88e08adb69f2618adf1a3ff6cc43c671612d1ca4",
      "holder": "0x5207bc61c2717ee9c385b93d3b8beea159ddf02e",
      "delta": "187432717264951835705"
    },
    {
      "token": "0x88e08adb69f2618adf1a3ff6cc43c671612d1ca4",
      "holder": "0xc64bc02594ba7f777f26b7a1eec6e6dc4a56362b",
      "delta": "18783772389521874444"
    },
    {
      "token": "0x02f92800f57bcd74066f5709f1daa1a4302df875",
      "holder": "0x5207bc61c2717ee9c385b93d3b8beea159ddf02e",
      "delta": "-192905158021960896382"
    },
    {
      "token": "0x02f92800f57bcd74066f5709f1daa1a4302df875",
      "holder": "0x7d48d6d775fada207291b37e3eaa68cc865bf9eb",
      "delta": "183259900120862851563"
    }
  ]
}
```

*Caption: Extended balance diff for the seed transaction showing net WeightedIndex and PEAS movements among the V2 pair, V3 pool, TokenRewards, and stakeholder `0xC64b…`. Adversary and helper balances are obtained from the trace storage changes.*

Together with the trace, this reveals:

- V2 pair `0x80e9…` net **+2.8345035105315947844e19** WeightedIndex.
- V3 pool `0x5207…` net **+1.87432717264951835705e20** WeightedIndex and **−1.92905158021960896382e20** PEAS.
- TokenRewards `0x7d48…` net **−3.75675447790437488882e20** WeightedIndex and **+1.83259900120862851563e20** PEAS.
- `0xC64b…` net **+1.8783772389521874444e19** WeightedIndex (stakeholder distribution).
- `0xedee…` net **+1.41113923030647830889e20** WeightedIndex (from helper, per trace).

Converting all WeightedIndex deltas to PEAS-equivalent at the observed price and summing P/L across these holders yields a net change equal to the PEAS burned by TokenRewards (≈ `9.645257901098044819e18` PEAS), confirming internal accounting consistency.

#### 3.4.2 ETH Balance Diffs (Seed and Funding Tx)

Native balance diffs show:

- **Seed tx (`0x2c1…86cc5`):**
  - `0xedee…`: `−657,338,321,534,568` wei (gas cost).
  - `0x9522…`: `+678,943,215,912` wei.
- **Funding tx (`0xf003…8dbe8`):**
  - `0xedee…`: `+3,513,546,707,507,229` wei.
  - `0x9522…`: `−3,531,770,468,363,229` wei.

Net for `0xedee…` across b:

- **+2,856,208,385,972,661 wei**, which is a strictly positive ETH component of the adversary’s P/L.

### 3.5 Vulnerability & Root Cause

#### 3.5.1 Vulnerability Brief

There is **no protocol bug** in WeightedIndex, TokenRewards, or PEAS. The arbitrage exploits **economic mispricing** between:

- WeightedIndex/PEAS Uniswap V3 pool (`0x5207…`), and
- WeightedIndex/PAIRED_LP Uniswap V2 pair (`0x80e9…`),

combined with Peapods’ fee-swap and rewards-distribution design. The contracts behave according to their specifications; the opportunity exists because AMM prices can diverge.

#### 3.5.2 Root Cause Detail

Key mechanisms:

- `DecentralizedIndex._processPreSwapFeesAndSwap`:
  - Aggregates index fees and swaps them via Uniswap V2 into PAIRED_LP_TOKEN.
  - Sends resulting PAIRED_LP_TOKEN into TokenRewards.
- `TokenRewards.depositFromPairedLpToken`:
  - Converts PAIRED_LP_TOKEN to PEAS via a Uniswap V3 pool.
  - Splits PEAS into burned yield and distributed rewards.

In the seed transaction:

1. Helper `0x21B1…` calls the V2 pair `0x80e9…` to flash-borrow `9.42e21` WeightedIndex.
2. It approves the V3 SwapRouter and swaps:
   - `9.42e21` WeightedIndex → `1.7022705134013541201301e22` PEAS in the V3 pool.
3. It performs a second V3 swap:
   - `1.7022705134013541201301e22` PEAS → `9.589458958135963778733e21` WeightedIndex.
4. It repays the V2 pair:
   - Sends back `9.448345035105315947844e21` WeightedIndex.
5. The difference:
   - `9.589458958135963778733e21 − 9.448345035105315947844e21 = 1.41113923030647830889e20` WeightedIndex.
6. This residual remains at `0x21B1…` and is then **transferred to `0xedee…`**, as shown in the trace.
7. Simultaneously, TokenRewards `0x7d48…` sends `3.56891675400915614438e20` WeightedIndex to the V3 pool and `1.8783772389521874444e19` WeightedIndex to `0xC64b…`, receiving `1.92905158021960896382e20` PEAS, of which:
   - `9.645257901098044819e18` PEAS are burned as yield.
   - The remainder is retained as rewards.

These flows match:

- The iter_1 call trace (WeightedIndex and PEAS transfers and storage changes).
- The iter_2 extended balance diffs (for holders tracked there).

The arbitrage profit is therefore **sourced from standard AMM mispricing and fee-conversion flows**, not from a mis-accounted balance or unauthorized transfer.

#### 3.5.3 Vulnerable Components (Economic Surface)

- **WeightedIndex token (`0x88e0…1ca4`)**
  - Particularly fee-swap path in `DecentralizedIndex._processPreSwapFeesAndSwap` and `_feeSwap`.
- **TokenRewards/index (`0x7d48…bf9Eb`)**
  - Functions `depositFromPairedLpToken` and `_processFeesIfApplicable`, which convert PAIRED_LP_TOKEN to PEAS and route/burn rewards.
- **Uniswap V2 pair (`0x80e9…1608`)**
  - WeightedIndex/PAIRED_LP AMM where the flash-like swap is initiated and repaid.
- **Uniswap V3 pool (`0x5207…dF02E`)**
  - WeightedIndex/PEAS AMM where the two-leg swap creates and then partially reverses price impact.

#### 3.5.4 Exploit Conditions

To realize the arbitrage, the following must hold:

1. **Price discrepancy:** WeightedIndex/PEAS Uniswap V3 pool and WeightedIndex/PAIRED_LP Uniswap V2 pair price WeightedIndex differently enough that:
   - A loop WeightedIndex → PEAS → WeightedIndex yields more WeightedIndex than required to repay the V2 flash amount and gas.
2. **Sufficient liquidity:** Both pools have sufficient depth for swaps of ~`1e22` token units without collapsing the spread.
3. **TokenRewards configuration:**
   - `trackingToken = WeightedIndex`, `rewardsToken = PEAS`, and a non-zero PEAS burn fee ensure part of the value is burned and part becomes rewards, while still allowing the arbitrage loop to close.
4. **Public access:**
   - Helper router `0x21B1…` is callable by any EOA and interacts only with public contracts.
5. **Timely inclusion:**
   - The adversary can get the seed tx included while the spread exists; the funding tx is an ordinary ETH transfer and not critical to the arbitrage mechanics.

When these conditions are satisfied, **any unprivileged EOA** can replicate the sequence and capture similar profit.

## 4. Adversary Flow Analysis

### 4.1 Adversary and Related Accounts

- **Adversary EOA (ACT adversary cluster):**
  - `0xedee6379fE90bD9B85d8d0B767d4a6deB0DC9dcF`.
  - Crafts and submits the seed transaction.
  - Receives the final 141.1139 WeightedIndex and net ETH gain.
- **Helper/router contract:**
  - `0x21B1b6D675aAE57684139200650c81a3686F5fc4`.
  - Executes flash-like operations and swaps; its net balance returns to zero for the relevant tokens.
  - No evidence from the artifacts that `0xedee…` deploys or controls this contract.
- **Funder address:**
  - `0x95222290dd7278aa3ddd389cc1e1d165cc4bafe5`.
  - Sends ETH to `0xedee…` in a separate, simple transfer.
  - Not clustered with `0xedee…` as an adversary account based on available data.
- **Protocol/AMM contracts:**
  - WeightedIndex index: `0x88e0…1ca4`.
  - TokenRewards/index: `0x7d48…bf9Eb`.
  - Uniswap V2 pair (WeightedIndex/PAIRED_LP): `0x80e9…1608`.
  - Uniswap V3 pool (WeightedIndex/PEAS): `0x5207…dF02E`.
- **Stakeholder / admin address:**
  - `0xC64bc02594bA7F777f26B7a1EeC6E6DC4a56362B`.
  - Receives a portion of WeightedIndex from TokenRewards; consistent with protocol fee routing.

The artifacts do not provide evidence that `0x21B1…`, `0x9522…`, or `0xC64b…` form part of the adversary cluster; the **adversary is identified as `0xedee…` alone**.

### 4.2 Lifecycle Stages

The exploit lifecycle is broken down into:

1. **Setup & State**
   - The system is in normal operating mode:
     - WeightedIndex, TokenRewards, and PEAS are deployed and configured.
     - Uniswap V2 and V3 pools hold liquidity with some price discrepancy between WeightedIndex/PEAS and WeightedIndex/PAIRED_LP.
   - No special preparation tx is required; this is a **one-block opportunity**.

2. **Arbitrage Execution (Seed Tx)**
   - `0xedee…` calls `0x21B1…::574df014`:
     - V2 pair `0x80e9…` flashes 9.42e21 WeightedIndex to `0x21B1…`.
     - `0x21B1…` swaps WeightedIndex → PEAS → WeightedIndex in V3 pool `0x5207…`.
     - TokenRewards `0x7d48…` sends WeightedIndex and receives PEAS, part of which is burned and part retained as rewards.
     - V2 pair is repaid; 141.1139 WeightedIndex remain and are transferred to `0xedee…`.

3. **Post-Arbitrage Holdings**
   - `0xedee…`:
     - WeightedIndex balance increases from 0 to 141.1139 tokens.
     - ETH balance increases by ~`2.8562e15` wei across the full sequence b.
   - TokenRewards `0x7d48…`:
     - Holds fewer WeightedIndex and more PEAS, with a net negative PEAS-equivalent P/L, reflecting burned yield and redistributed rewards.
   - V2 and V3 pools:
     - Reserves update according to standard Uniswap formulas.
   - `0xC64b…`:
     - Gains a modest amount of WeightedIndex consistent with being a protocol stakeholder.

## 5. Impact & Losses

### 5.1 Quantitative Overview (PEAS-Equivalent)

Using the WeightedIndex→PEAS spot price from the seed tx, the analysis computes approximate PEAS-equivalent P/L:

- **Adversary (`0xedee…`):**
  - +`141.113923030647830889` WeightedIndex.
  - ≈ `+2.50498042959614266673e20` PEAS-equivalent.
  - +`2,856,208,385,972,661` wei ETH across sequence b.

- **TokenRewards/index (`0x7d48…`):**
  - WeightedIndex: −`3.75675447790437488882e20`.
  - PEAS: +`1.83259900120862851563e20`.
  - Net ≈ `−4.83619472505202759207e20` PEAS-equivalent.

- **Uniswap V3 pool (`0x5207…`):**
  - WeightedIndex: +`1.87432717264951835705e20`.
  - PEAS: −`1.92905158021960896382e20`.
  - Net ≈ `+1.39815581740025386372e20` PEAS-equivalent.

- **Uniswap V2 pair (`0x80e9…`):**
  - WeightedIndex: +`2.8345035105315947844e19`.
  - Net ≈ `+5.03166212731617808047e19` PEAS-equivalent.

- **Stakeholder `0xC64b…`:**
  - WeightedIndex: +`1.8783772389521874444e19`.
  - Net ≈ `+3.33439686313032805383e19` PEAS-equivalent.

The sum of PEAS-equivalent P/L across these entities equals **minus the PEAS burned** by TokenRewards (`≈9.645257901098044819e18` PEAS), confirming that the valuation is consistent with the protocol’s burn mechanics.

### 5.2 Qualitative Impact

- **Primary effect:** A modest redistribution of value within the Peapods WeightedIndex ecosystem:
  - `0xedee…` gains WeightedIndex and ETH.
  - TokenRewards `0x7d48…` loses some WeightedIndex and gains PEAS, part of which is burned, with the remainder accruing to WeightedIndex holders and protocol stakeholders (including `0xC64b…`).
  - AMM reserves shift according to standard Uniswap pricing.
- **No protocol treasury drain:**
  - No direct outflows from a dedicated treasury wallet beyond what the contracts’ fee and reward logic prescribe.
- **No under-collateralized mint or unauthorized transfer:**
  - The WeightedIndex and PEAS contracts enforce standard ERC20 invariants.
  - No minting or transfer occurs outside documented code paths.
- **Classification:**
  - This event is correctly classified as an **ACT-style MEV arbitrage opportunity**, **not** a protocol exploit or bug.

## 6. References

Key underlying artifacts (summarized in this report):

1. **Seed tx trace and storage changes** — full call graph and storage diffs for tx `0x2c1a1998…86cc5` (cast `run -vvvv`) showing flash borrow, V3 swaps, TokenRewards interactions, and the final WeightedIndex transfer to `0xedee…`.
2. **Extended prestate balance diffs for seed tx** — QuickNode `prestateTracer` diff for the seed transaction, including ERC20 deltas for WeightedIndex and PEAS at the V2 pair, V3 pool, TokenRewards, and `0xC64b…`.
3. **Prestate balance diffs for funding tx** — QuickNode native-balance deltas for tx `0xf003685f…8dbe8`, establishing the net ETH P/L between `0x9522…` and `0xedee…`.
4. **WeightedIndex and TokenRewards contract sources** — verified Solidity implementations for the Peapods index and its rewards module, supporting the interpretation of fee-swap, burn, and reward-distribution mechanics.
5. **PEAS token contract source** — verified ERC20 implementation of PEAS, confirming standard mint/burn behavior and lack of special hooks exploited here.
6. **Prior challenger feedback** — earlier challenge result document highlighting the previously missing WeightedIndex transfer to `0xedee…` and motivating this refined, token-inclusive P/L analysis.

These artifacts collectively support the conclusion that the incident is a **permissionless MEV ACT opportunity** leveraging AMM price discrepancies and Peapods’ fee-distribution design, with **no evidence of a protocol-level bug or invariant violation**.

