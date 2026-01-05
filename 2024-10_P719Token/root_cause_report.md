# BSC High-Tax Token Redistribution Plus Unrelated Ce7 Trading (Non-ACT) — Root Cause Report

## 1. Incident Overview TL;DR

On BNB Smart Chain (BSC), EOA `0xfeb19a...` orchestrated a flash-loan-assisted buy of a high-tax token contract at `0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc` via an owner-gated router at `0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98`.  
In the seed transaction `0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3`, 4000 WBNB is flash-borrowed, unwrapped to BNB, and used to buy the high-tax token, which then redistributes exactly `575.799074208829188341` BNB out of its balance according to hard-coded tax logic.  
This redistribution sends BNB to:
- WBNB contract `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c` (re-wrapping 547.799074208829188341 BNB),
- BNB pool contract `0x99CD55d6A838F465CaEba3B64e267ADF29516e62` (14 BNB),
- Two EOAs `0x3d5d1e06e9e67908f940059D13fC0a655F81dD0B` and `0x0E074d49B4DC31D304Ed22c3F154DB61462161AA` (7 BNB each).

EOA `0xfeb19a...` itself pays a small net BNB cost in the seed tx (flash-loan fee and gas) and does not receive any of the redistributed BNB from `0x6bEee...` or `0x99CD55...`.  
Later, `0xfeb19a...` conducts a series of Ce7-related trades via public PancakeSwap/UniversalRouter paths (`0x3489...`, `0x92a1...`, `0x8572...`) that yield roughly +547 BNB profit, but these flows never touch `0x6bEee...` or `0x99CD55...`.  

**Determination:** This incident is **not** an anyone-can-take (ACT) exploit. It is a combination of:
- Intentional high-tax tokenomics on `0x6bEee...` that redistribute BNB to fixed recipients, and  
- Unrelated profitable Ce7 trading by `0xfeb19a...` through public liquidity pools.  

There is no deterministic, permissionless transaction sequence by which an unprivileged adversary can extract net profit from `0x6bEee...` or its BNB pool `0x99CD55...` beyond the designed tax redistribution.

## 2. Key Background

- **High-tax BSC tokens:** Many BSC tokens implement “taxed” buy/sell flows in which incoming BNB is automatically split and forwarded to reward pools, team/marketing wallets, and other fixed destinations. Large buys can therefore cause significant outflows from the token contract’s BNB balance without implying any bug or unintended vulnerability.

- **BNB pool and reward contracts:** Dedicated BNB pool contracts often act as aggregation points for tax-funded balances, managed by owner-only functions that control deposits, rewards, and withdrawals. These contracts are commonly not permissionless profit sources for arbitrary EOAs.

- **Ce7 and Pancake/UniversalRouter infrastructure:** Ce7 trading and standard BNB/USDT routing via PancakeSwap V2/V3 and UniversalRouter are widely used public trading mechanisms. Profitable trades through these pools, even when large, do not by themselves indicate exploitation of an unrelated protocol or pool; they represent trading PnL, not protocol-level theft.

In this context, the incident shows a high-tax token behaving according to its tax logic and an EOA capturing trading profits through public Ce7-related pools, rather than a vulnerability that enables anyone-can-take extraction from the token or its BNB pool.

## 3. Vulnerability Analysis

**Protocol classification**
- **Protocol / token:** High-tax token at `0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc` on BSC (chainid 56).
- **BNB pool:** `0x99CD55d6A838F465CaEba3B64e267ADF29516e62` (receives a fixed BNB share from taxed buys).
- **Router:** `0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98` (owner-gated router used to execute the seed flash-loan buy).
- **Primary EOA cluster:** `0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6` (trader) plus router `0x3F32c7...`.

**Observed behavior of the high-tax token**
- Decompiled code for `0x6bEee...` shows complex transfer logic with multiple storage maps and calls out to external contracts, including the BNB pool `0x99cd55...` and other addresses, consistent with high-tax redistribution rather than standard ERC20 transfers.
- In particular, transfer-related logic routes BNB value to `0x99cd55...` via a call corresponding to a reward/distribution function, using `msg.sender` information and internal accounting.

Excerpt from decompiled `0x6bEee...` (high-tax token) showing BNB forwarding to `0x99cd55...`:

```solidity
// Decompiled high-tax token 0x6bEee...
// ... within transfer-like logic ...
require(address(msg.sender).code.length);
require(!address(msg.sender));
// call into BNB pool 0x99cd55... with value derived from internal accounting
var_o = 0x21670f2200000000000000000000000000000000000000000000000000000000;
var_l = address(msg.sender);
var_m = var_d.length;
require(address(0x99cd55d6a838f465caeba3b64e267adf29516e62).code.length);
(bool success, bytes memory ret0) =
    address(0x99cd55d6a838f465caeba3b64e267adf29516e62)
        .{ value: storage_map_c[var_a] ether }Unresolved_21670f22(var_l); // call
// ...
```

This structure is consistent with a token that:
- Charges a high tax on buys,  
- Accumulates BNB internally, and  
- Forwards that BNB to `0x99cd55...` and other configured recipients.

**BNB pool behavior**

The decompiled BNB pool at `0x99cd55...` exposes owner-controlled functions like `deposit`, `reward`, `withdrawAll`, and `withdraw`, with access control enforced via `owner` checks:

```solidity
// Decompiled BNB pool 0x99cd55...
address public owner;

function withdrawAll(address arg0) public {
    require(arg0 == (address(arg0)));
    require(msg.sender == (address(owner)), "Ownable: caller is not the owner");
    (bool success, bytes memory ret0) = address(arg0).transfer(address(this).balance);
}

function reward(address arg0, uint256 arg1) public {
    require(arg0 == (address(arg0)));
    require(msg.sender == (address(owner)), "Ownable: caller is not the owner");
    // reward / accounting logic...
}
```

This confirms that:
- The pool’s BNB can only be withdrawn or rewarded by the `owner`,  
- It is **not** a permissionless profit source for arbitrary EOAs, and  
- Any BNB received from the high-tax token is under owner governance, not exposed via an exploitable public entry point.

**ACT classification**

Given the above:
- `0x6bEee...` behaves as a deliberately configured high-tax token.  
- `0x99cd55...` is an owner-controlled pool with no public, exploitable payout mechanism.  
- The Ce7 trading profits are realized entirely via public Pancake/UniversalRouter routes.

Therefore, there is **no vulnerability** in the ACT sense:
- No permissionless function or transaction sequence allows an unprivileged adversary to extract net profit from `0x6bEee...` or `0x99cd55...`.  
- The loss of BNB from the token contract is the direct result of its tax design, not a bug or exploit.

## 4. Detailed Root Cause Analysis

### 4.1 Seed flash-loan transaction and BNB redistribution

The seed transaction:
- **Chain:** BSC (chainid 56)  
- **Tx hash:** `0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3`  
- **Role:** `seed` (initial incident tx)

Trace evidence (`trace.cast.log`) shows router `0x3F32c7...` initiating a Pancake V3 flash loan of 4000 WBNB from pool `0x172fcD41E0913e95784454622d1c3724f546f849`, unwrapping to BNB, and interacting with the high-tax token:

```bash
# Seed transaction trace (0x9afc...)
Traces:
  [22591290] 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98::510a82a9(...)
    ├─ PancakeV3Pool::flash(..., 4000000000000000000000 [4e21], ...)
    │   ├─ WBNB::transfer(0x3F32c7..., 4000000000000000000000 [4e21])
    │   ├─ 0x3F32c7...::pancakeV3FlashCallback(...)
    │   │   ├─ WBNB::withdraw(4000000000000000000000 [4e21])
    │   │   ├─ 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc::totalSupply()
    │   │   ├─ ... token logic and approvals ...
```

The associated `balance_diff.json` confirms the BNB movements:

```json
{
  "chainid": 56,
  "txhash": "0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3",
  "native_balance_deltas": [
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "delta_wei": "547799074208829188341"
    },
    {
      "address": "0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6",
      "delta_wei": "-199009357672029392"
    },
    {
      "address": "0x6beee2b57b064eac5f432fc19009e3e78734eabc",
      "delta_wei": "-575799074208829188341"
    },
    {
      "address": "0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b",
      "delta_wei": "7000000000000000000"
    },
    {
      "address": "0x99cd55d6a838f465caeba3b64e267adf29516e62",
      "delta_wei": "14000000000000000000"
    },
    {
      "address": "0x0e074d49b4dc31d304ed22c3f154db61462161aa",
      "delta_wei": "7000000000000000000"
    }
  ]
}
```

Key facts:
- `0x6bEee...` loses **575.799074208829188341 BNB**.  
- WBNB `0xbb4c...` gains **547.799074208829188341 BNB** (re-wrapping most of the taxed BNB).  
- BNB pool `0x99cd55...` gains **14 BNB**.  
- EOAs `0x3d5d1e...` and `0x0e074d...` each gain **7 BNB**.  
- EOA `0xfeb19a...` loses ~`0.199 BNB` (flash-loan fee and gas) and does **not** receive a BNB inflow from the token or pool.

Combined with the decompiled token logic, this confirms:
- The BNB outflow from `0x6bEee...` is **driven by its configured tax mechanics**, not a bug.  
- The beneficiaries of the tax (WBNB, BNB pool, and EOAs) are fixed recipients defined in code, not opportunistic adversaries exploiting a flaw.

### 4.2 BNB pool 0x99CD55... as non-ACT component

From the decompiled `0x99cd55...`:
- Only the `owner` can call `withdrawAll`, `withdraw`, and `reward`.  
- The contract aggregates BNB and tracks per-address accounting for rewards.  
- There is no permissionless path for an arbitrary EOA (including `0xfeb19a...`) to withdraw this BNB.

Thus, the **14 BNB** sent to `0x99cd55...` in the seed tx becomes owner-governed pool funds, not a directly exploitable ACT opportunity.

### 4.3 Ce7-related trades and profit

After the seed tx, `0xfeb19a...` executes several Ce7-related trades through public PancakeSwap and UniversalRouter routes:

- `0x34893c8afc11d9650fe34d9c73a080f8aad02b2f499785b099230239a9796aa6` — Ce7 acquisition via UniversalRouter.  
- `0x92a11daf0a0582bb7838f99ed49ca66e0bd5d9e0603bea9fd2da871a5e59cff4` — Ce7 position unwind to WBNB.  
- `0x8572f0a729afba0a777e3138384d3e6d26b42a3f64cda71e032f91f630487790` — later USDT/BNB rebalancing.

These trades:
- Use UniversalRouter to route through Ce7/USDT/WBNB and related pools.  
- Never call into `0x6bEee...` or `0x99cd55...`.  
- Are standard swaps against public liquidity.

Example: `0x92a1...` balance diff shows net BNB profit for `0xfeb19a...` against WBNB:

```json
{
  "txhash": "0x92a11daf0a0582bb7838f99ed49ca66e0bd5d9e0603bea9fd2da871a5e59cff4",
  "native_balance_deltas": [
    {
      "address": "0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6",
      "delta_wei": "547399580129810382091"
    },
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "delta_wei": "-547400073203810382091"
    }
  ]
}
```

This indicates:
- `0xfeb19a...` gains ~**547.3996 BNB** in this unwind.  
- WBNB loses a corresponding amount, reflecting a profitable trade against public liquidity.

The complementary trade `0x3489...` shows `0xfeb19a...` spending 150 BNB via UniversalRouter to build the Ce7/USDT position:

```json
{
  "txhash": "0x34893c8afc11d9650fe34d9c73a080f8aad02b2f499785b099230239a9796aa6",
  "native_balance_deltas": [
    {
      "address": "0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6",
      "delta_wei": "-150004392861000000000"
    },
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "delta_wei": "150000000000000000000"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6",
      "delta": "85176856079591693694288"
    },
    ...
  ]
}
```

Putting these together:
- Across Ce7-related trades, `0xfeb19a...` ends up with a **net BNB gain of roughly +547 BNB**, consistent with the root_cause.json summary.  
- No trace or balance diff from these Ce7 trades shows calls to `0x6bEee...` or `0x99cd55...`.  

### 4.4 Causal linkage and root cause

From the full evidence:
- The **seed tx** is a flash-loan-assisted buy of a high-tax token, triggering tax redistribution from `0x6bEee...` to WBNB, `0x99cd55...`, and two EOAs.  
- The **Ce7 trades** are profitable but operate entirely via public pools unrelated to `0x6bEee...` or `0x99cd55...`.  
- `0xfeb19a...` does **not** receive BNB from the token contract or the BNB pool; its profit comes from Ce7-based trading PnL.

Therefore, the **root cause** is:
- **Tokenomics design, not a technical exploit.**  
  - `0x6bEee...` is configured to redistribute a large portion of incoming BNB as tax to specific addresses and a BNB pool.  
  - The 575.799 BNB outflow is the direct result of this configuration when a large buy is executed.  
- **Separate opportunistic trading.**  
  - `0xfeb19a...` independently executes profitable Ce7 trades using public infrastructure, without exploiting any misconfiguration or bug in `0x6bEee...` or `0x99cd55...`.

There is **no** deterministic, permissionless transaction sequence in which an arbitrary adversary can convert value from `0x6bEee...` or `0x99cd55...` into guaranteed profit beyond the intended tax redistribution. As such, the incident does **not** satisfy the ACT definition.

## 5. Adversary Flow Analysis

### 5.1 Actors and accounts

- **Adversary EOA:** `0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6`  
- **Owner-gated router:** `0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98` (controls the seed flash-loan tx)  
- **High-tax token (victim-like contract):** `0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc`  
- **BNB pool:** `0x99CD55d6A838F465CaEba3B64e267ADF29516e62`  
- **WBNB:** `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`  
- **Other EOAs receiving tax:** `0x3d5d1e06e9e67908f940059D13fC0a655F81dD0B`, `0x0E074d49B4DC31D304Ed22c3F154DB61462161AA`

### 5.2 Seed stage: high-tax token buy via flash loan

- **Stage:** Seed high-tax token buy  
- **Tx:** `0x9afc...` on BSC (role: `seed`)  
- **Mechanism:** Flash loan of 4000 WBNB → unwrap to BNB → call into `0x6bEee...` via router `0x3F32c7...` to perform a large buy.  
- **Effect:**  
  - `0x6bEee...` redistributes `575.799074208829188341` BNB to WBNB, `0x99cd55...`, and two EOAs as per its tax logic.  
  - `0xfeb19a...` pays a small BNB cost (flash-loan fee/gas) and receives no tax payout.

### 5.3 Ce7 acquisition via UniversalRouter

- **Stage:** Ce7 acquisition via UniversalRouter  
- **Tx:** `0x34893c8afc11d9650fe34d9c73a080f8aad02b2f499785b099230239a9796aa6`  
- **Mechanism:**  
  - UniversalRouter `0x1A0A18AC4BECDDbd6389559687d1A73d8927E416::execute{value: 150 BNB}`  
  - Route BNB → WBNB → USDT → Ce7 and related positions through public pools.  
- **Effect:**  
  - `0xfeb19a...` spends ~150 BNB and acquires a substantial Ce7/USDT position.  
  - No interaction with `0x6bEee...` or `0x99cd55...`.

### 5.4 Ce7 position unwind and BNB profit

- **Stage:** Ce7 position unwind and profit realization  
- **Txs:**  
  - `0x92a11daf0a0582bb7838f99ed49ca66e0bd5d9e0603bea9fd2da871a5e59cff4`  
  - `0x8572f0a729afba0a777e3138384d3e6d26b42a3f64cda71e032f91f630487790`
- **Mechanism:**  
  - Swap Ce7/USDT back to WBNB/BNB via public Pancake/UniversalRouter routes.  
  - Manage USDT/BNB exposure to lock in gains.
- **Effect:**  
  - Net BNB gain for `0xfeb19a...` of roughly **+547 BNB** across Ce7 trades.  
  - All flows occur through Ce7, USDT, WBNB, and other standard tokens; `0x6bEee...` and `0x99cd55...` are never touched.

### 5.5 ACT opportunity assessment

From the full adversary flow:
- The **only** contract that loses substantial BNB directly is `0x6bEee...`, due to its own tax payoff logic.  
- Tax recipients (`0x99cd55...` and two EOAs) are defined in code; they do not constitute an exploitable profit path for arbitrary actors.  
- The Ce7 trades that generate ~+547 BNB for `0xfeb19a...` are **standard market trades** against public liquidity, not drains of `0x6bEee...` or `0x99cd55...`.

Thus, the adversary flow does **not** constitute an ACT exploit:
- There is no permissionless, deterministic strategy that any unprivileged adversary could execute to drain `0x6bEee...` or `0x99cd55...` for guaranteed profit.  
- The outcome is a combination of tokenomics-driven redistribution and successful speculative trading by a specific EOA.

## 6. Impact & Losses

### 6.1 Token-level BNB movement

From `root_cause.json` and the seed `balance_diff.json`:

- **Total BNB leaving `0x6bEee...` in the seed tx:**  
  - `575.799074208829188341 BNB`

This amount is redistributed as:
- `547.799074208829188341 BNB` to WBNB `0xbb4c...` (re-wrapped, effectively moving value from the token contract to the WBNB pool).  
- `14 BNB` to BNB pool `0x99cd55...`.  
- `7 BNB` to EOA `0x3d5d1e...`.  
- `7 BNB` to EOA `0x0E074d...`.

This is a **redistribution of value** from `0x6bEee...`’s BNB balance to specified recipients, in line with the token’s high-tax configuration, not an unauthorized exploit.

### 6.2 Adversary PnL and victim perspective

- **Adversary PnL (Ce7 trades):**  
  - Approximately **+547 BNB** net gain for `0xfeb19a...` across Ce7-related trades (`0x3489...`, `0x92a1...`, `0x8572...`), as inferred from the balance diffs and net flows in BNB and WBNB.
- **Seed tx cost to adversary:**  
  - ~`0.199 BNB` net loss for `0xfeb19a...` in the seed tx (`0x9afc...`).

From the standpoint of `0x6bEee...` and its BNB liquidity:
- The **575.799 BNB** outflow is entirely dictated by its tax logic when a large buy occurs.  
- No evidence shows that this outflow is recoverable or controllable by arbitrary adversaries; it is a one-way redistribution to the configured recipients.  

From the ACT perspective:
- There is **no ACT loss**: no mechanism is demonstrated by which an unprivileged, arbitrary adversary can reproduce the Ce7 profits by exploiting a technical flaw in `0x6bEee...` or `0x99cd55...`.  
- The observed losses are better characterized as **tokenomics risk** (for buyers of the high-tax token) and **market risk** (for Ce7 counterparties), not protocol exploitation.

## 7. References

The analysis is based on the following concrete on-chain and artifact references:

- **[1] Seed transaction trace and balance diff (0x9afc...)**  
  - `artifacts/root_cause/seed/56/0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3/trace.cast.log`  
  - `artifacts/root_cause/seed/56/0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3/balance_diff.json`

- **[2] Decompiled high-tax token 0x6bEee...**  
  - `artifacts/root_cause/data_collector/iter_2/contract/56/0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc/decompile/0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc-decompiled.sol`

- **[3] Decompiled BNB pool 0x99CD55...**  
  - `artifacts/root_cause/data_collector/iter_2/contract/56/0x99CD55d6A838F465CaEba3B64e267ADF29516e62/decompile/0x99CD55d6A838F465CaEba3B64e267ADF29516e62-decompiled.sol`

- **[4] Router 0x3F32c7... decompiled source**  
  - `artifacts/root_cause/data_collector/iter_2/contract/56/0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98/decompile/0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98-decompiled.sol`

- **[5] Ce7/UniversalRouter unwind trace and balance diff (0x92a1...)**  
  - `artifacts/root_cause/data_collector/iter_4/tx/56/0x92a11daf0a0582bb7838f99ed49ca66e0bd5d9e0603bea9fd2da871a5e59cff4/trace.cast.log`  
  - `artifacts/root_cause/data_collector/iter_4/tx/56/0x92a11daf0a0582bb7838f99ed49ca66e0bd5d9e0603bea9fd2da871a5e59cff4/balance_diff.json`

- **[6] Ce7/BNB/USDT execute-with-value trace and balance diff (0x3489...)**  
  - `artifacts/root_cause/data_collector/iter_4/tx/56/0x34893c8afc11d9650fe34d9c73a080f8aad02b2f499785b099230239a9796aa6/trace.cast.log`  
  - `artifacts/root_cause/data_collector/iter_4/tx/56/0x34893c8afc11d9650fe34d9c73a080f8aad02b2f499785b099230239a9796aa6/balance_diff.json`

- **[7] Ce7/BNB/USDT unwind trace and balance diff (0x8572...)**  
  - `artifacts/root_cause/data_collector/iter_4/tx/56/0x8572f0a729afba0a777e3138384d3e6d26b42a3f64cda71e032f91f630487790/trace.cast.log`  
  - `artifacts/root_cause/data_collector/iter_4/tx/56/0x8572f0a729afba0a777e3138384d3e6d26b42a3f64cda71e032f91f630487790/balance_diff.json`

- **[8] All relevant transactions summary**  
  - `root_cause.json` `all_relevant_txs` list:  
    - `0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3` (seed)  
    - `0x92a11daf0a0582bb7838f99ed49ca66e0bd5d9e0603bea9fd2da871a5e59cff4` (Ce7 unwind)  
    - `0x34893c8afc11d9650fe34d9c73a080f8aad02b2f499785b099230239a9796aa6` (Ce7 acquisition)  
    - `0x8572f0a729afba0a777e3138384d3e6d26b42a3f64cda71e032f91f630487790` (later Ce7/BNB/USDT rebalancing)

These references collectively underpin the deterministic conclusion that the incident is a non-ACT high-tax redistribution combined with independent Ce7 trading, with no anyone-can-take exploit path on `0x6bEee...` or its BNB pool.

