## 1. Incident Overview TL;DR

On BNB Chain, adversary externally owned account (EOA) `0x26f8bf8a772b8283bc1ef657d690c19e545ccc0d` used a large Moolah USDT flash loan and Pancake V3 YULIAI/USDT price manipulation to trigger a Quoter-based payout on contract `0x8262325bf1d8c3be83eb99f5a74b8458ebb96282` (“YULIAI/USDT payout contract”).  
Within a single transaction (`0xeab946cfea49b240284d3baef24a4071313d76c39de2ee9ab00d957896a6c1c4`, chainid 56), the victim contract sent an oversized amount of USDT to external recipients, and the adversary cluster ended the transaction with a large net USDT gain.

The root cause is a protocol-level design flaw in contract `0x8262...`, which uses a single QuoterV2 price snapshot from a manipulable Pancake V3 pool to determine large USDT payouts without protecting against flash-loan-powered price swings. An unprivileged adversary can combine a flash-loan-driven pool move with a single call to selector `0x2397e4d7` to drain USDT from `0x8262...`.

## 2. Key Background

On BNB Chain (chainid 56), the following components and relationships are relevant:

- BEP20USDT at `0x55d398326f99059fF775485246999027B3197955` is a standard 18‑decimal USDT implementation. Its `Transfer` events and balance changes around the incident are captured in `artifacts/root_cause/seed/56/0xeab9...c1c4/balance_diff.json`.
- YuliAIToken at `0xDF54ee636a308E8Eb89a69B6893efa3183C2c1B5` is a BEP20 token paired with USDT in Pancake V3 pool `0xa687c7b3c2cf6adaef0c4edab234c55b88e01333`. Its transfers between the pool and victim contract `0x8262...` during the incident transaction are recorded in the same balance diff file.
- Moolah flash loans are accessed via ERC1967Proxy `0x8F73b65B4caAf64FBA2aF91cC5D4a2A1318E5D8C`. In the incident transaction, this proxy provides `200000 * 10^18` USDT to orchestrator contract `0xd6b9ee63c1c360d1ea3e4d15170d20638115ffaa` at the start of the call sequence and receives full repayment by the end.
- Pancake V3 SwapRouter `0x1b81d678ffb9c0263b24a97847620c99d213eb14` and QuoterV2 `0xB048Bbc1Ee6b733FFfCFb9e9CeF7375518e25997` are public routing and quoting contracts. Any EOA or contract can use them to route swaps and obtain price quotes on the YULIAI/USDT pool `0xa687...`.
- Contract `0x8262...` is a YULIAI/USDT payout contract. Its entry point with selector `0x2397e4d7` calls QuoterV2 to price YULIAI in USDT, pulls YULIAI from an orchestrator via `transferFrom`, and then pays USDT out to specified recipients. This behavior is summarized in `artifacts/root_cause/data_collector/iter_4/contract/56/0x8262.../pseudocode_0x2397e4d7_summary.json`.

The adversary deploys orchestrator contract `0xd6b9...` in block `57432055` and then uses it in block `57432056` to execute the flash loan, pool manipulation, Quoter-based payout, and final profit realization.

## 3. Vulnerability Analysis

### 3.1 Vulnerable design in contract 0x8262...

Contract `0x8262...` implements a payout mechanism that:

- Accepts an external call via selector `0x2397e4d7`.
- Uses QuoterV2 at `0xB048...` to obtain a spot quote for swapping YULIAI (`0xDF54...`) for USDT (`0x55d3...`) on Pancake V3 pool `0xa687...`.
- Pulls YULIAI from orchestrator `0xd6b9...` into `0x8262...` using `YuliAIToken::transferFrom`.
- Sends USDT from `0x8262...` to an external payout address `0x078f3f917c7355027a8388b7083b2199910c8a9a` and back to orchestrator `0xd6b9...` using `BEP20USDT::transfer`.

From the pseudocode summary:

```json
// Pseudocode summary for 0x8262... selector 0x2397e4d7
{
  "contract_address": "0x8262325bf1d8c3be83eb99f5a74b8458ebb96282",
  "entry_selector": "0x2397e4d7",
  "functions": [
    {
      "selector": "0x2397e4d7",
      "external_calls": [
        {
          "target": "QuoterV2",
          "address": "0xB048Bbc1Ee6b733FFfCFb9e9CeF7375518e25997",
          "selector": "0xc6a5026a"
        },
        {
          "target": "YuliAIToken",
          "address": "0xDF54ee636a308E8Eb89a69B6893efa3183C2c1B5",
          "selector": "transferFrom(address,address,uint256)"
        },
        {
          "target": "BEP20USDT",
          "address": "0x55d398326f99059fF775485246999027B3197955",
          "selector": "transfer(address,uint256)"
        }
      ]
    }
  ]
}
```

*Caption: Extract from `pseudocode_0x2397e4d7_summary.json` showing that `0x2397e4d7` calls QuoterV2, pulls YULIAI via `transferFrom`, and sends USDT via `transfer`.*

The vulnerability is that the contract treats the QuoterV2 result for the YULIAI/USDT pool as a reliable settlement price, even when the pool price has just been moved within the same transaction. There is no invariant or bounding logic that keeps USDT payouts safe under adversarial price movements.

### 3.2 Insecure use of AMM spot quotes

The ACT Root Cause Analysis section identifies the following key issues:

- The victim contract uses a single spot quote from QuoterV2 for a large OTC‑style USDT payout.
- The same transaction can route large swaps through SwapRouter `0x1b81...` against pool `0xa687...`, moving the YULIAI/USDT price that QuoterV2 observes.
- The contract does not constrain the timing or conditions of Quoter and payout calls so that they remain safe under adversarial pool moves.

As a result, any party who can manipulate the YULIAI/USDT pool price within the same transaction can force `0x8262...` to overpay USDT relative to the true pre‑manipulation price.

## 4. Detailed Root Cause Analysis

### 4.1 Evidence from the incident transaction

The exploit transaction is:

- Chain: BNB Chain (chainid 56)  
- Tx hash: `0xeab946cfea49b240284d3baef24a4071313d76c39de2ee9ab00d957896a6c1c4`  
- Block: `57432056`  
- From: EOA `0x26f8bf8a772b8283bc1ef657d690c19e545ccc0d`  
- To: orchestrator `0xd6b9ee63c1c360d1ea3e4d15170d20638115ffaa`

From the seed metadata:

```json
// Seed transaction metadata for 0xeab9...c1c4
{
  "chainid": 56,
  "txhash": "0xeab946cfea49b240284d3baef24a4071313d76c39de2ee9ab00d957896a6c1c4",
  "etherscan": {
    "tx": {
      "result": {
        "from": "0x26f8bf8a772b8283bc1ef657d690c19e545ccc0d",
        "to": "0xd6b9ee63c1c360d1ea3e4d15170d20638115ffaa",
        "blockNumber": "0x36c57f8"
      }
    }
  }
}
```

*Caption: Excerpt from `metadata.json` confirming chainid, txhash, sender EOA, and orchestrator target.*

### 4.2 Flash loan and price manipulation

The structured trace (`artifacts/root_cause/data_collector/iter_1/tx/56/0xeab9...c1c4/trace.debug.json`) shows the orchestrator taking a USDT flash loan from Moolah via proxy `0x8F73...`, routing swaps through Pancake V3, and manipulating the YULIAI/USDT price.

Relevant calls include:

```json
// Excerpt from trace.debug.json showing flash loan and swaps
{
  "from": "0x8f73b65b4caaf64fba2af91cc5d4a2a1318e5d8c",
  "to": "0x55d398326f99059ff775485246999027b3197955",
  "input": "0xa9059cbb...000000000000000000000000d6b9ee63c1c360d1ea3e4d15170d20638115ffaa...2a5a058fc295ed000000"
}
{
  "from": "0x1b81d678ffb9c0263b24a97847620c99d213eb14",
  "to": "0x55d398326f99059ff775485246999027b3197955",
  "input": "0x23b872dd...000000000000000000000000d6b9ee63c1c360d1ea3e4d15170d20638115ffaa000000000000000000000000a687c7b3c2cf6adaef0c4edab234c55b88e01333..."
}
{
  "from": "0xa687c7b3c2cf6adaef0c4edab234c55b88e01333",
  "to": "0xdf54ee636a308e8eb89a69b6893efa3183c2c1b5",
  "input": "0xa9059cbb...000000000000000000000000d6b9ee63c1c360d1ea3e4d15170d20638115ffaa..."
}
```

*Caption: Trace snippet showing USDT transfer from Moolah proxy to orchestrator, SwapRouter moving USDT into pool `0xa687...`, and YULIAI transfers from the pool to orchestrator.*

These calls establish that the orchestrator:

- Receives `200000 * 10^18` USDT from the Moolah proxy.  
- Grants allowance and routes swaps via SwapRouter `0x1b81...` into pool `0xa687...`.  
- Uses the pool to exchange USDT for YULIAI and move the YULIAI/USDT spot price observed by QuoterV2.

### 4.3 Quoter-based payout and USDT drain

Later in the same transaction, orchestrator `0xd6b9...` calls victim contract `0x8262...` with selector `0x2397e4d7`. Within that call, the trace shows:

- A call from `0x8262...` to QuoterV2 `0xB048...` with selector `0xc6a5026a`, quoting a YULIAI→USDT swap on pool `0xa687...`.
- A call from `0x8262...` to YuliAIToken `0xDF54...` using `transferFrom(0xd6b9..., 0x8262..., amount)`.
- Two calls from `0x8262...` to BEP20USDT `0x55d3...` using `transfer` to send USDT to `0x078f3f...` and back to `0xd6b9...`.

The resulting token balance changes from `balance_diff.json` are:

```json
// ERC20 balance deltas for USDT and YULIAI around the incident tx
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x8262325bf1d8c3be83eb99f5a74b8458ebb96282",
      "delta": "-99838034704531488579480",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x078f3f917c7355027a8388b7083b2199910c8a9a",
      "delta": "4991901735226574428960",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x26f8bf8a772b8283bc1ef657d690c19e545ccc0d",
      "delta": "78799932076881681340252",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0xdf54ee636a308e8eb89a69b6893efa3183c2c1b5",
      "holder": "0xa687c7b3c2cf6adaef0c4edab234c55b88e01333",
      "delta": "-3347358354974243185076585",
      "contract_name": "YuliAIToken"
    },
    {
      "token": "0xdf54ee636a308e8eb89a69b6893efa3183c2c1b5",
      "holder": "0x8262325bf1d8c3be83eb99f5a74b8458ebb96282",
      "delta": "3347358354974243185076585",
      "contract_name": "YuliAIToken"
    }
  ]
}
```

*Caption: Extract from `balance_diff.json` showing USDT outflow from `0x8262...`, USDT inflows to `0x078f3f...` and the attacker EOA, and YULIAI movements between pool `0xa687...` and `0x8262...`.*

In human‑readable units (18 decimals):

- Victim contract `0x8262...` loses `99,838.034704531488579480` USDT.  
- Payout address `0x078f3f...` receives `4,991.901735226574428960` USDT.  
- EOA `0x26f8...` receives `78,799.932076881681340252` USDT.  
- Pool `0xa687...` sends `3,347.358354974243185076585` YULIAI to `0x8262...`.

The cluster P&L file confirms the net result for the adversary:

```json
// Cluster P&L for attacker EOA + orchestrator
{
  "txhash": "0xeab946cfea49b240284d3baef24a4071313d76c39de2ee9ab00d957896a6c1c4",
  "chainid": 56,
  "cluster": [
    "0x26f8bf8a772b8283bc1ef657d690c19e545ccc0d",
    "0xd6b9ee63c1c360d1ea3e4d15170d20638115ffaa"
  ],
  "cluster_native_wei_delta": -9190274800000000,
  "cluster_usdt_wei_delta": 78799932076881681340252
}
```

*Caption: Excerpt from `tx_0xeab9...c1c4_cluster_pnl.json` showing the adversary cluster’s USDT profit and BNB gas cost.*

From this:

- The adversary cluster’s net USDT gain is `78,799.932076881681340252` (18‑decimal scaling of `cluster_usdt_wei_delta`).  
- The cluster pays `9,190,274,800,000,000` wei of BNB in gas (`cluster_native_wei_delta`).  
- There are no USDT‑denominated fees, so `fees_paid_in_reference_asset` in the ACT profit predicate is correctly set to `0`.

### 4.4 ACT opportunity characterization

The act_opportunity block in `root_cause.json` describes an “anyone‑can‑take” strategy:

- Block height `B = 57432056` on BNB Chain.  
- Pre‑state `σ_B` includes public balances and storage for the victim contract `0x8262...`, orchestrator `0xd6b9...`, pool `0xa687...`, Moolah proxy `0x8F73...`, Pancake routing/quoter contracts, and the relevant tokens.  
- The transaction sequence `b` consists of a single adversary‑crafted transaction `0xeab9...c1c4` that:
  - Takes a large USDT flash loan via Moolah proxy `0x8F73...`.  
  - Swaps via SwapRouter `0x1b81...` against pool `0xa687...` to move the YULIAI/USDT price.  
  - Calls victim contract `0x8262...` with selector `0x2397e4d7` using parameters compatible with the manipulated price.  
  - Settles the flash loan and forwards USDT profit back to `0x26f8...`.

The ACT success predicate is purely profit‑based:

- Reference asset: USDT.  
- Adversary address: `0x26f8bf8a772b8283bc1ef657d690c19e545ccc0d`.  
- `value_before_in_reference_asset = 0` (EOA has zero USDT before the incident transaction).  
- `value_after_in_reference_asset = 78799.932076881681340252`.  
- `value_delta_in_reference_asset = 78799.932076881681340252`.  
- `fees_paid_in_reference_asset = 0` (all fees are paid in BNB, accounted separately as `cluster_native_wei_delta`).

These values are deterministically backed by `balance_diff.json` and `tx_0xeab9...c1c4_cluster_pnl.json`.

## 5. Adversary Flow Analysis

### 5.1 Adversary strategy summary

The adversary executes a single orchestrated transaction that:

1. Uses a large Moolah USDT flash loan obtained via proxy `0x8F73...`.  
2. Trades on Pancake V3 YULIAI/USDT pool `0xa687...` through SwapRouter `0x1b81...` to move the spot price.  
3. Calls victim contract `0x8262...` with selector `0x2397e4d7`, which uses QuoterV2 pricing from the manipulated pool to compute USDT payouts.  
4. Repays the flash loan and routes the residual USDT to the adversary EOA.

### 5.2 Adversary-related accounts

- **Adversary cluster**
  - EOA `0x26f8bf8a772b8283bc1ef657d690c19e545ccc0d` (BNB Chain, chainid 56):  
    - Sender of the incident transaction `0xeab9...c1c4`.  
    - Direct recipient of the final USDT profit (`78,799.932076881681340252` USDT) in `balance_diff.json`.  
    - Deployer of orchestrator contract `0xd6b9...`.
  - Orchestrator contract `0xd6b9ee63c1c360d1ea3e4d15170d20638115ffaa` (BNB Chain, chainid 56):  
    - Deployed one block before the incident (`0x78e5931a7d91e90942dc7913e16184786d003bbdf7502fe3a34dc92bfe6d1c6e`, block `57432055`).  
    - Executes the flash loan, routing, and call into victim `0x8262...`.  
    - Forwards USDT profit back to the EOA.

- **Victim and infrastructure**
  - Victim payout contract `0x8262325bf1d8c3be83eb99f5a74b8458ebb96282` (BNB Chain, chainid 56).  
  - Pancake V3 YULIAI/USDT pool `0xa687c7b3c2cf6adaef0c4edab234c55b88e01333` (BNB Chain, chainid 56).  
  - QuoterV2 `0xB048Bbc1Ee6b733FFfCFb9e9CeF7375518e25997`.  
  - SwapRouter `0x1b81d678ffb9c0263b24a97847620c99d213eb14`.  
  - Moolah proxy `0x8F73b65B4caAf64FBA2aF91cC5D4a2A1318E5D8C`.  
  - Payout recipient `0x078f3f917c7355027a8388b7083b2199910c8a9a`.

### 5.3 Lifecycle stages

1. **Adversary orchestrator deployment**
   - Tx: `0x78e5931a7d91e90942dc7913e16184786d003bbdf7502fe3a34dc92bfe6d1c6e` (BNB Chain, block `57432055`).  
   - EOA `0x26f8...` deploys orchestrator contract `0xd6b9...`.  
   - Evidence: `artifacts/root_cause/data_collector/iter_2/address/56/0xd6b9.../txlist_57432055_57432056.json`.

2. **Flash loan and pool price manipulation**
   - Tx: `0xeab9...c1c4` (BNB Chain, block `57432056`), mechanism `flashloan_and_swap`.  
   - Orchestrator `0xd6b9...` borrows `200000 * 10^18` USDT from Moolah via proxy `0x8F73...`.  
   - It routes swaps through SwapRouter `0x1b81...` against pool `0xa687...`, moving the YULIAI/USDT spot price observed by QuoterV2.  
   - Evidence: flash loan and swap calls in `trace.debug.json`, showing interactions among `0xd6b9...`, `0x8F73...`, `0x1b81...`, and `0xa687...`.

3. **Victim payout and profit realization**
   - Tx: `0xeab9...c1c4` (same block), mechanism `payout_and_settlement`.  
   - After moving the pool price, `0xd6b9...` calls victim contract `0x8262...` with selector `0x2397e4d7`.  
   - `0x8262...` calls QuoterV2 `0xB048...` to obtain a YULIAI/USDT quote, pulls YULIAI from `0xd6b9...`, and sends:  
     - `4,991.901735226574428960` USDT to `0x078f3f...`.  
     - `78,799.932076881681340252` USDT back to the adversary cluster (ending at EOA `0x26f8...`).  
   - The orchestrator repays the flash loan and settles all legs, leaving the cluster with the USDT profit and the BNB gas cost specified in the P&L file.  
   - Evidence: call chain in `trace.debug.json`, token and native balance changes in `balance_diff.json`, and profit figures in `tx_0xeab9...c1c4_cluster_pnl.json`.

## 6. Impact & Losses

### 6.1 Quantitative losses

From the Impact & Losses section of `root_cause.json` and the underlying balance diffs:

- **USDT (BEP20USDT `0x55d3...`)**
  - Total loss for victim contract `0x8262...`:  
    - `99,838.034704531488579480` USDT (`-99838034704531488579480` base units).  
  - Adversary net profit (cluster EOA + orchestrator):  
    - `78,799.932076881681340252` USDT (`cluster_usdt_wei_delta = 78799932076881681340252`).  
  - USDT sent to payout address `0x078f3f...`:  
    - `4,991.901735226574428960` USDT.

- **YULIAI (YuliAIToken `0xDF54...`)**
  - `3,347.358354974243185076585` YULIAI moved from Pancake V3 pool `0xa687...` into victim contract `0x8262...`.

### 6.2 Qualitative impact

- The victim payout contract `0x8262...` suffers a large one‑shot USDT drain (`~99.8k` USDT) in a single transaction due to its reliance on a manipulable spot quote from QuoterV2.  
- The adversary cluster gains `~78.8k` USDT while paying only `9,190,274,800,000,000` wei of BNB in gas, making the exploit highly capital‑efficient.  
- Pancake V3 pool `0xa687...` experiences a significant but transient change in YULIAI and USDT reserves during the flash‑loan cycle, after which balances settle to a new state.  
- Address `0x078f3f...` receives a substantial USDT transfer, financed entirely by the loss of `0x8262...`.

## 7. References

The analysis and this report are backed by the following on‑disk artifacts:

- **[1]** Seed transaction metadata and balance diffs for `0xeab9...c1c4`  
  `artifacts/root_cause/seed/56/0xeab946cfea49b240284d3baef24a4071313d76c39de2ee9ab00d957896a6c1c4/`

- **[2]** Structured trace for incident transaction `0xeab9...c1c4`  
  `artifacts/root_cause/data_collector/iter_1/tx/56/0xeab946cfea49b240284d3baef24a4071313d76c39de2ee9ab00d957896a6c1c4/trace.debug.json`

- **[3]** Cluster P&L for adversary addresses `0x26f8...` and `0xd6b9...`  
  `artifacts/root_cause/data_collector/iter_3/pnl/tx_0xeab9...c1c4_cluster_pnl.json`

- **[4]** Pseudocode summary for victim contract `0x8262...` selector `0x2397e4d7`  
  `artifacts/root_cause/data_collector/iter_4/contract/56/0x8262325bf1d8c3be83eb99f5a74b8458ebb96282/pseudocode_0x2397e4d7_summary.json`

