# Flash-Loan Cross-Venue WETH/USDC Arbitrage on Arbitrum

## Incident Overview & TL;DR

On Arbitrum (chainid 42161), an unprivileged searcher EOA `0x8a0dfb61cad29168e1067f6b23553035d83fcfb2` deployed a custom strategy contract `0x69fa61eB4dC4E07263D401b01ed1CfCeb599dAb8` and used it to execute a flash-loan-based cross-venue arbitrage between Algebra’s GMX/USDC pool, Aave v3 WETH markets, and a Uniswap V3 WETH/USDC pool in seed transaction `0xb5cfa4ae4d6e459ba285fec7f31caf8885e2285a0b4ff62f66b43e280c947216`.

The core finding is that there is **no protocol-level bug or access control failure** in Algebra, Aave v3, Uniswap V3, or WETH. All protocols behave according to their published logic and invariants. The profitable behavior stems from a **transient economic mispricing** between:

- Algebra GMX/USDC pool `0x8cc8093218bCaC8B1896A1EED4D925F6F6aB289F`
- Aave v3 WETH pool `0x794a61358D6845594F94dc1DB02A252b5b4814aD` and WETH aToken `0xe50fA9b3c56FfB159cB0FCA61F5c9D750e8128c8`
- Uniswap V3 WETH/USDC pool `0xC31E54c7a869B9FcBEcc14363CF510d1c41fa443`

This mispricing allowed the strategy to borrow USDC via an Algebra flash loan, route it through Aave and Uniswap, fully repay the loan plus fees, and still leave the adversary with net profit in USDC.e, a WBTC-like wrapped BTC token, and WETH, which was then converted to ETH.

**Root cause (categorization):** Economic MEV-style cross-venue arbitrage arising from public price dislocation, not a smart-contract vulnerability.

## Key Background

- **Concentrated-liquidity AMMs (Algebra & Uniswap V3).**  
  Algebra and Uniswap V3 are concentrated-liquidity AMMs. Liquidity providers are passive counterparties to trades and flash loans; they earn fees but are exposed to inventory and price-risk when prices diverge. Any unprivileged actor can arbitrage these pools whenever their prices move out of line with other venues.

- **Aave v3 WETH market.**  
  Aave v3 uses a pool contract and separate aToken proxies. In this incident the relevant WETH pool proxy is `0x794a61358D6845594F94dc1DB02A252b5b4814aD` and the WETH aToken proxy is `0xe50fA9b3c56FfB159cB0FCA61F5c9D750e8128c8`. aToken `totalSupply` plus underlying token balances encode deposits and interest accrual. The collected on-chain sources confirm these are standard Aave v3 contracts on Arbitrum, running battle-tested logic.

- **Canonical WETH on Arbitrum.**  
  WETH `0x82af49447d8a07e3bd95bd0d56f35241523fbab1` wraps native ETH. `withdraw(uint256)` burns WETH and sends native ETH, allowing strategies to convert ERC-20-denominated profit into gas-usable ETH.

- **ParaSwap as a meta-DEX router.**  
  ParaSwap router `0xdef171fe48cf0115b1d80b88dc8eab59176fee57` exposes `megaSwap` and `simpleSwap` functions that route across underlying AMMs and bridges. Any EOA can use these functions by approving ERC-20 balances and calling the router; no privileged role is required.

These properties together mean that:

- Flash loans and deep liquidity are openly available on public AMMs and lending markets.
- Any EOA can orchestrate complex multi-hop swaps and lending interactions atomically within a single transaction.
- If prices drift, a well-crafted strategy can capture the resulting arbitrage spread without violating any protocol invariant.

## Vulnerability & Root Cause Analysis

### High-level vulnerability characterization

`root_cause.json` identifies that there is **no code-level defect** in Algebra, Aave v3, Uniswap V3, or WETH. The exploitable condition is purely **economic**:

- Prices across Algebra GMX/USDC, Aave WETH (via aeWETH), and Uniswap V3 WETH/USDC were sufficiently misaligned at block `259645908` that a flash-loan-funded cycle could:
  - Borrow a large amount of USDC from Algebra’s GMX/USDC pool.
  - Move value through Aave and Uniswap.
  - Repay Algebra with a fee.
  - Leave the adversary with a residual positive portfolio in USDC.e, WBTC-like, and WETH.

No invariant such as AMM balance conservation or Aave collateralization is violated. Instead, the incident is a textbook example of **MEV arbitrage** exploiting a temporary cross-venue price dislocation.

### Strategy contract and hardcoded components

The adversary’s strategy contract `0x69fa61eB4dC4E07263D401b01ed1CfCeb599dAb8` is deployed and then used as the core primitive orchestrating the flash loan and subsequent actions.

Key observations from the decompiled strategy (`0x69fa61…-decompiled.sol`) and related artifacts:

- The contract is owner-controlled (checking `tx.origin == _owner` in several functions) and is not a generic permissionless arbitrage contract.
- It encodes addresses of DeFi components used in the arbitrage:
  - Algebra GMX/USDC pool: `0x8cc8093218bCaC8B1896A1EED4D925F6F6aB289F`
  - Uniswap V3 WETH/USDC pool: `0xC31E54c7a869B9FcBEcc14363CF510d1c41fa443`
  - Aave v3 WETH pool and WETH aToken proxies: `0x794a61358D6845594F94dc1DB02A252b5b4814aD`, `0xe50fA9b3c56FfB159cB0FCA61F5c9D750e8128c8`
  - Tokens including USDC.e `0xaf88d065e77c8cC2239327C5EDb3A432268e5831`, GMX `0x3d9907F9a368ad0a51Be60f7Da3b97cf940982D8`, WBTC-like `0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f`, and WETH `0x82af49447d8a07e3bd95bd0d56f35241523fbab1`.

**Evidence snippet – strategy ownership and token-transfer logic (decompiled):**

```solidity
// Collected decompiled strategy contract for 0x69fa61eB... (heimdall-rs output)
contract DecompiledContract {
    address public _owner;

    /// @custom:selector    0x03508b67
    function Unresolved_03508b67() public {
        require(tx.origin == (address(_owner)), "Ownable: Caller not owner");
        (bool success, bytes memory ret0) = address(_owner).transfer(address(this).balance);
    }

    /// @custom:selector    0x2c8958f6
    function Unresolved_2c8958f6(uint256 arg0, uint256 arg1, uint256 arg2) public {
        require(tx.origin == (address(_owner)), "Ownable: Caller not owner");
        // ... token transfer logic using stored addresses ...
    }
}
```

*Caption: Decompiled strategy contract source showing owner-gated functions and custom token-transfer logic, confirming this is an adversary-controlled arbitrage primitive rather than a protocol contract.*

### Seed flash-loan transaction behavior

The pivotal transaction is the seed flash-loan tx:

- **Chain:** Arbitrum (`42161`)
- **Tx hash:** `0xb5cfa4ae4d6e459ba285fec7f31caf8885e2285a0b4ff62f66b43e280c947216`
- **Sender:** `0x8a0dfb61cad29168e1067f6b23553035d83fcfb2` (adversary EOA)
- **To:** `0x69fa61eB4dC4E07263D401b01ed1CfCeb599dAb8` (strategy contract)

From the collected trace (`cast run -vvvvv` style log) and balance-diff artifacts, the execution proceeds as:

1. The strategy checks existing balances and approvals via proxies.
2. Algebra GMX/USDC pool `0x8cc809…` executes `flash(...)`, lending `2,633,623,953,738` units of USDC to the strategy.
3. Inside the flash callback, the strategy routes the borrowed USDC through a sequence of swaps and Aave interactions involving:
   - Aave v3 WETH pool and aToken (deposit/withdraw/repay mechanics).
   - Uniswap V3 WETH/USDC pool `0xC31E54…`, where WETH reserves decrease and USDC reserves increase (indicating selling WETH for USDC).
4. At the end of the callback, the strategy repays the Algebra flash loan plus fee.
5. Residual assets (net of all repayments) accrue to the adversary EOA.

**Evidence snippet – Algebra flash loan and callback (seed transaction trace):**

```text
// Seed transaction trace for 0xb5cfa4ae..., focusing on Algebra flash and callback
Traces:
  [12788099] 0x69FA61eB4dC4E07263D401b01ed1CfCeb599dAb8::7ff8bc17(...)
    ...
    ├─ [12488996] 0x8cc8093218bCaC8B1896A1EED4D925F6F6aB289F::flash(
    │       0x69FA61eB4dC4E07263D401b01ed1CfCeb599dAb8,
    │       0,
    │       2633623953738 [2.633e12],
    │       0x000000000000000000000000000000000000000000000000000002653038614a)
    │   ...
    │   ├─ [30651] ...::transfer(
    │   │       from: 0x8cc8093218bCaC8B1896A1EED4D925F6F6aB289F,
    │   │       to:   0x69FA61eB4dC4E07263D401b01ed1CfCeb599dAb8,
    │   │       value: 2633623953738 [2.633e12])
    │   ...
    │   ├─ [12416037] 0x69FA61eB4dC4E07263D401b01ed1CfCeb599dAb8::algebraFlashCallback(
    │   │       0,
    │   │       263362396 [2.633e8],
    │   │       0x000000000000000000000000000000000000000000000000000002653038614a)
    │   ...
```

*Caption: Seed transaction trace showing Algebra GMX/USDC pool extending a flash loan of ~2.633e12 USDC and invoking the strategy’s `algebraFlashCallback` to perform the arbitrage cycle before repayment.*

### Pool and Aave state consistency

The aggregated Aave/AMM state around the seed transaction shows:

- Algebra GMX/USDC pool:
  - USDC reserves increase from `2,633,623,953,738` to `2,633,847,811,775` (+`223,858,037`), reflecting fee income and net inflow from the trade path.
- Uniswap V3 WETH/USDC pool:
  - WETH reserves decrease, USDC reserves increase, consistent with the strategy selling WETH for USDC.
- Aave WETH pool and aToken:
  - Underlying WETH balance in the pool remains constant at `0.1 ETH` (`100000000000000000` wei).
  - aToken `totalSupply` changes slightly, consistent with normal interest accounting, but does not indicate any undercollateralization or unbacked mint.

**Evidence snippet – pool and Aave state summary (pre/post seed tx):**

```json
// State summary around seed tx 0xb5cfa4ae... (selected entries)
{
  "0x8cc8093218bCaC8B1896A1EED4D925F6F6aB289F": {
    "type": "algebra_pool",
    "reserves_before": {
      "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": "2633623953738"
    },
    "reserves_after": {
      "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": "2633847811775"
    }
  },
  "0xC31E54c7a869B9FcBEcc14363CF510d1c41fa443": {
    "type": "uniswap_v3_pool",
    "reserves_before": {
      "0x82af49447d8a07e3bd95bd0d56f35241523fbab1": "1445714045733728958173",
      "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": "1418946949914"
    },
    "reserves_after": {
      "0x82af49447d8a07e3bd95bd0d56f35241523fbab1": "1444623093342631863373",
      "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": "1422802628151"
    }
  },
  "0x794a61358D6845594F94dc1DB02A252b5b4814aD": {
    "type": "aave_pool",
    "underlying_balance_before": "100000000000000000",
    "underlying_balance_after": "100000000000000000"
  }
}
```

*Caption: High-level state summary showing Algebra’s USDC reserves increasing, Uniswap V3 shifting from WETH to USDC, and Aave WETH pool balances remaining constant, consistent with fee-generating arbitrage rather than a protocol accounting failure.*

### Profit realization in the seed transaction

The decoded ERC-20 balance diffs for the seed tx show that the adversary EOA starts from zero in key assets and ends with significant positive balances:

- USDC.e (0xaf88d0…): `+125,795,603,292` units
- WBTC-like token (0x2f2a25…): `+679,208` units
- WETH (0x82af49…): `+2.25` WETH

**Evidence snippet – adversary ERC-20 gains in seed tx:**

```json
// Decoded balance diffs for tx 0xb5cfa4ae... (selected entries)
{
  "entries": [
    {
      "token": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
      "address": "0x8a0dfb61cad29168e1067f6b23553035d83fcfb2",
      "balance_before": "0",
      "balance_after": "125795603292",
      "balance_delta": "125795603292"
    },
    {
      "token": "0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f",
      "address": "0x8a0dfb61cad29168e1067f6b23553035d83fcfb2",
      "balance_before": "0",
      "balance_after": "679208",
      "balance_delta": "679208"
    },
    {
      "token": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
      "address": "0x8a0dfb61cad29168e1067f6b23553035d83fcfb2",
      "balance_before": "0",
      "balance_after": "2250000000000000000",
      "balance_delta": "2250000000000000000"
    }
  ]
}
```

*Caption: Balance-diff evidence that the adversary EOA acquires USDC.e, WBTC-like tokens, and 2.25 WETH in the seed tx while having zero balances in those tokens before the transaction.*

### Vulnerable components and exploit conditions

From the analysis:

- **Vulnerable components (economically exploitable, not buggy):**
  - Algebra GMX/USDC pool `0x8cc809…` (`flash` / `swap`)
  - Uniswap V3 WETH/USDC pool `0xC31E54…` (`swap`)
  - Aave v3 WETH pool `0x794a61…` and WETH aToken `0xe50fA9…`
  - WETH `0x82af49…` (`deposit`/`withdraw`)

- **Exploit conditions:**
  - At block `259645907` (pre-seed), the relative pricing across Algebra GMX/USDC, Aave WETH, and Uniswap V3 WETH/USDC must allow a flash-loan cycle that:
    - Borrows ~`2.6336e12` USDC from Algebra.
    - Trades via Aave and Uniswap.
    - Repays principal and fees.
    - Leaves a strictly positive residual position (USDC.e, WBTC-like, WETH).
  - All protocols must support the necessary flash loan sizes and liquidity depth at the implied prices.
  - Any unprivileged EOA can deploy a similar strategy contract and submit equivalent calls; there is no requirement for special roles.

### Security principles affected

No explicit on-chain invariant is broken. Instead, the incident illustrates:

- The **economic assumption** that cross-venue prices remain aligned enough to prevent large, near-riskless flash-loan arbitrage is violated.
- Public, composable DeFi protocols plus flash loans ensure that **any observable mispricing will be arbitraged** by searchers, transferring value from liquidity providers and counterparties to arbitrageurs.

## Adversary Flow Analysis

### Adversary strategy summary

The adversary’s lifecycle follows a clear multi-step pattern:

1. Deploy a custom strategy contract that hardcodes Algebra, Aave, Uniswap, WETH, and token addresses.
2. Use a single flash-loan-based transaction to borrow USDC from Algebra, route it through Aave and Uniswap to end with USDC.e, WBTC-like, and WETH profits.
3. Consolidate these ERC-20 gains into WETH / ETH via ParaSwap swaps.
4. Withdraw WETH to native ETH.
5. Transfer the ETH profit from the searcher EOA to a separate “profit-sink” EOA.

### Adversary-related accounts

`root_cause.json` attributes the following addresses to the adversary cluster:

- **Searcher EOA (controller):** `0x8a0dfb61cad29168e1067f6b23553035d83fcfb2`  
  - Sender of the strategy deployment tx, seed flash-loan tx, approvals, ParaSwap swaps, WETH withdraw, and final ETH transfer.
  - Direct recipient of ERC-20 profits in the seed transaction.

- **Strategy contract:** `0x69fa61eB4dC4E07263D401b01ed1CfCeb599dAb8`  
  - Deployed by the adversary EOA (nonce 0) and invoked in the seed tx.
  - Encodes the arbitrage logic and DeFi addresses used in the flow.

- **Profit-sink EOA:** `0xe236b17749524ed7ca89aa64c18cc48f7322baca`  
  - Receives `54.889565628636355588 ETH` from the adversary EOA in the final tx, consolidating the realized profit.

The main “victim” entities from a value-transfer perspective are **liquidity providers and counterparties** in:

- Algebra GMX/USDC pool `0x8cc809…`
- Uniswap V3 WETH/USDC pool `0xC31E54…`

### Lifecycle stage 1 – Strategy deployment and setup

- **Tx:** `0x1d2ae4c9cf09499c0f20beebcd5563f6710cefa1daa1759413189f8ebc853a9c`  
- **Mechanism:** Contract deployment  
- **Effect:** The adversary EOA deploys the strategy contract, wiring in key DeFi addresses as constructor parameters and storage constants. This creates a reusable on-chain arbitrage primitive.

Evidence comes from the Etherscan-style tx list for the adversary EOA and the decompiled strategy source (see snippet above). No invariant is violated at this stage; the adversary simply prepares infrastructure.

### Lifecycle stage 2 – Flash-loan arbitrage execution

- **Tx:** `0xb5cfa4ae4d6e459ba285fec7f31caf8885e2285a0b4ff62f66b43e280c947216` (seed)  
- **Mechanism:** Algebra flash loan (`flash`) combined with multi-venue swaps and Aave operations  
- **Effect:**
  - Borrow `2,633,623,953,738` units of USDC from Algebra GMX/USDC pool.
  - Execute swaps and Aave interactions that move value between:
    - Algebra GMX/USDC pool,
    - Uniswap V3 WETH/USDC pool,
    - Aave v3 WETH pool and aeWETH aToken,
    - WETH contract.
  - Repay the flash loan plus fee.
  - Leave the adversary EOA with:
    - `+125,795,603,292` USDC.e,
    - `+679,208` WBTC-like units,
    - `+2.25` WETH.

The earlier trace and balance-diff snippets concretely demonstrate the flash loan, routing, and resulting profit.

### Lifecycle stage 3 – Token consolidation via ParaSwap

- **Txs:**
  - `0xe86795071f7975254d0addb1e43fabf6297cf2ea958ec656028dbc9ac1cfc110` (ParaSwap `megaSwap`)
  - `0xf6fd4188921df9e8b5025d95302e9faa8f3d30e9a166e65bebd95e98bfb3615a` (ParaSwap `simpleSwap`)
- **Mechanism:** Meta-DEX routing of ERC-20 balances into WETH / ETH exposure.
- **Effect:**
  - The adversary first approves USDC.e and WBTC-like balances to ParaSwap.
  - In `megaSwap`, USDC.e is split across multiple underlying routes to acquire WETH/ETH exposure.
  - In `simpleSwap`, the WBTC-like token is swapped into WETH/ETH via a smaller path.
  - Decoded balance diffs show the EOA’s USDC.e and WBTC-like balances go from the positive values created in the seed tx back to zero across these swaps, indicating full conversion into WETH / ETH.

**Evidence snippet – ParaSwap megaSwap trace (USDC.e into WETH/ETH):**

```text
// ParaSwap megaSwap trace for tx 0xe86795...
Traces:
  [2541371] AugustusSwapper::fallback(MegaSwapSellData({
      fromToken: 0xaf88d065e77c8cC2239327C5EDb3A432268e5831,
      fromAmount: 125795603292 [1.257e11],
      toAmount: 51234155028405308750 [5.123e19],
      ...,
      path: [MegaSwapPath({ ... to: 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE, ... })]
  }))
  ...
```

*Caption: ParaSwap megaSwap call decoding in tx 0xe86795… showing the adversary selling 125,795,603,292 USDC.e via multiple underlying routes to obtain ETH-denominated exposure.*

### Lifecycle stage 4 – WETH withdrawal and ETH profit consolidation

- **Tx (WETH → ETH):** `0xee6aafce5bca96db2494320b30ea9f71e9b248407a7010b940f29848dd69c75c`  
- **Mechanism:** `WETH.withdraw(2.25 ether)`  
- **Effect:**
  - Burns the adversary’s `2.25 WETH` balance.
  - Increases the adversary’s native ETH balance by `2.2499989271 ETH`, net of this tx’s gas.
  - Decreases the WETH contract’s ETH balance by `2.25 ETH`.

**Evidence snippet – WETH withdrawal balance diffs:**

```json
// Decoded balance diffs for tx 0xee6aafce...
{
  "entries": [
    {
      "token": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
      "address": "0x8a0dfb61cad29168e1067f6b23553035d83fcfb2",
      "balance_before": "2250000000000000000",
      "balance_after": "0",
      "balance_delta": "-2250000000000000000"
    },
    {
      "token": "ETH",
      "address": "0x8a0dfb61cad29168e1067f6b23553035d83fcfb2",
      "balance_before": "52639567923232355588",
      "balance_after": "54889566850332355588",
      "balance_delta": "2249998927100000000"
    },
    {
      "token": "ETH",
      "address": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
      "balance_before": "219246505129072204420578",
      "balance_after": "219244255129072204420578",
      "balance_delta": "-2250000000000000000"
    }
  ]
}
```

*Caption: WETH withdrawal evidence showing 2.25 WETH burned from the adversary and ~2.2499989271 ETH credited to the EOA, confirming ERC-20 profit realization into native ETH.*

- **Tx (ETH profit transfer):** `0x7aa576503b53bab6bcc3dd24acf25de4cb2fc94e65ae0f1871a8418fd7541321`  
- **Mechanism:** Plain ETH transfer from the adversary EOA to the profit-sink EOA.
- **Effect:**
  - The adversary EOA’s ETH balance drops by ~`54.889565656e18` wei.
  - Profit-sink EOA `0xe236b1…` receives `54.889565628636355588 ETH`.

**Evidence snippet – final ETH consolidation:**

```json
// Decoded balance diffs for tx 0x7aa57650...
{
  "entries": [
    {
      "token": "ETH",
      "address": "0x8a0dfb61cad29168e1067f6b23553035d83fcfb2",
      "balance_before": "54889566850332355588",
      "balance_after": "494396000000",
      "balance_delta": "-54889566355936355588"
    },
    {
      "token": "ETH",
      "address": "0xe236b17749524ed7ca89aa64c18cc48f7322baca",
      "balance_before": "721391120750",
      "balance_after": "54889566350027476338",
      "balance_delta": "54889565628636355588"
    }
  ]
}
```

*Caption: Final ETH transfer from the adversary EOA to a profit-sink EOA, consolidating more than 54.88 ETH of balance in the sink address.*

## Impact & Losses

### Quantitative impact

The analysis in `root_cause.json` and `act_opportunity.exploit_predicate` concludes:

- **Reference asset:** ETH  
- **Adversary profit lower bound:**  
  - Gross WETH → ETH realized: `2.25 ETH`  
  - Total gas cost over all relevant adversary-crafted txs: `0.00022764971 ETH`  
  - **Net profit lower bound:** `2.24977235029 ETH` (rounded as `>= 2.24977235 ETH`).

The final ETH transfer of `54.889565628636355588 ETH` to `0xe236b1…` indicates the adversary cluster ends with **strictly more ETH** than at the start of the sequence, with at least `2.24977235 ETH` attributable to the documented arbitrage chain.

### Who pays?

- **Algebra GMX/USDC pool LPs (`0x8cc809…`).**  
  Their USDC reserves increase (due to fee income and routing flows), but they bear the price impact and inventory risk from providing liquidity at a mispriced level.

- **Uniswap V3 WETH/USDC pool LPs (`0xC31E54…`).**  
  Their WETH reserves decrease and USDC reserves increase, indicating they effectively buy WETH at a relatively high price while the adversary sells WETH at that price across venues.

- **Aave v3 WETH market.**  
  Aave’s pool and aToken accounting remain consistent before and after the seed transaction. There is no evidence of undercollateralization, unbacked aToken minting, or protocol insolvency.

In summary, **liquidity providers and route counterparties** are the economic losers, while the protocols themselves operate as designed and earn standard fees.

## References

The following collected artifacts support the analysis above. All paths refer to files in the orchestrator-provided artifact tree; users of this report do not need to open them to understand the conclusions, but they are listed here for completeness.

- **[1] Seed flash-loan tx trace (Algebra/Aave/Uniswap path)**  
  - Origin: Seed transaction trace (cast-style execution log) for `0xb5cfa4ae…`  
  - Evidence of: Algebra flash loan to the strategy, subsequent callback, and multi-protocol routing.

- **[2] Decoded balance diffs for seed and follow-on swaps/withdrawals**  
  - Origin: Pre/post-token-balance snapshots and decoded diffs for seed, ParaSwap swaps, WETH withdrawal, and final ETH transfer.  
  - Evidence of: Adversary balances in USDC.e, WBTC-like token, WETH, and ETH before/after each step; confirmation of no unbacked issuances or missing balances in DeFi protocols.

- **[3] Verified Aave v3 WETH pool and aToken proxy sources**  
  - Origin: Collected contract sources and ABIs for `0x794a61…` (pool) and `0xe50fA9…` (aToken).  
  - Evidence of: Standard Aave v3 proxy and implementation logic, including upgradeability and balance accounting, consistent with prior audits.

- **[4] Algebra GMX/USDC and Uniswap V3 WETH/USDC pool sources**  
  - Origin: Collected Algebra pool and Uniswap V3 pool source code and ABIs used by the strategy.  
  - Evidence of: Standard AMM swap and flash-loan mechanics, with no anomalous or custom logic suggesting a contract-level vulnerability.

## Limitations

All conclusions are based solely on the artifacts under the provided root-cause directory (seed traces, decoded balance diffs, contract sources, and state summaries). No external RPC calls or off-chain market data were fetched during this analysis. While the evidence is sufficient to establish that the event is a profitable cross-venue arbitrage rather than a protocol bug, precise real-time off-chain price feeds and order-book states at block `259645908` were not considered.

