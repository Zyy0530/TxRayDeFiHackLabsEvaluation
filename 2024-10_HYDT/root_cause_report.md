# HYDT InitialMintV2 Mispricing Arbitrage on BSC

Protocol: HYDT (BSC, chainid 56)  
Root cause category: protocol_bug  
ACT classification: **permissionless on-chain arbitrage opportunity** (is_act = true)

The incident centers on a single adversary-crafted transaction
`0xa9df1bd97cf6d4d1d58d3adfbdde719e46a1548db724c2e76b4cd4c3222f22b3`
in block `42985311` on BSC, in which an EOA exploits the pricing logic
of the HYDT InitialMintV2 contract to mint underpriced HYDT and dump it
through multiple pools for deterministic profit in BNB-equivalent units.

## Incident Overview TL;DR

An EOA `0x4645863205b47a0a3344684489e8c446a437d66c` on BSC calls a
dedicated orchestrator contract `0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14`
in transaction
`0xa9df1bd97cf6d4d1d58d3adfbdde719e46a1548db724c2e76b4cd4c3222f22b3`
(block `42985311`).
The orchestrator invokes HYDT InitialMintV2 at
`0xA2268Fcc2FE7A2Bb755FbE5A7B3Ac346ddFeDB9B` via
`InitialMintV2.initialMint{value: 11 BNB}`,
minting HYDT at a fixed **1 HYDT per 1 USD** rate derived from a WBNB/USDT
reference pool, and then immediately dumps the freshly minted HYDT
through three HYDT pools.

Because HYDT is trading above this implicit 1 HYDT = 1 USD price in those pools,
the sequence yields a deterministic profit in BNB-equivalent terms:
the adversary EOA’s BNB balance decreases by
`3.053395088913977748` BNB (including gas),
while its WBNB balance increases by
`10.168067925005859920` WBNB,
for a net gain of
`7.114672836091882172` units in the
`BNB-equivalent (BNB/WBNB)` reference asset.

The vulnerable mint pricing, the orchestrated call chain, and the profit
calculation are all fully supported by on-chain traces and verified
contract source code, and the opportunity is accessible to any
unprivileged EOA with sufficient BNB on BSC using only public on-chain
state, satisfying the ACT criteria.

## Key Background

- HYDT is an ERC‑20 token on BSC with liquidity across multiple
  HYDT/WBNB and HYDT/USDT pools.
- The InitialMintV2 contract implements an **initial mint** mechanism:
  it converts BNB to HYDT using `DataFetcher.quote` on a WBNB/USDT
  reference pool. The BNB is forwarded to a Reserve contract, and LP
  pools absorb slippage when the newly minted HYDT is dumped.
- The adversary does not call InitialMintV2 directly. Instead, they use
  an orchestrator contract
  `0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14` to chain together:
  - `InitialMintV2.initialMint`,
  - `HYDT.mint`,
  - router swaps through the three HYDT pools, and
  - final asset routing back to the EOA.
  All invoked functions are publicly accessible and behave under standard
  DeFi semantics; no privileged access checks or non-public data sources
  are involved in the exploit path.

From the ACT perspective, the **pre‑state** for this opportunity is:

- **Block height**: `B = 42985311` on BSC (chainid 56).
- **Pre‑state definition**:
  publicly reconstructible chain state immediately before block 42985311,
  including balances and pool reserves for HYDT, WBNB, USDT, the HYDT
  pools, the Reserve contract, and the adversary EOA
  `0x4645863205b47a0a3344684489e8c446a437d66c`.
- **Pre‑state evidence**:
  - `artifacts/root_cause/seed/56/0xa9df1bd9…22f22b3/metadata.json`
  - `artifacts/root_cause/seed/56/0xa9df1bd9…22f22b3/balance_diff.json`
  - `artifacts/root_cause/data_collector/iter_4/address/56/0x46458632…d66c/balance_snapshot_42985300-42986000.json`
  - `artifacts/root_cause/data_collector/iter_4/address/56/0x46458632…d66c/tokentx_42985300-42986000.json`
  - Verified contract sources for:
    - `InitialMintV2` at `0xA2268Fcc…dFeDB9B`,
    - `HYDT` at `0x9810512B…5D0cD51`,
    - HYDT pools at
      `0xD5f07FEd…E1346d7E`,
      `0xBB8ae522…38ce957a`,
      `0x03feD6eC…AeF79f0d`.

## Vulnerability Analysis

The core vulnerability lies in the **pricing design of InitialMintV2**
and its interaction with existing HYDT secondary markets.

### InitialMintV2 pricing logic

The verified InitialMintV2 contract at
`0xA2268Fcc2FE7A2Bb755FbE5A7B3Ac346ddFeDB9B` exposes
an external payable `initialMint` function with time‑window and
USD‑notional caps, but **no coupling to the actual HYDT market price**.
Relevant excerpt (simplified):

```solidity
function getCurrentPrice() public view returns (uint256) {
    address[] memory path = new address[](3);
    path[0] = address(HYDT);
    path[1] = WBNB;
    path[2] = USDT;
    uint256 amountIn = 1 * 1e18;
    uint256 price = DataFetcher.quoteRouted(PANCAKE_FACTORY, amountIn, path);
    return price;
}

function initialMint() external payable {
    require(msg.value > 0, "InitialMint: insufficient BNB amount");
    ...
    uint256 amount = DataFetcher.quote(PANCAKE_FACTORY, msg.value, WBNB, USDT);
    ...
    initialMints.amount += amount;
    dailyInitialMints.amount += amount;
    SafeETH.safeTransferETH(RESERVE, msg.value);
    HYDT.mint(_msgSender(), amount);

    emit InitialMint(_msgSender(), msg.value, amount, 1 * 1e18);
}
```

Key properties:

- `initialMint()` computes `amount` using
  `DataFetcher.quote(PANCAKE_FACTORY, msg.value, WBNB, USDT)`, i.e.
  **converting the input BNB to a USDT notional via a WBNB/USDT reference pool**.
- It then calls `HYDT.mint(_msgSender(), amount)` and emits an
  `InitialMint` event with `callingPrice = 1e18`, effectively minting
  HYDT at a fixed rate of **1 HYDT per 1 USD**.
- Limits `INITIAL_MINT_LIMIT` and `DAILY_INITIAL_MINT_LIMIT` cap the
  **total USD value** minted but do not depend on or constrain the
  prevailing HYDT price in other pools.

The HYDT token at `0x9810512Be701801954449408966c630595D0cD51`
is an AccessControl‑protected ERC‑20.
`HYDT.mint` is restricted to addresses granted the `CALLER_ROLE`,
which in deployment includes the InitialMintV2 contract, so
InitialMintV2 can freely mint HYDT as long as its own constraints are satisfied.

### Misalignment with secondary market price

- During the incident, HYDT trades in three pools:
  - `0xD5f07FEd6Ddca96c6e93f06498dfeCF7E1346d7E`,
  - `0xBB8ae522F812E9E65239A0e5db87a9D738ce957a`,
  - `0x03feD6eCF872a827C07EAb63106E8f04AeF79f0d`.
- HYDT prices in these pools are **above** the implicit 1 HYDT = 1 USD
  mint price set by InitialMintV2.
- This gap allows any EOA to:
  1. send BNB into InitialMintV2,
  2. receive underpriced HYDT at 1 HYDT per 1 USD, and
  3. immediately dump HYDT back into the HYDT/WBNB and HYDT/USDT pools,
     extracting profit funded by protocol‑ and LP‑owned liquidity.

### Vulnerable components

- **InitialMintV2 initial mint mechanism**
  at `0xA2268Fcc2FE7A2Bb755FbE5A7B3Ac346ddFeDB9B`:
  - pricing logic based solely on a WBNB/USDT reference pool,
  - fixed rate of 1 HYDT per 1 USD for mints, independent of HYDT
    market price elsewhere.
- **Reserve contract**
  at `0xc5161aE3437C08036B98bDb58cfE6bBfF876c177`
  and the three HYDT pools above:
  - act as **value sources**: Reserve receives BNB from mints; pools
    absorb slippage when HYDT is dumped.
- **Orchestrator contract**
  at `0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14`:
  - sequences InitialMintV2, HYDT, and router calls on behalf of the
    adversary EOA, turning the design flaw into a streamlined strategy.

### Security principles violated

- The primary mint price is **not aligned** with the secondary market
  price, enabling risk‑free arbitrage that extracts value from
  protocol/LP liquidity.
- The design **relies on a single external reference pool**
  (WBNB/USDT) to price HYDT mints without enforcing any invariant that
  keeps HYDT pools—where the minted HYDT is actually dumped—in sync with
  that reference, leaving them exposed to systematic exploitation.

## Detailed Root Cause Analysis

### ACT opportunity definition and transaction sequence

The ACT opportunity is defined around block `42985311` on BSC:

- **State snapshot B (pre‑state)**:
  - Balances and reserves of HYDT, WBNB, USDT,
    the three HYDT pools, the Reserve contract, and the adversary EOA.
  - All reconstructible from the listed metadata, balance diffs, and
    balance snapshots.

- **Transaction sequence `b`**:
  - Single transaction:
    - `index`: 1
    - `chainid`: 56 (BSC)
    - `txhash`:
      `0xa9df1bd97cf6d4d1d58d3adfbdde719e46a1548db724c2e76b4cd4c3222f22b3`
    - `type`: adversary-crafted
  - **Inclusion feasibility**:
    - The tx is a single EOA‑signed call from
      `0x4645863205b47a0a3344684489e8c446a437d66c`
      to public orchestrator
      `0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14`.
    - It uses a standard gas price and encounters no privileged access
      checks along the InitialMintV2, HYDT, SwapRouter, or pool calls.
    - All functions in the call chain are externally callable and
      operate on public on‑chain state.
    - Therefore, any unprivileged EOA with sufficient BNB balance on BSC
      can construct, sign, and submit an equivalent transaction against
      the same or similar pre‑state and obtain the same call sequence
      under standard inclusion rules.

The single relevant transaction is explicitly recorded as:

- `all_relevant_txs`:
  - chainid 56, txhash
    `0xa9df1bd97cf6d4d1d58d3adfbdde719e46a1548db724c2e76b4cd4c3222f22b3`,
    role = `adversary-crafted`.

### Trace-based reconstruction of the exploit path

The foundry trace for the incident transaction shows the detailed
sequence of calls within the orchestrator:

```text
... 0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14::3c9c2087{value: 3050065320913977748}(...) 
    ├─ InitialMintV2::initialMint{value: 11000000000000000000}(...)
    │   ├─ BEP20USDT::getReserves() ...   // via DataFetcher.quote on WBNB/USDT
    │   ├─ HYDT::mint(0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14,
    │   │             60961921249934820691479)
    │   │   ├─ emit Transfer(from: 0x0, to: 0x8f921E27..., value: 60961921249934820691479)
    │   ├─ emit InitialMint(user: 0x8f921E27...,
    │                       amountBNB: 11000000000000000000,
    │                       amountHYDT: 60961921249934820691479,
    │                       callingPrice: 1000000000000000000)
    ├─ HYDT::approve(SwapRouter: 0x1b81D678..., 30480960624967410345739)
    ├─ SwapRouter::exactInputSingle(...)
    │   ├─ PancakeV3Pool::swap(...)        // HYDT → USDT
    │   │   ├─ BEP20USDT::transfer(0x8f921E27..., 20801440045608164984189)
    ├─ subsequent swaps through HYDT pools and routers (HYDT/USDT, HYDT/WBNB) ...
```

This trace confirms:

- `InitialMintV2.initialMint` receives exactly 11 BNB,
  forwards it to the Reserve, and mints
  `60,961.921249934820691479` HYDT
  to the orchestrator address at a **calling price of 1e18** (1 HYDT).
- The orchestrator then approves HYDT to the SwapRouter and executes a
  sequence of swaps through the three HYDT pools, routing HYDT → USDT → WBNB.

### Balance-based verification of profit

The adversary EOA’s balance snapshot confirms the net BNB-equivalent gain:

```json
{
  "chainid": 56,
  "address": "0x4645863205b47a0a3344684489e8c446a437d66c",
  "native_balance": {
    "start_block": 42985300,
    "end_block": 42986000,
    "start_wei": 93096695723533900889,
    "end_wei": 90043300634619923141,
    "delta_wei": -3053395088913977748
  },
  "erc20_balances": {
    "WBNB": {
      "start_raw": 9170949962907504757,
      "end_raw": 19339017887913364677,
      "delta_raw": 10168067925005859920
    },
    "HYDT": { "start_raw": 0, "end_raw": 0, "delta_raw": 0 },
    "USDT": { "start_raw": 7509103030153373719815,
              "end_raw": 7509103030153373719815,
              "delta_raw": 0 }
  }
}
```

Interpreting these values:

- BNB: `delta_wei = -3.053395088913977748` BNB.
- WBNB: `delta_raw = 10.168067925005859920` WBNB.
- HYDT: no net position (minted HYDT is fully dumped within the tx).
- USDT: no net position.

The **success predicate** is purely monetary:

- `type`: `profit`.
- `reference_asset`: `BNB-equivalent (BNB/WBNB)`.
- `adversary_address`:
  `0x4645863205b47a0a3344684489e8c446a437d66c`.
- `fees_paid_in_reference_asset`: `0.003329768` BNB.
- `value_before_in_reference_asset` and `value_after_in_reference_asset`:
  those balances are taken directly from the balance snapshot above.
- `value_delta_in_reference_asset`:
  net **+7.114672836091882172** units of BNB-equivalent.
- `valuation_notes`:
  - derived from `balance_diff.json` and the iter_4 balance snapshot
    and token transfer logs,
  - the EOA pays `3.053395088913977748` BNB (including gas),
  - receives `10.168067925005859920` WBNB,
  - with no offsetting HYDT or USDT losses.

There is no additional non‑monetary success predicate; the fields
`oracle_name`, `oracle_definition`, and `oracle_evidence`
in the non‑monetary block are intentionally left empty.

### Root cause summary

Combining code, traces, and balances:

- InitialMintV2 is designed to always trade BNB for HYDT at a fixed
  1 HYDT per 1 USD reference price based on WBNB/USDT reserves.
- During the incident, HYDT’s market price in the HYDT pools is
  materially higher than this implicit mint price.
- The adversary uses a public orchestrator to:
  1. withdraw WBNB,
  2. call `InitialMintV2.initialMint{value: 11 BNB}`,
     minting `60,961.9212…` HYDT,
  3. route HYDT through HYDT/USDT and HYDT/WBNB pools,
  4. end with extra WBNB in their EOA.
- The net result is a deterministic profit of
  `7.114672836091882172` BNB-equivalent,
  funded entirely by protocol and pool liquidity.

This mechanism is fully deterministic, uses only publicly accessible
contracts and on-chain state, and does not depend on any hidden order
flow or private information, fulfilling the ACT definition.

## Adversary Flow Analysis

### Strategy summary

The adversary executes a **single-transaction mint‑and‑dump arbitrage**
using an orchestrator contract:

- BNB from the EOA is funneled through the orchestrator.
- The orchestrator calls InitialMintV2 to mint underpriced HYDT.
- Newly minted HYDT is immediately swapped through HYDT pools into USDT
  and then WBNB.
- The EOA ends with more WBNB than its starting BNB, while HYDT pools
  and the Reserve absorb the losses.

### Adversary-related accounts

**Adversary cluster**

- EOA `0x4645863205b47a0a3344684489e8c446a437d66c`
  - Sender of the incident transaction.
  - Direct beneficiary of the `10.168067925005859920` WBNB profit.
  - Balance snapshots and diff files show its BNB decrease and WBNB
    increase matching the profit calculation.
- Orchestrator `0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14`
  - Contract recipient of the EOA’s call.
  - Dispatches `InitialMintV2.initialMint`, `HYDT.mint`, and router/pool
    calls in the same transaction.
  - Address‑level txlists show calls in the analysis window originate
    from the adversary EOA.

**Victim candidates / value sources**

- `HYDT InitialMintV2`
  - Address: `0xA2268Fcc2FE7A2Bb755FbE5A7B3Ac346ddFeDB9B`.
  - Verified source; implements vulnerable mint pricing logic.
- `HYDT ERC‑20 token`
  - Address: `0x9810512Be701801954449408966c630595D0cD51`.
  - Verified source; grants `CALLER_ROLE` to InitialMintV2 and other
    protocol components, enabling minting.
- HYDT pools:
  - `0xD5f07FEd6Ddca96c6e93f06498dfeCF7E1346d7E`
  - `0xBB8ae522F812E9E65239A0e5db87a9D738ce957a`
  - `0x03feD6eCF872a827C07EAb63106E8f04AeF79f0d`
  - All verified; hold HYDT paired with WBNB and/or USDT; their reserves
    shift in line with the HYDT dump path.
- `Reserve`
  - Address: `0xc5161aE3437C08036B98bDb58cfE6bBfF876c177`.
  - Verified; receives the 11 BNB from `InitialMintV2.initialMint`.

### Lifecycle stages

1. **Adversary initial funding and setup**
   - Transaction:
     - Chain: BSC (56),
     - Tx: `0xa9df1bd9…22f22b3`,
     - Block: `42985311`,
     - Mechanism: transfer.
   - Effect:
     - The EOA allocates BNB and maintains WBNB balances sufficient to
       fund the orchestrator call.
     - This is visible in the pre-state balances from
       `balance_snapshot_42985300-42986000.json`, combined with
       token transfer logs.
   - Evidence:
     - `metadata.json` and `balance_diff.json` under the seed artifacts.
     - Iter_4 balance snapshot for the EOA.

2. **Adversary contract orchestration and mint**
   - Transaction:
     - Same tx/chain/block as above,
     - Mechanism: contract_call.
   - Effect:
     - The EOA calls orchestrator `0x8f921E27…` with
       `3.050065320913977748` BNB.
     - The orchestrator:
       - pulls 11 BNB from WBNB,
       - calls `InitialMintV2.initialMint{value: 11 BNB}`,
       - forwards 11 BNB to the Reserve,
       - mints `60,961.921249934820691479` HYDT to itself.
   - Evidence:
     - `trace.cast.log` for the incident tx (showing the mint and event).
     - Verified sources for InitialMintV2 and HYDT.

3. **Adversary HYDT dump and profit realization**
   - Transaction:
     - Same tx/chain/block,
     - Mechanism: swap.
   - Effect:
     - The orchestrator routes the freshly minted HYDT through:
       - pool `0xD5f07FEd…E1346d7E` (Pancake V3 style),
       - pool `0xBB8ae522…38ce957a`,
       - pool `0x03feD6eC…AeF79f0d`,
       using SwapRouter and PancakeRouter.
     - Intermediate USDT flows through
       `0x92b7807bF19b7DDdf89b706143896d05228f3121`.
     - The EOA ends with about `10.168067925005859920` WBNB
       and a `3.053395088913977748` BNB decrease (including gas),
       yielding the net `+7.114672836091882172` BNB-equivalent gain.
   - Evidence:
     - `trace.cast.log` (swap calls and Transfer events).
     - `balance_diff.json` (pool‑side HYDT and USDT deltas).
     - EOA balance snapshot and token transfer logs in iter_4.

## Impact & Losses

### Total loss overview

- Reference token: `BNB-equivalent (BNB/WBNB)`.
- Total adversary gain:
  - `7.114672836091882172` units in BNB-equivalent.

### Impact narrative

The adversary realizes a **deterministic** gain of
`7.114672836091882172` BNB-equivalent in a **single transaction** by:

- using InitialMintV2 to mint underpriced HYDT at 1 HYDT per 1 USD, and
- dumping that HYDT into the three HYDT pools to extract WBNB while the
  Reserve receives BNB.

The loss is borne by:

- LPs providing HYDT/USDT and HYDT/WBNB liquidity in the three pools,
  whose token balances shift unfavorably (as shown in `balance_diff.json`);
  they effectively finance the arbitrage profit via slippage.
- The Reserve, which accumulates BNB from initial mints without capturing
  the full economic value of the minted HYDT relative to secondary
  market prices.

Detailed per‑LP and per‑pool loss allocation is **not computed** in this
report, but pool‑side balance changes in `balance_diff.json` and the
verified contract sources suffice to attribute the high‑level loss to
protocol/LP liquidity rather than to any third party.

## References

Primary artifacts:

- **[1] Seed transaction metadata and trace**  
  `artifacts/root_cause/seed/56/0xa9df1bd97cf6d4d1d58d3adfbdde719e46a1548db724c2e76b4cd4c3222f22b3`
- **[2] InitialMintV2 and HYDT verified sources**  
  `artifacts/root_cause/data_collector/iter_1/contract/56`
- **[3] Adversary EOA balance snapshots and token transfers**  
  `artifacts/root_cause/data_collector/iter_4/address/56/0x4645863205b47a0a3344684489e8c446a437d66c`

ACT pre‑state and success predicate evidence:

- `metadata.json` and `balance_diff.json` for tx
  `0xa9df1bd97cf6d4d1d58d3adfbdde719e46a1548db724c2e76b4cd4c3222f22b3`
  under `artifacts/root_cause/seed/56/`.
- `balance_snapshot_42985300-42986000.json` and
  `tokentx_42985300-42986000.json` for EOA
  `0x4645863205b47a0a3344684489e8c446a437d66c`
  under `artifacts/root_cause/data_collector/iter_4/address/56/`.
- Verified contract trees for:
  - InitialMintV2 (`0xA2268Fcc…dFeDB9B`),
  - HYDT (`0x9810512B…5D0cD51`),
  - HYDT pools (`0xD5f07FEd…`, `0xBB8ae522…`, `0x03feD6eC…`).

This report is fully determined by the artifacts listed above, without
speculative language, and matches the ACT opportunity and root cause
described in `root_cause.json`.

