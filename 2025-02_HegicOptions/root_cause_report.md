## Incident Overview & TL;DR

On Ethereum mainnet, an unprivileged EOA `0x4b53608fF0cE42cDF9Cf01D7d024C2c9ea1aA2e8` used a non-verified helper contract `0xF51E888616a123875EAf7AFd4417fbc4111750f7` to interact with the HegicPUT WBTC Put Pool at `0x7094E706E75E13D1E0ea237f71A7C4511e9d270B`. The helper first created a single WBTC liquidity tranche (tranche ID 2) with a small 0.0025 WBTC deposit and then repeatedly invoked `withdrawWithoutHedge(2)` hundreds of times across two transactions. This sequence drained 1.0775 WBTC from the HegicPUT pool while only ever posting 0.0025 WBTC of capital, resulting in a net profit of approximately 1.07463308 WBTC for the adversary cluster after gas costs.

The root cause is a logic bug in the HegicPool contract. The external function `withdrawWithoutHedge(uint256 trancheID)` delegates to the internal `_withdraw(address owner, uint256 trancheID)` function without enforcing that a tranche can only be withdrawn once. `_withdraw` closes the tranche but does not require that it was previously open, because a key state guard (`require(t.state == TrancheState.Open);`) is commented out. As long as the caller is approved and the lockup period has elapsed, repeated calls to `withdrawWithoutHedge` on the same tranche recompute and pay out a positive withdrawal amount, allowing cumulative over-withdrawal of pool assets from a single liquidity position.

## Key Background

### Protocol and Contracts

- **HegicPUT WBTC Put Pool (HegicPool)**  
  - Address: `0x7094E706E75E13D1E0ea237f71A7C4511e9d270B`  
  - Role: Manages WBTC liquidity tranches, issues ERC721 tranche tokens, and handles withdrawals (including `withdrawWithoutHedge`) for WBTC-based put options.

- **WBTC Token**  
  - Address: `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599`  
  - Role: Underlying collateral token whose units are deposited into and withdrawn from the HegicPUT pool.

- **Helper Contract**  
  - Address: `0xF51E888616a123875EAf7AFd4417fbc4111750f7`  
  - Type: Non-verified contract (analyzed via decompile output).  
  - Role: Orchestrates Uniswap swaps, HegicPUT deposits via `provideFrom`, loops calls to `withdrawWithoutHedge`, and finally forwards WBTC to the EOA.

- **Adversary EOA**  
  - Address: `0x4b53608fF0cE42cDF9Cf01D7d024C2c9ea1aA2e8`  
  - Role: Originates all analyzed transactions, funds the exploit with ETH, and ultimately receives WBTC profit.

### Victim Transactions and Trace Sources

The analysis focuses on four adversary-crafted Ethereum mainnet transactions:

- `0x9c27d45c1daa943ce0b92a70ba5efa6ab34409b14b568146d2853c1ddaf14f82` — initial capital deployment and tranche creation.  
- `0x260d5eb9151c565efda80466de2e7eee9c6bd4973d54ff68c8e045a26f62ea73` — first withdrawal-loop transaction (100 iterations).  
- `0x444854ee7e7570f146b64aa8a557ede82f326232e793873f0bbd04275fa7e54c` — second withdrawal-loop transaction (331 iterations).  
- `0x722f67f6f9536fa6bbf4af447250e84b8b9270b66195059c9904a0e249543e80` — final WBTC transfer from helper to EOA.

Evidence is drawn from:

- Seed metadata and Foundry `cast run -vvvvv` traces for each transaction.  
- `debug_traceTransaction` prestateTracer outputs for HegicPUT and the Uniswap WBTC/WETH pair.  
- ERC20 Transfer-log–based balance diffs for WBTC and WETH.  
- Gas cost summaries for the adversary EOA.

## Vulnerability & Root Cause Analysis

### Vulnerable Logic in HegicPool

The core bug resides in the interaction between `withdrawWithoutHedge` and `_withdraw` in HegicPool:

```solidity
// Collected HegicPool.sol source for HegicPUT WBTC pool
function withdrawWithoutHedge(uint256 trancheID)
    external
    override
    nonReentrant
    returns (uint256 amount)
{
    address owner = ownerOf(trancheID);
    amount = _withdraw(owner, trancheID);
    emit Withdrawn(owner, trancheID, amount);
}

function _withdraw(address owner, uint256 trancheID)
    internal
    returns (uint256 amount)
{
    Tranche storage t = tranches[trancheID];
    // require(t.state == TrancheState.Open);
    require(_isApprovedOrOwner(_msgSender(), trancheID));
    require(
        block.timestamp > t.creationTimestamp + lockupPeriod,
        "Pool Error: The withdrawal is locked up"
    );

    t.state = TrancheState.Closed;
    amount = (t.share * totalBalance) / totalShare;
    totalShare -= t.share;
    totalBalance -= amount;
    token.safeTransfer(owner, amount);
}
```

*Snippet origin: Collected HegicPUT / HegicPool source code for contract `0x7094…` (verified on explorer and mirrored under the seed contracts directory). It shows that `_withdraw` lacks an active state check on `t.state`, with the intended guard commented out.*

Key observations:

- `withdrawWithoutHedge` is `external` and `nonReentrant` but otherwise delegates fully to `_withdraw`.  
- `_withdraw`:
  - Loads the tranche by `trancheID`.  
  - Does not enforce that `t.state` is `Open` because the `require(t.state == TrancheState.Open);` line is commented out.  
  - Only checks `_isApprovedOrOwner(msg.sender, trancheID)` and the lockup period.  
  - Sets `t.state = TrancheState.Closed` once per call, then computes:
    - `amount = (t.share * totalBalance) / totalShare`  
    - `totalShare -= t.share`  
    - `totalBalance -= amount`  
  - Transfers `amount` of WBTC to `owner`.

With this design, a tranche can be withdrawn multiple times in the same transaction, as long as:

- The caller remains approved or owner.  
- The lockup period has passed.  
- There is still positive `totalBalance` and `totalShare` to support a nonzero `amount` calculation.

The commented-out state guard is the direct root cause: it removes the invariant that a liquidity tranche can be closed exactly once.

### Evidence of Repeated Withdrawals for a Single Tranche

The withdrawal-loop transactions confirm that the helper repeatedly calls `withdrawWithoutHedge(2)` on the same tranche ID:

```txt
Traces:
  [1532947] 0xF51E888616a123875EAf7AFd4417fbc4111750f7::get(HegicPUT: [0x7094…], 2, 100)
    ├─ HegicPUT::withdrawWithoutHedge(2)
    │   ├─ WBTC::transfer(0xF51E8886…, 250000 [2.5e5])
    │   ├─ emit Withdrawn(account: 0xF51E8886…, trancheID: 2, amount: 250000 [2.5e5])
    ├─ HegicPUT::withdrawWithoutHedge(2)
    │   ├─ WBTC::transfer(0xF51E8886…, 250000 [2.5e5])
    │   ├─ emit Withdrawn(account: 0xF51E8886…, trancheID: 2, amount: 250000 [2.5e5])
    ├─ … (repeats up to 100 iterations)
```

*Snippet origin: Seed transaction trace (`cast run -vvvvv`) for tx `0x260d…`, showing helper `get` calling `HegicPUT::withdrawWithoutHedge(2)` 100 times, each emitting a Withdrawn event with 250,000 WBTC units and a matched WBTC transfer from HegicPUT to the helper.*

A similar pattern appears in the second loop transaction:

```txt
Traces:
  [4986833] 0xF51E888616a123875EAf7AFd4417fbc4111750f7::get(HegicPUT: [0x7094…], 2, 331)
    ├─ HegicPUT::withdrawWithoutHedge(2)
    │   ├─ WBTC::transfer(0xF51E8886…, 250000 [2.5e5])
    │   ├─ emit Withdrawn(account: 0xF51E8886…, trancheID: 2, amount: 250000 [2.5e5])
    ├─ … (repeats up to 331 iterations)
```

*Snippet origin: Seed transaction trace (`cast run -vvvvv`) for tx `0x4448…`, showing 331 repeated calls to `withdrawWithoutHedge(2)` within a single helper `get` invocation, each paying out 250,000 WBTC units to the helper contract.*

Across these transactions:

- The helper calls `withdrawWithoutHedge(2)` 100 times in `0x260d…` and 331 times in `0x4448…`.  
- Each call executes an ERC20 `transfer` of 250,000 WBTC units from HegicPUT to the helper and emits a `Withdrawn` event for tranche ID 2.  
- State diffs for HegicPUT (`hegicput_state_diff_prestate.json` for both txs) show `totalShare` and `totalBalance` decreasing across the sequence, consistent with repeated withdrawals from the same tranche.

### Amount Drained vs. Initial Deposit

The initial tranche is created in the first transaction `0x9c27…`:

```txt
Traces:
  0xF51E8886…::swap{value: 0.09 ETH}(HegicPUT: [0x7094…], WBTC: [0x2260…], 250000 [2.5e5])
    ├─ UniswapV2Router02::swapETHForExactTokens(250000 [2.5e5], [WETH, WBTC], …)
    ├─ WBTC::transfer(0xF51E8886…, 250000 [2.5e5])
    ├─ HegicPUT::provideFrom(0xF51E8886…, 250000 [2.5e5], true, 1)
    │   ├─ emit Transfer(... tokenId: 2)
    │   ├─ WBTC::transferFrom(0xF51E8886…, HegicPUT: [0x7094…], 250000 [2.5e5])
```

*Snippet origin: Seed transaction trace for tx `0x9c27…`, demonstrating that 0x4b53… swaps approximately 0.0898 ETH via Uniswap to acquire 250,000 raw WBTC units, which helper `0xF51E…` then deposits into HegicPUT, creating tranche ID 2 with 0.0025 WBTC of liquidity.*

From the withdrawal-loop traces and log-based balance diffs:

- Each call to `withdrawWithoutHedge(2)` transfers 250,000 WBTC units from HegicPUT to the helper.  
- The first loop (100 iterations) and second loop (331 iterations) together yield `100 + 331 = 431` transfers of 250,000 units:
  - `431 * 250,000 = 107,750,000` raw WBTC units = **1.0775 WBTC**.  
- This matches the narrative in the analysis that the helper receives 107,750,000 units from HegicPUT across the two transactions while only 250,000 units were initially deposited.

### Security Properties Violated

The combination of contract logic and trace evidence shows the following broken invariants:

- **Single-use withdrawal invariant for liquidity tranches**  
  - Intended behavior: each tranche can be withdrawn and closed once; subsequent calls should revert.  
  - Observed behavior: `_withdraw` happily processes multiple withdrawals for tranche ID 2 in the same transaction because the state guard is absent; `t.state` being `Closed` does not prevent further withdrawals.

- **Conservation of value for pool accounting**  
  - `totalShare` and `totalBalance` are updated per withdrawal but not in a way that prevents cumulative withdrawals for a single tranche from exceeding its fair share.  
  - The traces and diffs confirm that 1.0775 WBTC leaves the pool for an initial 0.0025 WBTC deposit.

- **Fail-safe access control on destructive operations**  
  - The guardrails for a destructive operation (liquidity withdrawal) fail open: if approvals and lockup checks pass, the contract does not check whether this tranche has already been closed.

Together, these issues constitute the root-cause logic bug that makes the exploit possible.

## Adversary Flow Analysis

### Adversary Accounts and Roles

The analysis identifies an adversary cluster and victim contracts:

- **EOA `0x4b53608fF0cE42cDF9Cf01D7d024C2c9ea1aA2e8`**  
  - Originates all four transactions (`0x9c27…`, `0x260d…`, `0x4448…`, `0x722f…`) based on seed metadata and transaction traces.  
  - Pays all gas costs.  
  - Receives 25,250,000 WBTC units from the helper in the final transaction.

- **Helper contract `0xF51E888616a123875EAf7AFd4417fbc4111750f7`**  
  - Called directly by the EOA in all four transactions.  
  - Executes the Uniswap swap and HegicPUT `provideFrom` call to create the initial tranche.  
  - Loops `withdrawWithoutHedge(2)` 100 times in `0x260d…` and 331 times in `0x4448…`.  
  - Acts as the intermediate holder of the drained WBTC before forwarding 25,250,000 units to the EOA.

- **Victim contracts**  
  - HegicPUT WBTC Put Pool `0x7094E706E75E13D1E0ea237f71A7C4511e9d270B` — loses 1.0775 WBTC of liquidity.  
  - WBTC token `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599` — underlying ERC20 used for pool accounting and transfers.

### Stage 1: Initial Capital Deployment and Tranche Creation (tx 0x9c27…)

- **Mechanism**: Swap-and-deposit via helper.  
- **Transaction**: `0x9c27d45c1daa943ce0b92a70ba5efa6ab34409b14b568146d2853c1ddaf14f82` (block 21691132).  

Flow:

1. EOA `0x4b53…` sends a type-2 transaction to helper `0xF51E…` with approximately 0.09 ETH.  
2. Helper invokes Uniswap’s WBTC/WETH pair to swap ~0.0898 ETH for 250,000 raw WBTC units (0.0025 WBTC).  
3. Helper then calls `HegicPUT::provideFrom` to deposit 250,000 WBTC units into the pool.  
4. HegicPUT mints a new tranche (ID 2) represented by an ERC721 token owned by the helper, backed by the 0.0025 WBTC deposit.

Evidence:

- The `cast run` trace shows the Uniswap `swapETHForExactTokens` call and a `WBTC::transfer` of 250,000 units to the helper, followed by `HegicPUT::provideFrom` and `WBTC::transferFrom` from the helper to HegicPUT.  
- Uniswap pair state diffs and WETH/WBTC Transfer logs (iter_3 and iter_4 artifacts) quantify the ETH spent and WBTC received.  
- HegicPUT state diffs for `0x9c27…` confirm updates to `totalShare`, `totalBalance`, and tranche tracking fields for tranche ID 2.

### Stage 2: Repeated Tranche Withdrawals via withdrawWithoutHedge (txs 0x260d…, 0x4448…)

- **Mechanism**: Pool-withdrawal loop.  
- **Transactions**:
  - `0x260d5eb9151c565efda80466de2e7eee9c6bd4973d54ff68c8e045a26f62ea73` (block 21794521) — 100 iterations.  
  - `0x444854ee7e7570f146b64aa8a557ede82f326232e793873f0bbd04275fa7e54c` (block 21794536) — 331 iterations.

Flow:

1. EOA `0x4b53…` sends a type-2 transaction to helper `0xF51E…` with zero ETH value, invoking a function that accepts the HegicPUT address, `trancheID = 2`, and a desired iteration count.  
2. Helper loops `HegicPUT::withdrawWithoutHedge(2)`:
   - 100 times in `0x260d…`.  
   - 331 times in `0x4448…`.
3. Each iteration:
   - Passes the approval and lockup checks (helper is the ERC721 owner).  
   - Executes `_withdraw`, which sets the tranche state to `Closed` but does not prevent subsequent calls.  
   - Computes a positive withdrawal amount based on current `totalBalance` and `totalShare`.  
   - Transfers 250,000 WBTC units from HegicPUT to the helper and emits a `Withdrawn` event for tranche ID 2.

Evidence:

- `cast run` traces for both transactions show repeated `HegicPUT::withdrawWithoutHedge(2)` calls nested under helper `get` calls, each paired with a `WBTC::transfer` from HegicPUT to the helper for 250,000 units and a `Withdrawn` event.  
- HegicPUT state diffs (`hegicput_state_diff_prestate.json` for both txs) show successive reductions of `totalShare` and `totalBalance` consistent with many withdrawals from a single tranche.  
- WBTC log-based diffs in iter_3 capture the aggregate WBTC outflow from HegicPUT to the helper, summing to 107,750,000 units (1.0775 WBTC).

Effect:

- The helper receives 1.0775 WBTC from HegicPUT across the two withdrawal-loop transactions while only 0.0025 WBTC was originally deposited in tranche ID 2.  
- The pool’s WBTC reserves are depleted by 1.0775 WBTC relative to the starting state before the exploit.

### Stage 3: Profit Realization to EOA (tx 0x722f…)

- **Mechanism**: Token transfer from helper to EOA.  
- **Transaction**: `0x722f67f6f9536fa6bbf4af447250e84b8b9270b66195059c9904a0e249543e80` (block 21794527).

Flow:

1. EOA `0x4b53…` sends a type-2 transaction to helper `0xF51E…`.  
2. Helper calls WBTC to transfer its remaining WBTC balance to the EOA:

```txt
Traces:
  0xF51E8886…::88a772f4(...)
    ├─ WBTC::balanceOf(0xF51E8886…) [staticcall]
    ├─ WBTC::transfer(0x4B53608f…, 25250000 [2.525e7])
    │   ├─ emit Transfer(from: 0xF51E8886…, to: 0x4B53608f…, value: 25250000 [2.525e7])
```

*Snippet origin: Seed transaction trace for tx `0x722f…`, demonstrating the helper reading its WBTC balance and transferring 25,250,000 raw units (0.2525 WBTC) to the EOA as profit realization.*

Evidence:

- WBTC Transfer-log–based balance diffs for `0x722f…` show:  
  - `0x4b53…` gains `25250000` raw units.  
  - `0xF51E…` loses `25250000` raw units.  
- Seed metadata and receipt confirm that no WBTC leaves `0x4b53…` in this transaction; it is a pure inflow from the helper.

Effect:

- The EOA realizes 0.2525 WBTC directly in its account, sourced from the helper’s drained balance.  
- The remaining WBTC drained by the helper may stay under helper control or be routed elsewhere in later transactions, but for this exploit cluster the net gain attributable to the four analyzed txs is captured in aggregate form in the profit calculation below.

## Impact & Losses

### Quantitative Impact

The analysis expresses the exploit impact in WBTC:

- **Reference asset**: WBTC.  
- **Adversary address**: `0x4b53608fF0cE42cDF9Cf01D7d024C2c9ea1aA2e8`.  
- **Total WBTC drained from HegicPUT to the helper**: `107,750,000` raw units = **1.0775 WBTC**.  
- **Initial WBTC deposit to create tranche ID 2**: `250,000` raw units = **0.0025 WBTC**.  
- **WBTC-equivalent gas and swap costs borne by the EOA**: approximately **0.0028669220 WBTC**, computed by:  
  - Summing ETH fees across the four transactions using seed `balance_diff.json` and gas cost summaries.  
  - Converting total ETH outflow to WBTC using Uniswap WBTC/WETH reserves and WETH Transfer logs for the initial swap transaction `0x9c27…`.

Resulting net profit:

- **Net WBTC profit to adversary cluster**:  
  - `1.0775 WBTC (drained) - 0.0028669220 WBTC (costs)`  
  - ≈ **1.07463308 WBTC**, strictly positive and derived entirely from on-chain traces, logs, and state diffs.

### Qualitative Impact

- HegicPUT’s WBTC pool at `0x7094…` loses 1.0775 WBTC of liquidity relative to the initial 0.0025 WBTC deposit used to create tranche ID 2.  
- The exploit does not rely on unusual market conditions or off-chain manipulation; it depends solely on the deterministic contract logic and publicly accessible on-chain state.  
- Liquidity providers in the HegicPUT WBTC pool are effectively diluted: a single small liquidity position is used to drain a much larger share of the pool’s WBTC reserves.

## References

- **[1] HegicPUT / HegicPool source code**  
  - Collected verified source for `0x7094E706E75E13D1E0ea237f71A7C4511e9d270B`, including `HegicPool.sol` with `withdrawWithoutHedge` and `_withdraw` implementations and commented-out tranche state guard.

- **[2] WBTC token source**  
  - Collected verified ERC20 source for `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599`, used to interpret Transfer logs and balance diffs.

- **[3] Key transaction metadata and traces**  
  - Seed `metadata.json` and `trace.cast.log` files for txs `0x9c27…`, `0x260d…`, `0x4448…`, and `0x722f…`, providing full call stacks, gas usage, and storage changes.

- **[4] State and balance diffs used for valuation**  
  - `debug_traceTransaction` prestateTracer state diffs for HegicPUT and the Uniswap WBTC/WETH pair.  
  - ERC20 Transfer-log–based WBTC and WETH balance diffs (`wbtc_balance_diff_from_logs.json` and `weth_balance_diff_from_logs.json`).  
  - Gas cost summaries linking ETH outflows from the adversary EOA to the four exploit transactions.

