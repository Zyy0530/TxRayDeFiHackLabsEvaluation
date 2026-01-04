## Incident Overview TL;DR

On BSC (chainid 56), an attacker-controlled orchestrator contract `0x631adFF068D484Ce531Fb519Cda4042805521641` used a single adversary-crafted transaction `0x2a65254b41b42f39331a0bcc9f893518d6b106e80d9a476b8ca3816325f4a150` in block `49470430` to drain `2157126179348943736411799` BEP20USDT units from PancakePair `0xB5252FCef718F8629F81f1DFCfF869594AD478c6` to attacker EOA `0xb32a53Af96F7735D47F4b76C525BD5Eb02B42600`. Only `0.001` BNB is effectively wrapped into WBNB as swap input; the orchestrator routes calls through helper contracts and the Pancake router, then forwards `0.999` BNB of the original `1` BNB transaction value to `0x1266c6be60392a8ff346e8d5eccd3e69dd9c5f20`. Storage snapshots confirm that the pair’s recorded reserves do not change across the transaction even though its BEP20USDT balance drops, leaving the pool in a mis-accounted state.

The root cause is a protocol-level bug in the PancakePair–BEP20USDT integration: BEP20USDT can be pulled out of the pair through orchestrated token transfers and helper contracts without invoking the pair’s reserve-updating logic, so the pair’s reserve variables do not track its actual BEP20USDT balance. This broken reserve/balance invariant creates an ACT opportunity where an unprivileged adversary can extract BEP20USDT from the pool while the pair’s accounting state continues to advertise the pre-exploit reserves.

## Key Background

- `PancakePair`-style AMMs store `reserve0` and `reserve1` in contract storage and rely on an internal `_update` function, called from `mint`, `burn`, `swap`, `skim`, and `sync`, to keep those reserves aligned with the current token balances at the pair address.
- BEP20USDT `0x55d398326f99059ff775485246999027b3197955` on BSC is an 18‑decimal BEP20 token implementing standard `transfer`, `transferFrom`, `approve`, and mint logic with no restrictions on where tokens can be held.
- The orchestrator contract `0x631adFF068D484Ce531Fb519Cda4042805521641` exposes two public entrypoints; opcode disassembly shows that both enforce an owner check against the address stored in storage slot `0`, and the exploit entrypoint `0xcd60b03d` additionally requires non‑zero `msg.value` and forwards its remaining BNB balance to a hardcoded external address.
- Helper contracts `0xB1C4605f08D90a2Af06a0f85348d50b499629Aa8`, `0xb9d3Bb65aaCd77BA6033f92cEf043b979d9c10D4`, `0x637D8Ce897bb653cb83bA436CDf76bBe158f05B1`, and `0xF703Cb8cCC1c64679F08CFb2DF49eec36f25d93C` are invoked via `delegatecall` from the orchestrator and implement the low‑level logic for querying reserves and decimals, performing token transfers, and wiring calls to the Pancake router `0x10ed43c718714eb63d5aa57b78b54704e256024e`.
- The attacker EOA `0xb32a53Af96F7735D47F4b76C525BD5Eb02B42600` deploys the orchestrator and uses it as a dedicated controller for the exploit path.

## Vulnerability Analysis

PancakePair `0xB5252FCef718F8629F81f1DFCfF869594AD478c6` is implemented as a standard PancakePair/Uniswap V2–style AMM. Verified source under `artifacts/root_cause/data_collector/iter_1/contract/56/0xB5252F.../source` shows that:

- `reserve0` and `reserve1` are stored in contract storage and updated only inside `_update`.
- `_update` is invoked from `mint`, `burn`, `swap`, `skim`, and `sync`.
- The design assumes that, after each such operation, the stored reserves match the actual token balances at the pair address.

BEP20USDT `0x55d398326f99059ff775485246999027b3197955` behaves as a standard BEP20 token with 18 decimals. It allows unrestricted transfers between arbitrary addresses, including AMM pair contracts.

In the adversary-crafted transaction, the attacker uses its owner-gated orchestrator to:

- Wrap a small portion of the supplied BNB (`0.001` BNB) into WBNB `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`.
- Approve helper contracts and the router to move WBNB.
- Use helper contracts to query PancakePair’s `token0`, `token1`, `getReserves`, and token `decimals`, and to route token transfers and swaps through the Pancake router and the pair.

The critical behavior is that the orchestrator and helpers cause BEP20USDT to be transferred out of the pair without invoking any function that calls `_update`, so the pair’s stored reserves remain unchanged even though its BEP20USDT balance decreases sharply.

This broken reserve/balance invariant is directly visible in the on-chain artifacts.

**BEP20USDT state diff for the seed transaction (pair and attacker balances):**

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xb5252fcef718f8629f81f1dfcff869594ad478c6",
      "before": "2159553516647587844183110",
      "after": "2427337298644107771311",
      "delta": "-2157126179348943736411799"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xb32a53af96f7735d47f4b76c525bd5eb02b42600",
      "before": "0",
      "after": "2157126179348943736411799",
      "delta": "2157126179348943736411799"
    }
  ]
}
```

*Caption: BEP20USDT state diff for transaction `0x2a6525...` showing `2157126179348943736411799` BEP20USDT units moving from PancakePair `0xB5252F...` to attacker EOA `0xb32a53...`.*

**PancakePair reserve snapshot pre/post exploit block:**

```json
{
  "blocks": {
    "pre": {
      "block_number": 49470429,
      "decoded": {
        "reserve0": "2541994247176251230766304024102157",
        "reserve1": "3131416588669279253299097692271094",
        "blockTimestampLast": 4000715161
      }
    },
    "post": {
      "block_number": 49470430,
      "decoded": {
        "reserve0": "2541994247176251230766304024102157",
        "reserve1": "3131416588669279253299097692271094",
        "blockTimestampLast": 4000715161
      }
    }
  }
}
```

*Caption: Storage-level reserves for PancakePair `0xB5252F...` immediately before and after block `49470430`, showing that `reserve0`, `reserve1`, `blockTimestampLast`, and `kLast` remain constant across the exploit transaction even though the BEP20USDT balance has decreased.*

Together, these snippets demonstrate that the protocol’s intended invariant “stored reserves reflect actual token balances” is violated: BEP20USDT leaves the pair, but the reserves remain at their pre-exploit values. This invariant break is the protocol bug the adversary exploits.

## Detailed Root Cause Analysis

The ACT opportunity is defined over a concrete pre-state σ_B and a single adversary-crafted transaction sequence `b`:

- **Chain and block:** BSC (chainid 56), block `49470430`.
- **Pre-state σ_B:** Chain state immediately before including transaction `0x2a6525...`, reconstructed from seed metadata, BEP20USDT balance changes, and PancakePair reserve storage snapshots around blocks `49470429–49470430`.
- **Transaction sequence `b`:** a single transaction, `0x2a6525...`, from attacker EOA `0xb32a53Af96F7735D47F4b76C525BD5Eb02B42600` to orchestrator `0x631adFF068D484Ce531Fb519Cda4042805521641` with `1` BNB value and standard 1 gwei gas price.

The success predicate is non-monetary and focuses on the PancakePair reserve/balance invariant:

- Let `O(σ_B, σ') = 1` when, after executing transaction sequence `b` from σ_B on BSC, the BEP20USDT token balance of PancakePair `0xB5252F...` (as returned by `BEP20USDT.balanceOf(pair)`) is strictly lower than in σ_B, while the pair’s stored BEP20USDT reserve variable and other reserve fields in its storage remain equal to their pre-state values.
- When `O(σ_B, σ') = 1`, the pair’s accounting invariant that reserves reflect balances is violated, and its published reserves no longer represent the assets actually held by the pool.

On-chain evidence shows that this predicate is satisfied:

- The BEP20USDT state diff for `0x2a6525...` shows the pair’s BEP20USDT balance decreasing by `2157126179348943736411799` units and the attacker EOA’s BEP20USDT balance increasing by the same amount.
- The PancakePair reserve snapshot confirms that `reserve0`, `reserve1`, and `kLast` are identical at blocks `49470429` and `49470430`.

The orchestrator’s owner-gated entrypoint, combined with helper contracts, constructs a path where:

- `0.001` BNB is wrapped into WBNB, approved to helper logic, and used as nominal swap input.
- Helper contracts query reserves and decimals to compute amounts, then route token transfers and the final `swap` on PancakePair.
- The pair executes `swap(0, 2157126179348943736411799, attacker, data)` sending BEP20USDT to the attacker, but the overall execution does not trigger a state change that updates the stored reserves, leaving the accounting state stale.

The profit-related fields in the analysis explicitly mark reference-asset valuation as out of scope (`reference_asset: "not evaluated"`, `fees/value_before/value_after/value_delta: "not computed"`). The ACT opportunity is framed purely in terms of the invariant break and the ability to drain BEP20USDT while leaving reserves unchanged, which is fully supported by the on-chain evidence.

## Adversary Flow Analysis

The adversary flow consists of three main stages: orchestrator deployment, exploit execution, and post-exploit BEP20USDT redistribution.

1. **Orchestrator deployment**

   - Attacker EOA `0xb32a53Af96F7735D47F4b76C525BD5Eb02B42600` deploys orchestrator contract `0x631adFF068D484Ce531Fb519Cda4042805521641` in prior blocks (e.g., around block `49470339` per address `txlist.json`).
   - Disassembly of `0x631adFF...` shows storage slot `0` holding the owner address and both public entrypoints enforcing `CALLER == owner`:

   ```text
   0000006e: JUMPDEST
   0000006f: PUSH1 0x00
   00000071: SLOAD
   00000072: PUSH1 0x01
   00000074: PUSH1 0x01
   00000076: PUSH1 0xa0
   00000078: SHL
   00000079: SUB
   0000007a: AND
   0000007b: CALLER
   0000007c: EQ
   0000007d: PUSH2 0x0085
   00000080: JUMPI
   ```

   *Caption: Orchestrator `0x631adFF...` opcode fragment showing the owner check (`CALLER` compared against address stored in slot 0) gating the exploit entrypoint.*

   - The same disassembly shows additional logic for WBNB deposits, approvals, and a final native transfer to `0x1266c6be60392a8ff346e8d5eccd3e69dd9c5f20`, consistent with the exploit transaction behavior.

2. **Adversary-crafted exploit execution (seed transaction `0x2a6525...`)**

   - **Transaction:** On BSC chainid 56, block `49470430`, attacker EOA `0xb32a53...` calls `0x631adFF...::cd60b03d` with `1` BNB value and gas settings as recorded in the seed metadata.
   - **Trace behavior:** The Foundry `trace.cast` log for this transaction shows:
     - A `WBNB::deposit{value: 1000000000000000}` call wrapping `0.001` BNB into WBNB.
     - `WBNB::approve` and `transferFrom` operations enabling helper contracts to use WBNB.
     - Delegatecalls into helper contracts that:
       - Query PancakePair `0xB5252F...` `token0`, `token1`, and `getReserves`.
       - Query BEP20USDT and WBNB `decimals`.
       - Route WBNB and BEP20USDT transfers, including a large WBNB transfer to the pair and a subsequent `swap` call.
     - A `PancakePair::swap(0, 2157126179348943736411799, attacker, data)` call which:
       - Emits a BEP20USDT `Transfer` from the pair to `0xb32a53...` for `2157126179348943736411799` units.
       - Leaves the pair’s stored reserves unchanged at the storage level across blocks `49470429–49470430`, as confirmed by the reserves snapshot.
     - A final transfer of `0.999` BNB from the orchestrator to `0x1266c6be60392a8ff346e8d5eccd3e69dd9c5f20`.

   The combination of trace, state diff, and storage snapshots shows that this single transaction is sufficient to realize the invariant break and move the entire BEP20USDT amount from the pool to the attacker.

3. **Post-exploit BEP20USDT redistribution**

   - BEP20USDT transfer logs for holder `0xb32a53...` in the window `49470430–49490430` show multiple transfers from the attacker to downstream addresses, including `0x0f4a1d7fdf4890be35e71f3e0bbc4a0ec377eca3` and others.
   - For example, the first observed disposal transaction `0x51bc7c2350d66812ee72fd843b44fc1de484af0b31b9a193c0dc1322dbac1935` includes a BEP20USDT `Transfer` from `0xb32a53...` to `0x0f4a1d7fdf4890be35e71f3e0bbc4a0ec377eca3`, as recorded in `bep20usdt_transfers_all_49470430_49490430.json`.
   - Additional transfers distribute the BEP20USDT position across multiple addresses, but these do not affect the identified root cause, which is fully realized in the seed transaction.

Throughout this flow, all adversary-related accounts—attacker EOA, orchestrator, helper contracts, PancakePair, BEP20USDT, WBNB, router, recipient `0x1266c6...`, and downstream BEP20USDT recipients—are identified explicitly from on-chain traces, state diffs, and logs.

## Impact & Losses

- **Token:** BEP20USDT (symbol `USDT`) `0x55d398326f99059ff775485246999027b3197955`.
- **Amount drained from PancakePair:** `2157126179348943736411799` BEP20USDT units.
- **Direct recipient:** EOA `0xb32a53Af96F7735D47F4b76C525BD5Eb02B42600`.

The adversary-crafted transaction transfers the full `2157126179348943736411799` BEP20USDT units from PancakePair `0xB5252F...` to the attacker while the pair’s stored reserves remain at their pre-exploit values. This leaves the pool in a state where:

- LP tokens and any integration relying on the pair’s reserve variables are backed by fewer BEP20USDT units than the contract reports.
- Subsequent swaps or withdrawals executed before a manual resync operate on misreported reserve data and may result in further unbalanced outcomes for honest users.

Profit in a single reference asset (e.g., BNB or USD) is not computed in this analysis; the focus is on the invariant violation and the concrete BEP20USDT outflow from the pool to the adversary.

## References

- [1] Seed transaction `0x2a6525...` metadata: `artifacts/root_cause/seed/56/0x2a65254b41b42f39331a0bcc9f893518d6b106e80d9a476b8ca3816325f4a150/metadata.json`
- [2] Seed transaction `0x2a6525...` state diff (including BEP20USDT balance deltas): `artifacts/root_cause/data_collector/iter_1/tx/56/0x2a65254b41b42f39331a0bcc9f893518d6b106e80d9a476b8ca3816325f4a150/state_diff.json`
- [3] PancakePair `0xB5252F...` reserves pre/post block `49470430`: `artifacts/root_cause/data_collector/iter_3/storage_slot/56/0xB5252FCef718F8629F81f1DFCfF869594AD478c6/pancake_pair_reserves_pre_post_49470430.json`
- [4] BEP20USDT transfer logs around the incident window, including attacker disposal flows: `artifacts/root_cause/data_collector/iter_3/token/56/0x55d398326f99059ff775485246999027b3197955/bep20usdt_transfers_all_49470430_49490430.json`
- [5] Orchestrator `0x631adFF...` runtime bytecode and opcode disassembly: `artifacts/root_cause/data_collector/iter_3/contract/56/0x631adFF068D484Ce531Fb519Cda4042805521641`

