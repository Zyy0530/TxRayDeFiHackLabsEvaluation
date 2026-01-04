## Overview & Context

This proof-of-concept (PoC) reproduces the Locker / TokenV2 exploit on Base (chainid 8453) in which an adversary abuses a reentrancy bug in the Locker contract to drain pooled TokenV2 collateral, swap it to WETH/ETH via Uniswap V3, and realize a net ETH profit.  
The design and success conditions are derived from the incident root cause analysis in `root_cause.json` and `root_cause_report.md`, and from the oracle specification in `artifacts/poc/oracle_generator/oracle_definition.json`.

**PoC command to run**

```bash
cd forge_poc
RPC_URL="<base_mainnet_quicknode_url>" forge test --via-ir -vvvvv
```

In the validator run, `RPC_URL` was constructed from the QuickNode Base endpoint and token in `.env` and mapped through `artifacts/poc/rpc/chainid_rpc_map.json` for chainid `8453`.

## PoC Architecture & Key Contracts

The PoC is implemented as a Foundry test (`test/Exploit.t.sol`) and a helper contract (`src/ExploitHelper.sol`) that collectively exercise the vulnerable on-chain contracts.

- `ExploitTest` (Foundry test)
  - Forks Base mainnet at block `24_282_176`, immediately before the first adversary-crafted transaction in the incident opportunity window.
  - Binds interfaces to real on-chain addresses:
    - `LOCKER_PROXY`: the Locker proxy contract.
    - `TOKEN_V2`: the pooled collateral token.
    - `TREASURY_SAFE`: the protocol treasury that receives lock fees.
    - `UNISWAP_POOL_TOKENV2_WETH9`: the TokenV2/WETH9 Uniswap V3 pool.
    - `WETH9`: canonical Base WETH.
    - `UNISWAP_V3_ROUTER`: Uniswap V3 router.
  - Creates a fresh attacker address via `makeAddr("attacker")` and labels all key actors using `vm.label` for trace readability.
  - Deploys `ExploitHelper` locally, passing in the protocol addresses and attacker address.

- `ExploitHelper`
  - Holds references to the live Locker, TokenV2, Uniswap V3 router, WETH9, and pool.
  - Implements two main methods:
    - `primeLock`: seeds TokenV2, calls `Locker.createLock` with an overpaid fee so `_feeHandler` executes, and records the attacker-controlled lock ID and unlock time.

      ```solidity
      function primeLock(
          uint256 amount,
          uint256 unlockTime
      ) external payable {
          require(msg.sender == attacker, "ExploitHelper: not attacker");
          // ...
          locker.createLock{value: msg.value}(address(tokenV2), 0, address(this), amount, unlockTime);
          attackerLockId = nextLockId;
      }
      ```

      _Snippet: Helper seeds an attacker-controlled TokenV2 lock in the real Locker contract._

    - `executeExploit`: overpays `Locker.splitLock` to trigger the vulnerable fee refund, reenters `withdrawLock` from the helper’s `receive()` function, then withdraws the split lock, swaps stolen TokenV2 to WETH via Uniswap V3, unwraps to ETH, and forwards profit to the attacker.

      ```solidity
      function executeExploit(
          uint256 splitAmount,
          uint256 minExpectedEthOut
      ) external payable {
          // ...
          inSplit = true;
          uint256 splitId = locker.splitLock{value: msg.value}(attackerLockId, splitAmount, attackerLockUnlockTime);
          inSplit = false;

          locker.withdrawLock(splitId);
          // swap stolen TokenV2 -> WETH -> ETH, then send ETH to attacker
      }
      ```

      _Snippet: Helper drives the splitLock + withdrawLock sequence that enables reentrancy and drains pooled TokenV2._

- Reentrancy hook (`receive()` in `ExploitHelper`)

```solidity
receive() external payable {
    // Reenter Locker during the ETH refund in _feeHandler
    if (inSplit && attackerLockId != 0) {
        locker.withdrawLock(attackerLockId);
    }
}
```

_Snippet: During the ETH refund in Locker’s `_feeHandler`, the helper reenters `withdrawLock` on the attacker lock, transferring its TokenV2 out before split accounting is updated._

## Adversary Execution Flow

The end-to-end adversary flow is encoded in `ExploitTest.reproducerAttack` and the main test `testExploit_ReproducesIncidentOracles`.

### 1. Funding and Environment Setup

- The test forks Base mainnet at `FORK_BLOCK = 24_282_176`, one block before the first adversary-crafted transaction in the incident sequence.
- A fresh attacker address is created and funded with 5 ETH via `vm.deal` to cover lock fees and gas.
- As an oracle pre_check, the test asserts that the Locker proxy holds a strictly positive TokenV2 balance before any exploit actions, ensuring that there is collateral to steal:

```solidity
uint256 lockerTokenBalanceBefore = tokenV2.balanceOf(LOCKER_PROXY);
assertGt(lockerTokenBalanceBefore, 0);
```

_Snippet: Oracle pre_check enforcing that Locker has a positive TokenV2 balance before the exploit._

### 2. Attacker Lock Creation (`primeLock`)

Inside `reproducerAttack`:

- The attacker starts a prank context (`vm.startPrank(attacker)`).
- The test credits the helper contract with `INITIAL_LOCK_AMOUNT` TokenV2, derived from the incident Locker snapshot for lock ID 11 (`locks_snapshots_0x1728465_0x1728466.json`).
- It computes the protocol-configured fee via `locker.fee(whitelist)` and overpays by 0.01 ETH when calling `helper.primeLock`, ensuring `_feeHandler` will refund excess ETH and match the incident’s fee pattern.

The helper then:
- Approves TokenV2 to the Locker.
- Calls `Locker.createLock` with the full amount, recording the lock ID and unlock time as `attackerLockId` and `attackerLockUnlockTime`.

### 3. Exploit Execution (`executeExploit`)

After advancing time so the attacker lock is fully unlocked, the attacker calls:

```solidity
uint256 valueForSplit = baseFee + 0.01 ether;
uint256 splitAmount = INITIAL_LOCK_AMOUNT / 2;
helper.executeExploit{value: valueForSplit}(splitAmount, minExpectedEthOut);
```

Execution sequence:

1. `executeExploit` recomputes the Locker fee and overpays `splitLock`, again ensuring `_feeHandler` executes and refunds excess ETH.
2. With `inSplit = true`, the helper calls `Locker.splitLock` on the attacker lock. Inside Locker:
   - `_feeHandler` charges the protocol fee and sends any excess ETH back to `msg.sender` (the helper).
   - The ETH refund triggers the helper’s `receive()` function.
3. Inside `receive`, the helper detects `inSplit == true` and reenters `Locker.withdrawLock(attackerLockId)`:
   - `withdrawLock` transfers the full `amount` of the original attacker lock to the helper without adjusting the amount field in the lock struct.
4. Control returns to `splitLock`, which then reduces the lock’s amount and creates a new split lock, but the TokenV2 backing the original lock has already been transferred out.
5. Back in `executeExploit`, the helper calls `locker.withdrawLock(splitId)` to drain additional pooled TokenV2 associated with the split lock, further breaking the collateralization invariant.

The accompanying Forge trace (`artifacts/poc/poc_validator/forge-test.log`) shows this nested call structure and the resulting TokenV2 transfers from the Locker to the helper.

### 4. Profit Realization and Cleanup

Once the helper holds the stolen TokenV2:

1. It approves the Uniswap V3 router to spend the stolen TokenV2.
2. It fetches the pool fee from the real TokenV2/WETH9 pool and executes `exactInputSingle`, swapping all stolen TokenV2 to WETH at mainnet prices.
3. It unwraps WETH to ETH via `WETH9.withdraw`.
4. It enforces a minimum ETH profit:

```solidity
uint256 ethBalance = address(this).balance;
require(ethBalance >= minExpectedEthOut, "ExploitHelper: insufficient ETH profit");
```

5. Finally, it forwards all ETH to the attacker address.

The test then checks that the attacker’s ETH balance increased and that the Locker’s TokenV2 balance decreased and is undercollateralized relative to outstanding TokenV2 locks.

## Oracle Definitions and Checks

The oracle definition JSON describes the variables, pre_check, and constraints that the PoC must satisfy.

### Variables

Key variables from `oracle_definition.json` include:

- `attacker`: the adversary EOA (modeled here as a fresh Foundry address).
- `locker_proxy`: the Locker proxy contract holding pooled TokenV2.
- `tokenV2`: the collateral token.
- `treasury_safe`: protocol treasury receiving lock fees.
- `uniswap_pool_tokenV2_WETH9`: the TokenV2/WETH9 pool used to swap TokenV2 into WETH.
- `weth9` and `eth`: the intermediary token and final profit asset.
- `helper_contract`: the incident helper contract (reimplemented locally as `ExploitHelper`).

### Pre-check

- **Pre-check**: Locker holds a strictly positive TokenV2 balance before the adversary sequence.
  - Implementation: `ExploitTest.setUp` calls `tokenV2.balanceOf(LOCKER_PROXY)` and asserts it is greater than zero before any attacker actions.

### Hard Constraints

1. **H1 – Attacker profits in native ETH**
   - Oracle requirement: attacker’s native ETH balance strictly increases over the exploit sequence.
   - Implementation:
     - The test records `attackerEthBefore = attacker.balance` and `attackerEthAfter` after calling `reproducerAttack`.
     - It asserts `assertGt(attackerEthAfter, attackerEthBefore)`.

2. **H2 – Locker TokenV2 balance decreases**
   - Oracle requirement: the pooled TokenV2 balance at the Locker proxy strictly decreases.
   - Implementation:
     - The test records `lockerTokenBalanceBefore` and `lockerTokenBalanceAfter = tokenV2.balanceOf(LOCKER_PROXY)` and asserts `assertLt(lockerTokenBalanceAfter, lockerTokenBalanceBefore)`.

3. **H3 – Undercollateralization after exploit**
   - Oracle requirement: after the exploit, the Locker’s TokenV2 balance is strictly less than the TokenV2 owed to outstanding locks.
   - Implementation:
     - The helper function `sumOutstandingTokenV2LocksAfter` iterates over all `locker.lockId()` entries, summing `l.amount` for non-withdrawn TokenV2 locks.
     - The test computes `totalOutstandingAfter` and asserts `assertLt(lockerTokenBalanceAfter, totalOutstandingAfter)`.

### Soft Constraint

1. **S1 – Attacker net ETH profit ≥ 0.01 ETH**
   - Oracle requirement: attacker ETH profit is at least 0.01 ETH, capturing a non-trivial economic gain while allowing flexibility relative to the exact incident profit.
   - Implementation:
     - The test passes `minExpectedEthOut = 0.01 ether` into `reproducerAttack`, which forwards it to `executeExploit`.
     - In `executeExploit`, the helper enforces `ethBalance >= minExpectedEthOut` before sending ETH to the attacker.
     - The test also computes `attackerEthDelta = attackerEthAfter - attackerEthBefore` and asserts `assertGe(attackerEthDelta, 0.01 ether)`.

Collectively, the test mirrors the oracle specification’s pre_check, hard constraints, and soft constraint in explicit Solidity assertions.

## Validation Result and Robustness

The validator ran the PoC using:

```bash
cd /home/wesley/TxRayExperiment/incident-202601031758/forge_poc
RPC_URL="<RPC_URL>" forge test --via-ir -vvvvv \
  > /home/wesley/TxRayExperiment/incident-202601031758/artifacts/poc/poc_validator/forge-test.log 2>&1
```

The Forge output reports:

- All test suites passed.
- `testExploit_ReproducesIncidentOracles` succeeded on the Base fork with the expected reentrancy and state transitions visible in the trace.

The validator wrote the structured result at:

- `artifacts/poc/poc_validator/poc_validated_result.json`

with:

- `overall_status = "Pass"`
- `poc_correctness_checks.passes_validation_oracles.passed = true`
- All quality checks marked as `passed = true`, including oracle alignment, human readability, no unjustified magic numbers, use of a mainnet fork without mocks, self-contained attacker modeling, end-to-end flow coverage, and alignment with the root cause.

In summary, the PoC:

- Passes all defined oracles.
- Demonstrates a realistic end-to-end exploit path on a Base mainnet fork.
- Is robust against minor parameter variations (e.g., forked state at the designated incident block and realistic Uniswap pool pricing).

## Linking PoC Behavior to Root Cause

The root cause analysis describes a reentrancy bug in Locker’s fee handling and lock accounting:

- `Locker.splitLock` calls `_feeHandler`, which sends ETH to the treasury and refunds excess ETH to `msg.sender` before adjusting the lock’s `amount` and creating the new split lock.
- The ETH refund enables reentrancy because it uses a low-level call with forwarded gas.
- `Locker.withdrawLock` transfers the full `amount` of the lock’s token to the beneficiary but does not reduce the `amount` field, and there is no invariant tying the Locker’s TokenV2 balance to the sum of outstanding lock amounts.

The PoC exercises this exact sequence:

- By overpaying both `createLock` and `splitLock`, it ensures `_feeHandler` is invoked with a refund to the helper.
- The helper’s `receive()` reenters `withdrawLock(attackerLockId)` during the refund in `splitLock`, draining TokenV2 associated with the original attacker lock before split accounting is applied.
- After returning from the reentrant call, `splitLock` continues, reducing the lock’s amount and setting up a new split lock that still records a positive TokenV2 amount.
- The helper then withdraws the split lock, stealing additional pooled TokenV2.

These steps match the ACT framing and the incident description:

- **Adversary-crafted actions (A)**: The attacker funds their helper, creates a large TokenV2 lock, and crafts an overpaid `splitLock` call that triggers reentrancy.
- **Contract (C)**: The Locker and Uniswap router/pool execute the vulnerable internal logic: fee refund with reentrancy, under-accounted TokenV2 withdrawals, and swap path TokenV2 → WETH → ETH.
- **Target (T)**: The Locker’s pooled TokenV2 collateral and the protocol’s economic invariants are violated, leaving the Locker undercollateralized while the attacker’s ETH balance increases.

The final assertions in `testExploit_ReproducesIncidentOracles`—Locker TokenV2 balance decrease, undercollateralization vs. outstanding locks, and attacker ETH profit exceeding 0.01 ETH—directly confirm the success predicate in the root cause analysis: a profitable reentrancy-driven drain of pooled TokenV2 converted into ETH on Base mainnet.

