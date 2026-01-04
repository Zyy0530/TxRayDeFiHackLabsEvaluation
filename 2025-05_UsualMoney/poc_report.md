## Overview & Context

This proof-of-concept (PoC) reproduces the Usual / Uniswap V3 Usd0–USDC cross-venue arbitrage that occurred on Ethereum mainnet at block 22,575,930. In the original incident, an unprivileged searcher executed a single contract-creation transaction that routed liquidity through:

- The Usd0/USDC Uniswap V3 pool (victim pool),
- The canonical USDC/WETH9 Uniswap V3 pool (hedging leg),
- Uniswap V3 `SwapRouter`,
- WETH9 to unwrap profit into native ETH.

Liquidity providers (LPs) in the Usd0/USDC pool lost a large amount of USDC, while the adversary realized substantial profit in native ETH. The PoC encodes this as an ACT-style opportunity where the success predicate is “attacker makes ETH profit while the Usd0/USDC pool loses USDC that flows into the USDC/WETH pool.”

To run the PoC on a forked Ethereum mainnet state:

```bash
cd forge_poc
RPC_URL="<your_mainnet_quicknode_url>" forge test --via-ir -vvvvv
```

In the validator environment, `RPC_URL` is derived from QuickNode configuration and the tests pass with detailed traces confirming the arbitrage path.

## PoC Architecture & Key Contracts

The core PoC logic lives in the Foundry test contract `ExploitTest` (under the project’s `test` directory). It uses Foundry’s standard test utilities and cheatcodes:

- `Test` and `StdCheats` from `forge-std`,
- `vm.createSelectFork` to create a mainnet fork at the incident block,
- `vm.deal` and `deal` to fund the attacker and mint Usd0.

### Roles and Addresses

Within `ExploitTest`, the following roles and contracts are configured:

- `attacker`: a fresh Foundry address created with `makeAddr("attacker")`, representing the MEV searcher.
- `usdcToken`: mainnet USDC token at `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`.
- `wethToken`: WETH9 at `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`.
- `usd0Token`: Usual’s Usd0 token at `0x73A15FeD60Bf67631dC6cd7Bc5B6e8da8190aCF5`.
- `usd0UsdcPool`: Usd0/USDC Uniswap V3 pool at `0x4e665157291DBcb25152ebB01061E4012F58aDd2` (victim pool).
- `usdcWethPool`: USDC/WETH9 Uniswap V3 pool at `0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640`.
- `swapRouter`: Uniswap V3 `SwapRouter` at `0xE592427A0AEce92De3Edee1F18E0157C05861564`.

The test labels these addresses for readability using `vm.label`, making the trace easy to interpret (e.g., “Usd0/USDC Pool”, “USDC/WETH Pool”, “UniswapV3 SwapRouter”).

### Main Adversary Logic

The core attack behavior is implemented in `reproducerAttack()`:

```solidity
function reproducerAttack() public {
    vm.startPrank(attacker);

    usd0Token.approve(address(swapRouter), type(uint256).max);
    usdcToken.approve(address(swapRouter), type(uint256).max);

    uint256 usd0Balance = usd0Token.balanceOf(attacker);
    require(usd0Balance > 0, "no Usd0 balance");

    ISwapRouter.ExactInputSingleParams memory usd0ToUsdcParams =
        ISwapRouter.ExactInputSingleParams({
            tokenIn: address(usd0Token),
            tokenOut: address(usdcToken),
            fee: usd0UsdcFee,
            recipient: attacker,
            deadline: block.timestamp + 1,
            amountIn: usd0Balance,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        });
    swapRouter.exactInputSingle(usd0ToUsdcParams);

    uint256 usdcBalance = usdcToken.balanceOf(attacker);
    require(usdcBalance > 0, "no USDC after Usd0 swap");

    ISwapRouter.ExactInputSingleParams memory usdcToWethParams =
        ISwapRouter.ExactInputSingleParams({
            tokenIn: address(usdcToken),
            tokenOut: address(wethToken),
            fee: usdcWethFee,
            recipient: attacker,
            deadline: block.timestamp + 2,
            amountIn: usdcBalance,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        });
    swapRouter.exactInputSingle(usdcToWethParams);

    uint256 wethBalance = wethToken.balanceOf(attacker);
    require(wethBalance > 0, "no WETH after USDC swap");

    wethToken.withdraw(wethBalance);

    vm.stopPrank();
}
```

*Snippet: Core adversary logic performing Usd0 → USDC → WETH → ETH swaps via the real Uniswap V3 pools and SwapRouter on a mainnet fork.*

## Adversary Execution Flow

### Environment Setup and Funding

In `setUp()`, the test creates a fork of Ethereum mainnet at the incident block and configures the environment:

- `vm.createSelectFork(rpcUrl, 22_575_930)` sets the chain state to the pre-incident block.
- A fresh `attacker` address is constructed and labeled.
- References to USDC, WETH9, Usd0, both Uniswap V3 pools, and `SwapRouter` are bound to their canonical mainnet addresses.
- The test queries each pool’s fee tier on-chain (`IUniswapV3Pool(pool).fee()`) instead of hard-coding fee numerics.

The attacker’s balances are prepared as follows:

- `vm.deal(attacker, 0.5 ether)` provides ETH for gas and baseline balance.
- `deal(address(usd0Token), attacker, initialUsd0)` mints a large Usd0 position, where:
  - `initialUsd0 = 60_000 * (10 ** usd0Decimals);`
  - This is documented in comments as a round-number approximation around the original incident’s ~42,877 USDC notional, scaled by Usd0 decimals.

This setup ensures the attack sequence is fully self-contained and reproducible within the test harness.

### Deployment and Configuration

No attacker-side contracts are deployed in the PoC; instead, the adversary uses SwapRouter directly. This is consistent with the root cause, where the helper contract primarily orchestrates routing through standard interfaces.

All critical components (tokens, pools, router) are mainnet contracts on the forked state:

- No local mocks are used to emulate tokens or pools.
- Fees and balances are read from on-chain state at block 22,575,930.

### Exploit Steps and Profit Realization

The test’s main exploit function `test_Exploit()` orchestrates the ACT sequence:

```solidity
function test_Exploit() public {
    uint256 usdcInUsd0UsdcPoolBefore = usdcToken.balanceOf(usd0UsdcPool);
    uint256 usdcInUsdcWethPoolBefore = usdcToken.balanceOf(usdcWethPool);
    uint256 attackerEthBefore = attacker.balance;

    assertGt(usdcInUsd0UsdcPoolBefore, 0);
    assertGt(usdcInUsdcWethPoolBefore, 0);
    assertGt(attackerEthBefore, 0);

    reproducerAttack();

    uint256 usdcInUsd0UsdcPoolAfter = usdcToken.balanceOf(usd0UsdcPool);
    uint256 usdcInUsdcWethPoolAfter = usdcToken.balanceOf(usdcWethPool);
    uint256 attackerEthAfter = attacker.balance;

    assertGt(attackerEthAfter, attackerEthBefore);
    assertLt(usdcInUsd0UsdcPoolAfter, usdcInUsd0UsdcPoolBefore);

    uint256 ethDelta = attackerEthAfter - attackerEthBefore;
    assertGe(ethDelta, 1 ether);

    uint256 usdcLoss = usdcInUsd0UsdcPoolBefore - usdcInUsd0UsdcPoolAfter;
    assertLt(usdcInUsd0UsdcPoolAfter, usdcInUsd0UsdcPoolBefore);
    assertGe(usdcLoss, 10_000_000_000);

    assertGt(usdcInUsdcWethPoolAfter, usdcInUsdcWethPoolBefore);
}
```

*Snippet: End-to-end exploit test capturing pool balances and attacker ETH before and after the Usd0 → USDC → WETH → ETH arbitrage.*

The sequence is:

1. **Pre-checks**: Ensure both pools have non-zero USDC liquidity and the attacker has positive ETH.
2. **Execution**: Call `reproducerAttack()` to:
   - Swap Usd0 → USDC via the Usd0/USDC pool.
   - Swap USDC → WETH via the USDC/WETH pool.
   - Withdraw WETH to ETH, crediting the attacker.
3. **Post-checks**:
   - The attacker’s ETH balance increases by a significant margin.
   - The Usd0/USDC pool loses USDC.
   - The USDC/WETH pool gains USDC.

The Forge run trace (captured in the validator log) confirms these balance changes and emits Uniswap `Swap` and WETH `Withdrawal` events consistent with the incident.

## Oracle Definitions and Checks

The PoC is driven by the oracle specification in `oracle_definition.json`, which defines:

- **Variables**: attacker, profit reference asset (ETH), USDC token, WETH token, Usd0 token, Usd0/USDC pool, USDC/WETH pool, SwapRouter.
- **Pre-checks**:
  1. Usd0/USDC pool must have non-zero USDC.
  2. USDC/WETH pool must have non-zero USDC.
  3. Attacker must have positive native ETH.
- **Hard constraints**:
  - `hard_asset_type_profit_eth`: attacker’s ETH balance after the exploit is strictly greater than before.
  - `hard_asset_type_victim_usdc`: Usd0/USDC pool’s USDC balance strictly decreases.
- **Soft constraints**:
  - `soft_attacker_profit_eth_threshold`: attacker ETH profit ≥ 1 ETH.
  - `soft_victim_usdc_depletion_threshold`: Usd0/USDC pool loses ≥ 10,000 USDC.
  - `soft_usdc_flow_to_usdc_weth_pool`: USDC/WETH pool’s USDC balance increases.

The `test_Exploit()` function implements these oracles one-to-one:

- Pre-check assertions (`assertGt` on both pool USDC balances and attacker ETH) correspond directly to the three `pre_check` entries.
- The hard constraints are enforced by:
  - `assertGt(attackerEthAfter, attackerEthBefore);`
  - `assertLt(usdcInUsd0UsdcPoolAfter, usdcInUsd0UsdcPoolBefore);`
- Soft constraints are enforced by:
  - `assertGe(ethDelta, 1 ether);`
  - `assertGe(usdcLoss, 10_000_000_000);` (10,000 USDC with 6 decimals).
  - `assertGt(usdcInUsdcWethPoolAfter, usdcInUsdcWethPoolBefore);`

This alignment means the PoC treats the oracle definition as the specification of success and checks all its critical components explicitly.

## Validation Result and Robustness

The validator executed the PoC with:

```bash
cd /home/wesley/TxRayExperiment/incident-202601040833/forge_poc
RPC_URL="<derived_mainnet_quicknode_url>" forge test --via-ir -vvvvv \
  > /home/wesley/TxRayExperiment/incident-202601040833/artifacts/poc/poc_validator/forge-test.log 2>&1
```

Results:

- All tests, including `ExploitTest::test_Exploit`, passed successfully on a forked Ethereum mainnet state at block 22,575,930.
- The detailed call trace shows SwapRouter calling the Usd0/USDC pool, then routing USDC into the USDC/WETH pool, and WETH unwrapping back to ETH for the attacker.
- The USDC balances of the pools and the attacker’s ETH balance change in the expected directions and with large magnitudes consistent with an economically meaningful arbitrage.

The validator’s structured result is stored at:

- `artifacts/poc/poc_validator/poc_validated_result.json`

Key conclusions from validation:

- `overall_status = "Pass"`: the PoC both executes correctly and meets all quality requirements.
- All validation oracles from `oracle_definition.json` are implemented and satisfied.
- Quality checks (oracle alignment, human readability and labels, lack of unjustified magic numbers, self-contained attacker, end-to-end ACT sequence, mainnet-fork realism, and alignment with the root cause) all pass.

## Linking PoC Behavior to Root Cause

The root cause report describes a MEV opportunity where:

- The Usd0/USDC Uniswap V3 pool sells USDC too cheaply relative to the USDC/WETH pool.
- A searcher routes Usd0 → USDC in the Usd0/USDC pool, then USDC → WETH in the USDC/WETH pool, then unwraps to ETH.
- LPs in the Usd0/USDC pool lose USDC, the USDC/WETH pool gains USDC, and the attacker realizes net ETH profit after gas.

The PoC’s behavior matches this narrative:

- It operates on the same mainnet contracts and at the same block height as in the root cause analysis.
- It uses the same routing path (Usd0 → USDC → WETH → ETH) via the real Uniswap V3 pools and SwapRouter.
- Assertions check:
  - **Attacker profit in ETH**: the ETH balance delta is strictly positive and exceeds 1 ETH.
  - **Victim loss in USDC**: the Usd0/USDC pool’s USDC balance decreases by at least 10,000 USDC.
  - **Cross-venue USDC flow**: the USDC/WETH pool’s USDC balance increases, showing USDC moving from the mispriced pool into the hedging pool.

In ACT terms:

- **A (Adversary-crafted transaction)**: `reproducerAttack()` encodes the searcher’s trade path without reusing the historical attacker identities.
- **C (Chain state)**: the mainnet fork at block 22,575,930 matches the pre-state used in the root cause artifacts.
- **T (Target predicate)**: the oracles ensure the attacker’s ETH profit and LP USDC loss are realized in the same structural pattern as the incident.

Overall, the PoC is a faithful, self-contained reproduction of the original MEV arbitrage opportunity, aligned with both the oracle specification and the independent root cause analysis.

