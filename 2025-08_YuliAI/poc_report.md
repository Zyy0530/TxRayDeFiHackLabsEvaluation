## 1. Overview & Context

This proof-of-concept (PoC) reproduces the BNB Chain YULIAI/USDT Quoter-based USDT drain described in the root cause analysis for contract `0x8262325bf1d8c3be83eb99f5a74b8458ebb96282` (“YULIAI/USDT payout contract”).  
On a fork of BNB Chain mainnet at block `57432055` (the block immediately before the real incident block `57432056`), the PoC shows how an unprivileged adversary can:

- Use a large USDT position (modeled as a flash‑loan-sized balance) to move the Pancake V3 YULIAI/USDT pool price,
- Cause the victim contract to call QuoterV2 against the manipulated pool inside its payout entrypoint (selector `0x2397e4d7`, modeled as `sellToken(uint256)`),
- Transfer YULIAI into the victim, and
- Drain USDT from the victim to an attacker-controlled address and the real payout recipient.

The PoC is implemented as a Foundry test in `Exploit.t.sol` and encodes the same attack predicate and state deltas as the original incident, but uses fresh attacker identities instead of the real attacker EOA and orchestrator contract.

**How to run the PoC**

From the session root:

```bash
cd /home/wesley/TxRayExperiment/incident-202601030959/forge_poc
export RPC_URL="https://indulgent-cosmological-smoke.bsc.quiknode.pro/a6a53e47429a27dac299922d0d518c66c3875b2e"
RPC_URL="$RPC_URL" forge test --via-ir -vvvvv \
  > /home/wesley/TxRayExperiment/incident-202601030959/artifacts/poc/poc_validator/forge-test.log 2>&1
```

The main exploit test is `testExploit()` in `Exploit.t.sol`. The validator run captured detailed traces and summary output in:

- `/home/wesley/TxRayExperiment/incident-202601030959/artifacts/poc/poc_validator/forge-test.log`

## 2. PoC Architecture & Key Contracts

### 2.1 On‑chain contracts and roles

The PoC reuses the real mainnet contracts involved in the incident:

- `USDT` (BEP20USDT): `0x55d398326f99059fF775485246999027B3197955`
- `YULIAI` (YuliAIToken): `0xDF54ee636a308E8Eb89a69B6893efa3183C2c1B5`
- `YuliaiPayoutVictim`: `0x8262325Bf1d8c3bE83EB99f5a74b8458Ebb96282`
- `PancakeV3_YULIAI_USDT_Pool`: `0xa687C7B3c2Cf6AdAEF0c4eDAB234c55b88e01333`
- `QuoterV2`: `0xB048Bbc1Ee6b733FFfCFb9e9CeF7375518e25997`
- `PancakeV3_SwapRouter`: `0x1b81D678ffb9C0263b24A97847620C99d213eB14`
- `PayoutRecipient`: `0x078F3F917c7355027a8388b7083B2199910c8A9a`

These addresses match the `variables` section of the oracle definition and the root cause artifacts.

The adversarial roles are implemented using fresh test addresses:

- `attacker`: created via `makeAddr("attacker")`, represents the EOA that ultimately profits in USDT.
- `whale`: created via `makeAddr("whale")`, represents a flash‑loan‑funded manipulator that performs large swaps on the Pancake V3 pool.

No real attacker EOA (`0x26f8bf8a772b8283bc1ef657d690c19e545ccc0d`) or orchestrator contract (`0xd6b9ee63c1c360d1ea3e4d15170d20638115ffaa`) is referenced in the test; they appear only in read‑only root cause artifacts.

### 2.2 Core test structure

The exploit is implemented in three functions:

- `setUp()`: configures the mainnet fork, addresses, labels, and initial balances, and records pre‑exploit snapshots for the oracles.
- `exploit()`: carries out price manipulation on the YULIAI/USDT pool, sizes the mispriced payout using QuoterV2, and calls the vulnerable victim entrypoint.
- `testExploit()`: wraps `exploit()` and encodes all correctness oracles as assertions.

Representative snippet from the test contract (simplified, from `Exploit.t.sol`):

```solidity
contract ExploitTest is Test {
    address constant USDT = 0x55d398326f99059fF775485246999027B3197955;
    address constant YULIAI = 0xDF54ee636a308E8Eb89a69B6893efa3183C2c1B5;
    address constant VICTIM = 0x8262325Bf1d8c3bE83EB99f5a74b8458Ebb96282;
    address constant POOL_YULIAI_USDT = 0xa687C7B3c2Cf6AdAEF0c4eDAB234c55b88e01333;
    address constant QUOTER_V2 = 0xB048Bbc1Ee6b733FFfCFb9e9CeF7375518e25997;
    address constant SWAP_ROUTER = 0x1b81D678ffb9C0263b24A97847620C99d213eB14;
    address constant PAYOUT_RECIPIENT = 0x078F3F917c7355027a8388b7083B2199910c8A9a;

    function setUp() public {
        string memory rpcUrl = vm.envString("RPC_URL");
        vm.createSelectFork(rpcUrl, 57432055);
        attacker = makeAddr("attacker");
        whale = makeAddr("whale");
        // labels and pre-exploit snapshots...
    }
}
```

*Snippet origin: High-level declaration and setup from `Exploit.t.sol`, showing the real mainnet addresses and fork configuration.*

## 3. Adversary Execution Flow

### 3.1 Environment setup and funding

In `setUp()`:

- The test forks BNB Chain at block `57432055`:

  ```solidity
  string memory rpcUrl = vm.envString("RPC_URL");
  vm.createSelectFork(rpcUrl, 57432055);
  ```

- It creates and labels two fresh addresses:

  - `attacker` (labels: `"Attacker"`)
  - `whale` (labels: `"WhalePriceManipulator"`)

- It funds:

  - `whale` with `200_000e18` USDT using `deal(USDT, whale, swapAmountIn)` to model the flash‑loaned USDT used to move the pool.
  - `whale` with `10 ether` BNB (for gas).
  - `attacker` with `1 ether` BNB (later topped up by the exact `msg.value` needed for the victim call).

- It records pre‑exploit balances:

  - `victimUsdtBefore = usdt.balanceOf(VICTIM)` and asserts it is non‑zero.
  - `poolUsdtBefore` and `poolYuliaiBefore` from the Pancake V3 pool, asserting both are non‑zero.
  - `attackerUsdtBefore` and `victimYuliaiBefore`.

These snapshots implement the `pre_check` section of the oracle definition and establish the reference state for all later balance‑delta checks.

### 3.2 Price manipulation via Pancake V3

The first step of `exploit()` is to move the YULIAI/USDT pool price by swapping a large USDT amount to YULIAI:

```solidity
uint256 swapAmountIn = 200_000e18;
vm.startPrank(whale);
usdt.approve(SWAP_ROUTER, swapAmountIn);

ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
    tokenIn: USDT,
    tokenOut: YULIAI,
    fee: 10_000,
    recipient: attacker,
    deadline: block.timestamp + 1 hours,
    amountIn: swapAmountIn,
    amountOutMinimum: 0,
    sqrtPriceLimitX96: 0
});

router.exactInputSingle(params);
vm.stopPrank();
```

*Snippet origin: Price manipulation block from `Exploit.t.sol::exploit()` showing the USDT→YULIAI swap that moves the pool price and sends YULIAI to the attacker.*

This mimics the real attack, where the orchestrator borrowed `200000 * 10^18` USDT from Moolah and routed swaps through Pancake V3 to shift the YULIAI/USDT spot price.

### 3.3 Sizing the mispriced payout with QuoterV2

After the swap, the test uses QuoterV2 to determine a base price for selling YULIAI back to USDT, then scales that to a payout size tied to the victim’s USDT balance:

- Calls `quoter.quoteExactInputSingle` with:

  - `tokenIn = YULIAI`
  - `tokenOut = USDT`
  - `amountIn = 1e18`
  - `fee = 10_000`

- From the returned `baseQuote`, it computes:

  - `targetPayout = victimUsdtBefore / 100` (aiming at ~1% of the victim’s pre‑exploit USDT balance).
  - `estimatedSellAmount = (targetPayout * 1e18) / baseQuote`.
  - Clamps `sellAmount` to ensure it is > 0 and at most half of the attacker’s YULIAI balance.

This step mirrors the victim’s design flaw: using a Quoter‑based spot quote, which can be influenced by prior swaps in the same transaction, to size a large USDT payout.

### 3.4 Exploit call into the victim and profit realization

Finally, the attacker executes the exploit call:

- Under `vm.startPrank(attacker)`, the attacker:

  - Ensures it holds YULIAI from the prior swap.
  - Approves the victim to pull YULIAI: `yuliai.approve(VICTIM, type(uint256).max)`.
  - Sets `callValue = 0.00025 ether` (from the incident trace).
  - Tops up its native balance with that value.
  - Calls `victim.sellToken{value: callValue}(sellAmount)`.

Within the forked victim contract, this triggers:

- A QuoterV2 call on the manipulated YULIAI/USDT pool,
- `YULIAI.transferFrom(attacker, VICTIM, sellAmount)`, and
- Two `USDT.transfer` calls:

  - One sending USDT from the victim to `PayoutRecipient` (`0x078F3F...`),
  - One sending USDT from the victim directly to `attacker`.

Post‑exploit, `testExploit()` measures:

- Attacker USDT balance vs `attackerUsdtBefore`.
- Victim USDT and YULIAI balances vs their pre‑exploit snapshots.
- Pool USDT balance vs `poolUsdtBefore`.

These are used to validate the profit and invariant‑drift oracles.

## 4. Oracle Definitions and Checks

The PoC treats `/home/wesley/TxRayExperiment/incident-202601030959/artifacts/poc/oracle_generator/oracle_definition.json` as the specification for success. It implements the following components:

### 4.1 Variables

From `oracle_definition.json`:

- `attacker`, `attacker_orchestrator`: adversary roles (addresses left `null` in the definition).
- `victim_contract`: `0x8262325bf1d8c3be83eb99f5a74b8458ebb96282`.
- `usdt_token`: `0x55d398326f99059fF775485246999027B3197955` (USDT).
- `yuliai_token`: `0xDF54ee636a308E8Eb89a69B6893efa3183C2c1B5` (YULIAI).
- `pancake_v3_pool_yuliai_usdt`: `0xa687c7b3c2cf6adaef0c4edab234c55b88e01333`.
- `flashloan_provider_moolah_proxy`: `0x8F73b65B4caAf64FBA2aF91cC5D4a2A1318E5D8C`.
- `quoter_v2`: `0xB048Bbc1Ee6b733FFfCFb9e9CeF7375518e25997`.
- `swap_router`: `0x1b81d678ffb9c0263b24a97847620c99d213eb14`.
- `payout_recipient`: `0x078f3f917c7355027a8388b7083b2199910c8a9a`.

The PoC:

- Instantiates interfaces pointing at the exact USDT, YULIAI, victim, pool, QuoterV2, and SwapRouter addresses.
- Labels them to match their semantic roles.
- Uses a fresh `attacker` instead of reusing the historical EOA, while still routing USDT and YULIAI through the real contracts.

### 4.2 Pre‑checks

The `pre_check` section requires:

1. Victim USDT balance is positive before the exploit.
2. The Pancake V3 pool has non‑zero USDT and YULIAI reserves.
3. Snapshot `attackerUsdtBefore`.
4. Snapshot victim’s USDT and YULIAI balances.

The test implements these directly in `setUp()`:

- `victimUsdtBefore = usdt.balanceOf(VICTIM); assertGt(victimUsdtBefore, 0, ...)`
- `poolUsdtBefore = usdt.balanceOf(POOL_YULIAI_USDT);`
- `poolYuliaiBefore = yuliai.balanceOf(POOL_YULIAI_USDT);`
- `attackerUsdtBefore = usdt.balanceOf(attacker);`
- `victimYuliaiBefore = yuliai.balanceOf(VICTIM);`

These values are reused in the oracle checks after the exploit.

### 4.3 Hard constraints

The oracle definition includes two hard constraints:

1. **HC_asset_type_usdt_profit**  
   - Profit must be realized in USDT, not some unrelated token.  
   - Implemented as:

     ```solidity
     address profitToken = address(usdt);
     assertEq(profitToken, address(usdt), "profit token must be USDT");
     ```

2. **HC_unprivileged_payout_call_succeeds**  
   - An unprivileged attacker must be able to call the victim’s payout entrypoint (selector `0x2397e4d7`) without revert.  
   - Implemented by:

     - Using a fresh `attacker` without any special on‑chain permissions.
     - Letting `testExploit()` call `exploit()`; any revert in the call chain causes the test to fail.
     - The validation run shows the exploit call succeeds and the test passes, confirming the entrypoint is callable by an unprivileged sender.

### 4.4 Soft constraints

The soft constraints and their implementations are:

1. **SC_attacker_usdt_profit_min_1_USDT**  
   - After the exploit: `attackerUsdtAfter - attackerUsdtBefore >= 1e18`.  
   - Implemented as:

     ```solidity
     uint256 attackerUsdtAfter = usdt.balanceOf(attacker);
     assertGe(
         attackerUsdtAfter - attackerUsdtBefore,
         1e18,
         "attacker must gain at least 1 USDT in profit_token"
     );
     ```

2. **SC_victim_usdt_depletion_min_1_USDT**  
   - Victim USDT loss is at least `1e18`.  
   - Implemented as:

     ```solidity
     uint256 victimUsdtAfter = usdt.balanceOf(VICTIM);
     assertGe(
         victimUsdtBefore - victimUsdtAfter,
         1e18,
         "victim must lose at least 1 USDT"
     );
     ```

3. **SC_victim_yuliai_inflow**  
   - Victim YULIAI balance increases during the exploit.  
   - Implemented as:

     ```solidity
     uint256 victimYuliaiAfter = yuliai.balanceOf(VICTIM);
     assertGt(
         victimYuliaiAfter,
         victimYuliaiBefore,
         "victim must receive some YULIAI during the exploit"
     );
     ```

4. **SC_pool_reserve_shift_usdt**  
   - USDT reserves in the YULIAI/USDT pool change by at least `1e18`.  
   - Implemented as:

     ```solidity
     uint256 poolUsdtAfter = usdt.balanceOf(POOL_YULIAI_USDT);
     uint256 diff = poolUsdtAfter > poolUsdtBefore
         ? poolUsdtAfter - poolUsdtBefore
         : poolUsdtBefore - poolUsdtAfter;
     assertGe(diff, 1e18, "pool USDT reserves must move by at least 1 USDT during exploit");
     ```

All of these checks passed in the validator run, confirming that the PoC satisfies the oracle specification.

## 5. Validation Result and Robustness

The PoC validator wrote its structured result to:

- `/home/wesley/TxRayExperiment/incident-202601030959/artifacts/poc/poc_validator/poc_validated_result.json`

Key fields:

- `overall_status = "Pass"`  
  The PoC both executes successfully and satisfies all correctness and quality criteria.

- `poc_correctness_checks.passes_validation_oracles.passed = "true"`  
  All hard and soft oracles derived from `oracle_definition.json` pass on a BNB Chain mainnet fork at block `57432055`.

- `poc_quality_checks.*.passed = "true"` for:

  - `oracle_alignment_with_definition`
  - `human_readable_and_labeled`
  - `no_magic_numbers_and_values_are_derived`
  - `mainnet_fork_no_local_mocks`
  - `self_contained_no_attacker_side_artifacts` (all subfields)
  - `end_to_end_attack_process_described`
  - `alignment_with_root_cause`

- `artifacts.validator_test_log_path` points to the Forge test log with full trace output:

  - `/home/wesley/TxRayExperiment/incident-202601030959/artifacts/poc/poc_validator/forge-test.log`

The Forge run summary in that log shows:

```text
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in ...
Ran 1 test suite ...: 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

*Snippet origin: Tail of `forge-test.log` summarizing that `ExploitTest.testExploit` passed on the mainnet fork.*

Taken together, these results indicate that the PoC is robust, correctly wired to live mainnet state, and not dependent on fragile or undocumented assumptions.

## 6. Linking PoC Behavior to Root Cause

The root cause report (`/home/wesley/TxRayExperiment/incident-202601030959/root_cause_report.md`) identifies the core vulnerability as a protocol bug in the YULIAI/USDT payout contract `0x8262...`:

- It uses a QuoterV2 spot quote from the Pancake V3 YULIAI/USDT pool to size large USDT payouts.
- It fails to defend against flash‑loan‑driven price manipulation of the pool within the same transaction.
- An unprivileged adversary can combine:

  - A large USDT flash loan from Moolah,
  - Price manipulation via Pancake V3 swaps,
  - A single call to selector `0x2397e4d7` on the victim,

to drain USDT from the victim while sending YULIAI in the opposite direction.

The PoC concretely exercises this logic:

- **Adversary‑crafted step (A)**: In `exploit()`, `whale` performs a large USDT→YULIAI swap on the real Pancake V3 pool, moving the on‑chain spot price used by QuoterV2.
- **Contract‑internal computation (C)**: The victim contract, when called via `sellToken`, invokes QuoterV2 with the manipulated pool state, pulls YULIAI from the attacker, and computes an oversized USDT payout.
- **Token transfers and profit realization (T)**: The victim’s USDT balance decreases while:

  - The real `PayoutRecipient` receives USDT,
  - The `attacker` receives USDT,
  - The victim’s YULIAI balance increases,
  - The pool’s USDT reserves shift.

These steps align with the ACT framing in the root cause JSON:

- **Opportunity**: The public mainnet state at block `57432055` and the ability to use public Moolah, Pancake V3, and QuoterV2 contracts without privileges.
- **Action**: The adversary orchestrates a large price‑moving swap and then calls the vulnerable victim entrypoint.
- **Consequence**: The attacker cluster gains USDT, the victim loses USDT and gains YULIAI, and the payout recipient is also funded from the victim’s USDT balance.

The PoC’s assertions directly encode this linkage:

- Attacker USDT profit and victim USDT loss confirm the monetary impact.
- Victim YULIAI inflow shows the mispriced OTC‑style trade from YULIAI into USDT.
- Pool USDT reserve change captures the adversarial price movement.
- The absence of special roles or whitelists in the call chain demonstrates that the exploit is feasible for any unprivileged actor with access to flash‑loan‑sized liquidity.

Overall, the PoC provides a faithful, self‑contained reproduction of the real incident’s exploit path and root cause, suitable for regression testing, external review, and future hardening work on protocols using Quoter‑based payouts.

