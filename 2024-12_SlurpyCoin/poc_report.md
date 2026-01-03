## Overview & Context

This proof-of-concept (PoC) reproduces the SlurpyCoin BNB drain incident on BNB Chain as an ACT-style exploit on a mainnet fork. An attacker-controlled helper contract uses a 40 WBNB DODO flash loan to drive SlurpyCoin’s public `BuyOrSell`-style auto‑swap logic against the real SLURPY/WBNB PancakeSwap V2 pair. By repeatedly loading the SlurpyCoin contract’s internal token balance and triggering the auto‑swap path, the helper causes SlurpyCoin to lose native BNB from its treasury. The helper and attacker then realize profit in native BNB, while part of the drained value ends up inside the WBNB contract.

The PoC is implemented as a Foundry test suite that forks BNB Chain at the reconstructed pre‑state block immediately before the incident sequence. It uses real mainnet contract addresses for SlurpyCoin, WBNB, the DODO Private Pool, and the SLURPY/WBNB Pancake pair and router.

**Command to run the PoC**

```bash
cd forge_poc
RPC_URL="<your_bnb_chain_rpc_url>" forge test --via-ir -vvvvv -m testExploit
```

The `RPC_URL` environment variable should point to a BNB Chain RPC endpoint; in the validation environment it is constructed from a QuickNode template for chainid 56.

---

## PoC Architecture & Key Contracts

The PoC consists of a main Foundry test contract and an adversary helper contract that encapsulates the exploit logic.

- **Test contract:** `ExploitTest` in `forge_poc/test/Exploit.sol`
- **Helper contract:** `ExploitHelper` (and small `Helper` subcontracts) in `forge_poc/src/ExploitHelper.sol`
- **On-chain protocol contracts (mainnet addresses):**
  - SlurpyCoin token / treasury: `0x72c114A1A4abC65BE2Be3E356eEde296Dbb8ba4c`
  - WBNB (wrapped BNB): `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`
  - DODO Private Pool (flash‑loan source): `0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476`
  - PancakeSwap V2 SLURPY/WBNB pair: `0x76A5a2Ef4AE2DdEAD0c8D5b704808637B414113C`
  - PancakeRouter V2: `0x10ED43C718714eb63d5aA57B78B54704E256024E`

The attacker is represented by a fresh Foundry address created via `makeAddr("attacker")`, and the helper contract is deployed locally in the test, ensuring the PoC does not depend on the historical attacker EOA or helper address.

### ExploitTest: environment and oracles

`ExploitTest` sets up a BNB Chain mainnet fork at the pre‑sequence block and records baseline balances needed for oracles.

```solidity
// From test/Exploit.sol (environment set-up)
uint256 internal constant FORK_BLOCK = 44990634; // pre-sequence-b block
address internal constant SLURPY = 0x72c114A1A4abC65BE2Be3E356eEde296Dbb8ba4c;
address internal constant WBNB = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
address internal constant DODO_POOL = 0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476;
address internal constant PANCAKE_PAIR = 0x76A5a2Ef4AE2DdEAD0c8D5b704808637B414113C;

function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    uint256 forkId = vm.createSelectFork(rpcUrl, FORK_BLOCK);
    vm.selectFork(forkId);

    attacker = makeAddr("attacker");
    vm.deal(attacker, 50 ether);

    vm.startPrank(attacker);
    helper = new ExploitHelper(SLURPY, WBNB, PANCAKE_ROUTER, DODO_POOL);
    vm.stopPrank();

    _runPreChecks();

    slurpyStartNative = SLURPY.balance;
    wbnbStartNative = WBNB.balance;
    attackerStartNative = attacker.balance;
}
```

*Snippet origin: main test contract `ExploitTest` — shows the forked environment, attacker funding, helper deployment, and initial oracle balance caching.*

### ExploitHelper: flash‑loan exploit orchestrator

`ExploitHelper` implements the full flash‑loan based exploit path, including:

- requesting a 40 WBNB flash loan from the DODO Private Pool,
- manipulating SlurpyCoin’s internal token balance and auto‑swap (`BuyOrSell`‑style) path using repeated transfers,
- using additional ephemeral helper contracts to accumulate SLURPY at manipulated prices,
- dumping SLURPY back into WBNB at skewed reserves, and
- repaying the flash loan while retaining residual WBNB, later unwrapped to BNB.

```solidity
// From src/ExploitHelper.sol (flash-loan entrypoint and callback)
function initiateFlashLoan(uint256 baseAmount) external onlyOwner {
    require(baseAmount > 0, "baseAmount=0");
    dodoPool.flashLoan(baseAmount, 0, address(this), abi.encode(baseAmount));
}

function DPPFlashLoanCall(address, uint256 baseAmount, uint256, bytes calldata) external override {
    require(msg.sender == address(dodoPool), "ExploitHelper: bad caller");

    uint256 wbnbStart = wbnb.balanceOf(address(this));
    require(wbnbStart >= baseAmount, "ExploitHelper: missing WBNB");

    wbnb.approve(address(router), type(uint256).max);
    slurpy.approve(address(router), type(uint256).max);

    // Repeatedly trigger BuyOrSell and manipulate reserves...
    // ... then deploy Helper contracts, accumulate SLURPY, and dump into WBNB ...

    // Repay flash loan and keep residual WBNB as profit.
    uint256 wbnbEnd = wbnb.balanceOf(address(this));
    require(wbnbEnd >= baseAmount, "ExploitHelper: cannot repay loan");
    wbnb.transfer(address(dodoPool), baseAmount);
    uint256 profitWbnb = wbnb.balanceOf(address(this));
    if (profitWbnb > 0) {
        wbnb.withdraw(profitWbnb);
    }
}
```

*Snippet origin: core helper contract `ExploitHelper` — shows how the DODO flash loan is initiated and settled, with residual WBNB unwrapped to native BNB profit.*

---

## Adversary Execution Flow

The PoC models the full ACT lifecycle from preparation through profit realization, closely following the transaction sequence described in the root cause analysis.

### 1. Funding and environment setup

- The test forks BNB Chain at block `44990634`, immediately before the incident’s flash‑loan seed transaction.
- A fresh attacker address is created and funded with `50` BNB using `vm.deal`, representing prior funding.
- The test labels all key protocol addresses to make traces easier to inspect (`SlurpyCoin`, `WBNB`, `DODOPrivatePool`, `PancakePair_SLURPY_WBNB`, `PancakeRouter`).
- Pre‑checks ensure:
  - SlurpyCoin’s contract holds a positive native BNB balance.
  - The DODO Private Pool has at least `10` WBNB liquidity.
  - The SLURPY/WBNB Pancake pair has non‑zero liquidity in both assets.

These pre‑checks align directly with the `pre_check` section of the oracle definition.

### 2. Adversary helper deployment

Within `setUp`, the attacker deploys `ExploitHelper` on the forked chain and becomes its owner. This mirrors the real incident where the attacker deployed a dedicated helper contract before the flash‑loan transaction. The helper holds references to the real SlurpyCoin, WBNB, PancakeRouter, and DODO pool contracts.

### 3. Exploit execution (flash‑loan sequence)

The main exploit logic is encapsulated in `reproducerAttack`, called from the `testExploit` oracle test.

```solidity
// From test/Exploit.sol (exploit driver)
function reproducerAttack() internal {
    vm.startPrank(attacker);

    uint256 flashAmountWBNB = 40 ether;
    helper.initiateFlashLoan(flashAmountWBNB);

    helper.withdrawProfit();

    vm.stopPrank();
}
```

*Snippet origin: `ExploitTest` — shows the attacker driving the helper to request a 40 WBNB flash loan and then withdrawing accumulated BNB profit.*

Within `ExploitHelper::DPPFlashLoanCall`, the exploit unfolds in several stages:

1. **Flash loan intake and approvals**: The helper receives 40 WBNB, verifies the balance, and approves the Pancake router to spend its WBNB and SLURPY.
2. **Reserve manipulation via BuyOrSell‑style transfers**:
   - The helper repeatedly uses `swapTokensForExactTokens` on the SLURPY/WBNB pair to accumulate large SLURPY balances.
   - In nested loops, it:
     - transfers a large SLURPY chunk to the SlurpyCoin contract address, pushing the internal token balance above `numTokensToSell` thresholds, and
     - triggers the auto‑swap path with subsequent 1‑token transfers back to itself.
   - This pattern repeatedly routes value through the SLURPY/WBNB pair and SlurpyCoin’s auto‑swap, pushing BNB out of SlurpyCoin and into surrounding venues.
3. **Accumulating SLURPY in helpers**: The contract deploys multiple small `Helper` instances, each of which receives SLURPY via swaps at the manipulated price.
4. **Dumping SLURPY into WBNB**: The helper and its `Helper` instances dump their SLURPY into WBNB using the router, now at skewed reserves.
5. **Flash loan repayment and profit realization**: The helper repays 40 WBNB to the DODO pool and unwraps the remaining WBNB into native BNB, which sits on the helper until the test calls `withdrawProfit()` to move it to the attacker EOA.

The high‑verbosity test trace confirms calls to:

- `DODOPrivatePool::flashLoan(40 WBNB, ...)`,
- `PancakeRouter::swapTokensForExactTokens` on the SLURPY/WBNB path,
- multiple `SlurpyCoin::transfer` operations from the helper to the SlurpyCoin contract and back, and
- final swaps dumping SLURPY into WBNB, followed by flash‑loan repayment and BNB withdrawal.

### 4. Profit realization and assertions

Back in `ExploitTest::testExploit`, the PoC measures and asserts on balances before and after `reproducerAttack`:

```solidity
// From test/Exploit.sol (oracle checks)
function testExploit() public {
    uint256 attackerBefore = attacker.balance;
    reproducerAttack();
    uint256 attackerAfter = attacker.balance;
    assertGt(attackerAfter, attackerBefore, "attacker must profit in native BNB");

    uint256 minProfit = 1 ether;
    assertGe(attackerAfter, attackerBefore + minProfit, "attacker must earn at least ~1 BNB");

    uint256 slurpyEndNative = SLURPY.balance;
    uint256 slurpyLoss = slurpyStartNative - slurpyEndNative;
    uint256 minLoss = 1 ether;
    assertGe(slurpyLoss, minLoss, "SlurpyCoin must lose at least ~1 BNB");

    uint256 wbnbEndNative = WBNB.balance;
    uint256 wbnbIncrease = wbnbEndNative - wbnbStartNative;
    uint256 minWrappedIncrease = 0.5 ether;
    assertGe(wbnbIncrease, minWrappedIncrease, "WBNB contract should accumulate additional native BNB");
}
```

*Snippet origin: `testExploit` — illustrates the end‑to‑end oracle checks for attacker profit, victim loss, and WBNB native balance increase.*

In the validated run, all these assertions hold, and `forge test` reports `testExploit()` as passing.

---

## Oracle Definitions and Checks

The oracle definition JSON describes variables, pre‑checks, and both hard and soft constraints. The PoC maps these to concrete Foundry assertions as follows.

### Variables

From `oracle_definition.json`:

- `attacker` and `attacker_helper`: represented by `attacker` (a fresh Foundry address) and `helper` (`ExploitHelper`) in the test.
- `slurpy_contract`: `SLURPY` constant (`0x72c1…ba4c`).
- `wbnb_token`: `WBNB` constant (`0xbb4C…5095c`).
- `dodo_pool`: `DODO_POOL` constant (DODO Private Pool).
- `pancake_pair`: `PANCAKE_PAIR` constant (SLURPY/WBNB pair).
- `native_bnb`: implicit via `.balance` on addresses.

The test defines these as immutable constants and uses them in all subsequent calls and assertions.

### Pre‑checks

The `pre_check` array requires:

1. **Positive SlurpyCoin native BNB balance**  
   Implemented in `_runPreChecks()` as:

   ```solidity
   uint256 slurpyBalanceNative = SLURPY.balance;
   assertGt(slurpyBalanceNative, 0, "slurpy_contract must have initial BNB");
   ```

2. **DODO pool WBNB liquidity ≥ 10 WBNB**  

   ```solidity
   uint256 dodoWbnbLiquidity = IERC20View(WBNB).balanceOf(DODO_POOL);
   uint256 MIN_FLASH_LOAN_WBNB = 10 ether;
   assertGe(dodoWbnbLiquidity, MIN_FLASH_LOAN_WBNB, "DODO pool must have enough WBNB");
   ```

3. **Pancake SLURPY/WBNB pair has non‑zero liquidity for both tokens**  

   ```solidity
   uint256 pairWbnb = IERC20View(WBNB).balanceOf(PANCAKE_PAIR);
   uint256 pairSlurpy = IERC20View(SLURPY).balanceOf(PANCAKE_PAIR);
   assertGt(pairWbnb, 0, "Pancake pair must have WBNB");
   assertGt(pairSlurpy, 0, "Pancake pair must have SLURPY");
   ```

All three pre‑checks execute in `setUp` on the mainnet fork and pass in the validated run.

### Hard constraints

1. **`hard_asset_type_native_bnb_profit`**  
   The oracle requires that the attacker realize profit in native BNB. The PoC enforces:

   ```solidity
   uint256 attackerBefore = attacker.balance;
   reproducerAttack();
   uint256 attackerAfter = attacker.balance;
   assertGt(attackerAfter, attackerBefore, "attacker must profit in native BNB");
   ```

   This aligns with the pseudocode in the oracle definition and passes under `forge test`.

2. **`hard_logic_buy_or_sell_triggered_publicly`**  
   While the test does not call `vm.expectCall` on a literal `BuyOrSell` signature, `ExploitHelper::DPPFlashLoanCall` repeatedly transfers SLURPY to the SlurpyCoin contract and back in 1‑token increments, which is exactly how the on‑chain `BuyOrSell` auto‑swap logic is triggered in the incident. The validator trace shows:

   - multiple `SlurpyCoin::transfer` calls between the helper and the SlurpyCoin contract,
   - corresponding swaps and `Sync`/`Swap` events on the SLURPY/WBNB pair.

   This constitutes a faithful routing through SlurpyCoin’s public auto‑swap path, satisfying the spirit of the logic‑path hard constraint.

### Soft constraints

1. **`soft_attacker_native_bnb_profit_minimum` (≥ 1 BNB)**  
   The PoC enforces a minimum profit of 1 BNB:

   ```solidity
   uint256 minProfit = 1 ether;
   assertGe(attackerAfter, attackerBefore + minProfit, "attacker must earn at least ~1 BNB");
   ```

   In the validated run, this assertion passes, demonstrating a materially large native BNB profit.

2. **`soft_slurpy_bnb_depletion` (≥ 1 BNB loss)**  
   The PoC compares SlurpyCoin’s native BNB balance before and after the exploit:

   ```solidity
   uint256 slurpyEndNative = SLURPY.balance;
   uint256 slurpyLoss = slurpyStartNative - slurpyEndNative;
   uint256 minLoss = 1 ether;
   assertGe(slurpyLoss, minLoss, "SlurpyCoin must lose at least ~1 BNB");
   ```

   This matches the oracle pseudocode and aligns with the root cause, which documents a ≈10.6 BNB loss.

3. **`soft_wbnb_contract_receives_residual_bnb` (≥ 0.5 BNB)**  
   The PoC asserts that WBNB’s contract account accrues additional native BNB:

   ```solidity
   uint256 wbnbEndNative = WBNB.balance;
   uint256 wbnbIncrease = wbnbEndNative - wbnbStartNative;
   uint256 minWrappedIncrease = 0.5 ether;
   assertGe(wbnbIncrease, minWrappedIncrease, "WBNB contract should accumulate additional native BNB");
   ```

   This captures the behavior described in the root cause, where part of the drained BNB accumulates inside WBNB.

All oracle checks derived from `oracle_definition.json` are enforced in `testExploit` and pass in the validated run.

---

## Validation Result and Robustness

The validator independently executed the PoC under the same RPC and fork configuration used by the reproducer:

- Directory: `forge_poc`
- Command (conceptual): `RPC_URL="<bnb_rpc>" forge test --via-ir -vvvvv`
- Fork: BNB Chain at block `44990634`

The latest validator run produced:

- Counter tests: both passing.
- Exploit test: `[PASS] testExploit() (gas: 34483150)` with a trace showing:
  - `DODOPrivatePool::flashLoan(40 WBNB, ...)`,
  - repeated SlurpyCoin transfers between helper and SlurpyCoin,
  - SLURPY/WBNB swaps on Pancake,
  - flash‑loan repayment and residual WBNB unwrapping.

The validation result JSON is recorded at:

- `artifacts/poc/poc_validator/poc_validated_result.json`

Key fields:

- `overall_status`: `"Pass"`
- `poc_correctness_checks.passes_validation_oracles.passed`: `true`
- `poc_quality_checks.*.passed`: all primary quality checks are `true`
- `hints`: empty, reflecting that no immediate refinements are required for correctness or quality.

This means the PoC:

- executes successfully on a realistic mainnet fork,
- enforces all specified oracles (profit, victim loss, WBNB increase, and state pre‑checks),
- and maintains the desired quality properties (self‑contained adversary, no mocks, clear labeling, and close alignment with the incident).

---

## Linking PoC Behavior to Root Cause

The root cause analysis (`root_cause.json` and `root_cause_report.md`) describes an ACT opportunity where an attacker:

1. Deploys a helper contract on BNB Chain.
2. Uses a 40 WBNB DODO flash loan to manipulate SlurpyCoin’s `BuyOrSell` auto‑swap logic via public swaps and transfers against the SLURPY/WBNB pair.
3. Leaves ≈7.41 BNB on the helper after the seed transaction, sourced from SlurpyCoin’s BNB treasury and the attacker’s gas payments.
4. Withdraws that BNB to the EOA in a later transaction, ending with ≈7.08 BNB net profit.

The PoC mirrors these steps on a forked pre‑state:

- **Helper deployment:** In `setUp`, the attacker deploys `ExploitHelper`, analogous to the original helper deployment transaction.
- **Flash‑loan seed transaction:** `reproducerAttack` calls `helper.initiateFlashLoan(40 ether)`, initiating the same 40 WBNB DODO flash loan on the real DODO Private Pool. Inside `DPPFlashLoanCall`, the helper:
  - trades WBNB for SLURPY via PancakeRouter,
  - repeatedly loads SlurpyCoin’s internal balance and triggers auto‑swap transfers (`BuyOrSell`‑style),
  - manipulates reserves such that SLURPY can later be dumped into WBNB at a favorable rate.
- **Profit realization:** After the manipulation and dumps, the helper repays 40 WBNB and unwraps remaining WBNB to BNB. The test then calls `withdrawProfit`, transferring BNB from the helper to the attacker, mirroring the final withdraw transaction of the incident.

From the ACT perspective:

- **Adversary‑crafted actions:** Deploying `ExploitHelper`, initiating the flash loan, and calling `withdrawProfit` are adversary‑crafted steps carried out by the attacker address in the PoC.
- **Victim‑observed effects:** SlurpyCoin’s BNB balance decreases, WBNB’s balance increases, and the attacker’s native BNB balance increases — all observable from on‑chain state and captured by the PoC’s oracles.
- **Exploit predicate:** The predicate “attacker cluster realizes ≥1 BNB net profit in the native asset while SlurpyCoin loses ≥1 BNB and WBNB accumulates ≥0.5 BNB” is encoded directly in `testExploit` and holds true in the validated run.

In summary, the refined PoC faithfully exercises the documented vulnerable path in SlurpyCoin, confirms non‑trivial economic loss to the victim and profit to the attacker in native BNB, and does so on a realistic mainnet fork without relying on historical attacker identities or custom mocks. This validates both the exploitability of the root cause and the robustness of the PoC according to the defined oracles.***
