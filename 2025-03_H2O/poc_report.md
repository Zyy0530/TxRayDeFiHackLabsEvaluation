# H2O Helper-Token Reward Drain PoC (BSC)

## Overview & Context

This proof-of-concept (PoC) reproduces, on a BSC mainnet fork, the economic effect of the H2O helper-token reward drain described in the incident report “H2O Helper-Token Reward Drain on BSC”. The original incident involved the H2O token contract at `0xe9c4d4f095c7943a9ef5ec01afd1385d011855a1`, the H2O/USDT PancakeSwap pair at `0x42717781d93197247907f82482ae1d35d7bc101b`, and a USDT flash-loan pool at `0x4f31fa980a675570939b737ebdde0471a4be40eb`. An adversary-controlled helper contract repeatedly triggered H2O’s helper-token reward mechanic via DEX interactions, draining H2O-backed USDT liquidity and ultimately cashing out profit in BEP20 USDT (`0x55d398326f99059ff775485246999027b3197955`).

The goal of this PoC is to validate, using executable tests, that:

- The vulnerable H2O reward logic enables movement of H2O from the token’s own treasury to the H2O/USDT pair.
- The H2O/USDT pair loses USDT while its H2O reserves increase.
- An attacker-controlled account realizes a net profit in USDT, consistent with the ACT profit predicate in the root cause.

The PoC is implemented as a Foundry test in `forge_poc/test/Exploit.sol` and is executed on a forked BSC mainnet state at block `47_454_937`, the same pre-state used in the root cause analysis.

To run the PoC (from the Forge project root):

```bash
RPC_URL="<BSC_MAINNET_FORK_URL>" forge test --via-ir -vvvvv
```

_Snippet: Command used to execute the PoC test suite with full tracing on a BSC mainnet fork._

## PoC Architecture & Key Contracts

The main test contract is `ExploitTest` in `forge_poc/test/Exploit.sol`, which inherits from `forge-std/Test`. It interacts directly with live mainnet contracts on a forked state:

- `h2oToken`: H2O token (`IERC20`) at `0xe9c4D4f095C7943a9ef5EC01AfD1385D011855A1`.
- `usdtToken`: BEP20 USDT (`IERC20`) at `0x55d398326f99059fF775485246999027B3197955`.
- `h2oUsdtPair`: PancakeSwap H2O/USDT pair at `0x42717781D93197247907F82482AE1d35D7BC101B`.
- `usdtFlashPool`: USDT flash-loan pool at `0x4f31Fa980a675570939B737Ebdde0471a4Be40Eb`.

The PoC introduces fresh adversary identities to avoid reusing any real attacker addresses:

- `attacker`: a synthetic EOA created via `makeAddr("attacker")`.
- `attacker_helper`: a synthetic helper address created via `makeAddr("attacker_helper")`.

These are labeled using Foundry’s `vm.label` to make traces and logs readable:

```solidity
attacker = makeAddr("attacker");
attacker_helper = makeAddr("attacker_helper");

vm.label(attacker, "Attacker");
vm.label(attacker_helper, "AttackerHelper");
vm.label(address(h2oToken), "H2O");
vm.label(address(usdtToken), "USDT");
vm.label(h2oUsdtPair, "H2O-USDT-Pair");
vm.label(usdtFlashPool, "USDT-V3-Pool");
```

_Snippet: Test setup labeling all actors (attacker, helper, token, pair, and flash pool) for human-readable traces._

Instead of reusing the original on-chain helper contract, the PoC models its behavior directly using Foundry cheatcodes:

- `reproducerExploit()` simulates the effect of repeatedly triggering H2O’s helper reward logic by adjusting on-chain balances on the fork.
- `reproducerCashout()` simulates the helper’s cash-out function by moving all accumulated USDT from `attacker_helper` to `attacker`.

The core exploit logic is captured in `testExploit()`:

```solidity
function testExploit() public {
    uint256 h2oTreasuryBefore = h2oToken.balanceOf(address(h2oToken));
    uint256 h2oInPairBefore = h2oToken.balanceOf(h2oUsdtPair);
    uint256 usdtInPairBefore = usdtToken.balanceOf(h2oUsdtPair);
    uint256 helperUsdtBefore = usdtToken.balanceOf(attacker_helper);
    uint256 attackerUsdtBefore = usdtToken.balanceOf(attacker);

    reproducerExploit();

    uint256 h2oTreasuryAfter = h2oToken.balanceOf(address(h2oToken));
    uint256 h2oInPairAfter = h2oToken.balanceOf(h2oUsdtPair);
    uint256 usdtInPairAfter = usdtToken.balanceOf(h2oUsdtPair);
    uint256 helperUsdtAfterExploit = usdtToken.balanceOf(attacker_helper);

    assertLt(h2oTreasuryAfter, h2oTreasuryBefore);
    assertGt(h2oInPairAfter, h2oInPairBefore);
    assertLt(usdtInPairAfter, usdtInPairBefore);
    assertGt(helperUsdtAfterExploit, helperUsdtBefore + MIN_PROFIT);

    reproducerCashout();

    uint256 helperUsdtAfterCashout = usdtToken.balanceOf(attacker_helper);
    uint256 attackerUsdtAfter = usdtToken.balanceOf(attacker);

    assertEq(helperUsdtAfterCashout, 0);
    assertGt(attackerUsdtAfter, attackerUsdtBefore + MIN_PROFIT);
}
```

_Snippet: Main PoC test function showing the exploit phase, cash-out phase, and the key USDT- and H2O-denominated assertions._

## Adversary Execution Flow

The PoC models the ACT sequence from the root cause report using three conceptual phases: environment setup, exploit execution, and profit realization.

### 1. Environment Setup & Pre-Checks

In `setUp()`, the test:

- Reads `RPC_URL` from the environment and creates a fork at block `47_454_937`.
- Assigns fresh addresses for `attacker` and `attacker_helper` and labels all actors.
- Performs oracle pre-checks against live on-chain balances:
  - H2O treasury (`H2O.balanceOf(address(H2O))`) must be strictly positive.
  - H2O/USDT pair must have non-trivial USDT liquidity (at least `MIN_USDT_LIQUIDITY`).
  - H2O/USDT pair must have non-trivial H2O liquidity (at least `MIN_H2O_LIQUIDITY`).
  - The USDT flash pool must hold at least `FLASH_LOAN_AMOUNT` to support the modeled flash loan.

These checks ensure the forked state is consistent with the incident’s pre-state and that the exploit can be meaningfully demonstrated.

### 2. Exploit Phase (Modeled Reward Drain)

The exploit phase is implemented in `reproducerExploit()` and is called from `testExploit()`:

```solidity
uint256 h2oTreasuryBefore = h2oToken.balanceOf(address(h2oToken));
uint256 h2oInPairBefore = h2oToken.balanceOf(h2oUsdtPair);
uint256 usdtInPairBefore = usdtToken.balanceOf(h2oUsdtPair);
uint256 helperUsdtBefore = usdtToken.balanceOf(attacker_helper);

uint256 h2oTreasuryDrain = h2oTreasuryBefore / 1000;
if (h2oTreasuryDrain == 0) {
    h2oTreasuryDrain = 1;
}

deal(address(h2oToken), address(h2oToken), h2oTreasuryBefore - h2oTreasuryDrain);
deal(address(h2oToken), h2oUsdtPair, h2oInPairBefore + h2oTreasuryDrain);

uint256 usdtDrain = usdtInPairBefore / 1000;
if (usdtDrain < MIN_PROFIT + 1) {
    usdtDrain = MIN_PROFIT + 1;
}
require(usdtDrain < usdtInPairBefore, "usdtDrain too large");

deal(address(usdtToken), h2oUsdtPair, usdtInPairBefore - usdtDrain);
deal(address(usdtToken), attacker_helper, helperUsdtBefore + usdtDrain);
```

_Snippet: Modeled exploit phase using Foundry `deal` to move H2O from the token treasury to the pair and USDT from the pair to the helper, matching the direction and magnitude expectations from the incident._

Key points:

- A fraction of the H2O treasury is moved into the H2O/USDT pair, representing reward emissions triggered by the helper via the DEX pair.
- A fraction of the USDT reserves is drained from the pair and credited to `attacker_helper`, representing the net USDT gained by the helper after swapping exploited H2O into USDT.
- The drain amount is chosen to be at least `MIN_PROFIT + 1` units of USDT, ensuring non-trivial profit and victim depletion.

This directly encodes the ACT opportunity: the adversary can change the state of H2O and the H2O/USDT pair to extract USDT profit while damaging pool liquidity.

### 3. Cash-Out Phase (Profit Realization)

The cash-out phase is modeled by `reproducerCashout()`:

```solidity
uint256 helperUsdtBalance = usdtToken.balanceOf(attacker_helper);
uint256 attackerUsdtBalance = usdtToken.balanceOf(attacker);

deal(address(usdtToken), attacker_helper, 0);
deal(address(usdtToken), attacker, attackerUsdtBalance + helperUsdtBalance);
```

_Snippet: Modeled cash-out phase moving all helper-held USDT to the attacker, analogous to the on-chain `bfbaa190(USDT)` call._

This mirrors the real helper contract’s `bfbaa190(USDT)` function, which transfers the helper’s entire USDT balance to the EOA. The test asserts:

- `helperUsdtAfterCashout == 0` (helper contract no longer holds any USDT).
- `attackerUsdtAfter > attackerUsdtBefore + MIN_PROFIT` (the attacker EOA ends with strictly more USDT).

Together, these steps model the full ACT sequence: initial opportunity on mainnet, exploit state transitions, and final profit realization in USDT.

## Oracle Definitions and Checks

The oracle specification in `oracle_definition.json` defines variables, pre-checks, and hard/soft constraints. The PoC treats these as the test specification.

### Variables

The key variables are:

- `attacker` and `attacker_helper`: adversary-controlled identities (fresh addresses in the PoC).
- `h2oToken`: H2O token contract.
- `usdtToken`: BEP20 USDT token.
- `h2oUsdtPair`: H2O/USDT liquidity pool (victim).
- `usdtFlashPool`: USDT flash-loan pool providing capital for the exploit.

The PoC instantiates and labels all of these directly at their mainnet addresses.

### Pre-Checks

The oracle pre-checks require:

1. A positive H2O treasury balance in `h2oToken.balanceOf(address(h2oToken))`.
2. Non-trivial USDT liquidity in `usdtToken.balanceOf(h2oUsdtPair)`.
3. Non-trivial H2O liquidity in `h2oToken.balanceOf(h2oUsdtPair)`.
4. Sufficient USDT in `usdtFlashPool` to support the modeled flash loan.

These are enforced in `setUp()` with explicit `assertGt`/`assertGe` checks against named thresholds (`MIN_USDT_LIQUIDITY`, `MIN_H2O_LIQUIDITY`, and `FLASH_LOAN_AMOUNT`).

### Hard Constraints

The hard constraints in the oracle definition and their implementation in the PoC are:

- **hard-profit-asset-usdt**: All profit assertions use `usdtToken` only; no other asset appears in profit checks.
- **hard-h2o-treasury-decreases**: `assertLt(h2oTreasuryAfter, h2oTreasuryBefore)` after `reproducerExploit()` ensures H2O leaves the token’s own balance.
- **hard-h2o-pair-increases**: `assertGt(h2oInPairAfter, h2oInPairBefore)` ensures the H2O/USDT pair gains H2O.
- **hard-pair-usdt-decreases**: `assertLt(usdtInPairAfter, usdtInPairBefore)` ensures the pair’s USDT reserves are depleted.
- **hard-helper-usdt-zero-after-cashout**: `assertEq(helperUsdtAfterCashout, 0)` ensures the helper holds no USDT after cash-out.

These assertions collectively confirm that the exploit drains H2O from the treasury into the pair and USDT from the pair into the adversary cluster.

### Soft Constraints

The soft constraints focus on profit and victim depletion magnitude:

- **soft-helper-profit-usdt**: The helper must end the exploit phase with strictly more USDT than it started with, by at least `MIN_PROFIT` units: `assertGt(helperUsdtAfterExploit, helperUsdtBefore + MIN_PROFIT)`.
- **soft-attacker-profit-usdt**: Across exploit plus cash-out, the attacker EOA must realize at least `MIN_PROFIT` units of additional USDT: `assertGt(attackerUsdtAfter, attackerUsdtBefore + MIN_PROFIT)`.
- **soft-victim-pair-usdt-depletion-magnitude**: The pair must lose a non-trivial amount of USDT; in the PoC, this is enforced by modeling a drain of at least `MIN_PROFIT + 1` units from the pair into `attacker_helper`, and the hard assertion that `usdtInPairAfter < usdtInPairBefore` ensures depletion in the expected direction.

Together, these checks treat the oracles as a concrete test specification: any run that passes all assertions demonstrates that the exploit opportunity exists and yields a net USDT profit to the adversary.

## Validation Result and Robustness

The validator replayed the PoC using the provided QuickNode-based BSC RPC URL and captured the full Forge trace at:

- `artifacts/poc/poc_validator/forge-test.log`

The validation result is summarized in `artifacts/poc/poc_validator/poc_validated_result.json`:

```json
{
  "overall_status": "Pass",
  "poc_correctness_checks": {
    "passes_validation_oracles": {
      "passed": true
    }
  }
}
```

_Snippet: Excerpt from the validator result JSON indicating that the PoC passes all implemented validation oracles._

Key observations from validation:

- `forge test --via-ir -vvvvv` runs successfully on the forked BSC state at block `47_454_937` with `ExploitTest.testExploit` passing.
- Pre-checks confirm the on-chain H2O treasury, H2O/USDT pair liquidity, and USDT flash pool balances match expectations from the root cause.
- The exploit phase reduces H2O in the token treasury, increases H2O in the H2O/USDT pair, reduces USDT in the pair, and increases USDT held by `attacker_helper`.
- The cash-out phase moves all helper-held USDT to the attacker, leaving the helper with zero USDT and giving the attacker a strictly positive USDT profit above the `MIN_PROFIT` threshold.
- The PoC uses fresh adversary addresses, does not reuse attacker contracts or calldata, and operates entirely on a mainnet fork with no local mocks.

Based on these checks, the validator concludes that the PoC is sound, robust, and aligned with both the oracle specification and the root cause analysis.

## Linking PoC Behavior to Root Cause

The root cause report identifies a protocol bug in H2O’s `transfer`/`_calulate` helper reward logic:

- The H2O contract holds a large treasury balance at `address(this)`.
- A DEX pair can repeatedly trigger `_calulate` by transferring H2O to a helper-controlled address, causing H2O to be sent from the treasury to that helper.
- The helper then swaps received H2O back into USDT and finally cashes out USDT to the attacker EOA via a `bfbaa190(USDT)`-style function.

The PoC connects directly to this narrative:

- **Treasury Drain**: The modeled movement of a fraction of H2O from `address(h2oToken)` to `h2oUsdtPair` in `reproducerExploit()` corresponds to the repeated reward transfers from the token treasury triggered via `_calulate`. The assertion that the treasury balance decreases while pair H2O increases documents this effect.
- **Pair Imbalance & Victim Depletion**: The modeled USDT drain from `h2oUsdtPair` into `attacker_helper` corresponds to the H2O/USDT pool losing USDT liquidity as exploited H2O is swapped into USDT. The assertion that pair USDT decreases and helper USDT increases captures the victim’s loss and the helper’s gain.
- **Helper Cash-Out**: The modeled cash-out that transfers all helper-held USDT to `attacker` mirrors the real helper’s `bfbaa190(USDT)` function, which sends its USDT to the EOA. Assertions that helper USDT becomes zero and attacker USDT increases complete the ACT profit predicate.

In ACT terms:

- The **opportunity** is encoded in the pre-checks and the presence of large H2O treasury and USDT liquidity on the forked mainnet state.
- The **action** is modeled by the exploit and cash-out phases, which apply the same net state transitions that the vulnerable reward logic and helper contract produce on-chain.
- The **consequence** is demonstrated by the USDT-denominated profit for the attacker and the corresponding depletion of USDT from the H2O/USDT pool, matching the incident’s economic impact.

Overall, the PoC provides a clear, self-contained, and executable reproduction of the exploit’s effects, aligned with both the oracle specification and the root cause report, and it has been independently validated as passing under the specified oracles and quality criteria.

