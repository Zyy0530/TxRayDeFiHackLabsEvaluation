## Overview & Context

This proof‑of‑concept (PoC) reproduces the Morpho / SilicaPools WBTC–WETH exploit executed in Ethereum mainnet transaction `0x9b9a6d…f0814`. In the incident, an attacker‑controlled contract used a WBTC flash loan from Morpho, routed value through a SilicaPools ERC1155 position, and then swapped WBTC for WETH on a Uniswap V3 pool before unwrapping WETH to native ETH via WETH9. The attacker cluster ended with significant ETH profit while fully repaying the WBTC flash loan and leaving its net WBTC balance unchanged.

The goal of this PoC is to:
- Recreate the end‑to‑end exploit flow on a forked Ethereum mainnet state.
- Demonstrate the economic effect observed in the incident: zero net WBTC change for the attacker cluster, a strictly positive ETH profit, and a decrease in WETH9’s native ETH balance.
- Tie these behaviors back to the root cause analysis and oracle specification.

The PoC runs as a Foundry test against a mainnet fork configured at the block immediately before the incident. The main test is `test_Exploit_MorphoSilica_WBTC_WETH` in `Exploit_MorphoSilica_WBTC_WETH.t.sol`, which drives a local attacker contract orchestrating the Morpho flash loan, SilicaPools interactions, Uniswap swap, and WETH9 withdrawal.

### How to Run the PoC

From the PoC root:

```bash
cd /home/wesley/TxRayExperiment/incident-202601031828/forge_poc
RPC_URL="<mainnet_rpc_url>" forge test --mc Exploit_MorphoSilica_WBTC_WETH_Test --via-ir -vvvvv
```

Where:
- `RPC_URL` points to an archival‑capable Ethereum mainnet endpoint.
- The test uses `vm.createSelectFork(RPC_URL, 22146339)` to fork one block before the incident and `vm.warp(1743176087)` to align the timestamp with the original transaction.
- The validator run captured logs to:

```bash
/home/wesley/TxRayExperiment/incident-202601031828/artifacts/poc/poc_validator/forge-test.log
```

_Snippet 1 – PoC execution command (from the reproducer notes and validator run)._ 

```bash
RPC_URL="<mainnet_rpc_url>" forge test --mc Exploit_MorphoSilica_WBTC_WETH_Test --via-ir -vvvvv
```

---

## PoC Architecture & Key Contracts

The PoC is built as a Foundry test suite that deploys a local attacker contract and interacts directly with the real mainnet protocol contracts. No mocks are used for the key protocols.

### Main Components

- **Test harness**: `Exploit_MorphoSilica_WBTC_WETH_Test` in `test/Exploit_MorphoSilica_WBTC_WETH.t.sol`.
- **Attacker orchestrator**: `MorphoSilicaWbtcWethAttacker` in `src/MorphoSilicaWbtcWethAttacker.sol`.
- **External protocol contracts (mainnet addresses)**:
  - `WBTC`: `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599`
  - `WETH9`: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
  - `Morpho` flash‑loan contract: `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb`
  - `SilicaPools`: `0xf3F84cE038442aE4c4dCB6A8Ca8baCd7F28c9bDe`
  - `Accounting token` (index): `0x9188738a7cA1E4B2af840a77e8726cC6Dcbe7Bdb`
  - `Uniswap V3 WBTC/WETH pool`: `0x4585FE77225b41b697C938B018E2Ac67Ac5a20c0`

The test uses fresh addresses for the attacker and profit receiver via `makeAddr`:
- `attacker_eoa` – the caller of `yoink()`.
- `attacker_contract` – the deployed `MorphoSilicaWbtcWethAttacker`.
- `profit_receiver` – the address that ultimately receives ETH profit.

### Attacker Contract Responsibilities

The attacker contract:
- Implements `IMorphoFlashLoanCallback` to receive and handle the WBTC flash loan.
- Implements `IUniswapV3SwapCallbackMinimal` to repay WBTC owed to the Uniswap V3 pool during the swap.
- Implements `onERC1155Received` so SilicaPools can safely transfer ERC1155 position tokens to it.

_Snippet 2 – Attacker contract interfaces and state (from `MorphoSilicaWbtcWethAttacker.sol`)._

```solidity
contract MorphoSilicaWbtcWethAttacker is IMorphoFlashLoanCallback, IUniswapV3SwapCallbackMinimal {
    address public immutable owner;
    address public immutable profitReceiver;

    IERC20 public immutable wbtc;
    IWETH9 public immutable weth;
    IMorphoFlashLoan public immutable morpho;
    ISilicaPoolsLike public immutable silicaPools;
    IAccountingToken public immutable accountingToken;
    IUniswapV3PoolMinimal public immutable uniswapPool;

    event LogWbtcBalance(string tag, uint256 balance);
}
```

This contract holds minimal mutable state (only immutable references to external protocols and the profit sink) and uses a set of trace‑derived constants (flash‑loan size, prepayment amount, ERC1155 share counts, long/short token IDs, and Uniswap swap parameters) to mirror the incident path.

---

## Adversary Execution Flow

The exploit is executed via a single test function which sets up the environment, drives the attacker contract, and then applies oracle checks on balances.

### Environment Setup

_Snippet 3 – Fork, timestamp alignment, and deployment (from `Exploit_MorphoSilica_WBTC_WETH.t.sol`)._

```solidity
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    uint256 forkId = vm.createSelectFork(rpcUrl, FORK_BLOCK);
    vm.selectFork(forkId);

    vm.warp(1_743_176_087);

    attackerEOA = makeAddr("attacker_eoa");
    profitReceiver = makeAddr("profit_receiver");

    vm.startPrank(attackerEOA);
    attackerContract = new MorphoSilicaWbtcWethAttacker(
        MORPHO, SILICA_POOLS, ACCOUNTING_TOKEN, WBTC, WETH, UNIV3_WBTC_WETH_POOL, profitReceiver
    );
    vm.stopPrank();

    vm.deal(attackerEOA, 1 ether);
}
```

Key points:
- Forks Ethereum mainnet at block `22146339`, i.e., the block immediately before the incident (`22146340`).
- Warps the forked chain’s timestamp to the incident timestamp, satisfying Silica pool lifecycle checks.
- Deploys the attacker contract from `attacker_eoa` and funds the EOA with 1 ETH for gas.

### Step‑by‑Step Exploit Flow

The core exploit logic is expressed in `yoink()` and `onMorphoFlashLoan()`:

1. **Flash‑loan request**  
   - `attacker_eoa` pranks into `attackerContract.yoink()`.  
   - `yoink()` approves WBTC to SilicaPools and Morpho, then calls `morpho.flashLoan(wbtc, 1_000_000_000, "")`.

2. **Morpho flash loan and Silica prepayment**  
   - Morpho transfers 1e9 WBTC to `attacker_contract` and invokes `onMorphoFlashLoan(assets=1e9, data="")`.  
   - The attacker logs its WBTC balance (`after_flash_loan`) and then pre‑pays `56,125,794` WBTC directly to SilicaPools.

3. **Silica collateralized mint and ERC1155 bounty flow**  
   - The attacker constructs `PoolParams(floor=41, cap=46, index=AccountingToken, targetStart=1743176087, targetEnd=1743176087, payoutToken=WBTC)` and calls `collateralizedMint` with a very large share amount.  
   - SilicaPools mints paired long/short ERC1155 position tokens to the attacker contract using the two large token IDs observed in the incident trace.  
   - The attacker implements `onERC1155Received` so these transfers succeed.  
   - The attacker then transfers `ERC1155_BOUNTY_SHARES` of both long and short tokens to the bounty receiver address `0xcC3a5dC003b3a58621745A39f706eF9646D5c481`, leaving a small residual position behind.

4. **Silica pool lifecycle and redemption**  
   - The attacker calls `accountingToken.change()`, then `silicaPools.startPool()`, `silicaPools.endPool()`, and finally `silicaPools.redeemShort()` for the same `PoolParams`.  
   - This sequence mirrors the incident’s bounty and settlement flow and returns WBTC to the attacker, producing the post‑redeem balance seen in logs (`after_redeem_short`).

5. **Uniswap V3 WBTC→WETH swap and callback**  
   - With WBTC back in hand, the attacker calls the real Uniswap V3 WBTC/WETH pool’s `swap` with `amountSpecified = 114,015,390` and `sqrtPriceLimitX96 = 4,295,128,740`.  
   - The pool invokes `uniswapV3SwapCallback(amount0Delta > 0, amount1Delta < 0, data)`.  

_Snippet 4 – Uniswap swap callback (from `MorphoSilicaWbtcWethAttacker.sol`)._

```solidity
function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external override {
    require(msg.sender == address(uniswapPool), "invalid pool");
    if (amount0Delta > 0) {
        address token0 = abi.decode(data, (address));
        require(token0 == address(wbtc), "unexpected token0");
        require(wbtc.transfer(msg.sender, uint256(amount0Delta)), "pay WBTC failed");
    }
    require(amount1Delta <= 0, "unexpected amount1Delta");
}
```

   - The callback pays back the required WBTC to the pool, completing the swap and leaving the attacker contract holding WETH.

6. **WETH unwrapping and ETH profit realization**  
   - The attacker reads its WETH balance, calls `WETH9.withdraw`, and receives native ETH into its `receive()` function.  
   - It then forwards its entire ETH balance to `profit_receiver` via a low‑level call.  
   - The test’s attacker cluster (EOA, attacker contract, profit receiver) sees a net positive ETH gain; the WETH9 contract’s native balance drops by the same amount.

7. **Flash‑loan repayment**  
   - After the callback returns, Morpho pulls back exactly 1e9 WBTC from `attacker_contract` via `transferFrom`, thanks to the initial approval.  
   - The attacker logs its WBTC balances at several points (`after_flash_loan`, `after_collateralized_mint`, `after_redeem_short`, `after_uniswap_swap`, `before_flash_loan_repay`) to verify that it retains enough WBTC to repay the flash loan but ends with no net WBTC profit.

The forge trace in `forge-test.log` confirms all these steps and matches the on‑chain incident structure, including the specific WBTC and WETH amounts, ERC1155 token IDs, and bounty receiver address.

---

## Oracle Definitions and Checks

The PoC is designed to satisfy an explicit oracle specification defined in `oracle_definition.json`. These oracles define what “success” means for the PoC.

### Variables

Key oracle variables:
- `attacker_eoa`, `attacker_contract`, `profit_receiver`, `attacker_cluster`: dynamic attacker identities, instantiated as fresh addresses in the test.
- `wbtc_token`, `weth_token`: mainnet WBTC and WETH9 contracts.
- `morpho_flash_loan_contract`, `silica_pools`, `accounting_token`, `uniswap_v3_pool`: core protocol contracts involved in the exploit path.

The test maps these directly:
- Constants for each protocol address.
- `attackerEOA`, `attackerContract`, `profitReceiver` matching the oracle’s attacker cluster notion.

### Pre‑Checks

The oracle pre‑checks require:
1. The PoC runs on an Ethereum mainnet fork (`chainid == 1`).
2. Morpho has sufficient WBTC liquidity (≥ `1_000_000_000` units) for the flash loan.
3. All key protocol contracts are deployed (non‑empty code) at the expected addresses.

_Snippet 5 – Pre‑checks (from `Exploit_MorphoSilica_WBTC_WETH.t.sol`)._

```solidity
assertEq(block.chainid, 1, "test must run on Ethereum mainnet fork");

uint256 minFlashLoanAmount = 1_000_000_000;
assertGe(wbtcToken.balanceOf(MORPHO), minFlashLoanAmount);

assertGt(MORPHO.code.length, 0);
assertGt(SILICA_POOLS.code.length, 0);
assertGt(ACCOUNTING_TOKEN.code.length, 0);
assertGt(UNIV3_WBTC_WETH_POOL.code.length, 0);
assertGt(WBTC.code.length, 0);
assertGt(WETH.code.length, 0);
```

These checks ensure the PoC uses the real deployed protocol state and that the flash‑loan path is feasible.

### Hard Constraint – WBTC Cluster Invariant

Hard oracle `hard_wbtc_cluster_invariant`:
- The attacker cluster must have zero net WBTC balance change across EOA, attacker contract, and profit receiver.

Implementation in the test:

```solidity
uint256 wbtcClusterBefore =
    wbtcToken.balanceOf(attackerEOA) +
    wbtcToken.balanceOf(address(attackerContract)) +
    wbtcToken.balanceOf(profitReceiver);

// exploit
vm.prank(attackerEOA);
attackerContract.yoink();

uint256 wbtcClusterAfter =
    wbtcToken.balanceOf(attackerEOA) +
    wbtcToken.balanceOf(address(attackerContract)) +
    wbtcToken.balanceOf(profitReceiver);

assertEq(
    wbtcClusterAfter,
    wbtcClusterBefore,
    "attacker cluster must have zero net WBTC change after exploit"
);
```

This matches the oracle’s requirement that WBTC is purely principal for the flash loan and not a source of net profit.

### Soft Constraint – Attacker ETH Profit

Soft oracle `soft_attacker_eth_profit`:
- The attacker cluster must realize at least 1 ETH of net native profit, with the incident profit around 50.88 ETH.

Implementation in the test:

```solidity
uint256 clusterEthBefore =
    attackerEOA.balance +
    address(attackerContract).balance +
    profitReceiver.balance;

// exploit already executed above

uint256 clusterEthAfter =
    attackerEOA.balance +
    address(attackerContract).balance +
    profitReceiver.balance;

assertGe(
    clusterEthAfter - clusterEthBefore,
    1 ether,
    "attacker cluster must earn at least 1 ETH of native profit from the exploit"
);
```

Under the validated run, the attacker cluster’s profit is much larger than 1 ETH, aligning qualitatively with the incident’s ~50.88 ETH gain.

### Soft Constraint – WETH9 Native Balance Decrease

Soft oracle `soft_weth_native_balance_decrease`:
- WETH9’s native ETH balance must strictly decrease, reflecting that WETH is unwrapped to ETH for the attacker cluster.

Implementation in the test:

```solidity
uint256 wethNativeBefore = address(WETH).balance;

// exploit already executed above

uint256 wethNativeAfter = address(WETH).balance;

assertLt(
    wethNativeAfter,
    wethNativeBefore,
    "WETH9 native ETH balance must decrease as WETH is unwrapped to pay the attacker cluster"
);
```

The forge trace shows WETH9 transferring `50.884937982392301148` WETH to the attacker contract, then calling `withdraw` for the same amount, and finally sending ETH to `profit_receiver`, exactly matching the victim depletion pattern captured in the root‑cause artifacts.

---

## Validation Result and Robustness

The validator reran the exploit test with the following command:

```bash
cd /home/wesley/TxRayExperiment/incident-202601031828/forge_poc
RPC_URL="<mainnet_rpc_url>" forge test --mc Exploit_MorphoSilica_WBTC_WETH_Test --via-ir -vvvvv \
  > /home/wesley/TxRayExperiment/incident-202601031828/artifacts/poc/poc_validator/forge-test.log 2>&1
```

Key observations from the validator run:
- Compilation succeeds with no missing sources or scripts.
- The test suite runs one test:
  - `test_Exploit_MorphoSilica_WBTC_WETH()` **[PASS]** (gas: ~543k).
- The trace shows:
  - `vm.createSelectFork` targeting mainnet block `22146339`.
  - Morpho flash‑loan of `1_000_000_000` WBTC to the attacker contract.
  - SilicaPools `collateralizedMint`, ERC1155 transfers to the bounty receiver, `startPool`, `endPool`, `redeemShort`.
  - Uniswap V3 swap with `amountSpecified = 114,015,390` WBTC and a non‑trivial state delta in the pool.
  - `WETH9.withdraw` of `50.884937982392301148` WETH, followed by a fallback on the profit receiver receiving the same ETH amount.
  - Final `WBTC::transferFrom` of exactly `1_000_000_000` WBTC from the attacker contract back to Morpho.

The validator’s structured result in `poc_validated_result.json` is:
- `overall_status`: `"Pass"`
- `poc_correctness_checks.passes_validation_oracles.passed`: `true`
- All PoC quality checks (oracle alignment, human readability, magic numbers justification, mainnet‑fork, self‑containment, end‑to‑end flow, and alignment with root cause) are marked `true`.
- `artifacts.validator_test_log_path` points to the Forge log captured above.

Robustness considerations:
- The PoC uses concrete amounts derived from the incident, but the oracle thresholds are tolerant (e.g., ≥1 ETH profit rather than an exact value), so minor variations in pool state or fees should still satisfy the checks as long as the economic structure of the exploit remains valid.
- The use of `vm.createSelectFork` at a fixed block ensures reproducibility and shields the PoC from future on‑chain state changes.

---

## Linking PoC Behavior to Root Cause

The root‑cause analysis for the seed transaction describes:
- An attacker contract `yoink` call that:
  - Approves WBTC to SilicaPools and Morpho.
  - Initiates a Morpho WBTC flash loan of `1_000_000_000` units.
  - Uses SilicaPools ERC1155 positions and accounting token mechanics to manipulate a pool and extract value.
  - Routes WBTC through a Uniswap V3 WBTC/WETH pool.
  - Calls WETH9 to withdraw WETH into ETH, reducing WETH9’s native balance by ~50.8849 ETH.
  - Leaves the attacker cluster with significant ETH profit and neutral WBTC balance.

The PoC mirrors this behavior using fresh attacker identities:

- **Morpho flash loan and zero WBTC net change**
  - The PoC’s `yoink` and `onMorphoFlashLoan` follow the same approval and flash‑loan pattern, borrowing exactly `1e9` WBTC and later repaying the same amount to Morpho.  
  - The hard oracle asserts that the attacker cluster’s WBTC balance is unchanged, matching the incident’s principal‑only WBTC flows.

- **SilicaPools ERC1155 mechanics**
  - The PoC uses the same SilicaPools contract, accounting token, ERC1155 token IDs, floor/cap values, and timestamps as identified in the trace.  
  - It replicates the sequence of `collateralizedMint`, ERC1155 `safeTransferFrom` to the bounty receiver, `startPool`, `endPool`, and `redeemShort`, demonstrating how the Silica pool configuration is exploited to route value back to the attacker.

- **Uniswap V3 WBTC/WETH swap and WETH9 withdrawal**
  - The PoC drives the real Uniswap V3 WBTC/WETH pool with the same swap parameters as in the incident.  
  - The validated trace shows the expected WBTC in/WETH out behavior and state diffs on the pool contract.  
  - Subsequent `WETH9.withdraw` and the ETH transfer to `profit_receiver` match the victim depletion pattern described in the root‑cause artifacts, including the magnitude of WETH/ETH flow.

- **Attacker profit and ACT framing**
  - **Adversary Actions (A)**: constructing the attacker contract, triggering the Morpho flash loan, driving SilicaPools, executing the swap, and unwrapping WETH.  
  - **Chain/Contract Transitions (C)**: Morpho flash‑loan callbacks, SilicaPools ERC1155 mints/transfers, accounting token index changes, Uniswap pool state updates, and WETH9 balance changes.  
  - **Target Observation (T)**: The oracles and final assertions observe:
    - ETH profit realized by the attacker cluster (attacker_eoa + attacker_contract + profit_receiver).  
    - No net WBTC gain for the attacker cluster.  
    - Depletion of WETH9’s native balance.

Together, these steps show that the PoC not only replays the structural exploit path but also satisfies the explicit oracle predicates that encode the root cause: an MEV‑style opportunity where an unprivileged attacker uses a flash loan and SilicaPools mispricing to convert protocol‑owned WETH into attacker‑owned ETH without taking WBTC principal risk.

This alignment between the PoC’s behavior, the oracle specification, and the root‑cause analysis justifies the validator’s conclusion that the PoC is correct, high‑quality, and fully reproduces the incident’s exploit conditions.

