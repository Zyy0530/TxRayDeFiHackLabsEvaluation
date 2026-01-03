# SorraV2 Staking Repeated Reward Withdrawal  

## Incident Overview & TL;DR

SorraV2 operates a staking contract, `sorraStaking` at `0x5d16b8ba2a9a4eca6126635a6ffbf05b52727d50`, which accepts SorraV2 (`SOR`) deposits and pays time‑based rewards. An adversary EOA, `0xdc8076c21365a93aac0850b67e4ca5fdec5fab9b`, controls a front‑end contract, `0xfa39257c629f9a5da2c0559debe2011eef7c1e9f`, that interacts with `sorraStaking` via `DELEGATECALL` into helper contracts.  

The incident centers on a protocol‑level accounting bug in `sorraStaking.withdraw`. For a fully vested position, each call to `withdraw(_amount)` recomputes the full vested reward for the user and transfers `_amount + reward` tokens, without tracking previously distributed rewards on a per‑deposit basis. By combining this bug with a helper contract that repeatedly calls `withdraw(1)` for the same fully vested position, the adversary drains a large quantity of SorraV2 from the staking pool and swaps it for ETH through the SOR‑WETH Uniswap V2 pair.  

The attack is profitable in ETH terms and constitutes an ACT opportunity: any unprivileged staker with a fully vested SorraV2 position in `sorraStaking` can, in principle, construct a similar repeated‑withdraw flow (with or without a front‑end) to realize the same pattern of repeated reward extraction until the pool is drained or positions are exhausted.

## ACT Opportunity and Pre‑State

### Pre‑state at Block 21550968

The analysis focuses on Ethereum mainnet block `21550968`, which contains the primary profit transaction `0x6439d63cc57fb68a32ea8ffd8f02496e8abad67292be94904c0b47a4d14ce90d`. Immediately prior to this block:

- `sorraStaking` (`0x5d16…7d50`) holds a large pool of SorraV2 and maintains user positions in `positions[wallet]`.
- SorraV2 (`0xe021baa5b70c62a9ab2468490d3f8ce0afdd88df`) is deployed with an active SOR‑WETH Uniswap V2 pair at `0xa15c4914be0b454b0b7c27b4839a4a01da8ed308`.
- The adversary front‑end `0xfa3925…` already has a substantial staked position in `sorraStaking`, created by earlier deposits controlled by EOA `0xdc8076…`.

This pre‑state is supported by:

- Seed metadata for the deposit and claim txs.  
- Verified source and bytecode for `sorraStaking` and SorraV2.  
- Address txlists for the front‑end showing prior interactions leading to an established position.

### ACT Exploit Predicate

The exploit predicate is profit‑based and evaluated in ETH:

- **Reference asset:** ETH.  
- **Adversary address:** `0xdc8076c21365a93aac0850b67e4ca5fdec5fab9b`.  
- **Value before (wei):** `464323822924538962`.  
- **Value after (wei):** `5158038564630217813`.  
- **Delta (wei):** `4693714741705678851`.  

These values come directly from `native_balance_deltas` in the balance diff for claim tx `0x6439d63c…`. The on‑chain ETH balance of the adversary EOA increases by ~4.6937 ETH over this single transaction, net of all inflows and outflows recorded in that balance diff. Gas fees were not separately broken out, but the resulting ETH delta is strictly positive, establishing that the incident is profitable in the reference asset.

### Key Seed Transactions

Two transactions serve as anchors for the analysis:

1. **Deposit tx (position creation) – `0x72a252277e30ea6a37d2dc9905c280f3bc389b87f72b81a59aa8f50baebd8eaa`**  
   - EOA `0xdc8076…` calls front‑end `0xfa3925…` with zero ETH and calldata for `deposit(100000000000000000000000, 0)`.  
   - The front‑end performs a `DELEGATECALL` into helper `0x943cd9f36374e0ef733213e23f4fd8a37c4f207e`, which:  
     - Reads SorraV2 balance of the front‑end.  
     - Approves `sorraStaking` for that balance.  
     - Calls `sorraStaking::deposit` to create a large staking position for `0xfa3925…`.  

2. **Claim tx (repeated reward withdrawal) – `0x6439d63cc57fb68a32ea8ffd8f02496e8abad67292be94904c0b47a4d14ce90d`**  
   - EOA `0xdc8076…` calls front‑end `0xfa3925…` with 0.1 ETH and calldata `claim(500, true)`.  
   - The front‑end `DELEGATECALL`s into helper `0xb575b2599b9dcf242bb9dca60dc2ad36a1ca8cd7`, which repeatedly calls `sorraStaking::withdraw(1)` for the front‑end’s position.  
   - Each call transfers `1` unit of principal plus a full vested reward amount, and the drained SorraV2 is sold for ETH through the SOR‑WETH pair.

#### Deposit Trace Snippet (Position Creation)

Origin: Seed transaction trace for deposit tx `0x72a25227…`.  

```text
0xFa39257C629F9A5DA2c0559deBe2011eEF7C1E9f::deposit(100000000000000000000000 [1e23], 0)
  ├─ 0x943cd9F36374E0Ef733213e23F4fd8a37c4F207E::deposit(...) [delegatecall]
  │   ├─ SorraV2::balanceOf(0xFa3925…)
  │   ├─ SorraV2::approve(sorraStaking: [0x5d16b8…7d50], 122868871710593438486048 [1.228e23])
  │   ├─ sorraStaking::deposit(122868871710593438486048 [1.228e23], 0)
  │   │   ├─ SorraV2::transferFrom(0xFa3925…, sorraStaking, 122868871710593438486048)
  │   │   ├─ emit Depositx(user: 0xFa3925…, amount: 122868871710593438486048)
```

*Caption: Helper 0x943c… uses delegatecall to move SorraV2 from the front‑end into `sorraStaking` and create a large tier‑0 position for address `0xfa3925…`.*  

#### Claim Trace Snippet (Repeated Withdrawals)

Origin: Seed transaction trace for claim tx `0x6439d63c…`.  

```text
0xFa39257C629F9A5DA2c0559deBe2011eEF7C1E9f::claim{value: 0.1 ETH}(500, true)
  ├─ 0xB575b2599B9dCf242BB9dCA60DC2aD36a1cA8CD7::claim(...) [delegatecall]
  │   ├─ sorraStaking::withdraw(1)
  │   │   ├─ emit Withdraw(user: 0xFa3925…, amount: 1)
  │   │   ├─ SorraV2::transfer(0xFa3925…, 6143443585529671924303 [6.143e21])
  │   │   ├─ emit RewardDistributed(user: 0xFa3925…, amount: 6143443585529671924302)
  │   ├─ sorraStaking::withdraw(1)
  │   │   ├─ (same pattern repeats many times)
```

*Caption: Helper 0xb575… repeatedly calls `withdraw(1)` for the front‑end’s fully vested position, each time triggering a full reward transfer and `RewardDistributed` event.*  

## Vulnerability & Root Cause Analysis

### sorraStaking Reward Accounting Bug

The staking contract `sorraStaking` implements deposit and withdraw functions around a `Position` made of multiple `Deposit` entries. Rewards are computed based on deposit amounts, per‑tier reward basis points, and vesting periods.

Key relevant excerpts from the verified source:

```solidity
function withdraw(uint256 _amount) external nonReentrant {
    require(_amount > 0, "Amount must be greater than 0");
    Position storage position = positions[_msgSender()];
    require(_amount <= position.totalAmount, "Insufficient balance");
    
    uint256 withdrawableAmount = 0;
    for (uint256 i = 0; i < position.deposits.length; i++) {
        Deposit memory dep = position.deposits[i];
        if (block.timestamp > dep.depositTime + vestingTiers[dep.tier].period) {
            withdrawableAmount += dep.amount;
        }
    }
    require(withdrawableAmount >= _amount, "Lock period not finished");
    
    uint256 rewardAmount = getPendingRewards(_msgSender());
    
    _updatePosition(_msgSender(), _amount, true, position.deposits[0].tier);
    
    if (rewardAmount > 0) {
        userRewardsDistributed[_msgSender()] += rewardAmount;
        totalRewardsDistributed += rewardAmount;
        IERC20(rewardToken).safeTransfer(_msgSender(), _amount + rewardAmount);
        emit RewardDistributed(_msgSender(), rewardAmount);
    } else {
        IERC20(rewardToken).safeTransfer(_msgSender(), _amount);
    }
}

function getPendingRewards(address wallet) public view returns (uint256) {
    if (positions[wallet].totalAmount == 0) {
        return 0;
    }
    return _calculateRewards(positions[wallet].totalAmount, wallet);
}

function _calculateRewards(uint256 /* unusedParam */, address wallet)
    internal
    view
    returns (uint256)
{
    Position storage pos = positions[wallet];
    uint256 length = pos.deposits.length;
    if (length == 0) return 0;

    uint256 totalRewards = 0;
    uint256 currentTime = block.timestamp;
    
    for (uint256 i = 0; i < length; i++) {
        Deposit storage dep = pos.deposits[i];
        uint256 timeElapsed = currentTime - dep.depositTime;
        uint256 vestingTime = vestingTiers[dep.tier].period;

        if (timeElapsed >= vestingTime) {
            uint256 rewardAmount = (dep.amount * dep.rewardBps) / 10000;
            totalRewards += rewardAmount;
        }
    }

    return totalRewards;
}
```

*Caption: `withdraw` recomputes `getPendingRewards` for the full position on each call and transfers `_amount + rewardAmount`, without subtracting previously distributed rewards per deposit.*  

The core properties of this logic are:

- `getPendingRewards(wallet)` computes rewards solely from the current `positions[wallet].deposits`, for all deposits whose vesting period has elapsed.  
- `withdraw(_amount)` calls `_updatePosition` to decrease principal (`totalAmount`) and potentially drop deposits, **after** computing `rewardAmount`.  
- `userRewardsDistributed[wallet]` and `totalRewardsDistributed` are incremented but **not** used as inputs to any subsequent reward calculation.  

Consequences:

- For a fully vested position, the first `withdraw(_amount)` call for a given wallet transfers `_amount + full_reward`.  
- Subsequent calls with smaller `_amount` values can still yield **the same full reward** as long as the remaining deposits are fully vested and non‑zero.  
- If a helper repeatedly calls `withdraw(1)` for a wallet whose full position has vested, each call can transfer an additional full reward amount plus 1 unit of principal, allowing repeated extraction of the same reward.

This behavior is exactly what is observed in the seed claim trace and balance diff.

### Front‑End and Delegatecall Helpers

The adversary controls a front‑end at `0xfa3925…` that uses `DELEGATECALL` to route user‑facing functions (`deposit` and `claim`) into helper logic contracts. Bytecode and decompiler output show:

- A fallback dispatcher that copies calldata and performs `DELEGATECALL`.  
- Admin‑style functions that compare `CALLER` to an owner address stored in contract storage.  
- No `ORIGIN` usage and no gating on arbitrary msg.sender beyond owner checks in admin paths.

#### Deposit Helper (0x943c…)

Decompiled code for `0x943c…` indicates:

- A `deposit(uint256, uint8)` function, selector `0x654cfdff`.  
- `require(msg.sender == address(store_a))`, enforcing that only the configured front‑end owner can invoke this logic.  
- Calls to SorraV2 `balanceOf(address(this))`, then `approve(sorraStaking, balance)`, then `sorraStaking.deposit(balance, tier)`.

This matches the deposit trace for tx `0x72a25227…` and explains how the large position for `0xfa3925…` is established.

#### Claim / Withdraw Helper (0xb575…)

Decompiled code for `0xb575…` contains:

- An entrypoint used via selector `0x71baa1af` from the front‑end (a claim‑like function).  
- A `withdraw()` function that requires `msg.sender == address(store_a)` and then calls into `sorraStaking`.

The relevant snippet around repeated withdraw calls:

```solidity
function withdraw() public {
    require(msg.sender == (address(store_a)));
    // ...
    uint256 var_u = (var_t / 0x0de0b6b3a7640000) * 0x0de0b6b3a7640000;
    require(address(0x5d16b8ba2a9a4eca6126635a6ffbf05b52727d50).code.length);
    (bool success, bytes memory ret0) =
        address(0x5d16b8ba2a9a4eca6126635a6ffbf05b52727d50).withdraw(var_u);
    // ...
}
```

*Caption: Helper 0xb575… computes a withdrawal amount and calls `sorraStaking.withdraw(var_u)` from within the front‑end’s context; in the trace this manifests as repeated `withdraw(1)` calls.*  

Combined with the seed claim trace, this shows that the helper repeatedly issues `withdraw(1)` for the same fully vested position, leveraging the staking contract’s accounting bug.

### On‑Chain Evidence of the Bug

From the balance diff for claim tx `0x6439d63c…`:

- `sorraStaking` (`0x5d16…7d50`) loses `3,071,721,792,764,835,962,145,225` SOR tokens.  
- The SOR‑WETH pair (`0xa15c49…`) and other addresses see inflows consistent with swaps.  
- The adversary EOA `0xdc8076…` gains `4,693,714,741,705,678,851` wei of ETH.  

These numbers match the repeated withdrawals and reward transfers observed in the trace and confirm that the buggy accounting is realized on‑chain as a large net token and ETH movement.

## Adversary Flow Analysis

### Key Entities

- **Adversary EOA:** `0xdc8076c21365a93aac0850b67e4ca5fdec5fab9b` (unprivileged externally owned account).  
- **Front‑end contract:** `0xfa39257c629f9a5da2c0559debe2011eef7c1e9f` (unverified, owner‑controlled router using `DELEGATECALL`).  
- **Deposit helper:** `0x943cd9f36374e0ef733213e23f4fd8a37c4f207e` (unverified delegatecall target for `deposit`).  
- **Claim/withdraw helper:** `0xb575b2599b9dcf242bb9dca60dc2ad36a1ca8cd7` (unverified delegatecall target for `claim` / withdraw).  
- **Victim staking contract:** `sorraStaking` at `0x5d16b8ba2a9a4eca6126635a6ffbf05b52727d50` (verified).  
- **SorraV2 token:** `0xe021baa5b70c62a9ab2468490d3f8ce0afdd88df` (verified).  
- **SOR‑WETH Uniswap V2 pair:** `0xa15c4914be0b454b0b7c27b4839a4a01da8ed308`.  

### Lifecycle Stages

#### 1. Front‑End Deployment and Funding

- EOA `0xdc8076…` receives ETH from funding address `0x5ad095de83693ba063941f2f2c5a0df02383b651`.  
- Using this funding, `0xdc8076…` deploys the front‑end contract at `0xfa3925…`.  
- Txlists for `0xdc8076…` and `0xfa3925…` over blocks `21400000–21600000` show deployment transactions and initial interactions.

Effect: The adversary establishes a contract surface (`0xfa3925…`) that can route user‑facing calls into helper logic via `DELEGATECALL`, with ownership stored on‑chain and controlled by `0xdc8076…`.

#### 2. SorraV2 Acquisition and Staking Deposit

- In tx `0xa6f056f2…`, `0xdc8076…` uses aggregator and `UniswapV2Router02` (`0x7a250d56…`) to acquire SorraV2, which ends up held by the front‑end (`0xfa3925…`).  
- In the seed deposit tx `0x72a25227…`, `0xdc8076…` calls `0xfa3925…::deposit(100000000000000000000000, 0)`.  
  - Front‑end delegates into helper `0x943c…`.  
  - Helper reads SorraV2 balance, approves `sorraStaking`, and calls `sorraStaking::deposit(122868871710593438486048, 0)`.  
  - `sorraStaking` transfers SorraV2 from `0xfa3925…` to itself and records a new `Deposit` for `0xfa3925…` in tier 0.  

Effect: A large SorraV2 position for `0xfa3925…` is created and begins vesting. This position later becomes fully vested and forms the basis for repeated reward withdrawals.

#### 3. Repeated‑Withdrawal Exploit and Token Dumping

Four key claim transactions implement the exploit pattern:

- `0x6439d63c…` (block `21550968`) – initial profit‑taking claim.  
- `0x03ddae63fc15519b09d716b038b2685f4c64078c5ea0aa71c16828a089e907fd` (block `21550970`).  
- `0xf1a494239af59cd4c1d649a1510f0beab8bb78c62f31e390ba161eb2c29fbf8b` (block `21550971`).  
- `0x09b26b87a91c7aea3db05cfcf3718c827eba58c0da1f2bf481505e0c8dc0766b` (block `21550972`).  

In each claim tx:

- EOA `0xdc8076…` calls `0xfa3925…` with selector `0x71baa1af` (claim) and small `_amount` parameters (e.g., 500, 700, 800, 500) plus small ETH values (0.1, 0.1, 0.1, 0.05).  
- Front‑end delegates into helper `0xb575…`.  
- Helper uses the front‑end’s state to issue multiple `sorraStaking::withdraw(1)` calls for user `0xfa3925…`.  
- Each `withdraw(1)` call recomputes `getPendingRewards(0xfa3925…)` and transfers `1 + reward` SorraV2 from `sorraStaking` to `0xfa3925…`, emitting `Withdraw` and `RewardDistributed`.  
- `0xfa3925…` then approves `UniswapV2Router02` and sells the drained SOR via the SOR‑WETH pair, routing proceeds to EOA `0xdc8076…` and protocol fee addresses.  

For tx `0x6439d63c…` alone, the balance diff shows:

- SorraV2 balance of `sorraStaking` decreases by `3,071,721,792,764,835,962,145,225` tokens.  
- The SOR‑WETH pair and SorraV2 contract treasury/op addresses receive flows consistent with swaps and fees.  
- EOA `0xdc8076…` gains `4,693,714,741,705,678,851` wei in ETH net.

Effect: The adversary realizes large ETH profit and significantly reduces SorraV2 reserves in `sorraStaking`. The three follow‑up claim txs repeat the same pattern, further draining the pool, though their individual balance diffs are not fully aggregated in this report.

#### 4. Post‑Exploit Fund Movements

After the repeated‑withdrawal exploit, `0xdc8076…` sends transactions to other contracts (including privacy‑oriented or DeFi protocols such as addresses with functions like `deposit(address _tornado, bytes32 _commitment, bytes _encryptedNote)`), dispersing or obfuscating ETH proceeds.  

Txlists over blocks `21400000–21600000` show subsequent `deposit` and related calls from `0xdc8076…`, consistent with typical post‑exploit fund handling.

## Impact & Losses

### Token‑Level Loss

For claim tx `0x6439d63c…`:

- `sorraStaking` loses exactly `3,071,721,792,764,835,962,145,225` SOR tokens according to `erc20_balance_deltas` in the prestateTracer‑based balance diff.  
- These SOR tokens flow from `sorraStaking` into the SOR‑WETH pair and are sold for WETH/ETH, then routed to the adversary EOA and various fee recipients.  

The `total_loss_overview` in the structured analysis reflects a minimum SOR loss of `3071721792764835962145225` tokens, corresponding to this first claim tx. The three subsequent claim transactions follow the same repeated‑withdrawal and swap pattern, further reducing SorraV2 reserves in `sorraStaking` and impairing the ability of other stakers to receive rewards from existing pools.

### Profit in ETH

For tx `0x6439d63c…`, the adversary’s ETH profit is quantified as:

- **ETH delta:** `+4,693,714,741,705,678,851` wei (`~4.6937` ETH).  

This is calculated directly from `native_balance_deltas` for address `0xdc8076…` in the balance diff. The analysis does not compute a gas‑adjusted multi‑tx aggregate across all four claim transactions, but the first claim alone provides clear evidence of positive ETH profit.

### Systemic and User Impact

- The sorraStaking pool’s SOR reserves are materially reduced by the exploit, directly harming the solvency of the reward pool.  
- Remaining stakers face a reduced pool from which future principal and rewards must be paid, impairing returns compared to the intended schedule.  
- The vulnerability is generic to SorraV2 staking logic: any user with a fully vested position and the ability to call `withdraw` repeatedly can realize repeated rewards, meaning the bug is not limited to the adversary’s front‑end.  
- The incident undermines trust in SorraV2’s staking product and increases risk for participants relying on its reward accrual logic.

## ACT Judgment and Exploitability

The ACT assessment is affirmative:

- **Availability:**  
  - `sorraStaking.deposit` and `sorraStaking.withdraw` are publicly callable functions.  
  - The SOR‑WETH pair (`0xa15c49…`) is active and liquid enough to convert drained SOR into ETH.  
  - Anyone can deploy helper or front‑end contracts similar to `0xfa3925…`, `0x943c…`, and `0xb575…`, or call `sorraStaking` directly.

- **Control:**  
  - The vulnerability arises from the staking contract’s own accounting design, not from a misconfiguration unique to the adversary.  
  - Any unprivileged account that controls a fully vested SOR position in `sorraStaking` can repeatedly call `withdraw` in small increments and realize multiple reward payments.

- **Targeting:**  
  - The victim is the global SOR staking pool and its participants, as `sorraStaking` represents a shared reward pool whose reserves can be drained through repeated withdrawals.  
  - The adversary’s specific implementation (front‑end + helpers) is one instantiation of a broader ACT opportunity inherent to the protocol.

Given this, the root cause and exploit path define a real, repeatable ACT opportunity that remains valid for any staker until the staking contract is upgraded or deposits are withdrawn and the pool is closed.

## Recommended Mitigations

To close the vulnerability and prevent repeated reward withdrawals:

1. **Track Per‑Deposit Reward Consumption**  
   - Introduce accounting that tracks, per deposit, how much reward has been realized so far.  
   - Ensure `getPendingRewards` and `withdraw` only return the incremental reward since the last withdrawal for each deposit.  
   - Alternatively, restructure the model so rewards are realized once per deposit at full vesting and are then marked as consumed.

2. **Re‑Architect Withdraw Logic**  
   - Recompute rewards based on a global accumulator (e.g., `rewardPerToken`) combined with per‑user snapshots, rather than per‑deposit loops, so that rewards are strictly additive and cannot be re‑earned by repeated calls.  
   - Use standard, battle‑tested staking patterns (e.g., single‑sided reward per token models) where cumulative rewards are monotonic and each user’s claim can't exceed the global accrual allocated to that address.

3. **Audit and Patch Existing Deployments**  
   - Deploy an upgraded version of `sorraStaking` with corrected accounting, and migrate user positions.  
   - Disable or restrict withdrawals in the vulnerable contract once a safe migration path exists, to prevent further repeated‑withdraw exploitation.

4. **Monitoring and Alerting**  
   - Add on‑chain or off‑chain monitoring for patterns such as:  
     - Multiple `Withdraw` and `RewardDistributed` events for the same address within a single transaction.  
     - Large SorraV2 outflows from `sorraStaking` followed by immediate large swaps via SOR‑WETH.  
   - Use these signals to trigger incident response and, if possible, pause mechanisms in future designs.

## References

- sorraStaking.sol source code (staking contract `0x5d16…7d50`).  
- SorraV2.sol source code (token `0xe021…88df`, including treasury and op addresses).  
- Deposit tx `0x72a25227…` trace and metadata (position creation).  
- Claim tx `0x6439d63c…` trace and balance diff (repeated withdrawals and ETH profit).  
- Address txlists and internal txlists for adversary EOA `0xdc8076…` and front‑end contract `0xfa3925…` (lifecycle and post‑exploit movement).  

