## Incident Overview & TL;DR

### High-Level Summary

On Ethereum mainnet, an unprivileged externally owned account (EOA) `0x8149f77504007450711023cf0ec11bdd6348401f` exploited a logic bug in the `R0ARStaking` contract to drain the contract’s entire pool of staking LP tokens and reward tokens in a single emergency withdrawal.

The vulnerable contract, `R0ARStaking` at `0xbd2cd71630f2da85399565f6f2b49c9d4ce0e77f`, holds:

- The staking asset: the `R0AR/WETH` Uniswap V2 LP token at `0x13028e6b95520ad16898396667d1e52cb5e550ac`.
- The reward asset: `ONE_R0AR_Token` (symbol `1R0R`) at `0xb0415d55f2c87b7f99285848bd341c367feac1ea`.

By first depositing a small amount of LP tokens and then invoking `EmergencyWithdraw(0)`, the attacker caused `R0ARStaking` to transfer its entire balances of both the LP token and the reward token to the attacker, rather than just the attacker’s own stake and rewards. At least one other user (`0x095781cca3588d935d25dba2029578a368714745`) retained a non‑zero recorded deposit in storage but was left with no backing assets.

### Root Cause Brief

The root cause is a flawed implementation of `EmergencyWithdraw(uint256 _pid)` in `R0ARStaking`. Instead of strictly limiting withdrawals to a user’s own deposited amount plus earned rewards, the function effectively uses the contract’s full token balances as the payout source and lacks any enforcement that the caller is only withdrawing their proportional share. With only a trivially true guard on `user.amount` and no access control, any depositor can invoke `EmergencyWithdraw` to seize all pooled LP and reward tokens, stranding other users’ positions.

---

## Key Background

### Protocol and Contract Roles

- `R0ARStaking` (`0xbd2cd71630f2da85399565f6f2b49c9d4ce0e77f`) is a MasterChef-style staking contract.
- For pool `pid = 0`, the staking asset is the `R0AR/WETH` Uniswap V2 LP token at `0x13028e6b95520ad16898396667d1e52cb5e550ac`.
- Rewards are paid in `ONE_R0AR_Token` (`1R0R`) at `0xb0415d55f2c87b7f99285848bd341c367feac1ea`.

The contract tracks positions per user and pool:

- A `PoolInfo` struct stores, for each pool, the `lpToken` and a set of `rewardPercents`.
- A `UserInfo` struct (per `pid` and `user`) stores an aggregate `amount` of LP tokens and an array of `Deposit` records that track individual deposits, lock-period dependent reward rates, timestamps, and withdrawal status.

Backing assets are held directly in `R0ARStaking`’s own token balances for the LP token and `1R0R`; user accounting is implemented in storage via `userInfo[pid][user]`.

In a correctly designed staking system:

- Deposit and withdrawal functions must only change balances in a way that preserves conservation of value per user.
- Any withdrawal, including emergency withdrawal paths, must not allow a single user to withdraw more than their own recorded stake and accrued rewards.
- Other users’ ability to withdraw must be preserved regardless of a single user’s actions.

---

## Vulnerability & Root Cause Analysis

### Relevant Code in R0ARStaking

The core staking logic is implemented in `Contract.sol` within the verified source for `R0ARStaking`. The deposit function for LP tokens is permissionless and records per‑user deposits:

```solidity
// Collected R0ARStaking source (Contract.sol), deposit implementation
function deposit(uint8 _pid, uint256 _amount) public {
    PoolInfo storage pool = poolInfo[_pid];
    UserInfo storage user = userInfo[_pid][msg.sender];
    if (_amount > 0) {
        pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
        user.amount = user.amount.add(_amount);
        user.deposits.push(Deposit(_pid, _amount, block.timestamp, 0, false));
    }
    emit Deposits(msg.sender, _pid, _amount);
}
```

*Caption: R0ARStaking’s deposit function is public and permissionless and records both an aggregate `user.amount` and a detailed `Deposit` entry for each call.*

The vulnerable emergency withdrawal logic is:

```solidity
// Collected R0ARStaking source (Contract.sol), EmergencyWithdraw implementation
function EmergencyWithdraw(uint256 _pid) public nonReentrant {
    PoolInfo storage pool = poolInfo[_pid];
    UserInfo storage user = userInfo[_pid][msg.sender];
    require(user.amount >= 0, "withdraw: not good");
    uint256 withdrawableAmount;
    uint256 lengths = user.deposits.length;
    uint256 rewardAmount;
    uint256 lastRewardTime = user.deposits[lengths -1].lastRewardTime;
    for (uint256 i = 0; i < lengths; i++) {
        if(user.deposits[i].withdrawn == false){
            user.deposits[i].withdrawn = true;
        }
    }
    if(lastRewardTime != 0){
        rewardAmount += user.amount.div(365 days * 1000).mul(pool.rewardPercents[0]).mul(block.timestamp.sub(lastRewardTime));
    }
    user.deposits[lengths - 1].lastRewardTime = block.timestamp;

    withdrawableAmount = user.amount;
    uint256 r0arTokenBalance = r0arToken.balanceOf(address(this));
    if(rewardAmount > 0) {
        if(r0arTokenBalance < rewardAmount){
            rewardAmount = r0arTokenBalance;
        }
        r0arToken.safeTransfer(address(msg.sender), rewardAmount);
    }

    uint256 lpTokenBalance = pool.lpToken.balanceOf(address(this));
    if(withdrawableAmount > 0) {
        if(lpTokenBalance < withdrawableAmount){
            withdrawableAmount = lpTokenBalance;
        }
        pool.lpToken.safeTransfer(address(msg.sender), withdrawableAmount);
    }
    user.amount = 0;
    emit Withdraw(msg.sender, _pid, withdrawableAmount);
}
```

*Caption: EmergencyWithdraw is permissionless, guarded only by a trivially true `require(user.amount >= 0)`, and pays out based on the contract’s live token balances, with no check that the caller is entitled to the entire pool.*

### Vulnerability Brief

`R0ARStaking`’s `EmergencyWithdraw(uint256 _pid)` function allows any depositor in pool `pid = 0` to withdraw the contract’s entire balances of both the LP token and the reward token instead of only their own stake. Because the function:

- Is public and non‑owner‑gated.
- Uses a trivially satisfied requirement `require(user.amount >= 0, "withdraw: not good")` on an unsigned integer.
- Consults the contract’s token balances (`r0arToken.balanceOf(address(this))` and `pool.lpToken.balanceOf(address(this))`) rather than enforcing strict per‑user limits.

an attacker who has performed a minimal deposit can invoke `EmergencyWithdraw(0)` to trigger a full‑pool drain.

### Detailed Root Cause

Key aspects of the bug:

1. **Trivially True Guard Condition**
   - `require(user.amount >= 0, "withdraw: not good");` is effectively always true because `user.amount` is a `uint256`.
   - This check provides no protection against misuse by accounts with zero or negligible stake.

2. **EmergencyWithdraw Ignores Per-User Entitlement**
   - The function treats the caller’s `user.amount` only as a parameter for reward calculation and as an initial `withdrawableAmount`, then uses the contract’s entire token balances as the binding constraint.
   - For the reward token, the code computes `rewardAmount` from `user.amount` and then caps it at `r0arToken.balanceOf(this)`, ensuring the caller can never receive more than the full reward balance but also not enforcing a proportional limit.
   - For the LP token, the function computes `withdrawableAmount = user.amount` and then caps it using:
     - `lpTokenBalance = pool.lpToken.balanceOf(address(this));`
     - If `lpTokenBalance < withdrawableAmount` it reduces `withdrawableAmount` to `lpTokenBalance`.
   - In the incident’s on-chain behavior, the emergency withdrawal results in the transfer of exactly `lpTokenBalance` and exactly `r0arToken.balanceOf(this)` to the caller, as shown by traces and balance diffs.

3. **No Access Control or Invariant Enforcement**
   - `EmergencyWithdraw` is callable by any account; it is not restricted to an owner role.
   - There is no check that:
     - The caller is withdrawing only their own principal and rewards, or
     - The pool will remain solvent for other users after the call.

4. **Observed On-Chain Consequences**
   - Immediately before the exploit `EmergencyWithdraw`:
     - `R0ARStaking` held `100000000099978913875247186` units of `1R0R`.
     - `R0ARStaking` held `26777446973800063826` LP units of the `R0AR/WETH` pair.
     - The attacker had only just deposited `36000000000000000` LP units.
   - Nonetheless, a single `EmergencyWithdraw(0)` call:
     - Transfers all `100000000099978913875247186` `1R0R` tokens to the attacker.
     - Transfers all `26777446973800063826` LP units to the attacker.
     - Leaves `R0ARStaking` with zero balances of both tokens.

The combination of (a) permissionless access, (b) ineffective guard logic, and (c) using full contract balances as the payout source rather than strictly bounded per‑user entitlements enables any depositor to unilaterally seize all pooled assets and strand all other users’ recorded deposits.

### Exploit Conditions

For the exploit to succeed, the following conditions hold (and are satisfied in the observed incident):

- The attacker can obtain a small positive balance of the `R0AR/WETH` LP token and approve `R0ARStaking` to transfer it.
- `R0ARStaking` already holds non‑zero balances of the LP token and `1R0R` (from prior user deposits and reward funding).
- At least one other user besides the attacker has a non‑zero recorded deposit in `userInfo[0][u]`, so draining the pool will leave their position stranded.
- `EmergencyWithdraw(uint256 _pid)` is callable by any depositor and remains unmodified and unabrogated.

### Security Principles Violated

The design violates key security expectations:

- **Separation of per-user accounting and global pool balances**: The contract fails to enforce that withdrawals are limited to a caller’s own recorded stake and rewards.
- **Least privilege for user actions**: A regular user-level function (`EmergencyWithdraw`) effectively acts as a global drain function over all pool assets without role‑based restriction.
- **Conservation of value per user**: Other users’ recorded deposits remain in storage but are no longer backed by assets, breaking the invariant that each user’s recorded claim is redeemable.

---

## ACT Opportunity and Exploit Predicate

### Pre-State σ_B (Block Height B)

The ACT opportunity is defined relative to a pre‑state `σ_B` at Ethereum mainnet block `B = 22278559`, immediately before block `22278560`. In this state:

- `R0ARStaking` at `0xbd2c...77f` holds:
  - The pooled `R0AR/WETH` Uniswap V2 LP tokens, including deposits from prior users.
  - A large balance of `ONE_R0AR_Token` rewards.
- There is at least one outstanding user position:
  - User `0x095781cca3588d935d25dba2029578a368714745` has previously deposited into pool `pid = 0` and has a non‑zero recorded amount in `userInfo[0][u]`.
- The adversary EOA `0x8149f77504007450711023cf0ec11bdd6348401f` controls some ETH and ERC20 balances but has not yet interacted with `R0ARStaking`.

Evidence supporting this characterization includes:

- The historical transaction list for `R0ARStaking` and the attacker EOA, which shows user `0x0957...4745` depositing into `R0ARStaking` at block `22249716` and no subsequent withdrawals from that address before the exploit.
- Seed metadata and prestate diffs around the exploit transaction `0xab2097bb...`, demonstrating that `R0ARStaking` holds a large `1R0R` balance and all LP tokens backing the pool, while the attacker EOA is alive and funded.

### Transaction Sequence b

From `σ_B`, there exists a public transaction sequence `b` on chainid `1`:

1. **Attacker deposit into R0ARStaking**
   - **Tx**: `0xb9d27d12802f125151291cc2f9777c4b1e39fd9758f0b1de38e66f23ee092d15`
   - **Type**: adversary‑crafted
   - **Mechanism**: `R0ARStaking.deposit(uint8 pid, uint256 amount)` with `pid = 0` and `amount = 36000000000000000` LP units.
   - **Inclusion feasibility**: `deposit` is a public, permissionless function. From `σ_B`, an unprivileged EOA can:
     - Acquire a small amount of the LP token `0x1302...50ac` via public DEXes.
     - Approve `R0ARStaking` as a spender.
     - Submit a standard Ethereum transaction calling `deposit(0, 36000000000000000)`.
   - **Effect**: Creates `userInfo[0][0x8149...]` with `amount = 36000000000000000` LP units, while the pool already holds approximately `26741446973800063826` LP units from prior users.

2. **Attacker emergency withdrawal from R0ARStaking**
   - **Tx**: `0xab2097bb3ce666493d0f76179f7206926adc8cec4ba16e88aed30c202d70c661`
   - **Type**: adversary‑crafted
   - **Mechanism**: `R0ARStaking.EmergencyWithdraw(uint256 _pid)` with `_pid = 0`.
   - **Inclusion feasibility**: `EmergencyWithdraw` is a public, non‑owner function guarded only by `require(user.amount >= 0)` and `ReentrancyGuard`. Any EOA that has deposited into pool `pid = 0` can send a standard Ethereum transaction invoking `EmergencyWithdraw(0)`; no private infrastructure or privileged role is required.
   - **Effect**: Deterministically transfers the staking contract’s entire holdings of:
     - `100000000099978913875247186` units of `ONE_R0AR_Token`, and
     - `26777446973800063826` units of `R0AR/WETH` LP tokens
     to the attacker EOA `0x8149...`, emitting `Withdraw(user=0x8149..., pid=0, amount=26777446973800063826)` and leaving `R0ARStaking` with zero balances of both tokens.

### Exploit Predicate

The ACT exploit predicate is defined in non‑monetary terms, focusing on pool solvency and user withdrawability.

#### Profit Component (Non-Monetary Context)

- **Reference asset**: `other` (no specific monetary reference asset is used).
- **Adversary address**: `0x8149f77504007450711023cf0ec11bdd6348401f`.
- **Fees, initial value, final value, value delta**: recorded as `"unknown"` in a specific reference asset because precise pricing for `1R0R` and the LP token at the relevant block is not available.
- **Valuation notes**:
  - Traces show `0x8149...` converting substantial amounts of drained `1R0R` and LP tokens into WETH/ETH via public routers and aggregators shortly after the drain.
  - Nothing in the evidence indicates a net loss for the attacker, but the analysis does not rely on a quantified monetary profit.
  - The ACT opportunity is instead established via a concrete non‑monetary predicate expressing broken withdrawability for other users.

#### Non-Monetary Predicate

- **Oracle name**: `R0ARStaking pool solvency and user withdrawability`.
- **Oracle definition**:

  Define `O(σ_B, σ') = 1` if, after executing the transaction sequence `b` from pre‑state `σ_B` to post‑state `σ'`, there exists at least one address `u ≠ 0x8149...401f` such that:

  - `userInfo[0][u].amount > 0` in `R0ARStaking` storage, and
  - `poolInfo[0].lpToken.balanceOf(R0ARStaking) = 0`.

  In other words, at least one user has a non‑zero recorded staking position while the pool holds no LP tokens to honor withdrawals, so that user’s principal is effectively unrecoverable.

- **Oracle evidence**:
  - `R0ARStaking`’s transaction history shows user `0x095781cca3588d935d25dba2029578a368714745` depositing `26523660243998956948` LP units into pool `pid = 0` via transaction `0x2d4f4d5bed7ea7f24eb10acadafc01952b240ee2c5225a9652f672d6beb65b89` at block `22249716`, calling `deposit(0, 0x17016f876aab55d94)` which decodes to exactly `26523660243998956948`.
  - No subsequent `withdraw` or `EmergencyWithdraw` calls from this user exist in the staking contract’s transaction list up to block `22278565`, implying they retain a non‑zero recorded deposit at the time the attacker drains the pool.
  - The pre‑ and post‑state differences and traces for the exploit transaction `0xab2097bb...` show:
    - `R0ARStaking`’s LP and `1R0R` balances drop from large positive values to zero.
    - The attacker’s balances increase accordingly.
    - Storage associated with user deposits remains non‑zero, confirming at least one other user with a stranded position.

---

## Adversary Flow Analysis

### Adversary Strategy Summary

The adversary executes a short, deterministic sequence on Ethereum mainnet:

1. Fund the EOA `0x8149...` with ETH for gas and initial capital.
2. Acquire and deposit a small amount of `R0AR/WETH` LP tokens into `R0ARStaking`.
3. Call `EmergencyWithdraw(0)` to drain all LP and reward tokens from the pool into the EOA.
4. Perform follow‑up swaps through public routers and aggregators to convert the stolen tokens into WETH/ETH and other more liquid assets.

### Adversary-Related Accounts

#### Adversary Cluster

- **Attacker EOA**
  - Chain: Ethereum mainnet (chainid `1`).
  - Address: `0x8149f77504007450711023cf0ec11bdd6348401f`.
  - `is_eoa`: `"true"`, `is_contract`: `"false"`.
  - Justification: Sender of the attacker‑crafted deposit (`0xb9d27d12...`) and `EmergencyWithdraw` (`0xab2097bb...`) transactions, direct recipient of all drained LP and `1R0R` balances and subsequent swap proceeds, as shown by traces and balance diffs.

#### Victim and Stakeholder Accounts

- **R0ARStaking staking contract**
  - Name: `R0ARStaking`.
  - Chain: Ethereum mainnet (`1`).
  - Address: `0xbd2cd71630f2da85399565f6f2b49c9d4ce0e77f`.
  - `is_verified`: `"true"` (source collected and compiled locally).

- **Reward token**
  - Name: `ONE_R0AR_Token (1R0R)`.
  - Chain: Ethereum mainnet (`1`).
  - Address: `0xb0415d55f2c87b7f99285848bd341c367feac1ea`.
  - `is_verified`: `"true"`.

- **LP token**
  - Name: `R0AR/WETH` Uniswap V2 LP pair.
  - Chain: Ethereum mainnet (`1`).
  - Address: `0x13028e6b95520ad16898396667d1e52cb5e550ac`.
  - `is_verified`: `"true"`.

- **Other depositor**
  - Name: `User depositor 0x0957...4745`.
  - Chain: Ethereum mainnet (`1`).
  - Address: `0x095781cca3588d935d25dba2029578a368714745`.
  - `is_verified`: `"unknown"` (EOA, but serves as a concrete victim for the non‑monetary exploit predicate).

### Adversary Lifecycle Stages

#### 1. Initial Funding

- **Stage name**: Adversary initial funding.
- **Tx**: `0x72fbd1c5d5b169ae4af091f5927cb5c8ddf6f85466b75aaaea34d7a123c53b1c`.
- **Block**: `22257934`.
- **Mechanism**: ETH transfer.
- **Effect**: EOA `0x8149...` receives `0.02` ETH from `0xe5438cda...`, providing gas and initial capital for subsequent interactions.
- **Evidence**: Normal transaction history for `0x8149...` showing the incoming transfer.

#### 2. Staking Deposit into R0ARStaking

- **Stage name**: Adversary staking deposit into R0ARStaking.
- **Tx**: `0xb9d27d12802f125151291cc2f9777c4b1e39fd9758f0b1de38e66f23ee092d15`.
- **Block**: `22278560`.
- **Mechanism**: `deposit(uint8 category_, uint256 amount_)`.

Trace excerpt:

```text
// Seed-style trace for attacker deposit 0xb9d27d12...
R0ARStaking::deposit(0, 36000000000000000)
  ├─ UniswapV2Pair::transferFrom(0x8149..., R0ARStaking: 0xbd2c..., 36000000000000000)
  │   ├─ emit Transfer(from: 0x8149..., to: R0ARStaking: 0xbd2c..., value: 36000000000000000)
  ├─ emit Deposits(user: 0x8149..., pid: 0, amount: 36000000000000000)
```

*Caption: The attacker deposits `3.6e16` LP units into `R0ARStaking` pool `pid = 0`, increasing the contract’s LP balance and creating a userInfo entry for the attacker.*

Balance diff excerpt:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x13028e6b95520ad16898396667d1e52cb5e550ac",
      "holder": "0x8149f77504007450711023cf0ec11bdd6348401f",
      "before": "376710205283016328",
      "after": "340710205283016328",
      "delta": "-36000000000000000"
    },
    {
      "token": "0x13028e6b95520ad16898396667d1e52cb5e550ac",
      "holder": "0xbd2cd71630f2da85399565f6f2b49c9d4ce0e77f",
      "before": "26741446973800063826",
      "after": "26777446973800063826",
      "delta": "36000000000000000"
    }
  ]
}
```

*Caption: The deposit moves `3.6e16` LP units from the attacker to `R0ARStaking`, increasing the contract’s LP balance while only a small fraction of the pool is attacker-contributed.*

#### 3. Execution of EmergencyWithdraw Exploit

- **Stage name**: Adversary executes EmergencyWithdraw exploit.
- **Tx**: `0xab2097bb3ce666493d0f76179f7206926adc8cec4ba16e88aed30c202d70c661`.
- **Block**: `22278565`.
- **Mechanism**: `EmergencyWithdraw(0)`.

Trace excerpt:

```text
// Seed transaction trace for EmergencyWithdraw 0xab2097bb...
R0ARStaking::EmergencyWithdraw(0)
  ├─ ONE_R0AR_Token::balanceOf(R0ARStaking: 0xbd2c...) → 100000000099978913875247186
  ├─ ONE_R0AR_Token::transfer(0x8149..., 100000000099978913875247186)
  │   ├─ emit Transfer(from: R0ARStaking: 0xbd2c..., to: 0x8149..., value: 100000000099978913875247186)
  ├─ UniswapV2Pair::balanceOf(R0ARStaking: 0xbd2c...) → 26777446973800063826
  ├─ UniswapV2Pair::transfer(0x8149..., 26777446973800063826)
  │   ├─ emit Transfer(from: R0ARStaking: 0xbd2c..., to: 0x8149..., value: 26777446973800063826)
  ├─ emit Withdraw(user: 0x8149..., pid: 0, amount: 26777446973800063826)
```

*Caption: EmergencyWithdraw(0) transfers exactly the staking contract’s full balances of both `1R0R` and LP tokens to the attacker and emits a `Withdraw` event for the full LP amount.*

Balance diff excerpt:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0xb0415d55f2c87b7f99285848bd341c367feac1ea",
      "holder": "0xbd2cd71630f2da85399565f6f2b49c9d4ce0e77f",
      "before": "100000000099978913875247186",
      "after": "0",
      "delta": "-100000000099978913875247186"
    },
    {
      "token": "0xb0415d55f2c87b7f99285848bd341c367feac1ea",
      "holder": "0x8149f77504007450711023cf0ec11bdd6348401f",
      "before": "958904109",
      "after": "100000000099978914834151295",
      "delta": "100000000099978913875247186"
    },
    {
      "token": "0x13028e6b95520ad16898396667d1e52cb5e550ac",
      "holder": "0xbd2cd71630f2da85399565f6f2b49c9d4ce0e77f",
      "before": "26777446973800063826",
      "after": "0",
      "delta": "-26777446973800063826"
    },
    {
      "token": "0x13028e6b95520ad16898396667d1e52cb5e550ac",
      "holder": "0x8149f77504007450711023cf0ec11bdd6348401f",
      "before": "340710205283016328",
      "after": "27118157179083080154",
      "delta": "26777446973800063826"
    }
  ]
}
```

*Caption: After EmergencyWithdraw, `R0ARStaking` holds zero `1R0R` and zero LP tokens; all such balances are consolidated under the attacker EOA.*

Prestate diff excerpt:

```json
{
  "post": {
    "0x13028e6b95520ad16898396667d1e52cb5e550ac": {
      "storage": {
        "0x6f7e...7804": "0x00000000000000000000000000000000000000000000000178570c46b674c1da"
      }
    },
    "0xb0415d55f2c87b7f99285848bd341c367feac1ea": {
      "storage": {
        "0x6f7e...7804": "0x00000000000000000000000000000000000000000052b7d2de2b3f1dfbb7f77f"
      }
    }
  }
}
```

*Caption: The prestate and poststate diffs for the exploit transaction confirm that the attacker’s token storage slots increase while the staking contract’s LP and `1R0R` holdings are zeroed.*

As of the post‑exploit state, at least one other depositor (`0x0957...4745`) still has a non‑zero recorded deposit but no backing assets exist in the contract, fulfilling the non‑monetary exploit predicate.

#### 4. Post-Drain Swaps and Profit Realization

- **Stage name**: Adversary post‑drain swaps and profit realization.
- **Primary txs**:
  - `0xf89715ae8b17443eb76d45a6e6640f251cc109057360648848f2c782d8c1a70c` (block `22278577`) – aggregator/DEX swap.
  - `0x64e3631e5bf8a684921677f266509615f9c969327678ba58be857ac9f7d0f520` (block `22278598`) – liquidity removal via router.
- **Mechanisms**:
  - Interactions with:
    - A router/aggregator at `0x7bfbb34b28f3d5e54aeb28e70bec655a23cee1e1`.
    - UniswapV2Router02 at `0x7a250d5630b4cf539739df2c5dacb4c659f2488d`.
    - Another router at `0xac4c6e212a361c968f1725b4d055b47e63f80b75`.
- **Effect**:
  - `0x8149...` swaps large amounts of `1R0R` and LP tokens for WETH/ETH and possibly other assets, consolidating value into more liquid tokens under the same EOA.

Trace excerpts (illustrative):

```text
// Aggregator swap tx 0xf89715ae...
0x8149... → Aggregator/Router (0x7bfb...)
  ├─ Swaps drained 1R0R and/or intermediate tokens into WETH/ETH via paths including UniswapV2 pairs.

// Liquidity removal tx 0x64e3631e...
0x8149... → UniswapV2Router02 (0x7a25...)
  ├─ removeLiquidityETH for the R0AR/WETH LP pair
  ├─ Receives ETH and R0AR (or routed equivalents) back to the attacker.
```

*Caption: Post‑drain swaps convert the drained `1R0R` and LP tokens into WETH/ETH and other liquid assets under the attacker’s control.*

---

## Impact & Losses

### Token Loss Overview

From the victim contract’s perspective, the exploit results in:

- **`ONE_R0AR_Token` (`1R0R`)**
  - Amount drained: `100000000099978913875247186`.

- **`R0AR/WETH` Uniswap V2 LP token**
  - Amount drained: `26777446973800063826` LP units.

These amounts are entirely transferred from `R0ARStaking` to the attacker EOA `0x8149...` in the single exploit `EmergencyWithdraw` transaction `0xab2097bb...`.

### Contract-Level Impact

- The entire `1R0R` reward pool held by `R0ARStaking` is transferred out.
- All `R0AR/WETH` LP tokens held by the staking contract are transferred out.
- `R0ARStaking` ends with zero balances of both the LP and reward tokens, rendering the pool effectively insolvent.

### User-Level Impact

- At least one other depositor, `0x0957...4745`, retains a non-zero recorded deposit in `userInfo` for `pid = 0`.
  - Their deposit transaction (`0x2d4f4d5b...`) indicates a deposit of `26523660243998956948` LP units.
  - No withdrawals are recorded for this user prior to the exploit.
- After the exploit:
  - `userInfo[0][0x0957...4745].amount` remains positive in storage.
  - `poolInfo[0].lpToken.balanceOf(R0ARStaking)` is `0`.

This state means:

- Honest participants’ principal is no longer withdrawable, even though their positions remain recorded on‑chain.
- The staking pool is effectively “bricked” from the perspective of non‑attacker users.

The analysis deliberately does not compute an exact net profit in a specific reference asset (such as ETH or USD) due to a lack of reliable off‑chain pricing for `1R0R` and the LP token at block `22278565`. However:

- On‑chain swap traces show `0x8149...` exchanging large amounts of both drained tokens into WETH/ETH immediately after the exploit.
- Nothing in the on‑chain evidence suggests that the attacker incurs a net loss.

The exploit is thus well‑captured by the non‑monetary predicate: other users’ recorded deposits become unrecoverable while the attacker captures all pool assets.

---

## All Relevant Transactions

The following transactions are relevant to the incident and analysis:

- **Seed / Exploit Transaction**
  - Chainid: `1`
  - Txhash: `0xab2097bb3ce666493d0f76179f7206926adc8cec4ba16e88aed30c202d70c661`
  - Role: `seed` (primary exploit transaction; EmergencyWithdraw drain).

- **Attacker Deposit**
  - Chainid: `1`
  - Txhash: `0xb9d27d12802f125151291cc2f9777c4b1e39fd9758f0b1de38e66f23ee092d15`
  - Role: `adversary-crafted` (attacker’s staking deposit).

- **Related Transaction**
  - Chainid: `1`
  - Txhash: `0x73daa36bdb49c20a13d0f644264b07b853067848c163b578f7b313db1558439d`
  - Role: `related` (contextual activity around the exploit).

- **Post-Drain Swaps**
  - Chainid: `1`
  - Txhash: `0xf89715ae8b17443eb76d45a6e6640f251cc109057360648848f2c782d8c1a70c`
  - Role: `related` (aggregator swap converting drained tokens).
  - Chainid: `1`
  - Txhash: `0x64e3631e5bf8a684921677f266509615f9c969327678ba58be857ac9f7d0f520`
  - Role: `related` (liquidity removal and further conversion of drained assets).

- **Victim Depositor Transaction**
  - Chainid: `1`
  - Txhash: `0x2d4f4d5bed7ea7f24eb10acadafc01952b240ee2c5225a9652f672d6beb65b89`
  - Role: `victim-observed` (user `0x0957...4745` depositing substantial LP tokens into `R0ARStaking` before the exploit).

---

## References

Key artifacts and references used in the analysis:

1. **Seed EmergencyWithdraw transaction trace (`0xab2097bb...`)**
   - Detailed execution trace (cast `run -vvvvv`) showing `EmergencyWithdraw(0)` transferring the full `1R0R` and `R0AR/WETH` LP balances from `R0ARStaking` to `0x8149...`.

2. **R0ARStaking verified source (`Contract.sol`)**
   - Collected and compiled contract source code for `R0ARStaking`, including the implementations of `deposit`, `withdraw`, `EmergencyWithdraw`, `pendingR0AR`, and `harvest`.

3. **Attacker deposit and balance diffs (`0xb9d27d12...`)**
   - Trace and balance diff artifacts confirming the attacker’s `deposit(0, 36000000000000000)` LP into `R0ARStaking` and the resulting LP balance change.

4. **R0ARStaking address transaction history with other depositor `0x0957...4745`**
   - Contract-level tx history showing `0x0957...4745` depositing `26523660243998956948` LP units via `deposit(0, 0x17016f876aab55d94)` and not withdrawing before the exploit.

5. **Post-drain aggregator and router swap traces (`0xf89715ae...`, `0x64e3631e...`)**
   - Traces and balance diffs for post‑exploit swaps and liquidity removals that convert the drained `1R0R` and LP tokens into WETH/ETH under the attacker’s control.

These artifacts, together with the on-chain state diffs and the verified `R0ARStaking` source, fully support the identified ACT opportunity and the conclusion that a protocol‑level logic bug in `EmergencyWithdraw` is the root cause of the incident.

