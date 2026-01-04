# Locker TokenV2 Reentrancy Drain on Base – Root Cause Report

## 1. Incident Overview TL;DR

On Base (chainid 8453), an unprivileged EOA `0x3cc1...` used an adversary-controlled helper contract `0x0f30a...` to exploit a reentrancy bug in a Locker proxy at `0x80b9...`.  
The helper contract repeatedly over-withdrew `TokenV2` from a pooled balance backing multiple time-locks by reentering `Locker::withdrawLock` during `Locker::splitLock` fee processing.  
The stolen `TokenV2` was swapped for WETH9 and then native ETH via Uniswap, resulting in an exact net profit of `4.304394973266647713` ETH for the adversary after all gas and lock fees.  
This is a permissionless ACT opportunity: it uses only public on-chain state, verified contract code, and standard transactions, and is classified under `root_cause_category = "protocol_bug"` for protocol `Locker / TokenV2 (Base chainid 8453)`.

## 2. Key Background

Locker is deployed as an ERC1967 proxy at `0x80b9c9c883e376c4aa43d72413ab1bd6a64a0654` on Base, with verified implementation `0xd6a7cfa86a41b8f40b8dfeb987582a479eb10693`.  
It manages time-locks of `TokenV2` in a pooled fashion: all `TokenV2` backing multiple lock IDs share a single ERC20 balance rather than isolated per-lock reserves.

`TokenV2` (`0xf3a6...`) is a standard ERC20 upgradeable token used as the locked asset.  
For the locks relevant to this incident:
- Lock `5` is a large `TokenV2` position whose beneficiary is `TokenV2` itself.  
- Lock `6` is a large `TokenV2` position for EOA `0xa691ce2c...`.  
- Lock `11` is an attacker-controlled `TokenV2` lock whose beneficiary is helper contract `0x0f30a...`.  
- Lock `61` is another pooled lock created during the exploit sequence.

Uniswap V3 router `0x2626...e481` and pool `0x5992...3c61` on Base provide a liquid `TokenV2`/WETH9 pair.  
The adversary uses this pool to convert stolen `TokenV2` into WETH9 (`0x4200...0006`) and then into native ETH inside the profit-taking transaction.

The ACT opportunity is defined relative to Base block `B = 24282177`.  
The pre-state `σ_B` is the publicly reconstructible L2 state immediately before adversary-crafted tx `0x01d0df430bb584116e60d4da8f955cc74c472b42f523398146f320b58b7a294d`, including balances for:
- EOA `0x3cc1...`,  
- Locker proxy `0x80b9...`,  
- `TokenV2` `0xf3a6...`,  
- Uniswap router and pool contracts, and  
- treasury Gnosis Safe `0x0977...`.

This pre-state is supported by:
- `artifacts/root_cause/data_collector/iter_1/address/8453/0x3cc1edd8a25c912fcb51d7e61893e737c48cd98d/normal_txs.json`,  
- balance diffs for txs `0x984c...873`, `0x01d0df4...294d`, and `0xb171f1...784`, and  
- the Locker lock snapshots and implementation source:
  - `artifacts/root_cause/data_collector/iter_3/contract/8453/0x80b9...0654/locks_snapshots_0x1728465_0x1728466.json`,  
  - `artifacts/root_cause/data_collector/iter_3/contract/8453/0xd6a7...0693/source/src/Locker.sol`.

## 3. Vulnerability Analysis

### 3.1 Root Cause Summary

The root cause is a reentrancy vulnerability in the Locker implementation.  
`Locker::splitLock` sends ETH to external targets via `_feeHandler` before it has finalized updates to the source lock’s amount and before all associated checks are complete.  
`_feeHandler` forwards fees to the treasury and refunds any excess ETH back to `msg.sender` using low-level calls.  
There is no reentrancy guard on `splitLock` or `withdrawLock`.

The adversary-controlled helper contract invokes `splitLock` on its own lock (id `11`) with parameters that trigger an ETH refund.  
During the refund, the helper reenters `Locker::withdrawLock` on lock `11`.  
Because `locks[11].amount` has not yet been reduced by `splitLock`, each reentrant `withdrawLock` call transfers the full nominal amount of lock `11` in `TokenV2` from the Locker proxy to the helper without decrementing the stored amount at the time of the transfer.  
By iterating this pattern across multiple `splitLock` invocations, the helper induces a sequence of `withdrawLock(11..60)` calls and receives `220627279869879905706908225` `TokenV2` even though the legitimate lock-11 deposit is only `4412545597397598114138189` `TokenV2`.

Because Locker pools all `TokenV2` backing locks `5`, `6`, `11`, and `61` into a single ERC20 balance, the over-withdrawals on the attacker’s lock are silently funded by tokens that should back other users’ locks.  
The contract does not enforce that its `TokenV2` balance is at least the sum of all outstanding `locks[id].amount`, and it does not maintain per-lock reserves, so the undercollateralization remains undetected.

### 3.2 Vulnerable Components

The vulnerable on-chain components are:
- Locker ERC1967 proxy at `0x80b9c9c883e376c4aa43d72413ab1bd6a64a0654` with implementation `0xd6a7cfa86a41b8f40b8dfeb987582a479eb10693`, specifically:
  - `splitLock`,  
  - `withdrawLock`, and  
  - their interaction with `_feeHandler`.  
- Pooled `TokenV2` accounting in Locker, which holds one `TokenV2` balance for multiple locks instead of isolating per-lock reserves or enforcing a strict `balance >= sum(locks[id].amount)` invariant.

### 3.3 ACT Exploit Conditions

The ACT opportunity requires the following conditions (all satisfied on Base at block `B`):
- `Locker::_feeHandler` must perform external ETH transfers (to treasury and `msg.sender`) before `splitLock` finishes updating lock state, and neither `splitLock` nor `withdrawLock` may be protected by a reentrancy guard.  
- At least one adversary-controlled lock (id `11`) must have a large `TokenV2` amount so that repeated reentrant `withdrawLock` calls are profitable after gas and fee costs.  
- The Locker must pool `TokenV2` backing multiple locks so that tokens belonging to other locks (notably ids `5` and `6`) can fund over-withdrawals on the adversary’s lock without immediate failure.  
- A liquid `TokenV2`/WETH9 market must exist (Uniswap V3 pool `0x5992...3c61`) so that the adversary can convert stolen `TokenV2` into WETH9 and then native ETH within the same transaction sequence.

### 3.4 Security Principles Violated

The design violates several standard security principles:
- **Checks-effects-interactions** – `splitLock` performs external ETH transfers via `_feeHandler` (interactions) before fully applying lock state updates (effects), opening a reentrancy window.  
- **Reentrancy protection** – neither `splitLock` nor `withdrawLock` is protected by a reentrancy guard, even though they move ERC20 balances and rely on internal accounting invariants.  
- **Balance invariants** – the contract does not maintain or enforce that its `TokenV2` balance is at least the sum of all outstanding lock amounts, so pooled undercollateralization created by reentrant withdrawals is not prevented or detected.

### 3.5 Code Evidence (Locker.sol)

The vulnerable logic appears directly in the verified Locker implementation source.

**Snippet 1 – splitLock and _feeHandler (Locker.sol, implementation 0xd6a7...0693):**

```solidity
function splitLock(uint256 _id, uint256 _newAmount, uint256 _newUnlockTime) external payable whenNotPaused returns (uint256 _splitId) {
    Lock storage _lock = locks[_id];
    require(!_lock.withdrawn, "Locker: lock already withdrawn");
    require(_newUnlockTime >= _lock.unlockTime, "Locker: new unlock time must be greater than or equal to the current lock time");
    require(_newAmount > 0 && _newAmount < _lock.amount, "Locker: invalid new amount");
    require(!_isNFT(_lock.token), "Locker: NFTs cannot be split");
    address[] memory _whitelist = new address[](2);
    _whitelist[0] = _lock.token;
    _whitelist[1] = _lock.beneficiary;
    _feeHandler(_whitelist);
    _lock.amount -= _newAmount;
    _splitId = lockId;
    ++lockId;
    locks[_splitId] = Lock({
        token: _lock.token,
        tokenId: 0,
        beneficiary: _lock.beneficiary,
        amount: _newAmount,
        unlockTime: _newUnlockTime,
        withdrawn: false
    });
    emit LockSplit(_id, _splitId);
}

function _feeHandler(address[] memory _whitelist) internal {
    uint256 _f = _fee(_whitelist);
    if (_f > 0) {
        (bool _success, ) = config.treasury().call{value: _f}("");
        require(_success, "Locker: fee transfer failed");
    }
    if (msg.value > _f) {
        (bool _success, ) = payable(_msgSender()).call{value: msg.value - _f}("");
        require(_success, "Locker: refund failed");
    }
}
```

This code shows that `_feeHandler` sends ETH to the treasury and to `msg.sender` before `splitLock` adjusts `_lock.amount` and creates the split lock.  
The low-level calls with forwarded gas enable the helper contract to reenter the Locker during the fee refund.

## 4. Detailed Root Cause Analysis

### 4.1 Internal Accounting Behavior

`Locker::withdrawLock` marks a lock as withdrawn and transfers its `amount` to the beneficiary, but it does not adjust the `amount` field:

```solidity
function withdrawLock(uint256 _id) external whenNotPaused {
    Lock storage _lock = locks[_id];
    require(!_lock.withdrawn, "Locker: lock already withdrawn");
    require(block.timestamp >= _lock.unlockTime, "Locker: lock not yet unlocked");
    require(_msgSender() == _lock.beneficiary, "Locker: not the beneficiary");
    _lock.withdrawn = true;
    if (_isNFT(_lock.token)) {
        IERC721(_lock.token).safeTransferFrom(address(this), _lock.beneficiary, _lock.tokenId);
    } else {
        IERC20(_lock.token).safeTransfer(_lock.beneficiary, _lock.amount);
    }
    emit LockWithdrawn(_id);
}
```

The mapping `locks` holds a single `Lock` struct per ID, and the contract holds a pooled `TokenV2` balance for all locks.  
There is no invariant or check that ties the Locker’s `TokenV2` balance to the sum of `locks[id].amount` across all IDs.

### 4.2 Lock Snapshots Before and After the Exploit

Locker.locks snapshots around the exploit block show the pooled structure and the effect of the attack:

**Snippet 2 – Locker.locks snapshot before and after exploit (locks 5, 6, 11, 60, 61):**

```json
{
  "lock_ids": [5, 6, 11, 60, 61],
  "blocks": ["0x1728465", "0x1728466"],
  "snapshots": {
    "0x1728465": {
      "5": { "amount": "198979591000000000000000000", "withdrawn": false },
      "6": { "amount": "50000000000000000000000000", "withdrawn": false },
      "11": { "amount": "4412545597397598114138189", "withdrawn": false }
    },
    "0x1728466": {
      "5": { "amount": "198979591000000000000000000", "withdrawn": false },
      "6": { "amount": "50000000000000000000000000", "withdrawn": false },
      "11": { "amount": "1", "withdrawn": true },
      "60": { "amount": "1", "withdrawn": true },
      "61": { "amount": "4412545597397598114138139", "withdrawn": false }
    }
  }
}
```

These snapshots (from `artifacts/root_cause/data_collector/iter_3/contract/8453/0x80b9...0654/locks_snapshots_0x1728465_0x1728466.json`) show:
- Before the exploit, lock `11` holds `4412545597397598114138189` `TokenV2` and is not withdrawn.  
- After the exploit, lock `11` has `amount = 1` and `withdrawn = true`, new locks `60` and `61` exist, and lock `61` holds `4412545597397598114138139` `TokenV2`.  
The large deficit in the Locker’s pooled `TokenV2` balance arises from repeated reentrant withdrawals during the exploit transaction, not from these nominal snapshot amounts alone.

### 4.3 On-chain Trace of the Exploit Transaction

The Foundry trace for tx `0x984cb29cdb4e92e5899e9c94768f8a34047d0e1074f9c4109364e3682e488873` on Base shows the reentrancy pattern:

**Snippet 3 – Seed transaction trace for exploit tx 0x984c...873 (excerpt):**

```text
[...]
│   │   ├─ [6329] GnosisSafeProxy::fallback{value: 10000000000000000}()
│   │   │   ├─ [1504] GnosisSafeL2::receive{value: 10000000000000000}() [delegatecall]
│   │   │   │   ├─ emit SafeReceived(sender: ERC1967Proxy: [0x80b9...0654], value: 10000000000000000 [1e16])
│   │   │   └─ ← [Return]
│   │   ├─ [56895] 0x0F30AE8f41a5d3Cc96abd07Adf1550A9A0E557b5::fallback{value: 1000000000000000}()
│   │   │   ├─ [56232] ERC1967Proxy::fallback(11)
│   │   │   │   ├─ [55922] Locker::withdrawLock(11) [delegatecall]
│   │   │   │   │   ├─ TokenV2::transfer(0x0F30AE8f41a5d3Cc96abd07Adf1550A9A0E557b5, 4412545597397598114138189)
│   │   │   │   │   ├─ emit LockWithdrawn(_id: 11)
│   │   │   │   │   ├─ storage changes: locks[11].withdrawn: 0 → 1
[...]
```

This excerpt (from `artifacts/root_cause/seed/8453/0x984c...873/trace.cast.log`) shows:
- `Locker::splitLock` calling `_feeHandler`, which sends `0.01` ETH to the treasury Gnosis Safe and refunds `0.001` ETH back to helper `0x0f30a...`.  
- During the refund, the helper’s fallback calls back into the Locker proxy and invokes `Locker::withdrawLock(11)` via delegatecall, transferring `4412545597397598114138189` `TokenV2` from the Locker to the helper and marking lock `11` as withdrawn.  
- This pattern repeats across lock IDs `11` through `60`, cumulatively draining `TokenV2` from the pooled Locker balance.

### 4.4 Quantitative Token and Balance Effects

Balance diffs for the exploit tx show the net `TokenV2` movements:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0xf3a605573b93fd22496f471a88ae45f35c1df5a7",
      "holder": "0x80b9c9c883e376c4aa43d72413ab1bd6a64a0654",
      "before": "253392136597397598114138189",
      "after": "32764856727517692407229964",
      "delta": "-220627279869879905706908225"
    },
    {
      "token": "0xf3a605573b93fd22496f471a88ae45f35c1df5a7",
      "holder": "0x599245fafc9a55e3d2f02176a65d9cd302023c61",
      "before": "72286970465239470742779450",
      "after": "292914250335119376449687675",
      "delta": "220627279869879905706908225"
    }
  ]
}
```

From `artifacts/root_cause/seed/8453/0x984c...873/balance_diff.json`:
- Locker proxy `0x80b9...` loses exactly `220627279869879905706908225` `TokenV2`.  
- Uniswap V3 pool `0x5992...3c61` gains the same amount, matching the described swap path.

Combined with the lock snapshots, this supports the conclusion that over-withdrawals from the pooled Locker balance drained `220627279869879905706908225` `TokenV2` that should back other users’ locks.

## 5. Adversary Flow Analysis

### 5.1 Strategy Summary

The adversary executes a three-transaction strategy:
1. Wrap ETH into WETH9 in the helper contract to prepare ERC20 liquidity.  
2. Create a large `TokenV2` lock under adversary control in the Locker.  
3. Use `splitLock`/`withdrawLock` reentrancy to over-withdraw pooled `TokenV2`, swap to WETH9, unwrap to ETH, pay the lock fee, and realize ETH profit on the EOA.

### 5.2 ACT Transaction Sequence and Roles

The ACT transaction sequence `b` on Base (chainid 8453) is:

1. **Tx 1 – WETH priming**  
   - Hash: `0x01d0df430bb584116e60d4da8f955cc74c472b42f523398146f320b58b7a294d`  
   - Type: adversary-crafted.  
   - Description: EOA `0x3cc1...` sends a standard type-2 transaction from its own funds to helper contract `0x0f30a...` to wrap `0.4` ETH into WETH9.  
   - Inclusion feasibility: the transaction uses normal gas pricing and calldata derived from public ABIs; any unprivileged searcher can realize the same transaction from pre-state `σ_B` with a standard type-2 submission.  
   - Notes: prepares WETH liquidity and primes the helper contract for later Locker and DEX interactions.

2. **Tx 2 – Adversary lock creation**  
   - Hash: `0xb171f1348ea505328df2cb9a2f7b26350a123b58be59ddcf6c12944543320784`  
   - Type: adversary-crafted.  
   - Description: the same EOA `0x3cc1...` sends a standard transaction to `0x0f30a...` with `0.01` ETH value and calldata that causes the Locker proxy to create lock id `11` in `TokenV2`.  
   - Notes: establishes an attacker-controlled lock with amount `4412545597397598114138189` `TokenV2` and pays the fixed `0.01` ETH fee to treasury `0x0977...`.

3. **Tx 3 – Reentrancy exploit and profit**  
   - Hash: `0x984cb29cdb4e92e5899e9c94768f8a34047d0e1074f9c4109364e3682e488873`  
   - Type: adversary-crafted (attacker-profit in the top-level summary).  
   - Description: EOA `0x3cc1...` sends a type-2 transaction with `0.51` ETH to `0x0f30a...`. The helper calls the Locker proxy and Uniswap V3 router/pool using only public ABIs; gas price and calldata are fully under adversary control and conform to standard inclusion rules.  
   - Notes: this transaction executes the reentrancy exploit, drains over-collateralized `TokenV2` from the pooled Locker balance, swaps to WETH9, unwraps to ETH, pays `0.5` ETH to the treasury, and forwards the remaining ETH profit back to the EOA.

All three transactions are listed in `all_relevant_txs` with roles:
- `0x01d0df4...294d` – `role = "adversary-crafted"`,  
- `0xb171f1...784` – `role = "adversary-crafted"`,  
- `0x984c...873` – `role = "attacker-profit"`.

### 5.3 Adversary and Victim Accounts

Adversary-related accounts:
- **EOA `0x3cc1edd8a25c912fcb51d7e61893e737c48cd98d`** – sender of all three adversary-crafted transactions and ultimate ETH profit recipient.  
- **Helper contract `0x0f30ae8f41a5d3cc96abd07adf1550a9a0e557b5`** – adversary-controlled contract that:
  - orchestrates `splitLock`/`withdrawLock` reentrancy against the Locker,  
  - receives over-withdrawn `TokenV2`,  
  - interacts with Uniswap V3 router `0x2626...e481` and pool `0x5992...3c61`,  
  - unwraps WETH9, and  
  - transfers ETH back to the EOA.

Victim-related contracts:
- **Locker proxy** – Base address `0x80b9c9c883e376c4aa43d72413ab1bd6a64a0654`, verified ERC1967 proxy.  
- **Locker implementation (Locker.sol)** – Base address `0xd6a7cfa86a41b8f40b8dfeb987582a479eb10693`, verified implementation containing the vulnerable logic.  
- **TokenV2 ERC20** – Base address `0xf3a605573b93fd22496f471a88ae45f35c1df5a7`, verified ERC20 token whose balances are drained from the Locker and traded on Uniswap.

### 5.4 Detailed Lifecycle Stages

The adversary lifecycle, as reflected in traces and balance diffs, is:

1. **Adversary funding and helper deployment**  
   - Tx: `0xcf399f203ce225bca0f197e8a0dfb2a06991d91474f67e386f74a28253b73a0d` (Base block `24282162`).  
   - Mechanism: contract deployment.  
   - Effect: EOA `0x3cc1...` deploys helper contract `0x0f30a...` with code designed to drive the Locker reentrancy and coordinate Uniswap swaps.  
   - Evidence: `iter_1` normal txs for `0x3cc1...` and helper disassembly at `artifacts/root_cause/data_collector/iter_1/contract/8453/0x0f30a.../disassembly.txt`.

2. **Adversary WETH priming**  
   - Tx: `0x01d0df4...294d` (block `24282177`).  
   - Mechanism: swap/wrap.  
   - Effect: EOA `0x3cc1...` sends `0.4` ETH to `0x0f30a...`, which wraps it into `0.4` WETH9 in the helper contract, preparing ERC20 liquidity for later Locker and DEX operations.  
   - Evidence: `artifacts/root_cause/data_collector/iter_2/tx/8453/0x01d0df4...294d/trace.cast.log` and `iter_3` balance diffs.

3. **Adversary lock creation**  
   - Tx: `0xb171f1...784` (block `24282195`).  
   - Mechanism: lock creation.  
   - Effect: the EOA sends `0.01` ETH to `0x0f30a...`, which calls the Locker proxy to create lock `11` in `TokenV2` with amount `4412545597397598114138189` tokens and pays a `0.01` ETH fee to treasury `0x0977...`, establishing an attacker-controlled lock funded from the pooled Locker balance.  
   - Evidence: `artifacts/root_cause/data_collector/iter_2/tx/8453/0xb171f1...784/trace.cast.log`, `iter_3` balance diffs, and the lock snapshots file above.

4. **Reentrancy exploit and profit realization**  
   - Tx: `0x984c...873` (block `24282214`).  
   - Mechanism: reentrancy exploit.  
   - Effect: helper `0x0f30a...`, funded by `0.51` ETH from the EOA, calls the Locker proxy to `splitLock` its lock `11`.  
     - `_feeHandler` sends `0.01` ETH to treasury `0x0977...` and refunds `0.001` ETH to `0x0f30a...`, whose fallback reenters `Locker::withdrawLock(11)` and later `withdrawLock(12..60)`.  
     - Each reentrant call transfers `TokenV2` from the Locker’s pooled balance to the helper without enforcing global balance invariants, cumulatively draining `220627279869879905706908225` `TokenV2`.  
     - The helper approves Uniswap V3 router `0x2626...e481` and swaps the drained `TokenV2` via pool `0x5992...3c61` for `5214470174770264654` WETH9, unwraps WETH9 to ETH, pays `0.5` ETH to the treasury, and forwards `5.224470174770264654` ETH back to the EOA.  
   - Evidence: seed trace `artifacts/root_cause/seed/8453/0x984c...873/trace.cast.log`, seed `balance_diff.json`, and Locker.sol source.

## 6. Impact & Losses

### 6.1 TokenV2 Shortfall

The total `TokenV2` loss from the Locker’s pooled balance is:

- `TokenV2` (`TokenV2` symbol) – `220627279869879905706908175` tokens.

On-chain `Locker.locks` snapshots and `TokenV2` balance diffs show that, relative to outstanding lock claims for ids `5`, `6`, and `61`, the Locker proxy’s `TokenV2` balance decreases by exactly `220627279869879905706908175` tokens after the exploit.  
This undercollateralization corresponds to:
- An over-withdrawal of `216214734272482307592770036` `TokenV2` from the attacker-controlled lock `11` beyond its own deposit,  
- plus a residual discrepancy attributable to rounding and prior state.

The entire `220627279869879905706908175` `TokenV2` shortfall represents value removed from the pooled `TokenV2` backing legitimate locks and routed into the adversary’s strategy, with a portion realized as ETH profit.

### 6.2 ETH Profit Calculation

The ACT success predicate is type `"profit"` with reference asset `ETH`.  
For the adversary EOA `0x3cc1edd8a25c912fcb51d7e61893e737c48cd98d`:

- `value_before_in_reference_asset` – `1.118414305886571899` ETH, from the EOA’s native balance immediately before tx `0x01d0df4...`, based on the pre-state of that tx’s balance diff (`1118414305886571899` wei).  
- `value_after_in_reference_asset` – `5.422809279153219612` ETH, from the EOA’s native balance immediately after tx `0x984c...873`, based on its balance diff (`5422809279153219612` wei).  
- `value_delta_in_reference_asset` – `4.304394973266647713` ETH, the exact difference `4304394973266647713` wei across the three adversary-crafted txs.  
- `fees_paid_in_reference_asset` – `0.010075204502835941` ETH, consisting of:
  - all gas paid on the three adversary-crafted txs, computed as the sum of positive native deltas to Base fee-recipient addresses `0x4200...0011`, `0x4200...0019`, and `0x4200...001a` in the three `balance_diff.json` files, totaling `75204502835941` wei (`0.000075204502835941` ETH), plus  
  - the fixed `0.01` ETH lock fee paid from the EOA to treasury `0x0977...` in tx `0xb171f1...`.  
No price oracles are used; all values derive directly from prestate-based balance diffs and on-chain tx metadata.

The non-monetary success predicate fields (`oracle_name`, `oracle_definition`, `oracle_evidence`) are empty for this incident.

### 6.3 Native Balance Changes in Exploit Tx

The exploit tx balance diff confirms the ETH profit mechanics:

```json
{
  "native_balance_deltas": [
    {
      "address": "0x3cc1edd8a25c912fcb51d7e61893e737c48cd98d",
      "before_wei": "708409545891204908",
      "after_wei": "5422809279153219612",
      "delta_wei": "4714399733262014704"
    },
    {
      "address": "0x0977250dbefe33086cebfb73970e0473c592fc54",
      "before_wei": "18333149513031731900",
      "after_wei": "18833149513031731900",
      "delta_wei": "500000000000000000"
    }
  ]
}
```

From `artifacts/root_cause/seed/8453/0x984c...873/balance_diff.json`:
- The EOA’s native balance increases by `4.714399733262014704` ETH in the exploit tx alone, consistent with the described swaps and fee payments.  
- Treasury Gnosis Safe `0x0977...` receives `0.5` ETH in the exploit tx, corresponding to protocol fees.

The ETH profit numbers and the `TokenV2` shortfall are fully aligned with the ACT success predicate in `root_cause.json`.

## 7. References

Primary evidence and references:

- **[1] Locker implementation source (Locker.sol)**  
  - `artifacts/root_cause/data_collector/iter_3/contract/8453/0xd6a7cfa86a41b8f40b8dfeb987582a479eb10693/source/src/Locker.sol`

- **[2] Exploit transaction trace and balance diff (0x984c...873)**  
  - `artifacts/root_cause/seed/8453/0x984cb29cdb4e92e5899e9c94768f8a34047d0e1074f9c4109364e3682e488873`

- **[3] Preparatory and lock-creation transaction traces and balance diffs (0x01d0df4..., 0xb171f1...)**  
  - `artifacts/root_cause/data_collector/iter_2/tx/8453`

- **[4] Locker.locks snapshots before and after exploit**  
  - `artifacts/root_cause/data_collector/iter_3/contract/8453/0x80b9c9c883e376c4aa43d72413ab1bd6a64a0654/locks_snapshots_0x1728465_0x1728466.json`

These references, together with the ACT opportunity specification and success predicate in `root_cause.json`, fully support the root cause and adversary flow described in this report.

