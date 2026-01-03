# Incident Overview & TL;DR

On Base (chainid 8453), an externally owned account (EOA) `0x3Cc1eDD8a25c912fCB51d7E61893e737C48Cd98D` used a helper contract `0x0F30AE8f41a5d3Cc96abd07Adf1550A9A0E557b5` to create and then withdraw a large TokenV2 position from a time-locking contract (`Locker`), swapping the unlocked tokens for WETH via Uniswap and briefly increasing the EOA’s native balance within a single transaction (`0x984c…8873`).  
After incorporating Locker source code, full lock lifecycle logs for ids 11–60, and extended balance snapshots, this pattern is determined **not** to be a proven ACT opportunity: the drained TokenV2 tokens come from a lock economically owned by the helper/EOA cluster itself, all Locker invariants are respected, and there is no durable, fee-aware profit extracted from third-party value.

---

## Seed Transaction and Participants

- **Chain:** Base (chainid 8453)  
- **Seed transaction:** `0x984cb29cdb4e92e5899e9c94768f8a34047d0e1074f9c4109364e3682e488873`  
- **Primary EOA (controller):** `0x3Cc1eDD8a25c912fCB51d7E61893e737C48Cd98D`  
- **Helper contract:** `0x0F30AE8f41a5d3Cc96abd07Adf1550A9A0E557b5` (deployed and controlled by the EOA)  
- **Locker proxy:** `0x80b9C9C883e376c4aA43d72413aB1Bd6A64A0654` (delegating to Locker implementation)  
- **Locker implementation:** `0xd6a7cfa86a41b8f40b8dfeb987582a479eb10693` (`Locker.sol`)  
- **Token under lock:** `TokenV2` at `0xF3a605573B93Fd22496f471A88AE45F35C1df5a7`  
- **AMM path:** Uniswap V3 pool `0x2626664c2603336E57B271c5C0b26F421741e481` and router `0x599245FAFc9a55e3d2f02176a65d9CD302023c61`  
- **Protocol treasury:** Gnosis Safe `0x0977250DbeFE33086Cebfb73970E0473c592fc54`

In the seed transaction, the EOA sends 0.51 ETH to the helper and calls a function (selector `0x735ac5b2`) that orchestrates Locker interactions and a subsequent swap.

---

## Locker Mechanics and Lock Lifecycle

The Locker contract is an upgradeable time-lock that holds ERC20 or NFT positions and enforces beneficiary and unlock-time checks on withdrawals and modifications.

Key parts of `Locker.sol` related to this incident:

```solidity
// Collected Locker source (Locker.sol) for 0xd6a7cfa8…
function withdrawLock(uint256 _id) external whenNotPaused {
    Lock storage _lock = locks[_id];
    require(!_lock.withdrawn, "Locker: lock already withdrawn");
    require(block.timestamp >= _lock.unlockTime, "Locker: lock not yet unlocked");
    require(_msgSender() == _lock.beneficiary, "Locker: not the beneficiary");
    _lock.withdrawn = true; /// @dev Prevents reentrancy
    if (_isNFT(_lock.token)) {
        IERC721(_lock.token).safeTransferFrom(address(this), _lock.beneficiary, _lock.tokenId);
    } else {
        IERC20(_lock.token).safeTransfer(_lock.beneficiary, _lock.amount);
    }
    emit LockWithdrawn(_id);
}

function splitLock(uint256 _id, uint256 _newAmount, uint256 _newUnlockTime) external payable whenNotPaused returns (uint256 _splitId) {
    Lock storage _lock = locks[_id];
    require(!_lock.withdrawn, "Locker: lock already withdrawn");
    require(_newUnlockTime >= _lock.unlockTime, "Locker: new unlock time must be greater than or equal to the current lock time");
    require(_newAmount > 0 && _newAmount < _lock.amount, "Locker: invalid new amount");
    require(!_isNFT(_lock.token), "Locker: NFTs cannot be split");
    // fee handler and creation of new Lock with same beneficiary…
}
```

*Caption: Locker’s withdrawal and split logic requires the caller to be the recorded beneficiary, enforces unlock times, prevents reentrancy via a `withdrawn` flag, and preserves the beneficiary when splitting locks.*

### Lock Creation and Splitting for IDs 11–60

Newly collected Locker logs show the full lifecycle of lock ids 11–60. Critically:

- **Only lock 11** has a `LockCreated` event.  
- The beneficiary for lock 11 is the helper contract, and the token is TokenV2.  
- Locks 12–60 are created **only** via `LockSplit` events that re-slice the same underlying position.

Representative excerpt:

```json
// Locker lock lifecycle logs for ids 11–60 (QuickNode log scan)
{
  "lock_events": {
    "11": [
      {
        "event": "LockCreated",
        "args": {
          "_id": 11,
          "_beneficiary": "0x0f30ae8f41a5d3cc96abd07adf1550a9a0e557b5",
          "_token": "0xf3a605573b93fd22496f471a88ae45f35c1df5a7",
          "_amount": 4412545597397598114138189,
          "_unlockTime": 1735353747
        },
        "txhash": "0xb171f1…0784"
      },
      {
        "event": "LockWithdrawn",
        "args": { "_id": 11 },
        "txhash": "0x984cb2…8873"
      },
      {
        "event": "LockSplit",
        "args": { "_id": 11, "_splitId": 12 },
        "txhash": "0x984cb2…8873"
      }
    ],
    "12": [
      {
        "event": "LockWithdrawn",
        "args": { "_id": 12 },
        "txhash": "0x984cb2…8873"
      },
      {
        "event": "LockSplit",
        "args": { "_id": 12, "_splitId": 13 },
        "txhash": "0x984cb2…8873"
      }
    ]
    // … pattern continues up to id 60
  }
}
```

*Caption: Lock 11 is created for the helper as beneficiary; locks 12–60 arise solely from `LockSplit` events in the seed transaction, indicating a self-owned, repeatedly split position rather than multiple independent user locks.*

The sequence in the seed transaction can be summarized as:

1. A prior transaction (`0xb171f1…0784`) calls `Locker::createLock`, creating lock 11 for the helper with TokenV2 as the locked asset.  
2. In the seed transaction, the helper:
   - Reads locks 11–50,  
   - Iteratively calls `splitLock` and `withdrawLock` over ids 11–60, always as the recorded beneficiary,  
   - Aggregates the withdrawn TokenV2 into the Uniswap path and performs a large swap for WETH.

There is no evidence of other beneficiaries or LockCreated events for ids 12–60, so all drained TokenV2 in this sequence stems from a single helper-owned lock.

---

## Seed Transaction Behavior and Balance Effects

Per-transaction balance diffs for the seed transaction show the flows between Locker, the Uniswap pool, WETH, the treasury, and the EOA.

```json
// Seed transaction balance diff for tx 0x984c…8873
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
      "delta_wei": "500000000000000000"
    },
    {
      "address": "0x4200000000000000000000000000000000000006",
      "delta_wei": "-5214470174770264654"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0xf3a605573b93fd22496f471a88ae45f35c1df5a7",
      "holder": "0x80b9c9c883e376c4aa43d72413ab1bd6a64a0654",
      "delta": "-220627279869879905706908225"
    },
    {
      "token": "0xf3a605573b93fd22496f471a88ae45f35c1df5a7",
      "holder": "0x599245fafc9a55e3d2f02176a65d9cd302023c61",
      "delta": "220627279869879905706908225"
    }
  ]
}
```

*Caption: The Locker proxy loses ~2.206e23 TokenV2, which are moved into the Uniswap path; WETH supply at the canonical contract decreases by ~5.214 WETH, the treasury gains 0.5 ETH in fees, and the EOA’s native balance increases by ~4.714 ETH in this single transaction.*

At the single-transaction level, the helper/EOA cluster pulls WETH out of the AMM, unwrapping it to native ETH and paying protocol and gas fees, resulting in a one-tx native balance increase for the EOA.

---

## Extended Profit and Ownership Analysis

### Ownership of Drained TokenV2

The key question for ACT classification is whether the drained TokenV2 originated from third-party victims or from the helper/EOA cluster itself.

Evidence:

- **LockCreated for id 11** shows the beneficiary is the helper contract and the token is TokenV2, with no intermediary LockTransferred events before the seed transaction.  
- **LockSplit events** from 11 through 60 simply redistribute this same economic position across new ids, preserving the helper as beneficiary.  
- The Locker code requires `msg.sender == beneficiary` for any `withdrawLock`, and the traces confirm that the helper is the caller for the withdrawals in the seed transaction.

Taken together, the drained TokenV2 were locked by, and remained owned by, the helper/EOA cluster throughout. No evidence supports third-party ownership of locks 11–60.

### Net Profit Over the Opportunity Window

Balance snapshots for the EOA and helper over a wider window (`0x1728300–0x1728600`) show that the cluster does not achieve a clear, fee-aware profit once preparation and follow-up activity are included.

```json
// Extended balance snapshots for EOA and helper over 0x1728300–0x1728600
{
  "address": "0x3cc1edd8a25c912fcb51d7e61893e737c48cd98d",
  "native": { "0x1728300": 0, "0x1728600": 152710255130493 },
  "erc20": { "WETH": { "0x1728300": 0, "0x1728600": 0 }, "TokenV2": { "0x1728300": 0, "0x1728600": 0 } }
}
{
  "address": "0x0f30ae8f41a5d3Cc96abd07Adf1550A9A0E557b5",
  "native": { "0x1728300": 0, "0x1728600": 0 },
  "erc20": { "WETH": { "0x1728300": 0, "0x1728600": 0 }, "TokenV2": { "0x1728300": 0, "0x1728600": 0 } }
}
```

*Caption: Across the extended window, the helper never holds nonzero native, WETH, or TokenV2 balances, and the EOA ends with only ~0.00015 ETH; this is consistent with prior per-block balance diffs showing sizable gas and fee outflows around the incident.*

Combined with earlier balance diffs (where the EOA’s native balance falls by ~1.118 ETH over `0x1728400–0x1728500`), the overall picture is:

- The helper/EOA cluster cycles a large self-owned TokenV2 lock through the Locker.  
- It temporarily pulls WETH out of the AMM, pays fees and gas, and ends the broader window with effectively no net gain in native, WETH, or TokenV2.  
- Any apparent per-tx “profit” is offset by setup and execution costs within the incident window, and in all cases the value at risk is the cluster’s own lock position and trade flow, not assets provably belonging to third parties.

---

## Adversary Cluster and Roles

- **Controller EOA:**  
  - `0x3Cc1eDD8a25c912fCB51d7E61893e737C48Cd98D`  
  - Deploys the helper contract and is stored as its owner in storage slot 0.  
  - Initiates both the lock-creation and the seed withdrawal transaction.

- **Helper contract:**  
  - `0x0F30AE8f41a5d3Cc96abd07Adf1550A9A0E557b5`  
  - Decompilation shows functions corresponding to lock creation, splitting/withdrawal, and swapping.  
  - Enforces `require(msg.sender == owner)`-style checks using storage slot 0, meaning only the EOA can drive the sequence.

- **Protocol contracts:**  
  - Locker proxy and implementation, TokenV2, Uniswap pool/router, and the treasury Gnosis Safe behave in line with their code and roles.  
  - No abnormal ownership changes or privilege escalations are observed in traces or logs.

There is no evidence of additional adversary-related accounts or of compromised protocol/operator keys.

---

## Why This Is Not a Proven ACT Opportunity

Based on all collected evidence, this pattern fails the ACT exploit predicate against third-party economic value for two independent reasons:

1. **No third-party victim lock or account is identified.**  
   - Logs for ids 11–60 show a single LockCreated for id 11, owned by the helper; all subsequent locks are splits of this same position with the same beneficiary.  
   - There are no LockTransferred events moving ownership from an external user to the helper before the withdrawals.  
   - The Locker’s `withdrawLock` and `splitLock` invariants are enforced and satisfied in every trace step.

2. **No durable, fee-aware profit for the helper/EOA cluster.**  
   - While the seed transaction shows a gross ETH inflow to the EOA, windowed balance diffs and snapshots demonstrate that the cluster’s net position across the preparation and execution window does not reflect a clear, positive profit once gas and fees are included.  
   - The helper and EOA end the extended window with no WETH or TokenV2 and only a negligible native balance.

As a result, the behavior is best described as an aggressive, self-owned position management and trade sequence using Locker and Uniswap, not an exploit that extracts value from third-party locks or protocol misconfigurations. Under the ACT framework, this incident is **not** a proven ACT opportunity.

---

## Protocol and Operator Lessons

- **Event-level provenance is crucial:**  
  Comprehensive lock lifecycle logs (LockCreated, LockSplit, LockWithdrawn) are sufficient to reconstruct economic ownership of locked positions. This incident shows that such logs can conclusively demonstrate self-ownership even when large flows initially look suspicious.

- **Beneficiary gating works as intended:**  
  The Locker’s strict `msg.sender == beneficiary` requirement, combined with unlock-time checks and a non-reentrant withdrawal pattern, effectively prevents unauthorized withdrawals of third-party locks.

- **Fee visibility helps risk assessment:**  
  The treasury’s explicit 0.5 ETH fee and the clear accounting of WETH deltas make it straightforward to evaluate whether sequences yield sustainable profit or are net-loss/self-funding operations.

- **Pipeline behavior for non-ACT patterns:**  
  For flows like this one, where all drained assets are self-owned and net profit is not established, it is appropriate for the pipeline to conclude “no proven ACT opportunity” and avoid emitting a full ACT-style victim root cause file. The iter_4 analysis now meets this bar.

