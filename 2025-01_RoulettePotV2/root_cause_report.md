# RoulettePotV2 XENCrypto Round 18580 — Large Honest Win, No ACT Exploit

**Protocol:** RoulettePotV2 / XENCrypto Casino (BSC)  
**Chain:** BNB Smart Chain (chainid 56)  
**Incident Round:** `roundId 18580`, `tokenId 6` (XENCrypto casino)  
**ACT Classification:** `is_act = false` (no ACT exploit)  
**Root Cause Category:** `other` (large but honest game outcome)

This report reconstructs the incident round and confirms that the observed ~39.52 BNB profit is the result of an extreme but fair roulette win, using unbiased Chainlink VRF randomness and protocol-designed fee conversions, rather than any manipulable vulnerability.

---

## Incident Overview & TL;DR

- An unprivileged player EOA and a helper flash-loan contract used RoulettePotV2 on BSC to settle XENCrypto casino round `18580`, realizing approximately **39.520332279709631513 BNB** in net profit in a single transaction.
- RoulettePotV2 obtains randomness from a dedicated **VRFv2Consumer** contract, which in turn uses **Chainlink VRFCoordinatorV2** as the on-chain randomness oracle.
- On-chain traces and verified source code show that randomness is requested, fulfilled, stored, and consumed in a standard VRF v2 pattern, without any avenue for attacker control over the random word.
- The settlement transaction calls `finishRound()` and `swapProfitFees()`, applying the VRF-generated outcome to all pending bets and swapping protocol profit tokens to BNB as designed.
- There is **no evidence of reentrancy, accounting errors, oracle manipulation, or other ACT-style exploit behavior**; the profit is consistent with the advertised high-variance roulette mechanics.

---

## Key Background

### RoulettePotV2 game and architecture

- **RoulettePotV2** is an on-chain roulette game deployed on BSC. It:
  - Accepts bets in XENCrypto and other tokens.
  - Tracks per-casino **liquidity**, **locked** amounts, and **profit**.
  - Settles rounds using a roulette wheel outcome in the range `[0, 37]`.
- Bets are grouped into rounds. Each round:
  - Aggregates multiple bets in `currentBets`.
  - Starts when the first bet arrives (`roundIds++`, `roundLiveTime` set).
  - Becomes eligible for VRF randomness after a timeout window.

### Randomness pipeline

- Randomness is provided indirectly via a separate **VRFv2Consumer** contract at `0x30262c…78BfB`, with source code verified as `VRFv2Consumer.sol`.
- RoulettePotV2 does **not** implement VRF logic itself. Instead, it:
  - Calls `IVRFv2Consumer(consumerAddress).requestRandomWords()` to request randomness.
  - Later queries `IVRFv2Consumer(consumerAddress).getRequestStatus(requestId)` to retrieve the random word.
- The VRFv2Consumer uses the public **Chainlink VRFCoordinatorV2** at `0xc587d9…A4EE` to generate and deliver randomness.

The relevant consumer implementation is:

```solidity
// Collected contract source: VRFv2Consumer.sol (verified on explorer)
contract VRFv2Consumer is VRFConsumerBaseV2 {
    VRFCoordinatorV2Interface COORDINATOR;
    uint64 public immutable s_subscriptionId;
    uint32 public callbackGasLimit = 500000;
    uint16 requestConfirmations = 3;
    uint32 numWords = 1;

    struct RequestStatus {
        bool fulfilled;
        bool exists;
        uint256[] randomWords;
    }

    mapping(uint256 => RequestStatus) public s_requests;
    mapping(address => bool) public authorized;

    constructor(uint64 subscriptionId) VRFConsumerBaseV2(vrfCoordinator) {
        COORDINATOR = VRFCoordinatorV2Interface(vrfCoordinator);
        s_owner = msg.sender;
        s_subscriptionId = subscriptionId;
        authorized[msg.sender] = true;
    }

    function requestRandomWords() external onlyAuthorized returns (uint256 requestId) {
        requestId = COORDINATOR.requestRandomWords(
            keyHash,
            s_subscriptionId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );
        s_requests[requestId] = RequestStatus({ randomWords: new uint256[](0), exists: true, fulfilled: false });
        return requestId;
    }

    function fulfillRandomWords(uint256 _requestId, uint256[] memory _randomWords) internal override {
        require(s_requests[_requestId].exists, "request not found");
        s_requests[_requestId].fulfilled = true;
        s_requests[_requestId].randomWords = _randomWords;
    }
}
```

> **Snippet 1 – VRF consumer behavior**  
> Source: collected contract source for `VRFv2Consumer.sol` (VRF randomness is requested from Chainlink and stored immutably in `s_requests[requestId]`).

This implementation matches a standard Chainlink VRF v2 pattern: once fulfilled, the random word is stored and cannot be altered by an adversary-controlled contract.

---

## Vulnerability & Root Cause Analysis

### High-level conclusion

- No **protocol bug**, **oracle-manipulation path**, or **access-control flaw** was found in:
  - RoulettePotV2 (`RouletteV2.sol` at `0xf57374…7F90f`),
  - VRFv2Consumer (`0x30262c…78BfB`), or
  - VRFCoordinatorV2 (`0xc587d9…A4EE`).
- The observed profit is explained by:
  - A **low-probability but fair roulette outcome** determined by Chainlink VRF.
  - Protocol-designed **profit-fee swaps** (via `swapProfitFees()`).
  - A **flash-loan wrapper** that atomically bundles settlement, swaps, and repayment.

### Detailed randomness and settlement flow

RoulettePotV2 integrates VRF randomness via a small, deterministic set of functions:

```solidity
// Collected contract source: RouletteV2.sol (RoulettePotV2 randomness integration)
function _requestVRF() internal {
    IVRFv2Consumer vrfConsumer = IVRFv2Consumer(consumerAddress);
    uint256 _requestId = vrfConsumer.requestRandomWords();
    requestId = _requestId;
    isVRFPending = true;
    emit VRFRequested();
}

function _updateRoundStatus() internal {
    if (!isVRFPending && roundLiveTime != 0 && block.timestamp > roundLiveTime + 120) {
        _requestVRF();
    }
    if (currentBetCount == 1) {
        roundLiveTime = block.timestamp;
        roundIds++;
    }
}

function requestNonce() external {
    require(!isVRFPending && roundLiveTime != 0 && block.timestamp > roundLiveTime + 120, "Round not ended");
    _requestVRF();
}

function finishRound() external nonReentrant {
    require(isVRFPending == true, "VRF not requested");

    (bool fulfilled, uint256[] memory nonces) = IVRFv2Consumer(consumerAddress).getRequestStatus(requestId);
    require(fulfilled == true, "not yet fulfilled");

    uint256 length = currentBetCount;
    uint256 linkPerRound = linkPerBet;

    for (uint256 i = 0; i < length; ++i) {
        BetInfo memory info = currentBets[i];
        linkSpent[info.tokenId] += (linkPerRound / length);
        _finishUserBet(info, nonces[0]);
    }

    isVRFPending = false;
    delete roundLiveTime;
    delete currentBetCount;
    emit RoundFinished(roundIds, nonces[0] % 38);
}
```

> **Snippet 2 – RoulettePotV2 requesting and consuming VRF randomness**  
> Source: collected contract source for `RouletteV2.sol` (RoulettePotV2 sets `requestId`, waits for fulfillment, then consumes `nonces[0] % 38` exactly once per round).

Key properties confirmed from code and traces:

- **Requesting randomness**
  - `_requestVRF()` calls the VRF consumer’s `requestRandomWords()`, which can only be invoked by authorized addresses in `VRFv2Consumer`.
  - This sets a new `requestId` and flips `isVRFPending = true`.
  - `_updateRoundStatus()` automatically triggers `_requestVRF()` once:
    - `roundLiveTime != 0` (a round has started),
    - `block.timestamp > roundLiveTime + 120` (timeout passed), and
    - `isVRFPending == false`.
  - Alternatively, `requestNonce()` exposes this same behavior to any caller once the timeout has passed.

- **Receiving randomness**
  - The VRFCoordinatorV2 transaction `0x0d16e86689fb46f825f878b1e25f24df7d254ff26a96d08ee535437228b94275` calls `VRFv2Consumer.fulfillRandomWords`, which:
    - Marks `s_requests[requestId].fulfilled = true`.
    - Stores the 256-bit random word in `randomWords`.
  - The consumer does **not** call RoulettePotV2 in this transaction, preventing reentrancy-based manipulation.

- **Consuming randomness**
  - `finishRound()` can be called by any address but enforces:
    - `isVRFPending == true` (VRF was requested), and
    - `fulfilled == true` for the stored `requestId`.
  - It reads `nonces[0]` from the consumer, applies `nonces[0] % 38` as the wheel outcome, and settles each bet via `_finishUserBet(...)`.
  - After settlement:
    - `isVRFPending` is set to `false`.
    - `roundLiveTime` and `currentBetCount` are cleared, preventing reuse.

The payout computation itself is a straightforward deterministic application of bet types to the wheel outcome:

```solidity
// Collected contract source: RouletteV2.sol (_spinWheel determining payouts)
function _spinWheel(Bet[] memory bets, uint256 nonce) internal pure returns (uint256) {
    uint256 totalReward;
    uint8[6] memory betRewards = [2, 3, 3, 2, 2, 36];

    for (uint256 i = 0; i < bets.length; ++i) {
        if (_isInBet(bets[i], nonce)) {
            totalReward += betRewards[bets[i].betType] * bets[i].amount;
        }
    }
    return totalReward;
}
```

> **Snippet 3 – Deterministic roulette payout calculation**  
> Source: collected contract source for `RouletteV2.sol` (given a nonce in `[0,37]`, rewards are fully determined by bet configuration).

### Incident roundId 18580: concrete sequence

For round `18580`, the key VRF-related transactions are:

1. **requestNonce tx**  
   - Tx: `0x2703bdba360c705f59197cf84123fce01a3a526ec79c31fd1e436f34247764d7` (block `45665815`)  
   - Sender: `0xdfAc7733c205C3A2a5E202293ebB37E4633BC286` (player EOA)  
   - Behavior (from `debug_trace_callTracer.json`):
     - `RoulettePotV2.requestNonce()` calls `_requestVRF()`.
     - `_requestVRF()` invokes `VRFv2Consumer.requestRandomWords()`.
     - VRFCoordinatorV2 emits a `RandomWordsRequested` event with `requestId = 0x7ad08c2f42d6876fbcd9d9aab239377b62737e265cd860d5b6c699a844d3703f`.

2. **VRF fulfill tx**  
   - Tx: `0x0d16e86689fb46f825f878b1e25f24df7d254ff26a96d08ee535437228b94275` (block `45665820`)  
   - Sender: `0x0255628fd6b092992c572ab1fd6c2de4b5a33461` (Chainlink VRF operator EOA)  
   - Behavior (from `receipt.json` and `debug_trace_callTracer.json`):
     - `VRFCoordinatorV2` verifies the VRF proof using precompiles.
     - It calls `VRFv2Consumer.fulfillRandomWords(requestId, randomWords)`.
     - Consumer stores the random word in `s_requests[requestId]` with `fulfilled = true`.
     - No calls into RoulettePotV2 occur in this transaction.

3. **Round settlement & fee swaps**  
   - Tx: `0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490` (block `45668286`)  
   - Sender: `0x0000000000004F3D8AAf9175fD824CB00aD4bf80` via helper contract `0x000000000000Bb1B11e5Ac8099E92e366B64c133`  
   - Behavior (from `trace.cast.log`):

```text
// Seed transaction trace for 0xd9e0…3490 (flash-loan settlement bundle)
PancakeV3Pool::flash(...)
  ├─ RoulettePotV2::finishRound()
  │   ├─ VRFv2Consumer::getRequestStatus(0x7ad08c2f…703f) [staticcall]
  │   ├─ XENCrypto::decimals() [staticcall]
  │   ├─ XENCrypto::transfer(0xdfAc…C286, 5915775945736601620461531446)
  │   ├─ emit FinishedBet(tokenId: 6, roundId: 18580, nonce: 19, …)
  │   ├─ emit LiquidityChanged(tokenId: 6, …, locked: 0, isFinishedBet: true)
  │   └─ emit RoundFinished(roundId: 18580, nonce: 19)
  └─ RoulettePotV2::swapProfitFees()
      ├─ PancakeRouter::getAmountsIn / getAmountsOut (WBNB ↔ LINK, etc.)
      ├─ Swaps of casino profit tokens into BNB and LINK
      └─ Funding of LINK-based VRF subscription and remaining BNB profit
```

> **Snippet 4 – Seed transaction trace for settlement and fee swaps**  
> Source: seed transaction `trace.cast.log` for `0xd9e0…3490` (round settlement, roulette payout to the player, profit-fee swaps, and flash-loan repayment).

Across these steps, the random word is generated by VRFCoordinatorV2, stored once in VRFv2Consumer, and later consumed by RoulettePotV2. There is no reentrancy or intermediate hook that would allow modifying the random word or reusing it across incompatible states.

### Vulnerable components and exploit conditions

- **Vulnerable components:**  
  - None identified. RoulettePotV2, VRFv2Consumer, and VRFCoordinatorV2 behave according to their verified source code and ABIs.

- **Exploit conditions:**  
  - Not applicable. The incident profit does not rely on:
    - Breaking an invariant,
    - Manipulating the randomness source, or
    - Bypassing access controls.
  - Instead, it relies on a low-probability roulette outcome (nonce `19` for roundId `18580`) that happens to favor the adversary’s bet configuration.

- **Security principles violated:**  
  - None identified. The randomness oracle is used as designed, and accounting invariants (liquidity, locked balances, and profit tracking) remain consistent with contract logic in the traces and balance diffs.

---

## ACT Opportunity and Profit Predicate

### Pre-state and transaction sequence

**Block_height_B:** `45665815`  
**Pre-state σ_B definition:**  
Publicly reconstructible BSC state immediately before the `requestNonce` transaction
`0x2703bdba360c705f59197cf84123fce01a3a526ec79c31fd1e436f34247764d7` in block
`45665815`, including:
- RoulettePotV2 at `0xf573748637E0576387289f1914627d716927F90f`,
- VRFv2Consumer at `0x30262cab106e2411B052ca83cd9Aa51e23678BfB`,
- VRFCoordinatorV2 at `0xc587d9053cd1118f25F645F9E08BB98c9712A4EE`, and
- The relevant casino token and LP balances.

Evidence used for σ_B includes:

- `debug_trace_prestateTracer.json` for:
  - Historical `initializeTokenBet_*` transactions,
  - The `requestNonce` transaction (`0x2703bdba…64d7`), and
  - The VRF fulfill transaction (`0x0d16e866…4275`).

**Transaction sequence B:**

1. **Index 1 – requestNonce (attacker-crafted)**
   - Chain: BSC (`56`)
   - Txhash: `0x2703bdba360c705f59197cf84123fce01a3a526ec79c31fd1e436f34247764d7`
   - Type: attacker-crafted (player-controlled)
   - Inclusion feasibility:  
     EOA `0xdfAc7733c205C3A2a5E202293ebB37E4633BC286` is unprivileged and can call
     `RoulettePotV2.requestNonce()` at any time after the round timeout; gas price and
     fees are standard and require no special permissions.
   - Notes:  
     `requestNonce` for `tokenId 6` / `roundId 18580`; forwards a VRF request via
     `VRFv2Consumer` to `VRFCoordinatorV2`, emitting `RandomWordsRequested` for
     `requestId 0x7ad08c2f42d6876fbcd9d9aab239377b62737e265cd860d5b6c699a844d3703f`.

2. **Index 2 – VRF callback (victim-observed)**
   - Chain: BSC (`56`)
   - Txhash: `0x0d16e86689fb46f825f878b1e25f24df7d254ff26a96d08ee535437228b94275`
   - Type: victim-observed
   - Inclusion feasibility:  
     The VRF callback is a standard `fulfillRandomWords` transaction sent by EOA
     `0x0255…3461` to public coordinator `0xc587d9…A4EE`. It is not crafted by the
     adversary and is observable to any searcher via typical BSC infrastructure.
   - Notes:  
     `VRFCoordinatorV2.fulfillRandomWords` delivers randomness for
     `requestId 0x7ad08c2f…703f` to `VRFv2Consumer` at `0x30262c…78BfB`; no calls into
     RoulettePotV2 occur in this transaction.

3. **Index 3 – flash-loan settlement (attacker-crafted)**
   - Chain: BSC (`56`)
   - Txhash: `0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490`
   - Type: attacker-crafted
   - Inclusion feasibility:  
     EOA `0x0000000000004F3D8AAf9175fD824CB00aD4bf80` is unprivileged and constructs a
     flash-loan transaction through helper contract
     `0x000000000000Bb1B11e5Ac8099E92e366B64c133` that calls
     `RoulettePotV2.finishRound()` and `swapProfitFees()`. All calls use standard BSC
     gas and permissions.
   - Notes:  
     The bundle settles round `18580` in RoulettePotV2, pays a large XENCrypto and
     20 BNB reward to player `0xdfAc…C286`, swaps accumulated protocol profit tokens
     into BNB, repays the flash loan (principal + fees), and leaves ~**39.52 BNB** net
     profit across the adversary cluster.

### Profit predicate

The analysis focuses on **monetary profit** in BNB.

- **Reference asset:** BNB  
- **Adversary address / cluster:**  
  `cluster:{0x0000000000004F3D8AAf9175fD824CB00aD4bf80, 0xdfAc7733c205C3A2a5E202293ebB37E4633BC286}`
- **Fees paid in reference asset:** Gas fees only (exact amount not derived; small relative to profit).
- **Value before (in BNB):** Absolute pre-incident balances are not fully reconstructed, but are strictly lower than post-incident balances for the cluster.
- **Value after (in BNB):** Approximately **39.520332279709631513 BNB higher** than before.
- **Delta:** `39520332279709631513` wei.

This is confirmed by the seed transaction balance diff:

```json
{
  "native_balance_deltas": [
    {
      "address": "0x0000000000004f3d8aaf9175fd824cb00ad4bf80",
      "delta_wei": "19520332279709631513"
    },
    {
      "address": "0xdfac7733c205c3a2a5e202293ebb37e4633bc286",
      "delta_wei": "20000000000000000000"
    },
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "delta_wei": "-35349990043684597646"
    },
    {
      "address": "0xf573748637e0576387289f1914627d716927f90f",
      "delta_wei": "-4171603472025223867"
    }
  ]
}
```

> **Snippet 5 – Balance diffs for seed settlement tx**  
> Source: `balance_diff.json` for `0xd9e0…3490` (cluster receives ~39.52 BNB; losses borne by WBNB/LP/router and RoulettePotV2).

**Valuation notes:**

- The cluster gains:
  - ~**19.5203 BNB** at `0x0000…4F80`, and
  - **20 BNB** at `0xdfAc…C286`.
- The losses are drawn from:
  - WBNB/LP/router positions, and
  - RoulettePotV2 itself (casino bankroll).
- Crucially, these transfers:
  - Occur via **documented game payouts** (`FinishedBet` and `LiquidityChanged` events).
  - Are consistent with the on-chain liquidity and fee logic in `RouletteV2.sol`.
  - Do not indicate insolvency or invariant breakage.

Non-monetary oracle predicates (e.g., mispriced price oracles) are **not applicable** here: the oracle in question is Chainlink VRF randomness, which behaves as designed.

---

## Adversary Flow Analysis

### Strategy summary

The adversary cluster behaves as a **sophisticated but unprivileged player**:

1. A player EOA places bets and later requests randomness for round `18580`.
2. Chainlink VRF fulfills the randomness request and stores the random word in VRFv2Consumer.
3. Once randomness is available, a helper contract obtains a flash loan, calls `finishRound()` and `swapProfitFees()` in RoulettePotV2, repays the loan, and captures the residual BNB profit.

Throughout this lifecycle, the adversary:
- Does not control VRF randomness.
- Does not exploit reentrancy or access-control bugs.
- Merely **times** the settlement and wraps it in a flash-loan bundle for capital efficiency.

### Adversary-related accounts and victim candidate

**Adversary cluster:**

- `0x0000000000004F3D8AAf9175fD824CB00aD4bf80`
  - Type: EOA
  - Role: Top-level sender of the seed flash-loan settlement transaction
    `0xd9e0…3490` that orchestrates round settlement and profit extraction.

- `0xdfAc7733c205C3A2a5E202293ebB37E4633BC286`
  - Type: EOA
  - Role: Player who:
    - Initializes bets in RoulettePotV2.
    - Calls `requestNonce` (tx `0x2703bdba…64d7`).
    - Receives the large XENCrypto payout and **20 BNB** when the round settles.

- `0x000000000000Bb1B11e5Ac8099E92e366B64c133`
  - Type: Contract
  - Role: Helper flash-loan contract invoked by `0x0000…4F80` to:
    - Obtain a flash loan from Pancake liquidity,
    - Call `RoulettePotV2.finishRound()` and `swapProfitFees()`, and
    - Route BNB profit back to the cluster.

**Victim candidate:**

- **RoulettePotV2 / XENCrypto Casino**
  - Chain: BSC (`56`)
  - Address: `0xf573748637E0576387289f1914627d716927F90f`
  - Source: Verified (`RouletteV2.sol`)
  - Role: Casino contract whose bankroll funds the roulette payouts and holds accumulated profit fees.

### Lifecycle stages

1. **Adversary betting and VRF request**
   - Tx: `0x2703bdba360c705f59197cf84123fce01a3a526ec79c31fd1e436f34247764d7`
   - Block: `45665815`
   - Mechanism: `requestNonce`
   - Effect:
     - EOA `0xdfAc…C286` calls `RoulettePotV2.requestNonce()` for `tokenId 6` /
       `roundId 18580`.
     - Contract forwards the call via `IVRFv2Consumer(consumerAddress).requestRandomWords()` to VRFCoordinatorV2 through the consumer.
     - A `RandomWordsRequested` event is emitted for `requestId 0x7ad08c2f…703f` with `numWords = 1` and `callbackGasLimit = 500000`.
   - Evidence:
     - `debug_trace_callTracer.json` and `receipt.json` for the tx.
     - `RouletteV2._requestVRF()` implementation (see Snippet 2).

2. **Chainlink VRF randomness delivery**
   - Tx: `0x0d16e86689fb46f825f878b1e25f24df7d254ff26a96d08ee535437228b94275`
   - Block: `45665820`
   - Effect:
     - EOA `0x0255…3461` sends a transaction to VRFCoordinatorV2 (`0xc587d9…A4EE`).
     - Coordinator verifies the VRF proof (via precompiles) and calls
       `VRFv2Consumer.fulfillRandomWords(requestId, randomWords)`.
     - Consumer sets `s_requests[requestId].fulfilled = true` and stores the single
       random word, emitting a `RequestFulfilled` event.
     - The consumer **does not** call RoulettePotV2 or other contracts in this tx.
   - Evidence:
     - `receipt.json` and `debug_trace_callTracer.json` for the tx.
     - `VRFv2Consumer.sol` and `VRFConsumerBaseV2.sol` source.

3. **Round settlement and profit extraction**
   - Tx: `0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490`
   - Block: `45668286`
   - Effect:
     - Helper contract `0x0000…Bb1B`, funded via a Pancake V3 flash loan, calls
       `RoulettePotV2.finishRound()` to consume the VRF result for
       `requestId 0x7ad08c2f…703f` and settle all pending bets in round `18580`.
     - RoulettePotV2:
       - Transfers a very large XENCrypto reward and `20 BNB` to
         `0xdfAc…C286`.
       - Updates casino liquidity and profit, unlocking previously locked amounts.
     - `swapProfitFees()` then:
       - Swaps accumulated profit tokens to BNB and LINK through PancakeRouter.
       - Funds the LINK-based VRF subscription via PegSwap and LINK677.
       - Leaves approximately **19.5203 BNB** residual profit at `0x0000…4F80`
         after flash-loan repayment.
   - Evidence:
     - `trace.cast.log` and `balance_diff.json` for the tx (Snippets 4 and 5).
     - `RouletteV2.finishRound()` and `swapProfitFees()` implementations.

Overall, the adversary’s flow leverages legitimate contract features and a favorable VRF outcome rather than exploiting a deviation from expected behavior.

---

## Impact & Losses

### Quantitative impact

- **Token:** BNB  
- **Total net profit to adversary cluster:**  
  - **39.520332279709631513 BNB**

This figure comes from:
- +19.520332279709631513 BNB to `0x0000…4F80` (flash-loan orchestrator), and
- +20 BNB to `0xdfAc…C286` (player EOA),
as reported in `balance_diff.json` for the seed settlement transaction.

### Qualitative impact

From the protocol’s perspective:

- Approximately **39.52 BNB** of combined casino and AMM (WBNB/LP/router) liquidity is transferred to the adversary cluster as:
  - Roulette payouts, and
  - Profit-fee conversions executed by `swapProfitFees()`.
- These transfers:
  - Are **consistent** with the documented game rules and fee logic.
  - Do not introduce insolvent states or invariant violations in the balance diffs.
  - Do not harm third-party users beyond the **normal risk of loss** associated with
    participating in a fair but high-variance roulette game.

In other words, stakeholders experience a **large but expected game outcome**, not a protocol exploit.

---

## References

The analysis relies on the following primary artifacts:

- **[1] Seed flash-loan settlement tx trace and balance diffs**  
  - Seed tx: `0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490`  
  - Artifacts: `trace.cast.log`, `balance_diff.json`.

- **[2] requestNonce tx for roundId 18580**  
  - Tx: `0x2703bdba360c705f59197cf84123fce01a3a526ec79c31fd1e436f34247764d7`  
  - Artifacts: `receipt.json`, `debug_trace_callTracer.json`, `debug_trace_prestateTracer.json`.

- **[3] VRF callback tx for requestId 0x7ad08c2f…703f**  
  - Tx: `0x0d16e86689fb46f825f878b1e25f24df7d254ff26a96d08ee535437228b94275`  
  - Artifacts: `receipt.json`, `debug_trace_callTracer.json`, `debug_trace_prestateTracer.json`.

- **[4] RoulettePotV2 (RouletteV2.sol) verified source**  
  - Contract: `0xf573748637E0576387289f1914627d716927F90f`  
  - Key functions: `_requestVRF`, `_updateRoundStatus`, `initializeTokenBet`, `initializeEthBet`, `finishRound`, `_spinWheel`, `swapProfitFees`.

- **[5] VRFv2Consumer.sol verified source**  
  - Contract: `0x30262cab106e2411B052ca83cd9Aa51e23678BfB`  
  - Key functions: `requestRandomWords`, `fulfillRandomWords`, `getRequestStatus`.

---

## All Relevant Transactions (Summary)

For completeness, the analysis considers the following transaction set:

- `0x3290d08b…` (seed transaction; supporting context in early game behavior).
- `0x2703bdba360c705f59197cf84123fce01a3a526ec79c31fd1e436f34247764d7` – `requestNonce` (player triggers VRF request).
- `0x0d16e86689fb46f825f878b1e25f24df7d254ff26a96d08ee535437228b94275` – VRF fulfill (oracle delivers randomness).
- `0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490` – flash-loan settlement (round settlement, fee swaps, and profit realization).

Each of these transactions behaves consistently with the verified contract code and the non-exploit conclusion described above.

