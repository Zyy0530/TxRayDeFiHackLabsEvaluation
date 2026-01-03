# Laundromat 1 ETH Withdrawal – Cryptographically Authorized, Non-ACT

**Protocol:** Laundromat (contract `0x934cbbe5377358e6712b5f041d90313d935c501c` on Ethereum mainnet)  
**ACT classification:** Non-ACT (`is_act = false`, `root_cause_category = "other"`)

Two on-chain transactions fully explain the lifecycle of the affected funds:

- Deposit tx `0x258407b03f11f0b26f287570eb47bce78294335db16abb9acd9789a11ed27e69` (role: victim-observed).
- Withdrawal / incident tx `0x08ffb5f7ab6421720ab609b6ab0ff5622fba225ba351119c21ef92c78cb8302c` (role: seed).

The ACT opportunity is defined at block height **2796628**, immediately before the deposit when the Laundromat contract has zero ETH balance and empty storage.

---

## Incident Overview & TL;DR

A single 1 ETH deposit was made into Laundromat `0x934c...` on Ethereum mainnet by EOA `0x8c6562b4742b428d6c5f6fab564498ac09cfb0c2`. A later transaction by EOA `0xd6be07499d408454d090c96bd74a193f61f706f4`, using a short-lived helper contract, withdrew exactly that same 1 ETH after satisfying Laundromat's elliptic-curve witness checks.

On-chain traces, balance diffs, and contract-level cryptographic analysis show that the withdrawal was executed via a valid witness under the protocol's design. No anyone-can-take opportunity or protocol bug is evidenced. The event is therefore best classified as a **cryptographically authorized withdrawal** rather than an exploit.

From an exploit-predicate standpoint, the incident yields profit to the withdrawing EOA but only by exercising the intended witness-gated withdrawal path for a previously deposited 1 ETH:

- Reference asset: **ETH**.
- Adversary address (for profit accounting): `0xd6be07499d408454d090c96bd74a193f61f706f4`.
- Fees paid: approximately **0.0036 ETH**.
- Value before: approximately **0 ETH**.
- Value after: approximately **0.9964 ETH**.
- Value delta: approximately **+0.9964 ETH**, matching a 1 ETH withdrawal less gas.

No non-monetary exploit predicate is identified (the non-monetary oracle fields are empty).

---

## Key Background

Laundromat `0x934c...` is an Ethereum mainnet contract whose verified source and static selector analysis indicate that:

- It manages deposits keyed by elliptic-curve public keys.
- Deposits are created via a `deposit(uint256 _pubkey1, uint256 _pubkey2)` function that stores commitments derived from the supplied public-key components in contract storage and increases the contract's ETH balance by the deposited amount.
- Withdrawals are executed via a function with selector `0x9ebb1250`, which performs elliptic-curve computations using the external library `ArithLib` at `0x600ad7b57f3e6aeee53acb8704a5ed50b60cacd6`. When the elliptic-curve witness checks pass, the contract executes a `CALL` that sends the locked ETH to a recipient address supplied in calldata.

The elliptic-curve library itself is a standalone, verified contract that implements the necessary group operations and hash-to-curve primitives.

```solidity
// Collected verified source for ArithLib (0x600a...)
pragma solidity ^0.4.0;

contract ArithLib {
    uint constant internal P = 115792089237316195423570985008687907853269984665640564039457584007908834671663;
    uint constant internal N = 115792089237316195423570985008687907852837564279074904382605163141518161494337;
    uint constant internal M = 57896044618658097711785492504343953926634992332820282019728792003956564819968;
    uint constant internal Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240;
    uint constant internal Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424;

    function jdouble(uint _ax, uint _ay, uint _az) constant returns (uint, uint, uint) {
        if (_ay == 0) return (0, 0, 0);
        // ... elliptic-curve doubling logic ...
    }

    function jadd(uint _ax, uint _ay, uint _az, uint _bx, uint _by, uint _bz) constant returns (uint, uint, uint) {
        if (_ay == 0) return (_bx, _by, _bz);
        if (_by == 0) return (_ax, _ay, _az);
        // ... elliptic-curve addition logic ...
    }
}
```

*Caption: Collected verified elliptic-curve arithmetic library used by Laundromat for witness verification (ArithLib at `0x600a...`).*

---

## Vulnerability & Root Cause Analysis

### ACT Opportunity and Pre-State

The ACT opportunity is defined at block height **2796628**, immediately before the 1 ETH deposit into Laundromat. The pre-state \(\sigma_B\) is:

- Chain: Ethereum mainnet.
- Laundromat (`0x934c...`) has **0 ETH** balance and **empty storage**.
- No prior deposits or commitments exist for this contract.

This pre-state is evidenced by:

- A **prestateTracer diff** for deposit tx `0x258407b0...`.
- The historical tx list for Laundromat `0x934c...` showing no earlier activity.

A minimal excerpt of the prestateTracer diff illustrates the transition from an empty contract to holding 1 ETH and initialized storage commitments:

```json
{
  "result": {
    "pre": {
      "0x934cbbe5377358e6712b5f041d90313d935c501c": {
        "balance": "0x0",
        "code": "0x6060...",  
        "storage": {}
      }
    },
    "post": {
      "0x934cbbe5377358e6712b5f041d90313d935c501c": {
        "balance": "0xde0b6b3a7640000",  
        "storage": {
          "0x6": "0x1",
          "0x7": "0x1",
          "0x8": "0x1",
          "0xa66c...": "0x03f2...",
          "0xf3f7...": "0x582d..."
        }
      }
    }
  }
}
```

*Caption: Deposit transaction prestate/poststate showing Laundromat `0x934c...` moving from zero balance and empty storage to 1 ETH balance with initialized elliptic-curve commitments (deposit tx `0x258407b0...`).*

### No On-Chain Vulnerability Demonstrated

The analysis concludes that **no protocol-level vulnerability or access-control bug is demonstrated**:

- **Deposit behavior:** The `deposit(uint256,uint256)` entry point stores elliptic-curve commitments (e.g., in slots `0x6`, `0x7`, `0x8` and keccak-keyed slots) and credits the contract's ETH balance. Deposits are keyed by public-key data, not by plain addresses.
- **Withdrawal behavior:** The `0x9ebb1250` selector is the withdrawal executor. Static selector analysis shows that it:
  - Reads commitments and note queues from multiple storage mappings.
  - Invokes ArithLib (`0x600a...`) to perform elliptic-curve computations and recompute expected commitments from calldata-supplied witness data.
  - When the witness checks succeed, executes an external `CALL` that sends ETH out of Laundromat to a recipient derived from storage and/or calldata.
- **Access control model:** No simple `require(msg.sender == depositor)` pattern is present. Instead, **knowledge of the correct cryptographic witness** is the sole gate that authorizes withdrawal. This is consistent with a privacy/obfuscation-focused design where cryptographic ownership, rather than plain account ownership, controls spending rights.

Given this structure and the available traces:

- There is **no code path** that allows withdrawal using only publicly visible on-chain data. 
- There is **no evidence** of arithmetic errors, missing checks, or other logic flaws that would allow an unprivileged, keyless adversary to withdraw funds they cannot cryptographically authorize.

### Root Cause Summary

The root cause is therefore characterized as follows:

- The contract correctly **stores elliptic-curve commitments** for a 1 ETH deposit and later **verifies an elliptic-curve witness** supplied in calldata.
- When the witness is valid, Laundromat **releases exactly 1 ETH** via a `CALL` that ultimately pays EOA `0xd6be...` (through the helper contract).
- The **witness requires non-public secrets** tied to the deposited public keys, so only a holder of those secrets (or someone to whom they were delegated) can construct it.
- No anyone-can-take opportunity is demonstrated under the ACT framework.

As a result, the incident is attributed to **a holder of the requisite cryptographic secrets exercising their withdrawal capability**, not to an exploit of the on-chain protocol.

### Vulnerable Components and Exploit Conditions

In line with this conclusion:

- **Vulnerable components:**
  - No exploitable on-chain component is identified.
  - Laundromat `0x934c...` and ArithLib `0x600a...` both operate as designed in the observed transactions.
- **Exploit conditions:**
  - There is **no condition** under which an unprivileged adversary, using only public on-chain information at or before the incident, can construct a valid withdrawal witness for the observed 1 ETH deposit.
- **Security principles violated:**
  - No on-chain security principle is violated in the observed behavior.
  - The main residual risk lies in **off-chain key management** or sharing of the cryptographic secrets required to construct valid witnesses.

---

## Adversary Flow Analysis

### High-Level Strategy

The observed flow is a straightforward two-transaction lifecycle:

1. A 1 ETH deposit into Laundromat keyed by elliptic-curve public-key components.
2. A later **cryptographically authorized withdrawal** of that same 1 ETH using a short-lived helper contract that forwards funds to the withdrawing EOA.

### Adversary-Related Accounts and Victim Candidate

The analysis identifies the following adversary-related cluster and victim candidate:

- **Adversary cluster:**
  - EOA `0xd6be07499d408454d090c96bd74a193f61f706f4` (Ethereum mainnet)
    - Sends the incident transaction `0x08ffb5f7...`.
    - Deploys helper contract `0x2E95CFC93EBb0a2aACE603ed3474d451E4161578` in the same transaction.
    - Ultimately receives the 1 ETH withdrawal via the helper's `SELFDESTRUCT` payout.
  - Helper contract `0x2E95CFC93EBb0a2aACE603ed3474d451E4161578` (Ethereum mainnet)
    - Deployed by `0xd6be...` in the incident transaction.
    - Receives 1 ETH from Laundromat `0x934c...`.
    - Immediately `SELFDESTRUCT`s, sending its entire balance to `0xd6be...`.

- **Victim candidate:**
  - Laundromat contract `0x934cbbe5377358e6712b5f041d90313d935c501c` (Ethereum mainnet), with verified source.
    - Tracks elliptic-curve-keyed deposits and enforces witness-based withdrawals.
    - Holds 1 ETH after the deposit and returns to 0 ETH after the withdrawal.

### Lifecycle Stages and Evidence

#### Stage 1 – 1 ETH Deposit into Laundromat

- **Transaction:** `0x258407b03f11f0b26f287570eb47bce78294335db16abb9acd9789a11ed27e69` (Ethereum mainnet, block `2796628`; mechanism: `transfer`).
- **Mechanics:**
  - EOA `0x8c6562b4742b428d6c5f6fab564498ac09cfb0c2` calls Laundromat `0x934c...` with selector `0xe2bbb158` (`deposit(uint256,uint256)`).
  - The call sends **1 ETH** and two 32-byte public-key components.
  - Laundromat's balance increases from **0 to 1 ETH**.
  - Storage slots, including `0x6`, `0x7`, and `0x8`, are set to `0x1`, and additional keccak-keyed slots store elliptic-curve commitments tied to the deposit.
- **Evidence used:**
  - PrestateTracer diff for the deposit tx.
  - Laundromat's address tx history confirming this is the first 1 ETH deposit.

A snippet from the prestateTracer diff (see earlier JSON excerpt) shows this state transition and confirms that the contract had no prior balance or storage before the deposit.

#### Stage 2 – Cryptographically Authorized Withdrawal via Helper Contract

- **Transaction:** `0x08ffb5f7ab6421720ab609b6ab0ff5622fba225ba351119c21ef92c78cb8302c` (Ethereum mainnet, block `14107039`; mechanism: `other`).
- **Mechanics:**
  - EOA `0xd6be...` deploys helper contract `0x2E95...` in the same transaction.
  - The helper makes a sequence of calls into Laundromat using deposit-like and preparation selectors (e.g., `0xe2bbb158` and `0x1a6c9c0d`) to register or manipulate elliptic-curve parameters.
  - Finally, the helper invokes Laundromat with selector `0x9ebb1250`, which drives a series of elliptic-curve computations in ArithLib `0x600a...` and, once checks pass, causes Laundromat to send exactly **1 ETH** to the helper contract.
  - The helper then `SELFDESTRUCT`s, forwarding the 1 ETH to EOA `0xd6be...`.
  - Laundromat's ETH balance drops from **1 ETH back to 0**, and its storage counters remain consistent with a single fully withdrawn deposit.
- **Evidence used:**
  - A combined call trace for the incident transaction (cast `callTracer` output).
  - Balance diffs for the incident transaction.
  - Selector-level static analysis report for Laundromat confirming the role of `0x9ebb1250` as the withdrawal executor.

The beginning of the call trace illustrates repeated deposit-style calls from the helper into Laundromat, followed by a more complex call that includes ArithLib interactions:

```json
[
  {
    "from": "0x2e95cfc93ebb0a2aace603ed3474d451e4161578",
    "to": "0x934cbbe5377358e6712b5f041d90313d935c501c",
    "type": "CALL",
    "input": "0xe2bbb158...",
    "value": "0x0"
  },
  {
    "from": "0x2e95cfc93ebb0a2aace603ed3474d451e4161578",
    "to": "0x934cbbe5377358e6712b5f041d90313d935c501c",
    "type": "CALL",
    "input": "0x1a6c9c0d...",
    "value": "0x0",
    "calls": [
      {
        "from": "0x934cbbe5377358e6712b5f041d90313d935c501c",
        "to": "0x600ad7b57f3e6aeee53acb8704a5ed50b60cacd6",
        "type": "CALL",
        "input": "0xd876fb21...",
        "value": "0x0"
      }
    ]
  }
]
```

*Caption: Seed transaction call trace for tx `0x08ffb5f7...`, showing helper contract `0x2E95...` calling Laundromat `0x934c...`, which in turn calls ArithLib `0x600a...` to evaluate elliptic-curve relations before withdrawal.*

The balance diff for the incident transaction confirms that 1 ETH moves from Laundromat to the withdrawing EOA, with a small gas loss:

```json
{
  "native_balance_deltas": [
    {
      "address": "0xd6be07499d408454d090c96bd74a193f61f706f4",
      "before_wei": "50000000000000000",
      "after_wei": "1046407109528025240",
      "delta_wei": "996407109528025240"
    },
    {
      "address": "0x934cbbe5377358e6712b5f041d90313d935c501c",
      "before_wei": "1000000000000000000",
      "after_wei": "0",
      "delta_wei": "-1000000000000000000"
    }
  ]
}
```

*Caption: Seed transaction balance diff for tx `0x08ffb5f7...`, showing 1 ETH transferred from Laundromat `0x934c...` to the `0xd6be...` cluster (net ~0.9964 ETH after gas).*


---

## Impact & Losses

The on-chain impact is limited to the 1 ETH lifecycle within Laundromat:

- **Total loss overview:**
  - Token: **ETH**.
  - Amount: **1 ETH**.

- **Impact narrative:**
  - Laundromat `0x934c...` releases 1 ETH that was previously locked as a single deposit.
  - The released 1 ETH is received by EOA `0xd6be...` via the helper contract.
  - This transfer reflects the exercise of a **cryptographically authorized withdrawal path**, not exploitation of an anyone-can-take protocol bug.
  - No broader pool drain, insolvency event, or cascading impact is observed in the collected on-chain history.

---

## References

Key supporting artifacts used in this analysis are:

- **[1] Deposit tx prestateTracer diff for `0x258407b0...`**  
  Captures the state transition for the 1 ETH deposit into Laundromat, including the initialization of storage commitments and the contract's ETH balance.

- **[2] Incident tx combined trace for `0x08ffb5f7...`**  
  Provides the full call tree showing the helper contract calling Laundromat, which then invokes ArithLib and eventually releases 1 ETH to the helper/EOA cluster.

- **[3] Laundromat `0x934c...` verified source and selector analysis**  
  Confirms the roles of deposit and withdrawal selectors (including `0xe2bbb158` and `0x9ebb1250`) and the use of ArithLib for elliptic-curve witness verification.

- **[4] ArithLib `0x600a...` verified source**  
  Provides the elliptic-curve arithmetic and hash-to-curve primitives relied upon by Laundromat to enforce cryptographic authorization of withdrawals.

