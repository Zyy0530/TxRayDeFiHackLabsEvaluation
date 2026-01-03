# Reentrancy-Based Referral Payout Drain of 0x9823... on BSC

## Incident Overview & TL;DR

An unprivileged attacker on BSC used a custom helper contract stack to exploit a reentrancy vulnerability in the referral payout logic of marketplace contract `0x9823E10A0bF6F64F59964bE1A7f83090bf5728aB`. In a single transaction, they repeatedly invoked `claimReferral(address)` via attacker-controlled contracts `0xd4c8...`, `0xB4C3...`, and `0x8F32...`, draining exactly 138 BNB from the marketplace and realizing approximately 137.85 BNB net profit after gas.

The root cause is a protocol-level bug in `claimReferral(address)`: the function reads a referral balance from storage, performs external calls (including value-bearing transfers) to the supplied address, and only then clears the referral balance in storage. It also lacks any reentrancy guard. This design allows attacker-controlled contracts to re-enter `claimReferral` while the balance remains non-zero, causing multiple payouts in a single transaction.

## Key Background

- The contract at `0x9823E10A0bF6F64F59964bE1A7f83090bf5728aB` is a marketplace-style protocol on BSC. It manages item listings, offers, owner cut percentages, and referral rewards. Referral balances are tracked in a mapping referred to (in the decompile) as `storage_map_g`, keyed by a combination of `msg.sender` and a token/referrer address.
- Referral rewards are configured via owner-only functions such as `setReferralFee(uint256)` and another owner-only routine (`Unresolved_5409ebc1(address,uint256)` in the decompile) that writes referral balances into `storage_map_g`. Withdrawals are exposed through the public `claimReferral(address)` entrypoint, which is meant to transfer accumulated referral balances to a chosen address.
- Helper contract `0xB4C32404de3367Ca94385ac5b952a7a84B5BdF76` (often abbreviated `0xB4C3...`) contains a `testAttack()` function that is explicitly restricted to `tx.origin == 0xfb1c...` (the attacker EOA). It uses standard DeFi building blocks including Wrapped BNB (`WBNB`), deposit/withdraw flows, ERC‑20 transfers, and a router/pool at `0x172fcd41e0913e95784454622d1c3724f546f849` (`0x172f...`) to move BNB/WBNB liquidity.
- Forwarder contract `0x8F327e60Fb2a7928c879C135453Bd2b4eD6B0fE9` (abbreviated `0x8F32...`) implements a function decoded as `50eb1dfe(address,uint256)`. This function forwards `msg.value` and an amount parameter into a `0x60acd67f(...)` call on an arbitrary target. In the exploit, `0xB4C3...` uses this forwarder to reach functions on `0x9823...`.
- In the seed transaction, a fresh adversary contract `0xd4c80700Ca911D5d3026a595E12Aa4174F4cACb3` (`0xd4c8...`) is deployed. Its constructor wires together `0x9823...`, `0xB4C3...`, `0x8F32...`, `WBNB`, and router/pool `0x172f...`, then executes an exploit path that repeatedly re-enters `claimReferral` until the marketplace’s BNB balance is exhausted.

## ACT Opportunity and Exploit Predicate

### System State σ_B and Block Height

- **Block height B:** `46843424` on BSC (chainid 56).
- **Pre-state σ_B:** Defined as BSC chain state at block `46843423`, immediately before inclusion of the seed transaction `0xef386a69ca6a147c374258a1bf40221b0b6bd9bc449a7016dbe5240644581877` (abbreviated `0xef38...877`). In this pre-state:
  - Marketplace contract `0x9823...` holds at least 138 BNB and has non-zero referral balances recorded in its `storage_map_g` mapping.
  - Helper contracts `0xB4C3...` and `0x8F32...` and router/pool `0x172f...` are already deployed and callable.
  - No special privileges are granted to the attacker EOA beyond standard, unprivileged EVM execution.
- **Key evidence for σ_B:**
  - Seed index: trace and balance diff references confirming the seed tx and pre/post-state.
  - Seed metadata for `0xef38...877` describing the transaction type, sender, and deployment of `0xd4c8...`.
  - Seed balance diff showing initial and final balances for `0x9823...`, `0xfb1c...`, WBNB, and an intermediate address.
  - Runtime bytecode and decompiled Solidity for `0x9823...` at σ_B, confirming the presence of referral and payout logic.

```json
// Seed index entry for tx 0xef38...877 (BSC)
{
  "chainid": 56,
  "txhash": "0xef386a69ca6a147c374258a1bf40221b0b6bd9bc449a7016dbe5240644581877",
  "artifacts": {
    "metadata": { "status": "ok" },
    "trace": { "status": "ok" },
    "balance_diff": { "status": "ok" }
  }
}
```
*Caption: Seed index confirming the BSC seed transaction and its supporting artifacts (metadata, trace, and balance diff).*

### Transaction Sequence b

Sequence **b** contains a single adversary-crafted transaction on BSC:

- **Index:** `1`
- **Chainid:** `56` (BSC)
- **Txhash:** `0xef386a69ca6a147c374258a1bf40221b0b6bd9bc449a7016dbe5240644581877`
- **Type:** `adversary-crafted` contract-creation, Type 0x2.
- **Inclusion feasibility:** The tx originates from unprivileged EOA `0xfb1cc1548d039f14b02cff9ae86757edd2cdb8a5` with standard gas limits and a 10 gwei gas price. It deploys helper/orchestrator contract `0xd4c8...` and, within the constructor, only interacts with publicly deployed contracts (`0x9823...`, `0xB4C3...`, `0x8F32...`, WBNB, and router/pool `0x172f...`). No admin-only entrypoints, privileged opcodes, or special roles are used; any unprivileged adversary could construct and submit equivalent calldata under the same public state.
- **Notes on sequence b:** Within this single transaction, `0xd4c8...` orchestrates its helper stack to call into `0x9823...::claimReferral(address)` repeatedly and drain the marketplace contract’s BNB balance. No additional priming transactions are required in sequence b beyond the pre-existing referral balances assumed in σ_B; referral balances are configured by the protocol before σ_B, and the exploit purely consumes them via reentrancy.

### Exploit Predicate and Profit

The exploit predicate is **monetary profit** for the adversary cluster denominated in BNB:

- **Reference asset:** `BNB`
- **Adversary primary address:** `0xfb1cc1548d039f14b02cff9ae86757edd2cdb8a5`
- **Fees paid:** `0.02396278` BNB (from `gasUsed = 2,396,278` and `effectiveGasPrice = 10 gwei` in the seed tx receipt).
- **Value before / after:** The absolute pre- and post-wealth of the adversary in BNB terms are not reconstructed (marked as `unknown`), but the delta is computed exactly from seed artifacts.
- **Value delta:** The balance diff shows the adversary EOA gaining `137.876033699999999999` BNB while `0x9823...` loses `138` BNB and WBNB gains `0.1` BNB. After subtracting gas fees, the net profit for the adversary cluster is approximately **137.85207092 BNB**.

```json
// Seed balance diff (simplified)
{
  "0x9823...": { "native_delta": "-138000000000000000000" },
  "0xfb1c...": { "native_delta": "137876033699999999999" },
  "0xbb4c...WBNB": { "native_delta": "100000000000000000" },
  "0xccb4...": { "native_delta": "1" }
}
```
*Caption: Seed balance diff showing 138 BNB leaving 0x9823..., 137.876 BNB accruing to the attacker EOA, and 0.1 BNB moving into WBNB.*

The receipt-derived gas cost combined with the balance diff supports the fee-aware profit calculation without relying on off-chain price data.

## Vulnerability & Root Cause Analysis

### Vulnerability Brief

The `claimReferral(address)` function in `0x9823...` is reentrancy-prone. It:

- Computes and reads a referral balance from the `storage_map_g` mapping, keyed by `(msg.sender, arg0)`.
- Performs external calls to the supplied `arg0` (including ERC‑20-style transfers and a value-bearing call that can revert with messages like `transfer-BNB-failed`).
- Only after these calls does it clear the entry in `storage_map_g`.
- Does not enforce any reentrancy guard or restrict `arg0` to trusted recipients.

As a result, an attacker can supply a specially crafted contract as `arg0`. When `0x9823...` calls that contract during `claimReferral`, the attacker can re-enter `claimReferral` while the referral balance is still non-zero, causing multiple payouts in a single transaction until the contract’s available BNB is drained.

### Code-Level Root Cause Detail

Decompiled and disassembled code for `0x9823...` confirms the structure of `claimReferral(address)` and its interaction with `storage_map_g` and external calls. The function:

- Checks a paused flag and input arguments.
- Constructs a storage key using `KECCAK256(msg.sender, arg0)` and reads a referral balance from `storage_map_g`.
- Constructs and executes an external token transfer (SafeERC20-style) to the `arg0` address and a value-bearing call that may revert with `transfer-BNB-failed`.
- Only after those external calls does it zero out the referral balance from `storage_map_g` and emit `ReferralClaimed` events.

```solidity
// Simplified decompiled pattern for referral accounting (0x9823... decompile)
// storage_map_g[(msg.sender, arg0)] holds a referral balance
require(bytes1(storage_map_g[var_e] / 0x0100...) != 0);
// ...
// external call to a helper/recipient contract with value
(bool success, bytes memory ret0) =
    address(storage_map_k[(0x0a * arg0) + keccak256(var_e)])
        .{ value: var_w ether }Error(var_t);
require(ret0.length == 0);
// eventually, storage_map_g[var_e] is updated/cleared only after calls
storage_map_g[var_e] = storage_map_g[var_e] + arg1; // elsewhere in buy/offer flows
```
*Caption: Decompiled snippet from 0x9823... showing referral balance handling via storage_map_g and external calls before storage is safely updated/cleared.*

The cast trace for the seed transaction shows repeated nested invocations of `0x9823...::claimReferral(0x0000000000000000000000000000000000000000)`. These appear deeper and deeper in the call tree, originating from `0xd4c8...` via `0xB4C3...` and its payable fallback, which in turn invokes `claimReferral` again before state is finalized.

```text
// Seed transaction call stack excerpt (cast trace)
0xd4c8...::constructor(...)
  ├─ 0xB4C3...::fallback{value: 3 BNB}()
  │   ├─ 0x9823...::claimReferral(0x0000000000000000000000000000000000000000)
  │   │   ├─ 0xB4C3...::fallback{value: 3 BNB}()
  │   │   │   ├─ 0x9823...::claimReferral(0x0000000000000000000000000000000000000000)
  │   │   │   │   ├─ 0xB4C3...::fallback{value: 3 BNB}()
  │   │   │   │   │   └─ ← [Revert] transfer-BNB-failed (OutOfFunds)
```
*Caption: Seed transaction trace showing multiple nested re-entries into 0x9823...::claimReferral via 0xB4C3...’s payable fallback, ending in an internal transfer-BNB-failed error.*

The combination of this call stack with the code structure above provides direct evidence of a reentrancy vulnerability: referral balances are read once, external interactions happen before storage clearing, and an attacker-controlled contract re-enters `claimReferral` multiple times.

### Vulnerable Components

The analysis identifies the following concrete vulnerable components:

- `0x9823E10A0bF6F64F59964bE1A7f83090bf5728aB::claimReferral(address)`
- The referral balance mapping `storage_map_g` in `0x9823...`, keyed by `(msg.sender, arg0)`, which is used to accumulate referral rewards and is only cleared after external calls.

### Exploit Preconditions

For the exploit to be possible, the following conditions must hold:

1. **Positive BNB balance and referral balances:** At σ_B, `0x9823...` must hold a positive BNB balance (≥ 138 BNB) and non-zero referral balances in `storage_map_g` for at least one `(caller, arg0)` pair.
2. **Control over caller and arg0:** An unprivileged attacker must be able to control both `msg.sender` and `arg0` in a call to `claimReferral(address)`, for example by calling through an attacker-owned helper contract that passes another attacker-controlled contract as `arg0`.
3. **Reentrant arg0 contract:** The attacker-controlled `arg0` contract must be able to trigger a reentrant call to `0x9823...::claimReferral(address)` when invoked, before the relevant `storage_map_g` entry is cleared.
4. **Checks‑effects‑interactions violation:** The `claimReferral` implementation must read the referral balance before the external call and only clear it after, without any reentrancy guard or restriction preventing re-entries by `arg0`.

### Violated Security Principles

The root cause reflects several standard security failures:

- **Checks‑effects‑interactions violation:** `claimReferral` performs external, value-bearing calls before updating internal state (clearing the referral balance), directly enabling reentrancy.
- **Lack of reentrancy protection:** A high-value public function that sends funds to arbitrary, user-supplied contracts (`arg0`) is exposed without any reentrancy guard.
- **Weak binding of referral balances:** Referral balances in `storage_map_g` are not tightly bound to specific, controlled withdrawal flows. Arbitrary helper contracts satisfying basic interface constraints can drain balances multiple times.

## Adversary Flow Analysis

### Strategy Summary

The adversary executes a single, multi-stage transaction on BSC that:

1. Deploys a custom orchestrator contract (`0xd4c8...`) from EOA `0xfb1c...`.
2. Uses that contract to wire together the victim marketplace `0x9823...`, attacker-controlled helpers `0xB4C3...` and `0x8F32...`, WBNB, and router/pool `0x172f...`.
3. Executes a sequence of swaps and helper calls that repeatedly re-enter `claimReferral(address)` inside the constructor of `0xd4c8...`, draining 138 BNB from `0x9823...` into the adversary cluster.
4. Pays a small amount to WBNB and routing infrastructure plus gas fees, while retaining ~137.85 BNB net profit at the attacker EOA.

### Adversary-Related Accounts and Cluster

The adversary cluster is identified as follows:

- **EOA 0xfb1cc1548d039f14b02cff9ae86757edd2cdb8a5 (BSC, chainid 56)**
  - Type: EOA (`is_eoa = true`, `is_contract = false`).
  - Role: Sender of the seed tx deploying `0xd4c8...`, hard-coded as `tx.origin` in `0xB4C3...::testAttack()`, and ultimate recipient of ~137.876 BNB as per balance diff.
- **Contract 0xd4c80700Ca911D5d3026a595E12Aa4174F4cACb3 (BSC)**
  - Type: Contract (`is_contract = true`).
  - Role: Orchestrator deployed by `0xfb1c...` in the seed tx. Its constructor stores references to `0x9823...`, `0xB4C3...`, `0x8F32...`, WBNB, and `0x172f...`, and drives the exploit call sequence.
- **Contract 0xB4C32404de3367Ca94385ac5b952a7a84B5BdF76 (BSC)**
  - Type: Contract helper (`is_contract = true`).
  - Role: Attack helper whose decompiled `testAttack()` requires `tx.origin == 0xfb1c...`. It interacts with `0x8F32...` and `0x172f...`, forwarding value and tokens along the exploit path. Its transaction history is dominated by the exploit and a later warning message transaction, consistent with attacker-only use.
- **Contract 0x8F327e60Fb2a7928c879C135453Bd2b4eD6B0fE9 (BSC)**
  - Type: Contract forwarder (`is_contract = true`).
  - Role: Helper that implements `50eb1dfe(address,uint256)`, forwarding `msg.value` and an amount parameter into a `0x60acd67f(...)` call on arbitrary targets. It is used by `0xB4C3...` in the exploit path and has no independent external transaction history, indicating it is tightly controlled by the attacker.

The primary victim candidate is:

- **“0x9823... referral marketplace” (`0x9823E10A0bF6F64F59964bE1A7f83090bf5728aB` on BSC, chainid 56)**
  - Identified as the marketplace contract with referral logic, unverified on the explorer but decompiled and disassembled locally.

Infrastructure such as router/pool `0x172f...` is treated as general-purpose DeFi infrastructure rather than attacker-owned assets, based on its broad transaction history involving many unrelated users and UniswapV3-style swaps.

### Lifecycle Stages

The entire adversary lifecycle is contained within the single seed transaction but can be broken into two stages.

#### Stage 1: Adversary Contract Deployment and Wiring

- **Transactions:**  
  - BSC tx `0xef38...877` at block `46843424`, type 0x2, contract-creation from `0xfb1c...`.
- **Effect:**  
  EOA `0xfb1c...` deploys `0xd4c8...`. The constructor:
  - Hard-codes references to marketplace contract `0x9823...`, helper contracts `0xB4C3...` and `0x8F32...`, WBNB, and router/pool `0x172f...`.
  - Sets up the infrastructure required to trigger reentrant `claimReferral` calls and route drained funds back to the attacker.
- **Key evidence:**  
  - Seed metadata for `0xef38...877` indicating contract creation and deployment of `0xd4c8...`.
  - Cast trace showing the constructor of `0xd4c8...` initializing references to `0x9823...`, `WBNB`, and `0x172f...`.
  - Decompiled code for `0xd4c8...` that reveals hard-coded addresses for the marketplace and helpers, consistent with an attacker-prepared orchestrator.

#### Stage 2: Adversary Exploit Execution

- **Transactions:**  
  - Same seed tx `0xef38...877` at block `46843424` (execution occurs within the constructor of `0xd4c8...` after deployment).
- **Effect:**  
  Within the constructor of `0xd4c8...`, the attacker:
  - Uses `0xB4C3...` and `0x8F32...` together with WBNB and `0x172f...` to pull liquidity and route BNB/WBNB value.
  - Invokes `0x9823...::claimReferral(address)` multiple times, passing attacker-controlled helper contracts as `arg0`.
  - Leverages `0xB4C3...`’s payable fallback to re-enter `claimReferral` repeatedly before `storage_map_g` is zeroed.
  - Drains 138 BNB from `0x9823...` to the adversary cluster while a small portion (0.1 BNB) flows into WBNB and minimal amounts go to infrastructure and coinbase.
- **Key evidence:**  
  - The seed cast trace (`trace.cast.log`) showing multiple nested calls to `0x9823...::claimReferral(0x0000...)` in a deep call stack, ending with `OutOfFunds` and `transfer-BNB-failed` while the outer transaction still succeeds.
  - The decompiled marketplace code (`0x9823...-decompiled.sol`) and helper contract disassembly (`0xB4C3...` disassembly) that match the observed call patterns and show no reentrancy guard on `claimReferral`.
  - The seed balance diff (`balance_diff.json`) confirming a 138 BNB decrease in `0x9823...` and a `~137.876` BNB increase in `0xfb1c...`, consistent with multiple payouts and minor routing overhead.

## Impact & Losses

The measured on-chain impact for the seed transaction is:

- **Total loss overview:**
  - `BNB`: `138` (exact) lost from `0x9823...`.

- **Impact details:**
  - Marketplace contract `0x9823...` loses exactly 138 BNB to the adversary cluster in a single transaction.
  - WBNB (`0xbb4c...`) gains 0.1 BNB in the process, reflecting part of the routing path.
  - A tiny residual `+1 wei` balance change appears on an intermediate address `0xccb4...`, and small amounts flow to infrastructure/coinbase per normal execution.
  - No other major token balances are materially affected in the seed tx; the loss is concentrated in BNB.
  - Functionally, the drained BNB represents referral funds or protocol-held capital that should not have been withdrawable in this manner under a secure design.

## References

Key supporting artifacts and their roles:

1. **[1] Seed tx metadata and receipt for 0xef38...877 on BSC**  
   - Contains transaction type, sender (`0xfb1c...`), gas parameters, contract address (`0xd4c8...`), and execution status. Used for block, gas, and deployment details.
2. **[2] Seed tx cast trace highlighting nested `claimReferral` calls and `transfer-BNB-failed`**  
   - Provides the full call tree for the seed tx, showing multiple re-entries into `0x9823...::claimReferral(...)` and the internal `transfer-BNB-failed` revert that occurs near the bottom of the stack while the overall tx succeeds.
3. **[3] Decompiled and disassembled code for 0x9823... marketplace contract**  
   - Supplies code-level evidence of referral accounting via `storage_map_g`, the `claimReferral(address)` implementation, and the checks‑effects‑interactions violation that enables reentrancy.
4. **[4] Decompiled helper contract 0xB4C3... with `testAttack` and `tx.origin` restriction**  
   - Shows that `0xB4C3...` is attacker-only infrastructure (restricted to `tx.origin == 0xfb1c...`) and encodes logic for interacting with `0x9823...`, `0x8F32...`, and `0x172f...` during the exploit.
5. **[5] Forwarder helper contract 0x8F32... implementing `50eb1dfe(address,uint256)`**  
   - Confirms that `0x8F32...` is a thin forwarder used in the helper stack to direct value and calls into `0x9823...` and related contracts.
6. **[6] Balance diff for seed tx showing 138 BNB loss from 0x9823... and 137.876 BNB gain to 0xfb1c...**  
   - Quantifies the victim loss and attacker gain, enabling a fee-aware profit calculation that underpins the exploit predicate.

Together, these artifacts provide a deterministic, code-and-trace-backed explanation of the exploit, the protocol bug in `0x9823...`, and the resulting BNB loss under the ACT framework.

