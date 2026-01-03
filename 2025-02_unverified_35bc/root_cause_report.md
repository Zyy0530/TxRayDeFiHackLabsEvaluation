# BSC staking pool reentrancy drain via releaseSlot(3)

Protocol: Unknown BSC staking pool (0xde91e6e9...)
Category: protocol_bug

## Incident Overview & TL;DR

On BSC (chainid 56) in block 46886078, an unprivileged EOA 0xd75652... deployed a wrapper and helper contract that repeatedly invoked the unverified staking pool 0xde91e6e9...::releaseSlot(3), causing the pool to send out 10.2 BNB while the attacker cluster received 10.8 BNB back in the same transaction and realized 10.19939358405 BNB of net profit after gas.

The pool's releaseSlot(uint256) function is reentrancy-vulnerable: it calls address(msg.sender).transfer(payout) before clearing the caller's slot and reconciling global accounting, so a helper contract can re-enter releaseSlot(3) multiple times to withdraw the same 0.6 BNB position seventeen times while slot-level storage and the global slot-21 counter end the tx in a state consistent with only a single release.

## Key Background

- 0xde91e6e9... is an unverified BSC staking pool contract whose Heimdall decompilation exposes withdrawPool(address,uint256), unlockSlot(uint256), and releaseSlot(uint256) entry points, with poolBalance stored at slot 17, an owner-withdrawn accumulator store_e at slot 22, and a global 18-decimal counter updated by releaseSlot() at storage slot 21.
- Normal user withdrawals call releaseSlot(slotId), which in the baseline tx 0xe73ea76d... pay exactly 0.6 BNB to the user, clear several keccak256-based per-slot mappings keyed on (slotId,msg.sender), and decrease slot 21 from 0x2a9ad4bc047300000 to 0x2a159aaee15f40000, corresponding to a 0.6 BNB decrement in the global counter.
- Normal owner withdrawals call withdrawPool(address,uint256), which in the baseline tx 0x334b8feb... subtract a chosen amount from poolBalance at slot 17, add the same amount to store_e at slot 22, and transfer that amount to the owner 0xe07e7586..., with no reentrancy and with poolBalance and store_e moving by 30.772858520523236121 BNB as expected.

## Vulnerability & Root Cause Analysis

releaseSlot(uint256) sends BNB to msg.sender via address(msg.sender).transfer(payout) before clearing the caller's slot and updating the global slot-21 counter, allowing a re-entrant helper contract to repeatedly withdraw a single 0.6 BNB position within one transaction while internal accounting only reflects a single release.

Heimdall decompilation of 0xde91e6e9... shows that releaseSlot(uint256 slotId) computes a payout from per-slot mappings (storage_map_k/l/m/o) and a fee parameter unresolved_d27ca89b, then immediately executes address(msg.sender).transfer(payout) while storage_map entries and the global counter at slot 21 still reflect an unredeemed position. In the normal releaseSlot(3) tx 0xe73ea76d..., this flow yields a single 0.6 BNB transfer to 0x8d785aab..., clears the mappings keyed by keccak256(slotId,msg.sender), and decreases slot 21 from 0x2a9ad4bc047300000 to 0x2a159aaee15f40000 (a 0.6 BNB decrement) while poolBalance at slot 17 and store_e at slot 22 remain unchanged. In the incident tx 0xd7a61b07..., helper 0x0A2f4D... first forwards 0.6 BNB into the pool, then its fallback re-enters releaseSlot(3) seventeen times: storage changes show slot 21 being updated eighteen times (one +0.6 BNB increment and seventeen -0.6 BNB decrements) so that the final slot-21 value equals its initial value, while the per-slot mappings keyed by (slotId=3,msg.sender=0x0A2f4D...) are only cleared once at the end of the nested calls. State diffs confirm that poolBalance at slot 17 drops by 10.2 BNB (matching the 10.2 BNB native balance loss from 10.611771813878061839 to 0.411771813878061839), but store_e at slot 22 does not increase by 10.2 BNB, so the internal accounting ends with a state consistent with a single 0.6 BNB release while 10.2 BNB has actually left the contract. The root cause is this reentrancy window in releaseSlot(), where external control is handed to msg.sender before slot and global counters are updated, combined with the fact that poolBalance and store_e are not tied to the per-slot release accounting.

### Affected Components
- Pool contract 0xde91e6e937ec344e5a3c800539c41979c2d85278::releaseSlot(uint256)
- Helper-controlled interaction pattern via contract 0x0A2f4DA966319C14Ee4C9f1A2BF04fE738DF3Ce5

### Code and State Evidence

**Pool `releaseSlot(uint256)` logic (Heimdall decompilation)**

```solidity
function releaseSlot(uint256 arg0) public { ... address(msg.sender).transfer(storage_map_m[var_f] - ((storage_map_m[var_f] * unresolved_d27ca89b) / 0x64)); ... }
```
This decompiled snippet (from the victim pool contract) shows `releaseSlot` sending BNB to `msg.sender` before clearing the slot mappings and updating global counters, creating a reentrancy window.

**Baseline user `releaseSlot(3)` trace**

```text
0xDE91E6E9...::releaseSlot(3) -> 0x8d785A... fallback{value: 600000000000000000}
storage @21: 0x2a9ad4bc047300000 -> 0x2a159aaee15f40000
```
This baseline trace (from the non-adversarial user transaction) shows a single 0.6 BNB payout and a one-step decrease of storage slot 21, matching the intended single-release behavior.

**Incident tx reentrant `releaseSlot(3)` pattern**

```text
helper 0x0A2f4D... sends 0.6 BNB to pool 0xde91e6e9... once
pool sends 0.6 BNB back to helper seventeen times (10.2 BNB total)
storage @21 updated up and down in 0.6 BNB steps, ending at its original value
```
This summary (from the incident trace and state diff) illustrates the reentrant loop: one deposit, seventeen payouts, and slot-21 accounting that ends consistent with a single release despite a 10.2 BNB outflow.

## Adversary Flow Analysis

Single-transaction, helper-mediated reentrancy attack on releaseSlot(3): a funding contract 0xcafd2f0a... primes EOA 0xd75652... with 0.81492334 BNB in tx 0x2ba6bf09..., the EOA then deploys wrapper 0x4634C13E... and helper 0x0A2f4D... in tx 0xd7a61b07..., forwards 0.6 BNB into the helper, and lets the helper repeatedly re-enter releaseSlot(3) to collect 10.2 BNB from the pool before aggregating 10.8 BNB back to the EOA.

### Adversary Cluster
- `0xd75652ada2f6a140f2ffcd7cd20f34c21fbc3fbc` (EOA): Sends incident tx 0xd7a61b07..., deploys wrapper 0x4634C13E..., and ultimately receives 10.8 BNB from the wrapper; balance diffs show a net gain of 10.19939358405 BNB.
- `0x4634C13E68DDf52CEFd0a7a1E6002ab4747cDE7b` (contract): Deployed by 0xd75652... in tx 0xd7a61b07..., deploys helper 0x0A2f4D..., forwards 0.6 BNB into the helper, then receives 10.8 BNB from the helper and forwards it to the EOA; txlist_normal and traces show no other activity.
- `0x0A2f4DA966319C14Ee4C9f1A2BF04fE738DF3Ce5` (contract): Deployed by wrapper 0x4634C13E... in tx 0xd7a61b07...; decompiled code forwards msg.value to 0xde91e6e9... using address(pool).transfer(msg.value), and txlist_internal plus traces show it receiving 0.6 BNB from the wrapper, sending 0.6 BNB to the pool once, receiving seventeen 0.6 BNB transfers back (10.2 BNB), and then sending 10.8 BNB to the wrapper.
- `0xcafd2f0a35a4459fa40c0517e17e6fa2939441ca` (contract): Long-range txlists show 0xcafd2f0a... as a funding/relay contract that, via internal call 0x2ba6bf09..., sends 0.81492334 BNB (814923340000000000 wei) to 0xd75652... at block 46885850, shortly before the incident; it has no direct interaction with the pool, so it is best classified as a funding address linked to the adversary cluster by value flow.

### Victim and Other Related Accounts
- Unknown BSC staking pool - `0xde91e6e937ec344e5a3c800539c41979c2d85278`

## Impact & Losses

On-chain native balance diffs show pool 0xde91e6e9... losing exactly 10.2 BNB in the incident tx while the attacker EOA gains 10.19939358405 BNB net after gas. The loss is concentrated in a single pool contract and is a direct drain of the pool's native backing as evidenced by the pool's 10.2 BNB balance reduction; on-chain data does not distinguish whether the economic loss ultimately falls on individual stakers or on a protocol treasury that owned the pool's balance.

### Loss Summary
- 10.2 BNB

## References

Key supporting artifacts:

- [1] Seed tx metadata and trace for 0xd7a61b07... (artifacts/root_cause/seed/56/0xd7a61b07ca4dc5966d00b3cc99b03c6ab2cee688fa13b30bea08f5142023777d/)
- [2] Pool state diff and balance diffs around incident (artifacts/root_cause/data_collector/iter_4/contract/56/0xde91e6e9.../state_diff_prestate.json)
- [3] Heimdall decompilations for pool, helper, and wrapper (artifacts/root_cause/data_collector/iter_1/contract/56/)
- [4] Baseline user and owner traces (releaseSlot(3) and withdrawPool) (artifacts/root_cause/data_collector/iter_4/tx/56/)
