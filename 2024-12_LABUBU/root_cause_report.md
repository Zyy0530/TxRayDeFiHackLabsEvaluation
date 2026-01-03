# LABUBU self-transfer mint bug exploited via Pancake V3/V2 routing on BNB Chain

**Protocol / Project:** LABUBU token and PancakeSwap pools on BNB Chain
**ACT Report:** true | **Root Cause Category:** protocol_bug

## Incident Overview & TL;DR

On BNB Chain, an adversary-controlled contract exploits a LABUBU ERC20 implementation bug that increases balances on self-transfer, then routes the inflated LABUBU through the LABUBU/VOVOToken Pancake V3 pool and the VOVOToken/WBNB Pancake V2 pair to extract BNB-denominated profit in a single adversary-crafted deployment transaction.

Root cause summary: LABUBU's _transfer logic violates ERC20-style conservation by first subtracting and then overwriting the same balance slot when sender == recipient, which deterministically mints tokens to the caller during self-transfers and enables a profitable swap path against existing AMM liquidity.

## Key Background

- LABUBU is an ERC20-like token on BNB Chain at 0x2ff960f1d9af1a6368c2866f79080c1e0b253997 with a custom _transfer implementation that uses a temporary variable and then writes back to the same storage slot.
- VOVOToken is another ERC20-like token on BNB Chain at 0x58b26c9b2d32df1d0e505bcca2d776698c9be6b6 with standard transfer semantics, and WBNB at 0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c wraps BNB with canonical deposit/withdraw behavior.
- The LABUBU/VOVOToken Pancake V3 pool 0xe70294c3D81ea914A883ad84fD80473C048C028C and VOVOToken/WBNB Pancake V2 pair 0xb98f5322a91019311af43cf1d938AD0c59A6148a were deployed and funded before the exploit, as shown by their txlists and traces, and operate with standard Pancake pricing and fee mechanics.
- Adversaries on BNB Chain can deploy arbitrary contracts and execute complex single-transaction strategies that combine flash-like liquidity usage, custom token logic, and routing through existing AMM pools.

## ACT Opportunity

- **Block height B:** 44751945
- **Pre-state c3_B definition:** BNB Chain state immediately before block 44751945, including deployed LABUBU token 0x2ff960f1d9af1a6368c2866f79080c1e0b253997, VOVOToken 0x58b26c9b2d32df1d0e505bcca2d776698c9be6b6, WBNB 0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c, the LABUBU/VOVOToken Pancake V3 pool 0xe70294c3D81ea914A883ad84fD80473C048C028C, the VOVOToken/WBNB Pancake V2 pair 0xb98f5322a91019311af43cf1d938AD0c59A6148a, and standard Pancake router contracts with their publicly observable balances and storage.
- **Evidence used to reconstruct c3_B:**
  - raw.json
  - artifacts/root_cause/seed/index.json
  - artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/metadata.json
  - artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/trace.cast.log
  - artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/balance_diff.json
  - artifacts/root_cause/data_collector/data_collection_summary.json
  - artifacts/root_cause/data_collector/iter_1/address/56/0x2Ff0Cc42e513535BD56bE20c3E686A58608260CA_txlist.json
  - artifacts/root_cause/data_collector/iter_1/address/56/0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30_txlist.json
  - artifacts/root_cause/data_collector/iter_1/contract/56/0x2Ff0Cc42e513535BD56bE20c3E686A58608260CA/decompile/0x2Ff0Cc42e513535BD56bE20c3E686A58608260CA-decompiled.sol
  - artifacts/root_cause/data_collector/iter_1/contract/56/0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30/decompile/0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30-decompiled.sol
  - artifacts/root_cause/data_collector/iter_1/contract/56/0xe70294c3D81ea914A883ad84fD80473C048C028C/source/src/PancakeV3Pool.sol
  - artifacts/root_cause/data_collector/iter_1/contract/56/0xb98f5322a91019311af43cf1d938AD0c59A6148a/source/src/Contract.sol
  - artifacts/root_cause/seed/_contracts/56/0x2ff960f1d9af1a6368c2866f79080c1e0b253997/source/src/Contract.sol
  - artifacts/root_cause/seed/_contracts/56/0x58b26c9b2d32df1d0e505bcca2d776698c9be6b6/source/src/Contract.sol
  - artifacts/root_cause/seed/_contracts/56/0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c/source/src/Contract.sol
  - artifacts/root_cause/data_collector/iter_2/address/56/0x27441c62dbe261fdf5e1feec7ed19cf6820d583b_txlist.json
  - artifacts/root_cause/data_collector/iter_2/address/56/0x2fF960F1D9AF1A6368c2866f79080C1E0B253997_txlist.json
  - artifacts/root_cause/data_collector/iter_2/address/56/0x58B26C9b2d32dF1D0E505BCCa2D776698c9bE6B6_txlist.json
  - artifacts/root_cause/data_collector/iter_3/address/56/0xe677284adefe23c545d9c4c716132559101ab0b0_txlist.json
  - artifacts/root_cause/data_collector/iter_3/address/56/0xe70294c3D81ea914A883ad84fD80473C048C028C_txlist.json
  - artifacts/root_cause/data_collector/iter_3/address/56/0xb98f5322a91019311af43cf1d938AD0c59A6148a_txlist.json
  - artifacts/root_cause/data_collector/iter_3/tx/56/0xe4e882205d8ec02b8e431ad4cd0c5e5f152ba3643217e7d8faaef412c3f818ad/metadata.json
  - artifacts/root_cause/data_collector/iter_3/tx/56/0xe4e882205d8ec02b8e431ad4cd0c5e5f152ba3643217e7d8faaef412c3f818ad/trace.cast.log
  - artifacts/root_cause/data_collector/iter_3/tx/56/0xe4e882205d8ec02b8e431ad4cd0c5e5f152ba3643217e7d8faaef412c3f818ad/balance_diff.json

### Transaction Sequence b
- Index 1 on chain 56: tx 0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de (adversary-crafted)
  - Inclusion feasibility: From pre-state \u03c3_B on BNB Chain, an unprivileged EOA with sufficient BNB balance and nonce can construct and sign the same type-2 contract-creation transaction as 0x27441c62dbe261fdf5e1feec7ed19cf6820d583b, deploying 0x2Ff0Cc42e513535BD56bE20c3E686A58608260CA with bytecode and calldata fully determined by public LABUBU, VOVOToken, WBNB, and Pancake router/pool metadata. Standard BNB Chain rules accept this transaction when the gas limit, max fee, and nonce are valid, so any unprivileged adversary that submits this transaction with competitive fees attains inclusion without requiring private orderflow or special permissions.
  - Notes: This single adversary-crafted deployment transaction both creates the exploit contract and executes the full exploit path, including helper deployment, LABUBU self-transfer inflation, swaps through the LABUBU/VOVOToken V3 pool and VOVOToken/WBNB V2 pair, and WBNB withdrawal to BNB.

### Exploit Predicate
- **Type:** profit
- **Profit details:**
  - reference_asset: BNB
  - adversary_address: 0x27441c62dbe261fdf5e1feec7ed19cf6820d583b
  - fees_paid_in_reference_asset: unknown
  - value_before_in_reference_asset: 53668375816173750 wei of BNB for 0x27441c62dbe261fdf5e1feec7ed19cf6820d583b (native_balance_deltas.before_wei)
  - value_after_in_reference_asset: 17447702735139275916 wei of BNB for 0x27441c62dbe261fdf5e1feec7ed19cf6820d583b (native_balance_deltas.after_wei)
  - value_delta_in_reference_asset: 17394034359323102166 wei of BNB net gain for 0x27441c62dbe261fdf5e1feec7ed19cf6820d583b in this transaction (native_balance_deltas.delta_wei)
  - valuation_notes: Profit is computed directly from artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/balance_diff.json by taking the native_balance_deltas entry for the origin EOA 0x27441c62dbe261fdf5e1feec7ed19cf6820d583b. The delta_wei value already reflects gas costs and transfers within the transaction, so a strictly positive delta_wei establishes a deterministic net profit in BNB for this EOA over the single adversary-crafted transaction.

## Vulnerability & Root Cause Analysis

Vulnerability brief: LABUBU's _transfer implementation increases the sender's balance when sender == recipient, turning self-transfers into a deterministic local mint primitive that breaks ERC20-style supply and balance conservation.

In artifacts/root_cause/seed/_contracts/56/0x2ff960f1d9af1a6368c2866f79080c1e0b253997/source/src/Contract.sol, LABUBU's _transfer function first subtracts amount from the sender's balance, stores the result in a local variable, and then, when sender == recipient, writes balance + amount back to the same storage slot. During self-transfers, this sequence reduces the balance in the temporary variable but then overwrites the on-chain balance with the original balance plus amount, producing a net increase equal to amount. The seed transaction trace at artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/trace.cast.log shows a loop where helper contract 0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30 calls LABUBU::transfer with from = to = helper and amount = 415636276381601458, and the associated storage writes repeatedly increase the helper's LABUBU balance slot by amount while emitting Transfer events with from == to. This behavior matches the source-level bug and confirms a deterministic self-transfer mint vulnerability. Because LABUBU is integrated into a Pancake V3 pool against VOVOToken, and VOVOToken is paired with WBNB in a Pancake V2 pair, inflated LABUBU balances obtained through this bug can be swapped through these pools to drain VOVOToken and acquire WBNB at the expense of LPs and pool counterparties.

### Vulnerable Components
- LABUBU token contract 0x2ff960f1d9af1a6368c2866f79080c1e0b253997, function _transfer(address,address,uint256)
- LABUBU/VOVOToken Pancake V3 pool 0xe70294c3D81ea914A883ad84fD80473C048C028C
- VOVOToken/WBNB Pancake V2 pair 0xb98f5322a91019311af43cf1d938AD0c59A6148a

### Exploit Conditions
- LABUBU must retain the self-transfer mint bug in its deployed implementation and remain callable by arbitrary contracts.
- The LABUBU/VOVOToken V3 pool and VOVOToken/WBNB V2 pair must hold sufficient liquidity to convert inflated LABUBU into VOVOToken and then into WBNB at a price that yields net BNB profit after fees.
- The adversary must be able to deploy a contract that performs a flash-like borrow from the LABUBU/VOVOToken V3 pool, executes a self-transfer loop in LABUBU, and then routes swaps through the V3 and V2 pools before repaying the flash-like borrow and withdrawing WBNB as BNB.

### Security Principles Violated
- Token balance conservation and totalSupply consistency within ERC20-like tokens.
- Invariant preservation in AMM pools that rely on honest token accounting for reserves and LP share valuation.
- Assumptions that third-party tokens integrated into AMMs do not introduce arbitrary local mint primitives via transfer hooks or misimplemented transfer functions.

## Adversary Flow Analysis

The adversary uses a single adversary-crafted deployment transaction to create an exploit contract, deploy a helper contract, borrow LABUBU from the LABUBU/VOVOToken V3 pool, inflate LABUBU via a self-transfer loop, swap inflated LABUBU for VOVOToken and then for WBNB, and finally withdraw WBNB to BNB, realizing a net BNB profit that is later sent through Tornado-style deposits.

### Adversary-Related Accounts
- **Adversary cluster:**
  - 0x27441c62dbe261fdf5e1feec7ed19cf6820d583b on BNB Chain (chainid 56), EOA=true, contract=false; reason: Origin EOA for the seed transaction 0xb06df3…, receives the final BNB profit according to native_balance_deltas, and initiates subsequent Tornado-style deposits.
  - 0x2Ff0Cc42e513535BD56bE20c3E686A58608260CA on BNB Chain (chainid 56), EOA=false, contract=true; reason: Contract created by the seed transaction that orchestrates the exploit sequence, including helper deployment, LABUBU self-transfer loop, AMM swaps, and WBNB withdrawal.
  - 0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30 on BNB Chain (chainid 56), EOA=false, contract=true; reason: Helper contract deployed by 0x2Ff0… during the seed transaction, which directly calls LABUBU::transfer in a self-transfer loop and interfaces with Pancake pools; its creation and control flow are fully determined by the adversary contract.
- **Victim candidates:**
  - LABUBU/VOVOToken Pancake V3 pool at 0xe70294c3D81ea914A883ad84fD80473C048C028C on BNB Chain (chainid 56), verified=unknown
  - VOVOToken/WBNB Pancake V2 pair at 0xb98f5322a91019311af43cf1d938AD0c59A6148a on BNB Chain (chainid 56), verified=unknown
  - VOVOToken token contract at 0x58b26c9b2d32df1d0e505bcca2d776698c9be6b6 on BNB Chain (chainid 56), verified=true
  - WBNB token contract at 0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c on BNB Chain (chainid 56), verified=true

### Adversary Lifecycle Stages
#### Adversary initial setup and funding

**Transactions:**
- 0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de on BNB Chain (chainid 56), block 44751945, mechanism=transfer

**Effect:** EOA 0x27441c62dbe261fdf5e1feec7ed19cf6820d583b holds sufficient BNB to pay for contract deployment and execution of a complex multi-call exploit strategy in a single transaction.

**Code or trace evidence:** native_balance_deltas for 0x2744… in artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/balance_diff.json and txlist entries in artifacts/root_cause/data_collector/iter_2/address/56/0x27441c62dbe261fdf5e1feec7ed19cf6820d583b_txlist.json.

#### Adversary contract deployment and helper creation

**Transactions:**
- 0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de on BNB Chain (chainid 56), block 44751945

**Effect:** The seed transaction deploys exploit contract 0x2Ff0… which in turn deploys helper contract 0x5CB7…, establishing adversary-controlled logic that interacts with LABUBU and the Pancake pools.

**Code or trace evidence:** Contract-creation frames and internal create opcodes for 0x2Ff0… and 0x5CB7… in the seed trace at artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/trace.cast.log, plus decompiled bytecode in artifacts/root_cause/data_collector/iter_1/contract/56/0x2Ff0Cc42e513535BD56bE20c3E686A58608260CA/decompile and 0x5CB7… decompile artifacts.

#### LABUBU self-transfer inflation and AMM routing

**Transactions:**
- 0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de on BNB Chain (chainid 56), block 44751945

**Effect:** Helper 0x5CB7… receives LABUBU from the LABUBU/VOVOToken V3 pool via a flash-like callback, executes a loop of LABUBU::transfer calls with from = to = helper that increases its LABUBU balance, then swaps inflated LABUBU for VOVOToken on the V3 pool and subsequently for WBNB on the V2 pair before repaying the flash-like borrow.

**Code or trace evidence:** Looped LABUBU::transfer calls and corresponding storage writes in artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/trace.cast.log; LABUBU _transfer implementation in artifacts/root_cause/seed/_contracts/56/0x2ff960f1d9af1a6368c2866f79080c1e0b253997/source/src/Contract.sol; swap calls on Pancake V3 and Pancake V2 in the same trace and standard pool behavior confirmed by artifacts/root_cause/data_collector/iter_1/contract/56/0xe70294c3D81ea914A883ad84fD80473C048C028C/source/src/PancakeV3Pool.sol and artifacts/root_cause/data_collector/iter_1/contract/56/0xb98f5322a91019311af43cf1d938AD0c59A6148a/source/src/Contract.sol.

#### Profit realization and post-exploit fund movement

**Transactions:**
- 0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de on BNB Chain (chainid 56), block 44751945

**Effect:** After AMM swaps and WBNB withdrawal, the origin EOA 0x2744… ends the seed transaction with a net BNB balance increase of 17394034359323102166 wei relative to its pre-transaction state and later sends BNB into a Tornado-style contract, consistent with concealment of profit flows.

**Code or trace evidence:** native_balance_deltas for 0x2744… in artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/balance_diff.json, WBNB::withdraw calls in the seed trace, and Tornado-like deposit patterns referenced in the iter_3 analysis using txlists in artifacts/root_cause/data_collector/iter_3/address/56/0x27441c62dbe261fdf5e1feec7ed19cf6820d583b_txlist.json.

## Impact & Losses

### Total Loss Overview
- BNB: 17394034359323102166 wei of net profit for the adversary EOA 0x27441c62dbe261fdf5e1feec7ed19cf6820d583b in the seed transaction, funded by value extracted from AMM counterparties and LPs.

### Impacts
The exploit transfers economic value from LABUBU/VOVOToken V3 LPs, VOVOToken/WBNB V2 LPs, and their trading counterparties to the adversary, as shown by the adverse VOVOToken and native BNB balance changes for the pools and the positive BNB delta for 0x2744…. Any protocol, LP, or user position that relies on LABUBU accounting, the LABUBU/VOVOToken V3 pool, or the VOVOToken/WBNB V2 pair experiences inconsistent token balances and price paths relative to ERC20-style conservation, and additional uses of the same self-transfer mint bug against existing or future liquidity produce further deterministic losses for those parties.

## References

- [1] Seed transaction metadata and balance diffs for 0xb06df3… on BNB Chain: artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/
- [2] LABUBU token source code: artifacts/root_cause/seed/_contracts/56/0x2ff960f1d9af1a6368c2866f79080c1e0b253997/source/src/Contract.sol
- [3] LABUBU/VOVOToken Pancake V3 pool source: artifacts/root_cause/data_collector/iter_1/contract/56/0xe70294c3D81ea914A883ad84fD80473C048C028C/source/src/PancakeV3Pool.sol
- [4] VOVOToken/WBNB Pancake V2 pair source: artifacts/root_cause/data_collector/iter_1/contract/56/0xb98f5322a91019311af43cf1d938AD0c59A6148a/source/src/Contract.sol
- [5] Iter_3 root cause analyzer current_analysis_result.json: artifacts/root_cause/root_cause_analyzer/iter_3/current_analysis_result.json

## All Relevant Transactions

- Chain 56, tx 0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de, role adversary-crafted
- Chain 56, tx 0xe4e882205d8ec02b8e431ad4cd0c5e5f152ba3643217e7d8faaef412c3f818ad, role related

## Key Evidence Snippets

LABUBU `_transfer` implementation (shows self-transfer mint bug):

```solidity
    function _transfer(address sender, address recipient, uint256 amount) internal {
    require(sender != address(0), "Xfer from zero addr");
    require(recipient != address(0), "Xfer to zero addr");

    uint256 senderBalance = _balances[sender];
    uint256 recipientBalance = _balances[recipient];

    uint256 newSenderBalance = SafeMath.sub(senderBalance, amount);
    if (newSenderBalance != senderBalance) {
        _balances[sender] = newSenderBalance;
    }

    uint256 newRecipientBalance = recipientBalance.add(amount);
    if (newRecipientBalance != recipientBalance) {
        _balances[recipient] = newRecipientBalance;
    }

    if (_balances[sender] == 0) {
        _balances[sender] = 16;
    }
```

Seed transaction trace snippet showing repeated LABUBU self-transfers:

```text
    │   │   ├─ [29507] LABUBU::transfer(0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30, 415636276381601458 [4.156e17])
    │   │   │   ├─ emit Transfer(from: 0xe70294c3D81ea914A883ad84fD80473C048C028C, to: 0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30, value: 415636276381601458 [4.156e17])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 0xa1c48b5873f93def888e143a8d083e802b00eeb4b9ac483c363fbde30bd7b928: 0 → 0x00000000000000000000000000000000000000000000000005c4a2fdc17dceb2
    │   │   │   │   @ 0x66554859ed55d6eff316e5207ad2fe91421c9cdf5a7ba04fadeb6a64e7a4cd8d: 0x00000000000000000000000000000000000000000000000005c4a2fdc17dceb2 → 16
    │   │   │   └─ ← [Return] true
    │   │   ├─ [196011] 0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30::pancakeV3FlashCallback(1039090690954004 [1.039e15], 0, 0x000000000000000000000000e70294c3d81ea914a883ad84fd80473c048c028c00000000000000000000000000000000000000000000000005c4a2fdc17dceb2)
    │   │   │   ├─ [266] 0xe70294c3D81ea914A883ad84fD80473C048C028C::token0() [staticcall]
    │   │   │   │   └─ ← [Return] LABUBU: [0x2fF960F1D9AF1A6368c2866f79080C1E0B253997]
    │   │   │   ├─ [24505] LABUBU::transfer(0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30, 415636276381601458 [4.156e17])
    │   │   │   │   ├─ emit Transfer(from: 0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30, to: 0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30, value: 415636276381601458 [4.156e17])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0xa1c48b5873f93def888e143a8d083e802b00eeb4b9ac483c363fbde30bd7b928: 0x00000000000000000000000000000000000000000000000005c4a2fdc17dceb2 → 0x0000000000000000000000000000000000000000000000000b8945fb82fb9d64
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [4594] LABUBU::transfer(0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30, 415636276381601458 [4.156e17])
    │   │   │   │   ├─ emit Transfer(from: 0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30, to: 0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30, value: 415636276381601458 [4.156e17])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0xa1c48b5873f93def888e143a8d083e802b00eeb4b9ac483c363fbde30bd7b928: 0x0000000000000000000000000000000000000000000000000b8945fb82fb9d64 → 0x000000000000000000000000000000000000000000000000114de8f944796c16
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [4594] LABUBU::transfer(0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30, 415636276381601458 [4.156e17])
```

Extract from seed transaction balance diff (attacker and WBNB native deltas):

```json
{
  "native_balance_deltas": [
    {
      "address": "0x27441c62dbe261fdf5e1feec7ed19cf6820d583b",
      "before_wei": "53668375816173750",
      "after_wei": "17447702735139275916",
      "delta_wei": "17394034359323102166"
    },
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "before_wei": "1349925548861955676638072",
      "after_wei": "1349908145779065353535906",
      "delta_wei": "-17403082890323102166"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0x2ff960f1d9af1a6368c2866f79080c1e0b253997",
      "holder": "0xe70294c3d81ea914a883ad84fd80473c048c028c",
      "before": "415636276381601458",
      "after": "860878127881130396",
      "delta": "445241851499528938",
      "balances_slot": "6",
      "slot_key": "0x66554859ed55d6eff316e5207ad2fe91421c9cdf5a7ba04fadeb6a64e7a4cd8d",
      "contract_name": "LABUBU"
    },
    {
      "token": "0x58b26c9b2d32df1d0e505bcca2d776698c9be6b6",
      "holder": "0xe70294c3d81ea914a883ad84fd80473c048c028c",
      "before": "12608288158248437362131369009",
      "after": "632480730445600731925",
      "delta": "-12608287525767706916530637084",
      "balances_slot": "1",
      "slot_key": "0x69fa50d4fa573c735a799bfd2bed636aab9d5451531e49e49d4fa63e4c237fd2",
      "contract_name": "VOVOToken"
    },
    {
      "token": "0x58b26c9b2d32df1d0e505bcca2d776698c9be6b6",
      "holder": "0xb98f5322a91019311af43cf1d938ad0c59a6148a",
      "before": "2376212717396342608743164210",
      "after": "14984500243164049525273801294",
      "delta": "12608287525767706916530637084",
      "balances_slot": "1",
      "slot_key": "0x6b02bcd83b56b47e07df79fa51c474f8cdf48d3da20beda59a52efff1aa29754",
      "contract_name": "VOVOToken"
    }
  ]
}
```
