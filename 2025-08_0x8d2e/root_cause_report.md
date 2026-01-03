# Base USDC 40,000 Exploit via Mis-guarded uniswapV3SwapCallback

## Incident Overview TL;DR

In block 34459414 on Base (chainid 8453), an adversary-controlled externally owned account (EOA) `0x4efd5f0749b1b91afdcd2ecf464210db733150e0` used its router contract `0x2a59ac31c58327efcbf83cc5a52fae1b24a81440` to trigger a mis-guarded `uniswapV3SwapCallback` on victim contract `0x8d2ef0d39a438c3601112ae21701819e13c41288`. In a single transaction (`0x6be0c4b5414883a933639c136971026977df4737b061f864a4a04e4bd7f07106`), the victim’s entire balance of 40,000.0 USDC was transferred to the adversary cluster.

The core protocol bug is that the victim contract’s `uniswapV3SwapCallback` authenticates `msg.sender` against an address derived from caller-controlled calldata instead of a fixed registry or whitelist of genuine pools. This design allows an arbitrary router (here `0x2a59ac31c58327efcbf83cc5a52fae1b24a81440`) to satisfy the check and withdraw the victim’s full USDC balance without a corresponding reduction in any liability it tracks.

This report follows the ACT (Adversary, Capability, Target) framing, and classifies the issue as a **protocol_bug** in the victim contract’s callback authentication logic, not in USDC itself.

## Key Background

- **USDC implementation on Base.** USDC on Base is deployed as an upgradeable `FiatTokenProxy` pointing to a `FiatTokenV2_2` implementation (token address `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`). Verified sources in the collected layout repository and `FiatTokenProxy.sol/FiatTokenV2_2` artifacts confirm standard ERC20 `balanceOf` and `transfer` semantics, with balances stored under a `balances` mapping slot.

- **Swap callbacks and authentication.** In Uniswap V3-style designs, `uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes data)` must only be callable by a genuine pool or designated router. Correct implementations enforce this by checking `msg.sender` against a fixed pool address or a tightly controlled registry. If a contract exposes this interface but authenticates `msg.sender` using caller-controlled calldata-derived data, any contract that can prepare suitable calldata can pass the check and induce token transfers.

- **Base gas and fee accounting.** On Base, total fees for a transaction consist of an L2 gas component (`gasUsed * effectiveGasPrice`) plus an L1 data fee (`l1Fee`), both visible in the receipt and reflected in native-balance deltas. For the exploit transaction, the analysis uses these fields together with a prestate tracer and balance-diff artifacts to compute exact gas costs borne by the adversary.

- **ACT opportunity and pre-state.** Immediately before block 34459414 (pre-state \u03c3\_B), USDC `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913` records:
  - Victim contract `0x8d2ef0d39a438c3601112ae21701819e13c41288` holding `40_000e6` USDC (40,000.0 USDC).
  - Adversary EOA `0x4efd5f0749b1b91afdcd2ecf464210db733150e0` holding 0 USDC.

  This is evidenced by:

  - `artifacts/root_cause/seed/8453/0x6be0c4b5.../metadata.json`
  - `artifacts/root_cause/data_collector/iter_1/state_diff/8453/0x833589fc.../prestate_tracer.json`
  - `artifacts/root_cause/seed/8453/0x6be0c4b5.../balance_diff.json`

  The prestate tracer shows the USDC balance slot for `0x8d2ef0d3...` containing exactly `40000000000` units and the slot for `0x4efd5f07...` containing 0 units immediately before the exploit executes.

## Vulnerability Analysis

### High-level vulnerability

The victim contract `0x8d2ef0d39a438c3601112ae21701819e13c41288` implements an `uniswapV3SwapCallback` function (selector `0xfa461e33`) that:

1. Decodes parameters from calldata.
2. Computes an address from those calldata parameters.
3. Compares `CALLER` (`msg.sender`) to this computed address.
4. Proceeds with a USDC transfer if and only if the equality check passes.

Critically, the address used for this equality check is fully derived from caller-controlled calldata. The contract does **not** consult any persistent whitelist, registry, or immutable pool address when validating `msg.sender`. As a result, any contract capable of:

- Reading the victim’s current USDC balance via `FiatTokenV2_2::balanceOf`, and
- Constructing calldata so that the derived address equals its own address,

can satisfy the callback’s `msg.sender` check and trigger a USDC transfer out of the victim.

### Evidence from victim disassembly

Disassembly of the victim (iter_3 disassembly) shows the relevant authentication sequence, where a computed address is masked and directly compared to `CALLER`:

```text
000029f9: DUP2
000029fa: ADD
000029fb: SWAP1
000029fc: PUSH2 0x2a05
...
00002a0a: DUP1
00002a0b: PUSH20 0xffffffffffffffffffffffffffffffffffffffff
00002a20: AND
00002a21: CALLER
00002a22: PUSH20 0xffffffffffffffffffffffffffffffffffffffff
00002a37: AND
00002a38: EQ
00002a39: PUSH2 0x2a77
00002a3c: JUMPI
...
```

Here, the value on the stack at `0x2a0a` is an address derived from calldata. It is masked to 160 bits and then compared to `CALLER`. If the comparison fails, execution jumps to a revert path; if it succeeds, the function continues and eventually performs the USDC transfer.

### Vulnerable components

- **Victim contract `0x8d2ef0d39a438c3601112ae21701819e13c41288` (liquidity manager).** Exposes `uniswapV3SwapCallback` with `msg.sender` authentication based solely on a calldata-derived address, allowing arbitrary routers to pass the check.

- **USDC token `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913` (`FiatTokenProxy` / `FiatTokenV2_2`).** Serves as the asset being drained. ERC20 behavior is standard and correct; the vulnerability arises from the victim’s incorrect usage and assumptions regarding who is allowed to move USDC from its balance.

### Security principles violated

- **Improper authentication of callback caller.** The callback trusts a caller-controlled address embedded in calldata instead of enforcing that only authorized pools/routers may invoke it.

- **Failure to maintain asset invariants.** The victim allows its entire USDC balance to be withdrawn by any contract satisfying the flawed `msg.sender` check, without verifying that the withdrawal corresponds to a legitimate user position or pool liability.

- **Insufficient trust boundary definition.** A callback interface intended for tightly scoped AMM pools is reused without preserving the assumption that only a controlled set of contracts can trigger it.

## Detailed Root Cause Analysis

### ACT framing and opportunity

This incident is analyzed under ACT as follows:

- **Adversary.** An unprivileged EOA `0x4efd5f0749b1b91afdcd2ecf464210db733150e0` on Base, together with its router contract `0x2a59ac31c58327efcbf83cc5a52fae1b24a81440`.
- **Capability.** Ability to deploy arbitrary contracts, read on-chain state (including USDC balances), and submit standard EIP-1559 transactions with sufficient gas.
- **Target.** Victim contract `0x8d2ef0d39a438c3601112ae21701819e13c41288`, which holds 40,000e6 USDC and exposes a mis-guarded `uniswapV3SwapCallback`.

In pre-state \u03c3\_B (just before block 34459414), USDC records:

- Victim balance: 40,000e6 USDC in `0x8d2ef0d3...`.
- Adversary balance: 0 USDC in `0x4efd5f07...`.

The state-diff artifacts and prestate tracer confirm these balances.

### Router behavior and calldata construction

Router `0x2a59ac31c58327efcbf83cc5a52fae1b24a81440` is deployed by the adversary in transaction:

- `0xf27f723007913b73217c462e758f5f04a99acb7b964ed1f9c3f14087dcfa9f4c` (block 34459381, Base).

Disassembly for this router (iter_3) shows:

- Use of the ERC20 `balanceOf` selector `0x70a08231` to query balances.
- Use of the `uniswapV3SwapCallback` selector `0xfa461e33` to call the victim.

A key fragment from the router disassembly highlights construction of `uniswapV3SwapCallback` calldata and subsequent `balanceOf` calls:

```text
000006bf: PUSH32 0xfa461e3300000000000000000000000000000000000000000000000000000000
...
000006e0: DUP6
000006e1: MSTORE              ; store selector and args for uniswapV3SwapCallback
...
0000070a: JUMPDEST
0000070b: PUSH1 0x40
0000070d: MLOAD
0000070e: PUSH32 0x70a0823100000000000000000000000000000000000000000000000000000000
...
```

In the exploit transaction, the router:

1. Reads the victim’s USDC balance via `FiatTokenV2_2::balanceOf(0x8d2ef0d3...)` and learns that it is exactly `40000000000` units (40,000.0 USDC).
2. Constructs `uniswapV3SwapCallback` calldata such that:
   - The `amount0Delta` passed into the callback is `40000000000` (the victim’s entire USDC balance).
   - The embedded address used in the victim’s equality check is the router’s own address `0x2a59ac31c58327efcbf83cc5a52fae1b24a81440`.
3. Calls `0x8d2ef0d3...::uniswapV3SwapCallback` with this calldata.

### Exploit transaction trace and token movements

The seed exploit transaction is:

- `0x6be0c4b5414883a933639c136971026977df4737b061f864a4a04e4bd7f07106` on Base, block 34459414.

The collected trace (`trace.cast.log`) shows the following call sequence (abridged):

```text
├─ [9750] FiatTokenProxy::fallback(0x8d2Ef0d39A438C3601112AE21701819E13c41288) [staticcall]
│   ├─ [2553] FiatTokenV2_2::balanceOf(0x8d2Ef0d39A438C3601112AE21701819E13c41288) [delegatecall]
...
├─ [34982] 0x8d2Ef0d39A438C3601112AE21701819E13c41288::uniswapV3SwapCallback(
│            40000000000 [4e10], 0,
│            0x000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913
│              0000000000000000000000002a59ac31c58327efcbf83cc5a52fae1b24a81440)
│   ├─ [32063] FiatTokenProxy::fallback(0x2A59Ac31C58327EFCbF83Cc5A52fAE1b24A81440, 40000000000 [4e10])
│   │   ├─ [31363] FiatTokenV2_2::transfer(0x2A59Ac31C58327EFCbF83Cc5A52fAE1b24A81440, 40000000000 [4e10]) [delegatecall]
...
├─ [1250] FiatTokenProxy::fallback(0x2A59Ac31C58327EFCbF83Cc5A52fAE1b24A81440) [staticcall]
│   ├─ [553] FiatTokenV2_2::balanceOf(0x2A59Ac31C58327EFCbF83Cc5A52fAE1b24A81440) [delegatecall]
...
├─ [27263] FiatTokenProxy::fallback(0x4EfD5F0749b1b91AFDcD2ECf464210db733150e0, 40000000000 [4e10])
│   ├─ [26563] FiatTokenV2_2::transfer(0x4EfD5F0749b1b91AFDcD2ECf464210db733150e0, 40000000000 [4e10]) [delegatecall]
```

This trace shows:

- The router calls USDC via the proxy to check the victim’s balance.
- The victim’s `uniswapV3SwapCallback` is invoked with `amount0Delta = 40,000e6`.
- Inside the callback, the victim calls USDC to transfer 40,000e6 USDC from its own balance to the router.
- The router then transfers the same 40,000e6 USDC on to the adversary EOA.

The associated `balance_diff.json` for this transaction quantitatively confirms token movements:

- Victim `0x8d2ef0d3...` USDC:
  - `before`: `40000000000`
  - `after`: `0`
  - `delta`: `-40000000000`

- Adversary EOA `0x4efd5f07...` USDC:
  - `before`: `0`
  - `after`: `40000000000`
  - `delta`: `40000000000`

Native-balance deltas show the adversary paying exactly `386,861,413,820` wei in total gas and L1 data fees.

### Exploit conditions

For this attack to succeed, the following conditions (all satisfied in this incident) must hold:

1. **Victim funded.** Victim contract `0x8d2ef0d3...` holds a non-zero USDC balance (here 40,000e6) in its `FiatTokenV2_2` balance slot immediately before block 34459414.
2. **Adversary router.** The adversary can deploy or control a router contract that:
   - Reads the victim’s USDC balance via `balanceOf`.
   - Calls `uniswapV3SwapCallback` on `0x8d2ef0d3...` with calldata chosen so that the derived address inside the victim’s authentication logic equals the router’s own address.
3. **Unprivileged feasibility.** The adversary can submit a standard type-2 EIP-1559 transaction on Base with sufficient gas to execute the router and victim code, without needing any privileged role, prior approval, or off-chain coordination.

### Success predicate and profit

The success predicate is purely monetary and defined in terms of the adversary cluster’s holdings of USDC and native gas:

- **Reference asset.** The pair `(USDC units, native gas in wei)`; no cross-asset conversion is applied.
- **Adversary address.** `0x4efd5f0749b1b91afdcd2ecf464210db733150e0` (clustered with router `0x2a59ac31...`).

From the seed transaction artifacts:

- **Fees paid.**
  - `gasUsed = 82875`
  - `effectiveGasPrice = 4,592,972` wei
  - Gas component: `380,642,554,500` wei
  - L1 data fee: `6,218,859,320` wei
  - **Total native fee:** `386,861,413,820` wei (matches native `delta_wei` for the EOA).

- **USDC balances.**
  - Before: 0 USDC
  - After: 40,000.0 USDC
  - Delta: +40,000.0 USDC

- **Native balances.**
  - Before: `3,081,625,460,517,407` wei
  - After: `3,081,238,599,103,587` wei
  - Delta: `-386,861,413,820` wei

Thus, in the reference asset, the adversary cluster’s net outcome for the exploit transaction is:

- **USDC:** +40,000.0
- **Native gas:** –386,861,413,820 wei

The analysis does not attempt to convert gas costs into USDC or to track what happens to the stolen USDC after the exploit (e.g., further trades or bridging).

## Adversary Flow Analysis

### Adversary-related accounts

The adversary-related cluster and key stakeholder addresses are:

- **Adversary EOA (origin and beneficiary).**
  - Address: `0x4efd5f0749b1b91afdcd2ecf464210db733150e0`
  - Role: Originator of the exploit transaction `0x6be0c4b5...`, payer of gas fees, and final recipient of 40,000.0 USDC in the seed transaction.
  - Evidence: `address_txlist` artifacts for this EOA include the router deployment transaction and the exploit transaction.

- **Adversary router contract.**
  - Address: `0x2a59ac31c58327efcbf83cc5a52fae1b24a81440`
  - Role: Router deployed by the EOA and used to orchestrate `balanceOf` queries and the `uniswapV3SwapCallback` into the victim.
  - Evidence: Deployed in tx `0xf27f7230...dcfa9f4c` with `from = 0x4efd5f07...` and `to = ""` (contract creation); disassembly shows calls to USDC and `uniswapV3SwapCallback`.

- **Victim contract.**
  - Address: `0x8d2ef0d39a438c3601112ae21701819e13c41288`
  - Role: Holds 40,000e6 USDC before the exploit, exposes the mis-guarded `uniswapV3SwapCallback`, and loses all 40,000.0 USDC in the exploit transaction.
  - Evidence: Disassembly artifacts and USDC balance-diff showing a `-40000000000` delta.

- **USDC token contract.**
  - Address: `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913` (`FiatTokenProxy` / `FiatTokenV2_2`)
  - Role: ERC20 token whose balances are reallocated between the victim and adversary cluster by the exploit.
  - Evidence: Verified sources and state-diff artifacts.

### Adversary lifecycle stages

1. **Router deployment**

   - Transaction: `0xf27f723007913b73217c462e758f5f04a99acb7b964ed1f9c3f14087dcfa9f4c`
   - Block: 34459381 (Base)
   - From: `0x4efd5f0749b1b91afdcd2ecf464210db733150e0`
   - To: contract creation (no `to` address in txlist)
   - Mechanism: `deploy_contract`

   This transaction creates router `0x2a59ac31c58327efcbf83cc5a52fae1b24a81440` shortly before the exploit. The deployment payload disassembles to a router with logic to call USDC, read balances, and invoke `uniswapV3SwapCallback` on other contracts.

2. **Victim contract funding and configuration**

   - Transaction: `0x51deb54d10016c97c549880d329720ebfa78625861896b1c160326b38f0cd829`
     - Block: 34458723
     - Role: Deposit or configuration transaction involving victim `0x8d2ef0d3...`.
   - Transaction: `0x633bd48f2771181215257c6ce2a8a2928697eedd2b8683bd340baea6c8d96fd4`
     - Block: 34452552
     - Role: Additional deposit or configuration involving the victim.

   Trace logs for these transactions show an operator account `0x3b00fe1a2051855f117f7915dd24973bdf6445a4` and related addresses providing USDC to `0x8d2ef0d3...` and configuring its state. As a result, immediately before block 34459414, `0x8d2ef0d3...` holds exactly 40,000e6 USDC.

3. **Exploit execution and profit realization**

   - Transaction: `0x6be0c4b5414883a933639c136971026977df4737b061f864a4a04e4bd7f07106`
   - Block: 34459414
   - Mechanism: `exploit_single_tx`

   In this transaction:

   - The adversary EOA calls its router `0x2a59ac31...`.
   - The router:
     - Reads `balanceOf(0x8d2ef0d3...)` for USDC to determine the victim’s entire balance.
     - Constructs and sends `uniswapV3SwapCallback` to `0x8d2ef0d3...` with:
       - `amount0Delta = 40000000000`
       - Callback data containing the USDC token address and the router’s own address.
   - Inside the callback, the victim authenticates `msg.sender` by comparing it to the calldata-derived address (which equals the router), so the check passes.
   - The victim then calls USDC’s proxy to transfer 40,000e6 USDC from its own balance to `0x2a59ac31...`.
   - The router, now holding 40,000e6 USDC, immediately calls USDC again to transfer the same amount to the adversary EOA `0x4efd5f07...`.

   The exploit completes in this single transaction, with no intermediate state that would prevent repetition if the victim’s balance were replenished.

### All relevant transactions summary

The analysis identifies the following key transactions on Base (chainid 8453):

- `0x6be0c4b5...` — attacker-crafted exploit transaction (router call into victim’s callback).
- `0xf27f7230...` — attacker-crafted router deployment transaction.
- `0x51deb54d...` — related victim funding/configuration transaction.
- `0x633bd48f...` — related victim funding/configuration transaction.

These transactions are fully enumerated in `all_relevant_txs` within `root_cause.json` and match the traces and txlist artifacts used in this report.

## Impact & Losses

### Quantified loss

The exploit causes a net reallocation of exactly 40,000.0 USDC from the victim to the adversary cluster in the analyzed transaction:

- **Token:** USDC (`0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`)
- **Total USDC lost by victim contract:** 40,000.0
- **Total USDC gained by adversary EOA:** 40,000.0

This is supported by the ERC20 balance-diff artifact for the exploit transaction, which shows:

- Victim `0x8d2ef0d3...`: `delta = -40000000000` USDC units.
- Adversary `0x4efd5f07...`: `delta = +40000000000` USDC units.

### Loss bearer and scope

At the level of on-chain accounts in the exploit transaction:

- **Loss-bearing account (in this report’s scope):** Victim contract `0x8d2ef0d3...`, whose USDC balance decreases from 40,000e6 to 0.
- **Beneficiary account:** EOA `0x4efd5f07...`, whose USDC balance increases from 0 to 40,000e6.

This report intentionally attributes impact at the contract-account level for the analyzed transaction and does not analyze how the 40,000.0 USDC loss is distributed across upstream depositors or users of `0x8d2ef0d3...`. Traces for funding and configuration transactions are available for further attribution but are out of scope for this root-cause-focused document.

### Native gas cost

The adversary’s native-gas expenditure for the exploit transaction is:

- **Total native fee:** `386,861,413,820` wei
  - L2 gas component: `380,642,554,500` wei
  - L1 data fee: `6,218,859,320` wei

This cost is fully captured in the native-balance deltas for `0x4efd5f07...` and the system addresses that receive gas and data fees.

## References

This section lists the primary artifacts used in the analysis:

1. `[1]` **Seed transaction trace and balance diffs.**
   - `artifacts/root_cause/seed/8453/0x6be0c4b5414883a933639c136971026977df4737b061f864a4a04e4bd7f07106/trace.cast.log`
   - `artifacts/root_cause/seed/8453/0x6be0c4b5414883a933639c136971026977df4737b061f864a4a04e4bd7f07106/balance_diff.json`

2. `[2]` **USDC prestate tracer and state diff.**
   - `artifacts/root_cause/data_collector/iter_1/state_diff/8453/0x833589fcd6edb6e08f4c7c32d4f71b54bda02913/prestate_tracer.json`

3. `[3]` **Victim contract disassembly (`0x8d2ef0d39a438c3601112ae21701819e13c41288`).**
   - `artifacts/root_cause/data_collector/iter_3/contract/8453/0x8d2ef0d39a438c3601112ae21701819e13c41288/disassemble/code_disassembly_cast.txt`

4. `[4]` **Router contract disassembly (`0x2a59ac31c58327efcbf83cc5a52fae1b24a81440`).**
   - `artifacts/root_cause/data_collector/iter_3/contract/8453/0x2a59ac31c58327efcbf83cc5a52fae1b24a81440/disassemble/code_disassembly_cast.txt`

5. `[5]` **Upstream victim funding traces.**
   - `artifacts/root_cause/data_collector/iter_2/tx/8453/0x51deb54d10016c97c549880d329720ebfa78625861896b1c160326b38f0cd829/trace.cast.log`
   - `artifacts/root_cause/data_collector/iter_2/tx/8453/0x633bd48f2771181215257c6ce2a8a2928697eedd2b8683bd340baea6c8d96fd4/trace.cast.log`

6. **USDC source and layout repository.**
   - `artifacts/root_cause/seed/8453/0x2ce6311ddae708829bc0784c967b7d77d19fd779/src/Users/aloysius.chan/Repositories/circlefin/stablecoin-evm-private-usdc-mainnet-base/contracts`

7. **Address txlists for adversary and victim.**
   - `artifacts/root_cause/data_collector/iter_2/address/8453/0x4efd5f0749b1b91afdcd2ecf464210db733150e0/txlist.json`
   - `artifacts/root_cause/data_collector/iter_1/address/8453/0x8d2ef0d39a438c3601112ae21701819e13c41288/txlist.json`
   - `artifacts/root_cause/data_collector/iter_1/address/8453/0x2a59ac31c58327efcbf83cc5a52fae1b24a81440/txlist.json`

These artifacts jointly support the deterministic, evidence-backed root cause and adversary-flow analysis presented in this report.

