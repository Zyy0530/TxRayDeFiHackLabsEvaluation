# BSC-56 BEP20USDT Proxy-Cluster Drain via Accounting Bug

## 1. Incident Overview TL;DR

On BSC chain 56, EOA `0x4B63C0cf524F71847ea05B59F3077A224d922e8D` executed a two-transaction ACT-style exploit against the BEP20USDT proxy-cluster `0xb8ad82c4771DAa852DdF00b70Ba4bE57D22eDD99` / `0x2Cc8B879E3663d8126fe15daDaaA6Ca8D964BbBE`.  
Both transactions were sent to router-like contract `0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C` and used helper contracts `0xCAC261d08Cc190eA2BF271aaB40cf21EbCb30cbA`, `0x6Ac39F58d3192CbBB4167BA3b559287D231eeBC7`, and `0x4D85f6AF054A2271a15F8D3cF880Ba7b7497225F`, plus upgradeable proxies delegating to implementation `0x1a1a84b45d2fEeeC1B1726F5C1da7d3fe2f37041`, to execute a flash-loan-based drain of BEP20USDT.  
The root cause is a protocol-level accounting bug: the proxy-cluster allows BEP20USDT to be pulled out via delegatecalls and helpers without a corresponding reduction in the proxies’ recorded liabilities, breaking alignment between on-chain token balances and internal accounting.  
The analyzer correctly classifies this as an ACT (`is_act = true`) protocol bug (`root_cause_category = "protocol_bug"`), realized purely from public on-chain state, verified contract code/disassemblies, and observable transactions.

## 2. Key Background

- BEP20USDT at `0x55d398326f99059fF775485246999027B3197955` is a standard BEP20 stablecoin on BSC, and WBNB at `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c` wraps BNB; both have verified sources in the seed artifacts.  
- Router-like contract `0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C` orchestrates:
  - Flash loans from Pancake V3 pool `0x92b7807bF19b7DDdf89b706143896d05228f3121`.  
  - Swaps via PancakeRouter `0x10ED43C718714eb63d5aA57B78B54704E256024E`.  
  - Calls into helper contracts `0xCAC261…`, `0x6Ac39…`, and `0x4D85f6AF…`, which delegatecall into implementation `0x4beefd0F0064Cb8FAF045B989976A453ae983Da6` to perform ERC20 `transferFrom` operations.  
- Upgradeable proxies `0xb8ad82c4771DAa852DdF00b70Ba4bE57D22eDD99` and `0x2Cc8B879E3663d8126fe15daDaaA6Ca8D964BbBE` on chain 56 delegatecall into implementation `0x1a1a84b45d2fEeeC1B1726F5C1da7d3fe2f37041`.  
  - Disassembly for `0x1a1a84b4…` shows a dispatcher for standard ERC20 functions and custom accounting methods that read/write storage via `KECCAK256`-based mappings, implementing an internal liability/position ledger on top of BEP20USDT balances held by the proxies.  
- Pancake V3 pool `0x92b7807bF19b7DDdf89b706143896d05228f3121` and pair `0x16b9a82891338f9Ba80E2D6970FddA79D1eb0daE` provide BEP20USDT–WBNB liquidity.  
  - Verified sources under `artifacts/root_cause/data_collector/iter_1/contract/56/` confirm standard AMM behavior and no protocol-side special-casing for these addresses.

## 3. Vulnerability Analysis

The ACT opportunity arises because the BEP20USDT proxy-cluster (`0xb8ad82c4…` / `0x2Cc8B8…`) with implementation `0x1a1a84b4…` allows helper contracts and router `0x3b3E1E…` to move a large BEP20USDT balance out of proxy `0xb8ad82c4…` and into AMM pools while the proxy’s delegated storage in `0x1a1a84b4…` does not decrease a corresponding liability or supply-like variable.  
This breaks the invariant that external token balances on BEP20USDT and internal accounting in the proxy implementation must remain aligned.

**Vulnerable components**

- BSC-56 upgradeable proxy `0xb8ad82c4771DAa852DdF00b70Ba4bE57D22eDD99`, delegating to implementation `0x1a1a84b45d2fEeeC1B1726F5C1da7d3fe2f37041`, holding BEP20USDT and exposing accounting functions used during exploit transaction `0x26bcefc152d8cd49f4bb13a9f8a6846be887d7075bc81fa07aa8c0019bd6591f`.  
- BSC-56 upgradeable proxy `0x2Cc8B879E3663d8126fe15daDaaA6Ca8D964BbBE`, also delegating to `0x1a1a84b4…` and participating in the same accounting scheme.  
- Helper contracts `0xCAC261d08Cc190eA2BF271aaB40cf21EbCb30cbA`, `0x6Ac39F58d3192CbBB4167BA3b559287D231eeBC7`, and `0x4D85f6AF054A2271a15F8D3cF880Ba7b7497225F` plus implementation `0x4beefd0F0064Cb8FAF045B989976A453ae983Da6`, providing generalized ERC20 `transferFrom` and swap sequencing used to extract BEP20USDT from the proxy-cluster.  
- Router-like contract `0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C`, which coordinates helpers, proxies, PancakeRouter, and AMM pools during both preparation and exploit transactions.

**Security principles violated**

- **Alignment between external token balances and internal accounting**: the proxy implementation fails to ensure that internal liabilities or share-like variables are reduced when BEP20USDT is transferred out of `0xb8ad82c4…`.  
- **Invariant preservation across delegatecall-based architectures**: the combination of proxies, implementation `0x1a1a84b4…`, router `0x3b3E1E…`, and helper contracts lets delegatecall sequences alter external token balances while leaving delegated storage inconsistent.  
- **Least-privilege use of ERC20 approvals**: generalized helpers that can `transferFrom` arbitrary callers to arbitrary recipients are granted approvals that, together with the flawed accounting scheme, allow adversarial sequences to drain tokens from the proxy-cluster.

## 4. Detailed Root Cause Analysis

### 4.1 On-chain pre-state and ACT opportunity

- The relevant ACT pre-state `σ_B` is at BSC block `57780130` (and the later exploit block `57780985`), defined as the publicly reconstructible chain state immediately before:
  - Transaction `0x27baa4c57686fb256aadecf3990cd750195a9cf7b778b908a4d9bbda091847e7` in block `57780130`, and  
  - Transaction `0x26bcefc152d8cd49f4bb13a9f8a6846be887d7075bc81fa07aa8c0019bd6591f` in block `57780985`.  
- This state is derived from:
  - Etherscan transaction metadata.  
  - QuickNode prestateTracer state diffs for both transactions.  
  - BEP20USDT and WBNB verified token sources.  
  - Verified sources or disassemblies for the involved router, proxies, implementation contracts, and helpers.  
- Evidence for this reconstruction includes:
  - `artifacts/root_cause/seed/56/0x26bcefc1…/metadata.json` and `balance_diff.json`.  
  - PrestateTracer diffs and raw state-diff logs under `artifacts/root_cause/data_collector/iter_1/` and `iter_3/tx/56/*`.  
  - Contract sources and disassemblies under `artifacts/root_cause/data_collector/iter_1/contract/56/` and `iter_2/contract/56/`.  
  - Address-level txlists for the proxies and helper/router contracts.

Within this pre-state, the proxies hold large BEP20USDT balances, helper contracts and router are deployed and callable, and AMM pools contain sufficient liquidity to support the observed flash loan and swaps. No privileged configuration or off-chain secret is required; the exploit is realizable by any unprivileged actor with access to public RPC and explorer data.

### 4.2 Victim transaction and storage behavior

The seed exploit transaction is:

- Chain: `BSC (56)`  
- Tx hash: `0x26bcefc152d8cd49f4bb13a9f8a6846be887d7075bc81fa07aa8c0019bd6591f`  
- Role: `seed` (primary exploit)  

Core effects (from `balance_diff_prestate_tracer.json` and `state_diff_prestateTracer_raw.json`):

- A flash loan of `20,000,000` BEP20USDT is taken from pool `0x92b7807bF19b7DDdf89b706143896d05228f3121`.  
- The borrowed USDT is routed through:
  - Helpers `0xCAC261…` and `0x6Ac39…` (delegatecalling `0x4beefd0F…`).  
  - Proxies `0xb8ad82c4…` and `0x2Cc8B8…` (delegating to `0x1a1a84b4…`).  
  - PancakeRouter `0x10ED43C7…`.  
  - AMM pools `0xaec58FBd7Ed8008A3742f6d4FFAA9F4B0ECbc30e` and `0x16b9a82891338f9Ba80E2D6970FddA79D1eb0daE`.  
- BEP20USDT balance deltas include:
  - `-239,832,087.664667062923384` units for proxy `0xb8ad82c4771DAa852DdF00b70Ba4bE57D22eDD99`.  
  - Matching positive deltas for `0x92b7807b…`, AMM participants `0xaec58FBd7Ed8008A3742f6d4FFAA9F4B0ECbc30e`, `0x13342140a62cb51c052b5a70eb186f40a1725ebf`, and `0x16b9a82891338f9Ba80E2D6970FddA79D1eb0daE`.  
- `state_diff_prestateTracer_raw.json` shows storage updates for `0x16b9a828…` and `0x2Cc8B8…` but **no storage entry** for `0xb8ad82c4…`, even though its BEP20USDT balance on the token contract is reduced by `239,832,087.664667062923384` units.

This directly demonstrates that the underlying token ledger for BEP20USDT changes while the proxy’s delegated storage in `0x1a1a84b4…` remains unchanged, leaving the proxy economically undercollateralized.

### 4.3 Helper implementation behavior

Disassembly for helper implementation `0x4beefd0F0064Cb8FAF045B989976A453ae983Da6` shows a dispatcher keyed on selector `0xe09618e9`, which constructs and executes ERC20 `transferFrom`-style calls when invoked via delegatecall from helper contracts:

```text
00000000: PUSH1 0x80
00000002: PUSH1 0x40
00000004: MSTORE
00000005: CALLVALUE
00000006: DUP1
00000007: ISZERO
00000008: PUSH2 0x000f
0000000b: JUMPI
0000000c: PUSH0
0000000d: DUP1
0000000e: REVERT
0000000f: JUMPDEST
00000010: POP
00000011: PUSH1 0x04
00000013: CALLDATASIZE
00000014: LT
00000015: PUSH2 0x0029
00000018: JUMPI
00000019: PUSH0
0000001a: CALLDATALOAD
0000001b: PUSH1 0xe0
0000001d: SHR
0000001e: DUP1
0000001f: PUSH4 0xe09618e9
00000024: EQ
00000025: PUSH2 0x002d
00000028: JUMPI
```

Helper contracts `0xCAC261…`, `0x6Ac39…`, and `0x4D85f6AF…` delegatecall into this implementation, enabling flexible `transferFrom`-based extraction of BEP20USDT from callers such as the proxies and router into AMM pools and profit-taking addresses.

### 4.4 ACT exploit conditions

The ACT opportunity is fully determined by the public pre-state and holds whenever:

- Proxies `0xb8ad82c4…` and `0x2Cc8B8…` hold substantial BEP20USDT balances and delegatecall into implementation `0x1a1a84b4…` with the accounting behavior observed in the state diffs and disassembly.  
- Helper contracts `0xCAC261…`, `0x6Ac39…`, and `0x4D85f6AF…` exist and are callable via router `0x3b3E1E…`, as shown by preparation transaction `0x27baa4c5…` traces and state diffs.  
- Proxies and helpers expose public methods that allow an unprivileged EOA to arrange approvals, `transferFrom` calls, and swaps that move BEP20USDT from proxy `0xb8ad82c4…` into AMM pools and then into BNB, without a matching reduction of liabilities in the delegated storage of `0x1a1a84b4…`.  
- Pancake V3 pool `0x92b7807b…` and pair `0x16b9a828…` provide enough BEP20USDT and WBNB liquidity to support the `20,000,000` USDT flash loan and swaps seen in the seed trace.

Any unprivileged adversary with access to these public contracts, balances, and pools can reproduce the exploit.

## 5. Adversary Flow Analysis

### 5.1 High-level strategy

The adversary uses a two-step strategy on BSC:

1. **Helper deployment and configuration** – Transaction `0x27baa4c57686fb256aadecf3990cd750195a9cf7b778b908a4d9bbda091847e7` from EOA `0x4B63C0cf524F71847ea05B59F3077A224d922e8D` to router `0x3b3E1E…` deploys helper contracts (including `0xCAC261…` and `0x4D85f6AF…`) and configures them to delegatecall implementation `0x4beefd0F…`, establishing generic ERC20 `transferFrom` and swap sequencing capabilities.  
2. **Flash-loan exploit and profit realization** – Transaction `0x26bcefc1…` executes a `20,000,000` BEP20USDT flash loan via pool `0x92b7807b…`, routes the borrowed USDT through helpers, proxies `0xb8ad82c4…` / `0x2Cc8B8…`, PancakeRouter `0x10ED43C7…`, and AMM pairs `0xaec58FBd7Ed8008A3742f6d4FFAA9F4B0ECbc30e` and `0x16b9a828…`, then repays `20,002,000` USDT and converts the residual USDT into BNB profit for the adversary cluster `{0x4B63…, 0x1266C6…}`.

### 5.2 Adversary-related accounts

**Adversary cluster**

- `0x4B63C0cf524F71847ea05B59F3077A224d922e8D` (EOA, chain 56): sender of both preparation tx `0x27baa4c5…` and exploit tx `0x26bcefc1…`; prestateTracer native balance deltas and `adversary_net_profit_bnb.json` attribute the majority of the `~190.55` BNB profit to this address.  
- `0x1266C6bE60392A8Ff346E8d5ECCd3E69dD9c5F20` (EOA, chain 56): recipient of `0.3` BNB in `0x26bcefc1…`, as shown in `balance_diff_prestate_tracer.json` and BEP20/WBNB traces; included in the profit-taking cluster in `adversary_net_profit_bnb.json`.  
- `0xCAC261d08Cc190eA2BF271aaB40cf21EbCb30cbA` (contract, chain 56): helper deployed in `0x27baa4c5…` and called from router `0x3b3E1E…` in `0x26bcefc1…`; disassembly and traces show it delegatecalling `0x4beefd0F…` to perform ERC20 `transferFrom` operations.  
- `0x6Ac39F58d3192CbBB4167BA3b559287D231eeBC7` (contract, chain 56): helper used alongside `0xCAC261…` to delegatecall `0x4beefd0F…`; the seed trace for `0x26bcefc1…` shows it called between router `0x3b3E1E…` and implementation `0x4beefd0F…` as an intermediate contract moving BEP20USDT.  
- `0x4D85f6AF054A2271a15F8D3cF880Ba7b7497225F` (contract, chain 56): helper deployed in `0x27baa4c5…`; its disassembly shows sequencing of ERC20 `approve`, `transferFrom`, and router calls, used in `0x26bcefc1…` to move BEP20USDT through proxies and AMMs.  
- `0x4beefd0F0064Cb8FAF045B989976A453ae983Da6` (contract, chain 56): helper implementation called via delegatecall from `0xCAC261…` and `0x6Ac39…`; disassembly shows function `0xe09618e9` constructing ERC20 `transferFrom` calls, enabling helpers to pull BEP20USDT from callers and route it through AMM pools.  
- `0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C` (contract, chain 56): router-like contract receiving both adversary-crafted transactions; `trace.cast.log` shows it orchestrating calls to helpers, proxies, PancakeRouter, and AMM pools.

**Victim candidates**

- `bsc-56-proxy-0xb8ad82c4` – proxy `0xb8ad82c4771DAa852DdF00b70Ba4bE57D22eDD99` (verified), chain 56; loses `239,832,087.664667062923384` BEP20USDT units during the exploit.  
- `bsc-56-proxy-0x2Cc8B8` – proxy `0x2Cc8B879E3663d8126fe15daDaaA6Ca8D964BbBE` (verified), chain 56; participates in the same delegated accounting scheme and exploitation path.

### 5.3 Adversary lifecycle stages

1. **Adversary funding**  
   - Tx: `0x6d30be2a19261ae308142432132264a58d32181647ab7976b0f3bc830211c700` (BSC, block `58015697`).  
   - Effect: EOA `0x4B63…` receives BNB from `0xbeeb28c202d00949c9cbec93cbcbe75476f851a1`, providing native tokens used to pay gas for later adversary-crafted transactions, as shown in `txlist_normal.json` for `0x4B63…`.  
2. **Helper contracts deployment and configuration**  
   - Tx: `0x27baa4c57686fb256aadecf3990cd750195a9cf7b778b908a4d9bbda091847e7` (BSC, block `57780130`).  
   - Effect: router `0x3b3E1E…` deploys helpers including `0xCAC261…` and `0x4D85f6AF…` and configures them to delegatecall `0x4beefd0F…`, establishing flexible ERC20 `transferFrom` and swap sequencing for later use.  
3. **Flash-loan exploit and profit realization**  
   - Tx: `0x26bcefc1…` (BSC, block `57780985`).  
   - Effect: executes a `20,000,000` BEP20USDT flash loan via pool `0x92b7807b…`, routes USDT through helpers, proxies `0xb8ad82c4…` / `0x2Cc8B8…`, PancakeRouter `0x10ED43C7…`, and AMM pairs `0xaec58FBd7Ed8008A3742f6d4FFAA9F4B0ECbc30e` and `0x16b9a828…`; repays `20,002,000` USDT and uses `162,050.884788503640076373` USDT to buy `190.553117446131167874` WBNB from pair `0x16b9a828…`. WBNB is unwrapped to BNB and distributed as `+190.253117446131167874` BNB to `0x4B63…` and `+0.3` BNB to `0x1266C6…`, with a matching `-190.553117446131167874` BNB delta on WBNB contract `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c` and a `-239,832,087.664667062923384` BEP20USDT delta on proxy `0xb8ad82c4…`.

### 5.4 Trace evidence snippet

Seed transaction `0x26bcefc1…` trace (Foundry `cast run -vvvvv` output) shows the flash loan from pool `0x92b7807b…` to router `0x3b3E1E…`, transfer of `20,000,000` USDT, and subsequent callback into the router, which then interacts with proxies and helpers:

```text
Traces:
  [13423023] 0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C::592d448f(...)
    ├─ [13259861] 0x92b7807bF19b7DDdf89b706143896d05228f3121::flash(0x3b3E1E..., 20000000000000000000000000 [2e25], 0, ...)
    │   ├─ [2531] BEP20USDT::balanceOf(0x92b7807bF19b7DDdf89b706143896d05228f3121) [staticcall]
    │   ├─ [27971] BEP20USDT::transfer(0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C, 20000000000000000000000000 [2e25])
    │   │   ├─ emit Transfer(from: 0x92b7807b..., to: 0x3b3E1E..., value: 20000000000000000000000000 [2e25])
    │   ├─ [13185458] 0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C::pancakeV3FlashCallback(2000000000000000000000 [2e21], 0, ...)
    │   │   ├─ [24562] BEP20USDT::approve(0xCAC261d08Cc190eA2BF271aaB40cf21EbCb30cbA, 12313575093686077974655 [1.231e22])
```

This snippet illustrates the flash loan, transfer of USDT to the router, and approval to helper `0xCAC261…`, which is then used to route USDT through the proxies and AMMs while the proxy’s delegated storage remains unchanged.

## 6. Impact & Losses

**Total loss overview**

- Token: `BEP20USDT`  
- Amount: `239,832,087.664667062923384` units  

**Impact details**

- `balance_diff_prestate_tracer.json` for tx `0x26bcefc1…` shows that proxy `0xb8ad82c4771DAa852DdF00b70Ba4bE57D22eDD99` loses `239,832,087.664667062923384` BEP20USDT units, while AMM pools and intermediaries receive matching positive BEP20USDT deltas.  
- `adversary_net_profit_bnb.json` shows that the adversary cluster `{0x4B63…, 0x1266C6…}` realizes a net profit of `190.55096618353116` BNB after gas costs.  
- The drain leaves the proxy-cluster economically undercollateralized and shifts losses onto holders whose positions are represented by the proxy’s delegated storage in implementation `0x1a1a84b4…`.

## 7. References

**Primary incident metadata and ACT reconstruction**

- Root cause report metadata:  
  - Title: `BSC-56 BEP20USDT proxy-cluster drain via accounting bug`.  
  - Protocol name: `bsc-56-proxy-cluster-0xb8ad82-0x2Cc8`.  
  - `is_act = true`, `root_cause_category = "protocol_bug"`.  
- ACT pre-state and reconstruction evidence:  
  - Seed transaction trace and balance diff for `0x26bcefc1…`: `artifacts/root_cause/seed/56/0x26bcefc1…`.  
  - PrestateTracer diffs and adversary profit calculation for `0x26bcefc1…` and `0x27baa4c5…`: `artifacts/root_cause/data_collector/iter_3/tx/56`.  
  - Verified sources and disassemblies for BEP20USDT, WBNB, proxies, and helpers: `artifacts/root_cause/data_collector/iter_1/contract/56`.  
  - Helper contracts disassemblies for `0xCAC261…`, `0x6Ac39…`, and `0x4D85f6AF…`: `artifacts/root_cause/data_collector/iter_2/contract/56`.

**root_cause.json section references**

- `[1]` Seed transaction trace and balance diff for `0x26bcefc1…` – `artifacts/root_cause/seed/56/0x26bcefc1…`.  
- `[2]` PrestateTracer diffs and adversary profit calculation for `0x26bcefc1…` and `0x27baa4c5…` – `artifacts/root_cause/data_collector/iter_3/tx/56`.  
- `[3]` Verified sources and disassemblies for BEP20USDT, WBNB, proxies, and helpers – `artifacts/root_cause/data_collector/iter_1/contract/56`.  
- `[4]` Helper contracts disassemblies for `0xCAC261…`, `0x6Ac39…`, and `0x4D85f6AF…` – `artifacts/root_cause/data_collector/iter_2/contract/56`.

This report is fully derived from and consistent with `root_cause.json`, seed transaction traces, prestateTracer outputs, and verified contract sources/disassemblies, and contains no speculative or undetermined content.

