# BSC USDT Vault / Anti-Flashloan Token Flashloan Exploit (tx 0x26bcefc1…)

## Incident Overview TL;DR

- Chain and protocol: BNB Smart Chain (chainid 56), custom USDT vault and anti-flashloan token stack composed of two TransparentUpgradeableProxy contracts and associated implementations, plus Pancake-style AMMs and a PancakeV3Pool.
- Classification: ACT (anyone-can-take) opportunity and protocol_bug — the live configuration at block 57,780,985 embeds a same-block “Flash loan protection: cannot sell in the same block of purchase.” invariant that fails to prevent the observed flashloan-driven, same-block buy-and-sell route.
- Core event: EOA `0x4b63c0cf524f71847ea05b59f3077a224d922e8d` sends a single legacy type‑0 transaction `0x26bcefc152d8cd49f4bb13a9f8a6846be887d7075bc81fa07aa8c0019bd6591f` to orchestrator contract `0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C`, which takes a large USDT flashloan from PancakeV3Pool `0x92b7807bF19b7DDdf89b706143896d05228f3121`, routes value through a proxy-based USDT vault and anti-flashloan token plus a USDT–proxy AMM pair, repays the flashloan, and leaves the attacker’s EOA with a large net BNB profit funded by WBNB and vault-held USDT.
- Deterministic profit: From the pre-state σ_B immediately before including block 57,780,985, replaying the exact calldata, gas and value for tx `0x26bcefc1…` deterministically yields a net BNB portfolio increase of `190.252041814831167874` BNB for the attacker EOA while fully repaying the USDT flashloan.

## Key Background

- System composition: The exploit path combines standard BSC infrastructure with custom components:
  - BEP20USDT token `0x55d398326f99059ff775485246999027b3197955`.
  - Wrapped BNB (WBNB) `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`.
  - PancakeV3Pool-like flashloan pool `0x92b7807bF19b7DDdf89b706143896d05228f3121`.
  - PancakePair-like AMM (USDT–proxy pair) `0xaec58FBd7Ed8008A3742f6d4FFAA9F4B0ECbc30e`.
  - Two TransparentUpgradeableProxy contracts:
    - Custom token proxy `0x2Cc8B879E3663d8126fe15daDaaA6Ca8D964BbBE` over implementation `0x13b5ca6642d9c2309b4c34f8b591e35b629458fc`.
    - USDT vault proxy `0xb8ad82c4771DAa852DdF00b70Ba4bE57D22eDD99` over implementation `0x89a0af274e6244f781a50d632b222231ef7655eb`.
  - Router/pricing contract `0x94DDCd7253AC864Ec77A2dDC2bE4B2418Ed17C9D` and implementation `0x1a1a84b45d2fEeeC1B1726F5C1da7d3fe2f37041` that compute prices and execute exchanges used in the exploit route.
- Embedded anti-flashloan invariant: Decompiled implementations `0x13b5ca6642d9c2309b4c34f8b591e35b629458fc` and `0x1a1a84b45d2fEeeC1B1726F5C1da7d3fe2f37041` both:
  - Maintain per-address, block-number-related storage (for example via mappings such as `storage_map_a[...]`).
  - Contain multiple `require` statements that embed the revert string:

```solidity
require(storage_map_a[var_a] < block.number, "Flash loan protection: cannot sell in the same block of purchase.");
```

  - These branches implement a same-block trading restriction for certain transfer paths involving the proxy token and vault.
- Evidence of value shifts: Balance and state diffs for the exploit transaction (from `balance_diff.json` and `balance_diff_prestateTracer.json`) show:
  - The USDT flashloan principal to pool `0x92b7…` is repaid with fee.
  - Attacker EOA `0x4b63…` increases its native BNB balance from `0.3930199406` BNB to `190.645061755431167874` BNB, a net delta of `+190.252041814831167874` BNB.
  - WBNB contract `0xbb4c…` loses approximately `190.553117446131167874` BNB of native balance.
  - USDT vault proxy `0xb8ad82…` experiences a large negative USDT balance delta, while addresses `0x13342140A62Cb51C052b5a70eb186f40a1725eBf` and `0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae` receive significant USDT inflows.
- Public pre-state σ_B: The pre-state σ_B at block height `57780985` is publicly reconstructible from canonical on-chain data and the provided artifacts. It covers code and storage for:
  - Orchestrator `0x3b3E…`, proxies `0x2Cc8…` and `0xb8ad82…`, implementations `0x13b5…`, `0x89a0…`, `0x1a1a84…`, router/pricing `0x94DD…`, PancakeV3Pool `0x92b7…`, PancakePair `0xaec5…`, BEP20USDT `0x55d3…`, and WBNB `0xbb4c…`.
  - σ_B is justified by `metadata.json`, `state_diff_prestateTracer.json`, `balance_diff_prestateTracer.json`, and `data_collection_summary.json`.

## Vulnerability Analysis

- Advertised invariant: The custom token and vault stack implement an explicit same-block “Flash loan protection” invariant intended to prevent sell operations in the same block as a purchase. This is implemented through:
  - Per-address tracking of recent block numbers.
  - `require` guards that compare `storage_map_a[...]` values against `block.number` and include the revert string “Flash loan protection: cannot sell in the same block of purchase.” in multiple locations in the decompiled implementations.
- Observed behavior: Despite the presence of this invariant:
  - In block `57780985`, the orchestrator executes a flashloan-driven route that buys and sells via the proxy token and vault in a single transaction.
  - The trace for tx `0x26bcefc1…` shows these operations completing successfully; no internal call reverts with the “Flash loan protection” message.
  - State and balance diffs confirm a full cycle: USDT borrowed and later repaid with fee, proxy/vault balances updated, AMM reserves shifted, and attacker BNB profit realized.
- Vulnerable components:
  - Implementation `0x13b5ca6642d9c2309b4c34f8b591e35b629458fc` behind proxy `0x2Cc8B879E3663d8126fe15daDaaA6Ca8D964BbBE` (custom token implementation with embedded same-block trading restriction).
  - Implementation `0x89a0af274e6244f781a50d632b222231ef7655eb` behind proxy `0xb8ad82c4771DAa852DdF00b70Ba4bE57D22eDD99` (vault implementation holding large USDT balances and participating in the exploit route).
  - Implementation `0x1a1a84b45d2fEeeC1B1726F5C1da7d3fe2f37041` and router/pricing contract `0x94DDCd7253AC864Ec77A2dDC2bE4B2418Ed17C9D`, which supply `price()`, `getAmountOut`, and `exchange` functionality used by the orchestrator.
  - Orchestrator contract `0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C`, which composes flashloan, vault, token, router and AMM interactions into a single exploit transaction.
- Vulnerability summary: Under σ_B at block `57780985`, the anti-flashloan invariant encoded in the custom token/vault implementations does not apply to, or fails to enforce on, the contract-mediated routing path used by the orchestrator. As a result, a same-block buy-and-sell cycle that the system intends to block is permitted to execute and extract value from protocol-side balances.

## Detailed Root Cause Analysis

### Exploit transaction and trace

The seed and exploit transaction is:

- Chain: BSC (chainid 56).
- Transaction: `0x26bcefc152d8cd49f4bb13a9f8a6846be887d7075bc81fa07aa8c0019bd6591f`.
- Sender (attacker EOA): `0x4b63c0cf524f71847ea05b59f3077a224d922e8d`.
- To (orchestrator): `0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C`.
- Type: legacy type‑0, value `0`, gas limit `0x112a880`, gasPrice `0x5f5e100` (100,000,000 wei).
- Block: `57780985` (0x371aaf9).

A key portion of the trace (from `trace.cast.log`) shows the flashloan and callback wiring:

```text
0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C::592d448f(...)
  ├─ PancakeV3Pool::flash(0x3b3E1Edeb7…, 20000000000000000000000000, 0, ...)
  │   ├─ BEP20USDT::transfer(0x3b3E1Edeb7…, 20000000000000000000000000)
  │   └─ ...
  ├─ 0x3b3E1Edeb7…::pancakeV3FlashCallback(2000000000000000000000, 0, ...)
  │   ├─ PancakeRouter::getAmountsIn(...)
  │   ├─ TransparentUpgradeableProxy (0x2Cc8… / 0xb8ad82…) delegatecalls into
  │   │   implementations 0x13b5… and 0x1a1a84… via router/pricing contract 0x94DD…
  │   ├─ PancakeRouter::swapExactTokensForTokensSupportingFeeOnTransferTokens(...)
  │   └─ PancakePair::swap(...) along the USDT–proxy pair 0xaec58F…
  └─ ...
```

This trace shows that the orchestrator:

- Calls `PancakeV3Pool::flash` on `0x92b7…` to borrow `20,000,000 * 10^18` USDT.
- In the flash callback, routes the borrowed USDT through:
  - Vault proxy `0xb8ad82…` and token proxy `0x2Cc8…` via their implementations.
  - Router/pricing contract `0x94DD…` and implementation `0x1a1a84…` to compute exchange amounts and carry out transfers.
  - PancakeRouter and AMM pair `0xaec58F…` to perform swaps between USDT and the proxy token.
- Repays the flashloan principal plus fee to `0x92b7…` before the transaction completes.

Throughout this sequence, no call in the trace reverts with the “Flash loan protection: cannot sell in the same block of purchase.” message, despite the same-block buy-and-sell cycle.

### Code-level invariant evidence

Decompiled implementations for the token and vault logic explicitly embed the anti-flashloan invariant. For example, the decompiled contract for implementation `0x13b5ca6642d9c2309b4c34f8b591e35b629458fc` includes:

```solidity
require(storage_map_a[var_a] < block.number, "Flash loan protection: cannot sell in the same block of purchase.");
require(!(storage_map_a[var_a] < block.number), "Flash loan protection: cannot sell in the same block of purchase.");
```

Similar guards appear in implementation `0x1a1a84b45d2fEeeC1B1726F5C1da7d3fe2f37041`, which also tracks per-address data and applies constraints based on the difference between `block.number` and stored values. These snippets demonstrate that:

- The system attempts to encode a same-block restriction on sell-side flows after a purchase.
- Violations of this invariant are intended to revert with the precise string “Flash loan protection: cannot sell in the same block of purchase.”.

### Evidence of invariant failure on the exploit path

Combining trace and diff evidence:

- The exploit transaction executes a USDT → proxy token purchase, intermediate routing through the vault and proxies, and a subsequent sell back through the same stack, all within block `57780985`.
- The internal calls traverse the exact components that embed the anti-flashloan checks (`0x13b5…`, `0x1a1a84…`, `0x94DD…`), but the trace shows no revert carrying the “Flash loan protection” message.
- `balance_diff.json` and `balance_diff_prestateTracer.json` show:
  - Attacker EOA `0x4b63…` native BNB delta: `+190.252041814831167874` BNB.
  - WBNB contract `0xbb4c…` native balance delta: `−190.553117446131167874` BNB.
  - USDT vault proxy `0xb8ad82…` large negative USDT delta, while AMM and external addresses gain USDT.
  - The USDT pool `0x92b7…` ends with a higher USDT balance due to the flash fee.

This establishes that the invariant is not enforced on the contract-mediated route actually taken by the orchestrator under σ_B. The root cause is therefore:

- The system’s same-block anti-flashloan protection, as deployed and configured at σ_B, does not cover the orchestrator’s flashloan-driven buy-and-sell path through the proxies, vault, router and AMM.
- This gap enables a fully automated, single-transaction exploitation that conforms to all public interfaces but violates the intended invariant, resulting in deterministic attacker profit.

### ACT opportunity characterization

The act_opportunity description is fully satisfied:

- Pre-state σ_B is public: All required code and storage for orchestrator, proxies, implementations, router, pool, AMM, USDT and WBNB are reconstructible from RPC, traces and the provided state-diff artifacts at block `57780985`.
- Transaction sequence `b`: A single attacker-crafted transaction (`index: 1`) on chainid 56 with:
  - From `0x4b63…` (unprivileged EOA).
  - To `0x3b3E…` (orchestrator).
  - Standard gas and gasPrice consistent with public network conditions.
  - No private ordering or privileged access; the call sequence involves only public flashloan, proxy, router and AMM functions.
- Inclusion feasibility: Any unprivileged EOA can submit the same calldata, gas and value on σ_B and have the transaction included under normal BSC rules, leading to the same trace.
- Success predicate:
  - Type: `profit` in reference asset BNB.
  - Attacker address: `0x4b63c0cf524f71847ea05b59f3077a224d922e8d`.
  - Value before: `0.3930199406` BNB.
  - Value after: `190.645061755431167874` BNB.
  - Net delta: `190.252041814831167874` BNB.
  - Gas fees: already reflected in the net balance delta; the exact fee is not separately reported in the artifacts but is fully accounted for in the before/after values.

Given these facts, this incident is an ACT opportunity: any unprivileged adversary with access to on-chain data and the exploit calldata could have reproduced the profit.

## Adversary Flow Analysis

### Strategy summary

- The adversary strategy is a single-transaction flashloan exploit:
  - Deploy a custom orchestrator contract capable of composing flashloan, vault, token and AMM interactions.
  - Use the orchestrator to take a large USDT flashloan from PancakeV3Pool `0x92b7…`.
  - Route the borrowed USDT through the proxy-based USDT vault and anti-flashloan token stack using router/pricing logic and the USDT–proxy AMM pair.
  - Repay the flashloan principal and fee within the same transaction.
  - Exit with a large BNB profit in the attacker EOA, funded by WBNB/native balance reductions and vault-side USDT movements.

### Adversary-related accounts

- Adversary cluster:
  - EOA `0x4b63c0cf524f71847ea05b59f3077a224d922e8d`
    - Role: Sender and gas payer of exploit transaction `0x26bcefc1…`.
    - Evidence: `txlist_57779000_57782000.json` records this address as `from` for both the orchestrator deployment tx and the exploit tx.
  - Orchestrator contract `0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C`
    - Role: Contract created by the attacker EOA and used as the target of the exploit transaction; executes the flashloan and routing logic.
    - Evidence: Deployment transaction `0x36811c78469e63316f042c105dfc74a00a3df848efac12413df48ecad56cf2c6` has `to == ""` and `contractAddress == 0x3b3E…`; exploit tx `0x26bcefc1…` sends input `0x592d448f…` to this contract.

- Victim and protocol-side components:
  - BEP20USDT `0x55d398326f99059ff775485246999027b3197955`.
  - WBNB `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`.
  - PancakeV3Pool (USDT pool) `0x92b7807bF19b7DDdf89b706143896d05228f3121`.
  - USDT–proxy AMM pair `0xaec58FBd7Ed8008A3742f6d4FFAA9F4B0ECbc30e`.
  - USDT vault proxy `0xb8ad82c4771DAa852DdF00b70Ba4bE57D22eDD99`.
  - Custom token proxy `0x2Cc8B879E3663d8126fe15daDaaA6Ca8D964BbBE`.
  - These addresses act as liquidity reservoirs and routing components; balance and reserve changes at these contracts fund the attacker’s net BNB profit.

### Lifecycle stages

- Orchestrator Deployment
  - Transaction: `0x36811c78469e63316f042c105dfc74a00a3df848efac12413df48ecad56cf2c6`.
  - Block: `57779996`.
  - Chain: BSC (56).
  - Mechanism: `contract_deploy` from EOA `0x4b63…` with value `0`.
  - Effect: Creates orchestrator contract `0x3b3E1Edeb726b52D5dE79cF8dD8B84995D9Aa27C` with logic to request flashloans and route funds.
  - Evidence: `txlist_57779000_57782000.json` and orchestrator decompile (`0x3b3E…-decompiled.sol`).

- Exploit Execution
  - Transaction: `0x26bcefc152d8cd49f4bb13a9f8a6846be887d7075bc81fa07aa8c0019bd6591f`.
  - Block: `57780985`.
  - Chain: BSC (56).
  - Mechanism: `flashloan+amm+vault_routing`.
  - Effect:
    - Orchestrator calls PancakeV3Pool `0x92b7…::flash` to borrow `20,000,000 * 10^18` USDT.
    - In the callback, it uses router/pricing `0x94DD…` and implementation `0x1a1a84…` to calculate path amounts and exchange USDT for the proxy token via proxies `0x2Cc8…` / `0xb8ad82…` and AMM pair `0xaec58F…`.
    - It performs a same-block buy-and-sell cycle for the proxy token, moving value out of vault-held USDT and AMM reserves.
    - It repays the flashloan principal and fee to the USDT pool.
    - The attacker EOA’s BNB balance increases by `190.252041814831167874` BNB.
  - Evidence:
    - Trace: `artifacts/root_cause/seed/56/0x26bcefc1…/trace.cast.log`.
    - Balance diffs: `balance_diff.json` and `balance_diff_prestateTracer.json`.
    - State diffs: `state_diff_prestateTracer.json`, including focus slices for proxies and implementations.
    - Decompiles for `0x13b5…`, `0x89a0…`, `0x1a1a84…`, and `0x94DD…`.

## Impact & Losses

- Attacker BNB profit:
  - Native balance for EOA `0x4b63…` increases from `0.3930199406` BNB to `190.645061755431167874` BNB.
  - Net delta: `+190.252041814831167874` BNB.
  - This delta is already net of gas costs, as it is taken directly from before/after native balance readings in `balance_diff.json`.
- WBNB losses:
  - WBNB contract `0xbb4c…` native balance decreases by `190.553117446131167874` BNB.
  - This indicates that WBNB-related liquidity providers effectively fund the attacker’s BNB profit (together with shifts in USDT).
- USDT flows:
  - USDT vault proxy `0xb8ad82…` suffers a large negative USDT balance delta, reflecting outflows of vault-held USDT.
  - USDT AMM pair `0xaec58F…` and external addresses:
    - `0x13342140A62Cb51C052b5a70eb186f40a1725eBf` receives `+39,668,885,677,805,882,830,887` USDT (in token units).
    - `0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae` receives `+162,050,884,788,503,640,076,373` USDT.
  - PancakeV3Pool `0x92b7…` ends with a net `+2,000,000,000,000,000,000,000` USDT delta due to the flash fee.
- Economic incidence:
  - The net BNB gains for the attacker are mirrored by WBNB contract native balance losses and USDT redistributions out of the vault.
  - The immediate economic losses therefore fall on:
    - WBNB liquidity providers whose reserves are drawn down.
    - USDT vault participants whose vault-held USDT is partially drained or reallocated.
  - The flashloan pool itself is not harmed; it receives its principal plus fee and ends with higher USDT balance.

## References

- [1] Exploit transaction metadata and trace  
  `artifacts/root_cause/seed/56/0x26bcefc152d8cd49f4bb13a9f8a6846be887d7075bc81fa07aa8c0019bd6591f`

- [2] Balance and state diffs (prestateTracer)  
  `artifacts/root_cause/data_collector/iter_2/tx/56/0x26bcefc152d8cd49f4bb13a9f8a6846be887d7075bc81fa07aa8c0019bd6591f`

- [3] Contract sources and decompiles for orchestrator, proxies, implementations, router, pool and AMM  
  `artifacts/root_cause/data_collector`

- [4] Attacker EOA txlist around exploit and orchestrator deployment  
  `artifacts/root_cause/data_collector/iter_2/address/56/0x4b63c0cf524f71847ea05b59f3077a224d922e8d/txlist_57779000_57782000.json`

- [5] Relevant transactions (BSC chainid 56)  
  - Orchestrator deployment (related): `0x36811c78469e63316f042c105dfc74a00a3df848efac12413df48ecad56cf2c6`  
  - Exploit transaction (attacker-crafted): `0x26bcefc152d8cd49f4bb13a9f8a6846be887d7075bc81fa07aa8c0019bd6591f`

