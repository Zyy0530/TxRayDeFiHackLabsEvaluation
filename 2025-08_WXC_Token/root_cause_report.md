# BNB Chain 0x4769…7309 Strategy Profit Without Proven ACT Exposure

**Incident Overview TL;DR**
- On BNB Chain (chainid 56), EOA `0x476954c752a6ee04b68382c97f7560040eda7309` sent transaction `0x1397bc7f0d284f8e2e30d0a9edd0db1f3eb0dd284c75e30d226b02bf09ad068f` in block `57177438` to bespoke strategy contract `0x798465b25b68206370d99f541e11eea43288d297`.
- The strategy routed ≈`1.0087` BNB through PancakeSwap, WBNB, a Moolah-style proxy at `0x8f73b65b4caaf64fba2af91cc5d4a2a1318e5d8c`, a second proxy at `0x8087720eeea59f9f04787065447d52150c09643e`, custom token `0x4c100d30d9c511b8bb9d1c951bbc1be489a0172f`, and staking/reward contract `0x7f356c3a964a4a0da96d00a15246d26269e93425` to produce ≈`37.55` WBNB.
- Portfolio balance diffs over blocks `57176000–57181000` show a net change for `0x4769…7309` of `-1.009744059927102680` BNB and `+37.554715963191219441` WBNB, i.e. ≈`+36.544971903264` BNB-equivalent profit after gas.
- Disassembly and traces show that the profitable entrypoint on `0x7984…d297` enforces `ORIGIN==CALLER==0x4769…7309`. There is no evidence that an arbitrary unprivileged EOA can execute the same path, so under the ACT framework the incident is classified as **non-ACT** (`metadata.is_act = "false"`, `root_cause_category = "other"`).

**Key Background**
- The incident takes place on BNB Chain around block `57177438` and involves:
  - Profit-taking EOA `0x4769…7309`.
  - Strategy contract `0x7984…d297`.
  - ERC1967Proxy/Moolah implementation `0x8f73…5d8c`.
  - Proxy `0x8087…43e`.
  - Custom token `0x4c10…172f`.
  - Staking/reward contract `0x7f35…3425`.
  - WBNB `0xbb4c…095c`, PancakeRouter `0x10ed…024e`, and PancakePair `0xda5c…c965`.
- The ACT pre-state `σ_B` is the publicly reconstructible BNB Chain state immediately before block `57177438`, covering balances and contract code for all of the above addresses. It is supported by:
  - Seed tx metadata for `0x1397…068f` and account txlists for `0x4769…7309` and `0x7984…d297`.
  - Verified source for the ERC1967Proxy/Moolah contract at `0x8f73…5d8c`.
  - Cast disassembly for strategy `0x7984…d297`.
  - On-chain bytecode for token `0x4c10…172f` and staking contract `0x7f35…3425`.
- Data collection produced:
  - Full tx metadata and a `cast run -vvvvv` trace for the seed transaction `0x1397…068f`.
  - Portfolio-style balance diffs for `0x4769…7309` and related EOAs over the incident window.
  - Verified source for WBNB and the Moolah proxy, plus raw bytecode and partial tooling outputs for `0x4c10…172f` and `0x7f35…3425`.
- Contract source for `0x4c10…172f` and `0x7f35…3425` is not verified and high-level decompilation failed in this environment; their internal role/invariant design remains opaque. This limitation is explicitly accounted for in the final non-ACT classification.
- Under the ACT definition, a valid opportunity must be a permissionless, anyone-can-take strategy for an unprivileged adversary using only public on-chain state and metadata. Caller-restricted or whitelisted paths that other EOAs cannot invoke do **not** qualify as ACT.

**Vulnerability Analysis**
- ACT Root Cause (summary):
  - The only demonstrated profitable sequence is the seed transaction `0x1397…068f`, which calls selector `0x32e4d6f3` on strategy contract `0x7984…d297`.
  - Disassembly and traces show that this path first checks `ORIGIN` and then `CALLER` against the constant address `0x4769…7309` before executing the multi-leg strategy.
  - Because this entrypoint is hardwired to a single caller and the downstream custom contracts have opaque privilege models, there is no evidence of a permissionless, unprivileged anyone-can-take strategy.
- The key components involved are:
  - Strategy contract `0x798465b25b68206370d99f541e11eea43288d297`, selector `0x32e4d6f3`, with caller restriction to `0x4769…7309`.
  - Custom token `0x4c100d30d9c511b8bb9d1c951bbc1be489a0172f`, whose internal mint/burn/reward and role logic cannot be reconstructed from verified source in this environment.
  - Staking/reward contract `0x7f356c3a964a4a0da96d00a15246d26269e93425`, whose reward accounting and access control are similarly opaque.
- Conditions under which the strategy can function as observed:
  - Control of EOA `0x476954c752a6ee04b68382c97f7560040eda7309` to satisfy the `CALLER==0x4769…7309` and `ORIGIN==0x4769…7309` checks for selector `0x32e4d6f3` on `0x7984…d297`.
  - Adequate liquidity and routing via PancakeRouter `0x10ed…024e`, PancakePair `0xda5c…c965`, and WBNB `0xbb4c…095c`.
  - Operational behavior of token `0x4c10…172f` and staking contract `0x7f35…3425` consistent with the observed flows (mint/burn, reward additions) without requiring extra privileged actions within the transaction.
- Security principle characterization:
  - The design concentrates economic power in a bespoke, caller-restricted strategy path with opaque custom-token mechanics. This may represent opaque or preferential treatment for a single address but, under the ACT adversary model, it is **not** an ACT vulnerability because the path is not provably available to arbitrary unprivileged EOAs.

**Detailed Root Cause Analysis**
- Seed transaction and sequence `b`:
  - The candidate ACT sequence `b` consists of a single transaction:
    - Chainid `56`, txhash `0x1397bc7f0d284f8e2e30d0a9edd0db1f3eb0dd284c75e30d226b02bf09ad068f`.
    - Type: `adversary-crafted` (from `0x4769…7309` to `0x7984…d297`).
  - Inclusion feasibility:
    - As an EOA-signed transaction from `0x4769…7309` with the observed gas, gasPrice, value, and calldata, the tx is valid under BNB Chain rules and miners/validators can include it.
    - However, because the called entrypoint enforces `CALLER==0x4769…7309`, this exact sequence is executable only by that address and not by arbitrary unprivileged EOAs.
  - Notes:
    - This single transaction is sufficient to realize the observed profit for `0x4769…7309` but does not establish an anyone-can-take opportunity.
- Profit predicate and magnitude:
  - The success predicate is purely monetary, with reference asset BNB.
  - For adversary address `0x4769…7309` over blocks `57176000–57181000`:
    - Starting BNB-equivalent value: `77.616386396689` (BNB + WBNB).
    - Ending BNB-equivalent value: `114.161358299954`.
    - Net delta: ≈`+36.544971903264` BNB-equivalent, after accounting for BNB spent.
    - Fees paid in BNB: `0.001008164000000000`.
  - These values are derived from portfolio balance diffs:

```json
{
  "symbol": "BNB",
  "delta": "-1009744059927102680"
},
{
  "symbol": "WBNB",
  "delta": "37554715963191219441"
}
```

_(Portfolio balance diffs for `0x4769…7309` over blocks `57176000–57181000`.)_

- Strategy contract caller restriction:
  - Disassembly of `0x7984…d297` shows the profitable entrypoint hardwiring `0x4769…7309` into ORIGIN and CALLER checks:

```text
00000adc: PUSH20 0x476954c752a6ee04b68382c97f7560040eda7309
00000af1: PUSH2 0x0afb
00000af4: DUP2
00000af5: ORIGIN
00000af6: EQ
...
00000b06: CALLER
00000b07: EQ
00000b08: PUSH2 0x0cb3
```

_(Disassembly snippet for strategy contract `0x7984…d297`, showing the ORIGIN and CALLER equality checks against `0x4769…7309` on the profitable path.)_

- Multi-leg flow via proxies, token, staking, and DEX:
  - The seed transaction trace shows:
    - Initial call from `0x4769…7309` to `0x7984…d297` with selector `0x32e4d6f3` and ≈`1.0087` BNB value.
    - Proxy-mediated approvals and transfers for token `0x4c10…172f` and WBNB `0xbb4c…095c` through ERC1967Proxy contracts `0x8f73…5d8c` and `0x8087…43e`.
    - Allowance setup for PancakeRouter and subsequent swaps via PancakeRouter `0x10ed…024e` and PancakePair `0xda5c…c965`, including fee-on-transfer style paths.
    - Reward-related interactions with staking/reward contract `0x7f35…3425` and updates to its internal storage (e.g., `addRewards` calls).
    - Final WBNB withdrawal and BNB transfers to addresses including `0x2739…c8ab`.

```text
0x7984…d297::32e4d6f3{value: 1008735895927102680}(...) 
  ├─ ERC1967Proxy::fallback(..., PancakeRouter)
  ├─ WBNB::approve(ERC1967Proxy: 0x8f73…5d8c, 2^256-1)
  ├─ ... swaps via PancakeRouter and PancakePair 0xda5c…c965 ...
  ├─ ERC1967Proxy::fallback(...)->0x7f35…3425::addRewards(...)
  ├─ PancakePair::sync()
  └─ WBNB/BNB transfers to counterparties and `0x4769…7309`
```

_(Seed transaction trace for `0x1397…068f`, illustrating the orchestrated multi-leg strategy.)_

- Opaque downstream contracts:
  - For token `0x4c10…172f` and staking contract `0x7f35…3425`, data collection obtained:
    - Raw on-chain bytecode.
    - BscScan/Etherscan source JSONs indicating they are not verified.
    - Cast bytecode outputs and attempted disassemblies.
  - High-level decompilation via heimdall was blocked by environment constraints, and cast disassembly on some artifacts failed due to formatting (odd number of digits).
  - As a result, detailed invariants, reward accounting, and role/whitelist structures for these contracts cannot be reconstructed, and no reliable code snippets beyond low-level artifacts are available.
- Conclusion under ACT:
  - The evidence proves that EOA `0x4769…7309` can, via a bespoke caller-restricted entrypoint and opaque custom contracts, realize a large net BNB-equivalent profit in a single transaction.
  - It does **not** prove that any arbitrary unprivileged EOA, using only public state at or before block `57177438`, can reproduce this behavior.
  - It also does not establish a violation of intended protocol invariants that is open to anyone; instead, it is consistent with a privileged or bespoke strategy path.
  - Therefore, under the ACT framework, the root cause is classified as **non-ACT: no anyone-can-take opportunity established**.

**Adversary Flow Analysis**
- High-level strategy summary:
  - A single, caller-restricted strategy transaction from `0x4769…7309` to `0x7984…d297` orchestrates swaps and staking interactions via PancakeSwap, WBNB, the Moolah-style proxy, and custom token/staking contracts, turning ≈`1.01` BNB into ≈`37.55` WBNB and capturing ≈`36.54` BNB-equivalent profit.
- Adversary-related accounts:
  - Adversary cluster:
    - `0x476954c752a6ee04b68382c97f7560040eda7309` (EOA, chainid 56): sender of the seed transaction; portfolio diffs show this address realizes the net BNB+WBNB profit.
    - `0x798465b25b68206370d99f541e11eea43288d297` (contract, chainid 56): strategy contract called by `0x4769…7309`; trace and disassembly show it enforces `CALLER==0x4769…7309` for the profitable entrypoint and orchestrates the downstream flows.
  - Victim candidates (custom ecosystem components affected by value flows):
    - Custom token `0x4c100d30d9c511b8bb9d1c951bbc1be489a0172f` (unverified).
    - Staking/reward contract `0x7f356c3a964a4a0da96d00a15246d26269e93425` (unverified).
- Lifecycle stages:
  - Adversary Positioning and Strategy Setup:
    - Transaction `0x028666e232acabe6ba58c4960d25de8f204181ea20df085979336c353ce9808b` (block `57177394`, mechanism `other`) prepares liquidity, allowances, and/or positions in USDT and the custom ecosystem via the Moolah proxy and related contracts ahead of the main profit-taking transaction.
  - Adversary Profit-Taking Strategy Execution:
    - Seed transaction `0x1397bc7f0d284f8e2e30d0a9edd0db1f3eb0dd284c75e30d226b02bf09ad068f` (block `57177438`, mechanism `swap`) sends ≈`1.0087` BNB from `0x4769…7309` to `0x7984…d297`.
    - The strategy entrypoint enforces `CALLER==0x4769…7309` and executes the multi-leg path via PancakeRouter, WBNB, the Moolah proxy, and custom token/staking contracts, culminating in a large WBNB gain and small BNB loss for `0x4769…7309`.
  - Post-Strategy Portfolio State:
    - Transaction `0x70f47c80a8ef6bec4bba0dc42177a3ecc51cdf4b3c6a650fa2e61f9c88d334c2` (block `57177439`, mechanism `other`) consolidates positions but does not overturn the profit measured over `57176000–57181000`; `0x4769…7309` retains the net WBNB-denominated gain.
- Relevant transactions set:
  - `0x1397…068f` (chainid 56): adversary-crafted profit-taking transaction.
  - `0x0286…808b` (chainid 56): related positioning/setup transaction.
  - `0x70f4…34c2` (chainid 56): related post-strategy consolidation transaction.

**Impact & Losses**
- Quantified impact:
  - Over blocks `57176000–57181000`, address `0x4769…7309` realizes a net gain of ≈`36.54` BNB-equivalent (BNB + WBNB), as measured by portfolio balance diffs.
  - This is summarized as a BNB-equivalent change of `-36.544971903264` from the perspective of counterparties, reflecting profit extracted by `0x4769…7309`.
- Flow of value:
  - Counterparties including `0x27391d90ff854bb8d0cc56c0a17f884f9a31c8ab` and `0x4848489f0b2bedd788c696e2d79b6b69d7484848` experience corresponding outflows along the strategy path (e.g., via liquidity and reward-related transfers).
- ACT lens on impact:
  - The available evidence does not establish that this gain results from a permissionless ACT-style exploit of protocol invariants.
  - Instead, it is consistent with a bespoke, caller-restricted strategy producing profit for a single address within an opaque custom ecosystem; under the ACT framework this is recorded as a **non-ACT** incident (no anyone-can-take exposure proven).

**References**
- [1] Seed transaction metadata (BNB Chain tx `0x1397…068f`): `artifacts/root_cause/seed/56/0x1397bc7f0d284f8e2e30d0a9edd0db1f3eb0dd284c75e30d226b02bf09ad068f/metadata.json`
- [2] Seed transaction trace (BNB Chain tx `0x1397…068f`): `artifacts/root_cause/seed/56/0x1397bc7f0d284f8e2e30d0a9edd0db1f3eb0dd284c75e30d226b02bf09ad068f/trace.cast.log`
- [3] Portfolio balance diffs for `0x4769…7309` (blocks `57176000–57181000`): `artifacts/root_cause/data_collector/iter_3/balance_diff/56/0x476954c752a6ee04b68382c97f7560040eda7309/portfolio_57176000_57181000.json`
- [4] Strategy contract `0x7984…d297` disassembly: `artifacts/root_cause/data_collector/iter_2/contract/56/0x798465b25b68206370d99f541e11eea43288d297/disassemble/bytecode_disassembly.txt`
- [5] Data collection summary and contract-source limitations: `artifacts/root_cause/data_collector/data_collection_summary.json`

