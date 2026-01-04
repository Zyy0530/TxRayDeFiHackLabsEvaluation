## Incident Overview TL;DR

On BSC, an unprivileged adversary used a custom routing contract and USDT flash loans to drain almost all USDT liquidity from the DCF/USDT Pancake V2 pool, enrich the DCT/USDT pool, and concentrate the extracted USDT in their own addresses. The exploit relied on the combined tokenomics and LP-accounting behavior of the DCF and DCT contracts, which allow USDT value to be moved between pools and into the attacker’s control without preserving USDT‑denominated LP value. The attack was executed in a single atomic sequence of five adversary-crafted transactions at block height 44,290,969–44,290,972, culminating in a profit of approximately 4.42e5 USDT at a gas cost of at most ~17.86 USDT. All steps are permissionless and realizable as an ACT opportunity by any searcher with access to standard BSC RPC, pool reserves, and verified contract sources.

## Key Background

The incident targets the DCF/DCT ecosystem on BSC, which consists of:
- BEP20USDT token at `0x55d398326f99059ff775485246999027b3197955`.
- DCF token at `0xa7e92345ddf541aa5cf60fee2a0e721c50ca1adb` with custom tokenomics and LP-related transfer logic.
- DCT token at `0x56f46bd073e9978eb6984c0c3e5c661407c3a447` with LP-related accounting around its USDT pool.
- DCF/USDT Pancake V2 pair at `0x8487f846d59f8fb4f1285c64086b47e2626c01b6` (primary victim LP).
- DCT/USDT Pancake V2 pair at `0x5aac7375196e9ea76b1598ed4be19b41fa5ba651`.
- Multiple USDT flash-loan pools on Pancake V3 at:
  - `0x92b7807bf19b7dddf89b706143896d05228f3121`
  - `0x36696169c63e42cd08ce11f5deeBbCeBae652050`
  - `0x4f31Fa980a675570939B737Ebdde0471a4Be40Eb`

The adversary-controlled addresses are:
- EOA `0x00c58434f247dfdca49b9ee82f3013bac96f60ff` (funding source, seed caller, and final profit recipient).
- Contract `0x77ab960503659711498a4c0bc99a84e8d0a47589` (custom routing contract deployed by the EOA).

The ACT opportunity is defined at block height `44290969`, immediately before seed transaction `0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd` in block `44290970`. At this pre-state, public BSC data fully specifies balances and reserves for BEP20USDT, DCF, DCT, and their key pools, along with historical activity for the attacker EOA and contract. The pre-state is reconstructed from:
- `artifacts/root_cause/seed/56/0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd/metadata.json`
- `artifacts/root_cause/data_collector/iter_3/tx/56/0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd/pool_reserve_summary.json`
- Address txlists for the EOA and DCF/USDT pool:
  - `artifacts/root_cause/data_collector/iter_1/address/56/0x00c58434f247dfdca49b9ee82f3013bac96f60ff/txlist_44280000-44300000.json`
  - `artifacts/root_cause/data_collector/iter_2/address/56/0x8487f846d59f8fb4f1285c64086b47e2626c01b6/txlist_44280000-44300000.json`

## Vulnerability Analysis

The core vulnerability is an economic and logic flaw in how DCF and DCT interact with their LPs and pools, rather than a conventional reentrancy or access-control bug. Reviewing the verified DCF and DCT sources together with reserve and trace data shows that:
- DCF’s transfer and helper functions, when exercised via router paths and liquidity operations, allow large DCF amounts to be minted, burned, or redistributed in ways that change LP token balances without maintaining a strict relationship between USDT reserves and LP shares.
- DCT’s LP-related functions similarly enable DCT/USDT reserves to be shifted while DCT supply and balances adjust in ways that do not enforce conservation of USDT‑denominated LP value.
- When these behaviors are composed with flash loans and AMM swaps, an external contract can temporarily borrow USDT, route it through DCF and DCT interactions, and end with a net USDT gain while LPs in the DCF/USDT pool lose USDT and gain only DCF exposure.

This design violates several security principles:
- **Conservation of LP value:** DCF/USDT LPs can lose nearly all USDT reserves while receiving DCF whose USDT‑denominated value does not compensate the loss.
- **Flash-loan safety:** The protocol was not hardened against adversarial compositions of flash loans, router paths, and custom tokenomics, enabling large reserve shifts in a single transaction.
- **Invariant-based design:** There is no robust on-chain invariant tying LP share value to USDT reserves across DCF and DCT pools.
- **Economic least privilege:** Arbitrary callers are given powerful value-moving levers (via transfers and LP helpers) without additional safeguards such as rate limits or sanity checks.

These properties collectively create an ACT-style protocol bug that any searcher can exploit given access to public on-chain state, traces, and verified contract sources.

## Detailed Root Cause Analysis

### Root Cause Summary

The DCF–DCT ecosystem allows an attacker to use flash-loaned USDT and DCF/DCT tokenomics to move USDT value from DCF LPs to DCT LPs and the attacker’s addresses without preserving USDT‑denominated LP value. Specifically:
- DCF token logic and LP-related operations permit reserve and balance movements that decouple LP shares from underlying USDT value in the DCF/USDT pool.
- DCT token and its DCT/USDT pool enable complementary reserve shifts that absorb USDT while adjusting DCT balances.
- Combined with flash loans, these behaviors let an attacker drain USDT from the DCF/USDT pool, enrich DCT/USDT, and retain a large USDT balance in their contract, later swept to the EOA.

### Evidence from Traces and Reserves

The seed transaction is:
- Chain: BSC (`chainid = 56`)
- Seed txhash: `0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd`
- Role: `seed`

The Foundry execution trace for this transaction shows the attacker contract orchestrating nested USDT flash loans from multiple Pancake V3 pools and routing them through DCF and DCT interactions:

```bash
# Seed transaction trace excerpt for tx 0xb3759...
cat artifacts/root_cause/seed/56/0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd/trace.cast.log
```

An excerpt illustrates the structure of nested `flash` calls and USDT transfers:

```text
0x77aB960503659711498A4C0BC99a84e8D0A47589::47e493d5(000000000000000000000000a7e92345ddf541aa5cf60fee2a0e721c50ca1adb)
  ├─ PancakeV3Pool::flash(..., 5322925517933464020123149, 0, ...)
  │   ├─ BEP20USDT::transfer(0x77aB960503659711498A4C0BC99a84e8D0A47589, 5322925517933464020123149)
  ├─ 0x77aB9605...::pancakeV3FlashCallback(...)
  │   ├─ PancakeV3Pool::flash(..., 44801797770412691497103674, 0, ...)
  │   │   ├─ BEP20USDT::transfer(0x77aB9605..., 44801797770412691497103674)
  │   ├─ 0x4f31Fa98...::flash(..., 13480584228357223259817393, 0, ...)
  │   │   ├─ BEP20USDT::transfer(0x77aB9605..., 13480584228357223259817393)
  ...
```

The corresponding `balance_diff.json` for the seed transaction confirms large USDT movements from the flash-loan pools into the attacker contract:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x77ab960503659711498a4c0bc99a84e8d0a47589",
      "before": "0",
      "after": "442028607465892649035455",
      "delta": "442028607465892649035455",
      "contract_name": "BEP20USDT"
    }
  ]
}
```

The `pool_reserve_summary.json` around blocks 44,290,969–44,290,970 shows:
- DCF/USDT pool `0x8487...` loses almost all USDT reserves, dropping from `698,634,425,616,096,796,822,251` to `39,351,777,270,094,825` units, while its DCF reserve increases from `4,074,442,371,848,803,073,636` to `78,618,712,756,698,854,301`.
- DCT/USDT pool `0x5aac73...` gains USDT reserves, increasing from `449,993,288,709,649,796,088,892` to `588,023,199,185,192,380,984,868`, while its DCT reserve decreases.

These reserve transitions are consistent with the attacker using flash‑loaned USDT and DCF/DCT tokenomics to move USDT out of the DCF/USDT pool and into DCT/USDT and the attacker contract.

### Vulnerable Components and Conditions

The vulnerable components are:
- DCF token `0xa7e9...` (DCF.sol) and its LP-related transfer/tokenomics logic.
- DCT token `0x56f4...` and its LP-related accounting in the DCT/USDT pool.
- DCF/USDT pair `0x8487...` whose reserves are dramatically skewed by the exploit.
- DCT/USDT pair `0x5aac73...` which accumulates USDT and participates in the routing path.
- Pancake V3 USDT pools (`0x92b78...`, `0x366961...`, `0x4f31Fa...`) providing flash liquidity.

The ACT exploit conditions are:
- DCF and DCT must retain their observed tokenomics and LP-accounting behavior, including the ability to move value between DCF/USDT and DCT/USDT without enforcing a strict USDT‑value invariant for LPs.
- DCF/USDT and DCT/USDT must be sufficiently liquid to support the flash-loan and swap sequence at acceptable slippage.
- Pancake V3 USDT pools must offer adequate flash liquidity (`flash` calls) for USDT.
- The attacker must be able to deploy a routing contract like `0x77ab96...` and pre-fund an EOA with DCF/DCT and gas.
- All contracts and pools must remain callable via standard BSC RPC so the sequence can be simulated and submitted by any searcher.

## Adversary Flow Analysis

### Adversary Accounts and Roles

The adversary cluster consists of:
- **EOA 0x00c58434f247dfdca49b9ee82f3013bac96f60ff**
  - Sender of all attacker-crafted transactions in the sequence.
  - Pays gas across funding, deployment, priming, main exploit, and out(USDT) steps.
  - Final recipient of the harvested BEP20USDT in tx `0xe8cd91...` per its `balance_diff.json`.
- **Contract 0x77ab960503659711498a4c0bc99a84e8d0a47589**
  - Deployed by the EOA in tx `0x81fd83...`.
  - Executes all routing logic in the seed transaction `0xb3759...` including flash loans, swaps, and interactions with DCF/USDT and DCT/USDT pools.
  - Temporarily holds the large BEP20USDT balance (`442,028,607,465,892,649,035,455` units) before out(USDT).

Victim and infrastructure addresses include:
- DCF/USDT PancakePair (DCF LP) at `0x8487f846d59f8fb4f1285c64086b47e2626c01b6` (unverified source locally).
- DCT/USDT PancakePair (DCT LP) at `0x5aac7375196e9ea76b1598ed4be19b41fa5ba651` (verified).
- DCF token at `0xa7e92345ddf541aa5cf60fee2a0e721c50ca1adb` (verified).
- DCT token at `0x56f46bd073e9978eb6984c0c3e5c661407c3a447` (verified).
- BEP20USDT at `0x55d398326f99059ff775485246999027b3197955` (verified).
- DCF-side recipient contract at `0x16600100b04d17451a03575436b4090f6ff8f404` (unverified locally).

### Transaction Sequence b

The adversary strategy unfolds through five key transactions (all on BSC, `chainid = 56`):

1. **Funding / WBNB Unwrap**
   - Tx: `0xa967e1cee31b78d3a67f4c422bc30bcf0a78d1a5f4de1777497eebf2e32a6f07`
   - Type: adversary-crafted.
   - Action: EOA unwraps WBNB into native BNB via the canonical WBNB contract `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`.
   - Effect: EOA BNB balance increases by `1.12214866684874653` BNB; WBNB contract balance decreases by `1.12217909484874653` BNB; the `0.000030428` BNB difference is gas.
   - Evidence: `balance_diff.json` at  
     `artifacts/root_cause/data_collector/iter_3/tx/56/0xa967e1cee31b78d3a67f4c422bc30bcf0a78d1a5f4de1777497eebf2e32a6f07/balance_diff.json`.

2. **Attacker Contract Deployment**
   - Tx: `0x81fd83a3a38a154bc5e225de50dc0d8ca489f605acce2d09f0f21106fd6a7f61`
   - Type: adversary-crafted.
   - Action: EOA deploys contract `0x77ab96...` using standard contract-creation semantics.
   - Effect: Gas used is `3,595,825` at `1 gwei`, costing exactly `0.003595825` BNB.
   - Evidence: `trace.cast.log` and `balance_diff.json` at  
     `artifacts/root_cause/data_collector/iter_2/tx/56/0x81fd83a3a38a154bc5e225de50dc0d8ca489f605acce2d09f0f21106fd6a7f61/`.

3. **DCF Priming Self-Transfer**
   - Tx: `0x9cad0aafaab4b83fd76e81d0f2a3648e2c995384557f1345617693320c59d500`
   - Type: adversary-crafted.
   - Action: EOA calls `DCF::transfer(0x00c58434f..., 8e18)` on `0xa7e9...`.
   - Effect: Emits a standard BEP20 `Transfer` event; under DCF tokenomics this self-transfer primes DCF balances for subsequent routing. Gas used is `34,700` at `1 gwei`, costing exactly `0.0000347` BNB; ERC20 deltas are not visible in `balance_diff.json`, consistent with internal tokenomics.
   - Evidence: `trace.cast.log` and `balance_diff.json` at  
     `artifacts/root_cause/data_collector/iter_3/tx/56/0x9cad0aafaab4b83fd76e81d0f2a3648e2c995384557f1345617693320c59d500/`.

4. **Main Exploit Transaction (Seed)**
   - Tx: `0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd`
   - Type: adversary-crafted, designated as the seed transaction.
   - Action: EOA calls `0x77ab96...` with selector `0x47e493d5` and DCF address argument. The contract:
     - Takes nested USDT flash loans from Pancake V3 pools at `0x92b78...`, `0x366961...`, and `0x4f31Fa...`.
     - Routes USDT through DCF and DCT interactions, including DCF/USDT and DCT/USDT swaps and LP-related calls.
     - Uses DCF and DCT tokenomics to skew reserves: DCF/USDT loses USDT and gains DCF; DCT/USDT gains USDT while DCT balances adjust.
   - Effect:
     - DCF/USDT `0x8487...` USDT reserve drops from `698,634,425,616,096,796,822,251` to `39,351,777,270,094,825` units; DCF reserve increases from `4,074,442,371,848,803,073,636` to `78,618,712,756,698,854,301`.
     - DCT/USDT `0x5aac73...` USDT reserve increases from `449,993,288,709,649,796,088,892` to `588,023,199,185,192,380,984,868`; DCT reserve decreases.
     - Attacker contract `0x77ab96...` ends with `442,028,607,465,892,649,035,455` units of BEP20USDT.
   - Evidence:
     - Seed trace and balance diff:  
       `artifacts/root_cause/seed/56/0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd/trace.cast.log`  
       `artifacts/root_cause/seed/56/0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd/balance_diff.json`
     - Receipt and call tracer:  
       `artifacts/root_cause/data_collector/iter_2/tx/56/0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd/receipt.json`  
       `artifacts/root_cause/data_collector/iter_2/tx/56/0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd/debug_trace_callTracer.json`
     - Pool reserves:  
       `artifacts/root_cause/data_collector/iter_3/tx/56/0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd/pool_reserve_summary.json`

5. **Profit Realization (USDT Sweep to EOA)**
   - Tx: `0xe8cd91d9135d98988b8ab8197d70d7fd0ece57b79c5149e40fbd4e574b7234a0`
   - Type: adversary-crafted.
   - Action: EOA calls `0x77ab96...::out(BEP20USDT)`, which invokes `BEP20USDT::transfer(0x00c58434f..., 442,028,607,465,892,649,035,455)`.
   - Effect: Entire USDT balance moves from `0x77ab96...` to the EOA, leaving the contract with zero USDT and the EOA with the full harvested amount (minus the small gas fee for this transaction).
   - Evidence: `trace.cast.log` and `balance_diff.json` at  
     `artifacts/root_cause/data_collector/iter_2/tx/56/0xe8cd91d9135d98988b8ab8197d70d7fd0ece57b79c5149e40fbd4e574b7234a0/`.

All interactions in these transactions are permissionless: any EOA can perform identical WBNB unwraps, contract deployments, DCF transfers, flash loans, swaps, and token transfers, given sufficient balances and gas. This satisfies the definition of an ACT opportunity.

## Impact & Losses

The incident’s primary impact is a large USDT loss for DCF/USDT LPs:
- The DCF/USDT Pancake V2 pool at `0x8487...` loses almost all USDT reserves in the seed transaction, leaving LP positions heavily skewed toward DCF with much lower USDT‑denominated value.
- The DCT/USDT pool at `0x5aac73...` gains USDT reserves, effectively absorbing part of the value extracted from DCF LPs.
- The adversary EOA `0x00c58434f...` receives `442,028,607,465,892,649,035,455` units of BEP20USDT (≈ `442,028.61` USDT) via the out(USDT) transaction, while paying at most approximately `17.86` USDT in gas, as bounded by exact BNB usage and contemporaneous BNBUSDT prices.

Total loss overview:
- Token: USDT
- Amount: `≈ 4.42e5` USDT

This constitutes a substantial transfer of USDT‑denominated value away from DCF LPs and into the adversary’s portfolio and DCT-side liquidity, with no compensating mechanism for affected LPs under the current protocol design.

## References

- [1] Seed transaction metadata, trace, and balance diff for main exploit  
  `artifacts/root_cause/seed/56/0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd`
- [2] Out(USDT) transaction trace and balance diff  
  `artifacts/root_cause/data_collector/iter_2/tx/56/0xe8cd91d9135d98988b8ab8197d70d7fd0ece57b79c5149e40fbd4e574b7234a0`
- [3] Pool reserve summary for DCF/USDT and DCT/USDT around blocks 44,290,969–44,290,970  
  `artifacts/root_cause/data_collector/iter_3/tx/56/0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd/pool_reserve_summary.json`
- [4] Attacker contract deployment trace and balance diff  
  `artifacts/root_cause/data_collector/iter_2/tx/56/0x81fd83a3a38a154bc5e225de50dc0d8ca489f605acce2d09f0f21106fd6a7f61`
- [5] Verified sources for BEP20USDT, DCF, DCT, and DCT/USDT  
  `artifacts/root_cause/seed/56`
- [6] Binance BNBUSDT daily kline for 2024-11-24 (fee upper bound)  
  `https://api.binance.com/api/v3/klines?symbol=BNBUSDT&interval=1d&startTime=1732402800000&endTime=1732489200000`

