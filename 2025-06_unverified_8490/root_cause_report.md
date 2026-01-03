## Incident Overview TL;DR

On BNB Chain, an unprivileged adversary cluster executed a two-transaction, flash-assisted MEV strategy centered on the MOMO/Stablecoin Pancake V3 pool around block 51190822. In the first transaction (0x9191153c8523d97f3441a08fef1da5e4169d9c2983db9398364071daa33f59d1), the adversary used a Stablecoin flash loan and routing via Pancake SmartRouter and SwapRouter to accumulate a large MOMO position from the MOMO/Stablecoin pool while moving its price. In the second transaction (0x46551eb82de388ccf6833057a9641e21098e49319828fb69a668941e6ff11a93), the adversary unwound this MOMO position back into Stablecoin via a generic DexRouter and UniversalUniswapV3Adaptor path. The combined effect, after accounting for BNB gas costs, is a deterministic net profit of exactly 68.84941091891468265517766246 USD1 for the adversary cluster. The incident is classified as an ACT-style MEV opportunity (metadata.is_act = true, root_cause_category = mev) rather than a protocol bug or access-control failure.

## Key Background

- Protocol and pool: The incident involves the MOMO Stablecoin Pancake V3 ecosystem on BNB Chain, specifically the MOMO/Stablecoin Pancake V3 pool at `0x2c79bb8155acbaa38d96bdb5c770d2372c509a32` and a related Stablecoin flash pool at `0xbaf9f711a39271701b837c5cc4f470d533bacf33`. The protocol name in the analysis is “MOMO Stablecoin Pancake V3 Pool on BNB Chain”.
- Tokens: MOMO (`0x0b9ddfca570305128d347a263d7061e1eb774444`) is an 18‑decimal ERC20 token with liquidity on the Pancake V3 MOMO/Stablecoin pool. Stablecoin (`0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d`) is implemented via an upgradeable proxy/implementation pair and is treated as a USD‑pegged token (USD1), allowing all value flows to be measured in a single reference asset.
- Pool mechanics: PancakeV3Pool contracts for the MOMO/Stablecoin pool (`0x2c79...`) and the Stablecoin flash pool (`0xbaf9...`) follow UniswapV3‑style constant‑product and tick‑based mechanics with standard `flash` and `swap` functions. There is no special‑case logic granting privileged access to the adversary.
- Routing infrastructure: Pancake SmartRouter (`0x13f4ea83d0bd40e75c8222255bc855a974568dd4`) and SwapRouter (`0x1b81d678ffb9c0263b24a97847620c99d213eb14`) are public routers that any EOA or contract can call to route swaps through Pancake V3 pools given sufficient ERC20 approvals. DexRouter (`0x9b9efa5efa731ea9bbb0369e91fa17abf249cfd4`) and UniversalUniswapV3Adaptor (`0x7A7AD9aa93cd0A2D0255326E5Fb145CEc14997FF`) form a generic routing stack that pulls tokens via a TokenApprove/IApproveProxy contract (`0xd99cAE3FAC551f6b6Ba7B9f19bDD316951eeEE98`) and then calls UniswapV3‑style pools.
- Pre‑state and data sources: The pre‑state σ_B is defined as publicly reconstructible BNB Chain state at block 51,190,821 for Stablecoin, MOMO, the two Pancake V3 pools (`0xbaf9...` and `0x2c79...`), and the adversary addresses `{0xf514..., 0xc59..., 0x8490..., 0x5dda...}`. Evidence for this pre‑state and subsequent balance diffs includes:
  - `artifacts/root_cause/seed/56/0x9191...f59d1/metadata.json`
  - `artifacts/root_cause/seed/56/0x9191...f59d1/balance_diff.json`
  - `artifacts/root_cause/data_collector/iter_1/address/56/{0xf514...,0xc59...,0x8490...,0x5dda...}/txlist.json`
- Price data: BNB price information around the incident window comes from `artifacts/root_cause/data_collector/iter_4/other/56/bnb_price_blocks_51190822_51193024.json`, which provides a stable mapping from BNB gas expenditure to USD1‑denominated value. Stablecoin is assumed to maintain its USD1 peg for valuation.

The ACT opportunity is evaluated at block height `B = 51190822`, with the two adversary‑crafted transactions forming the minimal profitable sequence under σ_B.

## Vulnerability Analysis

The ACT opportunity arises from standard features operating on thin liquidity rather than from a discrete code defect:

- Exposed components:
  - The MOMO/Stablecoin Pancake V3 pool at `0x2c79bb8155acbaa38d96bdb5c770d2372c509a32` provides UniswapV3‑style swap pricing on relatively thin liquidity, making prices sensitive to large trades and flash‑assisted strategies.
  - The Stablecoin flash pool at `0xbaf9f711a39271701b837c5cc4f470d533bacf33` provides `9.35e21` Stablecoin units as flash liquidity to the adversary’s strategy contract.
  - Public routers and adapters — SmartRouter (`0x13f4...`), SwapRouter (`0x1b81...`), DexRouter (`0x9b9e...`), and UniversalUniswapV3Adaptor (`0x7A7A...`) — allow any account with sufficient approvals and minimal funding to compose complex multi‑hop swaps.
- Exploit conditions:
  - Sufficient flash‑loan capacity in Stablecoin from the flash pool (`0xbaf9...`) to move the price of the MOMO/Stablecoin pool (`0x2c79...`).
  - Thin liquidity in the MOMO/Stablecoin pool so that large Stablecoin‑for‑MOMO trades and the subsequent unwind can produce a net gain in Stablecoin after fees and gas.
  - Unrestricted access to public routers and adapters, with only ERC20 approvals required, so the adversary can execute both the flash‑assisted accumulation and the unwind without any privileged roles.
  - Stable or predictable BNB/USD and MOMO/Stablecoin prices over the interval between the accumulation and the unwind, ensuring the same two‑transaction sequence yields positive USD1 value.
- Security principles affected:
  - Economic neutrality for liquidity providers in thin AMM pools is violated: large flash‑assisted trades allow sophisticated searchers to extract value from LPs and counterparties.
  - The assumption that public flash loans and routing infrastructure will not be combined into deterministic multi‑step strategies that produce profit using only public data and unprivileged access is broken.

No invariant violation, access‑control bypass, or logic bug is required; the vulnerability is an economic ACT/MEV opportunity created by the interaction of thin liquidity, flash loans, and generic routing.

## Detailed Root Cause Analysis

### Transactions and inclusion feasibility

The ACT opportunity is realized through a two‑transaction sequence on BNB Chain (chainid 56):

1. **Seed transaction (index 1)**  
   - Hash: `0x9191153c8523d97f3441a08fef1da5e4169d9c2983db9398364071daa33f59d1`  
   - Type: adversary‑crafted  
   - Inclusion feasibility: A standard EOA `0xf514c02048e9296d56d693f24dfc6780a2bdd18a` submits a type‑2 transaction to strategy contract `0xc59d50e26aee2ca34ae11f08924c0bc619728e7c` with sufficient gas and fee parameters. The call uses only public functions on:
     - Stablecoin flash pool `0xbaf9f711a39271701b837c5cc4f470d533bacf33` (`flash`)
     - SmartRouter `0x13f4ea83d0bd40e75c8222255bc855a974568dd4`
     - SwapRouter `0x1b81d678ffb9c0263b24a97847620c99d213eb14`
     - MOMO/Stablecoin pool `0x2c79bb8155acbaa38d96bdb5c770d2372c509a32`  
     plus ERC20 transfers of Stablecoin and MOMO. No privileged roles, admin checks, or whitelists gate these paths, so any unprivileged adversary with minimal BNB and Stablecoin funding can reproduce the transaction in the public mempool.
   - Effect: This transaction takes a flash loan of `9.35e21` Stablecoin from `0xbaf9...`, routes the borrowed and helper‑supplied Stablecoin through the MOMO/Stablecoin V3 pool `0x2c79...` to accumulate `1.59416187664162922432782869e26` MOMO at EOA `0x5dda362775267d2c77d8a49583751174efa47e1c`, and leaves the adversary cluster net down `4.94083496965065944013e20` Stablecoin but long MOMO.

2. **Exit transaction (index 2)**  
   - Hash: `0x46551eb82de388ccf6833057a9641e21098e49319828fb69a668941e6ff11a93`  
   - Type: adversary‑crafted  
   - Inclusion feasibility: EOA `0x5dda362775267d2c77d8a49583751174efa47e1c` sends a public `smartSwapByOrderId` call to DexRouter `0x9b9efa5efa731ea9bbb0369e91fa17abf249cfd4`, which pulls MOMO via IApproveProxy/TokenApprove `0xd99cAE3FAC551f6b6Ba7B9f19bDD316951eeEE98` and routes through UniversalUniswapV3Adaptor `0x7A7AD9aa93cd0A2D0255326E5Fb145CEc14997FF` into PancakeV3Pool `0x2c79...`. All contracts are publicly callable and rely only on ERC20 approvals and standard AMM interactions, so any unprivileged adversary who controls the MOMO balance and has paid approvals can submit the same transaction and have it included under normal fee rules.
   - Effect: This transaction sells the entire `1.59416187664162922432782869e26` MOMO position from `0x5dda...` back into the same pool `0x2c79...` and receives `5.63252856601837412403e20` Stablecoin, closing the loop of the two‑step strategy.

The set `all_relevant_txs` contains exactly these two adversary‑crafted transactions.

### Trace evidence of flash loan and swaps

Seed transaction trace excerpt (flash loan and SmartRouter/PancakeV3Pool path for tx `0x9191...f59d1`):

```text
Seed transaction trace (0x9191...f59d1), flash + swap path

0xC59D50e26Aee2Ca34aE11f08924C0BC619728e7C::6ca2a392(...)
  ├─ 0xbaf9f711a39271701b837c5cC4F470d533bACf33::flash(0xC59..., 0, 9350000000000000000000 [9.35e21], 0x00)
  │   ├─ TransparentUpgradeableProxy::fallback(0xbaf9..., ...) [Stablecoin::balanceOf]
  │   ├─ TransparentUpgradeableProxy::fallback(0xC59..., 9350000000000000000000 [9.35e21])
  │   │   └─ Stablecoin::transfer(0xC59..., 9350000000000000000000 [9.35e21]) [delegatecall]
  │   ├─ 0xC59...::pancakeV3FlashCallback(0, 935000000000000000 [9.35e17], 0x00)
  │   │   ├─ SmartRouter::exactInputSingle(...)
  │   │   │   ├─ SmartRouterHelper::getPool(..., Token: [MOMO], fee: 100) → 0x2c79...
  │   │   │   └─ PancakeV3Pool::swap(0xC59..., false, 9350000000000000000000 [9.35e21], ...)
  │   │   │       └─ Token::transfer(0xC59..., 759262671378154040730935134 [7.592e26])  // MOMO out
```

Exit transaction trace excerpt (DexRouter/UniversalUniswapV3Adaptor path for tx `0x4655...1a93`):

```text
Exit transaction trace (0x4655...1a93), unwind via DexRouter and adaptor

DexRouter::smartSwapByOrderId(..., BaseRequest({ fromTokenAmount: 159416187664162922432782869 [1.594e26], ... }))
  ├─ 0xd99cAE3FAC551f6b6Ba7B9f19bDD316951eeEE98::claimTokens(Token: [MOMO], 0x5dda..., UniversalUniswapV3Adaptor: [0x7A7A...], 159416187664162922432782869 [1.594e26])
  │   └─ Token::transferFrom(0x5dda..., UniversalUniswapV3Adaptor: [0x7A7A...], 159416187664162922432782869 [1.594e26])
  └─ UniversalUniswapV3Adaptor::sellBase(0x5dda..., PancakeV3Pool: [0x2c79...], ...)
      └─ PancakeV3Pool::swap(0x5dda..., true, 159416187664162922432782869 [1.594e26], ...)
          └─ Stablecoin::transfer(0x5dda..., 563252856601837412403 [5.632e20])  // Stablecoin out
```

These traces match the narrative in the root cause analysis: the first transaction creates a large MOMO position via flash‑assisted swaps, and the second transaction routes that MOMO back through the same pool into Stablecoin.

### Quantitative profit computation

The success predicate is of type `profit`, defined over the adversary cluster:

- Reference asset: `USD1` (Stablecoin `0x8d0d...` treated as USD‑pegged).
- Adversary address cluster: `{0xf514c02048e9296d56d693f24dfc6780a2bdd18a, 0xc59d50e26aee2ca34ae11f08924c0bc619728e7c, 0x8490aa884adb08a485bc8793c17296c9e2c91294, 0x5dda362775267d2c77d8a49583751174efa47e1c}`.
- Net value change in reference asset: `68.84941091891468265517766246` USD1.
- Fees paid (gas) in reference asset: `0.31994871785678573482233754` USD1.

The valuation uses only on‑chain balance diffs and BNB price samples:

```json
// Seed tx balance diffs (0x9191...f59d1), Stablecoin & MOMO excerpts
{
  "erc20_balance_deltas": [
    {
      "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
      "holder": "0xc59d50e26aee2ca34ae11f08924c0bc619728e7c",
      "delta": "48264803792092412941512"
    },
    {
      "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
      "holder": "0x8490aa884adb08a485bc8793c17296c9e2c91294",
      "delta": "-48758887289057478885525"
    },
    {
      "token": "0x0b9ddfca570305128d347a263d7061e1eb774444",
      "holder": "0x5dda362775267d2c77d8a49583751174efa47e1c",
      "delta": "159416187664162922432782869"
    }
  ]
}
```

```json
// Exit tx balance diffs (0x4655...1a93), Stablecoin & MOMO excerpts
{
  "erc20_balance_deltas": [
    {
      "token": "0x0b9ddfca570305128d347a263d7061e1eb774444",
      "holder": "0x5dda362775267d2c77d8a49583751174efa47e1c",
      "delta": "-159416187664162922432782869"
    },
    {
      "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
      "holder": "0x5dda362775267d2c77d8a49583751174efa47e1c",
      "delta": "563252856601837412403"
    }
  ]
}
```

Summing the Stablecoin deltas across the adversary cluster over both transactions gives a net gain of `6.9169359636771468390e19` Stablecoin units, which equals `69.169359636771468390` USD1 at 18 decimals. Native balance diffs show total gas expenditure of `481466108200000` wei (sum of `-410266408200000` wei from `0xf514...` and `-71199700000000` wei from `0x5dda...`). Using the BNB price samples:

```json
// BNB price samples around blocks 51190822 and 51193024
{
  "records": [
    {
      "block_number": 51190822,
      "bnb_usd_price": { "price_usd": 664.5300934118497 }
    },
    {
      "block_number": 51193024,
      "bnb_usd_price": { "price_usd": 664.5300934118497 }
    }
  ]
}
```

the gas cost is valued as:

- BNB spent: `0.000481466108200000` BNB
- Gas cost in USD1: `0.000481466108200000 × 664.5300934118497 = 0.31994871785678573482233754` USD1

Subtracting gas from the Stablecoin gain yields a net portfolio profit of `68.84941091891468265517766246` USD1 for the adversary cluster. All quantities are derived directly from `balance_diff.json` files and price records without approximation in the arithmetic. The non_monetary success predicate fields are left empty, indicating that only monetary profit is considered.

## Adversary Flow Analysis

### Strategy summary

The adversary executes a two‑step MEV strategy:

1. A flash‑assisted accumulation transaction (tx `0x9191...f59d1`) that uses Stablecoin liquidity and Pancake V3 routing to acquire a large MOMO position while pushing the MOMO/Stablecoin pool price.
2. An unwind transaction (tx `0x4655...1a93`) that routes the MOMO back through a generic DexRouter/adapter stack into Stablecoin, capturing a net Stablecoin gain after gas.

### Adversary and victim accounts

Adversary cluster (BNB Chain, chainid 56):

- `0xf514c02048e9296d56d693f24dfc6780a2bdd18a` (EOA): Sender of the seed flash+swap transaction `0x9191...f59d1`, paying gas for the initial strategy execution.
- `0xc59d50e26aee2ca34ae11f08924c0bc619728e7c` (contract): Strategy contract called by `0xf514...` in the seed transaction; orchestrates the Stablecoin flash from `0xbaf9...` and the SmartRouter swap on the MOMO/Stablecoin pool, and ends the seed tx with a positive Stablecoin balance.
- `0x8490aa884adb08a485bc8793c17296c9e2c91294` (contract): Helper contract that supplies `4.8758887289057478885525e22` Stablecoin into the MOMO/Stablecoin pool via SwapRouter `0x1b81...`, ends the seed tx with zero Stablecoin, and is economically linked to the strategy contract and profit EOA.
- `0x5dda362775267d2c77d8a49583751174efa47e1c` (EOA): Receives the entire `1.59416187664162922432782869e26` MOMO position in the seed tx and later sends that MOMO into DexRouter `0x9b9e...` in the exit tx, receiving `5.63252856601837412403e20` Stablecoin and paying gas; this EOA is the direct profit recipient.

Victim candidates:

- Pancake V3 MOMO/Stablecoin LPs on `0x2c79bb8155acbaa38d96bdb5c770d2372c509a32` (BNB Chain, chainid 56).
- Traders providing price‑improving orderflow around the incident window who interact with the same pool at disadvantaged prices.

### Lifecycle stages

1. **Adversary preparation and approvals**  
   - Transactions: Funding and approval operations visible in `artifacts/root_cause/data_collector/iter_1/address/56/*/txlist.json` before block 51,190,822.  
   - Effect: The adversary funds EOAs and contracts with BNB and Stablecoin and sets ERC20 approvals to SmartRouter, SwapRouter, DexRouter, and TokenApprove/IApproveProxy, enabling subsequent flash‑loan and routing transactions.  
   - Evidence: Address txlists under `artifacts/root_cause/data_collector/iter_1/address/56/` and associated ERC20 transfer/Approval logs.

2. **Flash‑assisted accumulation on MOMO/Stablecoin pool**  
   - Transaction: Seed tx `0x9191...f59d1` in block 51,190,822 (mechanism: flashloan).  
   - Effect: Strategy contract `0xc59d...` borrows `9.35e21` Stablecoin from `0xbaf9...`, swaps the borrowed and helper‑supplied Stablecoin through the MOMO/Stablecoin Pancake V3 pool to accumulate `1.59416187664162922432782869e26` MOMO at EOA `0x5dda...`, and repays the flash principal plus a `9.35e17` Stablecoin fee, leaving the adversary cluster down `4.94083496965065944013e20` Stablecoin and long MOMO.  
   - Evidence: Seed `trace.cast.log` under `artifacts/root_cause/seed/56/0x9191...f59d1/trace.cast.log`, pool and router source under `artifacts/root_cause/data_collector/iter_1/contract/56/{0xbaf9...,0x2c79...,0x13f4...,0x1b81...}/source`, and seed `balance_diff.json`.

3. **Unwind of MOMO position into Stablecoin**  
   - Transaction: Exit tx `0x4655...1a93` in block 51,193,024 (mechanism: swap).  
   - Effect: EOA `0x5dda...` uses DexRouter `0x9b9e...` and UniversalUniswapV3Adaptor `0x7A7A...` to route a swap that transfers the full MOMO balance from `0x5dda...` back to pool `0x2c79...` and returns `5.63252856601837412403e20` Stablecoin to `0x5dda...`, closing the position with a gross Stablecoin gain relative to the initial outlay.  
   - Evidence: Exit `balance_diff.json` and `tx_receipt.json` under `artifacts/root_cause/data_collector/iter_3/tx/56/0x4655...1a93/`, and DexRouter/UniversalUniswapV3Adaptor source under `artifacts/root_cause/data_collector/iter_4/contract/56/{0x9b9e...,0x7A7A...}/source`.

4. **Net profit realization**  
   - Transactions: The sequence `[0x9191...f59d1, 0x4655...1a93]` across blocks 51,190,822–51,193,024 (mechanism: portfolio rebalancing).  
   - Effect: Across the two transactions, the adversary cluster’s Stablecoin holdings increase by `6.9169359636771468390e19` units and BNB balances decrease by an amount corresponding to `0.31994871785678573482233754` USD1 of gas, resulting in a net portfolio gain of `68.84941091891468265517766246` USD1 in the Stablecoin reference asset.  
   - Evidence: Stablecoin and native balance diffs in the seed and exit `balance_diff.json` files, combined with BNB price samples in `bnb_price_blocks_51190822_51193024.json`.

This lifecycle matches the ACT Root Cause Analysis section: the opportunity is reproducible by any searcher with similar pre‑state and routing capability, and it depends only on public information and deterministic contract behavior.

## Impact & Losses

- Total quantified profit in reference asset:
  - Token: `USD1 (Stablecoin 0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d)`
  - Amount: `68.84941091891468265517766246` USD1
- Economic impact description: Liquidity providers and counterparties in the MOMO/Stablecoin Pancake V3 pool collectively transfer `6.9169359636771468390e19` Stablecoin units (`69.169359636771468390` USD1) to the adversary cluster, minus `0.31994871785678573482233754` USD1 of gas paid to block producers. No protocol invariants or safety properties of the inspected contracts are broken; the effect is a redistributive MEV outcome enabled by open flash loans and routing infrastructure on a thin‑liquidity pool.

There are no additional non‑monetary impact dimensions defined in the analysis; the success criterion is purely monetary profit in the USD1 reference asset.

## References

- [1] Seed transaction metadata and trace — `artifacts/root_cause/seed/56/0x9191153c8523d97f3441a08fef1da5e4169d9c2983db9398364071daa33f59d1`
- [2] Seed balance diffs for MOMO and Stablecoin — `artifacts/root_cause/seed/56/0x9191153c8523d97f3441a08fef1da5e4169d9c2983db9398364071daa33f59d1/balance_diff.json`
- [3] Exit transaction balance diffs and receipt — `artifacts/root_cause/data_collector/iter_3/tx/56/0x46551eb82de388ccf6833057a9641e21098e49319828fb69a668941e6ff11a93`
- [4] Pancake V3 pool and router source code — `artifacts/root_cause/data_collector/iter_1/contract/56`
- [5] DexRouter and UniversalUniswapV3Adaptor source code — `artifacts/root_cause/data_collector/iter_4/contract/56`
- [6] BNB price samples around incident window — `artifacts/root_cause/data_collector/iter_4/other/56/bnb_price_blocks_51190822_51193024.json`

These references, together with the on‑chain transaction hashes and addresses listed above, are sufficient to independently reconstruct the incident, verify the traces, and recompute the adversary’s profit in USD1.

