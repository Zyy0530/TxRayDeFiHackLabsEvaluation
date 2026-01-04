# Usual / Uniswap V3 Usd0–USDC cross-venue arbitrage at block 22575930

## Incident Overview TL;DR

On Ethereum mainnet at block 22575930, an unprivileged searcher used a single adversary-crafted contract-creation transaction 0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8 to execute a deterministic cross-venue arbitrage between the Usd0/USDC Uniswap V3 pool 0x4e665157291dbcb25152ebb01061e4012f58add2 and the canonical USDC/WETH9 pool 0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640, facilitated by a custom helper contract 0xf195b8800B729aEe5E57851dD4330fCBB69F07EA and SwapRouter 0xe592427a0aece92de3edee1f18e0157c05861564.

A transient but fully exploitable price discrepancy between the Usd0/USDC and USDC/WETH9 Uniswap V3 pools created a deterministic MEV-style arbitrage opportunity in ETH, which a searcher realized permissionlessly using standard Uniswap and SwapRouter interfaces, with economic losses borne by LPs in the Usd0/USDC pool rather than by Usual's vault or Uniswap protocol code.

## Key Background

## Vulnerability Analysis

The root cause is a permissionless arbitrage opportunity created by a misaligned exchange rate between the Usd0/USDC Uniswap V3 pool and the USDC/WETH9 Uniswap V3 pool, combined with standard SwapRouter routing that allows a searcher to trade along the Usd0 → USDC → WETH path and capture the difference as ETH profit in a single transaction.

- Vulnerable component: Uniswap V3 Usd0/USDC pool 0x4e665157291dbcb25152ebb01061e4012f58add2 swap function, which quotes a Usd0/USDC price that diverges from the USDC/WETH9 pool price and lets searchers remove USDC against Usd0 at that rate.
- Vulnerable component: Uniswap V3 USDC/WETH9 pool 0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640 swap function, which provides the opposing leg of the USDC → WETH trade and enables the adversary to turn underpriced USDC from the Usd0/USDC pool into WETH and then ETH.
- Vulnerable component: Usual ecosystem liquidity positions in the Usd0/USDC pool, whose LPs are exposed to cross-venue price risk when Usd0 and USDC prices deviate across pools.

- Exploit condition: The Usd0/USDC Uniswap V3 pool price for USDC relative to Usd0 is lower than the effective price of USDC relative to WETH in the USDC/WETH9 Uniswap V3 pool by more than the adversary's gas costs and any routing fees.
- Exploit condition: The adversary can deploy and call helper contract 0xf195b8800B729aEe5E57851dD4330fCBB69F07EA, which interacts with SwapRouter and Uniswap V3 pools using standard ERC20 approvals and callbacks, without requiring any privileged roles.
- Exploit condition: The adversary has at least 0.15 ETH of initial capital (funded in tx 0x88a32e4e357d01d545bd5e6f850c7a8a55241b81923f31632cfaab5a730f4acf) to pay gas and support any temporary balance fluctuations along the arbitrage path.

- Security principle: Liquidity providers in correlated Uniswap V3 pools are exposed to deterministic cross-venue arbitrage when pool prices diverge and no mechanism enforces price parity or caps exposure.
- Security principle: The system does not enforce a risk control that limits Usd0/USDC pool exposure to external USDC/WETH price movements, allowing a single MEV searcher to extract a large, fee-adjusted profit in one transaction while pushing inventory imbalances onto LPs.

## Detailed Root Cause Analysis

PrestateTracer ERC20 balance diffs for FiatTokenV2_2 (USDC) in artifacts/root_cause/data_collector/iter_1/tx/1/0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8_balance_diff_prestate_tracer.json show that the Usd0/USDC pool 0x4e665157291dbcb25152ebb01061e4012f58add2 loses exactly 42877423895 USDC units (42,877.423895 USDC) while the USDC/WETH9 pool 0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640 gains the same amount. The debug_call_tracer for the seed transaction in artifacts/root_cause/data_collector/iter_2/tx/1/0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8_debug_call_tracer.json shows SwapRouter 0xe592427a0aece92de3edee1f18e0157c05861564 calling the Usd0/USDC pool with selector 0x128acb08 (swap), triggering the Uniswap V3 callback to the helper contract 0xf195b8800B729aEe5E57851dD4330fCBB69F07EA, which in turn routes USDC into the USDC/WETH9 pool and withdraws WETH. WETH9 native_balance_deltas in the same balance diff artifact show that WETH9 loses exactly 15925452345403740016 wei (15.925452345403740016 ETH), and the EOA 0x2ae2f691642bb18cd8deb13a378a0f95a9fee933 gains 15887105773747314980 wei (15.88710577374731498 ETH). This confirms that the Usd0/USDC pool sells USDC below the price implied by the USDC/WETH9 pool, allowing the searcher to convert the underpriced USDC into WETH and then into native ETH profit, with the difference between the WETH outflow and the EOA's profit exactly matching the gas paid. There is no evidence of storage corruption or access-control failures in Usual's vault/router or in Uniswap V3; the protocol logic behaves as designed, and the loss arises purely from cross-venue pricing.

```json
{
  "calls": [
    {
      "from": "0xa3931d71877c0e7a3148cb7eb4463524fec27fbd",
      "gas": "0x643729",
      "gasUsed": "0x6cb4",
      "input": "0xa9059cbb000000000000000000000000fb45bcd7239774cdbc5018fd47faf1a2fc219d1f000000000000000000000000000000000000000000000000000000000000000a",
      "logs": [
        {
          "address": "0xa3931d71877c0e7a3148cb7eb4463524fec27fbd",
          "data": "0x000000000000000000000000000000000000000000000000000000000000000a",
          "index": 0,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x000000000000000000000000f195b8800b729aee5e57851dd4330fcbb69f07ea",
            "0x000000000000000000000000fb45bcd7239774cdbc5018fd47faf1a2fc219d1f"
          ]
        }
      ],
      "output": "0x0000000000000000000000000000000000000000000000000000000000000001",
      "to": "0x4e7991e5c547ce825bdeb665ee14a3274f9f61e0",
      "type": "DELEGATECALL",
      "value": "0x0"
    }
  ],
  "from": "0xf195b8800b729aee5e57851dd4330fcbb69f07ea",
  "gas": "0x65cfc5",
  "gasUsed": "0x6e40",
  "input": "0xa9059cbb000000000000000000000000fb45bcd7239774cdbc5018fd47faf1a2fc219d1f000000000000000000000000000000000000000000000000000000000000000a",
  "output": "0x0000000000000000000000000000000000000000000000000000000000000001",
  "to": "0xa3931d71877c0e7a3148cb7eb4463524fec27fbd",
  "type": "CALL",
  "value": "0x0"
}
```

Seed transaction trace excerpt for tx 0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8 showing helper and SwapRouter interactions with Uniswap V3 pools.

```json
{
  "chainid": 1,
  "txhash": "0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8",
  "native_balance_deltas": [
    {
      "address": "0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97",
      "before_wei": "5830940823354723826",
      "after_wei": "5838345859354723826",
      "delta_wei": "7405036000000000"
    },
    {
      "address": "0x2ae2f691642bb18cd8deb13a378a0f95a9fee933",
      "before_wei": "150000000000000000",
      "after_wei": "16037105773747314980",
      "delta_wei": "15887105773747314980"
    },
    {
      "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "before_wei": "2799376188098007370170763",
      "after_wei": "2799360262645661966430747",
      "delta_wei": "-15925452345403740016"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0xa3931d71877c0e7a3148cb7eb4463524fec27fbd",
      "holder": "0xf195b8800b729aee5e57851dd4330fcbb69f07ea",
      "before": "10",
      "after": "0",
      "delta": "-10",
      "balances_slot": "2",
      "slot_key": "0x0e54b025604338dfca561efe3c1ed0f2c2a0c69b8c3b4e31f9ccce6b577f6183",
      "layout_address": "0x4e7991e5c547ce825bdeb665ee14a3274f9f61e0",
      "contract_name": "SUsds"
    },
    {
      "token": "0xa3931d71877c0e7a3148cb7eb4463524fec27fbd",
      "holder": "0xb4f2210c6641f7d018bd314fecc96f7758be3d68",
      "before": "0",
      "after": "1",
      "delta": "1",
      "balances_slot": "2",
      "slot_key": "0xb76352772fe31247e5f56acb1c106b88a31b9de9f8aa68d288690b7b2de55d4a",
      "layout_address": "0x4e7991e5c547ce825bdeb665ee14a3274f9f61e0",
      "contract_name": "SUsds"
    },
    {
      "token": "0xa3931d71877c0e7a3148cb7eb4463524fec27fbd",
      "holder": "0xef13101c5bbd737cfb2bf00bbd38c626ad6952f7",
      "before": "182235002328603076",
      "after": "182235002328603080",
      "delta": "4",
      "balances_slot": "2",
      "slot_key": "0xfd85dfc1b8704f237a6fcedafd7808f0e4f66bf32dc1f96318dfeb6481913b0a",
      "layout_address": "0x4e7991e5c547ce825bdeb665ee14a3274f9f61e0",
      "contract_name": "SUsds"
    },
    {
      "token": "0xa3931d71877c0e7a3148cb7eb4463524fec27fbd",
      "holder": "0x67ec31a47a4126a66c7bb2fe017308cf5832a4db",
      "before": "294954199841440345580623",
      "after": "294954199841440345580628",
      "delta": "5",
      "balances_slot": "2",
      "slot_key": "0xd995e7c97a171d2ee93a294db9beb5034dec75da6b40ceea96ca1fc7db44c936",
      "layout_address": "0x4e7991e5c547ce825bdeb665ee14a3274f9f61e0",
      "contract_name": "SUsds"
    },
    {
      "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "holder": "0x4e665157291dbcb25152ebb01061e4012f58add2",
      "before": "216171485590",
      "after": "173294061695",
      "delta": "-42877423895",
      "balances_slot": "9",
      "slot_key": "0xcd6597f47343796408b3e0e66e4e068fa26ff1075b26079569c2aabfb081d36c",
      "layout_address": "0x43506849d7c04f9138d1a2050bbf3a0c054402dd",
      "contract_name": "FiatTokenV2_2"
    },
    {
      "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "holder": "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
      "before": "71890369246175",
      "after": "71933246670070",
      "delta": "42877423895",
      "balances_slot": "9",
      "slot_key": "0x1f21a62c4538bacf2aabeca410f0fe63151869f172e03c0e00357ba26a341eff",
      "layout_address": "0x43506849d7c04f9138d1a2050bbf3a0c054402dd",
      "contract_name": "FiatTokenV2_2"
    }
  ],
  "erc20_balance_delta_errors": [],
  "errors": []
}
```

PrestateTracer balance diffs for the arbitrage transaction, quantifying ETH and USDC movements and confirming profit and pool losses.

## Adversary Flow Analysis

The adversary funds an EOA with ETH, deploys a purpose-built helper contract in the arbitrage transaction, and uses that contract together with SwapRouter and Uniswap V3 pools to route value along a Usd0 → USDC → WETH → ETH path, capturing a 15.88710577374731498 ETH net profit in a single deterministic transaction and then consolidating that profit into a secondary EOA.

### Adversary initial funding

EOA 0x2ae2f691642bb18cd8deb13a378a0f95a9fee933 receives exactly 0.15 ETH from 0x4388b5ec68d7ca9cb756a26b7d66b0d6d1f5c4da, providing the initial ETH capital used to pay gas and support the arbitrage.

### Adversary contract deployment and arbitrage execution

EOA 0x2ae2f691642bb18cd8deb13a378a0f95a9fee933 sends a type-2 contract-creation transaction that deploys helper contract 0xf195b8800B729aEe5E57851dD4330fCBB69F07EA and, within the same transaction, routes assets through SwapRouter 0xe592427a0aece92de3edee1f18e0157c05861564, the Usd0/USDC pool 0x4e665157291dbcb25152ebb01061e4012f58add2, the USDC/WETH9 pool 0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640, and WETH9 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 to convert USDC from the Usd0/USDC pool into ETH profit.

### Profit consolidation

EOA 0x2ae2f691642bb18cd8deb13a378a0f95a9fee933 transfers 16.03695667374731498 ETH to profit-recipient EOA 0xac5d14d7d1159009fb8b2901fe9ea2d51ee9def6, realizing the arbitrage profit at the cluster level and moving it away from the original sender address.

## Impact & Losses

Liquidity providers in the Usd0/USDC Uniswap V3 pool 0x4e665157291dbcb25152ebb01061e4012f58add2 lose exactly 42,877.423895 USDC in this transaction, as measured by the ERC20 balance diff on FiatTokenV2_2 for the pool's holder address, while the USDC/WETH9 pool 0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640 gains the same USDC amount. The adversary-related cluster {0x2ae2f691642bb18cd8deb13a378a0f95a9fee933, 0xf195b8800B729aEe5E57851dD4330fCBB69F07EA, 0xfb45bcd7239774cdbc5018fd47faf1a2fc219d1f, 0xac5d14d7d1159009fb8b2901fe9ea2d51ee9def6} realizes a net profit of 15.88710577374731498 ETH after paying 0.038346571656425036 ETH in gas fees, with the profit initially accruing to 0x2ae2f691642bb18cd8deb13a378a0f95a9fee933 and then being transferred to 0xac5d14d7d1159009fb8b2901fe9ea2d51ee9def6. Usual's core vault, router, and governance contracts do not lose assets or suffer invariant violations in this transaction; the economic impact is concentrated on LPs and on the distribution of USDC and Usd0 inventory across pools.

- USDC lost by Usd0/USDC pool LPs: 42877.423895
- ETH net profit to adversary cluster: 15.88710577374731498

## References

[1] Seed transaction metadata and on-chain trace: artifacts/root_cause/seed/1/0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8/metadata.json; artifacts/root_cause/data_collector/iter_2/tx/1/0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8_debug_call_tracer.json
[2] PrestateTracer balance and state diffs: artifacts/root_cause/data_collector/iter_1/tx/1/0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8_balance_diff_prestate_tracer.json; artifacts/root_cause/data_collector/iter_2/state/1/0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8_prestate_diff_focus_key_contracts.json
[3] Contract sources for key protocol components: artifacts/root_cause/data_collector/iter_1/contract/1/0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09/source/; artifacts/root_cause/data_collector/iter_3/contract/1/0x4e665157291dbcb25152ebb01061e4012f58add2/source/src/UniswapV3Pool.sol; artifacts/root_cause/seed/1/0xae12f6f805842e6dafe71a6d2b41b28ba5fc821e; artifacts/root_cause/seed/1/0x43506849d7c04f9138d1a2050bbf3a0c054402dd; artifacts/root_cause/seed/1/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
