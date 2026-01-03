## Incident Overview TL;DR

The analyzed Arbitrum transactions are a GMX user funding an increase order via a router and a GMX keeper executing that increase order with a configured execution fee. On-chain traces, balance diffs, and verified GMX contract code show that these transactions follow the intended protocol design. There is no exploit, protocol failure, or ACT opportunity; the system operates as designed with allowlisted keepers executing user orders and receiving documented execution fees.

## Key Background

GMX on Arbitrum uses an OrderBook and PositionManager architecture for leveraged positions. Users fund increase or decrease orders through a router that interacts with the GMX OrderBook and Vault. Collateral is held in the OrderBook until an allowlisted keeper executes the order via PositionManager functions such as `executeIncreaseOrder` or `executeDecreaseOrder`.

Execution fees for GMX orders are explicitly configured at order creation. When a keeper later executes an order, the GMX contracts pay the configured execution fee to a keeper address that is registered in PositionManager as an order keeper. These fees compensate keepers for gas costs and are part of the documented protocol design.

On Arbitrum, GMX uses WETH/aeWETH and a Vault contract to manage collateral. The WETH/aeWETH token and Vault contracts are verified. The aeWETH implementation mints and burns tokens 1:1 with ETH backing, and the Vault handles deposits and withdrawals according to GMX’s leverage and collateral logic. There is no non-standard minting, burning, or accounting logic relevant to the observed transactions.

## Vulnerability Analysis

The reviewed transactions implement standard GMX order funding and keeper execution behavior. A user funds a GMX increase order via a router, which converts part of the sent ETH into WETH and credits the OrderBook as collateral, while retaining a configured amount of ETH on the router as part of the order funding path. Later, an allowlisted GMX keeper executes the increase order via PositionManager, transferring WETH collateral from the OrderBook to the Vault and receiving the configured execution fee.

Verified contract source, traces, and balance diffs confirm:
- No access control failure: `PositionManager::executeIncreaseOrder` is restricted by `onlyOrderKeeper`, and the caller in the seed keeper transaction is consistent with a GMX keeper address.
- No oracle manipulation: price queries in the trace go through GMX’s standard oracle aggregation (Chainlink and FastPriceFeed) and are used to validate the order.
- No unsafe accounting: WETH/aeWETH deposits and transfers are 1:1 with ETH backing; collateral moves exactly as expected between OrderBook and Vault.
- No reentrancy or delegatecall abuse: calls stay within verified GMX contracts and the router; the router does not perform delegatecall into untrusted addresses in the observed flows.

Because there is no bug, misconfiguration, or economic vulnerability that allows an unprivileged adversary to extract profit or cause non-monetary harm, there is no ACT root cause and no vulnerability to remediate.

## Detailed Root Cause Analysis

### Seed Transaction 1: User Order Funding (0x0b8c…4712)

On Arbitrum (chainid 42161), EOA `0xdf3340a436c27655ba62f8281565c9925c3a5221` sends `0.2003` ETH to router contract `0x7d3bd50336f64b7a473c51f54e7f0bd6771cc355` with selector `0x601894bb`. The transaction metadata and balance diffs are in:
- `artifacts/root_cause/seed/42161/0x0b8cd648fb585bc3d421fc02150013eab79e211ef8d1c68100f2820ce90a4712/metadata.json`
- `artifacts/root_cause/seed/42161/0x0b8cd648fb585bc3d421fc02150013eab79e211ef8d1c68100f2820ce90a4712/balance_diff.json`

The trace shows the router calling GMX contracts and the WETH/aeWETH proxy:

```text
Seed transaction trace (cast run -vvvvv) for tx 0x0b8c…4712
  [452331] 0x7D3BD50336f64b7A473C51f54e7f0Bd6771cc355::601894bb{value: 200300000000000000}(...)
    ├─ [22599] 0xaBBc5F99639c9B6bCb58544ddf04EFA6802F4064::approvePlugin(0x09f77E8A13De9a35a7231028187e9fD5DB8a2ACB)
    ├─ [86098] 0x489ee077994B6658eAfA855C308275EAd8097C4A::getMinPrice(TransparentUpgradeableProxy: [0x82aF49447D8a07e3bd95BD0d56f35241523fBab1]) [staticcall]
    ├─ [313108] 0x09f77E8A13De9a35a7231028187e9fD5DB8a2ACB::createIncreaseOrder{value: 100300000000000000}([...])
    │   ├─ [19811] TransparentUpgradeableProxy::fallback{value: 100300000000000000}()
    │   │   ├─ [12574] aeWETH::deposit{value: 100300000000000000}() [delegatecall]
    │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x09f77E8A13De9a35a7231028187e9fD5DB8a2ACB, value: 100300000000000000)
    │   │   └─ ← [Stop]
    │   └─ storage updates for the new order
    └─ ← [Stop]
```

The associated balance diffs show:
- The WETH/aeWETH contract at `0x82af49447d8a07e3bd95bd0d56f35241523fbab1` increases its ETH backing by `0.1003` ETH.
- The router `0x7d3bd50336f64b7a473c51f54e7f0bd6771cc355` ends with `0.1` ETH more than before.
- The user EOA loses approximately `0.20031791504954` ETH, accounting for the funded order amount and gas.

This behavior matches a GMX router that:
- Receives the user’s ETH.
- Forwards `0.1003` ETH via the WETH/aeWETH proxy to mint WETH to the OrderBook as collateral.
- Retains `0.1` ETH on the router in preparation for keeper execution and fees.

The router’s pseudo-decompilation summarizes this behavior:

```text
Pseudo-decompilation summary for router 0x7d3b…c355
1) User fund handling
- The router is the direct recipient of user ETH in tx 0x0b8c…4712, receiving 0.2003 ETH from the user EOA.
- It forwards 0.1003 ETH (via the WETH/aeWETH proxy) into the GMX OrderBook by calling deposit() and crediting WETH collateral.
- The remaining 0.1 ETH is retained in the router’s own balance as part of the GMX order funding path.
```

There is no abnormal control flow, no reentrancy, and no unexplained external sends beyond the GMX contracts involved.

### Seed Transaction 2: Keeper Order Execution (0x28a0…beef)

In the second seed transaction, EOA `0xd4266f8f82f7405429ee18559e548979d49160f3` calls GMX PositionManager `0x75e42e6f01baf1d6022bea862a28774a9f8a4a0c` with selector `0xd38ab519` (`executeIncreaseOrder`), passing:
- `user` (the account whose order is executed): `0x7d3bd50336f64b7a473c51f54e7f0bd6771cc355` (the router)
- `orderIndex`: `0`
- `feeReceiver`: `0xd4266f8f82f7405429ee18559e548979d49160f3` (the caller)

The transaction metadata and balance diffs are in:
- `artifacts/root_cause/seed/42161/0x28a000501ef8e3364b0e7f573256b04b87d9a8e8173410c869004b987bf0beef/metadata.json`
- `artifacts/root_cause/seed/42161/0x28a000501ef8e3364b0e7f573256b04b87d9a8e8173410c869004b987bf0beef/balance_diff.json`

These show:
- The WETH contract’s ETH backing decreases by `0.0003` ETH.
- The keeper EOA gains approximately `0.000279091535982` ETH (after paying gas).
- The OrderBook’s WETH balance decreases by `0.1003` WETH.
- The Vault’s WETH balance increases by `0.1` WETH.

This matches a GMX increase order execution where:
- The configured `executionFee` is `0.0003` ETH.
- The keeper receives this execution fee.
- WETH collateral of `0.1003` is partially moved from OrderBook to Vault to realize the position.

The `PositionManager::executeIncreaseOrder` function is restricted using `onlyOrderKeeper`. The collected GMX source for PositionManager confirms that only addresses in `isOrderKeeper` can call this function. The address history for `0xd4266f8f82f7405429ee18559e548979d49160f3` shows repeated calls to GMX PositionManager functions with zero transaction value and small execution fees, consistent with a GMX keeper rather than a one-off adversary.

### Code-Level Behavior

The aeWETH token and GMX contracts provide further evidence:
- The aeWETH implementation’s deposit function mints WETH tokens 1:1 with the ETH sent, updating balances and backing without custom hooks or bridge-specific logic that would affect these transactions.
- GMX OrderBook and PositionManager code handle order creation and execution with explicit bounds, oracle checks, and collateral accounting.

Together, the on-chain traces, balance diffs, and code confirm that:
- The router correctly forwards collateral and retains ETH as part of the standard GMX funding pattern.
- The keeper executes the order according to GMX rules, receiving only the configured execution fee.
- No unauthorized state changes or anomalous value flows occur.

### Root Cause Conclusion

There is no ACT root cause. The seed transactions implement:
- Standard GMX user behavior: funding an increase order via a router, which partially converts ETH to WETH collateral and retains some ETH for fees.
- Standard GMX keeper behavior: an allowlisted keeper executing the order via `executeIncreaseOrder`, transferring collateral between OrderBook and Vault and receiving the configured execution fee.

No unprivileged adversary transaction sequence b exists that yields profit or non-monetary harm relative to any pre-state sigma_B. Protocol invariants remain satisfied, and there is no vulnerability to remediate.

## Adversary Flow Analysis

No adversary is present in this scenario. The participants are:
- A normal GMX user EOA (`0xdf3340a436c27655ba62f8281565c9925c3a5221`) funding an increase order through the router.
- The GMX router contract (`0x7d3bd50336f64b7a473c51f54e7f0bd6771cc355`) acting as a front-end/aggregator for GMX OrderBook.
- The GMX OrderBook (`0x09f77E8A13De9a35a7231028187e9fD5DB8a2ACB`), PositionManager (`0x75e42e6f01baf1d6022bea862a28774a9f8a4a0c`), and Vault (`0x489ee077994B6658eAfA855C308275EAd8097C4A`) contracts.
- An allowlisted GMX keeper EOA (`0xd4266f8f82f7405429ee18559e548979d49160f3`) repeatedly calling `executeIncreaseOrder` and related functions to process user orders.

Address histories for the keeper EOA indicate repeated, small-fee interactions with GMX’s PositionManager, typical of a service account executing many orders. There is no pattern of exploiting a bug or extracting aberrant profit. The router’s behavior is deterministic and limited to the documented GMX plugin interactions.

Because there is no adversary, there is no adversary lifecycle (reconnaissance, exploitation, cash-out) and no adversary cluster to identify. The accounts involved perform their expected roles under GMX’s design.

## Impact & Losses

There is no protocol loss, user loss, or non-monetary harm resulting from these transactions. The observed value transfers are:
- User funds used to create and collateralize a GMX increase order.
- A configured GMX execution fee (`0.0003` ETH) paid from protocol flow to the allowlisted keeper when the order is executed.

These transfers are expected behavior and part of the GMX incentive model. No additional value is diverted to any account beyond these documented flows, and all collateral and accounting updates align with GMX’s design.

## References

- [1] Root cause analyzer current_analysis_result for iteration 3: `artifacts/root_cause/root_cause_analyzer/iter_3/current_analysis_result.json`
- [2] GMX OrderBook, PositionManager, and Vault verified source (Arbitrum): `artifacts/root_cause/data_collector/iter_1/contract/42161`
- [3] Router decompilation and traces for `0x7d3bd50336f64b7a473c51f54e7f0bd6771cc355`: `artifacts/root_cause/data_collector/iter_2/contract/42161/0x7d3bd50336f64b7a473c51f54e7f0bd6771cc355`
- [4] Seed transaction metadata, traces, and balance diffs: `artifacts/root_cause/seed/42161`

