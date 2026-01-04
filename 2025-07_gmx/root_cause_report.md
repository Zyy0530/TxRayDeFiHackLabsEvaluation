## Incident Overview TL;DR

On Arbitrum, a GMX user created an increase order that paid a 0.000300000000000000 ETH execution fee into the GMX OrderBook contract. A whitelisted keeper EOA `0xd4266f8f82f7405429ee18559e548979d49160f3` then executed that order via `PositionManager.executeIncreaseOrder`, which routed to `OrderBook.executeIncreaseOrder` and paid the entire execution fee to the keeper as ETH. After paying 20908464018000 wei of gas, the keeper realised a deterministic net profit of 279091535982000 wei in ETH. From the same pre-state, any EOA in the `isOrderKeeper` set that can call `executeIncreaseOrder` with itself as `feeReceiver` against this stored order realises the same net ETH profit while the order remains valid and price conditions hold.

The technical root cause is that GMX exposes `OrderBook.executeIncreaseOrder` as an external nonReentrant function with no `msg.sender`-based access control and a caller-specified `feeReceiver` parameter, and the GMX Router authenticates plugins using `CALLER` rather than `ORIGIN`. Once a user-funded order with a positive `executionFee` is stored in `OrderBook`, executing that order pays the entire `executionFee` to the chosen `feeReceiver`, creating a deterministic MEV-style ACT opportunity for authorised keepers or searchers.

## Key Background

- GMX on Arbitrum uses an off-chain keeper model: users submit orders via the Router and PositionManager, which store `IncreaseOrder` structs in `OrderBook` including an `executionFee` in ETH. Later, keepers execute these orders and receive the `executionFee` as compensation.
- The `aeWETH` contract at `0x8b194beae1d3e0788a1a35173978001acdfba668` wraps native ETH as ERC20 `0x82af49447d8a07e3bd95bd0d56f35241523fbab1` and is used as `purchaseToken` and `collateralToken` for WETH-denominated GMX positions. Balance diffs for the incident transactions show only this token moving between OrderBook and Vault when the order is created and executed.
- GMX Router `0x7d3bd50336f64b7a473c51f54e7f0bd6771cc355` maintains a plugin list and forwards user and keeper calls to OrderBook, Vault, and PositionManager. Disassembly of the Router bytecode shows `CALLER`-based checks for plugin authentication and no `ORIGIN` opcode, so Router cannot distinguish whether `OrderBook.executeIncreaseOrder` is reached via PositionManager or via a direct plugin call from an EOA.
- PositionManager `0x75e42e6f01baf1d6022bea862a28774a9f8a4a0c` enforces an `onlyOrderKeeper` modifier on `executeIncreaseOrder`, restricting which addresses may call it. However, once `OrderBook.executeIncreaseOrder` is entered, the logic does not re-check `msg.sender` and always pays the `executionFee` to the provided `_feeReceiver` address after price and Vault checks pass.

## Vulnerability Analysis

The ACT opportunity arises from a combination of contract interfaces and fee-handling design:

- `OrderBook` exposes `executeIncreaseOrder` as an external nonReentrant entrypoint, with no access-control modifier beyond `nonReentrant`. The function reads a stored `IncreaseOrder`, validates price, forwards the `purchaseToken` to Vault, calls `IRouter(router).pluginIncreasePosition`, and then unconditionally pays `order.executionFee` to `_feeReceiver`.
- Router authenticates plugins using `CALLER`-based checks and contains no `ORIGIN` opcode. This means Router cannot distinguish whether it is called by PositionManager or directly by a keeper EOA acting through a plugin entrypoint; the chain of calls into `OrderBook.executeIncreaseOrder` remains valid as long as plugin checks on `CALLER` pass.
- PositionManager wraps `executeIncreaseOrder` with `onlyOrderKeeper` to restrict who can route executions via this contract, but the economic outcome is that whichever keeper executes the order first chooses the `feeReceiver` and captures the entire user-funded `executionFee`.
- Execution fees are not bound to a specific executor or to protocol-controlled distribution logic. Instead, they become a deterministic profit opportunity for any keeper or searcher able to reach `executeIncreaseOrder` for a stored order and satisfy the price and Vault checks.

The core vulnerable components are:

- `GMX OrderBook` at `0x09f77e8a13de9a35a7231028187e9fd5db8a2acb` (Arbitrum): `executeIncreaseOrder` is external nonReentrant and unconditionally pays `executionFee` to a caller-specified `_feeReceiver`.
- `GMX Router` at `0x7d3bd50336f64b7a473c51f54e7f0bd6771cc355` (Arbitrum): routes execution via plugin functions authenticated solely by `CALLER`, forwarding to `OrderBook.executeIncreaseOrder`.
- `GMX PositionManager` at `0x75e42e6f01baf1d6022bea862a28774a9f8a4a0c` (Arbitrum): wraps `executeIncreaseOrder` with `onlyOrderKeeper`, forwarding keeper calls into `OrderBook` with a chosen `feeReceiver`.

The design violates the following security principles:

- Execution fee accounting is not tightly bound to the economic role of a specific keeper; any authorised keeper or searcher that satisfies the price checks can collect user-funded fees as profit, without constraints on how or by whom execution occurs.
- Exposed execution entrypoints (`executeIncreaseOrder`) allow generalised MEV strategies: they provide a direct one-transaction path from observing a stored order to receiving the fee as ETH in the same transaction.
- The protocol does not enforce that execution fees compensate a uniquely selected executor; instead, they are available to any address in the keeper set that reaches the execution first, turning user-funded fees into a deterministic competition prize.

## Detailed Root Cause Analysis

### Pre-state σ_B and stored order

The relevant pre-state σ_B is Arbitrum block `355878385` immediately after user funding transaction:

- Chain: Arbitrum One (`chainid = 42161`)
- Tx: `0x0b8cd648fb585bc3d421fc02150013eab79e211ef8d1c68100f2820ce90a4712`

From `metadata.json`, `trace.cast.log`, `balance_diff.json`, and `receipt.json` for this tx, plus `OrderBook.sol` and `aeWETH.sol`, the analyzer reconstructs:

- EOA `0xdf3340a436c27655ba62f8281565c9925c3a5221` sends `0.200300000000000000` ETH to Router `0x7d3b...`.
- Router calls into GMX components (Vault, price feeds) and then calls `OrderBook.createIncreaseOrder{value: 0.100300000000000000}` with a WETH-only path.
- Inside the WETH proxy `0x82af49447d8a07e3bd95bd0d56f35241523fbab1`, `aeWETH.deposit` mints `0.100300000000000000` `aeWETH` to OrderBook.
- `balance_diff.json` shows:
  - OrderBook’s `aeWETH` balance increase by `0.100300000000000000` token.
  - Router retaining `0.100000000000000000` ETH.
  - The user’s native balance decreasing by ~`0.200317915049540000` ETH including gas.
- The `CreateIncreaseOrder` log in the receipt records `executionFee = 0.000300000000000000` ETH (`300000000000000` wei) for this order.

σ_B therefore includes:

- `OrderBook` stores an `IncreaseOrder` for account `0x7d3b...` with `executionFee = 300000000000000` wei and `purchaseToken = aeWETH`.
- `isOrderKeeper[0xd4266f8f82f7405429ee18559e548979d49160f3] = true` in `PositionManager`.

### Permissionless execution entrypoint and fee payout

The key function in `OrderBook.sol` is:

```solidity
function executeIncreaseOrder(address _address, uint256 _orderIndex, address payable _feeReceiver) external nonReentrant {
    IncreaseOrder memory order = increaseOrders[_address][_orderIndex];
    require(order.account != address(0), "OrderBook: non-existent order");

    // increase long should use max price
    // increase short should use min price
    (uint256 currentPrice, ) = validatePositionOrderPrice(
        order.triggerAboveThreshold,
        order.triggerPrice,
        order.indexToken,
        order.isLong,
        true
    );

    delete increaseOrders[_address][_orderIndex];

    IERC20(order.purchaseToken).safeTransfer(vault, order.purchaseTokenAmount);

    if (order.purchaseToken != order.collateralToken) {
        address[] memory path = new address[](2);
        path[0] = order.purchaseToken;
        path[1] = order.collateralToken;

        uint256 amountOut = _swap(path, 0, address(this));
        IERC20(order.collateralToken).safeTransfer(vault, amountOut);
    }

    IRouter(router).pluginIncreasePosition(order.account, order.collateralToken, order.indexToken, order.sizeDelta, order.isLong);

    // pay executor
    _transferOutETH(order.executionFee, _feeReceiver);

    emit ExecuteIncreaseOrder(
        order.account,
        _orderIndex,
        order.purchaseToken,
        order.purchaseTokenAmount,
        order.collateralToken,
        order.indexToken,
        order.sizeDelta,
        order.isLong,
        order.triggerPrice,
        order.triggerAboveThreshold,
        order.executionFee,
        currentPrice
    );
}
```

Properties:

- The function is `external nonReentrant` with no access-control modifier. It does not check `msg.sender` or restrict callers beyond reentrancy protection.
- It deletes the stored `IncreaseOrder`, moves `purchaseToken` from OrderBook to Vault, triggers `pluginIncreasePosition` on Router, and then unconditionally calls `_transferOutETH(order.executionFee, _feeReceiver)`.
- The `_feeReceiver` is fully controlled by the caller of `executeIncreaseOrder`.

Disassembly of Router `0x7d3b...` shows that it uses `CALLER`-based checks for plugin authentication and includes no `ORIGIN` opcodes. This confirms that Router cannot distinguish whether `executeIncreaseOrder` is reached via PositionManager or a direct plugin path; as long as the plugin check on `CALLER` passes, the call sequence to OrderBook is valid.

### Keeper execution and realised profit

The adversary profit transaction is:

- Chain: Arbitrum One (`chainid = 42161`)
- Tx: `0x28a000501ef8e3364b0e7f573256b04b87d9a8e8173410c869004b987bf0beef`
- Sender (keeper EOA): `0xd4266f8f82f7405429ee18559e548979d49160f3`

From `metadata.json`, `debug_trace_callTracer.json`, `receipt.json`, and `balance_diff.json`:

- The keeper sends a 0-value transaction to PositionManager `0x75e4...` with selector `0xd38ab519` (`executeIncreaseOrder`) and parameters `(account=0x7d3b..., orderIndex=0, feeReceiver=0xd4266f...)`.
- The call tracer shows the sequence:
  - `EOA 0xd4266f...` → `PositionManager.executeIncreaseOrder`
  - `PositionManager` (gated by `onlyOrderKeeper`) reads the order from `OrderBook.getIncreaseOrder`, performs Vault and price checks.
  - `PositionManager` calls `OrderBook.executeIncreaseOrder(account=0x7d3b..., orderIndex=0, feeReceiver=0xd4266f...)`.
  - Inside `OrderBook.executeIncreaseOrder`, `purchaseToken` is moved to Vault, `pluginIncreasePosition` is called on Router, and `_transferOutETH(order.executionFee, _feeReceiver)` sends the execution fee to `0xd4266f...`.
- The `balance_diff.json` for tx `0x28a0...beef` records:

```json
{
  "native_balance_deltas": [
    {
      "address": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
      "before_wei": "190705247770672407830199",
      "after_wei": "190705247470672407830199",
      "delta_wei": "-300000000000000"
    },
    {
      "address": "0xd4266f8f82f7405429ee18559e548979d49160f3",
      "before_wei": "21021084863633651560",
      "after_wei": "21021363955169633560",
      "delta_wei": "279091535982000"
    }
  ]
}
```

- The WETH/aeWETH wrapper `0x82af...` decreases by `300000000000000` wei of native ETH.
- The keeper EOA `0xd4266f...` increases by `279091535982000` wei.
- `erc20_balance_deltas` show `-0.100300000000000000` `aeWETH` from OrderBook and `+0.100000000000000000` `aeWETH` to Vault, matching the position increase.
- `receipt.json` shows:
  - `gasUsed = 662961`
  - `effectiveGasPrice = 31538000` wei
  - Gas fees = `662961 * 31538000 = 20908464018000` wei.

The net ETH profit is therefore:

- `300000000000000` wei (execution fee) − `20908464018000` wei (gas) = `279091535982000` wei.

This matches the native balance delta for the keeper and confirms that executing this stored order from σ_B yields a fixed ETH profit to the executor who sets itself as `feeReceiver`.

### Deterministic ACT opportunity

Given σ_B:

- OrderBook holds an `IncreaseOrder` with `executionFee = 300000000000000` wei for account `0x7d3b...` and orderIndex 0.
- Price and Vault conditions are satisfied (as evidenced by the successful keeper execution).
- `isOrderKeeper[0xd4266f...] = true` in PositionManager; more generally, any EOA in `isOrderKeeper` can call `PositionManager.executeIncreaseOrder`.

Any EOA `X` in the `isOrderKeeper` set that submits a transaction `PositionManager.executeIncreaseOrder(account=0x7d3b..., orderIndex=0, feeReceiver=X)` while the order remains valid will:

- Enter `OrderBook.executeIncreaseOrder` with `_feeReceiver = X`.
- Cause `_transferOutETH(order.executionFee, X)` to send `300000000000000` wei of ETH to `X`.
- Pay the same gas cost as the observed keeper (up to minor variance from state-dependent gas), resulting in a net ETH profit close to `279091535982000` wei.

This is a single-transaction ACT opportunity using only:

- Publicly observable on-chain data (the stored order and `executionFee`).
- Public contract interfaces and bytecode (OrderBook, PositionManager, Vault, Router).
- Standard transaction submission from an EOA in the keeper set.

## Adversary Flow Analysis

### Adversary strategy

The adversary strategy is a one-shot MEV-style keeper execution:

- Observe a user-funded GMX increase order with a positive `executionFee` stored in OrderBook.
- Construct a transaction calling `PositionManager.executeIncreaseOrder` with `feeReceiver` set to the adversary-controlled EOA.
- Submit this transaction with competitive gas so it executes the order while price conditions hold, capturing the `executionFee` as ETH profit after gas.

### Adversary-related accounts and stakeholders

- Adversary EOA:
  - Chain: Arbitrum One
  - Address: `0xd4266f8f82f7405429ee18559e548979d49160f3`
  - Role: Sender of keeper tx `0x28a0...beef`, executor of the stored increase order, and direct recipient of the `300000000000000` wei execution fee, realising a net ETH balance increase of `279091535982000` wei.
- User EOA:
  - Chain: Arbitrum One
  - Address: `0xdf3340a436c27655ba62f8281565c9925c3a5221`
  - Role: Funds and creates the GMX increase order with the execution fee in tx `0x0b8c...4712`.
- Key contracts:
  - OrderBook: `0x09f77e8a13de9a35a7231028187e9fd5db8a2acb` (verified GMX OrderBook).
  - Router: `0x7d3bd50336f64b7a473c51f54e7f0bd6771cc355` (GMX Router, unverified source but disassembled).
  - PositionManager: `0x75e42e6f01baf1d6022bea862a28774a9f8a4a0c` (verified GMX PositionManager/BasePositionManager).
  - Vault: `0x489ee077994b6658eafa855c308275ead8097c4a` (GMX Vault).
  - aeWETH implementation: `0x8b194beae1d3e0788a1a35173978001acdfba668` (wraps `0x82af...`).

### Transaction-level lifecycle

1. **User order funding and storage**
   - Chain: Arbitrum One
   - Tx: `0x0b8cd648fb585bc3d421fc02150013eab79e211ef8d1c68100f2820ce90a4712`
   - Block: `355878385`
   - Role: `victim-observed`
   - Effect:
     - User EOA `0xdf3340...5221` sends `0.200300000000000000` ETH to Router `0x7d3b...`.
     - Router routes to `OrderBook.createIncreaseOrder` and `aeWETH.deposit`, minting `0.100300000000000000` aeWETH to OrderBook and retaining `0.100000000000000000` ETH.
     - An `IncreaseOrder` is stored with `executionFee = 300000000000000` wei.

2. **Keeper execution and fee collection**
   - Chain: Arbitrum One
   - Tx: `0x28a000501ef8e3364b0e7f573256b04b87d9a8e8173410c869004b987bf0beef`
   - Block: `355878605`
   - Role: `adversary-crafted`
   - Effect:
     - Keeper EOA `0xd4266f...60f3` calls `PositionManager.executeIncreaseOrder` with `account=0x7d3b...`, `orderIndex=0`, `feeReceiver=0xd4266f...`.
     - PositionManager forwards execution to `OrderBook.executeIncreaseOrder`.
     - OrderBook moves `0.100300000000000000` aeWETH from OrderBook to Vault and pays `300000000000000` wei of ETH as `executionFee` to `0xd4266f...`.
     - Gas fees equal `20908464018000` wei; the keeper’s net ETH profit is `279091535982000` wei, as confirmed by native balance deltas.

The `normal_transactions_355878384_355878672.json` for `0xd4266f...` over the incident window shows no conflicting activity; this keeper transaction is the unique profit realisation event for the address in that block range.

## Impact & Losses

- Total user-paid execution fee:
  - Token: ETH
  - Amount: `0.000300000000000000` ETH paid by the user order in tx `0x0b8c...4712`.
- Profit captured by keeper:
  - Net ETH profit: `0.000279091535982000` ETH to EOA `0xd4266f8f82f7405429ee18559e548979d49160f3` in tx `0x28a0...beef`.

There is no protocol insolvency or asset theft: the user explicitly funded an execution fee, and the protocol design allocates this fee entirely to the executor. However, this configuration means:

- Execution fees on GMX Arbitrum form a deterministic MEV-style revenue stream for authorised keepers.
- Once a user order with a positive `executionFee` is stored and price conditions are met, whichever keeper executes `executeIncreaseOrder` first captures the entire fee as ETH.
- Execution fairness and fee distribution depend on off-chain competition among keepers rather than on-chain constraints, concentrating value in the fastest actors within the keeper set.

## References

- Seed tx `0x0b8c...4712` metadata, trace, and balance diff:
  - `artifacts/root_cause/seed/42161/0x0b8cd648fb585bc3d421fc02150013eab79e211ef8d1c68100f2820ce90a4712/`
- Seed tx `0x28a0...beef` metadata and balance diff:
  - `artifacts/root_cause/seed/42161/0x28a000501ef8e3364b0e7f573256b04b87d9a8e8173410c869004b987bf0beef/`
- GMX OrderBook.sol source (`executeIncreaseOrder` implementation):
  - `artifacts/root_cause/data_collector/iter_1/contract/42161/0x09f77e8a13de9a35a7231028187e9fd5db8a2acb/source/src/core/OrderBook.sol`
- GMX PositionManager and BasePositionManager source:
  - `artifacts/root_cause/data_collector/iter_1/contract/42161/0x75e42e6f01baf1d6022bea862a28774a9f8a4a0c/source/`
- GMX Vault contract source:
  - `artifacts/root_cause/data_collector/iter_1/contract/42161/0x489ee077994b6658eafa855c308275ead8097c4a/source/src/Contract.sol`
- GMX Router bytecode and disassembly:
  - `artifacts/root_cause/data_collector/iter_2/contract/42161/0x7d3bd50336f64b7a473c51f54e7f0bd6771cc355/disassemble/disassembly.txt`

