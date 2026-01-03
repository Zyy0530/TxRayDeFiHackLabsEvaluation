# Arbitrum EVA/StandardArb OrderBook Flash-Loan Arbitrage

## 1. Incident Overview TL;DR

On Arbitrum (chainid 42161), an adversary-origin EOA `0xaa06fde501a82ce1c0365273684247a736885daf` used a custom ClonableBeaconProxy/StandardArbERC20 orchestrator `0x2faD746CfaAF68AA098f704fB6537b0a05786Df8` together with a zero-fee Morpho flash loan from `0x6c247b1F6182318877311737BaC0844bAa518F5e` to exploit a mispriced EverValueCoin (EVA) sell order on the OrderBookFactory EVA/StandardArbERC20 order book `0x03339ECAE41bc162DAcAe5c2A275C8f64D6c80A0`.

In the seed transaction `0xb13b2ab202cb902b8986cbd430d7227bf3ddca831b79786af145ccb5f00fcf3f` (block `373990723` / `0x164aa543`), the orchestrator borrowed `1,200,000,000` units of StandardArbERC20 (`0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f`), bought `60,000` EVA (`0x45D9831d8751B2325f3DBf48db748723726e1C8c`) from a resting OrderBookFactory sell order at an underpriced rate, resold the EVA into two EVA/StandardArbERC20 AMM pools `0x42a4755709DD1bBfe959b3DeA7200D4cB4f357D1` and `0x57dF9434CAb6Bc174899287Fad42058dA712AE85`, repaid the flash loan in full, and transferred the remaining `119,331,045` StandardArbERC20 back to the EOA as profit.

This is an anyone-can-take (ACT) MEV opportunity: given the same pre-state `σ_B` (block `373990723` just before the seed transaction), any unprivileged searcher with access to the same contracts and public calldata could reproduce the exact sequence and realize the same StandardArbERC20 profit using only on-chain data and public infrastructure.

## 2. Key Background

The incident relies on the interaction of several publicly deployed contracts and token pairs on Arbitrum:

- **Morpho flash-loan lender (`0x6c247b1F6182318877311737BaC0844bAa518F5e`)**
  - Exposes an unpermissioned flash-loan interface for arbitrary ERC20 tokens.
  - The relevant implementation is the `flashLoan` function in the Morpho contract:

```solidity
function flashLoan(address token, uint256 assets, bytes calldata data) external {
    require(assets != 0, ErrorsLib.ZERO_ASSETS);

    emit EventsLib.FlashLoan(msg.sender, token, assets);

    IERC20(token).safeTransfer(msg.sender, assets);

    IMorphoFlashLoanCallback(msg.sender).onMorphoFlashLoan(assets, data);

    IERC20(token).safeTransferFrom(msg.sender, address(this), assets);
}
```

  - This logic transfers `assets` of `token` to `msg.sender`, calls back into `msg.sender` via `onMorphoFlashLoan`, and then requires the same amount to be returned in the same transaction via `safeTransferFrom`. There is no fee charged in the borrowed token, so a borrower can round-trip liquidity in a single transaction without paying any fee in StandardArbERC20.

- **OrderBookFactory EVA/StandardArbERC20 order book (`0x03339ECAE41bc162DAcAe5c2A275C8f64D6c80A0`)**
  - Implements a user-priced limit order book over pairs defined in `PairLib`.
  - For the EVA/StandardArbERC20 pair, users create orders with a price integer scaled by `1e18`; settlement transfers EVA and StandardArbERC20 between makers and takers according to that stored price and quantity.
  - The public `addNewOrder` entrypoint is used by the adversary orchestrator and is defined as:

```solidity
function addNewOrder(bytes32 _pairId, uint256 _quantity, uint256 _price, bool _isBuy, uint256 _timestamp)
    external
    onlyEnabledPair(_pairId)
    nonReentrant
    whenNotPaused
{
    if (_isBuy) {
        pairs[_pairId].addBuyOrder(_price, _quantity, _timestamp);
    } else {
        pairs[_pairId].addSellOrder(_price, _quantity, _timestamp);
    }
}
```

  - In the seed trace, this function is invoked on the EVA/StandardArb pair ID `0x3e0eda1b16003a6bbf05702d0b0474c698229478dc3cf66aa0f56dcb3d4df98f` with `_quantity = 60,000 * 10^18` EVA, `_price = 15,000 * 10^18`, `_isBuy = true`. During settlement, the order book transfers `884,760,000` StandardArbERC20 from the orchestrator proxy to the order book and `60,000 * 10^18` EVA from the order book to the orchestrator, partially filling a resting EVA sell order from maker address `0x61E66F0D08F64681d891D2B7E03fa3304d7b68d2` and updating `lastTradePrice` from `12,260` to `14,746`.

- **EVA and StandardArbERC20 tokens**
  - EVA (`0x45D9831d8751B2325f3DBf48db748723726e1C8c`) and StandardArbERC20 (`0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f`) are standard ERC20 tokens used as base and quote assets in the order book and as the token pair in the AMM pools.

- **EVA/StandardArbERC20 AMM pools**
  - `0x42a4755709DD1bBfe959b3DeA7200D4cB4f357D1` (UniswapV3Pool-like) and `0x57dF9434CAb6Bc174899287Fad42058dA712AE85` (PancakeV3Pool-like) are verified concentrated-liquidity pools for the EVA/StandardArbERC20 pair.
  - Pricing in each pool is fully determined by their on-chain reserves, fee parameters, and swap calldata. In the seed transaction, these pools respectively send `504,060,866` and `500,030,179` StandardArbERC20 to the orchestrator in exchange for two `30,000 * 10^18` EVA swaps.

- **ClonableBeaconProxy/StandardArbERC20 orchestrator (`0x2faD746CfaAF68AA098f704fB6537b0a05786Df8`)**
  - A ClonableBeaconProxy whose implementation is the StandardArbERC20 contract at `0x3f770Ac673856F105b586bb393d122721265aD46`.
  - Exposes a custom entrypoint `0xe3f2be84` that orchestrates the Morpho flash loan, approvals, OrderBookFactory `addNewOrder` call, AMM swaps via routers `0x1b81D678ffb9C0263b24A97847620C99d213eB14` and `0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45`, flash-loan repayment, and final profit transfer to the EOA.
  - All StandardArbERC20 logic (`approve`, `transferFrom`, `transfer`, `balanceOf`) executes via `delegatecall` from this proxy to the implementation.

## 3. Vulnerability Analysis

### 3.1 ACT Opportunity and Mispriced Order

At pre-state `σ_B` immediately before block `373990723` (`0x164aa543`), the OrderBookFactory EVA/StandardArbERC20 order book contained a resting EVA sell order from maker address `0x61E66F0D08F64681d891D2B7E03fa3304d7b68d2` on pair ID `0x3e0eda1b16003a6bbf05702d0b0474c698229478dc3cf66aa0f56dcb3d4df98f`. The on-chain price for this order, when combined with the specified quantity of `60,000 * 10^18` EVA, implied that a taker would pay only `884,760,000` StandardArbERC20 for those `60,000` EVA units.

At the same time, the two EVA/StandardArbERC20 AMM pools `0x42a4…57D1` and `0x57df…AE85` priced EVA significantly higher relative to StandardArbERC20. In the seed transaction, the orchestrator is able to resell the same `60,000 * 10^18` EVA into these pools for `504,060,866` and `500,030,179` StandardArbERC20, respectively, for a total of `1,004,091,045` StandardArbERC20.

Comparing the two legs:

- **Order-book leg (buy EVA):**
  - Pay `884,760,000` StandardArbERC20.
  - Receive `60,000 * 10^18` EVA.

- **AMM legs (sell EVA):**
  - Send `60,000 * 10^18` EVA (in two chunks of `30,000 * 10^18`).
  - Receive `504,060,866 + 500,030,179 = 1,004,091,045` StandardArbERC20.

The difference between the AMM receipts and the order-book payment is exactly `1,004,091,045 - 884,760,000 = 119,331,045` StandardArbERC20, which is the profit later realized by the adversary after repaying the `1,200,000,000`-unit flash loan.

This deterministic price discrepancy between the order book and the AMMs constitutes the core vulnerability: a publicly visible, mispriced EVA sell order exposes an anyone-can-take arbitrage where any unprivileged taker can buy EVA cheaply on the order book and sell it more expensively into AMM liquidity.

### 3.2 Flash-Loan-Enabled Capital Efficiency

The Morpho `flashLoan` interface allows any address to borrow StandardArbERC20 without collateral as long as the borrowed amount is returned in the same transaction. There is no fee in the borrowed token, and only normal gas in ETH is paid by the sender EOA.

In this incident, the orchestrator borrows `1,200,000,000` StandardArbERC20, which is sufficient to pay `884,760,000` StandardArbERC20 to the order book and still hold enough StandardArbERC20 to pay gas and maintain temporary balances during AMM swaps.

Because the flash loan is unpermissioned and fee-less in StandardArbERC20, the mispriced order requires no pre-existing StandardArbERC20 capital to exploit; any unprivileged searcher can borrow the necessary tokens, execute the order-book and AMM legs, and return the notional principal, keeping the surplus as profit.

### 3.3 Economic Safety of User Orders

The maker-side EVA sell order on OrderBookFactory is economically unsafe relative to contemporaneous AMM prices:

- The maker deposits `60,000 * 10^18` EVA into the order book.
- The order price is set such that a taker pays only `884,760,000` StandardArbERC20 for these `60,000` EVA.
- AMM pricing at `σ_B` implies that the same `60,000` EVA can be sold for `1,004,091,045` StandardArbERC20.

The difference (`119,331,045` StandardArbERC20) is a pure surplus that can be extracted by any arbitrageur. The protocol faithfully executes the maker’s specified price and quantity; there is no reentrancy or control-flow bug. The vulnerability is that the order book accepts user-provided prices that can be grossly out of line with external markets, and the combination of flash loans and liquid AMM liquidity makes such mispricing immediately exploitable on-chain.

## 4. Detailed Root Cause Analysis

### 4.1 Pre-State σ_B

The ACT opportunity is defined relative to a pre-state `σ_B` immediately before block `373990723` (`0x164aa543`) on Arbitrum. From on-chain evidence, `σ_B` includes:

- Deployed and initialized contracts:
  - Morpho flash-loan lender `0x6c247b1F6182318877311737BaC0844bAa518F5e` with the `flashLoan` implementation shown above.
  - OrderBookFactory `0x03339ECAE41bc162DAcAe5c2A275C8f64D6c80A0` with an EVA/StandardArbERC20 pair whose pair ID is `0x3e0eda1b16003a6bbf05702d0b0474c698229478dc3cf66aa0f56dcb3d4df98f`.
  - ClonableBeaconProxy/StandardArbERC20 orchestrator `0x2faD746CfaAF68AA098f704fB6537b0a05786Df8` deployed earlier by the adversary EOA.
  - EVA token `0x45D9831d8751B2325f3DBf48db748723726e1C8c` and StandardArbERC20 token `0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f`.
  - EVA/StandardArbERC20 AMM pools `0x42a4755709DD1bBfe959b3DeA7200D4cB4f357D1` and `0x57dF9434CAb6Bc174899287Fad42058dA712AE85`.

- Balances and order-book state:
  - OrderBookFactory holds at least `100,000 * 10^18` EVA (reduced to `40,000 * 10^18` EVA after the seed transaction) and maintains a resting EVA sell order from maker `0x61E66F0D08F64681d891D2B7E03fa3304d7b68d2` that is partially filled in the seed transaction.
  - AMM pools hold StandardArbERC20 and EVA reserves consistent with the pre-trade balances in `balance_diff.json` and the seed trace.

These conditions are all reconstructible from public data: the seed metadata, balance diffs, execution trace, and verified contract sources.

### 4.2 Transaction Sequence b

The ACT transaction sequence `b` consists of a single adversary-crafted transaction on Arbitrum:

- **b[1]:**
  - `chainid = 42161` (Arbitrum).
  - `txhash = 0xb13b2ab202cb902b8986cbd430d7227bf3ddca831b79786af145ccb5f00fcf3f`.
  - `from = 0xaa06fde501a82ce1c0365273684247a736885daf` (adversary EOA).
  - `to = 0x2faD746CfaAF68AA098f704fB6537b0a05786Df8` (ClonableBeaconProxy/StandardArbERC20 orchestrator).
  - `calldata` starts with selector `0xe3f2be84` followed by parameters including EVA token, OrderBookFactory address, pair ID, quantity, price, and timestamp.

The seed trace for this transaction shows the following high-level call stack and effects:

```text
0x2faD746CfaAF68AA098f704fB6537b0a05786Df8::e3f2be84(...)
  ├─ Morpho::flashLoan(token = StandardArbERC20, assets = 1,200,000,000)
  │   ├─ StandardArbERC20::transfer(lender → orchestrator, 1,200,000,000)
  │   └─ Orchestrator::onMorphoFlashLoan(assets, data)
  │       ├─ StandardArbERC20::approve(OrderBookFactory, routers, lender, ...)
  │       ├─ OrderBookFactory::addNewOrder(pairId, quantity = 60,000*1e18, price = 15,000*1e18, isBuy = true)
  │       │   ├─ StandardArbERC20::transferFrom(orchestrator → OrderBookFactory, 884,760,000)
  │       │   ├─ EverValueCoin::transfer(OrderBookFactory → orchestrator, 60,000*1e18)
  │       │   └─ emit OrderFilled / OrderPartiallyFilled (maker = 0x61E6…68d2)
  │       ├─ SwapRouter02::exactInputSingle(EVA → StandardArbERC20 via 0x42a4…57D1, amountIn = 30,000*1e18)
  │       │   └─ Pool 0x42a4…57D1 sends 504,060,866 StandardArbERC20 to orchestrator
  │       ├─ SwapRouter::exactInputSingle(EVA → StandardArbERC20 via 0x57df…AE85, amountIn = 30,000*1e18)
  │       │   └─ Pool 0x57df…AE85 sends 500,030,179 StandardArbERC20 to orchestrator
  │       ├─ StandardArbERC20::transferFrom(orchestrator → lender, 1,200,000,000)
  │       └─ StandardArbERC20::transfer(orchestrator → EOA, 119,331,045)
```

This trace is fully determined by the calldata, contract code, and pre-state balances. No private keys, admin roles, or out-of-band dependencies influence the execution once the transaction is submitted.

### 4.3 Adversary Model and Feasibility

The adversary model is fully unprivileged and consistent with ACT requirements:

- The originator is a normal EOA (`0xaa06…5daf`) with no special on-chain privileges.
- Morpho `flashLoan`, OrderBookFactory `addNewOrder`, router `exactInputSingle` functions, and token `transfer`/`transferFrom` are all publicly callable.
- The ClonableBeaconProxy/StandardArbERC20 orchestrator `0x2faD…6Df8` is deployed by the adversary EOA in a prior transaction (`0xb96d2776ed5553916a4d83dc3e9ef342a48da6afa3f7812617ece7998dffb59b`) and is addressable by any EOA that knows its address and ABI.
- There are no admin-only modifiers, whitelists, or non-standard inclusion rules gating the flash loan or order-book/AMM interactions.

Given `σ_B`, any unprivileged EOA can deploy an equivalent orchestrator contract or reuse `0x2faD…6Df8`, then submit the same calldata with identical parameters. The resulting token flows and profit are deterministic under the ACT model.

### 4.4 Profit Predicate and Accounting

The success predicate is purely monetary and is defined in terms of StandardArbERC20 balances for the adversary EOA.

From `balance_diff.json` for `0xb13b2ab2…f3f`:

- For StandardArbERC20 `0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f`:
  - `holder = 0xaa06fde501a82ce1c0365273684247a736885daf`
  - `before = 0`
  - `after = 119331045`
  - `delta = 119331045`

- For EVA `0x45d9831d8751b2325f3dbf48db748723726e1c8c`:
  - The adversary EOA does not hold EVA before or after the transaction; EVA flows occur between OrderBookFactory, the orchestrator, and the AMM pools.

- For ETH:
  - The EOA pays `7,963,600,000,000` wei in gas (`delta_wei = -7963600000000`).

The ACT success predicate in `root_cause.json` captures this precisely:

- `reference_asset = StandardArbERC20` (encoded as `other` with an explicit token address in notes).
- `value_before_in_reference_asset = 0`.
- `value_after_in_reference_asset = 119,331,045`.
- `value_delta_in_reference_asset = 119,331,045`.
- `fees_paid_in_reference_asset = 0` (flash loan is fee-less in StandardArbERC20; gas is paid in ETH).

Thus, the net positive value for the adversary in the reference asset is `+119,331,045` StandardArbERC20, which is verified on-chain.

## 5. Adversary Flow Analysis

### 5.1 Adversary-Related Accounts

The adversary cluster and victim-side accounts are:

- **Adversary cluster**
  - EOA `0xaa06fde501a82ce1c0365273684247a736885daf` (Arbitrum):
    - Originator of the seed transaction `0xb13b2ab2…f3f`.
    - Pays gas and receives `119,331,045` StandardArbERC20 net profit.
    - Its `txlist` shows deployment of the orchestrator contract and subsequent arbitrage-style activity using the same entrypoint and related swap contracts.
  - ClonableBeaconProxy/StandardArbERC20 orchestrator `0x2faD746CfaAF68AA098f704fB6537b0a05786Df8` (Arbitrum):
    - Deployed by the adversary EOA in transaction `0xb96d2776ed5553916a4d83dc3e9ef342a48da6afa3f7812617ece7998dffb59b`.
    - Executes the `onMorphoFlashLoan` callback, calls OrderBookFactory `addNewOrder`, performs the AMM swaps through routers, repays the flash loan, and transfers the residual StandardArbERC20 to the EOA.

- **Victim and liquidity-providing stakeholders**
  - OrderBookFactory EVA/StandardArbERC20 order book `0x03339ECAE41bc162DAcAe5c2A275C8f64D6c80A0` (verified): holds maker deposits and settles order-book trades, including the mispriced EVA sell order.
  - EVA/StandardArbERC20 UniswapV3Pool-like AMM `0x42a4755709DD1bBfe959b3DeA7200D4cB4f357D1` (verified): provides part of the EVA→StandardArbERC20 liquidity used for the arbitrage.
  - EVA/StandardArbERC20 PancakeV3Pool-like AMM `0x57dF9434CAb6Bc174899287Fad42058dA712AE85` (verified): provides the remainder of EVA→StandardArbERC20 liquidity.
  - EVA seller order maker `0x61E66F0D08F64681d891D2B7E03fa3304d7b68d2` (EOA): identified in OrderBookFactory `OrderFilled`/`OrderPartiallyFilled` events in the seed trace as the trader whose EVA sell order is partially filled; this address is the on-chain origin of the mispriced liquidity.

### 5.2 Adversary Lifecycle Stages

The adversary’s activity around the incident can be separated into distinct lifecycle stages:

1. **Adversary contract deployment and setup**
   - Transaction: `0xb96d2776ed5553916a4d83dc3e9ef342a48da6afa3f7812617ece7998dffb59b` (Arbitrum).
   - From `0xaa06…5daf`, `to = null` (contract creation).
   - Deploys the ClonableBeaconProxy/StandardArbERC20 orchestrator `0x2faD…6Df8`.
   - The deploy code configures StandardArbERC20 and router addresses (including `0x1b81…EB14` and `0x68b3…Fc45`) and sets up the proxy to delegate to the StandardArbERC20 implementation.
   - Evidence: adversary EOA `txlist.json` and orchestrator `disassembly.txt` show the deployment and structure of `0x2faD…6Df8`.

2. **Adversary flash-loan arbitrage execution (seed transaction)**
   - Transaction: `0xb13b2ab202cb902b8986cbd430d7227bf3ddca831b79786af145ccb5f00fcf3f` (Arbitrum, block `373990723`).
   - From `0xaa06…5daf` to `0x2faD…6Df8` with selector `0xe3f2be84`.
   - Execution flow (as per trace and balance diffs):
     - Morpho `flashLoan` transfers `1,200,000,000` StandardArbERC20 from lender `0x6c24…F5e` to the orchestrator and calls `onMorphoFlashLoan` on the orchestrator.
     - The orchestrator, via StandardArbERC20 delegatecalls, approves routers and the order book for large StandardArbERC20 allowances.
     - OrderBookFactory `addNewOrder` is invoked on pair ID `0x3e0e…f98f` with quantity `60,000 * 10^18` EVA, price `15,000 * 10^18`, and `isBuy = true`.
     - During settlement:
       - `884,760,000` StandardArbERC20 are transferred from the orchestrator to OrderBookFactory.
       - `60,000 * 10^18` EVA are transferred from OrderBookFactory to the orchestrator.
       - Order events identify maker `0x61E6…68d2` and update `lastTradePrice` from `12,260` to `14,746`.
     - The orchestrator then performs two EVA→StandardArbERC20 swaps via the two AMM pools, receiving `504,060,866` and `500,030,179` StandardArbERC20.
     - `1,200,000,000` StandardArbERC20 are transferred back from the orchestrator to the lender, repaying the flash loan in full.
     - The remaining `119,331,045` StandardArbERC20 are transferred from the orchestrator to the adversary EOA.

This sequence matches both the seed trace and the balance diffs, and there are no unresolved or speculative steps.

## 6. Impact & Losses

The impact is a deterministic transfer of StandardArbERC20 value from public liquidity sources (the order book and AMM pools) to the adversary EOA in a single transaction.

From `balance_diff.json` for `0xb13b2ab2…f3f`:

- **Adversary EOA (`0xaa06…5daf`)**
  - StandardArbERC20 balance: `0 → 119,331,045` (delta `+119,331,045`).
  - ETH balance: `4017512076411144 → 4009548476411144` (delta `-7,963,600,000,000` wei), reflecting gas costs.

- **OrderBookFactory (`0x0333…80A0`)**
  - StandardArbERC20 balance: `0 → 884,760,000` (delta `+884,760,000`).
  - EVA balance: `100,000,000000000000000000 → 40,000,000000000000000000` (delta `-60,000,000000000000000000`), representing the partially filled EVA sell order.

- **EVA/StandardArbERC20 AMM pools**
  - UniswapV3Pool-like pool `0x42a4…57D1`:
    - StandardArbERC20: `4,304,998,131 → 3,800,937,265` (delta `-504,060,866`).
    - EVA: `223,282,819,235,627,524,190,987 → 253,282,819,235,627,524,190,987` (delta `+30,000,000000000000000000`).
  - PancakeV3Pool-like pool `0x57df…AE85`:
    - StandardArbERC20: `3,979,045,444 → 3,479,015,265` (delta `-500,030,179`).
    - EVA: `204,709,849,219,905,727,544,768 → 234,709,849,219,905,727,544,768` (delta `+30,000,000000000000000000`).

The net StandardArbERC20 profit to the adversary EOA is `+119,331,045` units, matching the ACT success predicate in `root_cause.json`. The economic loss is borne by:

- The EVA maker `0x61E6…68d2`, who sells EVA for too little StandardArbERC20 relative to market prices.
- The AMM liquidity providers, whose pools pay out more StandardArbERC20 for EVA than they received via the order book leg.

The `total_loss_overview` section in `root_cause.json` correctly reports a single-asset loss:

- Token: StandardArbERC20.
- Amount: `119,331,045`.

## 7. References

The following on-disk artifacts back this analysis and are sufficient to reconstruct the ACT opportunity from public data:

- `[1]` Seed tx metadata (Arbitrum tx `0xb13b2ab2…f3f`):
  - `artifacts/root_cause/seed/42161/0xb13b2ab202cb902b8986cbd430d7227bf3ddca831b79786af145ccb5f00fcf3f/metadata.json`
- `[2]` Seed tx ERC20 balance diffs (StandardArbERC20 and EVA flows):
  - `artifacts/root_cause/seed/42161/0xb13b2ab202cb902b8986cbd430d7227bf3ddca831b79786af145ccb5f00fcf3f/balance_diff.json`
- `[3]` Seed tx execution trace (flashLoan, addNewOrder, swaps, transfers):
  - `artifacts/root_cause/seed/42161/0xb13b2ab202cb902b8986cbd430d7227bf3ddca831b79786af145ccb5f00fcf3f/trace.cast.log`
- `[4]` Morpho flash-loan contract source (`0x6c24…F5e`):
  - `artifacts/root_cause/data_collector/iter_1/contract/42161/0x6c247b1F6182318877311737BaC0844bAa518F5e/source`
- `[5]` OrderBookFactory contract source (`0x0333…80A0`):
  - `artifacts/root_cause/data_collector/iter_1/contract/42161/0x03339ECAE41bc162DAcAe5c2A275C8f64D6c80A0/source`
- `[6]` UniswapV3Pool-like EVA/StandardArbERC20 pool source (`0x42a4…57D1`):
  - `artifacts/root_cause/data_collector/iter_1/contract/42161/0x42a4755709DD1bBfe959b3DeA7200D4cB4f357D1/source`
- `[7]` PancakeV3Pool-like EVA/StandardArbERC20 pool source (`0x57df…AE85`):
  - `artifacts/root_cause/data_collector/iter_1/contract/42161/0x57dF9434CAb6Bc174899287Fad42058dA712AE85/source`
- `[8]` ClonableBeaconProxy/StandardArbERC20 orchestrator disassembly (`0x2faD…6Df8`):
  - `artifacts/root_cause/data_collector/iter_1/contract/42161/0x2faD746CfaAF68AA098f704fB6537b0a05786Df8/disassembly.txt`
- `[9]` Adversary EOA txlist including deployment and related arbitrage txs (`0xaa06…5daf`):
  - `artifacts/root_cause/data_collector/iter_2/address/42161/0xaa06fde501a82ce1c0365273684247a736885daf/txlist.json`

These artifacts, together with the verified contract sources and the state at block `373990723`, suffice to independently verify the ACT classification, adversary model, profit calculation, and lifecycle analysis described in this report.
