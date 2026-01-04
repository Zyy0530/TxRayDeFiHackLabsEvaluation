# Incident Overview TL;DR

In Ethereum mainnet block 23134257, an on-chain searcher EOA `0xc31a49d1c4c652af57cefdef248f3c55b801c649` used the 0x MainnetSettler contract `0xDf31A70a21A1931e02033dBBa7DEaCe6c45cfd0f`, via an unverified entrypoint `0xf0d539955974b248d763d60c3663ef272dfc6971`, to execute `MainnetSettler::execute` in a way that spent Andy (ANDY) tokens from holder `0x382fFCe2287252F930E1C8DC9328dac5BF282bA1` using a pre-existing unlimited allowance. In adversary-crafted tx `0x33b2cb5bc3c0ccb97f0cc21e231ecb6457df242710dfce8d1b68935f0e05773b`, MainnetSettler calls `Andy::transferFrom` to move `88,438,777,696,239,504,000,000` ANDY from `0x382f…` to `0xF0D5…`, then routes those tokens through an ANDY/WETH UniswapV2 pair into WETH and ETH. The resulting ETH is split between `0xc31a…` (which nets `639200525661836` wei ≈ 0.6392 ETH profit after gas) and `0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97`, while `0x382f…` only loses ANDY and receives no compensation in this transaction.

The root cause is a protocol-level authorization design in 0x MainnetSettler: `execute(AllowedSlippage,bytes[],bytes32)` allows arbitrary callers to construct actions that direct the contract to perform `ERC20.transferFrom` using allowances held by other addresses (such as `0x382f…`), without binding the spend to those owners’ own transactions or fresh signatures. Any unprivileged actor who observes such allowances and available DEX liquidity can construct a single transaction that drains victim-approved tokens for their own benefit. This is an ACT-style opportunity realized here by `0xc31a…` on ANDY.

# Key Background

- **0x MainnetSettler architecture**  
  MainnetSettler `0xDf31A70a21A1931e02033dBBa7DEaCe6c45cfd0f` is a 0x settlement contract that exposes a public
  ```solidity
  function execute(
      AllowedSlippage calldata slippage,
      bytes[] calldata actions,
      bytes32 /* zid & affiliate */
  ) public payable override takerSubmitted returns (bool);
  ```
  It uses an internal dispatcher `_dispatch` to decode `actions` into concrete swap helpers such as `sellToUniswapV2`, `sellToUniswapV3`, `basicSellToPool`, and others, implemented in `MainnetTakerSubmittedFlat.sol` (verified source at `artifacts/root_cause/data_collector/iter_1/contract/1/0xdf31.../source/src/flat/MainnetTakerSubmittedFlat.sol`).

- **AllowanceHolder and forwarder context**  
  MainnetSettler inherits `AllowanceHolderContext`, which integrates with a trusted `IAllowanceHolder`:
  ```solidity
  interface IAllowanceHolder {
      function exec(
          address operator,
          address token,
          uint256 amount,
          address payable target,
          bytes calldata data
      ) external payable returns (bytes memory result);

      function transferFrom(
          address token,
          address owner,
          address recipient,
          uint256 amount
      ) external returns (bool);
  }

  abstract contract AllowanceHolderContext is Context {
      IAllowanceHolder internal constant _ALLOWANCE_HOLDER =
          IAllowanceHolder(0x0000000000001fF3684f28c67538d4D072C22734);

      function _msgSender() internal view virtual override returns (address sender) {
          sender = super._msgSender();
          if (sender == address(_ALLOWANCE_HOLDER)) {
              bytes calldata data = super._msgData();
              assembly ("memory-safe") {
                  sender := shr(0x60, calldataload(add(data.offset, sub(data.length, 0x14))))
              }
          }
      }
  }
  ```
  This design allows off-chain users to approve `AllowanceHolder` or MainnetSettler and have a separate operator consume those allowances during `execute`, but it does not bind token spending to a specific user transaction.

- **ANDY token properties**  
  The Andy token `0x68bbed6a47194eff1cf514b50ea91895597fc91e` is a standard ERC20 with conventional `approve` and `transferFrom` semantics, as seen in `artifacts/root_cause/seed/1/0x68bbed6a.../src/Contract.sol`. Its allowance behavior is standard: `approve(spender, amount)` writes an allowance, and `transferFrom(from, to, amount)` checks and decreases the allowance when called by an approved spender.

- **Victim’s prior activity and allowance**  
  Andy holder `0x382fFCe2287252F930E1C8DC9328dac5BF282bA1` is an active DeFi user. In tx
  `0x8df54ebe76c09cda530f1fccb591166c716000ec95ee5cb37dff997b2ee269f2` they call `approve` on the ANDY contract:
  ```json
  {
    "from": "0x382ffce2287252f930e1c8dc9328dac5bf282ba1",
    "to": "0x68bbed6a47194eff1cf514b50ea91895597fc91e",
    "input": "0x095ea7b3...0000000000000000df31a70a21a1931e02033dbba7deace6c45cfd0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  }
  ```
  The decoded call is `approve(0xDf31A70a21A1931e02033dBBa7DEaCe6c45cfd0f, 2^256-1)`, granting MainnetSettler an unlimited ANDY allowance. The cast replay trace (`trace.cast.log`) shows:
  ```text
  Andy::approve(0xDf31A70a21A1931e02033dBBa7DEaCe6c45cfd0f, 1157920892373...639935)
    ├─ emit Approval(owner: 0x382f..., spender: 0xDf31..., value: 2^256-1)
  ```
  and `balance_diff.json` confirms no ERC20 balance changes for ANDY in this tx, only gas paid in ETH by `0x382f…`.

  Txlist data for `0x382f…` (under `artifacts/root_cause/data_collector/iter_1/address/1/0x382f.../txlist.json`) also shows two direct interactions with MainnetSettler using methodId `0x1fff991f`:
  - `0xac852213787ed55f70a6cf5e731aba2884528c4e348b4fef99414f2ec8465620` at block 23134172  
  - `0x9168e74d195bc9d506a8abef5524f4fd86e3fd06323e202c2cf99d0e6de55abb` at block 23134405  
  indicating that `0x382f…` also uses MainnetSettler for “legit” trades before and after the incident.

- **Entrypoint contract used by the adversary**  
  Entrypoint `0xf0d539955974b248d763d60c3663ef272dfc6971` is an unverified contract used as a generic router by several EOAs, including `0xc31a…`, to call MainnetSettler and DEX routers. Verified Solidity source is not available, but QuickNode `debug_traceTransaction` outputs for txs
  `0xcd464f82ef9a4b28d98fb2e9f2de04f8875598ded3b4559abb632bba75c399ba` and
  `0x5186a3e655d8c6ac3269c71a306754f0bc3334d8403482ebd1c65cc4d64ea492`
  (`trace.debug_call.json`) show `0xf0d5…` forwarding calls into `MainnetSettler::execute` and then to UniswapV2 and other routers using calldata controlled by the sender.

# Vulnerability Analysis

The vulnerability is a protocol-level authorization flaw in MainnetSettler that creates an ACT opportunity:

- **Unbound allowance consumption**  
  MainnetSettler is designed to consume ERC20 allowances granted to itself (or via AllowanceHolder) as part of multi-hop swaps. However, its public `execute` function is callable by any address, and the internal dispatcher uses the caller-supplied `actions` bytes to decide which tokens to sell and in what amounts. There is no requirement that the token owner whose allowance is being consumed is:
  - the `msg.sender`, or  
  - a party providing a fresh, per-trade on-chain signature in the same transaction.

- **Use of victim allowances in third-party-initiated swaps**  
  For ANDY, the victim `0x382f…` granted an effectively unlimited allowance to MainnetSettler in tx `0x8df5…`. At the time of block 23134257, debug-prestate traces show:
  - `allowance(0x382f…, 0xDf31…)` is still large and non-zero.  
  - `balanceOf(0x382f…)` is `105493579719278780000000` ANDY.  
  These values are visible both in the seed `trace.cast.log` for the profit tx and in `trace.debug_prestate.json` under `artifacts/root_cause/data_collector/iter_1/tx/1/0x33b2cb5b...`.

- **Settler’s execute/dispatch path**  
  The relevant portion of the verified MainnetSettler code is:
  ```solidity
  function execute(
      AllowedSlippage calldata slippage,
      bytes[] calldata actions,
      bytes32 /* zid & affiliate */
  ) public payable override takerSubmitted returns (bool) {
      if (actions.length != 0) {
          (uint256 action, bytes calldata data) = actions.decodeCall(0);
          if (!_dispatchVIP(action, data)) {
              if (!_dispatch(0, action, data)) {
                  revertActionInvalid(0, action, data);
              }
          }
      }

      for (uint256 i = 1; i < actions.length; i = i.unsafeInc()) {
          (uint256 action, bytes calldata data) = actions.decodeCall(i);
          if (!_dispatch(i, action, data)) {
              revertActionInvalid(i, action, data);
          }
      }

      _checkSlippageAndTransfer(slippage);
      return true;
  }
  ```
  And in the MainnetMixin `_dispatch` implementation, the UniswapV2 path is:
  ```solidity
  } else if (action == uint32(ISettlerActions.UNISWAPV2.selector)) {
      (address recipient, address sellToken, uint256 bps, address pool, uint24 swapInfo, uint256 amountOutMin) =
          abi.decode(data, (address, address, uint256, address, uint24, uint256));

      sellToUniswapV2(recipient, sellToken, bps, pool, swapInfo, amountOutMin);
  }
  ```
  Inside `sellToUniswapV2` (and related helpers), MainnetSettler uses balances and allowances it holds as an operator. In combination with AllowanceHolder and Permit2 pathways, it can call `transferFrom` to move tokens from users who have given it approval.

- **Security principles violated**  
  The analysis highlights three violated principles:
  - *Authorization binding between token spend and caller identity*: MainnetSettler uses ERC20 allowances granted to itself by third-party users (like `0x382f…`) but allows arbitrary external callers to decide when and how those allowances are spent, breaking the expectation that spending is bound to the token owner’s own transaction or a directly authorized order.
  - *Least authority and confused deputy resistance*: MainnetSettler acts as an execution “deputy” with broad authority to use user allowances. It exposes low-level actions so that callers can instruct it to act on behalf of anyone who has approved it, creating a classic confused-deputy where a third party leverages the Settler’s authority (the allowance) for their own benefit.
  - *Separation of intent and execution*: Off-chain user intent, if any, is not enforced on-chain for the allowance-draining path. On-chain enforcement is purely based on pre-existing ERC20 allowances and arbitrary calldata, enabling a searcher to construct a profitable swap that does not compensate the approving user.

# Detailed Root Cause Analysis

## Pre-state and ACT feasibility

The ACT pre-state is defined at Ethereum mainnet block height **23134257**:

- `0x382f…` holds `105493579719278780000000` ANDY and has granted MainnetSettler `0xDf31…` an effectively unlimited ANDY allowance via tx `0x8df5…`.  
- The ANDY/WETH UniswapV2 pair `0xa1bF0e900FB272089c9fd299EA14BFccb1D1C2c0` and WETH9 `0xC02aaA39b223FE8D0A0e5c4F27eAD9083C756Cc2` balances match the reserves used in the later swap.  

This pre-state is evidenced by:
- Seed artifacts for tx `0x8df5…`:
  - `metadata.json`
  - `trace.cast.log`
  - `balance_diff.json`  
- QuickNode `debug_prestate` traces:
  - `artifacts/root_cause/data_collector/iter_1/tx/1/0x33b2cb5b.../trace.debug_prestate.json`  
- Contract sources:
  - MainnetSettler: `MainnetTakerSubmittedFlat.sol`  
  - Andy token: `Contract.sol` under `artifacts/root_cause/seed/1/0x68bbed6a.../src/Contract.sol`  
  - ANDY/WETH UniswapV2 pair source and router sources under `artifacts/root_cause/data_collector/iter_1/contract/1/*/source`.

The ACT opportunity relies only on:
- Public on-chain allowances and balances.  
- Verified contract code for MainnetSettler, ANDY, UniswapV2 pair, and routers.  
- Public transaction data and traces (no private orderflow).

## Exploited mechanism in MainnetSettler

The exploited mechanism is MainnetSettler’s ability, when called via `execute`, to:
1. Read and use allowances that third-party users (like `0x382f…`) have granted to it.  
2. Execute a sequence of swaps (here, ANDY → WETH → ETH) using those tokens.  
3. Send the resulting ETH to arbitrary recipients specified in the `actions` calldata.

The root_cause.json `root_cause_detail` ties this to concrete code paths:
- The `execute` function loops over `actions` and dispatches each via `_dispatchVIP` or `_dispatch`.  
- For the `UNISWAPV2` action, `_dispatch` decodes `(recipient, sellToken, bps, pool, swapInfo, amountOutMin)` and calls `sellToUniswapV2`.  
- `sellToUniswapV2` constructs the necessary transfers to the UniswapV2 pair `0xa1bF0e9…` and performs a `swap`, using the contract’s holdings and allowances as the source of `sellToken`.  
- Because MainnetSettler has an unlimited allowance on ANDY from `0x382f…`, it can pull ANDY from `0x382f…` via `transferFrom` and route the proceeds to any recipient.

The AllowanceHolder integration further supports a pattern where an operator (here, effectively the adversary) consumes token “permits” via `transferFrom` without direct involvement by the token owner in that transaction.

## Concrete transaction sequence (TransactionSequence_B)

The core ACT transaction sequence_b consists of a single adversary-crafted transaction:

- **Tx 1 (adversary-crafted)**  
  - `chainid`: 1 (Ethereum mainnet)  
  - `txhash`: `0x33b2cb5bc3c0ccb97f0cc21e231ecb6457df242710dfce8d1b68935f0e05773b`  
  - `from`: `0xc31a49d1c4c652af57cefdef248f3c55b801c649` (EOA)  
  - `to`: `0xf0d539955974b248d763d60c3663ef272dfc6971` (unverified entrypoint)  
  - `value`: `0x654` wei (small ETH value)  
  - `input` begins with selector `0x0000047b` and encodes an `actions` array that drives `MainnetSettler::execute`.

From the `metadata.json` and `trace.debug_prestate.json` for this tx:
```json
"txhash": "0x33b2cb5b...",
"from": "0xc31a49d1c4c652af57cefdef248f3c55b801c649",
"to": "0xf0d539955974b248d763d60c3663ef272dfc6971",
"input": "0x0000047b0001a10f93e6785b... (actions encoded)"
```

The call trace (`trace.cast.log` and `trace.debug_call.json`) shows:
- `0xc31a…` → `0xf0d5…` (selector `0x0000047b`).  
- `0xf0d5…` → `MainnetSettler::execute` on `0xDf31…` with a single action whose data begins with `0x38c9c147` and encodes:
  - token: ANDY `0x68bbed6a47194eff1cf514b50ea91895597fc91e`  
  - owner: `0x382fFCe2287252F930E1C8DC9328dac5BF282bA1`  
  - amount: `88438777696239504000000` ANDY.  
- Inside `execute`, MainnetSettler issues:
  ```text
  Andy::transferFrom(0x382f..., 0xF0D5..., 88438777696239504000000)
  ```
  consuming part of the existing allowance.
- Those ANDY tokens are then routed to UniswapV2Pair `0xa1bF0e900FB272089c9fd299EA14BFccb1D1C2c0`, swapped into WETH9 `0xC02aaA39b223FE8D0A0e5c4F27eAD9083C756Cc2`, and finally withdrawn to ETH.
- ETH is distributed between:
  - `0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97` (fee/partner recipient)  
  - `0xc31a49d1c4c652af57cefdef248f3c55b801c649` (adversary EOA)  
  while `0x382f…` receives no ETH or ANDY inflow in this tx.

This entire construction is feasible for any unprivileged searcher:
- The calldata layout (including `actions` encoding) is visible from the on-chain transaction input for `0x33b2cb5b…`.  
- The necessary parameters (ANDY allowance, ANDY/WETH reserves) are determined from canonical on-chain state at or before block 23134257.  
- No private mempool or privileged key is required; an EOA like `0xc31a…` can broadcast such a type-2 transaction to the public mempool with the observed gas parameters.

## Profit computation and ACT success predicate

The ACT success predicate is “profit in ETH” for the adversary EOA `0xc31a…`.

From the prestate trace and balance diff:
- `value_before_in_reference_asset` (ETH) for `0xc31a…`: `5542795268505035476` wei.  
- `value_after_in_reference_asset` for `0xc31a…`: `5543889916624416016` wei.  
- `fees_paid_in_reference_asset` (gas fee): `455447593718704` wei (from `metadata.json.normalized.totalFeeWei`).  
- Net profit after gas: `value_delta_in_reference_asset = 639200525661836` wei (~0.6392 ETH).

These numbers come from:
- `artifacts/root_cause/data_collector/iter_1/tx/1/0x33b2cb5b.../trace.debug_prestate.json` (pre-balance for `0xc31a…`).  
- `artifacts/root_cause/seed/1/0x33b2cb5b.../balance_diff.json` (native balance deltas).  
- `artifacts/root_cause/data_collector/iter_2/tx/1/0x33b2cb5b.../metadata.json` (gas fee).  

There are no offsetting outflows in the same tx, so `0xc31a…`’s net ETH position increases by `639200525661836` wei as a direct result of draining `0x382f…`’s ANDY allowance and swapping it through MainnetSettler.

# Adversary Flow Analysis

## Adversary strategy summary

The adversary behaves as a searcher running a MainnetSettler-based strategy:
- Identify a victim address with a large, liquid ERC20 allowance to MainnetSettler (here, ANDY from `0x382f…`).  
- Compute a profitable swap path via UniswapV2 that converts those tokens into WETH/ETH based on current reserves.  
- Submit a single `MainnetSettler::execute` call—via generic entrypoint `0xf0d5…`—that:
  - pulls ANDY from the victim using `transferFrom`,  
  - routes the tokens through the ANDY/WETH pair into WETH and ETH, and  
  - directs the ETH to `0xc31a…` and a fee recipient, leaving the victim uncompensated.

## Adversary-related accounts

- **Adversary EOA**  
  - Address: `0xc31a49d1c4c652af57cefdef248f3c55b801c649`  
  - Role: sends the attacker-crafted tx `0x33b2cb5b…` and related aggregator-style txs `0xcd464f82…` and `0x5186a3e6…` to entrypoint `0xf0d5…`.  
  - Evidence: txlists for `0xc31a…` and balance diffs show a positive net ETH delta of `639200525661836` wei after gas in `0x33b2cb5b…`.  

- **Victim candidates**
  - `0x382fFCe2287252F930E1C8DC9328dac5BF282bA1` (Andy holder)  
    - Grants an unlimited ANDY allowance to MainnetSettler in tx `0x8df5…`.  
    - Loses `88,438,777,696,239,504,000,000` ANDY in `0x33b2cb5b…` with no compensating inflow.  
  - `0xDf31A70a21A1931e02033dBBa7DEaCe6c45cfd0f` (MainnetSettler)  
    - Verified 0x contract used as the settlement engine.  

- **Other relevant addresses**
  - Entrypoint router: `0xf0d539955974b248d763d60c3663ef272dfc6971` (unverified).  
  - ANDY token: `0x68bbed6a47194eff1cf514b50ea91895597fc91e`.  
  - ANDY/WETH UniswapV2 pair: `0xa1bF0e900FB272089c9fd299EA14BFccb1D1C2c0`.  
  - WETH9: `0xC02aaA39b223FE8D0A0e5c4F27eAD9083C756Cc2`.  
  - ETH recipient / partner: `0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97`.

## Adversary lifecycle stages

1. **Victim allowance grant and Settler usage**
   - Txs:
     - `0x8df54ebe76c09cda530f1fccb591166c716000ec95ee5cb37dff997b2ee269f2` (block 23133529) — `approve` ANDY for MainnetSettler.  
     - `0xac852213787ed55f70a6cf5e731aba2884528c4e348b4fef99414f2ec8465620` (block 23134172) — `0x382f…` → MainnetSettler (methodId `0x1fff991f`).  
     - `0x9168e74d195bc9d506a8abef5524f4fd86e3fd06323e202c2cf99d0e6de55abb` (block 23134405) — `0x382f…` → MainnetSettler (methodId `0x1fff991f`).  
   - Effect:  
     `0x382f…` grants an unlimited ANDY allowance to MainnetSettler and continues to use MainnetSettler for its own trades. Debug-prestate for `0x33b2cb5b…` shows the ANDY allowance remains large and non-zero immediately before the attacker-crafted tx.

2. **Searcher MEV-style MainnetSettler usage**
   - Txs:
     - `0xcd464f82ef9a4b28d98fb2e9f2de04f8875598ded3b4559abb632bba75c399ba` (block 23134057) — `0xc31a…` → `0xf0d5…` (methodId `0x000004bb`), which calls MainnetSettler and DEX routers.  
     - `0x5186a3e655d8c6ac3269c71a306754f0bc3334d8403482ebd1c65cc4d64ea492` (block 23134257) — `0xc31a…` → `0xf0d5…` (methodId `0x0000050f`), also calling MainnetSettler and DEXes.  
   - Effect:  
     These transactions show `0xc31a…` operating as a general searcher or MEV strategy on top of MainnetSettler, sending multiple aggregator-style transactions that route through `0xf0d5…` into `MainnetSettler::execute` and various DEX functions. CallTracer outputs confirm `0xf0d5…` forwards into MainnetSettler and routers using caller-provided calldata.

3. **Allowance drain and profit realization**
   - Tx:
     - `0x33b2cb5bc3c0ccb97f0cc21e231ecb6457df242710dfce8d1b68935f0e05773b` (block 23134257) — the incident tx.  
   - Effect:  
     Using the ANDY allowance granted by `0x382f…` to MainnetSettler, the adversary constructs an `execute` action that:
     - Moves `88,438,777,696,239,504,000,000` ANDY from `0x382f…` to `0xf0d5…` via `transferFrom`.  
     - Deposits those ANDY tokens into the ANDY/WETH UniswapV2 pair and swaps them to WETH and then ETH.  
     - Yields positive net ETH for `0xc31a…` after gas, while `0x382f…` only loses ANDY.  
     Seed `trace.cast.log`, `balance_diff.json` for `0x33b2cb5b…`, `trace.debug_prestate.json`, and the MainnetSettler/DexRouter/UniswapV2Pair sources jointly substantiate this flow.

# Impact & Losses

- **Token-level loss**  
  - Victim: `0x382fFCe2287252F930E1C8DC9328dac5BF282bA1`.  
  - Token: ANDY (`0x68bbed6a47194eff1cf514b50ea91895597fc91e`).  
  - Amount lost in incident tx: `88,438,777,696,239,504,000,000` ANDY.  
  - Source: `balance_diff.json` for tx `0x33b2cb5b…` shows this ANDY as outflow from `0x382f…` with no ANDY or ETH inflow in that tx.

- **Market impact**  
  The ANDY sold in `0x33b2cb5b…` is deposited into the ANDY/WETH UniswapV2Pair `0xa1bF0e9…` and swapped into WETH/ETH, affecting the ANDY/ETH price around block 23134257. The precise price trajectory and any downstream liquidation cascades are out of scope for this analysis.

- **Adversary and fee recipient gains**  
  - Adversary EOA `0xc31a…` realizes a net ETH gain of `639200525661836` wei (~0.6392 ETH) after paying gas in the same tx.  
  - Address `0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97` receives `211012241593069` wei as part of the same flow (likely a partner/fee recipient), as indicated by `balance_diff.json`.  

No refunds or compensating on-chain flows to `0x382f…` occur in the incident transaction itself.

# References

- **[1] Seed trace and balance diff for profit tx**  
  - Path: `artifacts/root_cause/seed/1/0x33b2cb5bc3c0ccb97f0cc21e231ecb6457df242710dfce8d1b68935f0e05773b`  
  - Contents: `metadata.json`, `trace.cast.log`, `balance_diff.json` describing the full call tree and balance deltas for tx `0x33b2cb5b…`.

- **[2] Andy token source and victim approve tx**  
  - Path: `artifacts/root_cause/seed/1/0x68bbed6a47194eff1cf514b50ea91895597fc91e`  
  - Contents: `src/Contract.sol` (Andy ERC20 source) and the approve tx `0x8df5…` artifacts showing `approve(0xDf31…, 2^256-1)`.

- **[3] MainnetSettler verified source**  
  - Path: `artifacts/root_cause/data_collector/iter_1/contract/1/0xdf31a70a21a1931e02033dbba7deace6c45cfd0f/source/src/flat/MainnetTakerSubmittedFlat.sol`  
  - Contents: Flattened 0x Settler implementation, including `execute`, `_dispatch`, `MainnetMixin`, and `AllowanceHolderContext`.

- **[4] QuickNode debug_prestate trace for profit tx**  
  - Path: `artifacts/root_cause/data_collector/iter_1/tx/1/0x33b2cb5bc3c0ccb97f0cc21e231ecb6457df242710dfce8d1b68935f0e05773b/trace.debug_prestate.json`  
  - Contents: Pre-transaction balances and storage values for key addresses (victim, ANDY, MainnetSettler, UniswapV2 pair, WETH, adversary, fee recipient).

- **[5] CallTracer traces for adjacent Settler/entrypoint txs**  
  - Path: `artifacts/root_cause/data_collector/iter_2/tx/1`  
  - Contents: `trace.debug_call.json` and `trace.debug_prestate.json` for txs `0xac8522…`, `0x9168e7…`, `0xcd464f82…`, and `0x5186a3e6…`, showing typical MainnetSettler usage by the victim and adversary and confirming that entrypoint `0xf0d5…` forwards into `MainnetSettler::execute` and DEX routers using publicly observable calldata.

