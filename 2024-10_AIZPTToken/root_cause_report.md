# Flash-swap arbitrage drains BNB reserves from AIZPT314 bonding-curve token

**Protocol:** AIZPT314 bonding-curve token / Pancake V3 WBNB pool on BSC  
**Category:** MEV-style economic exploit (flash-swap arbitrage)  
**Chain / Block:** BSC (chainid 56), block 42,846,998  
**Primary adversary EOA:** `0x3026c464d3bd6ef0ced0d49e80f171b58176ce32`  
**Primary transaction:** `0x5e694707337cca979d18f9e45f40e81d6ca341ed342f1377f563e779a746460d`

---

## Incident Overview & TL;DR

At BSC block 42,846,998, an unprivileged searcher EOA `0x3026...ce32` executed a single transaction to router `0x8408...8320` that performed a flash-swap style arbitrage between:
- Pancake V3 pool `0x36696169c63e42cd08ce11f5deebbcebae652050` (WBNB / AIZPT314), and
- The AIZPT314 bonding-curve token contract `0xbe779d420b7d573c08eee226b9958737b6218888`.

The router borrowed WBNB from the Pancake V3 pool, unwrapped it to BNB, and used that BNB to interact with AIZPT314’s on-chain bonding-curve buy/sell logic. Within the same transaction it then:
- Repaid the pool with more WBNB than it borrowed, and
- Sent the surplus WBNB to the adversary EOA as profit.

From `balance_diff.json` and the transaction receipt:
- The AIZPT314 contract’s BNB balance decreased by **39.034317811221904278 BNB**.
- The WBNB contract’s BNB balance increased by the same amount.
- The adversary EOA received **34.934317811221904278 WBNB**, paying **0.011310339 BNB** in gas, for a net profit of **≈34.923007472221904278 BNB**.

The root cause is **economic, not technical**: AIZPT314 is an ERC314-style bonding-curve token whose price function is based directly on its own BNB reserves and internal token balances. Listing this token against WBNB in a Pancake V3 pool, without any mitigation against flash-swap or large MEV trades, creates a permissionless arbitrage path that allows a searcher to extract BNB reserves from the token contract in a single transaction.

---

## Key Background

### AIZPT314 bonding-curve token (ERC314-style)

The AIZPT314 token at `0xbe779d420b7d573c08eee226b9958737b6218888` is an ERC314-style bonding-curve token:
- The contract itself custodies BNB reserves and an internal token balance.
- Buys and sells are implemented directly in the token contract, using `address(this).balance` (BNB reserves) and `_balances[address(this)]` (token inventory) to determine price.
- Transfers to the token’s own address are interpreted as **sells**, which trigger a BNB payout to the seller.

The core reserve and pricing functions are:

```solidity
// Collected AIZPT314 token source (Contract.sol)
function getReserves() public view returns (uint256, uint256) {
    return (address(this).balance, _balances[address(this)]);
}

function getAmountOut(uint256 value, bool _buy) public view returns (uint256) {
    (uint256 reserveETH, uint256 reserveToken) = getReserves();

    if (_buy) {
      return ((value * reserveToken) / (reserveETH + value)) / 2;
    } else {
      return (value * reserveETH) / (reserveToken + value);
    }
}

function buy() internal {
    require(tradingEnable, 'Trading not enable');

    uint256 swapValue = msg.value;
    uint256 token_amount = (swapValue * _balances[address(this)]) / (address(this).balance);
    ...
}

function sell(uint256 sell_amount) internal {
    require(tradingEnable, 'Trading not enable');

    uint256 ethAmount = (sell_amount * address(this).balance) /
        (_balances[address(this)] + sell_amount);
    ...
    payable(msg.sender).transfer(ethAmount);
}
```

*Caption: AIZPT314’s bonding-curve logic prices buys and sells using the contract’s own BNB reserves (`address(this).balance`) and token inventory, and pays BNB directly out of reserves on each `sell` (source: collected Contract.sol).*

This design means:
- **Buys** add BNB to the contract and remove tokens from its internal balance.
- **Sells** send BNB out of the contract, consuming BNB reserves.
- Price is a deterministic function of on-contract state, not external oracles.

### Pancake V3 pool and flash-swap capability

The Pancake V3 pool at `0x36696169c63e42cd08ce11f5deebbcebae652050` is a standard implementation linking:
- `token0`: WBNB (`0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`)
- `token1`: AIZPT314 (`0xbe779d420b7d573c08eee226b9958737b6218888`)

Pancake V3 pools support swap callbacks that allow a caller (e.g., a router) to:
- Borrow one token from the pool,
- Perform arbitrary logic using that temporary liquidity, and
- Repay the pool within the same transaction (flash-swap pattern).

The pool’s implementation enforces balance-based repayment and uses a reentrancy lock, but otherwise allows any contract to execute such swaps. There is **no protocol-level restriction** preventing a router from:
- Borrowing WBNB,
- Converting it to BNB,
- Trading against a bonding-curve token like AIZPT314, and
- Returning WBNB with an additional amount representing profit.

### Adversary transaction and opportunity

The analyzed opportunity is fully captured by a single adversary-crafted transaction:
- **Tx:** `0x5e69...460d` on BSC (chainid 56), block 42,846,998.
- **From:** EOA `0x3026...ce32`.
- **To:** Router `0x8408497c18882bfb61be9204cfff530f4ee18320`.
- **Role:** MEV-style searcher / arbitrageur.

Per `root_cause.json` and the seed metadata:
- The transaction is a standard type-2 BSC transaction with sufficient gas and fee.
- It calls the router (selector `0x69b0f29c`), which in turn calls the Pancake V3 pool (selector `0x490e6cbc`) to initiate a WBNB flash-swap.
- The router then uses the borrowed WBNB to interact with AIZPT314’s buy/sell logic and finally repays the pool, retaining surplus WBNB as profit.

The pre-state (`pre_state_sigma_B`) is the canonical BSC state immediately prior to the block, including:
- Pool reserves for WBNB/AIZPT314 in `PancakeV3Pool` `0x3669...2050`.
- BNB reserves and token balances in AIZPT314 contract `0xbe77...8888`.

---

## Adversary Flow and Economic Exploit

### High-level flow

Within a single transaction, the adversary (via the router) executes:
1. **Flash-borrow WBNB** from the Pancake V3 pool `0x3669...2050`.
2. **Unwrap WBNB to BNB**, crediting the router with BNB.
3. **Perform a sequence of buys and sells** against AIZPT314’s bonding-curve:
   - Calls into AIZPT314 with BNB to trigger `buy()` logic.
   - Repeatedly transfers large token amounts back to the AIZPT314 contract, triggering `sell()` logic many times.
4. **Re-wrap BNB to WBNB**, sending sufficient WBNB back to the pool to:
   - Repay the borrowed WBNB amount.
   - Leave additional WBNB in the pool, adjusting pool price.
5. **Send residual WBNB** to the adversary EOA as profit.

### Evidence from call trace (flash-swap and bonding-curve interaction)

The `callTracer` output for `0x5e69...460d` shows the router’s interactions with the pool, WBNB, and AIZPT314. A minimal excerpt:

```json
// Seed transaction trace (debug_traceTransaction callTracer) for tx 0x5e69...460d
{
  "calls": [
    {
      "from": "0x36696169c63e42cd08ce11f5deebbcebae652050",
      "to": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "type": "CALL",
      "input": "0xa9059cbb...0001b1ae4d6e2ef5000000",
      "value": "0x0"
    },
    {
      "from": "0x8408497c18882bfb61be9204cfff530f4ee18320",
      "to": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "type": "CALL",
      "input": "0x2e1a7d4d...0001b1ae4d6e2ef5000000",
      "value": "0x0"
    },
    {
      "from": "0x8408497c18882bfb61be9204cfff530f4ee18320",
      "to": "0xbe779d420b7d573c08eee226b9958737b6218888",
      "type": "CALL",
      "input": "0x",
      "value": "0x1b1ae4d6e2ef5000000"
    },
    {
      "from": "0x8408497c18882bfb61be9204cfff530f4ee18320",
      "to": "0xbe779d420b7d573c08eee226b9958737b6218888",
      "type": "CALL",
      "input": "0xa9059cbb...00032c931835d1b6948c0000",
      "value": "0x0"
    }
  ]
}
```

*Caption: The pool sends WBNB to the router; the router un-wraps WBNB via `withdraw` (`0x2e1a7d4d`), sends BNB into AIZPT314, then repeatedly calls `transfer` to AIZPT314 with large token amounts, triggering `sell()` and BNB payouts back to the router (source: callTracer JSON).*

Key points from the trace:
- The Pancake V3 pool `0x3669...2050` calls WBNB `0xbb4c...c095c` to transfer ~8,000 WBNB to the router.
- The router calls `withdraw(uint256)` on WBNB, unwrapping that WBNB into BNB with value matching the borrowed amount.
- The router then:
  - Sends BNB directly to the AIZPT314 contract (`CALL` with non-zero `value` and empty `input`), corresponding to a **buy** per AIZPT314’s payable fallback / `buy()` logic.
  - Repeatedly calls AIZPT314’s `transfer(address(this), amount)` (selector `0xa9059cbb` to the token contract, with `to` set to the token address), which by design invokes the `sell()` path, causing the token contract to transfer BNB back to the router many times in the same transaction.

### Evidence from receipt and logs (WBNB flows and final payouts)

The transaction receipt for `0x5e69...460d` confirms:
- WBNB transfers from pool to router and back.
- WBNB deposit and withdrawal events.
- Final WBNB transfer to the adversary EOA.

```json
// Tx receipt snippet for 0x5e69...460d (cast/eth_getTransactionReceipt)
{
  "from": "0x3026c464d3bd6ef0ced0d49e80f171b58176ce32",
  "to": "0x8408497c18882bfb61be9204cfff530f4ee18320",
  "gasUsed": "0x398701",
  "effectiveGasPrice": "0xb2d05e00",
  "logs": [
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "topics": ["Transfer", "...pool", "...router"],
      "data": "0x...0001b1ae4d6e2ef5000000"
    },
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "topics": ["Deposit", "...router"],
      "data": "0x...0001b3cc032f6b8895bb96"
    },
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "topics": ["Transfer", "...router", "...pool"],
      "data": "0x...0001b1e7338e75f01a0000"
    },
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "topics": ["Transfer", "...router", "...3026c4...ce32"],
      "data": "0x...000000000000001e4cfa0f5987bbb96"
    }
  ],
  "status": "0x1"
}
```

*Caption: Receipt logs show WBNB transferred from the pool to the router, a WBNB `Deposit` (wrap of BNB), WBNB transferred back from the router to the pool, and the final WBNB transfer of ~34.9343 WBNB from the router to the adversary EOA (source: tx receipt JSON).*

This log pattern matches the narrative:
- Router borrows WBNB, wraps/un-wraps, interacts with AIZPT314, then:
  - Returns >8,000 WBNB to the pool.
  - Sends 34.934317811221904278 WBNB to the adversary.

### Evidence from balance diffs (BNB reserves drained from AIZPT314)

`balance_diff.json` for the seed transaction quantifies native BNB flow:

```json
// State delta summary for tx 0x5e69...460d (prestateTracer diff)
{
  "native_balance_deltas": [
    {
      "address": "0x3026c464d3bd6ef0ced0d49e80f171b58176ce32",
      "delta_wei": "-11310339000000000"
    },
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "delta_wei": "39034317811221904278"
    },
    {
      "address": "0xbe779d420b7d573c08eee226b9958737b6218888",
      "delta_wei": "-39034317811221904278"
    }
  ]
}
```

*Caption: Native balance deltas show AIZPT314 losing 39.0343 BNB, WBNB gaining the same amount, and the adversary EOA only losing gas (≈0.0113 BNB), consistent with reserves being drained from the token into WBNB and then partially paid out as profit (source: balance_diff.json).*

From these deltas:
- AIZPT314’s BNB reserves **decrease by 39.034317811221904278 BNB**.
- WBNB’s BNB backing **increases by the same amount**.
- The EOA’s only BNB loss is gas (`-0.011310339 BNB`), meaning the actual value extraction is in WBNB.

Combining the balance deltas with ERC20 transfer logs:
- AIZPT314 sends BNB to the router many times during `sell()` calls.
- WBNB’s balance increases as the router wraps that BNB back into WBNB.
- The router then splits WBNB between the pool (repayment) and the adversary EOA (profit).

### Root cause: permissionless arbitrage on bonding-curve reserves

The exploit is **not** due to a reentrancy bug, access-control error, or mis-implementation of the Pancake V3 pool. Instead, it arises from:
- AIZPT314’s bonding-curve design, where:
  - Price is a deterministic function of on-chain BNB reserves and token inventory.
  - Sells always pay out BNB from the contract’s reserves to the seller, according to the formula in `sell()`.
- The absence of safeguards in AIZPT314 or the surrounding ecosystem against:
  - Large one-shot sells or buy/sell loops that significantly change reserves.
  - Use of flash-swap liquidity to amplify such loops.
- The presence of a WBNB/AIZPT314 AMM pair, which:
  - Exposes AIZPT314 to external, composable liquidity.
  - Allows a router to **borrow WBNB**, use it to manipulate or exploit the bonding curve, and repay the borrow in a single transaction.

Because these mechanics are entirely permissionless and require no privileged role, any MEV searcher can run similar strategies whenever the on-chain state and prices allow profitable trades. The incident is therefore best understood as a **deliberate extraction of protocol reserves via MEV arbitrage**, rather than an unintended code exploit.

---

## Impact & Losses

### Quantitative impact

From `root_cause.json` and `balance_diff.json`:
- **Token / Asset:** BNB (native asset of BSC).
- **Total BNB reserves lost by AIZPT314:**  
  ≈ **39.034317811221904278 BNB**, corresponding to the negative balance delta on `0xbe779d420b7d573c08eee226b9958737b6218888`.
- **Adversary gross WBNB received:**  
  34.934317811221904278 WBNB (1:1 BNB equivalent), transferred from router `0x8408...8320` to EOA `0x3026...ce32`.
- **Gas fees paid by adversary:**  
  `gasUsed = 3,770,113`, `effectiveGasPrice = 3 gwei` → 0.011310339 BNB.
- **Adversary net profit:**  
  ≈ **34.923007472221904278 BNB** (34.934317811221904278 − 0.011310339).
- **Remaining BNB value:**  
  The remainder of the drained BNB stays backing WBNB in the Pancake V3 pool as part of the updated reserves.

### Qualitative impact

- **Protocol-level effect:**  
  AIZPT314’s on-contract BNB reserves, which economically back the token and determine its bonding-curve price, are significantly reduced in a single transaction.

- **User impact:**  
  Holders of AIZPT314 who expected reserves to remain in the contract to support price and redemption value are harmed. The bonding curve after the trade reflects lower reserves, which can lower effective prices for future sells and reduce perceived backing.

- **Security posture:**  
  - No direct invariant violation or unauthorized state change was observed beyond what the contract logic allows.
  - The protocol’s design does not distinguish between “legitimate” sells and MEV-scale, flash-swap assisted trades.
  - The exploit showcases **economic risk** from combining bonding-curve tokens with composable AMM liquidity and flash-swap mechanisms.

---

## References

- **[1] Seed transaction metadata and balance diffs**  
  - Origin: Seed artifacts for `tx 0x5e69...460d` (metadata and `balance_diff.json`).
  - Content: Transaction context, native balance deltas showing AIZPT314’s BNB loss and WBNB’s gain.

- **[2] Transaction trace (callTracer) for `0x5e69...460d`**  
  - Origin: `debug_traceTransaction` callTracer output collected during analysis.  
  - Content: Call tree showing:
    - Pancake V3 pool calling WBNB to transfer tokens to the router.
    - Router calling WBNB `withdraw` to unwrap BNB.
    - Router sending BNB into AIZPT314 and repeatedly calling AIZPT314 `transfer` to its own address (triggering `sell()`), with nested BNB transfers back to the router.

- **[3] Transaction receipt and logs for `0x5e69...460d`**  
  - Origin: On-chain receipt collected in the root-cause artifacts.  
  - Content: Event logs for WBNB transfers, WBNB deposits, and the final WBNB transfer to the adversary, plus execution metadata (`gasUsed`, `effectiveGasPrice`).

- **[4] AIZPT314 token source (`Contract.sol`)**  
  - Origin: Verified/collected contract source for `0xbe779d420b7d573c08eee226b9958737b6218888`.  
  - Content: ERC314-style implementation including:
    - `getReserves`, `getAmountOut`, `buy`, and `sell` functions.
    - Logic that interprets transfers to `address(this)` as sells and pays BNB from reserves.

- **[5] Pancake V3 pool source (`PancakeV3Pool.sol`)**  
  - Origin: Collected source for `0x36696169c63e42cd08ce11f5deebbcebae652050`.  
  - Content: Standard Pancake V3 implementation with swap/flash callbacks and reentrancy guard, enabling flash-swap style interactions.

- **[6] EOA transaction history for `0x3026c464d3bd6ef0ced0d49e80f171b58176ce32`**  
  - Origin: Collected transactions-by-address JSON.  
  - Content: Broader activity of the adversary EOA, supporting characterization as an MEV/searcher account (not strictly needed for the core root-cause but available for context).

All referenced artifacts are present under the provided root-cause analysis directory; no required evidence was found missing during this report.

