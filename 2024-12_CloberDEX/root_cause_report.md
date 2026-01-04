## Incident Overview TL;DR

On Base (chainid 8453), an unprivileged EOA `0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025` deployed a custom strategy contract `0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1` and, in the same block (`23514451`), executed a flash-loan-backed transaction `0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04` that drained `133.7` WETH9 from a shared Rebalancer locker. The strategy borrowed `267.4` WETH9 from Morpho (`0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb`), minted and burned positions via Rebalancer `0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895` and BookManager `0x382CCccbD3b142D7DA063bF68cd0c89634767F76`, repaid the flash loan principal, and unwrapped the remaining `133.7` WETH9 to ETH for the EOA.

Pre-/post-state native and ERC-20 balance diffs show:
- The attacker EOA’s native balance increases by `133540501283062363385` wei over the exploit block.
- Rebalancer’s WETH9 ERC-20 balance decreases by exactly `133700000000000000000` wei.
- The WETH9 contract’s native balance decreases by the same `133700000000000000000` wei as it is unwrapped to ETH.

The root cause is a protocol-level accounting bug in the Rebalancer/BookManager design: currency deltas for all pools are aggregated under a single locker address (`address(this)` in Rebalancer) instead of being tracked per pool key. As a result, an attacker-controlled, newly created pool can withdraw historical positive WETH9 currency delta that belongs to other participants, realizing it as immediate profit in a single flash-loan-backed transaction.

This incident satisfies the ACT (anyone-can-take) criteria: the exploit strategy is fully permissionless, relies only on canonical on-chain data and public contract interfaces, and is reproducible by any unprivileged EOA capable of broadcasting transactions with sufficient gas and fees.

## Key Background

- **Protocol components and roles**
  - **Rebalancer** `0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895` acts as a *locker* on top of **BookManager** `0x382CCccbD3b142D7DA063bF68cd0c89634767F76`, holding pooled WETH9 (`0x4200000000000000000000000000000000000006`) and token `0xd3c8d0cd07Ade92df2d88752D36b80498cA12788` on behalf of strategies and LPs across multiple books.
  - BookManager tracks per-book trading and settlement but exposes *currency deltas* against locker addresses rather than per-pool state. In Rebalancer, all pools share the same locker identity (`address(this)`), so deltas from different pool keys accumulate at the Rebalancer address.
  - Morpho at `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb` provides permissionless WETH9 flash loans.
  - WETH9 (`0x4200000000000000000000000000000000000006`) supports standard `deposit`/`withdraw` functions, mapping ERC-20 balances to native ETH.

- **Adversary-controlled strategy contract**
  - The strategy contract `0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1` is deployed by EOA `0x012F...` in transaction `0x4fe2383c6dc0f03e53ea5ad4dd3b87c058c960234e57855fb49a9935a810a290` (same block `23514451` as the exploit).
  - Normal transaction history for `0x32Fb...` shows it is created by and then called only by that EOA around the incident block, linking it tightly to the adversary cluster.

- **Pre-state reconstruction (sigma_B)**
  - The ACT opportunity is defined at pre-block `0x166cd52` (block `23514450`), immediately before the exploit block `0x166cd53` (`23514451`).
  - The pre-state sigma_B (`σ_B`) is reconstructed using:
    - Seed tx metadata for `0x8fcdfc...`  
      `artifacts/root_cause/seed/8453/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04/metadata.json`
    - BookManager sigma_B P/L view at pre-block `0x166cd52`  
      `artifacts/root_cause/data_collector/iter_6/address/8453/0x382CCccbD3b142D7DA063bF68cd0c89634767F76_books_sigma_B_PL_view_pre_0x166cd52.json`
    - WETH9 ERC-20 balance diff across pre/post blocks `0x166cd52` / `0x166cd53`  
      `artifacts/root_cause/data_collector/iter_6/tx/8453/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04/erc20_balance_diff_pre_0x166cd52_post_0x166cd53.json`
  - These artifacts jointly fix Rebalancer’s WETH9 position, the locker balances, and the per-book sigma_B view of historical P/L prior to the exploit.

## Vulnerability Analysis

The core vulnerability is *lack of per-pool accounting isolation* for locker currency deltas in the Rebalancer/BookManager integration:

- Rebalancer defines pools keyed by `bytes32` but uses a single BookManager locker address (`address(this)`) for all of them.
- BookManager exposes currency deltas (`getCurrencyDelta(locker, currency)`) at the locker level, aggregating contributions from all books and hooks.
- In Rebalancer, the same aggregated locker-level delta is used when updating reserves and computing withdrawals for a specific pool, without segregating deltas per pool key or enforcing that withdrawals are limited to that pool’s own deposits and P/L.

This design allows a newly created, attacker-controlled pool to:
- Reference existing WETH9/`0xd3c8...` books that have accumulated historical WETH9 gains at the locker.
- Execute a mint/burn sequence that settles against the **global locker-wide WETH9 currency delta** rather than the pool’s own economic contribution.
- Withdraw WETH9 that economically belongs to historical LPs/traders of other pools and books.

The vulnerable components are:
- **Rebalancer** contract `0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895` on chainid 8453 (locker accounting over BookManager).
- **BookManager** contract `0x382CCccbD3b142D7DA063bF68cd0c89634767F76` on chainid 8453 (currency delta exposure by locker address).
- **Seed exploit transaction** `0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04` on chainid 8453, which exercises the accounting bug via a flash-loan-backed strategy.

Security principles violated:
- **Per-pool accounting isolation**: state and P/L that should be segregated per pool key are aggregated at the locker address, allowing cross-pool value leakage.
- **Conservation of value for LP/trader positions**: historical WETH9 gains attributable to prior counterparties are withdrawable by a newly created, attacker-controlled pool.
- **Invariant enforcement around locker balances**: the protocol does not enforce that withdrawals from a pool correspond only to that pool’s own deposits and trade P/L.

## Detailed Root Cause Analysis

### Rebalancer locker accounting over BookManager

Rebalancer integrates with BookManager via a locker interface. The key settlement path is:

```solidity
// Rebalancer.sol – burn path and currency settlement
function _burn(bytes32 key, address user, uint256 burnAmount)
    public
    selfOnly
    returns (uint256 withdrawalA, uint256 withdrawalB)
{
    Pool storage pool = _pools[key];
    uint256 supply = totalSupply[uint256(key)];

    (uint256 canceledAmountA, uint256 canceledAmountB, uint256 claimedAmountA, uint256 claimedAmountB) =
        _clearPool(key, pool, burnAmount, supply);

    uint256 reserveA = pool.reserveA;
    uint256 reserveB = pool.reserveB;

    withdrawalA = (reserveA + claimedAmountA) * burnAmount / supply + canceledAmountA;
    withdrawalB = (reserveB + claimedAmountB) * burnAmount / supply + canceledAmountB;

    _burn(user, uint256(key), burnAmount);
    pool.strategy.burnHook(msg.sender, key, burnAmount, supply);

    IBookManager.BookKey memory bookKeyA = bookManager.getBookKey(pool.bookIdA);

    pool.reserveA = _settleCurrency(bookKeyA.quote, reserveA) - withdrawalA;
    pool.reserveB = _settleCurrency(bookKeyA.base, reserveB) - withdrawalB;
}

function _settleCurrency(Currency currency, uint256 liquidity) internal returns (uint256) {
    bookManager.settle(currency);

    int256 delta = bookManager.getCurrencyDelta(address(this), currency);
    if (delta > 0) {
        bookManager.withdraw(currency, address(this), uint256(delta));
        liquidity += uint256(delta);
    } else if (delta < 0) {
        currency.transfer(address(bookManager), uint256(-delta));
        bookManager.settle(currency);
        liquidity -= uint256(-delta);
    }
    return liquidity;
}
```

Key observations:
- `_settleCurrency` calls `bookManager.getCurrencyDelta(address(this), currency)` **without specifying a pool key or book ID**. Any positive currency delta accumulated at the locker across *all* books is pulled into `liquidity`.
- `_burn` uses `_settleCurrency` to update `pool.reserveA` and `pool.reserveB` for the specific `key`, then computes withdrawals as a function of those reserves and the pool’s LP supply.
- There is no mechanism to:
  - Track per-pool currency deltas, or
  - Restrict withdrawals so they only consume the pool’s own contributions and P/L.

Thus, if historical trading and LP activity in other WETH9/`0xd3c8...` books have produced a positive WETH9 delta at the locker, *any* pool that shares the locker address can, upon `burn`, withdraw part or all of this accumulated WETH9.

### Evidence from pre-/post-state balances

The pre/post ERC-20 balance diff for WETH9 across blocks `0x166cd52` and `0x166cd53` shows:

```json
// WETH9 ERC-20 balance diff (pre 0x166cd52 -> post 0x166cd53)
{
  "0x4200000000000000000000000000000000000006": {
    "0x012fc6377f1c5ccf6e29967bce52e3629aaa6025": {
      "before": "1092334517332237561",
      "after": "1092334517332237561",
      "delta": "0"
    },
    "0x32fb1bedd95bf78ca2c6943ae5aeaeaafc0d97c1": {
      "before": "0",
      "after": "0",
      "delta": "0"
    },
    "0x382ccccbd3b142d7da063bf68cd0c89634767f76": {
      "before": "2414641672943344102",
      "after": "2414641672943344102",
      "delta": "0"
    },
    "0x6a0b87d6b74f7d5c92722f6a11714dbeda9f3895": {
      "before": "133707875556674808577",
      "after": "7875556674808577",
      "delta": "-133700000000000000000"
    },
    "0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb": {
      "before": "28190570621762065045871",
      "after": "28190570621762065045871",
      "delta": "0"
    }
  }
}
```

Caption: *WETH9 ERC-20 balance diff across pre/post blocks `0x166cd52`/`0x166cd53`, showing a `-133.7` WETH9 change at the Rebalancer locker and no offsetting WETH9 deltas at the attacker EOA, strategy contract, BookManager, or Morpho.*

The native balance diff for the exploit transaction further shows:

```json
// Native balance deltas for tx 0x8fcdfc...
{
  "native_balance_deltas": [
    {
      "address": "0x012fc6377f1c5ccf6e29967bce52e3629aaa6025",
      "before_wei": "1153475443767715212",
      "after_wei": "134693976726830078597",
      "delta_wei": "133540501283062363385"
    },
    {
      "address": "0x4200000000000000000000000000000000000006",
      "before_wei": "229548026276542983668186",
      "after_wei": "229414326276542983668186",
      "delta_wei": "-133700000000000000000"
    }
  ]
}
```

Caption: *Prestate native balance diff for tx `0x8fcdfc...`, showing the attacker EOA’s native balance increasing by ~`133.54` ETH while the WETH9 contract’s native balance decreases by exactly `133.7` ETH.*

Combined, these diffs demonstrate that:
- `133.7` WETH9 leaves the Rebalancer locker as ERC-20.
- That WETH9 is unwrapped to native ETH from the WETH9 contract.
- The attacker EOA realizes a net native balance gain of `133540501283062363385` wei after all gas and protocol fees; the remainder flows to Base system fee addresses.

### Trace evidence of the mint/burn exploit

The seed transaction trace for `0x8fcdfc...` shows the flash loan, Rebalancer/BookManager interactions, and the critical WETH9 transfer from Rebalancer to the strategy:

```text
// Excerpt from trace.cast log for tx 0x8fcdfc...
0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1::setup()
  ...
  0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb::flashLoan(WETH9, 267400000000000000000, ...)
    WETH9::transfer(0x32Fb..., 267400000000000000000)
    0x32Fb...::onMorphoFlashLoan(...)
      Rebalancer::open(... WETH9/0xd3c8 books ..., 0x32Fb...)
      ...
      WETH9::transfer(0x32Fb..., 133700000000000000000)
      ...
```

Caption: *Seed transaction trace for `0x8fcdfc...`, showing the Morpho WETH9 flash loan, Rebalancer `open` call tying a new pool to existing WETH9/`0xd3c8` books, and the `133.7` WETH9 transfer from Rebalancer to the strategy contract.*

This trace confirms:
- The strategy takes a WETH9 flash loan of `267.4` WETH9.
- It uses Rebalancer and BookManager to open a new pool keyed to existing WETH9/`0xd3c8` books.
- After the mint/burn sequence, Rebalancer transfers exactly `133.7` WETH9 to the strategy contract, which is then unwrapped and forwarded as ETH to the attacker EOA.

### ACT exploit conditions

The ACT exploit conditions derived from the above evidence are:
- There exists a positive WETH9 value accumulated under Rebalancer’s locker address for the relevant WETH9/`0xd3c8` books at pre-state sigma_B (captured in the `133.7` WETH9 that can be withdrawn without new capital risk to the attacker).
- An unprivileged adversary can deploy an arbitrary strategy contract and register a new Rebalancer pool key that references existing WETH9/`0xd3c8` books while sharing the same locker address.
- Morpho flash-loan liquidity for `267.4` WETH9 is available, allowing the adversary to supply temporary notional collateral without upfront capital.
- The protocol does not impose per-pool accounting isolation for locker currency deltas, so burns from the attacker-controlled pool settle against aggregated locker-wide WETH9 deltas.

## Adversary Flow Analysis

### Strategy summary

The adversary uses a single-block, two-transaction strategy:
- In transaction `0x4fe2383c6dc0f03e53ea5ad4dd3b87c058c960234e57855fb49a9935a810a290`, EOA `0x012F...` deploys the strategy contract `0x32Fb...`.
- In transaction `0x8fcdfc...`, the same EOA calls `0x32Fb...::setup()`, which:
  - Takes a WETH9 flash loan from Morpho.
  - Interacts with Rebalancer and BookManager to mint and burn positions tied to existing WETH9/`0xd3c8` books.
  - Exploits locker-wide accounting to withdraw `133.7` WETH9.
  - Unwraps WETH9 to ETH and forwards `133.7` ETH to the EOA.

### Adversary-related accounts

- **Adversary cluster**
  - `0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025` (EOA, Base 8453)  
    - Sender of both attacker-crafted transactions `0x4fe2383c6d...` and `0x8fcdfc...`.  
    - Receives `133.7` ETH unwrapped from WETH9 in the seed tx.  
    - Initiates subsequent large transfers of `132` ETH-equivalent ERC-20 and `132` native ETH, as shown in:
      - `artifacts/root_cause/data_collector/iter_6/address/8453/0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025_normal_txs_0x1660000-0x1675000.json`
      - `artifacts/root_cause/data_collector/iter_6/address/8453/0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025_erc20_txs_0x1660000-0x1675000.json`
  - `0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1` (strategy contract, Base 8453)  
    - Deployed by `0x012F...` in tx `0x4fe2383c6d...`.  
    - Immediately used in seed tx `0x8fcdfc...` to orchestrate the Morpho flash loan and Rebalancer/BookManager calls.  
    - Its normal tx history shows it is created and used solely by the attacker EOA around the incident.

- **Victim candidates**
  - **Rebalancer locker** – `0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895` (verified).  
    - Holds pooled WETH9 and `0xd3c8...` from historical LPs and traders.  
    - Its WETH9 balance decreases by exactly `133.7` WETH9 in the exploit block.
  - **BookManager** – `0x382CCccbD3b142D7DA063bF68cd0c89634767F76` (verified).  
    - Maintains per-book state and currency deltas, but exposes those deltas at the locker level, enabling the cross-pool leak.

### Lifecycle stages

1. **Adversary contract deployment**
   - Tx: `0x4fe2383c6dc0f03e53ea5ad4dd3b87c058c960234e57855fb49a9935a810a290` (block `23514451`, Base 8453).  
   - EOA `0x012F...` deploys strategy contract `0x32Fb...` with zero value, preparing a helper contract to interact with Morpho, Rebalancer, BookManager, and WETH9.
   - Evidence:  
     `artifacts/root_cause/data_collector/iter_1/address/8453/0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1_normal_txs.json`.

2. **Flash-loan-backed Rebalancer exploit**
   - Tx: `0x8fcdfc...` (block `23514451`, Base 8453).  
   - The strategy contract `0x32Fb...`:
     - Borrows `267.4` WETH9 via Morpho flash loan.  
     - Uses Rebalancer and BookManager to open a pool key tied to existing WETH9/`0xd3c8` books, mint LP, and then burn it.  
     - During burn, Rebalancer’s `_settleCurrency` pulls the locker-wide WETH9 currency delta into the pool’s reserves and pays it out via `withdrawalA/withdrawalB`, resulting in a `133.7` WETH9 transfer from Rebalancer to `0x32Fb...`.  
     - Repays the flash-loan principal and unwraps the remaining `133.7` WETH9 to ETH, sending `133.7` ETH to EOA `0x012F...`.
   - Evidence:
     - Seed trace: `artifacts/root_cause/seed/8453/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04/trace.cast.log`.
     - Rebalancer and BookManager sources under  
       `artifacts/root_cause/data_collector/iter_1/contract/8453/`.
     - ERC-20 and native balance diffs:
       - `artifacts/root_cause/data_collector/iter_5/tx/8453/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04/balance_diff_prestate.json`
       - `artifacts/root_cause/data_collector/iter_6/tx/8453/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04/erc20_balance_diff_pre_0x166cd52_post_0x166cd53.json`

3. **Post-exploit profit distribution**
   - After the exploit block, EOA `0x012F...` distributes a large portion of the gained ETH:
     - Tx `0x0f4dac09163b8b39d77f851d36ea3df6e7173d78c566d37d8083f0b20693ab40` (block `23514579`, Base 8453): sends `132` ETH to `0x514786c268f7080573687f240da9bd37d574aae3`.
     - Tx `0x158e47edaaceb71da8731cced81c302e356fa2f6855155ff602a73c2e76154f3` (block `23515032`, Base 8453): sends `132` ERC-20 ETH-equivalent tokens (e.g., `ETH..`) to `0x51473f469fd3b9e3d7eff30b57e9f210e23faae3`.
   - These transfers are not required for the ACT success predicate but illustrate subsequent profit movement away from the original EOA while keeping control within the adversary cluster.

## Impact & Losses

- **Total loss overview**
  - `133.7` WETH9 drained from the Rebalancer locker.
  - `133.540501283062363385` ETH (native) realized as net profit to the adversary EOA `0x012F...` after accounting for gas and protocol fees.

- **Economic impact**
  - ERC-20 and native balance diffs show that in the exploit block:
    - The Rebalancer locker’s WETH9 balance decreases by exactly `133.7` WETH9.
    - The attacker EOA’s native balance increases by `133540501283062363385` wei after all fees.
    - The remaining `0.159498716937636615` ETH-equivalent from the `133.7` WETH9 unwound value goes to Base system fee addresses.
  - The economic loss is borne by the aggregated set of LPs and traders whose historical WETH9 P/L had been accumulated in Rebalancer’s locker for the affected WETH9/`0xd3c8` books.  
  - The available on-chain artifacts do not allow decomposition of the `133.7` WETH9 loss across specific LP/trader addresses; only the aggregate loss is observable.

## References

1. **Seed exploit trace for tx `0x8fcdfc...`**  
   `artifacts/root_cause/seed/8453/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04/trace.cast.log`

2. **Rebalancer.sol source code** (`0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895`, chainid 8453)  
   `artifacts/root_cause/data_collector/iter_1/contract/8453/0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895/source/src/src/Rebalancer.sol`

3. **BookManager.sol source code** (`0x382CCccbD3b142D7DA063bF68cd0c89634767F76`, chainid 8453)  
   `artifacts/root_cause/data_collector/iter_1/contract/8453/0x382CCccbD3b142D7DA063bF68cd0c89634767F76/source/src/BookManager.sol`

4. **Prestate native balance diff for exploit tx `0x8fcdfc...`**  
   `artifacts/root_cause/data_collector/iter_5/tx/8453/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04/balance_diff_prestate.json`

5. **WETH9 ERC-20 balance diff across pre/post blocks `0x166cd52` / `0x166cd53`**  
   `artifacts/root_cause/data_collector/iter_6/tx/8453/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04/erc20_balance_diff_pre_0x166cd52_post_0x166cd53.json`

6. **BookManager sigma_B P/L view at pre-block `0x166cd52`**  
   `artifacts/root_cause/data_collector/iter_6/address/8453/0x382CCccbD3b142D7DA063bF68cd0c89634767F76_books_sigma_B_PL_view_pre_0x166cd52.json`

7. **Attacker EOA normal transactions and ERC-20 transfers around exploit block**  
   - `artifacts/root_cause/data_collector/iter_6/address/8453/0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025_normal_txs_0x1660000-0x1675000.json`  
   - `artifacts/root_cause/data_collector/iter_6/address/8453/0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025_erc20_txs_0x1660000-0x1675000.json`

