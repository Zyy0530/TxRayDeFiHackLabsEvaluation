# MEV arbitrage on SASHA via Uniswap V2/V3

- **Protocol:** Sasha Cat (SASHA) / Uniswap V2 & V3  
- **Category:** MEV economic arbitrage (no contract bug)  
- **Chain / Block:** Ethereum mainnet, block `20905302`  
- **Primary ACT transaction:** `0xd9fdc7d03eec28fc2453c5fa68eff82d4c297f436a6a5470c54ca3aecd2db17e`  
- **Primary adversary EOA:** `0x493c5655d40b051a64bc88a6af21d73d3a9b72a2`  
- **Aggregator contract:** `0x991493900674B10BDf54BdFe95B4E043257798Cf`  

All conclusions below are derived solely from the provided root-cause artifacts and on-disk traces; no external chain data was queried.

---

## Incident Overview & TL;DR

An MEV-style searcher EOA (`0x493c…72a2`) used an unverified but decompiled aggregator contract (`0x9914…98Cf`) to execute a single Ethereum mainnet transaction in block `20905302`. The aggregator routes `0.07` ETH (wrapped to WETH) through a Uniswap V2 SASHA/WETH pair (`0xB23F…38fe`) and a Uniswap V3 SASHA/WETH pool (`0x5EAc…8264`), resulting in a large net ETH gain for the adversary cluster.

The core mechanism is a **purely economic price discrepancy** between:

- **Uniswap V2 SASHA/WETH pair:** `0xB23FC1241e1Bc1a5542a438775809d38099838fe`
- **Uniswap V3 SASHA/WETH pool:** `0x5EAc5992e8c7cC6B04bad2C5bBC00D101d4C8264`

At the time of the ACT transaction, SASHA is sufficiently cheaper on the V2 pair than on the V3 pool. By buying SASHA on V2 and selling on V3 in a single bundled route, the adversary extracts **~249 ETH of profit** from the combined SASHA/WETH liquidity, without relying on any contract-level vulnerability or privileged role.

The **pre-state** `σ_B` is the Ethereum mainnet state immediately before including the ACT transaction in block `20905302`, including balances and pool reserves for:

- SASHA token: `0xD1456D1b9CEb59abD4423a49D40942a9485CeEF6`
- Uniswap V2 SASHA/WETH pair: `0xB23F…38fe`
- Uniswap V3 SASHA/WETH pool: `0x5EAc…8264`

Under this state, the adversary can profitably submit the ACT transaction as a public, permissionless legacy type-0 transaction; inclusion does not require any non-standard assumptions beyond typical MEV competition.

**Net effect:**  
Using ETH as the reference asset and treating the adversary cluster as the EOA plus its aggregator, balance diffs show the cluster’s ETH holdings increase from `19.801163498787925` ETH to `268.7536281219615` ETH, a **net gain of ~`248.95` ETH after gas and input capital**, while the aggregator’s SASHA balance also increases.

**Seed transaction trace evidence** (cast run `-vvvvv` for tx `0xd9fd…db17e`):

```text
│   ├─ [87872] UniswapV2Pair::swap(0, 142298849366578503610012 [1.422e23], 0x991493900674B10BDf54BdFe95B4E043257798Cf, 0x)
│   ├─ [178271] UniswapV3Pool::swap(0x991493900674B10BDf54BdFe95B4E043257798Cf, false, 99000000000000000000000 [9.9e22], 1461446703485210103287273052203988822378723970341 [1.461e48], 0x...)
│   │   │   ├─ emit Transfer(from: UniswapV3Pool: [0x5EAc5992e8c7cC6B04bad2C5bBC00D101d4C8264], to: 0x991493900674B10BDf54BdFe95B4E043257798Cf, value: 249276511929373786924 [2.492e20])
│   │   │   ├─ [105673] 0xD1456D1b9CEb59abD4423a49D40942a9485CeEF6::transferFrom(0x991493900674B10BDf54BdFe95B4E043257798Cf, UniswapV3Pool: [0x5EAc5992e8c7cC6B04bad2C5bBC00D101d4C8264], 99000000000000000000000 [9.9e22])
```

_Caption: Seed transaction trace showing SASHA inflow from the Uniswap V2 pair into the aggregator, followed by a large SASHA transfer into the Uniswap V3 pool and a WETH transfer of ~`249.28` WETH back to the aggregator._

---

## Key Background

### SASHA token

- **Token:** SASHA (`0xD1456D1b9CEb59abD4423a49D40942a9485CeEF6`)  
- **Standard:** ERC-20, with owner-configurable buy/sell fees and simple anti-bot / trading-gate logic.  
- **Deployment pattern:** Initial supply minted to a dev wallet; integrates with Uniswap V2 via the canonical router `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D`.

Collected SASHA source code shows a conventional fee-on-transfer token that accumulates fees in the contract and optionally swaps them back into ETH via Uniswap V2. There is no indication of reentrancy, non-standard mints/burns, or exotic access control.

**Collected contract source snippet (SASHA ERC-20, verified source for `0xD145…eEF6`):**

```solidity
bool takeFee = !swapping && !_isExcludedFromFees[from] && !_isExcludedFromFees[to];

uint256 fees = 0;
if (takeFee) {
    if (auto1[to]) {
        fees = amount.mul(sellFee).div(100);
    }
     if (auto2[to]) {
        fees = amount.mul(sellFee).div(100);
    }
    else if(auto1[from]) {
        fees = amount.mul(buyFee).div(100);
    }
    else if(auto2[from]) {
        fees = amount.mul(buyFee).div(100);
    }
    if (fees > 0) {
        super._transfer(from, address(this), fees);
    }
    amount -= fees;
}
super._transfer(from, to, amount);
```

_Caption: SASHA token transfer logic with configurable buy/sell fees and no non-standard minting or privileged siphons._

### Uniswap V2 & V3 SASHA/WETH venues

- **Uniswap V2 SASHA/WETH pair:** `0xB23FC1241e1Bc1a5542a438775809d38099838fe`  
  - Standard Uniswap V2 pair implementation with constant-product invariant and 0.3% fee.
  - Serves as the **underpriced SASHA leg**, where the aggregator buys SASHA cheaply using WETH.

- **Uniswap V3 SASHA/WETH pool:** `0x5EAc5992e8c7cC6B04bad2C5bBC00D101d4C8264`  
  - Standard Uniswap V3 pool implementation with concentrated liquidity and price tick structure.
  - Serves as the **overpriced SASHA leg**, where the aggregator sells accumulated SASHA back into WETH.

**Collected contract source snippet (Uniswap V2 pair, verified SASHA/WETH pair `0xB23F…38fe`):**

```solidity
function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external lock {
    require(amount0Out > 0 || amount1Out > 0, 'UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT');
    (uint112 _reserve0, uint112 _reserve1,) = getReserves(); // gas savings
    require(amount0Out < _reserve0 && amount1Out < _reserve1, 'UniswapV2: INSUFFICIENT_LIQUIDITY');
    // ...
    uint balance0Adjusted = balance0.mul(1000).sub(amount0In.mul(3));
    uint balance1Adjusted = balance1.mul(1000).sub(amount1In.mul(3));
    require(balance0Adjusted.mul(balance1Adjusted) >= uint(_reserve0).mul(_reserve1).mul(1000**2), 'UniswapV2: K');
    // ...
}
```

_Caption: Uniswap V2 swap logic enforcing the constant-product invariant and standard 0.3% fee for the SASHA/WETH pair._

### Aggregator / searcher contract

The adversary routes all activity through an **unverified aggregator contract** at `0x991493900674B10BDf54BdFe95B4E043257798Cf`. This contract is decompiled (via `heimdall-rs`) and shows:

- A highly specialized fallback that interprets packed calldata and then:
  - Delegates into strategy logic.
  - Queries token balances via `balanceOf`.
  - Transfers tokens via `transfer`/`transferFrom`.
  - Wraps/unwraps WETH using canonical WETH at `0xC02a…6Cc2`.
  - Pays block.coinbase and other addresses a fraction of profits.

**Aggregator decompiled snippet (collected decompilation of `0x9914…98Cf`):**

```solidity
var_a = 0x70a0823100000000000000000000000000000000000000000000000000000000;
var_d = address(this);
(bool success, bytes memory ret0) = address(0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2).Unresolved_70a08231(var_d); // staticcall
// ...
var_a = 0x2e1a7d4d00000000000000000000000000000000000000000000000000000000;
var_d = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff + (var_e);
(bool success, bytes memory ret0) = address(0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2).Unresolved_2e1a7d4d(var_d); // call
// ...
(bool success, bytes memory ret0) = address(block.coinbase).transfer(address(this).balance * (var_b >> 0xf0) / 0x2710);
```

_Caption: Aggregator logic interacting directly with WETH and paying a share of profits to the block proposer via `block.coinbase`._

---

## Vulnerability & Root Cause Analysis

### Nature of the vulnerability

The **vulnerability is purely economic**:

- At block `20905302`, there was a **large, exploitable price gap** between:
  - The SASHA/WETH rate offered by the Uniswap V2 pair `0xB23F…38fe`, and
  - The SASHA/WETH rate offered by the Uniswap V3 pool `0x5EAc…8264`.
- This gap allowed a **single-transaction triangular route**:
  1. WETH → SASHA on Uniswap V2 (cheap SASHA).  
  2. SASHA → WETH on Uniswap V3 (expensive SASHA).  
  3. Unwrap WETH to ETH and distribute profits.

No contract-level invariant is violated; instead, **liquidity fragmentation and thinly-arbitraged meme-token markets** created a temporary price discrepancy big enough to fund a large MEV extraction.

### No contract-level bug in SASHA

Inspection of the SASHA token source (verified `Contract.sol` for `0xD145…eEF6`) shows:

- Standard ERC-20 interface and implementation.
- Owner-controlled fee parameters (buy/sell) and anti-bot/trading-open flags.
- Fee accrual to the contract with swap-back into ETH via Uniswap V2.
- No non-standard mint/burn hooks, no reentrancy gadgets, and no privileged backdoors that could directly explain an ETH windfall.

The observed ETH profit therefore **does not arise from a broken token contract**, but from trading against its liquidity across venues at misaligned prices.

### Vulnerable components (from an economic perspective)

- **SASHA ERC-20 token (`0xD145…eEF6`):**  
  - No code-level bug, but the asset whose fragmented liquidity enables arbitrage.

- **Uniswap V2 SASHA/WETH pair (`0xB23F…38fe`):**  
  - Provides the underpriced leg where the adversary buys SASHA cheaply with WETH.

- **Uniswap V3 SASHA/WETH pool (`0x5EAc…8264`):**  
  - Provides the overpriced leg where the adversary sells SASHA back into WETH.

- **Aggregator/searcher contract (`0x9914…98Cf`):**  
  - Encodes the path and parameters to maximize P/L, including profit sharing with infrastructure providers.

### Exploit conditions (high level)

For this MEV opportunity to exist in block `20905302`, the following conditions had to hold:

- **Price gap condition:**  
  The SASHA/WETH price on the V2 pair must be sufficiently below the price on the V3 pool so that:
  - Buying SASHA on V2,  
  - Selling the same SASHA (plus existing inventory) on V3,  
  - After all swap fees and gas costs, yields **positive ETH P/L**.

- **Liquidity condition:**  
  Both pools must have enough SASHA/WETH liquidity that:
  - Swapping `0.07` WETH into SASHA on V2, and  
  - Swapping `99,000+` SASHA back into WETH on V3  
  does not collapse the effective price to the point of erasing profitability.

- **Execution condition:**  
  The adversary must be able to:
  - Construct the sequence via the aggregator contract, and  
  - Get the transaction included (likely via a builder/relayer) **without being over-bid** by competing searchers.

### Security principles implicated

While no protocol rules or invariants are violated, this event illustrates:

- **Economic safety for thinly traded tokens:**  
  Meme tokens like SASHA, when listed across multiple venues with uneven monitoring, can exhibit large, exploitable price gaps that transfer value from LPs and passive traders to sophisticated MEV actors.

- **Price-consistency assumptions across venues:**  
  Users and token communities may assume that Uniswap V2 and V3 pools for the same pair trade at nearly identical prices. In practice, without continuous arbitrage, prices can diverge substantially, enabling opportunities like this ACT transaction.

---

## adversary Flow Analysis

### Adversary cluster

Root-cause analysis identifies the following key addresses:

- **Adversary EOA (searcher):** `0x493c5655d40b051a64bc88a6af21d73d3a9b72a2`  
  - Sender of both the ACT transaction (`0xd9fd…db17e`) and a prior interaction (`0x3b43…95cb`) with the same aggregator.
  - Receives the bulk of the ETH profit (~`+248.95` ETH delta).

- **Aggregator/searcher contract:** `0x991493900674B10BDf54BdFe95B4E043257798Cf`  
  - Destination of the EOA’s calls and the contract orchestrating the Uniswap V2/V3 interactions.

- **Infrastructure / profit-sharing addresses:**
  - Builder/proposer-related addresses: `0x95222290dd7278aa3ddd389cc1e1d165cc4bafe5`, `0x81164c9edab507aa4bac08dceccefaba1340d3b7`.
  - These receive smaller ETH slices, consistent with standard MEV profit-sharing.

### Lifecycle stages

1. **Prior interaction with aggregator (setup / reuse)**
   - **Tx:** `0x3b4323b20c6ce4713bd7306a37d3396475aa4394f397e9984e603bbad1a695cb` at block `20901413`.  
   - **Flow:** EOA `0x493c…72a2` calls aggregator `0x9914…98Cf` with `methodId = 0x00000000` and `value = 0`.  
   - **Interpretation:** Demonstrates prior use of the same aggregator and function selector by the same EOA, supporting cluster attribution.

   **Evidence (aggregator tx list around blocks 20901413–20905302):**

   ```json
   [
     {
       "blockNumber": "20901413",
       "hash": "0x3b4323b20c6ce4713bd7306a37d3396475aa4394f397e9984e603bbad1a695cb",
       "from": "0x493c5655d40b051a64bc88a6af21d73d3a9b72a2",
       "to": "0x991493900674b10bdf54bdfe95b4e043257798cf",
       "value": "0",
       "methodId": "0x00000000",
       "functionName": "buyAndFree22457070633(uint256 amount)"
     },
     {
       "blockNumber": "20905302",
       "hash": "0xd9fdc7d03eec28fc2453c5fa68eff82d4c297f436a6a5470c54ca3aecd2db17e",
       "from": "0x493c5655d40b051a64bc88a6af21d73d3a9b72a2",
       "to": "0x991493900674b10bdf54bdfe95b4e043257798cf",
       "value": "70000000000000000",
       "methodId": "0x00000000",
       "functionName": "buyAndFree22457070633(uint256 amount)"
     }
   ]
   ```

   _Caption: Aggregator transaction history showing repeated calls from the same EOA into the same method, linking the ACT transaction to the adversary cluster._

2. **Adversary profit-taking arbitrage execution (ACT transaction)**
   - **Tx:** `0xd9fdc7d03eec28fc2453c5fa68eff82d4c297f436a6a5470c54ca3aecd2db17e`, block `20905302`, chainid `1`.  
   - **Mechanism:** A **single, complex swap route** encoded into a `methodId = 0x00000000` call to the aggregator with `0.07` ETH `msg.value`.

   **High-level flow (from trace and balance diffs):**

   1. The EOA sends `0.07` ETH to the aggregator.  
   2. The aggregator wraps ETH into WETH (`0xC02a…6Cc2`).  
   3. The aggregator uses Uniswap V2 SASHA/WETH pair `0xB23F…38fe` to swap WETH → SASHA, netting **~`142,298,849,366,578,503,610,012` SASHA** into the aggregator.  
   4. The aggregator combines these SASHA with pre-existing SASHA inventory and calls Uniswap V3 pool `0x5EAc…8264` to swap **`99,000,000,000,000,000,000,000` SASHA** back into WETH.  
   5. The pool sends **~`249.276511929373786924` WETH** to the aggregator.  
   6. The aggregator unwraps WETH to ETH and distributes:
      - The majority of the ETH to the EOA (`0x493c…72a2`).  
      - Smaller ETH slices to infrastructure addresses, including the block proposer via `block.coinbase`.

   The **trace and ERC-20 diffs** corroborate this:

   - `erc20_transfers` show WETH/SASHA movements between:
     - Aggregator ↔ Uniswap V2 pair (`0xB23F…38fe`)  
     - Aggregator ↔ Uniswap V3 pool (`0x5EAc…8264`)  
   - `native_balance_deltas` show ETH inflow to the EOA and smaller gains for infrastructure addresses.

   **Evidence (selected balance diff entries for the ACT transaction):**

   ```json
   {
     "native_balance_deltas": [
       {
         "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
         "before_wei": "2967743444956760553121348",
         "after_wei": "2967494238444341660031009",
         "delta_wei": "-249206512418893090339"
       },
       {
         "address": "0x95222290dd7278aa3ddd389cc1e1d165cc4bafe5",
         "before_wei": "7896073987140259959",
         "after_wei": "8148466912175068759",
         "delta_wei": "252392925034808800"
       },
       {
         "address": "0x81164c9edab507aa4bac08dceccefaba1340d3b7",
         "before_wei": "451688589501924757",
         "after_wei": "451689079021228172",
         "delta_wei": "489519303415"
       },
       {
         "address": "0x493c5655d40b051a64bc88a6af21d73d3a9b72a2",
         "before_wei": "19801163498787927008",
         "after_wei": "268753628121961515025",
         "delta_wei": "248952464623173588017"
       }
     ],
     "erc20_transfers": [
       {
         "token": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
         "from": "0x991493900674b10bdf54bdfe95b4e043257798cf",
         "to": "0xb23fc1241e1bc1a5542a438775809d38099838fe",
         "value": "70000000000000000"
       },
       {
         "token": "0xd1456d1b9ceb59abd4423a49d40942a9485ceef6",
         "from": "0xb23fc1241e1bc1a5542a438775809d38099838fe",
         "to": "0x991493900674b10bdf54bdfe95b4e043257798cf",
         "value": "142298849366578503610012"
       },
       {
         "token": "0xd1456d1b9ceb59abd4423a49d40942a9485ceef6",
         "from": "0x991493900674b10bdf54bdfe95b4e043257798cf",
         "to": "0x5eac5992e8c7cc6b04bad2c5bbc00d101d4c8264",
         "value": "99000000000000000000000"
       },
       {
         "token": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
         "from": "0x5eac5992e8c7cc6b04bad2c5bbc00d101d4c8264",
         "to": "0x991493900674b10bdf54bdfe95b4e043257798cf",
         "value": "249276511929373786924"
       }
     ]
   }
   ```

   _Caption: Balance diffs and ERC-20 transfers for the ACT transaction, showing WETH outflow from the pools and large ETH inflow to the adversary EOA plus smaller slices to infrastructure addresses._

---

## Impact & Losses

### Quantitative impact

- **Reference asset:** ETH  
- **Adversary cluster:** at minimum, EOA `0x493c…72a2` and aggregator `0x9914…98Cf`.  
- **Value before (cluster, ETH):** `19.801163498787925` ETH  
- **Value after (cluster, ETH):** `268.7536281219615` ETH  
- **Net ETH profit (including gas and input capital):** approximately **`+248.95` ETH**

The **total loss to SASHA/WETH liquidity** (V2 + V3 pools combined) is thus on the order of **`~249` ETH**, acknowledging that precise attribution between LPs and passive counterparties cannot be computed from the provided data alone.

### Distribution of value

Based on `balance_diff.json`:

- The **WETH contract** (`0xC02a…6Cc2`) shows a large negative native delta (`-249.2065…` wei-equivalent), reflecting WETH being unwrapped and sent out of the pools.  
- The **adversary EOA** (`0x493c…72a2`) gains ~`248.95` ETH, capturing nearly all of the profit.  
- An address associated with infrastructure (`0x9522…bFe5`) gains ~`0.252` ETH, likely a share to the builder or relay.  
- Another address (`0x8116…d3b7`) gains a very small amount (`489,519,303,415` wei), matching a dust-level transfer noted in ERC-20/WETH movements.

Because we do not have complete off-chain or cross-block state for the pools’ LP positions, we **do not** attempt to split the loss exactly between:

- LPs on the V2 pair and V3 pool, vs.  
- End-users trading against these pools.

However, the **direction of value transfer is unambiguous**: LPs and counterparties lose value, while the adversary cluster and infrastructure addresses gain value.

---

## References

All of the following references are **local artifacts** supplied as part of the root-cause analysis; paths are described in human terms rather than raw filesystem locations.

- **[1] Seed transaction artifact bundle for tx `0xd9fd…db17e`:**  
  - Includes: Etherscan-style RPC metadata, full `debug_traceTransaction` cast trace, and `balance_diff.json` with native and ERC-20 balance deltas.  
  - Used to confirm the exact call tree, pool interactions, and profit distribution.

- **[2] SASHA token source:**  
  - Verified Solidity source (`Contract.sol`) for `0xD1456D1b9CEb59abD4423a49D40942a9485CeEF6`.  
  - Used to verify that SASHA is a standard fee-on-transfer ERC-20 with no direct exploit vector.

- **[3] Uniswap V2 SASHA/WETH pair source:**  
  - Verified Uniswap V2 pair (`Contract.sol`) for `0xB23FC1241e1Bc1a5542a438775809d38099838fe`.  
  - Used to confirm standard AMM behavior and fee structure for the underpriced venue.

- **[4] Uniswap V3 SASHA/WETH pool source:**  
  - Verified Uniswap V3 pool (`UniswapV3Pool.sol`) for `0x5EAc5992e8c7cC6B04bad2C5bBC00D101d4C8264`.  
  - Used to confirm standard Uniswap V3 mechanics for the overpriced venue in the arbitrage.

- **[5] Aggregator decompiled contract:**  
  - Heimdall decompilation of the unverified aggregator at `0x991493900674B10BDf54BdFe95B4E043257798Cf`.  
  - Used to understand how the adversary encodes paths, manages WETH/SASHA balances, and shares profits with block proposers.

### Evidence availability and limitations

- All artifacts referenced in this report (`root_cause.json`, seed transaction bundle, traces, balance diffs, contract sources, address tx lists, and decompilation) were **present and readable** in the supplied root-cause directory.  
- No external RPC, explorer, or on-chain queries were performed; conclusions are strictly bounded by these artifacts.  
- Due to the lack of full historical pool state beyond the seed transaction, the report does **not** attempt a precise LP-vs-trader loss breakdown, but the direction and approximate magnitude of ETH value transfer are clearly established.

