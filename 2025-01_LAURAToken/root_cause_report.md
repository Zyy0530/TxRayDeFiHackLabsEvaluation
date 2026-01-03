## PumpToken removeLiquidityWhenKIncreases Uniswap LP Drain

### Incident Overview & TL;DR

An unprivileged Ethereum EOA (`0x25869347f7993c50410a9b9b9c48f37d79e12a36`) deployed a helper contract and, in a single flashLoan-backed transaction, exploited PumpToken’s public `removeLiquidityWhenKIncreases()` function to drain value from the PumpToken/WETH UniswapV2 liquidity pool, ending with a net ETH profit. The attack borrowed 30,000 WETH from the Balancer Vault, manipulated the PumpToken/WETH reserves via UniswapV2, invoked the vulnerable function to shrink the pair’s PumpToken balance, removed liquidity, swapped PumpToken back to WETH, repaid the flashLoan, and finally converted the residual WETH to ETH for adversary-controlled accounts.

The root cause is a protocol-level bug in PumpToken. The function `removeLiquidityWhenKIncreases()` is an unauthenticated, publicly callable entrypoint that burns PumpToken from the PumpToken/WETH pair based solely on a reserve-derived product `K`, without compensating LPs or adjusting LP shares. An attacker who temporarily increases `K` (for example via flashLoan-powered liquidity provision and trades) can invoke this function to reduce the pair’s PumpToken balance and subsequently extract WETH from the LP when removing liquidity and swapping, leaving LPs with reduced WETH backing.

### Key Background

- PumpToken (`0x05641e33fd15baf819729df55500b07b82eb8e89`) is a custom ERC20 with a bonding-curve mechanism and a special function `removeLiquidityWhenKIncreases()` that reads a UniswapV2 pair’s reserves and adjusts the pair’s PumpToken balance when the product `K` increases beyond a threshold.
- The PumpToken/WETH UniswapV2 pair at `0xb292678438245Ec863F9FEa64AFfcEA887144240` holds PumpToken and WETH9 (`0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`) liquidity. UniswapV2Router02 at `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D` is used for adding/removing liquidity and swapping.
- The Balancer Vault (`0xBA12222222228d8Ba445958a75a0704d566BF2C8`) provides a flashLoan interface that allows arbitrary callers to borrow and repay assets such as WETH within a single transaction, enabling large temporary reserve changes without upfront capital.
- In a constant-product AMM such as UniswapV2, reserve manipulation via flashLoans and temporary liquidity can change `K` and prices. Protocol code that reacts to `K` without robust invariants or access control is exploitable, especially when it directly modifies pool token balances.

From an ACT perspective:

- **Block height \(B\)**: The exploit transaction is included in Ethereum mainnet block **21529888**.
- **Pre-state \(\u03c3\_B\)**: The analysis uses the Ethereum mainnet pre-state immediately before inclusion of tx `0xef34f4fdf03e403e3c94e96539354fb4fe0b79a5ec927eacc63bc04108dbf420` in block 21529888, including the PumpToken/WETH pair, PumpToken, WETH9, Balancer Vault, and adversary accounts. This state is reconstructed from:
  - Seed transaction metadata (etherscan RPC snapshot).
  - Storage-level prestate diff for the exploit tx.
  - Native and ERC20 balance diffs around the exploit tx.

```json
{
  "chainid": 1,
  "txhash": "0xef34f4fdf03e403e3c94e96539354fb4fe0b79a5ec927eacc63bc04108dbf420",
  "native_balance_deltas": [
    {
      "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "before_wei": "2964982195304915405537834",
      "after_wei": "2964969854947838121232628",
      "delta_wei": "-12340357077284305206"
    },
    {
      "address": "0x25869347f7993c50410a9b9b9c48f37d79e12a36",
      "before_wei": "2876766120831698440",
      "after_wei": "15186961778116003646",
      "delta_wei": "12310195657284305206"
    },
    {
      "address": "0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97",
      "before_wei": "6342501223369044852",
      "after_wei": "6362348586610710214",
      "delta_wei": "19847363241665362"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0x05641e33fd15baf819729df55500b07b82eb8e89",
      "holder": "0xb292678438245ec863f9fea64affcea887144240",
      "before": "6099572126618875527765833",
      "after": "6086464626951459453849811",
      "delta": "-13107499667416073916022",
      "contract_name": "PumpToken"
    }
  ]
}
```

*Caption: Native and ERC20 balance diffs for the exploit transaction, showing WETH9 losing 12.340357077284305206 ETH-equivalent while the adversary EOA and 0x4838…5f97 gain 12.310195657284305206 ETH and 0.019847363241665362 ETH respectively, and the PumpToken/WETH pair losing 13,107,499,667,416,073,916,022 PumpToken units.*

### Vulnerability & Root Cause Analysis

#### Vulnerability Summary

PumpToken’s `removeLiquidityWhenKIncreases()` function is deployed as a publicly callable, unauthenticated function that reduces `PumpToken._balances[uniswapV2Pair]` whenever the PumpToken/WETH pair’s product of reserves `K = tokenReserve * wethReserve` exceeds 105% of a hard-coded `INITIAL_UNISWAP_K`. This effectively burns PumpToken from the pair without adjusting LP token shares, allowing an attacker who temporarily inflates `K` to withdraw disproportionately more WETH when removing liquidity.

#### Root Cause Detail

The PumpToken contract encodes a target initial AMM configuration via constants such as `TOKENS_IN_LP_AFTER_FILL`, `ETH_TO_FILL`, `INITIAL_UNISWAP_K`, and `REAL_LP_INITIAL_SUPPLY`. It sets up the PumpToken/WETH pair and tracks `K` using ABDK fixed-point math. The vulnerable logic is:

```solidity
function removeLiquidityWhenKIncreases() public {
    (uint256 tokenReserve, uint256 wethReserve) = getReservesSorted();
    uint256 currentK = tokenReserve * wethReserve;

    if (currentK > (105 * INITIAL_UNISWAP_K / 100)) {
        IUniswapV2Pair pair = IUniswapV2Pair(uniswapV2Pair);

        _balances[uniswapV2Pair] -= tokenReserve * (currentK - INITIAL_UNISWAP_K) / currentK;
        pair.sync();
    }
}
```

*Caption: PumpToken’s vulnerable `removeLiquidityWhenKIncreases()` function from the verified source, showing an unauthenticated reduction of the pair’s PumpToken balance based solely on `currentK` relative to `INITIAL_UNISWAP_K`.*

Key properties of this function:

- It is **public**, with no `onlyOwner` or other access control, so any address can call it.
- It uses the live UniswapV2 reserves `tokenReserve` and `wethReserve` to compute `currentK = tokenReserve * wethReserve`.
- When `currentK` exceeds `1.05 * INITIAL_UNISWAP_K`, it decreases `_balances[uniswapV2Pair]` by `tokenReserve * (currentK - INITIAL_UNISWAP_K) / currentK` and then calls `pair.sync()`, which updates on-chain reserves to match the ERC20 balances.
- The function does **not** adjust LP token shares or otherwise compensate LPs for the removed PumpToken, effectively altering the pool’s token composition to the benefit of whoever later removes liquidity.

Because `currentK` can be increased arbitrarily using flashLoan-sourced WETH to add liquidity and trade against the pair, an attacker can:

1. Inflate `K` by adding PumpToken/WETH liquidity and performing trades.
2. Call `removeLiquidityWhenKIncreases()` to burn PumpToken from the pair based on the artificially high `K`.
3. Remove liquidity and swap PumpToken back to WETH, extracting more WETH than their net contribution, with losses borne by existing LPs.

On-chain diffs and traces from the exploit tx show exactly this behavior: PumpToken’s balance for the pair address decreases by **13,107,499,667,416,073,916,022** units, and the pair’s WETH reserves later drop dramatically as liquidity is removed and swapped.

#### Vulnerable Components

- **PumpToken contract** at `0x05641e33fd15baf819729df55500b07b82eb8e89`, function `removeLiquidityWhenKIncreases()`.
- **PumpToken/WETH UniswapV2 pair** at `0xb292678438245Ec863F9FEa64AFfcEA887144240`, whose PumpToken balance is directly modified by `PumpToken::removeLiquidityWhenKIncreases()`.
- **Protocol design assumption** that `INITIAL_UNISWAP_K` and `K`-based adjustments can be safely exposed via a public function without access control or protections against flashLoan-driven reserve manipulation.

#### Exploit Conditions

The exploit is enabled by the following concrete conditions:

- There is significant PumpToken/WETH liquidity in the UniswapV2 pair, so increasing `K` and later withdrawing WETH is economically meaningful.
- `removeLiquidityWhenKIncreases()` is deployed as a public function with no access control or rate limiting, callable by arbitrary addresses.
- An attacker can borrow a large amount of WETH (30,000 WETH) via the Balancer flashLoan, provide PumpToken/WETH liquidity, and trade against the pair to increase `K` beyond 105% of `INITIAL_UNISWAP_K`.
- The protocol does not compensate LPs or adjust LP share accounting when `PumpToken._balances[uniswapV2Pair]` is reduced, allowing subsequent remove-liquidity and swap operations to extract WETH disproportionate to the attacker’s net contribution.

#### Security Principles Violated

- **Lack of access control** on a powerful reserve-manipulating function that directly changes a liquidity pool’s token balances.
- **Failure to account for adversarial reserve manipulation**, particularly flashLoan-driven changes to AMM reserves and `K`, in the design of protocol-level reactions.
- **Breaking LP invariants**: LP token holders lose reserves to third parties without a corresponding transfer of LP shares or explicit, pre-agreed protocol fees.

### Adversary Flow Analysis

#### Adversary Strategy Summary

The adversary executes a single exploit transaction that:

1. Deploys a helper contract.
2. Borrows 30,000 WETH from the Balancer Vault via flashLoan.
3. Uses UniswapV2 to add PumpToken/WETH liquidity and trade, inflating `K`.
4. Calls the public `removeLiquidityWhenKIncreases()` function to burn PumpToken from the pair.
5. Removes liquidity and swaps PumpToken back to WETH.
6. Repays the flashLoan and forwards the residual ETH-denominated profit to adversary-controlled addresses.

This entire flow occurs within tx `0xef34f4fdf03e403e3c94e96539354fb4fe0b79a5ec927eacc63bc04108dbf420` on Ethereum mainnet (block 21529888).

#### Adversary-Related Accounts

- **Adversary EOA (primary)**  
  - Address: `0x25869347f7993c50410a9b9b9c48f37d79e12a36`  
  - Role: Sender of the attacker-crafted seed transaction, originator of the helper contract deployment, and primary recipient of **12.310195657284305206 ETH** net profit in the exploit transaction (as shown in balance diffs).

- **Helper contract**  
  - Address: `0x55877Cf2F24286DBA2aCB64311beca39728Fbd10`  
  - Role: Contract deployed by the adversary EOA within the exploit tx. Executes the Balancer flashLoan, UniswapV2 liquidity provision and trades, the call to `PumpToken::removeLiquidityWhenKIncreases()`, liquidity removal, swaps, and profit forwarding. Its source was not verified on-chain but was decompiled for analysis.

- **Secondary profit recipient**  
  - Address: `0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97`  
  - Role: Immediate beneficiary of **0.019847363241665362 ETH** sent from the helper contract in the exploit tx, representing part of the extracted value from the manipulated PumpToken/WETH LP.

Candidate victims:

- **PumpToken/WETH UniswapV2 LP** at `0xb292678438245Ec863F9FEa64AFfcEA887144240` (LPs collectively lose WETH backing).  
- **PumpToken protocol / PumpToken holders** associated with `0x05641e33fd15baf819729df55500b07b82eb8e89`, whose tokenomics are distorted by the unauthorized burning of PumpToken from the LP.

#### Adversary Lifecycle Stages

1. **Adversary contract deployment and flashLoan**
   - **Transaction**: `0xef34f4fdf03e403e3c94e96539354fb4fe0b79a5ec927eacc63bc04108dbf420` (block 21529888, Ethereum mainnet).
   - **Mechanism**: `flashloan`.
   - **Effect**: The EOA `0x2586…2a36` deploys the helper contract `0x5587…Bd10` and, via the Balancer Vault, obtains a 30,000 WETH flashLoan to the helper. This seeds the helper with temporary WETH liquidity used to manipulate the PumpToken/WETH UniswapV2 pair and drive `K` above the 105% threshold.
   - **Evidence sources**: Seed transaction metadata and a structured call trace (`debug_trace_callTracer.json`) showing the Balancer flashLoan call to the helper.

2. **Reserve manipulation and vulnerable function call**
   - **Transaction**: Same tx `0xef34…f420` (block 21529888).
   - **Mechanism**: `mint` (liquidity provision).
   - **Effect**:
     - The helper uses UniswapV2Router02 to add PumpToken/WETH liquidity and perform trades, pushing the pair’s reserves to approximately  
       - `tokenReserve ≈ 1.744e22` PumpToken  
       - `wethReserve ≈ 2.306e22` WETH  
       as seen in the UniswapV2Pair `Sync` events.
     - The increased reserves raise `currentK` beyond `1.05 * INITIAL_UNISWAP_K`.
     - The helper then calls `PumpToken::removeLiquidityWhenKIncreases()`, which reads the reserves, computes `currentK`, and reduces `PumpToken._balances[uniswapV2Pair]` by **13,107,499,667,416,073,916,022** units, followed by `pair.sync()`, syncing the pair to the lower PumpToken balance.

```text
│   │   │   ├─ [14325] PumpToken::removeLiquidityWhenKIncreases()
│   │   │   │   ├─ [14162] PumpToken::removeLiquidityWhenKIncreases() [delegatecall]
│   │   │   │   │   ├─ [504] UniswapV2Pair::getReserves() [staticcall]
│   │   │   │   │   │   └─ ← [Return] 17442327956960784747337 [1.744e22], 23068964517278041866222 [2.306e22], 1735737755
│   │   │   │   │   ├─ [7803] UniswapV2Pair::sync()
│   │   │   │   │   │   ├─ emit Sync(reserve0: 4334828289544710831315 [4.334e21], reserve1: 23068964517278041866222 [2.306e22])
│   │   │   │   │   │   ├─  storage changes:
│   │   │   │   │   │   │   @ 0x3c3f86b3bfb9...: 0x...0003b18ced1f7110790b49 → 0x...0000eafdd3c26fb2a0bcd3
```

*Caption: Extract from the exploit transaction’s verbose trace (cast run and callTracer), showing the helper contract calling `PumpToken::removeLiquidityWhenKIncreases()`, which in turn reads Uniswap reserves and calls `sync()`, resulting in a large decrease in the pair’s PumpToken balance.*

3. **Liquidity removal, swaps, and profit realization**
   - **Transaction**: Same tx `0xef34…f420` (block 21529888).
   - **Mechanism**: `transfer` (LP burn and swaps).
   - **Effect**:
     - After the PumpToken burn from the pair, the helper calls UniswapV2Router02 to remove PumpToken/WETH liquidity, receiving significant PumpToken and WETH.
     - It then executes a large PumpToken→WETH swap, leaving the pair with drastically reduced WETH reserves while the helper holds the extracted value.
     - The helper repays the 30,000 WETH flashLoan to the Balancer Vault.
     - The remaining **12.340357077284305206 WETH** is converted to ETH and distributed, with **12.310195657284305206 ETH** accruing to the adversary EOA and **0.019847363241665362 ETH** to `0x4838…5f97`, as evidenced by `native_balance_deltas`.

These lifecycle stages are fully contained within a single adversary-crafted transaction that is feasible for any unprivileged EOA: the helper deployment is a standard type-2 contract creation, all called contracts expose the necessary public entrypoints, and no special permissions are required beyond sufficient gas and tip.

### Impact & Losses

#### Quantitative Losses

- **WETH**  
  - Approximate adversary profit: **≈12.33 ETH-equivalent** extracted from the system.  
  - Breakdown from balance diffs:
    - **12.310195657284305206 ETH** net gain for adversary EOA `0x2586…2a36`.
    - **0.019847363241665362 ETH** gain for `0x4838…5f97`.  
  - WETH9’s balance decreases by **12.340357077284305206 ETH** across the transaction, matching the sum of the gains plus gas costs.

- **PumpToken**  
  - **13,107,499,667,416,073,916,022** PumpToken units are removed from the PumpToken/WETH pair by `removeLiquidityWhenKIncreases()` during the exploit tx, redistributing value away from LPs.

The adversary’s net ETH-denominated profit is strictly positive even after fees. Using the tx’s gas limit (`0x18bedf`) and gas price (`0x4a817c800`), the maximum possible gas fee is approximately **0.03243454 ETH**, comfortably below the 12.310195657284305206 ETH gain shown for the attacker EOA.

#### Qualitative Impacts

- LPs in the PumpToken/WETH UniswapV2 pool suffer a **loss of WETH reserves**, as value is shifted from the pool to adversary-related accounts via the combination of:
  - `PumpToken::removeLiquidityWhenKIncreases()` burning PumpToken from the pair.
  - Subsequent liquidity removal.
  - PumpToken→WETH swaps.
- The PumpToken/WETH **price and `K` are distorted** during the attack window, and the pool is left in a degraded state with significantly lower WETH backing relative to PumpToken.
- The exploit demonstrates that the protocol’s design of coupling a bonding curve and AMM-based liquidity via a public `K`-reactive function is unsafe without rigorous consideration of flashLoan-driven adversarial actions.

### ACT Opportunity Summary

This incident presents a clear ACT (Automated Counter-Transaction) opportunity:

- **Opportunity time**: Before inclusion of tx `0xef34…f420` in block 21529888, given pre-state \(\u03c3\_B\) that already includes all relevant contracts and balances.
- **Exploit predicate**: A profit predicate on ETH is satisfied when:
  - The adversary cluster’s ETH-equivalent portfolio value after executing the tx exceeds its value before, net of gas fees.
  - This is established directly from:
    - Seed `metadata.json` (providing pre- and post-tx balances and gas parameters).
    - `balance_diff.json` (native and ERC20 diffs).
    - `debug_trace_prestate_diff.json` (storage-level changes for PumpToken, the PumpToken/WETH pair, WETH9, and related contracts).
- **Non-monetary predicate**: Not required here (`oracle_name = "N/A"`), as the exploit predicate is purely financial.

The analysis shows that the adversary’s ETH-denominated value increases from **2.87676612083169844 ETH** to **15.186961778116003646 ETH**, a delta of **12.310195657284305206 ETH**, and that even under a conservative gas cost bound (≈0.03243454 ETH), the net profit remains positive.

### References

- **[1] Seed tx metadata** for `0xef34f4fdf03e403e3c94e96539354fb4fe0b79a5ec927eacc63bc04108dbf420`  
  - Origin: Seed transaction metadata collected via Ethereum JSON-RPC and Etherscan.

- **[2] PumpToken source (removeLiquidityWhenKIncreases)**  
  - Origin: Verified PumpToken contract source and ABI fetched via `forge` clone for `0x05641e33fd15baf819729df55500b07b82eb8e89`.

- **[3] Exploit tx call trace (callTracer)**  
  - Origin: `debug_traceTransaction` with `callTracer`, providing a structured call tree including Balancer flashLoan, UniswapV2Router02 interactions, `removeLiquidityWhenKIncreases()`, and liquidity removal/swaps.

- **[4] Exploit tx storage-level prestate diff**  
  - Origin: `debug_traceTransaction` with `prestateTracer` in `diffMode`, capturing storage changes for PumpToken, the PumpToken/WETH pair, WETH9, and related contracts across the exploit tx.

- **[5] Exploit tx balance diff (native and ERC20)**  
  - Origin: Balance diff computation based on prestateTracer output and verified token storage layouts, summarizing native and ERC20 balance changes for all relevant addresses.

