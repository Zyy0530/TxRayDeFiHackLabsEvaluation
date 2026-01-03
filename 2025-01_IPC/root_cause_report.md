## Incident Overview & TL;DR

On BSC chainid 56, AI IPC Token (`0xEAb0d46682Ac707A06aEFB0aC72a91a3Fd6Fe5d1`) and the IPC–USDT PancakePair (`0xDe3595a72f35d587e96d5C7B6f3E6C02ed2900AB`) were exploited by an adversary-controlled orchestrator contract (`0x3BE77A356848cF7220503E62E93Dfd0ff3f0074A`) and EOA (`0x09ea8b5e546914746f3dc686ac164486a607fb7b`). In a single attacker-crafted transaction `0x5ef1edb9...`, the orchestrator combined flash-liquidity from DODO-style pools with IPC Token’s `_destroy` mint/burn mechanism to reduce the pair’s IPC balance while minting new IPC to a `pool` address and forcing a `sync`, then drained `591934203.953053577941826` USDT from the pair to the attacker EOA.

At root, IPC Token’s `_destroy` function burns IPC from the IPC–USDT liquidity pair and mints twice that amount to a `pool` address while forcing the pair to `sync`. This design allows an adversary to manipulate AMM reserves and extract USDT from the PancakePair using orchestrated swaps and flash-liquidity.

## Key Background

- IPC Token contract `0xEAb0d4...` on BSC defines a custom `_destroy(uint256 burnNum)` routine that targets the USDT–IPC pair and mints new IPC to a `pool` address.
- IPC Token’s `_transfer` logic calls `_destroy(destroyNum)` on specific sell and non-pair transfer paths, enabling repeated depletion of IPC from the pair and minting to `pool` while forcing `sync` updates.
- The IPC–USDT PancakePair `0xDe3595a7...` uses standard PancakePair swap and sync mechanics and does not account for a token contract directly modifying its own balance at the pair.
- The adversary routes interactions through orchestrator contract `0x3BE77A3...`, which calls DODO pools `0x6098...` and `0x0e15...`, PancakeRouter `0x10ED43...`, IPC Token, and BEP20USDT.

### IPC Token `_destroy` and `_transfer` (Token.sol)

Origin: Collected IPC Token source (verified-style source code for `0xEAb0d4...`, `Token.sol`).

```solidity
function _transfer(address sender, address recipient, uint256 amount) internal {
    ...
    address pair = IUniswapV2Factory(SWAP_V2_FACTORY).getPair(address(this), USDT);
    ...
    } else if (recipient == pair && sender != address(this)) {
        if (_isAddLP(pair)) {
            lastSellIsAdd = true;
        } else {
            //sell
            if (block.timestamp < transferTime[sender] + TRANSFER_LOCK) revert TransferTimeLock();
            fee = amount * (MARKET_TAX + PUBLISH_TAX) / 1000;
            _destroy(destroyNum);
            destroyNum += (amount - fee) / 2;
            lastDestroyNum = (amount - fee) / 2;
            _sell(fee);
        }
    }
    ...
    if (sender != pair && recipient != pair) {
        if (block.timestamp < transferTime[sender] + TRANSFER_LOCK) revert TransferTimeLock();
        _destroy(destroyNum);
    }
    ...
}

function _destroy(uint256 burnNum) internal {
    if (burnNum < 1) return;
    address pair = IUniswapV2Factory(SWAP_V2_FACTORY).getPair(USDT, address(this));
    uint256 pairToken = IERC20(address(this)).balanceOf(pair);
    if (pairToken - 10**18 < burnNum) {
        burnNum = pairToken - 10**18;
    }
    balances[pair] -= burnNum;
    balances[address(0)] += burnNum;
    IUniswapV2Pair(pair).sync();
    ...
    uint256 produceNum = burnNum * 2;
    if (totalSupply + produceNum > MAX_TOTAL_SUPPLY) {
        produceNum = MAX_TOTAL_SUPPLY - totalSupply;
    }
    totalSupply += produceNum;
    balances[pool] += produceNum;
    ...
}
```

*Caption: IPC Token’s `_transfer` and `_destroy` functions burn IPC directly from the USDT–IPC pair, force a `sync`, and mint twice the burned amount to the `pool` address, enabling reserve manipulation.*

## Vulnerability & Root Cause Analysis

### High-level Vulnerability

IPC Token’s `_destroy` function burns IPC tokens from the IPC–USDT liquidity pair and mints twice that amount to a `pool` address while forcing the pair to `sync`. This breaks the assumption that AMM reserves change only through swaps and liquidity operations and enables extraction of USDT from the pair by manipulative trading.

### Detailed Root Cause

Token.sol for IPC (`0xEAb0...`) shows that `_destroy(uint256 burnNum)`:

- Obtains the USDT–IPC pair address via `IUniswapV2Factory(SWAP_V2_FACTORY).getPair(USDT, address(this))`.
- Reads the pair’s IPC balance and caps `burnNum` to `pairToken - 1e18`.
- Reduces the pair’s IPC balance by `burnNum`, credits the zero address with `burnNum`, and calls `IUniswapV2Pair(pair).sync()`.
- Computes `produceNum = min(2 * burnNum, MAX_TOTAL_SUPPLY - totalSupply)`.
- Mints `produceNum` new IPC tokens directly to a configurable `pool` address and increases `totalSupply`.

The `_transfer` function:

- Detects whether `sender` or `recipient` is the USDT–IPC pair.
- On sell paths where `recipient == pair`, `_isAddLP(pair)` is false, and the time-lock holds, calls `_destroy(destroyNum)` before updating `destroyNum` and `lastDestroyNum` based on the trade amount and fee.
- On non-pair transfers, calls `_destroy(destroyNum)` under a time-lock condition.

This design allows sequences of trades and transfers to:

- Repeatedly invoke `_destroy`, systematically removing IPC from the pair.
- Mint new IPC to the `pool` address on each invocation.
- Force the pair to `sync` after each burn/mint, updating reserves to reflect the manipulated balances.

The IPC–USDT PancakePair contract (`0xDe3595a7...`, `Contract.sol`) uses the standard PancakeSwap pair implementation. Its swap pricing and reserve invariants assume that token balances change only via the pair’s own `swap`, `mint`, and `burn` functions. It does not account for a token contract directly burning from and minting into its own balance at the pair address while forcing `sync`.

The adversary-controlled orchestrator `0x3BE77A3...` (from the decompiled contract) includes functions corresponding to selectors `0x3c9c2087` and `0x2e865dd5`. These functions route calls through:

- DODO-style pools `0x6098...` and `0x0e15...`,
- PancakeRouter `0x10ED43...`,
- IPC Token `0xEAb0...`,
- BEP20USDT `0x55d39...`,
- IPC–USDT PancakePair `0xDe3595a7...`.

By orchestrating token flows through these components while repeatedly triggering `_destroy`, the attacker drives the pair into a configuration where IPC and USDT reserves are misaligned, enabling a profitable drain of USDT from the pair into the attacker’s EOA.

### Vulnerable Components

- **IPC Token (`0xEAb0d4...`)** – functions `_transfer` and `_destroy` in the collected `Token.sol` source.
- **IPC–USDT PancakePair (`0xDe3595a7...`)** – AMM swap and sync logic in the collected `Contract.sol` source.

### Exploit Preconditions

- The IPC–USDT pair holds sufficient IPC and USDT liquidity for `_destroy`-driven reserve distortion to be economically meaningful.
- IPC Token has `pool` configured and `isOpenSwap` enabled so that `_transfer` paths involving the pair can invoke `_destroy` and mint new IPC to `pool`.
- The adversary controls both orchestrator contract `0x3BE77A3...` and EOA `0x09ea8b5e546914746f3dc686ac164486a607fb7b`, allowing them to route funds through DODO pools, IPC Token, PancakeRouter, and the IPC–USDT pair along the observed paths.
- No external mechanism prevents IPC Token from arbitrarily reducing the pair’s IPC balance and minting IPC to `pool` while forcing `sync`, so AMM users implicitly rely on reserves that can be changed by token-level logic outside the PancakePair.

### Violated Security Principles

- AMM reserves and prices are assumed to change only via swaps and liquidity operations within the AMM contract.
- Conservation-of-value expectations for tokens paired in constant-product AMMs are violated when token contracts can arbitrarily burn from and mint into the pair while forcing `sync`.
- Separation of concerns between token supply mechanics and AMM reserve accounting is broken.

## Adversary Flow Analysis

### Adversary Strategy Summary

The exploit is a single-block, multi-step sequence on BSC. The attacker-controlled orchestrator combines flash-liquidity from DODO pools, IPC Token’s `_destroy` mint/burn mechanism, and PancakeRouter swaps against the IPC–USDT PancakePair to drain USDT into the attacker EOA, followed by same-block USDT routing calls.

### Adversary-Related Accounts

- **Attacker EOA (`0x09ea8b5e546914746f3dc686ac164486a607fb7b`)**
  - Sends attacker-crafted transactions `0x5ef1edb9...`, `0x1dcc56...`, and `0x142b48...` on chainid 56.
  - Directly receives `591934203.953053577941826` USDT from IPC–USDT PancakePair `0xDe3595a7...` in `0x5ef1edb9...` as shown by prestateTracer balance diffs.

- **Orchestrator Contract (`0x3BE77A356848cF7220503E62E93Dfd0ff3f0074A`)**
  - Direct `to` address in attacker-crafted transactions `0x5ef1edb9...` and `0x142b48...`.
  - USDT recipient in `0x1dcc56...` via BEP20USDT `transfer`.
  - Decompiled functions route calls to DODO pools `0x6098...` / `0x0e15...`, PancakeRouter `0x10ED43...`, IPC Token, and BEP20USDT.
  - Observed usage in the incident window is exclusively by EOA `0x09ea...`, linking it to the adversary cluster.

### Victim and Related Contracts

- **AI IPC Token** – `0xEAb0d4...` (verified source).
- **IPC–USDT PancakePair** – `0xDe3595a7...` (verified source).
- **BEP20USDT** – `0x55d398326f99059fF775485246999027B3197955`.
- **DODO DPP/DVM-style pool** – `0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476`.
- **DODO DPP/DVM-style pool** – `0x0e15e47C3DE9CD92379703cf18251a2D13E155A7`.

### Lifecycle Stage 1: Adversary Initial Funding and Orchestrator Call

- **Transaction:** `0x5ef1edb9749af6cec511741225e6d47103e0b647d1e41e08649caaff66942a91` (BSC, block `45561316`).
- **Role:** Main exploit and funding orchestration.

EOA `0x09ea...` sends `52.309591946251435332` BNB (the `value` field) to orchestrator `0x3BE77A3...` and calls selector `0x3c9c2087` (function `Unresolved_3c9c2087`). Trace logs show this function:

- Borrowing or routing liquidity via DODO-style pools `0x6098...` and `0x0e15...`.
- Interacting with IPC Token `0xEAb0...`, PancakeRouter `0x10ED43...`, and IPC–USDT PancakePair `0xDe3595a7...`.

**Evidence snippet – seed transaction trace (cast run -vvvvv) for tx `0x5ef1edb9...`:**

```bash
# Excerpt-style representation of trace
CALL 0x3BE77A3... Unresolved_3c9c2087
  CALL 0x6098A563...  (DODO-style pool)
  CALL 0x0e15e47C...  (DODO-style pool)
  CALL 0xEAb0d4...    (IPC Token)
  CALL 0x10ED43C7...  (PancakeRouter)
  CALL 0xDe3595a7...  (IPC–USDT PancakePair)
```

*Caption: Seed transaction trace shows the orchestrator routing through DODO pools, IPC Token, PancakeRouter, and the IPC–USDT pair within the main exploit transaction.*

### Lifecycle Stage 2: Intra-Transaction Exploitation of IPC Token and IPC–USDT Pair

- **Transaction:** `0x5ef1edb9...` (same as Stage 1).

Within `0x5ef1edb9...`, orchestrator-controlled calls execute IPC Token transfers that trigger `_transfer` and `_destroy` as defined in Token.sol:

- IPC is burned from IPC–USDT PancakePair `0xDe3595a7...`.
- New IPC is minted to the `pool` address `0x054525bf471dfbad447e27b45c763ce6e2b05a78`.
- The pair is forced to `sync`, updating reserves after the burn and mint.

QuickNode prestateTracer balance diffs for `0x5ef1edb9...` show:

- IPC Token `0xEAb0...` balance at `0xDe3595a7...` decreases by `991564846557401299746225`.
- The zero address gains `881481308897628769271441` IPC.
- `pool` address `0x054525bf471dfbad447e27b45c763ce6e2b05a78` gains `1762962617795257538542882` IPC.
- BEP20USDT `0x55d39...` balance at `0xDe3595a7...` decreases by `591934203.953053577941826`.
- BEP20USDT balance at `0x09ea...` increases by the same `591934203.953053577941826`.

**Evidence snippet – prestateTracer ERC20 balance diffs for tx `0x5ef1edb9...`:**

```json
{
  "USDT": {
    "0xDe3595a7...": {
      "delta": "-591934203.953053577941826"
    },
    "0x09ea8b5e546914746f3dc686ac164486a607fb7b": {
      "delta": "591934203.953053577941826"
    }
  },
  "IPC": {
    "0xDe3595a7...": {
      "delta": "-991564846557401299746225"
    },
    "0x0000000000000000000000000000000000000000": {
      "delta": "881481308897628769271441"
    },
    "0x054525bf471dfbad447e27b45c763ce6e2b05a78": {
      "delta": "1762962617795257538542882"
    }
  }
}
```

*Caption: State diff confirms IPC is burned from the pair, minted to the `pool`, and that USDT moves from the pair to the attacker EOA in equal and opposite deltas.*

These deltas show that, within a single transaction, IPC supply is increased at `pool` while the pair loses IPC, and that USDT equal to `591934203.953053577941826` flows from the pair to `0x09ea...`. The orchestrator’s use of `_destroy` and AMM swaps thus converts the reserve distortion into realized USDT profit.

### Lifecycle Stage 3: Immediate Post-Exploit USDT Routing and Orchestrator Follow-up

- **Transactions (same block `45561316`):**
  - `0x1dcc562553f37d28ed6743c21a3540a01d542ca41ba382d67d4e7081a8f5aa9f`
  - `0x142b485a08833e784639968ec0b1c68c84b47c479f49b2995d9bed5bc8ef1a6e`

Address txlist for EOA `0x09ea...` in the incident window shows exactly three transactions in block `45561316`:

1. `0x5ef1edb9...` from `0x09ea...` to orchestrator `0x3BE77A3...`.
2. `0x1dcc56...` from `0x09ea...` to BEP20USDT `0x55d39...` with methodId `0xa9059cbb`, transferring USDT from `0x09ea...` to orchestrator `0x3BE77A3...`.
3. `0x142b48...` from `0x09ea...` to `0x3BE77A3...` with selector `0x2e865dd5` (function `Unresolved_2e865dd5`) and arguments:
   - `0x4848489f0b2bedd788c696e2d79b6b69d7484848`,
   - BEP20USDT `0x55d398326f99059fF775485246999027B3197955`,
   - PancakeRouter `0x10ED43C718714eb63d5aA57B78B54704E256024E`,
   - an encoded `uint256 amount`.

This stage records only deterministic facts about:

- Transaction ordering within the block,
- Participants (EOA, orchestrator, token contracts),
- Function selectors and arguments as visible in transaction inputs,
- The direct USDT transfer from `0x09ea...` to `0x3BE77A3...` in `0x1dcc56...`.

The report does not attribute any additional swaps, distributions, or profit to `0x142b48...` beyond what is directly evidenced by the available traces and balance diffs.

**Evidence snippet – attacker EOA txlist window around block `45561316`:**

```json
[
  {
    "hash": "0x5ef1edb9...",
    "from": "0x09ea8b5e546914746f3dc686ac164486a607fb7b",
    "to": "0x3BE77A3...",
    "value": "52.309591946251435332 BNB"
  },
  {
    "hash": "0x1dcc56...",
    "from": "0x09ea8b5e546914746f3dc686ac164486a607fb7b",
    "to": "0x55d398326f99059fF775485246999027B3197955",
    "input_method_id": "0xa9059cbb"
  },
  {
    "hash": "0x142b48...",
    "from": "0x09ea8b5e546914746f3dc686ac164486a607fb7b",
    "to": "0x3BE77A3...",
    "input_selector": "0x2e865dd5"
  }
]
```

*Caption: Attacker EOA sends the main exploit transaction, a USDT transfer to the orchestrator, and a follow-up orchestrator call, all within the same block.*

## Impact & Losses

### Quantified USDT Loss

QuickNode prestateTracer balance diffs for tx `0x5ef1edb9...` on BSC show:

- BEP20USDT `0x55d398326f99059fF775485246999027B3197955` balance at IPC–USDT PancakePair `0xDe3595a7...` decreases by `591934203.953053577941826`.
- BEP20USDT balance at EOA `0x09ea8b5e546914746f3dc686ac164486a607fb7b` increases by `591934203.953053577941826`.

This implies that at least `591934203.953053577941826` USDT of liquidity was removed from the pair and transferred to the adversary in the main exploit transaction. Gas fees are paid in BNB and are not converted into USDT units here, so the net USDT profit is at least this ERC20 delta minus an unquantified BNB fee component.

### Token Supply Effects

The same prestateTracer file shows:

- IPC Token balance at `0xDe3595a7...` decreasing by `991564846557401299746225`.
- The zero address gaining `881481308897628769271441` IPC.
- `pool` address `0x054525bf471dfbad447e27b45c763ce6e2b05a78` gaining `1762962617795257538542882` IPC.

These changes reflect supply expansion aligned with the `_destroy` implementation and demonstrate that IPC supply was increased at `pool` while the pair lost IPC. This report does not assign a separate reference-asset valuation to the IPC deltas.

## References

- **[1] IPC Token.sol source** – collected source for `0xEAb0d46682Ac707A06aEFB0aC72a91a3Fd6Fe5d1` (`Token.sol`).
- **[2] IPC–USDT PancakePair Contract.sol source** – collected source for `0xDe3595a72f35d587e96d5C7B6f3E6C02ed2900AB` (`Contract.sol`).
- **[3] Orchestrator decompile** – decompiled contract for `0x3BE77A356848cF7220503E62E93Dfd0ff3f0074A`.
- **[4] Profit transaction metadata and seed trace** – metadata and `cast` trace for tx `0x5ef1edb9749af6cec511741225e6d47103e0b647d1e41e08649caaff66942a91`.
- **[5] Profit transaction prestateTracer balance diff** – QuickNode prestateTracer diff for tx `0x5ef1edb9...`.
- **[6] Attacker EOA txlist window** – address txlist for `0x09ea8b5e546914746f3dc686ac164486a607fb7b` around block `45561316`.

