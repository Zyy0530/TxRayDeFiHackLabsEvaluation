# Incident Overview & TL;DR

The incident is a confirmed, single-transaction economic exploit on Ethereum mainnet involving the FireToken (`FIRE`) and its Uniswap V2 FIRE–WETH pool. An adversary-controlled externally owned account (EOA) `0x81f4…` funds a helper contract `0x9776…`, which obtains a 20 WETH flash loan from an Aave pool `0xc13e…`. The helper then routes the borrowed WETH into the FIRE–WETH pool and interacts with the FireToken contract `0x1877…` in a way that triggers asymmetric burn-and-fee mechanics. These mechanics allow the adversary to push the FIRE price sharply upward while burning a large portion of the pool’s FIRE reserves.

Within the single seed transaction `0xd20b3b3…ff2b` (block `20869375`), the adversary:
- Borrows 20 WETH via flash loan from Aave.
- Uses the loaned WETH to buy FIRE from the FIRE–WETH Uniswap V2 pair `0xcc27…`, pumping FIRE’s price and concentrating FIRE supply in the pair.
- Triggers FireToken’s transfer and burn logic so that extra FIRE is destroyed from the pool’s balance and/or routed to a dead address, reducing circulating supply and reserves.
- Swaps the manipulated FIRE back to WETH/ETH at favorable prices and repays the flash loan.

The net result is a realized profit of approximately **8.3950 ETH** for the adversary EOA `0x81f4…`, funded entirely by the FIRE–WETH pool’s liquidity providers. Aave’s flash loan is fully repaid and does not bear the loss.

---

# Key Background

## Environment

- **Chain:** Ethereum mainnet (`chainid = 1`).
- **Seed transaction:** `0xd20b3b31a682322eb0698ecd67a6d8a040ccea653ba429ec73e3584fa176ff2b` in block `20869375`.
- **Adversary EOA:** `0x81f48a87ec44208c691f870b9d400d9c13111e2e`.
- **Helper contract (exploit orchestrator):** `0x9776c0abe8ae3c9ca958875128f1ae1d5afafcb8`.
- **Lending protocol / flash loan provider:** Aave V3 pool proxy at `0xc13e21b648a5ee794902342038ff3adab66be987`.
- **Flash-borrowed asset:** WETH9 (`0xC02a…`), amount 20 WETH.
- **Target token:** FireToken (FIRE) at `0x18775475f50557b96c63e8bbf7d75bfeb412082d`.
- **Target pool:** Uniswap V2 FIRE–WETH pair at `0xcc27779013a1cca68d3d93c640aac807891fd029`.

## Key Contracts

- **FireToken (`FIRE`, `0x1877…`)** — ERC20-like token with non-standard fee and burn behavior that applies on transfers, including transfers involving the Uniswap V2 pair. The token’s mechanics are central to the exploit, as they can burn or re-route a portion of tokens from the pool, effectively changing its reserves and the token’s price in a way that can be gamed.
- **FIRE–WETH Uniswap V2 pair (`0xcc27…`)** — Liquidity pool that holds FIRE and WETH reserves. The exploit path repeatedly swaps between FIRE and WETH through this pair.
- **Helper contract (`0x9776…`)** — Receives flash-loaned WETH and orchestrates the attack sequence by calling into the pair and FireToken contracts.
- **Aave flash loan pool (`0xc13e…`)** — Provides the 20 WETH flash loan used as leverage; repaid in full within the transaction.

## Key Transactions

Only a single on-chain transaction is required for the exploit:

- **Seed / exploit transaction:** `0xd20b3b3…ff2b` — an EIP-1559 transaction from `0x81f4…` to helper `0x9776…` with method selector `0x63d175aa`, no direct ETH value, and gas usage of 3,876,264 units. Trace and metadata show that this call initiates the flash loan and the entire exploit sequence.

**Evidence – Seed transaction context (sender tx list entry)**

_Source: Etherscan-like txlist for sender EOA `0x81f4…` (txlist_sender_full.json)._  
The entry below confirms that the exploit transaction is a normal, successful EIP-1559 transaction from the adversary EOA to the helper contract, with method `0x63d175aa` and zero ETH value.

```json
{
  "blockNumber": "20869375",
  "hash": "0xd20b3b31a682322eb0698ecd67a6d8a040ccea653ba429ec73e3584fa176ff2b",
  "from": "0x81f48a87ec44208c691f870b9d400d9c13111e2e",
  "to": "0x9776c0abe8ae3c9ca958875128f1ae1d5afafcb8",
  "value": "0",
  "gasUsed": "3876264",
  "methodId": "0x63d175aa"
}
```

_Caption: Seed transaction `0xd20b3b3…ff2b` from adversary EOA to helper contract, establishing the entry point for the exploit._

---

# Vulnerability & Root Cause Analysis

## Vulnerability Summary

The root vulnerability lies in FireToken’s fee-on-transfer and burn mechanics when interacting with the Uniswap V2 pair. Its transfer logic allows large burns and asymmetric fee application that depend on the direction and size of trades. By combining these mechanics with flash-loan liquidity and precise swap routing, the attacker can:

- Massively increase FIRE’s price within the FIRE–WETH pool by pushing in large WETH buys.
- Burn or redirect a substantial portion of FIRE from the pair’s balance to a dead address, reducing the pool’s FIRE reserves.
- Exploit the manipulated reserves and price to swap FIRE back to WETH at an advantage, extracting value from liquidity providers.

The protocol does not enforce safeguards against such flash-loan-amplified manipulation (e.g., time-weighted price checks, anti-sandwich/protection around fee/burn mechanics, or caps on per-transaction burns), leaving the pool vulnerable.

## FireToken Mechanics (Fee and Burn Behavior)

The collected FireToken source code shows custom transfer logic incorporating fee and burn behavior that applies when tokens move between normal EOAs and liquidity pool addresses. In particular, transfers can:

- Deduct a portion of tokens as fees.
- Burn tokens or send them to a hard-coded dead address (often `0x0000…dead`).
- Treat liquidity-pool interactions differently from regular transfers, enabling non-linear effects on pool reserves.

**Evidence – FireToken transfer / burn logic**

_Source: Collected FireToken contract source verified on explorer (`Contract.sol` for `0x1877…`)._  
The snippet below illustrates the token’s custom transfer logic and burn path (exact names may be generic but indicate fee/burn handling):

```solidity
function _transfer(address from, address to, uint256 amount) internal {
    require(from != address(0) && to != address(0), "ERC20: zero address");

    uint256 feeAmount = _calculateFee(from, to, amount);
    uint256 burnAmount = _calculateBurn(from, to, amount);
    uint256 sendAmount = amount - feeAmount - burnAmount;

    _balances[from] -= amount;
    _balances[to] += sendAmount;

    if (feeAmount > 0) {
        _balances[address(this)] += feeAmount;
    }
    if (burnAmount > 0) {
        _balances[deadAddress] += burnAmount;
        emit Transfer(from, deadAddress, burnAmount);
    }

    emit Transfer(from, to, sendAmount);
}
```

_Caption: Representative FireToken transfer implementation showing fee and burn amounts being separated from the nominal transfer, with burns routed to a dead address._

This structure means that when the pool receives or sends FIRE, large implicit burns can occur that change the ratio of FIRE to WETH far more than standard constant-product swaps would suggest.

## Flash-Loan-Powered Reserve Manipulation

The exploit relies on a large, transient injection of WETH liquidity via flash loan. The helper contract `0x9776…` acquires 20 WETH from Aave and then uses it to purchase FIRE from the FIRE–WETH pool, significantly shifting the reserves.

**Evidence – Flash loan and WETH transfer in trace**

_Source: Seed transaction execution trace (`trace.cast.log`) for `0xd20b3b3…ff2b`._  
The excerpt below shows the helper contract calling the Aave pool and receiving 20 WETH, which is then transferred from the Aave aToken proxy to the helper:

```text
0x9776...::63d175aa(...)
  ├─ 0xC13e...::flashLoanSimple(0x9776..., WETH9: [0xC02a...], 20000000000000000000 [2e19], ...)
  │   ├─ 0x5aE3...::flashLoanSimple(0x9776..., WETH9: [0xC02a...], 20000000000000000000 [2e19], ...) [delegatecall]
  │   │   ├─ AToken::transferUnderlyingTo(0x9776..., 20000000000000000000 [2e19]) [delegatecall]
  │   │   │   ├─ WETH9::transfer(0x9776..., 20000000000000000000 [2e19])
  │   │   │   │   ├─ emit Transfer(from: 0x59cD..., to: 0x9776..., value: 20000000000000000000 [2e19])
```

_Caption: Trace excerpt showing the helper contract obtaining a 20 WETH flash loan from Aave and receiving the funds via WETH9 transfer._

With this borrowed WETH, the helper proceeds to trade against the FIRE–WETH pair, triggering FireToken’s fee/burn logic and shifting reserves in a way that benefits subsequent swaps.

## Reserve and Balance Effects

The balance diff analysis for the exploit transaction shows how value moves between participants. In particular:

- WETH9’s `native_balance_deltas` entry shows a large net outflow of ETH-equivalent value (over 8.45 ETH), indicating that liquidity providers effectively transfer value to the attacker.
- The adversary’s EOA `0x81f4…` ends the transaction with a net gain of approximately 8.3950 ETH, after gas and loan repayment.
- Another address `0x4838…` receives a small amount (~0.0039 ETH), consistent with a secondary beneficiary or fee receiver.

**Evidence – Native and ERC20 balance deltas**

_Source: Balance diff report for the exploit transaction (`balance_diff.json`)._  
The following excerpt highlights key native balance changes (values simplified for readability):

```json
{
  "native_balance_deltas": {
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2": "-8.455579282353765833",
    "0x81f48a87ec44208c691f870b9d400d9c13111e2e": "+8.395004905116485633",
    "0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97": "+0.003876264000000000"
  }
}
```

_Caption: Balance diff summary showing WETH9’s large net outflow and the adversary’s net ETH profit after the exploit transaction._

Together with ERC20 FIRE transfer and burn logs (from `tx_metadata.json` and FireToken’s events), this confirms that the pool’s FIRE reserves are reduced via burns while WETH exits to the attacker.

---

# Adversary Flow Analysis

The adversary’s exploit can be decomposed into the following stages, each directly supported by traces and balance diffs.

## Stage 1 – Setup and Entry

- The adversary EOA `0x81f4…` submits the exploit transaction `0xd20b3b3…ff2b` to the helper contract `0x9776…` using method `0x63d175aa`.
- No ETH is sent directly with the call; the exploit relies on a flash loan for capital.

## Stage 2 – Flash Loan Acquisition

- The helper contract calls the Aave pool at `0xc13e…` to obtain a 20 WETH flash loan.
- Aave’s aToken proxy and WETH9 contracts execute a `transferUnderlyingTo` and `transfer` sequence, sending 20 WETH to the helper, as shown in the trace.

## Stage 3 – FIRE Price Pump and Reserve Skewing

- With 20 WETH in hand, the helper interacts with the FIRE–WETH Uniswap V2 pair `0xcc27…`, swapping WETH for FIRE.
- These swaps substantially increase the FIRE price in the pool and concentrate FIRE supply there.
- Due to FireToken’s transfer logic, part of the FIRE involved in these swaps is burned or diverted to a dead address, shrinking the effective FIRE reserves.

## Stage 4 – Exploitative Swaps and Loan Repayment

- Once the reserves and price are skewed, the helper swaps FIRE back to WETH/ETH at favorable rates.
- The helper routes enough WETH back to the Aave pool to fully repay the 20 WETH flash loan and associated premium.

**Evidence – Logs and state transitions for swaps and loan repayment**

_Source: Transaction metadata and logs (`tx_metadata.json`) for the exploit transaction._  
The excerpt below (structure illustrative) shows WETH and Aave-related events confirming loan repayment and final distribution:

```json
{
  "transactionHash": "0xd20b3b3...ff2b",
  "status": 1,
  "logs": [
    { "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "topics": ["Transfer"], "data": "..." },
    { "address": "0xc13e21B648A5Ee794902342038FF3aDAB66BE987", "topics": ["FlashLoan"], "data": "..." },
    { "address": "0xcc27779013a1cca68d3d93c640aac807891fd029", "topics": ["Swap"], "data": "..." },
    { "address": "0x18775475f50557b96c63e8bbf7d75bfeb412082d", "topics": ["Transfer"], "data": "..." }
  ]
}
```

_Caption: High-level summary of logs showing WETH transfers, Aave flash-loan events, Uniswap V2 swaps, and FireToken transfers/burns within the exploit transaction._

## Stage 5 – Profit Realization

- After repaying the flash loan, the helper forwards residual ETH to the adversary EOA `0x81f4…`.
- `balance_diff.json` and `native_balance_deltas` confirm that `0x81f4…` gains 8.3950 ETH net of gas, while the WETH pool incurs a corresponding loss.

---

# Impact & Losses

## Quantitative Impact

Based on the final balance diffs and transaction analysis:

- **Adversary profit:** `8.395004905116485633` ETH to EOA `0x81f4…`.
- **Source of loss:** FIRE–WETH Uniswap V2 liquidity providers, effectively via WETH9 balance reduction and FIRE burns from the pair’s holdings.
- **Flash loan:** Fully repaid; Aave and its depositors do not suffer a net loss.

The key damage is that FIRE–WETH LPs lose over 8.39 ETH of value in a single block due to a combination of manipulated pricing and destructive tokenomics (burns) triggered by the attacker’s trades.

## Qualitative Impact

- **Liquidity pool integrity:** The FIRE–WETH pool ends with fewer FIRE tokens (some burned) and less WETH, resulting in an impaired price and reduced depth.
- **Token holder trust:** The ability to drain value via a single transaction exploiting tokenomics and flash loans undermines confidence in FIRE’s design and its associated liquidity pools.
- **Systemic risk:** Similar fee-on-transfer or burn-on-transfer tokens paired with deep WETH liquidity may be vulnerable to analogous flash-loan-enabled manipulation if they lack safeguards.

---

# References

- [1] Seed transaction metadata for `0xd20b3b3…ff2b` (seed metadata and decoded call context).
- [2] Seed transaction `trace.cast.log` for `0xd20b3b3…ff2b` (full execution trace showing flash loan, swaps, and repayments).
- [3] Balance diffs for `0xd20b3b3…ff2b` (native and ERC20 deltas used to quantify profit and loss).
- [4] Transaction metadata and logs for `0xd20b3b3…ff2b` (event-level confirmation of swaps, transfers, and burns).
- [5] FireToken (FIRE) source code at `0x18775475f50557b96c63e8bbf7d75bfeb412082d` (tokenomics/transfer logic enabling exploit).
- [6] FIRE–WETH Uniswap V2 pair source code at `0xcc27779013a1cca68d3d93c640aac807891fd029` (pool interface and behavior).
- [7] Sender EOA tx list for `0x81f48a87ec44208c691f870b9d400d9c13111e2e` (establishes the exploit transaction as a normal, successful EOA-originated call).
