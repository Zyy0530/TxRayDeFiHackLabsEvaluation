# KB/USDT BSC Pool Drain via KB Tokenomics Bug

## Incident Overview & TL;DR

On BNB Chain, an unprivileged adversary used DODO (DPP) and Pancake V3 flash loans to borrow large amounts of BEP20USDT, routed this temporary liquidity through the KB/USDT PancakeSwap V2 pair, and exploited KB’s custom transfer logic so that KB tokens were burned directly from the liquidity pool while reserves were synced. After pushing the pool into a state with almost all USDT and very little KB, the attacker swapped KB back for BEP20USDT, draining nearly all USDT into their externally owned account (EOA) before repaying the flash loans.

The root cause is a protocol-level design bug in KB’s swap-specific `_transfer` implementation: when the configured swap address is the counterparty, the token burns KB from the KB/USDT pair and immediately calls `sync()` on the pair. This lets an attacker with flash-loan liquidity deterministically skew AMM reserves and extract USDT without any privileged access.

## Key Background

KB (symbol KRC) is an ERC20-like token deployed on BNB Chain with complex on-chain mining and reward mechanics. Its ecosystem includes a helper contract (KBTO) and multiple reward and referral flows, all wired through PancakeSwap V2 via a configurable swap address and the canonical router at `0x10ED43C718714eb63d5aA57B78B54704E256024E`. The KB contract exposes `setSwap`, which was used to configure the KB/USDT PancakeSwap pair as the token’s swap address.

The primary market for KB during the incident was a standard PancakeSwap V2 pair between KB and BEP20USDT (a USDT wrapper on BNB Chain). This KB/USDT pair is implemented as a normal Pancake V2 LP token contract whose `swap`, `sync`, and `skim` functions preserve a constant-product invariant over token0 (KB) and token1 (USDT). The pair itself does not contain any bespoke logic for KB.

To fund the exploit, the adversary relied on two independent flash-liquidity sources:

- A DODO Private Pool (DPP) at `0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476`, which exposes an unrestricted `flashLoan` interface callable by any address that can repay principal plus fees in the same transaction.
- A Pancake V3-style pool at `0x36696169C63e42cd08ce11f5deeBbCeBae652050`, which provides a `flash`-like mechanism allowing callers to borrow tokens and repay them via a callback.

The adversary model assumed by the analysis—and confirmed by the evidence—is a fully unprivileged on-chain actor that can deploy contracts, obtain flash loans from these public pools, and call standard router and pair functions while paying normal BNB gas costs.

From an ACT perspective, the opportunity is defined relative to the public BNB Chain state at block height 49,875,423 (`σ_B`). At this point:

- KB token `0x1814a8443F37dDd7930A9d8BC4b48353FE589b58` had its swap address configured to the KB/USDT PancakePair `0xdBEAD75d3610209A093AF1D46d5296BBeFFd53f5`.
- BEP20USDT `0x55d398326f99059fF775485246999027B3197955` was the stablecoin side of the pair.
- The DPP pool `0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476` and Pancake V3 pool `0x36696169C63e42cd08ce11f5deeBbCeBae652050` held substantial pre-trade reserves that could be tapped via flash-loan style calls.

These conditions were fully public and available to any searcher or adversary on BNB Chain.

### Evidence: Pre-state and key contracts

```json
{
  "chainid": 56,
  "txhash": "0x78f242dee5b8e15a43d23d76bce827f39eb3ac54b44edcd327c5d63de3848daf",
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xdbead75d3610209a093af1d46d5296bbeffd53f5",
      "before": "7205807872520012958697",
      "after": "1000000000000000000",
      "delta": "-7204807872520012958697"
    }
  ]
}
```

*Caption: Seed transaction balance diff on BNB Chain showing BEP20USDT drained from the KB/USDT Pancake pair (metadata and balance-diff artifact for tx 0x78f242…).*

```solidity
function _transfer(
    address sender,
    address recipient,
    uint256 amount
) internal override {
    if (swap == sender) {
        // ... special handling when the pair sends KB
    } else if (swap == recipient) {
        if (sender == address(this) || sender == hhbTo || sender == owner()) {
            super._transfer(sender, recipient, amount);
        } else {
            uint256 aaaSum = amount.percentage(100000);
            uint256 sum = amount - aaaSum;
            if (getKBUSDT() < isSwapPrice && !isSwap) {
                super._transfer(swap, destroy, sum.percentage(500000));
            } else {
                super._transfer(swap, destroy, sum.percentage(100000));
            }
            IUniswap(swap).sync();
            super._transfer(sender, hhbTo, aaaSum);
            super._transfer(sender, recipient, sum);
        }
    } else if (amount == 0) {
        // reward-claim branches omitted
    } else {
        super._transfer(sender, recipient, amount);
    }
}
```

*Caption: KB token `_transfer` implementation showing swap-specific burns from the pair and immediate `sync()` calls (verified KB source).*

## Vulnerability & Root Cause Analysis

### Vulnerability summary

KB’s transfer logic for its configured swap address violates safe integration assumptions for fee-on-transfer tokens. When the KB/USDT PancakePair is configured as `swap`, user trades that send KB into the pair trigger a path where KB is burned from the pair’s balance and the pair is immediately synced. This allows an attacker with temporary USDT liquidity to drive the pool into a state with minimal KB and large USDT reserves, then use swaps to withdraw the USDT. The AMM code itself is standard; the bug lies entirely in KB’s tokenomics and its interaction with the pool.

### Detailed root cause

In `Contract.sol` for KB, `_transfer` is overridden to treat the `swap` address specially:

- When `swap` is the **recipient** (user sends KB into the pair):
  - The transfer amount is split into a small fee portion `aaaSum` and a remainder `sum`.
  - A portion of `sum` is transferred from `swap` to a burn address `destroy`, directly burning KB held by the liquidity pair.
  - Immediately after burning, the contract calls `IUniswap(swap).sync()`, forcing the KB/USDT pair to update its reserves using the reduced KB balance and unchanged USDT.
  - The fee portion is routed to the internal rewards address `hhbTo`.
  - The remaining KB (`sum`) is then credited from the user to `swap`.

- When `swap` is the **sender**, another set of special branches applies that can also redirect transfers based on price and configuration, but the critical issue for this exploit is the “burn-from-pair and sync” branch on inbound trades.

Because the PancakePair contract for KB/USDT is a standard AMM that is unaware of these internal burns, it treats the KB balance reduction as if it resulted from a legitimate swap. Repeated large trades that invoke these branches cause KB to be removed from the pool while USDT remains, moving the implied price in a predictable direction and enabling highly asymmetric trades.

Armed with DPP and Pancake V3 flash loans, the attacker contract executed a carefully ordered sequence of swaps that:

1. Borrowed substantial BEP20USDT into the attacker-controlled contract.
2. Pushed USDT into the KB/USDT pair via router calls, causing KB’s `_transfer` to burn KB from the pair and call `sync()`, leaving the pool with negligible KB and a large USDT reserve.
3. After skewing reserves, swapped KB back into the pool to withdraw nearly all USDT, then repaid the flash loans within the same transaction.

The bug is therefore a pure protocol-level design flaw in KB’s tokenomics and its integration with a standard AMM. No misbehavior or non-standard logic in the PancakePair or the flash-loan pools is required for the exploit to succeed.

### Vulnerable components

The key vulnerable or involved components are:

- **KB token (`0x1814a8443F37dDd7930A9d8BC4b48353FE589b58`)**: overrides `_transfer` with swap-specific burning and `sync()` calls that operate directly on the KB/USDT pair’s LP-held balance.
- **KB helper (KBTO) and distribution logic**: supports KB’s mining and reward system and routes KB and USDT through the configured swap and router, increasing the impact of the flawed transfer rules.
- **KB/USDT PancakePair (`0xdBEAD75d3610209A093AF1D46d5296BBeFFd53f5`)**: a standard AMM pool whose reserves are manipulated by KB’s transfer behavior yet are still treated as if they follow a normal constant-product invariant.

### Exploit preconditions

For the exploit to be possible, the following conditions had to hold (and did hold at block 49,875,423):

- `KB.swap` was configured to the KB/USDT PancakePair and was neither changed nor paused before the exploit block.
- The KB/USDT pair held significant KB and BEP20USDT liquidity, so burning KB while leaving USDT in the pool could materially move price and enable large-value trades.
- The DPP pool and Pancake V3 pool had sufficient BEP20USDT reserves to provide the temporary liquidity used in the flash-loan legs.
- KB and the PancakePair behaved exactly as their deployed source code specifies; no owner interventions, upgrades, or pausing mechanisms were used to disable the burning-from-pair behavior before the exploit.

### Security principles violated

The design and resulting exploit violate several security principles:

- **AMM safety expectations**: It implicitly assumes that tokenomics cannot arbitrarily burn or seize LP-held tokens in ways that break AMM invariants. KB’s `_transfer` breaks this assumption by burning from the pair’s balance and then syncing.
- **Safe fee-on-transfer integration**: Best practice for fee-on-transfer tokens is to avoid direct manipulation of LP balances or to adjust reserves in a way that preserves invariants. KB instead burns from the pair and immediately calls `sync()`, creating an exploitable arbitrage surface.
- **Least authority**: KB’s `_transfer` has the power to change balances of arbitrary addresses (including the liquidity pair and burn addresses) in ways that are not directly tied to a single user’s intended transfer, increasing systemic risk.

### Evidence: Vulnerable logic and AMM interaction

```solidity
// PancakePair core transfer and sync logic (simplified)
function _update(uint balance0, uint balance1, uint112 _reserve0, uint112 _reserve1) private {
    require(balance0 <= uint112(-1) && balance1 <= uint112(-1), 'Pancake: OVERFLOW');
    uint32 blockTimestamp = uint32(block.timestamp % 2**32);
    reserve0 = uint112(balance0);
    reserve1 = uint112(balance1);
    emit Sync(reserve0, reserve1);
}
```

*Caption: Standard Pancake V2 pair `Sync` logic that blindly trusts token balances (KB/USDT PancakePair source).*

## Adversary Flow Analysis

### Strategy summary

The adversary executed a single, carefully constructed transaction from an EOA that:

1. Borrowed BEP20USDT via a DPP flash loan and a Pancake V3-style `flash` call into an attacker-controlled orchestrator contract.
2. Used PancakeRouter to route large USDT amounts into the KB/USDT pair, triggering KB’s swap-specific `_transfer` logic to burn KB from the pair and repeatedly call `sync()`, driving the pool into a state with minimal KB and large USDT reserves.
3. After reserves were skewed, swapped KB back to USDT to extract almost all BEP20USDT from the pair, then repaid both flash loans and returned any required fees, leaving the attacker with a large net BEP20USDT gain.

All of this occurred in a single block and a single transaction, with no privileged calls.

### Adversary-related accounts and roles

The analysis identifies a small adversary cluster:

- **EOA `0x9943f26831f9b468a7fe5ac531c352baab8af655` (BNB Chain)**  
  - Confirmed EOA (not a contract).  
  - Sender of the exploit transaction.  
  - Deployer of the orchestrator contract.  
  - Direct recipient of BEP20USDT profit at the end of the exploit.

- **Orchestrator contract `0xd995edcab2efe3283514ff111cedc9aaff0349c8` (BNB Chain)**  
  - Deployed by `0x9943…` shortly before the exploit.  
  - Receives flash-loaned BEP20USDT from the DPP and Pancake V3 pool.  
  - Calls PancakeRouter, the KB/USDT pair, and KB to perform swaps and token transfers.  
  - Forwards BEP20USDT profit back to the EOA while repaying flash loans.

The primary victim-side contracts are:

- **KB/USDT PancakePair `0xdBEAD75d3610209A093AF1D46d5296BBeFFd53f5` (BNB Chain)**: the liquidity pool that loses virtually all of its BEP20USDT and most of its KB.
- **KB token `0x1814a8443F37dDd7930A9d8BC4b48353FE589b58` (BNB Chain)**: the token whose transfer logic enables the exploit and whose holders suffer from the destroyed liquidity.

Address history artifacts show that the EOA first deployed the orchestrator contract and then used it for the exploit, with no evidence of privileged roles or protocol ownership.

```json
[
  {
    "blockNumber": "49875418",
    "hash": "0x23940f334991b520e2b84adb9b2a5de3cb80ebf7d1c17e2f288bc64cae316ac7",
    "from": "0x9943f26831f9b468a7fe5ac531c352baab8af655",
    "to": "",
    "contractAddress": "0xd995edcab2efe3283514ff111cedc9aaff0349c8"
  },
  {
    "blockNumber": "49875424",
    "hash": "0x78f242dee5b8e15a43d23d76bce827f39eb3ac54b44edcd327c5d63de3848daf",
    "from": "0x9943f26831f9b468a7fe5ac531c352baab8af655",
    "to": "0xd995edcab2efe3283514ff111cedc9aaff0349c8"
  }
]
```

*Caption: Address history showing the attacker EOA deploying the orchestrator and then invoking it for the exploit (address txlist for 0x9943… and 0xd995ed…).*

### Lifecycle stages

1. **Adversary orchestrator deployment**
   - **Transaction:** `0x23940f334991b520e2b84adb9b2a5de3cb80ebf7d1c17e2f288bc64cae316ac7` on BNB Chain (block 49,875,418).  
   - **Mechanism:** Contract deployment from `0x9943…`, creating the orchestrator at `0xd995ed…`.  
   - **Effect:** Establishes a dedicated contract that can receive flash loans, interact with routers and pairs, and implement the exploit sequence.  
   - **Evidence:** Normal transaction lists for `0x9943…` and `0xd995ed…`, plus the decompiled orchestrator bytecode.

2. **Flash-loan acquisition and KB/USDT reserve manipulation**
   - **Transaction:** Seed/exploit transaction `0x78f242dee5b8e15a43d23d76bce827f39eb3ac54b44edcd327c5d63de3848daf` on BNB Chain (block 49,875,424).  
   - **Mechanism:** `flashloan+swap`. The orchestrator:
     - Calls DPP `flashLoan` to borrow BEP20USDT.
     - Uses the Pancake V3-style pool’s `flash` interface to obtain additional BEP20USDT.
     - Approves PancakeRouter and routes USDT through the KB/USDT pair, repeatedly invoking KB::transfer and PancakePair::swap/sync/skim.
   - **Effect:** KB’s `_transfer` burns KB from the pair and calls `sync()` during these swaps, leaving the KB/USDT pair with minimal KB and large BEP20USDT reserves—a highly imbalanced state favorable to the attacker.
   - **Evidence:** Structured call-trace for the seed transaction and KB/PancakePair sources.

3. **Profit realization and loan repayment**
   - **Transaction:** Same seed transaction `0x78f242…` (block 49,875,424).  
   - **Mechanism:** `swap+repay`. After reserves are skewed:
     - The orchestrator swaps KB back to BEP20USDT, pulling USDT from the pair into the attacker-controlled contract and then to the EOA.
     - Flash loans from the DPP and Pancake V3 pool are repaid with principal and any required fees.
   - **Effect:** Nearly all BEP20USDT is removed from the KB/USDT pair and consolidated into the attacker EOA, while the flash-loan pools are made whole within the same transaction.
   - **Evidence:** State diffs and call-trace leaf calls showing BEP20USDT transfers from the pair to `0xd995ed…`, onward to `0x9943…`, and back to `0x6098…` for flash-loan repayment.

### Evidence: End-to-end trace of the exploit transaction

```json
{
  "calls": [
    {
      "from": "0xd995edcab2efe3283514ff111cedc9aaff0349c8",
      "to": "0x6098a5638d8d7e9ed2f952d35b2b67c34ec6b476",
      "input": "DPP::flashLoan(...)",
      "type": "CALL"
    },
    {
      "from": "0x36696169c63e42cd08ce11f5deebbcebae652050",
      "to": "0x55d398326f99059ff775485246999027b3197955",
      "input": "BEP20USDT::transfer(0xd995ed..., 1e23)",
      "type": "CALL"
    },
    {
      "from": "0x10ed43c718714eb63d5aa57b78b54704e256024e",
      "to": "0xdbead75d3610209a093af1d46d5296bbeffd53f5",
      "input": "swap and sync calls via KB::_transfer",
      "type": "CALL"
    }
  ]
}
```

*Caption: Structured call-tracer excerpt for tx 0x78f242… showing flash loans, router interactions, and KB/USDT pair calls (structured JSON trace).*

## Impact & Losses

### Token-level loss overview

The primary loss was in BEP20USDT (USDT) held by the KB/USDT PancakeSwap pair:

- **USDT (BEP20USDT) loss:** `-7,204,807,872,520,012,958,697` units (18 decimals).

According to the balance diff and state diff for the seed transaction:

- The KB/USDT PancakePair (`0xdBEAD75d…`) decreased its BEP20USDT balance from `7,205,807,872,520,012,958,697` to `1,000,000,000,000,000,000`, a net loss of `-7,204,807,872,520,012,958,697`.
- The attacker EOA (`0x9943…`) increased its BEP20USDT balance from `0` to `7,154,807,872,520,012,958,697`.
- The Pancake V3 pool (`0x3669…`) increased its BEP20USDT balance by `50,000,000,000,000,000,000` (50e18), consistent with it retaining a small amount of USDT after the attack.

KB balances also moved significantly:

- The KB/USDT pair lost most of its KB holdings, with large amounts burned to the dead address and some KB redistributed to the orchestrator contract and another beneficiary address.

Native BNB balances show the attacker EOA paying `512,313,208,000,000` wei in gas, which is small relative to the BEP20USDT profit and is not converted into USDT for valuation.

### Economic and protocol impact

The practical impact of these token movements is:

- The KB/USDT PancakeSwap pair lost nearly all of its BEP20USDT (leaving only 1e18 units) and most of its KB, effectively destroying on-chain liquidity for KB holders.
- The attacker EOA realized a net profit of `7,154,807,872,520,012,958,697` BEP20USDT after flash-loan repayments, with the Pancake V3 pool retaining 50e18 BEP20USDT as part of the ecosystem’s post-trade distribution.
- KB’s market depth and price stability were severely compromised; without external recapitalization of the KB/USDT pool, normal trading for KB holders becomes impractical or impossible.

### Evidence: Final balances and profit

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xdbead75d3610209a093af1d46d5296bbeffd53f5",
      "delta": "-7204807872520012958697"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x9943f26831f9b468a7fe5ac531c352baab8af655",
      "delta": "7154807872520012958697"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x36696169c63e42cd08ce11f5deebbcebae652050",
      "delta": "50000000000000000000"
    }
  ]
}
```

*Caption: ERC20 balance delta snippet confirming USDT loss from the KB/USDT pair and profit distribution to the attacker EOA and the Pancake V3 pool (balance-diff artifact for tx 0x78f242…).*

## ACT Opportunity and Profit Predicate

From the ACT perspective, the exploit constitutes a clean ACT opportunity `b`:

- **Block height `B`:** 49,875,424 (BNB Chain).  
- **Pre-state `σ_B`:** Public BNB Chain state at block 49,875,423, with:
  - KB token `0x1814…` configured to use the KB/USDT PancakePair `0xdBEAD75d…` as its swap.
  - BEP20USDT `0x55d398…` as the stablecoin reserve in the pair.
  - DPP pool `0x6098…` and Pancake V3 pool `0x3669…` providing flash-liquidity as indicated by their pre-trade reserves.

### Transaction sequence `b`

The opportunity consists of a single adversary-crafted transaction:

- **Index:** 1  
- **Chain:** BNB Chain (chainid 56)  
- **Tx hash:** `0x78f242dee5b8e15a43d23d76bce827f39eb3ac54b44edcd327c5d63de3848daf`  
- **Type:** `adversary-crafted`  
- **Inclusion feasibility:** Any unprivileged EOA can deploy a contract equivalent to `0xd995ed…` and submit an identical transaction to the public DPP and Pancake contracts. The DPP `flashLoan` and Pancake V3 `flash` calls are unrestricted, KB and BEP20USDT accept standard approvals, and the gas limit and price used in the observed transaction are within normal network bounds. Inclusion is therefore feasible under standard rules.  
- **Operational notes:** The transaction:
  - Obtains BEP20USDT from the DPP and Pancake V3 pools via flash loans.
  - Routes USDT through the KB/USDT pair in ways that trigger KB’s swap-specific `_transfer` branches, burning KB from the pair and syncing reserves.
  - Executes final swaps to withdraw BEP20USDT profit to the attacker while repaying all flash loans within the same transaction.

### Profit predicate

The exploit is classified as a **profit-motivated** attack:

- **Reference asset:** BEP20USDT (USDT on BNB Chain), treated as “other” in the schema.  
- **Adversary address:** EOA `0x9943f26831f9b468a7fe5ac531c352baab8af655`.  
- **Value before:** `0` BEP20USDT (the attacker EOA held zero BEP20USDT before the seed transaction).  
- **Value after:** `7,154,807,872,520,012,958,697` BEP20USDT (raw token units, 18 decimals).  
- **Value delta:** `7,154,807,872,520,012,958,697` BEP20USDT net gain. Gas is paid in BNB (512,313,208,000,000 wei) and is not converted into USDT.  
- **Fees in reference asset:** Recorded as unknown in the schema because fees are paid in native BNB, not in BEP20USDT.  
- **Valuation notes:** State diffs confirm:
  - The attacker EOA’s BEP20USDT balance increases by exactly `7,154,807,872,520,012,958,697`.  
  - The KB/USDT pair loses `-7,204,807,872,520,012,958,697` BEP20USDT.  
  - The Pancake V3 pool retains `50,000,000,000,000,000,000` BEP20USDT.  
  - Flash-loan pools are fully repaid, consistent with a net profit realized entirely in BEP20USDT by the adversary.

The non-monetary oracle fields in the schema (oracle name, definition, and evidence) are intentionally empty because this incident does not involve an oracle-manipulation root cause.

## Relevant Transactions

The following on-chain transactions are central to the incident:

1. **Orchestrator deployment (adversary-crafted, but not the profit tx)**  
   - **Chain:** BNB Chain (56)  
   - **Tx hash:** `0x23940f334991b520e2b84adb9b2a5de3cb80ebf7d1c17e2f288bc64cae316ac7`  
   - **Role:** Adversary-crafted deployment of the orchestrator `0xd995ed…` from EOA `0x9943…`.

2. **Exploit / seed transaction**  
   - **Chain:** BNB Chain (56)  
   - **Tx hash:** `0x78f242dee5b8e15a43d23d76bce827f39eb3ac54b44edcd327c5d63de3848daf`  
   - **Role:** Seed and exploit transaction that performs the flash loans, KB/USDT manipulation, profit extraction, and flash-loan repayment.

These two transactions, together with the static contract deployments for KB, BEP20USDT, the DPP, the Pancake V3 pool, and the KB/USDT pair, are sufficient to fully explain the exploit lifecycle.

## References

The analysis and conclusions are supported by the following artifacts:

- **[1] Seed transaction metadata, trace, and balance diff for tx `0x78f242dee5b8e15a43d23d76bce827f39eb3ac54b44edcd327c5d63de3848daf`.**  
  - `/home/ziyue/TxRayExperiment/incident-202512300213/artifacts/root_cause/seed/56/0x78f242dee5b8e15a43d23d76bce827f39eb3ac54b44edcd327c5d63de3848daf`

- **[2] KB token source (`Contract.sol`).**  
  - `/home/ziyue/TxRayExperiment/incident-202512300213/artifacts/root_cause/seed/56/0x1814a8443f37ddd7930a9d8bc4b48353fe589b58/src/Contract.sol`

- **[3] DPP flash-loan pool source.**  
  - `/home/ziyue/TxRayExperiment/incident-202512300213/artifacts/root_cause/data_collector/iter_1/contract/56/0x6098a5638d8d7e9ed2f952d35b2b67c34ec6b476/source/src/Contract.sol`

- **[4] KB/USDT PancakePair source.**  
  - `/home/ziyue/TxRayExperiment/incident-202512300213/artifacts/root_cause/data_collector/iter_1/contract/56/0xdbead75d3610209a093af1d46d5296bbeffd53f5/source/src/Contract.sol`

- **[5] Structured call-trace and prestate state-diff outputs for the seed transaction.**  
  - `/home/ziyue/TxRayExperiment/incident-202512300213/artifacts/root_cause/data_collector/iter_1/tx/56/0x78f242dee5b8e15a43d23d76bce827f39eb3ac54b44edcd327c5d63de3848daf`

