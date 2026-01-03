## Incident Overview & TL;DR

An unprivileged adversary exploited SilicaPools on Ethereum mainnet (chainid 1) in block 22146340 using a custom Silica index contract and a helper contract. Within a single block, the adversary:

- Obtained a WBTC flashloan.
- Manipulated the index’s `decimals` value during the Silica pool lifecycle.
- Minted and later redeemed ERC‑1155 position tokens under mis‑scaled parameters.
- Swapped WBTC to WETH and then to ETH.
- Routed more than 50 ETH to a profit EOA while leaving additional ETH on a helper contract.

The core root cause is that SilicaPools trusts an external `ISilicaIndex` implementation whose `decimals` field can be changed by an adversary during the pool lifecycle. `PoolMaths` uses `decimals` together with `shares` and `balance` to compute collateral requirements and payouts, but SilicaPools does not enforce that `decimals` is immutable or consistent with the units of the index state. A malicious index changes `decimals` mid‑lifecycle, causing mis‑scaled accounting and enabling undercollateralized payouts to the adversary’s positions.

The adversary cluster achieves at least 2.0 ETH net profit (after gas) in the reference asset ETH, with a conservative upper bound of 0.1 ETH on total gas costs for the three attacker-crafted transactions.

---

## Key Background

- SilicaPools (`0xf3F84cE038442aE4c4dCB6A8Ca8baCd7F28c9bDe`) is an ERC‑1155‑based protocol. Each pool is parameterized by:
  - A payout token (here WBTC).
  - A custom `ISilicaIndex` address.
  - Floor and cap parameters.
  - Target start and end timestamps.
  Long and short ERC‑1155 tokens represent claims on how the index’s balance changes over the pool’s lifetime.
- The `ISilicaIndex` interface exposes `shares()`, `balance()`, and `decimals()`. SilicaPools assumes:
  - `decimals` correctly describes the scale of the index’s quantities relative to the payout token.
  - The relationship between `shares`, `balance`, and `decimals` remains consistent across the pool lifecycle.
- `PoolMaths` uses the index’s `shares()`, `balance()`, and `decimals()` along with pool parameters to compute required collateral and the `balanceChangePerShare` value that determines payouts to long and short ERC‑1155 holders.
- In this incident, the index at `0x9188738a7cA1E4B2af840a77e8726cC6Dcbe7Bdb` is unverified and adversary‑controlled. The decompiled code shows:
  - Storage variables corresponding to `shares`, `decimals`, and `balance`.
  - A function that can set `decimals` from 31 to 1.
  - State diffs confirm that the index’s `decimals` value is changed inside the primary exploit transaction.
- The helper contract `0x80BF7Db69556D9521c03461978B8fC731DBBD4e4` is an unverified dispatcher callable by EOA `0xfde0d1575ed8e06fbf36256bcdfa1f359281455a`. It orchestrates:
  - A WBTC flashloan from `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb`.
  - SilicaPools interactions.
  - Swaps on the WBTC/WETH Uniswap V3 pool.
  - WETH withdrawals and ETH profit payouts to EOA `0x229b8325bb9ac04602898b7e8989998710235d5f`.

### Key Contract Snippets

**SilicaPools reliance on index.decimals() (verified source for SilicaPools at 0xf3F8…9bDe)**

The pool end logic records the ending index state and uses `index.decimals()` when computing `balanceChangePerShare` in `endPool`:

```solidity
// Collected SilicaPools source, endPool() snippet
function endPool(PoolParams calldata poolParams) public {
    bytes32 poolHash = hashPool(poolParams);
    PoolState storage sState = sPoolState[poolHash];

    ISilicaIndex index = ISilicaIndex(poolParams.index);

    // ...
    uint256 indexBalanceAtEnd = index.balance();
    sState.balanceChangePerShare = uint128(
        PoolMaths.balanceChangePerShare(
            indexBalanceAtEnd,
            sState.indexInitialBalance,
            sState.indexShares,
            index.decimals(),
            poolParams.floor,
            poolParams.cap
        )
    );
    // ...
}
```

*Caption: Verified SilicaPools code shows that `endPool` recomputes `balanceChangePerShare` using a live call to `index.decimals()`, rather than pinning the value used at pool start or collateralization.*

**Custom index with mutable decimals (decompiled index at 0x9188…7Bdb)**

```solidity
// Decompiled index contract (heimdall-rs), key fields
contract DecompiledContract {
    address public owner;
    uint256 public shares;
    uint256 store_d;
    uint256 public decimals;
    uint256 public balance;

    /// @custom:selector 0xa6f9dae1
    function changeOwner(address arg0) public payable {
        require(arg0 == (address(arg0)));
        owner = (address(arg0) * 0x01) | (uint96(owner));
    }

    /// @custom:selector 0x2ee79ded
    function change() public payable {
        decimals = 0x01;
    }
}
```

*Caption: The adversary-controlled index exposes a public `decimals` storage variable and a `change()` function that sets `decimals` to 1, allowing the adversary to modify the units used by SilicaPools at any point in the pool lifecycle.*

**Index storage diff showing decimals change during exploit**

```json
// State diff for index 0x9188…7Bdb during primary yoink() tx 0x9b9a6d…f0814
{
  "storage_diff": {
    "0x0000000000000000000000000000000000000000000000000000000000000002": {
      "from": "0x000000000000000000000000000000000000000000000000000000000000001f",
      "to":   "0x0000000000000000000000000000000000000000000000000000000000000001"
    }
  }
}
```

*Caption: Collected state diff shows storage slot 2 (the `decimals` field) changing from 31 to 1 during the primary exploit transaction, confirming on‑chain manipulation of index decimals.*

---

## Vulnerability & Root Cause Analysis

### Vulnerability Summary

SilicaPools trusts an external `ISilicaIndex` for `shares`, `balance`, and `decimals` at multiple lifecycle steps but does not constrain how the index can change `decimals` or validate that these values remain consistent with the payout token units. A malicious index can change `decimals` mid‑lifecycle in a way that breaks `PoolMaths`’ assumptions and causes undercollateralized or mis‑priced payouts.

### Detailed Root Cause

1. **Lifecycle dependence on external index:**
   - At collateralization (e.g., via `collateralizedMint`), WBTC collateral is transferred into SilicaPools based on `PoolMaths.collateral(...)`, which depends on the index’s `shares` and `decimals`.
   - When a pool is started (`startPool`), SilicaPools records snapshot values:
     - `index.shares()`.
     - `index.balance()` as `indexInitialBalance`.
     - These snapshots implicitly depend on the then‑current `decimals` (via `PoolMaths` behavior during collateralization).
   - When a pool is ended (`endPool`), SilicaPools again calls the index:
     - Reads `index.balance()` at end.
     - Reads `index.decimals()` live.
     - Computes `balanceChangePerShare` via `PoolMaths.balanceChangePerShare(...)`, which uses the current `decimals`.
2. **Assumed invariants:**
   - SilicaPools implicitly assumes:
     - `decimals` is a stable configuration parameter describing how index units map to the payout token.
     - The relationship between `shares`, `balance`, and `decimals` stays consistent from collateralization through pool end.
   - These assumptions are **not enforced** in code:
     - `decimals` is not pinned at pool start.
     - The contract does not check that `decimals` remains unchanged.
3. **Adversary-controlled index behavior:**
   - The custom index at `0x9188…7Bdb` is unverified and controlled by the adversary.
   - The decompiled contract exposes:
     - A public `decimals` variable with an auto‑generated getter.
     - A `change()` function that sets `decimals = 1`.
   - The index’s `shares` and `balance` can be set to arbitrary values consistent with the adversary’s strategy.
4. **On-chain evidence of decimals manipulation:**
   - The state diff for `0x9188…7Bdb` during the primary yoink() transaction `0x9b9a6d…f0814` shows:
     - Slot 2 (the `decimals` field) changed from `0x1f` (31) to `0x01` (1).
   - The SilicaPools call trace during the same tx includes:
     - A `STATICCALL` to `index.decimals()` before or around pool end computation.
5. **Effect on pool math and payouts:**
   - At collateralization/start, collateral requirements and initial index state are effectively tied to `decimals = 31`.
   - At pool end, `PoolMaths.balanceChangePerShare` is computed using `decimals = 1`.
   - This mismatch causes `balanceChangePerShare` (and therefore long/short payouts) to be computed on a different scale from the one implied by the locked collateral, allowing the adversary’s positions to receive a WBTC‑denominated payout that is too large relative to the WBTC originally deposited.
   - The undercollateralization occurs at the protocol level: SilicaPools pays out more WBTC than is justified by the index evolution and collateral.

### Vulnerable Components

- **SilicaPools contract (`0xf3F8…9bDe`):**
  - Uses `ISilicaIndex` for `shares`, `balance`, and `decimals` without enforcing immutability or consistency of `decimals`.
  - Calls `index.decimals()` at pool end for `balanceChangePerShare` instead of using a pinned value.
  - Relies on `PoolMaths` to compute both collateral and payouts using the same logical units, which are broken by the mutable index.
- **Custom index contract (`0x9188…7Bdb`):**
  - Adversary‑controlled implementation of `ISilicaIndex`.
  - Exposes a mutable `decimals` field via `change()`.
  - On‑chain storage diffs show `decimals` changing mid‑transaction.
- **External ecosystem components (used but not themselves flawed in this context):**
  - WBTC token (`0x2260…c599`).
  - WETH9 token (`0xC02a…6Cc2`).
  - Flashloan provider (`0xBBBB…FFCb`).
  - WBTC/WETH Uniswap V3 pool (router and pool contracts interacting with the helper contract).

---

## ACT Opportunity & Transaction Sequence

### Pre‑state σ\_B

- **Block height B:** `22146340`.
- **Pre‑state definition:** Ethereum mainnet state immediately before block 22146340, prior to:
  - Funding transaction `0xac6c9ec1b77f3084ac5345813bfa48e4d9cdd67d9309305ce6dfaff69a7cbd11`.
  - Attacker‑crafted yoink() transactions:
    - `0x9b9a6dd05526a8a4b40e5e1a74a25df6ecccae6ee7bf045911ad89a1dd3f0814`.
    - `0xb8a15efb31211b335e3e2b662cfef4ab0ae8cb5513ec67fa260c95485bad5114`.

Evidence for σ\_B:

- Seed transaction metadata and traces.
- Data collection summary and state diffs for:
  - SilicaPools (`0xf3F8…9bDe`).
  - Custom index (`0x9188…7Bdb`).
  - The three relevant transactions.

### Transaction Sequence b

1. **Tx 1 (funding, attacker-crafted)**
   - **Hash:** `0xac6c9ec1b77f3084ac5345813bfa48e4d9cdd67d9309305ce6dfaff69a7cbd11`
   - **From:** EOA `0x229b8325bb9ac04602898b7e8989998710235d5f`.
   - **To:** Helper contract `0x80BF7Db69556D9521c03461978B8fC731DBBD4e4`.
   - **Type:** Standard ETH transfer.
   - **Role:** Funds the helper contract with ETH for gas and protocol interactions.

   ```json
   // Funding tx trace summary (debug_traceTransaction callTracer)
   {
     "result": {
       "from": "0x229b8325bb9ac04602898b7e8989998710235d5f",
       "to":   "0x80bf7db69556d9521c03461978b8fc731dbbd4e4",
       "value": "0x29dfee0c2a906076d"
     }
   }
   ```

   *Caption: Trace for tx 0xac6c9e…bd11 shows a direct ETH transfer from the profit EOA to the helper contract with value 0x29dfee0c2a906076d ≈ 48.2782721821223 ETH.*

2. **Tx 2 (primary yoink, attacker-crafted)**
   - **Hash:** `0x9b9a6dd05526a8a4b40e5e1a74a25df6ecccae6ee7bf045911ad89a1dd3f0814`
   - **From:** EOA `0xfde0d1575ed8e06fbf36256bcdfa1f359281455a`.
   - **To:** Helper contract `0x80BF7Db69556D9521c03461978B8fC731DBBD4e4`.
   - **Mechanism:** Flashloan + index/pool manipulation + swaps + ETH payout.
   - **Role:** Main exploit transaction that realizes undercollateralized payouts.

   Key on‑chain behaviors:

   - Approvals for WBTC:
     - Helper approves SilicaPools and flashloan provider to move WBTC.
   - WBTC flashloan:
     - Flashloan provider at `0xBBBB…FFCb` sends `1e9` units of WBTC to the helper.
   - SilicaPools interactions:
     - Helper moves WBTC into SilicaPools to collateralize a pool using the malicious index.
     - SilicaPools calls `index.shares()`, `index.balance()`, and `index.decimals()`, and later `endPool` computes `balanceChangePerShare`.
   - Index manipulation:
     - Index `0x9188…7Bdb` changes its `decimals` from 31 to 1 via `change()`, as seen in the storage diff.
   - Payout and swaps:
     - SilicaPools pays an undercollateralized WBTC amount back to the helper.
     - Helper swaps WBTC→WETH on Uniswap V3 and unwraps WETH to ETH via WETH9.
     - Helper forwards most ETH to the profit EOA and retains a small remainder.

   ```json
   // Excerpt from call trace of primary yoink() tx 0x9b9a6d…f0814
   {
     "calls": [
       {
         "from": "0x80bf7db69556d9521c03461978b8fc731dbbd4e4",
         "to":   "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
         "input": "0x095ea7b3…",  // WBTC approve SilicaPools
         "type": "CALL"
       },
       {
         "from": "0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb",
         "to":   "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
         "input": "0xa9059cbb…",  // Flashloan provider transfers WBTC to helper
         "type": "CALL"
       },
       {
         "from": "0xf3f84ce038442ae4c4dcb6a8ca8bacd7f28c9bde",
         "to":   "0x9188738a7ca1e4b2af840a77e8726cc6dcbe7bdb",
         "input": "0x313ce567",   // index.decimals()
         "output": "0x…1f",
         "type": "STATICCALL"
       }
     ]
   }
   ```

   *Caption: Primary yoink() call trace shows WBTC approvals and transfers, a flashloan from 0xBBBB…FFCb, and a `STATICCALL` to the malicious index’s `decimals()` function as part of the SilicaPools pool computation.*

3. **Tx 3 (second yoink, attacker-crafted, same block)**
   - **Hash:** `0xb8a15efb31211b335e3e2b662cfef4ab0ae8cb5513ec67fa260c95485bad5114`
   - **From:** Same EOA `0xfde0d1575ed8e06fbf36256bcdfa1f359281455a`.
   - **To:** Helper contract `0x80BF7Db69556D9521c03461978B8fC731DBBD4e4`.
   - **Mechanism:** Repeats a similar flashloan + SilicaPools + swap pattern.
   - **Role:** Provides additional profit but is not necessary to prove a strictly positive ACT profit delta.

   ```json
   // Excerpt from call trace of second yoink() tx 0xb8a15e…d5114
   {
     "calls": [
       {
         "from": "0x4585fe77225b41b697c938b018e2ac67ac5a20c0",
         "to":   "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
         "input": "0xa9059cbb…",  // WBTC transfer to helper
         "type": "CALL"
       },
       {
         "from": "0x80bf7db69556d9521c03461978b8fc731dbbd4e4",
         "to":   "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
         "input": "0xd0e30db0",   // WETH9.deposit (wrap ETH to WETH)
         "type": "CALL"
       }
     ]
   }
   ```

   *Caption: Second yoink() trace shows additional WBTC movements and WETH interactions via the helper contract, mirroring the primary exploit pattern and generating extra ETH profit.*

---

## Adversary Flow Analysis

### Adversary-Related Accounts

- **Profit EOA:** `0x229b8325bb9ac04602898b7e8989998710235d5f`
  - Provides initial ETH funding to the helper contract.
  - Receives the majority of ETH profits from the helper.
- **Helper contract:** `0x80BF7Db69556D9521c03461978B8fC731DBBD4e4`
  - Orchestrates flashloans, SilicaPools interactions, swaps, and ETH payouts.
  - Retains a small amount of ETH as residual profit.
- **Transaction‑sender EOA:** `0xfde0d1575ed8e06fbf36256bcdfa1f359281455a`
  - Originates the yoink() transactions calling the helper contract.
  - Pays gas for the attacker-crafted transactions.
- **Malicious index:** `0x9188738a7cA1E4B2af840a77e8726cC6Dcbe7Bdb`
  - Adversary‑controlled implementation of `ISilicaIndex`.
  - Provides mutable `decimals`, enabling the mis‑scaling exploit.

These entities form the adversary cluster used in the ACT profit calculation.

### Lifecycle Stages

1. **Adversary initial funding**
   - **Tx:** `0xac6c9e…bd11`.
   - The profit EOA `0x229b…d5f5` transfers exactly `48.278272182122317677` ETH to the helper contract `0x80BF…d4e4`.
   - This funding covers gas and any protocol fees needed for the exploit.

2. **Adversary tx execution (primary yoink)**
   - **Tx:** `0x9b9a6d…f0814`.
   - Sender EOA `0xfde0…455a` invokes the helper contract.
   - The helper:
     - Obtains a `1e9`‑unit WBTC flashloan from `0xBBBB…FFCb`.
     - Approves and transfers WBTC into SilicaPools to collateralize a pool parameterized with the malicious index.
     - Triggers pool lifecycle actions (start and end) that cause SilicaPools to:
       - Read index state and `decimals`.
       - Compute a mis‑scaled `balanceChangePerShare` due to the `decimals` change from 31 to 1.
     - Receives an undercollateralized WBTC payout from SilicaPools.
     - Swaps WBTC→WETH on Uniswap V3 and unwraps WETH to ETH via WETH9.
     - Pays back the flashloan principal plus fee.
     - Forwards:
       - `50.834053044409908846` ETH to profit EOA `0x229b…d5f5`.
       - Keeps `0.050884937982393301` ETH on the helper contract.

3. **Adversary repeated execution (second yoink)**
   - **Tx:** `0xb8a15e…d5114`.
   - Sender EOA `0xfde0…455a` again calls the helper contract.
   - The transaction reuses the same helper and malicious index setup to run another decimals‑based pool manipulation strategy, increasing total profit.
   - This second transaction is additive to the adversary’s gain but not required to satisfy the ACT profit predicate.

---

## Profit Predicate & Quantitative Analysis

### ACT Profit Predicate

- **Type:** Profit.
- **Reference asset:** ETH.
- **Adversary address (cluster representative):** `0x229b8325bb9ac04602898b7e8989998710235d5f`.

The analysis considers the adversary cluster:

- EOA `0x229b…d5f5` (profit receiver and funder).
- Helper contract `0x80BF…d4e4`.
- Sender EOA `0xfde0…455a` (tx origin for yoink()).

### Balance Deltas from Primary Yoink

Using `balance_diff.json` and `balance_diff_extended.json` for the primary yoink() transaction `0x9b9a6d…f0814`:

```json
// Seed balance diff for 0x9b9a6d…f0814 (native ETH)
{
  "native_balance_deltas": [
    {
      "address": "0x80bf7db69556d9521c03461978b8fc731dbbd4e4",
      "delta_wei": "50884937982393301"
    },
    {
      "address": "0xfde0d1575ed8e06fbf36256bcdfa1f359281455a",
      "delta_wei": "-476756366117580"
    },
    {
      "address": "0x229b8325bb9ac04602898b7e8989998710235d5f",
      "delta_wei": "50834053044409908846"
    }
  ]
}
```

*Caption: Native balance diffs for the primary yoink() tx show ETH gains for the helper contract and profit EOA, and a small gas payment loss for the sender EOA.*

ETH‑denominated changes in the primary yoink() tx:

- Profit EOA `0x229b…d5f5`: `+50.834053044409908846` ETH.
- Helper contract `0x80BF…d4e4`: `+0.050884937982393301` ETH.
- Sender EOA `0xfde0…455a`: `-0.00047675636611758` ETH (gas).

### Funding Transaction Delta

In the funding transaction `0xac6c9e…bd11`:

- Profit EOA `0x229b…d5f5` sends exactly `48.278272182122317677` ETH to the helper contract `0x80BF…d4e4`.

### Net Profit Calculation (Cluster)

Aggregate over the adversary cluster for the funding and primary yoink() transactions:

- Cluster gross ETH gain:
  - `50.834053044409908846` (profit EOA gain)
  - `+ 0.050884937982393301` (helper gain)
  - `− 48.278272182122317677` (funding outflow)
  - `− 0.00047675636611758` (yoink() gas)
  - ≈ `2.606188` ETH gross profit.

Gas costs for the other attacker‑crafted transactions (funding and second yoink()) are also included in the conservative bound:

- All three attacker‑crafted transactions:
  - Gas limits below `1,000,000`.
  - Gas prices below `30 gwei`.
- Therefore, total gas spent is strictly `< 0.1` ETH.

Subtracting the conservative upper bound of `0.1` ETH gas from the ≈ `2.606188` ETH gross gain yields:

- Net cluster profit > `2.5` ETH.

The analysis conservatively asserts:

- **Value delta in reference asset:** `>= 2.0` ETH for the adversary cluster after all fees.

This satisfies the ACT profit predicate: the adversary can deterministically achieve strictly positive ETH‑denominated profit from state σ\_B by executing the transaction sequence b.

---

## Impact & Losses

### Quantified Minimum Profit

- **Reference asset:** ETH.
- **Adversary cluster profit:** At least `2.0` ETH net of gas, based on:
  - Exact ETH balance deltas across the funding and primary yoink() transactions.
  - A conservative `< 0.1` ETH upper bound on total gas fees for all three attacker‑crafted transactions.

### Protocol-Level Impact

- SilicaPools suffers undercollateralized payouts denominated in WBTC that are converted to ETH by the adversary.
- The protocol’s accounting invariants between collateral, index evolution, and payouts are broken for pools that integrate the malicious index.
- Additional impacts:
  - The exact WBTC‑denominated protocol loss and any secondary DeFi side‑effects (such as WBTC/WETH Uniswap pool imbalance) are not fully quantified in this analysis.
  - However, the adversary’s ETH‑denominated profit is proven to be at least `2.0` ETH net of gas, establishing a clear economic loss to SilicaPools and its users.

---

## References

Key artifacts underlying this analysis:

1. **Seed transaction metadata and trace**
   - Seed transaction `0x9b9a6d…f0814` metadata and `callTracer` trace.
2. **SilicaPools contract source**
   - Verified source for `SilicaPools.sol` at `0xf3F84cE038442aE4c4dCB6A8Ca8baCd7F28c9bDe`.
3. **Custom index decompiled source**
   - Heimdall‑decompiled contract for `0x9188738a7cA1E4B2af840a77e8726cC6Dcbe7Bdb`, showing mutable `decimals` behavior.
4. **Primary yoink() call trace**
   - `callTracer` output for `0x9b9a6d…f0814`, covering flashloan, SilicaPools, index, WBTC/WETH pool, and WETH9 interactions.
5. **Funding and second yoink() call traces**
   - `callTracer` outputs for:
     - Funding tx `0xac6c9e…bd11`.
     - Second yoink() tx `0xb8a15e…d5114`.
6. **State and balance diffs**
   - Index and SilicaPools storage diffs during the primary yoink() tx.
   - Native balance diffs for the three adversary-crafted transactions used to compute the ETH profit lower bound.

