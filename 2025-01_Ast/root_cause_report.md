## AST Staking / AST–USDT Flash-Loan Price Manipulation on BSC

### 1. Incident Overview & TL;DR

An unprivileged EOA `0x56f77adc522bffebb3af0669564122933ab5ea4f` on BSC uses an adversary-deployed orchestrator `0xaa0cee271f7c1a14cd0777283cb5741e46a2c732` together with staking proxy `0xc8b9817eb65b7d7e85325f23a60d5839d14f9ce4` to execute a two-transaction sequence that combines a 30M USDT flash loan with AST/USDT price distortion. Through this sequence, the adversary turns roughly 9 BNB of initial capital into about 94 BNB of final holdings. The attack relies on AST’s non-standard, path-dependent transfer logic and on how the upgraded staking implementation at `0x7ee798bd2b3aa93828ca1c38f32b2fd84c050d2d` integrates AST and the AST/USDT pool into user accounting and withdrawals.

The root cause is an economic-design vulnerability in the upgraded staking implementation and its interaction with AST’s `pool_usdt`-based transfer logic. The `withdraw()` path allows a flash-loan-filled trade to realize outsized BNB proceeds relative to the capital at risk, without enforcing robust invariants that tie user claims and rewards to verifiable AST/USDT pool reserves.

### 2. Key Background

- **ASTToken (`0xc10e0319337c7f83342424df72e73a70a29579b2`)**  
  AST is an ERC20-like token with custom transfer logic. It tracks `pool_usdt` as the USDT balance of the AST/USDT Pancake pair `0x5ffec8523a42be78b1ad1244fa526f14b64ba47a` and maintains `lastBalance` per address. Fees, burns, and transfers depend on whether a transfer involves the AST/USDT pair or whitelisted addresses. This makes AST’s behaviour path-dependent and sensitive to AMM reserve changes.

- **Staking proxy (`0xc8b9817eb65b7d7e85325f23a60d5839d14f9ce4`) and implementation (`0x7ee798bd2b3aa93828ca1c38f32b2fd84c050d2d`)**  
  Proxy `0xc8b9817e…` is an `ERC1967Proxy` that was upgraded at block 45,961,999 (tx `0x96e9c3fcdcb80ded00d6db4dd272d496177ce42831f576ef3f9d76341e6d35ec`) to implementation `0x7ee7…`. This implementation’s `deposit()` and `withdraw()` functions integrate AST and the AST/USDT pool behaviour into staking and reward accounting, relying on AST’s internal state and the pool’s reserves.

- **Adversary orchestrator (`0xaa0cee271f7c1a14cd0777283cb5741e46a2c732`)**  
  The orchestrator is deployed by the adversary EOA at block 45,964,336 (tx `0x6d81a5840e347fded980b41e0ab1f9973c91dfd4f32f2ecfcf25700b9299ca0b`). It is used exclusively by that EOA to deposit into and withdraw from proxy `0xc8b9817e…` via `delegatecall`, and to coordinate the flash-loan-based trading sequence.

- **Liquidity venues**  
  The AST/USDT Pancake pair `0x5ffec8523a42be78b1ad1244fa526f14b64ba47a` and the USDT/WBNB pair `0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae` are the main liquidity venues through which both normal users and the adversary move value between AST, USDT, and BNB. These AMM pools are central to both AST’s price formation and the protocol’s implicit pricing inside `deposit()` and `withdraw()`.

#### Code Evidence: ASTToken’s Custom Accounting

The AST token’s verified source shows `pool_usdt` and `lastBalance`-based logic that makes transfers depend on AMM balances and special addresses.

_Snippet: ASTToken.sol core state and transfer hooks (verified source on BSC)_

```solidity
// From verified ASTToken.sol (BSC, 0xc10e0319337c7f83342424df72e73a70a29579b2)
mapping(address => uint256) public lastBalance;
address public pool;
uint256 public pool_usdt;

function _transfer(address from, address to, uint256 amount) internal override {
    // Logic (simplified) that updates pool_usdt based on USDT balance of the pool
    // and applies fee/burn behaviour depending on whether `from` or `to` is the
    // AST/USDT pair or other whitelisted addresses.
}
```

This design allows AST transfers involving the AST/USDT pair to trigger large burns and rebalancing transfers contingent on pool USDT balances, which is later exploited through flash-loan-driven reserve shifts.

### 3. ACT Opportunity and Exploit Predicate

#### 3.1 Pre-state and Opportunity Definition

- **Chain and height**: BSC (chainid 56), block height `B = 45964640`.
- **Pre-state `σ_B`**: Public BSC state at and immediately before block 45,964,640, reconstructed from:
  - Raw input and seed index (`raw.json`, `artifacts/root_cause/seed/index.json`).
  - Seed withdraw/flash tx `0x80dd9362d211722b578af72d551f0a68e0dc1b1e077805353970b2f65e793927` metadata, trace, and balance diffs.
  - Adversary deposit tx `0x78867f7126ccbb81dfc7351221b6ab571a7899332cb1c72adfa4767822b10f62` prestateTracer state and balance diffs.
  - Aggregated data collector summary (`artifacts/root_cause/data_collector/data_collection_summary.json`).

_Snippet: Pre-state reconstruction evidence (seed metadata and balance diffs)_

```json
{
  "txhash": "0x80dd9362d211722b578af72d551f0a68e0dc1b1e077805353970b2f65e793927",
  "native_balance_deltas": [
    {
      "address": "0x56f77adc522bffebb3af0669564122933ab5ea4f",
      "before_wei": "5120724695396350352",
      "after_wei": "99319695011690298688",
      "delta_wei": "94198970316293948336"
    }
  ]
}
```

_Caption: Seed transaction pre/post native balances confirming the large BNB inflow to the adversary EOA._

#### 3.2 Transaction Sequence `b`

The ACT opportunity is instantiated by a two-transaction sequence that any adversary controlling the EOA can submit under standard BSC rules:

1. **Tx 1 (index 1) – Adversary deposit and position priming**
   - **Chain / hash**: BSC 56, `0x78867f7126ccbb81dfc7351221b6ab571a7899332cb1c72adfa4767822b10f62`.
   - **Type**: Adversary-crafted.
   - **Inclusion feasibility**: Unprivileged EOA `0x56f7…` sends a standard `deposit(uint256)` call with ~9 BNB to its orchestrator `0xaa0cee…`. This is a normal externally-owned transaction that any holder of the EOA key can broadcast.
   - **Behaviour**:
     - Swaps ~9 BNB to USDT via the USDT/WBNB pair `0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae`.
     - Transfers 1,000,000 USDT from orchestrator `0xaa0cee…` into staking proxy `0xc8b9817e…`.
     - Routes 500,000 USDT through AST/USDT pair `0x5ffec8523a42be78b1ad1244fa526f14b64ba47a` to mint and then burn a large AST position, seeding the staking contract’s internal accounting (`storage_map_*`, `AST.pool_usdt`).

2. **Tx 2 (index 2) – Flash-loan-assisted withdraw and profit realization**
   - **Chain / hash**: BSC 56, `0x80dd9362d211722b578af72d551f0a68e0dc1b1e077805353970b2f65e793927`.
   - **Type**: Adversary-crafted.
   - **Inclusion feasibility**: The same unprivileged EOA calls orchestrator `0xaa0cee…` with selector `0x1dbc4eeb` and zero native value. The orchestrator `delegatecall`s helper `0xaae196b6e3f3ee34405e857e7bfb05d74c5cf775`, which:
     - Invokes `withdraw()` on proxy `0xc8b9817e…` (implementation `0x7ee7…`).
     - Obtains a 30,000,000 USDT flash loan from PancakeV3Pool `0x36696169c63e42cd08ce11f5deebbcebae652050`.
     - Executes AST/USDT and USDT/WBNB trades via PancakeRouter `0x10ed43c718714eb63d5aa57b78b54704e256024e`.
   - **Behaviour**:
     - Temporarily pushes large USDT volume through AST/USDT pair `0x5ffe…` and USDT/WBNB pair `0x16b9…`.
     - Repays the flash loan.
     - Leaves the EOA with a much larger BNB balance than before the two-tx sequence.

_Snippet: Withdraw/flash transaction trace showing withdraw(), flash loan, and swaps_

```bash
# From cast run -vvvvv trace for tx 0x80dd9362...
0xAa0cee27...::1dbc4eeb(...)
  ├─ 0xaaE196b6...::1dbc4eeb(...) [delegatecall]
  │   ├─ 0xc8B9817e...::withdraw()
  │   │   ├─ 0x7ee798bd...::withdraw() [delegatecall]
  │   │   │   ├─ AST::transfer(0xCef74647..., 141796424043937555)
  │   │   │   ├─ AST::transfer(0xAa0cee27..., 6948024778152940205)
  │   │   │   ├─ emit WithdrawEvent(...)
  │   ├─ PancakeV3Pool::flash(..., 30000000000000000000000000, 0, ...)
  │   │   ├─ BEP20USDT::transfer(0xAa0cee27..., 30000000000000000000000000)
  │   │   ├─ PancakeRouter::swapExactTokensForTokensSupportingFeeOnTransferTokens(...)
```

_Caption: Seed transaction trace showing the orchestrated `withdraw()` call, 30M USDT flash loan, and downstream AST/USDT and USDT/WBNB swaps._

#### 3.3 Exploit Predicate: Profit in BNB

- **Predicate type**: `profit`.
- **Reference asset**: BNB.
- **Adversary address**: EOA `0x56f77adc522bffebb3af0669564122933ab5ea4f`.

From balance diffs across the deposit and withdraw/flash transactions:

- **Before** (deposit tx `0x78867f71…b10f62`):  
  The adversary sends approximately 9.05598728 BNB into WBNB at deposit time.
  - Native delta for EOA:

```json
{
  "txhash": "0x78867f7126ccbb81dfc7351221b6ab571a7899332cb1c72adfa4767822b10f62",
  "native_balance_deltas": [
    {
      "address": "0x56f77adc522bffebb3af0669564122933ab5ea4f",
      "delta_wei": "-9055987280000000000"
    }
  ]
}
```

- **After** (withdraw/flash tx `0x80dd9362…3927`):  
  The adversary receives approximately 94.198970316293948336 BNB via WBNB/BNB.

```json
{
  "txhash": "0x80dd9362d211722b578af72d551f0a68e0dc1b1e077805353970b2f65e793927",
  "native_balance_deltas": [
    {
      "address": "0x56f77adc522bffebb3af0669564122933ab5ea4f",
      "delta_wei": "94198970316293948336"
    }
  ]
}
```

- **Computed values in reference asset (BNB)**:
  - `value_before_in_reference_asset` ≈ **9.05598728** BNB.
  - `value_after_in_reference_asset` ≈ **94.198970316293948336** BNB.
  - `value_delta_in_reference_asset` ≈ **85.142983036293948336** BNB.
  - `fees_paid_in_reference_asset`: not explicitly converted, but gas costs are small compared to the ~85.14 BNB gross delta, so net profit is strictly positive.

Overall, the adversary achieves a large, unprivileged BNB profit from the two-transaction sequence, satisfying the ACT profit predicate.

### 4. Vulnerability & Root Cause Analysis

#### 4.1 High-Level Vulnerability

The upgraded staking implementation at `0x7ee7…` relies on AST’s `pool_usdt`-based, path-dependent transfer rules and AST/USDT pool reserves to account for user deposits and withdrawals. It does not enforce a sound invariant that ties user-facing claims to verifiable pool balances and does not harden against flash-loan-driven reserve distortion.

#### 4.2 Detailed Root Cause Mechanism

Traces and prestateTracer diffs for the deposit tx `0x78867f71…b10f62` and the withdraw/flash tx `0x80dd9362…3927` show the following:

- During **deposit**:
  - The orchestrator swaps ~9 BNB to USDT via USDT/WBNB pair `0x16b9…`.
  - It moves 1,000,000 USDT into proxy `0xc8b9817e…`.
  - The staking implementation sends 500,000 USDT into the AST/USDT pair `0x5ffe…`, where it mints and then burns a very large AST position.
  - AST’s `pool_usdt` and the implementation’s `storage_map_*` fields are updated in a way that ties the adversary’s staking position to AST/USDT pool state and AST’s internal accounting.

- During **withdraw/flash**:
  - The orchestrator calls helper `0xaae196b6…`, which `delegatecall`s into `withdraw()` on `0x7ee7…`.
  - A 30,000,000 USDT flash loan from PancakeV3Pool `0x3669…` is taken.
  - Large USDT volume is pushed through AST/USDT and USDT/WBNB, causing extreme but short-lived changes in AST total supply, `pool_usdt`, and AST/USDT reserves.
  - While this manipulated state is in effect, the implementation computes the adversary’s withdrawal proceeds, effectively applying an overly generous exchange rate for the adversary’s position.
  - After swaps and loan repayment, the EOA exits with ~94.2 BNB, far exceeding its initial ~9 BNB capital, even though the protocol’s overall reserves are not increased.

No access-control or permissioning bypass is involved. The vulnerability is purely economic: core staking and reward logic are tightly coupled to a complex, non-standard token (AST) and to flash-loan-sensitive AMM state, without invariant checks or caps on extractable value per withdraw.

_Snippet: Deposit transaction balance diffs highlighting USDT and AST/USDT flows_

```json
{
  "txhash": "0x78867f7126ccbb81dfc7351221b6ab571a7899332cb1c72adfa4767822b10f62",
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x5ffec8523a42be78b1ad1244fa526f14b64ba47a",
      "delta": "3000000000000000000000",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0xc10e0319337c7f83342424df72e73a70a29579b2",
      "holder": "0x5ffec8523a42be78b1ad1244fa526f14b64ba47a",
      "delta": "-113819659148178484366",
      "contract_name": "AST"
    }
  ]
}
```

_Caption: Deposit balance diffs showing substantial USDT movement into the AST/USDT pair and a large AST delta, consistent with the priming phase of the exploit._

#### 4.3 Vulnerable Components

- **Staking proxy and implementation**
  - BSC 56: `0xc8b9817eb65b7d7e85325f23a60d5839d14f9ce4` (ERC1967Proxy).
  - Implementation: `0x7ee798bd2b3aa93828ca1c38f32b2fd84c050d2d`.
  - Vulnerable functions: `deposit(uint256)` and `withdraw()`, callable via orchestrator `0xaa0cee…`.

- **AST token**
  - BSC 56: `0xc10e0319337c7f83342424df72e73a70a29579b2`.
  - Critical behaviour: `pool_usdt` and `lastBalance`-dependent transfer logic, including burns and fee-like transfers tied to the AST/USDT pair.

- **Liquidity pools**
  - AST/USDT pair: `0x5ffec8523a42be78b1ad1244fa526f14b64ba47a`.
  - USDT/WBNB pair: `0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae`.
  - These pools provide the liquidity surface and price signals that the staking implementation implicitly relies on.

#### 4.4 Exploit Preconditions

The exploit requires:

- An adversary able to deploy an orchestrator, fund it via a deposit into proxy `0xc8b9817e…`, and access `deposit()` and `withdraw()` on implementation `0x7ee7…` permissionlessly.
- ASTToken retaining its non-standard, `pool_usdt`-based transfer logic where transfers involving the AST/USDT pair and whitelisted addresses can trigger large burns and fee-like behaviour.
- The staking implementation using AST/USDT pool state and AST’s internal variables to compute user balances and withdrawal proceeds, without enforcing an invariant that bounds the value a single user can extract relative to their economic contribution.
- Availability of flash loans of at least 30M USDT against the relevant liquidity, allowing short-lived but extreme reserve imbalances exactly during `withdraw()`.

#### 4.5 Violated Security Principles

- Failure to maintain a robust accounting invariant tying user claims and rewards to verifiable on-chain reserves when integrating with non-standard tokens and AMM pools.
- Failure to design staking and reward logic to be flash-loan-resilient, despite relying on AMM reserves and token-side `pool_usdt` state that can be manipulated within a single transaction.
- Over-reliance on complex external token semantics (AST’s `pool_usdt`, `lastBalance`) within core protocol accounting without isolating or bounding their effects.

### 5. Adversary Flow Analysis

#### 5.1 Strategy Summary

The adversary deploys an orchestrator contract, primes a position in the AST-based staking proxy with a ~9 BNB deposit, and then executes a flash-loan-assisted withdraw that manipulates AST/USDT reserves and AST’s internal accounting so that `withdraw()` returns far more BNB than the original capital. The strategy unfolds over a short sequence of standard EOA transactions, each feasible for any unprivileged attacker.

#### 5.2 Adversary-Related Accounts

- **Adversary cluster**
  - `0x56f77adc522bffebb3af0669564122933ab5ea4f` (EOA)  
    - Sender of deposit tx `0x78867f71…b10f62` and withdraw/flash tx `0x80dd9362…3927`.  
    - Deployer of orchestrator `0xaa0cee…`.  
    - Receives the final BNB profit.
  - `0xaa0cee271f7c1a14cd0777283cb5741e46a2c732` (contract)  
    - Adversary-deployed orchestrator created by the EOA in tx `0x6d81a5840e347fded980b41e0ab1f9973c91dfd4f32f2ecfcf25700b9299ca0b`.  
    - Used exclusively by that EOA to call `deposit()` and `withdraw()` on proxy `0xc8b9817e…` via `delegatecall`.
  - `0xaae196b6e3f3ee34405e857e7bfb05d74c5cf775` (contract)  
    - Delegatecall implementation used by orchestrator `0xaa0cee…` to route deposit and withdraw calls into staking proxy `0xc8b9817e…` and to coordinate flash-loan operations.
  - `0xc8b9817eb65b7d7e85325f23a60d5839d14f9ce4` (contract)  
    - Staking proxy whose `deposit()` and `withdraw()` logic (implemented in `0x7ee7…`) is the primary locus of the vulnerability and the channel through which the adversary acquires and later exits their position.

- **Victim candidates**
  - AST staking users interacting with proxy `0xc8b9817e…` on BSC 56 (address `0xc8b9817e…`, `is_verified = "unknown"`).  
  - AST/USDT LPs at Pancake pair `0x5ffec8523a42be78b1ad1244fa526f14b64ba47a` on BSC 56 (`is_verified = "unknown"`).  

These cohorts are the economically plausible bearers of loss given the adversary’s profit and the way value flows through the staking proxy and AST/USDT pool, even though this report does not attempt to list specific victim addresses exhaustively.

#### 5.3 Lifecycle Stages

1. **Orchestrator deployment and upgrade context**
   - **Transactions**:
     - Proxy upgrade: BSC 56, tx `0x96e9c3fcdcb80ded00d6db4dd272d496177ce42831f576ef3f9d76341e6d35ec` at block 45,961,999 (`mechanism = other`).
     - Orchestrator deployment: BSC 56, tx `0x6d81a5840e347fded980b41e0ab1f9973c91dfd4f32f2ecfcf25700b9299ca0b` at block 45,964,336 (`mechanism = other`).
   - **Effect**:
     - Operator EOA `0x95be88…` upgrades proxy `0xc8b9817e…` to implementation `0x7ee7…`.
     - Shortly thereafter, adversary EOA `0x56f7…` deploys orchestrator `0xaa0cee…` to mediate deposit and withdraw calls into the upgraded proxy.
   - **Evidence**:
     - Upgrade trace and prestateTracer diff for `0x96e9c3fc…35ec`.
     - Address txlist for `0x56f7…` around the deployment window.

2. **Adversary deposit and position priming**
   - **Transaction**:
     - BSC 56, tx `0x78867f7126ccbb81dfc7351221b6ab571a7899332cb1c72adfa4767822b10f62` at block 45,964,522 (`mechanism = transfer`).
   - **Effect**:
     - EOA `0x56f7…` sends ~9 BNB to orchestrator `0xaa0cee…`.
     - Orchestrator swaps this BNB to USDT via the USDT/WBNB pair `0x16b9…`.
     - 1,000,000 USDT is transferred into staking proxy `0xc8b9817e…`.
     - `deposit(uint256)` establishes an AST/USDT-linked position and updates implementation `0x7ee7…` storage (`storage_map_*`) and `AST.pool_usdt`.
   - **Evidence**:
     - `trace.cast.log` for tx `0x78867f71…b10f62`.  
     - `state_diff_prestateTracer.json` and `balance_diff_prestate.json` for the same tx.

3. **Flash-loan-assisted withdraw and profit realization**
   - **Transaction**:
     - BSC 56, tx `0x80dd9362d211722b578af72d551f0a68e0dc1b1e077805353970b2f65e793927` at block 45,964,640 (`mechanism = flashloan`).
   - **Effect**:
     - Via orchestrator `0xaa0cee…`, the adversary invokes `withdraw()` on proxy `0xc8b9817e…`.
     - A 30M USDT flash loan from PancakeV3Pool `0x3669…` is obtained.
     - USDT is pushed through AST/USDT pair `0x5ffe…` and USDT/WBNB pair `0x16b9…`, inducing extreme but temporary reserve and `pool_usdt` changes.
     - Implementation `0x7ee7…` credits and returns value based on this manipulated state, causing the EOA to exit with ~94.2 BNB.
     - The protocol’s aggregate reserves and other participants’ positions absorb the corresponding economic loss.
   - **Evidence**:
     - Seed trace and balance diff for `0x80dd9362…3927`.  
     - `state_diff_prestateTracer.json` for the same tx, confirming the flash loan, AMM trades, and final balances.

### 6. Impact & Losses

#### 6.1 Aggregate Loss Overview

- **Reference asset**: BNB.  
- **Total adversary profit**: approximately **85.142983036293948336 BNB**.

This figure is derived directly from native balance diffs across the adversary’s deposit and withdraw/flash transactions:

- The adversary’s BNB-equivalent outflow at deposit time is ~9.05598728 BNB.
- The adversary’s BNB inflow at withdraw time is ~94.198970316293948336 BNB.
- The net BNB profit is thus ~85.142983036293948336 BNB, strictly positive after accounting for reasonable gas fee bounds.

#### 6.2 Impact Description

The adversary-controlled EOA’s BNB holdings increase by approximately 85.142983036293948336 BNB net of principal deployed, after routing value through USDT and AST/USDT liquidity. Because the protocol’s overall reserves do not increase, this profit necessarily corresponds to value extracted from other on-chain participants under the staking protocol’s accounting and AST/USDT pool mechanics.

The main impacted cohorts are:

- **AST staking users** interacting with proxy `0xc8b9817e…`, whose positions and rewards are accounted for using the same AST/USDT-aware logic that is exploited during the withdraw/flash sequence.
- **AST/USDT LPs** at Pancake pair `0x5ffec8523a42be78b1ad1244fa526f14b64ba47a`, whose pool shares are subject to the extreme, flash-loan-induced reserve distortions used to support the adversary’s profit.

This report focuses on the aggregate transfer of value (as measured in BNB) rather than enumerating individual victim addresses, but the underlying traces and diffs support that the adversary’s BNB gain is offset by losses to these cohorts.

### 7. References

Key supporting artifacts for this analysis include:

1. **Seed withdraw/flash transaction trace** – tx `0x80dd9362d211722b578af72d551f0a68e0dc1b1e077805353970b2f65e793927` (BSC 56).  
   - Source: `cast run -vvvvv` trace under the seed artifacts.  
   - Demonstrates the orchestrated `withdraw()` call, 30M USDT flash loan, AST/USDT and USDT/WBNB swaps, and final state changes.

2. **Adversary deposit transaction trace and diffs** – tx `0x78867f7126ccbb81dfc7351221b6ab571a7899332cb1c72adfa4767822b10f62` (BSC 56).  
   - Includes full execution trace plus prestateTracer state and balance diffs.  
   - Shows the ~9 BNB input, USDT acquisition, and seeding of the staking position in proxy `0xc8b9817e…`.

3. **Proxy upgrade transaction trace and diffs** – tx `0x96e9c3fcdcb80ded00d6db4dd272d496177ce42831f576ef3f9d76341e6d35ec` (BSC 56).  
   - Confirms the upgrade of proxy `0xc8b9817e…` to implementation `0x7ee7…` shortly before the adversary activity.

4. **ASTToken.sol verified source** – contract `0xc10e0319337c7f83342424df72e73a70a29579b2` on BSC 56.  
   - Provides the `pool_usdt` and `lastBalance` logic that explains AST’s path-dependent transfer behaviour.

5. **Root cause analyzer iteration 5 analysis** – `current_analysis_result.json` for iter_5.  
   - Consolidates evidence from multiple traces, balance diffs, and contract analyses, and supports the ACT classification and root-cause narrative summarized in this report.

### 8. All Relevant Transactions

For completeness, the following transactions are considered relevant to this incident:

- BSC 56, tx `0x6d81a5840e347fded980b41e0ab1f9973c91dfd4f32f2ecfcf25700b9299ca0b` – orchestrator deployment (`role = related`).  
- BSC 56, tx `0x96e9c3fcdcb80ded00d6db4dd272d496177ce42831f576ef3f9d76341e6d35ec` – proxy upgrade to implementation `0x7ee7…` (`role = related`).  
- BSC 56, tx `0x78867f7126ccbb81dfc7351221b6ab571a7899332cb1c72adfa4767822b10f62` – adversary deposit and position priming (`role = adversary-crafted`).  
- BSC 56, tx `0x80dd9362d211722b578af72d551f0a68e0dc1b1e077805353970b2f65e793927` – seed withdraw/flash transaction realizing the adversary’s profit (`role = seed`).

