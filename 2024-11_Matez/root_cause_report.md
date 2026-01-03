# MatezStakingProgram MATEZ Reserve Drain via uint128 Downcast

## Incident Overview & TL;DR

On BSC (chainid 56), an unprivileged attacker controlling EOA `0xd4f04374385341da7333b82b230cd223143c4d62` and orchestrator contract `0x0ad02ce1b8eb978fd8dc4abec5bf92dfa81ed705` executed two adversary-crafted transactions that drained a total of `134.681438633400217641` MATEZ from the `MatezStakingProgram` contract `0x326fb70ef9e70f8f4c38cfbfaf39f960a5c252fa` without depositing any MATEZ into it.  
The root cause is a protocol-level bug in `MatezStakingProgram`: stake and reward amounts are downcast from `uint256` to `uint128` before being priced via a TWAP oracle, while the full `uint256` values are recorded in internal accounting. This allows the attacker to create zero-deposit positions with huge recorded amounts and later claim rewards against the contract’s real MATEZ reserves.

Metadata:
- Protocol: `Matez / MatezStakingProgram`
- Root cause category: `protocol_bug`
- ACT framing: `is_act = true` with an explicit opportunity against the staking contract’s MATEZ reserve.

## Key Background

The key components and environment are:
- Matez is a BEP20-style token on BSC (`0x010c0d77055a26d09bb474ef8d81975f55bd8fc9`) with standard `transfer` and `transferFrom` semantics.
- `MatezStakingProgram` (`0x326fb70ef9e70f8f4c38cfbfaf39f960a5c252fa`) is a staking contract that uses a Uniswap V3–style TWAP oracle to convert between `token0` and `token1`, tracking per-user orders, `selfInvest`, team/referral metrics, and rewards.
- The orchestrator contract (`0x0ad02ce1b8eb978fd8dc4abec5bf92dfa81ed705`) gates its key functions with `require(tx.origin == owner)`, so any unprivileged EOA that controls `owner` can deploy helper contracts and route calls into `MatezStakingProgram`.
- All relevant activity occurs on BSC chainid 56 and is fully observable through the provided transaction metadata, traces, and balance diffs.

ACT pre-state:
- Block height `B`: `44222632`.
- Pre-state `σ_B`: publicly reconstructible BSC state at or before block 44222632, containing:
  - Matez token contract `0x010c0d77055a26d09bb474ef8d81975f55bd8fc9`.
  - `MatezStakingProgram` contract `0x326fb70ef9e70f8f4c38cfbfaf39f960a5c252fa`.
  - Orchestrator contract `0x0ad02ce1b8eb978fd8dc4abec5bf92dfa81ed705`.
  - Attacker EOA `0xd4f04374385341da7333b82b230cd223143c4d62` with sufficient BNB to pay gas.
- Evidence used to define this pre-state:
  - Seed transaction metadata and trace for the profit transaction.
  - Verified source for `MatezStakingProgram`.
  - Verified source for the Matez token.
  - Decompiled source for the orchestrator contract.

## ACT Opportunity and Exploit Predicate

### Transaction sequence b (adversary-crafted)

From pre-state `σ_B`, an unprivileged adversary controlling EOA `0xd4f0…` can submit the following transaction sequence on BSC:

1. **Tx 0x20a49d36… (index 1, chainid 56, type = adversary-crafted)**  
   - EOA `0xd4f0…` directly signs and sends a 0-value transaction with selector `0x614c8325` to orchestrator `0x0ad0…`, with sufficient gas and no special permissions beyond normal BSC rules.  
   - The orchestrator deploys helper contracts, each of which:
     - Registers with `MatezStakingProgram` (`register(router_or_helper)`).
     - Calls `stake(2^128)` on `MatezStakingProgram`.  
   - The orchestrator then routes reward-claim flows via a DEX router so that `MatezStakingProgram` transfers `67189210529208867041` MATEZ to `0x0ad0…`, while all associated `depositToken.transferFrom` calls move 0 MATEZ into the staking contract.

2. **Tx 0x840b0dc6… (index 2, chainid 56, type = adversary-crafted)**  
   - The same EOA `0xd4f0…` sends a second `0x614c8325` transaction to `0x0ad0…`, again 0-value with standard gas usage.  
   - The call pattern is repeated: helper deployments, `register+stake(2^128)` calls, and router-driven reward claims.  
   - This drains an additional `67492228104191350600` MATEZ from `MatezStakingProgram` to `0x0ad0…`, again without any MATEZ deposits from the helpers; the EOA only pays BNB gas.

These two transactions are both included in block 44222632 and are the complete adversary-crafted sequence b for the exploit.

### Non-monetary exploit predicate

- **Type**: `non-monetary` (reserve safety violation).
- **Profit view (reference-asset-agnostic)**:
  - Reference asset: `other` (MATEZ vs BNB or USD not normalized).
  - Adversary address: orchestrator `0x0ad0…`.
  - `fees_paid_in_reference_asset`: `unknown` (gas costs measured in BNB, not converted).
  - `value_before_in_reference_asset`, `value_after_in_reference_asset`, `value_delta_in_reference_asset`: all recorded as `unknown`, because cross-asset valuation is intentionally left unspecified.
  - Valuation notes: across the two exploit transactions, the attacker pays a total of `224239652000000000` wei (~`0.224239652` BNB) in gas from EOA `0xd4f0…`, and receives `134681438633400217641` units (`134.681438633400217641` MATEZ assuming 18 decimals) of MATEZ at orchestrator `0x0ad0…`. A full cross-asset valuation of MATEZ vs BNB or USD is not required to establish ACT existence and is intentionally omitted.

#### Reserve-safety oracle

- **Oracle name**: `MatezStakingProgram MATEZ-reserve safety invariant`.
- **Oracle definition**:  
  Let `O(σ_B, σ') = 1` iff, relative to pre-state `σ_B` at or before block 44222632, `MatezStakingProgram` contract `0x326f…` does **not** transfer out more MATEZ than has been legitimately deposited into it via `depositToken.transferFrom` calls recorded in its staking accounting.  
  `O` is 0 when the contract’s on-chain MATEZ balance decreases by more than the sum of all recorded deposits (i.e., the reserve is drained without corresponding deposits).
- **Oracle evidence**:  
  Traces and balance diffs for txs `0x20a49d36…` and `0x840b0dc6…` show that:
  - Every `depositToken.transferFrom` in `stake()` transfers **0 MATEZ** due to `uint128(amnt)` truncation, while the contract records full 256-bit order amounts.
  - Across the two transactions, `MatezStakingProgram` transfers a total of `134681438633400217641` MATEZ to orchestrator `0x0ad0…`.  
  Therefore the post-state `σ'` violates the reserve-safety invariant; the ACT predicate is satisfied.

## Vulnerability & Root Cause Analysis

### High-level vulnerability

In both `stake()` and `claim()`, `MatezStakingProgram` downcasts user-supplied and accrued amounts from `uint256` to `uint128` before passing them to the TWAP oracle function `estimateAmountOut`. For sufficiently large 256-bit amounts (e.g., `2^128`), the `uint128` downcast wraps the value to zero, so the oracle quotes `amountIn = 0` and the actual ERC20 transfers move 0 tokens. At the same time, the full 256-bit amounts are stored in internal accounting fields (`selfInvest`, `orders[...].amount`, and reward-related variables), so later reward calculations treat them as extremely large deposits.

As a result, an attacker can:
- Stake a very large nominal amount (`2^128`) that is priced as 0, so no MATEZ is ever deposited.
- Record a huge positive position in internal state.
- Later call `claim()` to compute rewards based on that inflated recorded amount, again using `uint128` downcasts for pricing but moving real MATEZ from the contract’s reserves to the attacker.

### Code evidence: stake and claim downcasts

Verified `MatezStakingProgram` source for BSC contract `0x326f…` (stake path):

```solidity
// Verified MatezStakingProgram source (stake path)
function stake(uint256 amnt) public {
    require(users[msg.sender].id != 0, "Register Before Deposit!");

    users[msg.sender].invest_count++;
    address sponsor = users[msg.sender].sponsor;
    if (users[msg.sender].invest_count == 1) {
        users[sponsor].directs++;
        addteam(sponsor);
    }

    uint256 amntin = estimateAmountOut(address(token1), uint128(amnt), 1);
    depositToken.transferFrom(msg.sender, address(this), amntin);
    users[msg.sender].selfInvest += amnt;

    uint40 o_id = users[msg.sender].invest_count;
    orders[msg.sender][o_id].amount = amnt;
    orders[msg.sender][o_id].timestamp = uint40(block.timestamp);
    orders[msg.sender][o_id].last_claim = uint40(block.timestamp);
    orders[msg.sender][o_id].status = true;
}
```

Verified `MatezStakingProgram` source for BSC contract `0x326f…` (claim path):

```solidity
// Verified MatezStakingProgram source (claim path)
function claim(uint40 typ, uint40 pkgid, uint256 amount) public {
    if (typ == 2) {
        // ...
        uint256 amntout = estimateAmountOut(address(token1), uint128(amount), 1);
        depositToken.transfer(msg.sender, amntout);
        // ...
    }

    if (typ == 1) {
        // ...
        uint256 pendingamnt = (perday * ttldays) - orders[msg.sender][pkgid].claimed;
        // ...
        uint256 amntout = estimateAmountOut(address(token1), uint128(pendingamnt), 1);
        depositToken.transfer(msg.sender, amntout);
        // ...
    }

    if (typ == 3) {
        // ...
        uint256 amntin = estimateAmountOut(address(token1), uint128(reward[pkgid]), 1);
        depositToken.transfer(msg.sender, amntin);
        // ...
    }
}
```

These snippets show that:
- User-controlled `amnt`, `pendingamnt`, and `reward[pkgid]` are downcast to `uint128` before price conversion.
- Internal accounting (e.g., `selfInvest`, `orders[...].amount`) tracks the original 256-bit values.

### Concrete exploit behavior

The root-cause JSON summarizes the exploit as follows:
- `stake(uint256 amnt)` computes `amntin = estimateAmountOut(address(token1), uint128(amnt), 1)` and calls `depositToken.transferFrom(msg.sender, address(this), amntin)`, while recording `amnt` in `users[msg.sender].selfInvest` and `orders[msg.sender][o_id].amount`.
- For very large `amnt` values such as `2^128`, `uint128(amnt)` wraps to `0`, so `amntin = 0` and `transferFrom` moves 0 tokens. The contract nevertheless records a huge positive deposit amount.
- Subsequent `claim(typ=1 or typ=3)` calls compute payout amounts based on these inflated recorded values, again using `uint128` downcasts inside `estimateAmountOut` before calling `depositToken.transfer`.
- Exploit traces confirm that **all** `depositToken.transferFrom` calls in the two exploit transactions transfer 0 MATEZ, while `MatezStakingProgram` later transfers large amounts of MATEZ out to the attacker cluster.

### Exploit conditions

The exploit is possible whenever all of the following hold:
- The attacker can call `stake()` with `amnt` values at or above `2^128`, so that `uint128(amnt)` truncation drives `amntin` to zero while internal accounting records the full 256-bit value.
- The attacker (or an orchestrated router) can later trigger `claim()` calls on those inflated positions, so `MatezStakingProgram` transfers MATEZ based on the recorded amounts despite having received no MATEZ deposits.
- `MatezStakingProgram` holds a non-trivial MATEZ reserve at `σ_B` that can be drained via such claims.

### Security principles violated

This bug violates multiple core security principles:
- **Conservation of value**: the contract allows withdrawals that exceed actual deposited assets.
- **Safe numeric casting**: lossy downcasts (`uint256` → `uint128`) are applied directly to user-controlled values in core accounting and payout paths.
- **Invariant-based design**: internal accounting for user deposits is not tied to actual ERC20 transfers (i.e., recorded deposits can diverge from token balances).

## Adversary Flow Analysis

### Strategy summary

The adversary executes a two-step orchestrated exploit on BSC:
- An unprivileged EOA `0xd4f0…` controls orchestrator contract `0x0ad0…` via `tx.origin == owner` checks.
- The orchestrator repeatedly deploys short-lived helper contracts that:
  - Register themselves with `MatezStakingProgram`.
  - Call `stake(2^128)` to create huge recorded positions with zero actual deposits.
- A DEX router interacts with `MatezStakingProgram::claim` on those positions, causing the staking contract to transfer real MATEZ from its reserves to the orchestrator, which ultimately benefits the attacker-controlled cluster.

### Adversary-related accounts

Adversary cluster:
- `0xd4f04374385341da7333b82b230cd223143c4d62` (BSC, EOA):
  - Sender of both adversary-crafted `0x614c8325` transactions.
  - Identified as `owner` of orchestrator `0x0ad0…` via `tx.origin == owner` checks in the decompiled code.
- `0x0ad02ce1b8eb978fd8dc4abec5bf92dfa81ed705` (BSC, contract):
  - Orchestrator that receives the attacker-crafted calls, deploys helper contracts, and routes `register/stake/claim` flows into `MatezStakingProgram`.
- Ephemeral helper contracts (multiple short-lived addresses):
  - Deployed by `0x0ad0…` in each exploit transaction.
  - Call `register` and `stake(2^128)` on `MatezStakingProgram` and participate in the router flows; they are fully controlled by `0x0ad0…`.

Victim:
- `MatezStakingProgram` (`0x326fb70ef9e70f8f4c38cfbfaf39f960a5c252fa`, BSC, verified source).

Historical code evidence:
- Address `0x80d93e9451a6830e9a531f15cca42cb0357d511f` was previously considered as a possible intermediate contract. Historical code queries at block `0x2a2c8a8` (decimal 44222632) return `0x` (no bytecode). It therefore behaves as a non-contract (EOA-like) address at the incident height and does not hide additional attacker logic.

### Orchestrator ownership and gating

Decompiled orchestrator code for BSC contract `0x0ad0…` (selector `0x614c8325`), showing `tx.origin` gating:

```solidity
// Decompiled orchestrator contract (selector 0x614c8325)
function Unresolved_614c8325(address arg0, uint256 arg1, uint256 arg2, uint256 arg3, uint256 arg4) public payable {
    // ...
    require(address(tx.origin) == address(owner / 0x01), "owner");
    // ...
}
```

This confirms that:
- The orchestrator is fully controlled by whichever EOA is stored as `owner`.
- No protocol-admin privileges are required; any unprivileged EOA can act as the attacker if they control `owner`.

### Lifecycle stages and on-chain evidence

Stage 1 — Adversary preparation and contract control:
- Transaction: `0x20a49d36a7cccc66f19ed0ad4883ace9cdbac486172000cc9043ee3c59e273c9` (BSC, block 44222632).
- Behavior:
  - EOA `0xd4f0…` calls orchestrator `0x0ad0…` with selector `0x614c8325`.
  - The orchestrator demonstrates its ability to deploy helpers and execute the `register + stake(2^128)` pattern against `MatezStakingProgram`.
- Evidence:
  - Decompiled orchestrator code (ownership gating and helper usage).
  - Detailed `cast run -vvvvv` trace for tx `0x20a49d36…`, showing helper deployments and calls into `MatezStakingProgram`.

Stage 2 — Zero-deposit staking and order inflation:
- Transactions: `0x20a49d36…` and `0x840b0dc6…` (both at block 44222632).
- Behavior:
  - In both transactions, helper contracts call `MatezStakingProgram::stake(2^128)`.
  - Due to the `uint128` downcast inside `stake`, `estimateAmountOut` computes `amountIn = 0`, so `depositToken.transferFrom` moves 0 MATEZ in each call.
  - The contract nevertheless records extremely large order amounts and `selfInvest` values for the helper addresses.
- Evidence:
  - Verified `MatezStakingProgram` source (see stake snippet above).
  - Traces for both transactions, showing `stake(2^128)` calls and `transferFrom(..., 0)` events.

Stage 3 — Reward extraction and reserve drain:
- Transactions: `0x20a49d36…` and `0x840b0dc6…` (same block).
- Behavior:
  - The Pancake router interacts with `MatezStakingProgram::claim` on the same inflated positions.
  - `MatezStakingProgram` transfers `67189210529208867041` MATEZ in the first transaction and `67492228104191350600` MATEZ in the second transaction from its reserves to orchestrator `0x0ad0…`.
  - Across the two txs, `134681438633400217641` MATEZ is drained, while the attacker only pays BNB gas.

Prestate tracer balance diff for earlier orchestrator tx `0x20a49d36…` (summary excerpt):

```json
{
  "chainid": 56,
  "txhash": "0x20a49d36a7cccc66f19ed0ad4883ace9cdbac486172000cc9043ee3c59e273c9",
  "native_balance_deltas": [
    {
      "address": "0xd4f04374385341da7333b82b230cd223143c4d62",
      "before_wei": "2496167013474399383",
      "after_wei": "2384044037474399383",
      "delta_wei": "-112122976000000000"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0x010c0d77055a26d09bb474ef8d81975f55bd8fc9",
      "holder": "0x326fb70ef9e70f8f4c38cfbfaf39f960a5c252fa",
      "before": "7662750871540920462148",
      "after": "7595561661011711595107",
      "delta": "-67189210529208867041"
    },
    {
      "token": "0x010c0d77055a26d09bb474ef8d81975f55bd8fc9",
      "holder": "0x0ad02ce1b8eb978fd8dc4abec5bf92dfa81ed705",
      "delta": "67189210529208867041"
    }
  ]
}
```

Caption: prestate-tracer balance diff for tx `0x20a49d36…` on BSC, showing BNB gas paid by `0xd4f0…`, a `-67189210529208867041` MATEZ delta at `MatezStakingProgram`, and a matching positive delta at orchestrator `0x0ad0…`. An analogous diff for tx `0x840b0dc6…` shows the second half of the MATEZ drain.

### All relevant transactions

The root-cause JSON records all relevant transactions as:
- `0x20a49d36a7cccc66f19ed0ad4883ace9cdbac486172000cc9043ee3c59e273c9` (BSC, role = adversary-crafted).
- `0x840b0dc64dbb91e8aba524f67189f639a0bc94ee9256c57d79083bb3fd46ec91` (BSC, role = adversary-crafted).

These exactly match the ACT sequence b and the lifecycle stages above.

## Impact & Losses

Quantitative token impact:
- Total MATEZ lost by `MatezStakingProgram`: `134.681438633400217641` MATEZ (sum of:
  - `67.189210529208867041` MATEZ in tx `0x20a49d36…`.
  - `67.492228104191350600` MATEZ in tx `0x840b0dc6…`).
- Total gas cost to attacker EOA `0xd4f0…`: `224239652000000000` wei (~`0.224239652` BNB) across both transactions.
- No other ERC20 balances change in the exploit transactions; the immediate token-level impact is confined to:
  - The MATEZ reserve held by `MatezStakingProgram` (loss).
  - Orchestrator `0x0ad0…` (gain).

Portfolio view:
- Because cross-asset valuation (MATEZ vs BNB or USD) is intentionally left unspecified, the analysis does **not** attempt to compute an exact profit in a single reference asset.
- From an ACT perspective, it is sufficient that:
  - `MatezStakingProgram` loses a large quantity of its reserve token.
  - The adversary-controlled orchestrator gains the same quantity.
  - These flows occur with zero MATEZ deposits from the adversary cluster.

## References

The root-cause JSON references the following primary artifacts:
- **[1] Seed tx metadata and trace for `0x840b0d…`**  
  Original exploit transaction metadata, trace, and balance diff for the seed profit tx on BSC.
- **[2] Balance diffs for exploit txs**  
  Extended prestate-tracer balance diffs for both exploit transactions, used to quantify BNB gas and MATEZ deltas.
- **[3] MatezStakingProgram verified source**  
  Full verified Solidity source for `MatezStakingProgram` (`0x326f…`), including the `stake` and `claim` implementations shown above.
- **[4] Matez token verified source**  
  Verified Solidity source for the Matez BEP20 token (`0x010c0d77…`), confirming standard ERC20-style semantics and no non-standard transfer side effects.
- **[5] Orchestrator 0x0ad0… decompiled code**  
  Decompiled Solidity-like view of orchestrator `0x0ad0…`, showing function selectors `0x614c8325` and `0x5fd012e4` and the `tx.origin == owner` gating that places control in the attacker’s EOA.

Together, these artifacts underpin the deterministic conclusion that a `uint128` downcast bug in `MatezStakingProgram` allows an unprivileged adversary-controlled cluster to drain `134.681438633400217641` MATEZ from the contract’s reserves via two adversary-crafted transactions at block 44222632, with no corresponding MATEZ deposits.

