## 1. Incident Overview TL;DR

On BSC (chainid 56), EOA `0x3fee6d8aaea76d06cf1ebeaf6b186af215f14088` deployed and configured an owner-only router/holder contract `0xe82Fc275B0e3573115eaDCa465f85c4F96A6c631` that integrates with a BorrowerOperationsV6 / TokenHolder stack and WBNB (`0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`).  
Across a four-transaction sequence (deploy, configure, leveraged operation, withdraw), this owner-controlled stack generated a net gain of **19.2 WBNB** for the owner EOA while paying only gas in native BNB.  
Selector-level analysis and traces show that all critical entrypoints on `0xe82F...` are strictly owner-gated with storage-configured router, token, and beneficiary addresses, so **no anyone-can-take (ACT) opportunity exists**: an unprivileged adversary cannot reproduce this flow.  
No protocol or user losses occurred; the observed behavior is consistent with an owner-operated leveraged router and fee routing design rather than an exploit of a vulnerable victim.

## 2. Key Background

The incident centers on a custom leveraged router and TokenHolder stack on BSC:

- **Router/holder contract**: `0xe82Fc275B0e3573115eaDCa465f85c4F96A6c631` (unverified runtime, analyzed via disassembly and selector analysis).  
- **Leveraged router**: `0x616B36265759517AF14300Ba1dD20762241a3828`.  
- **BorrowerOperationsV6 / TokenHolder contracts**:  
  - `0x8c7f34436C0037742AeCf047e06fD4B27Ad01117`  
  - `0x2EeD3DC9c5134C056825b12388Ee9Be04E522173`  
  - `0x3403f2Ba8aA448c208c2d1a41F2089c5a6f924e4`  
- **Fee address**: `0x8432CD30C4d72Ee793399E274C482223DCA2bF9e`.  
- **Reference asset**: WBNB (`0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`), whose verified implementation is a standard wrapped-BNB ERC‑20 with 1:1 redeemability.

The relevant pre-state `σ_B` is BSC at block **63856623**, where:

- The BorrowerOperationsV6 / TokenHolder / fee contracts are already deployed and funded per protocol design.  
- The owner EOA `0x3fee6...` holds **0 WBNB**.  
- Router/holder `0xe82F...` is **not yet deployed**.

From this pre-state, the owner executes:

1. A contract deployment tx creating `0xe82F...` and storing the owner and WBNB addresses in storage.  
2. A configuration tx that writes the leveraged router address into `0xe82F...`’s storage and sets routing parameters.  
3. A leveraged operation (seed tx) that pulls 20 WBNB from TokenHolder, pays 0.8 WBNB in fees, and leaves 19.2 WBNB on `0xe82F...`.  
4. A withdrawal tx that transfers the 19.2 WBNB from `0xe82F...` to the owner EOA.

## 3. Vulnerability Analysis

The key question is whether the observed profit arises from a **permissionless vulnerability** (an ACT opportunity) or from **intended, owner-controlled behavior**.

Evidence from on-chain traces, selector-level reverse engineering, and contract source confirms:

- `0xe82F...` enforces an **owner-only guard** on both the leveraged entrypoint (`0xe4c61b84`) and the withdrawal function `withdrawERC20(address)` (`0xf4f3b200`).  
- The leveraged entrypoint does **not** forward `msg.sender` as a beneficiary; instead, it loads router, token, and beneficiary addresses from **fixed storage slots** written during deploy/config txs.  
- The withdrawal function similarly loads the token and recipient from storage and sweeps the entire contract token balance to that recipient, again guarded by the owner-only check.

Selector analysis for `0xe4c61b84` and `0xf4f3b200` (from `artifacts/root_cause/data_collector/iter_3/contract/56/0xe82fc275b0e3573115eadca465f85c4f96a6c631/selector_analysis_e4c61b84_f4f3b200.json`) shows:

```json
{
  "functions": {
    "0xe4c61b84": {
      "summary": "Dispatcher ... enforces msg.sender == owner stored in storage slot 0 ... then invokes external router via selector 0xd54c73bf (sell(uint256,bytes,address,address,address,address))",
      "access_control": "Owner-only: CALLER is compared against an address extracted from storage slot 0; non-owners revert ..."
    },
    "0xf4f3b200": {
      "known_signatures": ["withdrawERC20(address)"],
      "summary": "Enforces msg.sender == owner, loads token from storage (slot 3), calls ERC20.balanceOf(address(this)), then ERC20.transfer to a beneficiary loaded from storage",
      "access_control": "Owner-only ... non-owners revert.",
      "token_transfer_logic": [
        "Loads token from storage and calls ERC20.balanceOf(address(this))",
        "Builds ERC20.transfer calldata with a recipient read from storage and transfers the full balance out"
      ]
    }
  }
}
```

This design is **not** an open faucet: an unprivileged EOA cannot call these functions successfully, nor can it redirect funds by supplying arbitrary recipients. Misconfiguration, if any, lies entirely in addresses controlled by the owner in storage, not in a missing access control that would create an ACT opportunity.

Given:

- Strict owner-only gating on the leveraged and withdraw entrypoints.  
- Storage-fixed router, token, and beneficiary addresses.  
- WBNB’s standard behavior and the BorrowerOperationsV6 / TokenHolder logic.  

There is **no exploitable vulnerability** available to arbitrary actors. The observed profit is an **owner-operated leveraged router outcome**, not an anyone-can-take exploit.

## 4. Detailed Root Cause Analysis

### 4.1 Classification and High-Level Root Cause

The root cause analysis concludes:

- **Incident type**: Non-ACT, owner-operated leveraged router on BSC.  
- **Root cause category**: `other` (no protocol invariant is violated; behavior is consistent with protocol design and owner authority).  
- **Profit mechanism**: A sequence of owner-only operations that moves WBNB from the TokenHolder ecosystem into the owner’s EOA, with fee routing to the designated fee address.

The seed transaction (`0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6`) is an owner-only leveraged operation via `0xe4c61b84` that:

- Calls into the leveraged router `0x616B...` and BorrowerOperationsV6 / TokenHolder contracts.  
- Draws **20 WBNB** from TokenHolder.  
- Pays **0.8 WBNB** to the fee address `0x8432...`.  
- Leaves **19.2 WBNB** on the router/holder `0xe82F...`.

The final withdrawal transaction (`0xa9f735df65cc26f2bda9a51ac46824fdb09dd5092d869c9690d7b273a51c164e`) then uses `withdrawERC20(WBNB)` on `0xe82F...` to transfer the entire **19.2 WBNB** balance from `0xe82F...` to the owner EOA.

### 4.2 On-Chain Trace Evidence

The seed tx trace (`artifacts/root_cause/seed/56/0xc291...64c6/trace.cast.log`) shows the leveraged flow:

```text
0xe82F...::e4c61b84(...)
  ├─ 0x616B...::sell(...)
  │   ├─ 0x8c7f...::sell(...) [delegatecall]
  │   │   ├─ 0xe82F...::privilegedLoan(WBNB, 20000000000000000000, ...)
  │   │   │   ├─ emit PrivilegedLoan(..., 20000000000000000000 [2e19])
  │   │   ├─ WBNB::transfer(0x8432..., 800000000000000000 [8e17])
  │   │   ├─ WBNB::transfer(0xe82F..., 800000000000000000 [8e17])
  │   │   ├─ WBNB::transfer(0xe82F..., 18400000000000000000 [1.84e19])
  │   │   └─ emit Sell(..., 20000000000000000000 [2e19], 20000000000000000000 [2e19])
  ├─ WBNB::balanceOf(0xe82F...) → 19200000000000000000 [1.92e19]
  └─ ← [Stop]
```

This trace establishes:

- 20 WBNB leave TokenHolder and are processed through the router and privilegedLoan logic.  
- 0.8 WBNB are transferred to the fee address `0x8432...`.  
- 19.2 WBNB accumulate on the router/holder `0xe82F...`.

The withdrawal tx trace (`artifacts/root_cause/data_collector/iter_3/tx/56/0xa9f7...64e/trace.cast.log`) shows the owner sweep:

```text
0xe82F...::withdrawERC20(WBNB)
  ├─ WBNB::balanceOf(0xe82F...) → 19200000000000000000 [1.92e19]
  ├─ WBNB::transfer(0x3fee6..., 19200000000000000000 [1.92e19])
  │   ├─ emit Transfer(src: 0xe82F..., dst: 0x3fee6..., wad: 1.92e19)
  └─ ← [Stop]
```

ERC‑20 balance diff artifacts (`artifacts/root_cause/data_collector/iter_3/tx/56/0xa9f7...64e/erc20_balance_diff_balanceOf.json`) confirm the 19.2 WBNB increase at the owner EOA and corresponding decrease at `0xe82F...`.

### 4.3 Balance and Profit Accounting

Using WBNB as the reference asset:

- **Before sequence** (σ_B at block 63856623):  
  - Owner EOA `0x3fee6...`: **0 WBNB**.  
  - Router/holder `0xe82F...`: not yet deployed.

- **After the four-tx sequence**:  
  - Owner EOA holds **19.2 WBNB** as per ERC‑20 balance diffs.  
  - Router/holder `0xe82F...` has **0 WBNB**.  
  - TokenHolder and fee address balances adjust in line with the 20 WBNB loan and 0.8 WBNB fee.

Gas costs are paid in native BNB; gas paid is not converted into WBNB units in this analysis, but native balance diffs show only small BNB losses consistent with gas expenditure (e.g., seed tx native delta `-0.0179888` BNB).

The success predicate from `root_cause.json`:

- `value_before_in_reference_asset`: `0` (WBNB)  
- `value_after_in_reference_asset`: `19.2` (WBNB)  
- `value_delta_in_reference_asset`: `19.2` (WBNB)

Given standard WBNB behavior (1:1 redeemability), this is a clear **net positive payoff** for the owner EOA, achieved via owner-only contract logic.

### 4.4 Why There Is No ACT Opportunity

The ACT definition requires a **permissionless, anyone-can-take strategy** realizable by unprivileged adversaries using only on-chain data and public tools. The evidence shows:

- Both `0xe4c61b84` (leveraged entrypoint) and `0xf4f3b200` (withdrawERC20) enforce `msg.sender == owner` using the owner address stored in slot 0.  
- The deploy and config traces (`0xba47...bf6`, `0x6598...e406`) show storage writes that set:
  - Owner slot 0 to `0x3fee6...`.  
  - Router slot 1 to `0x616B...`.  
  - Token and beneficiary slots to WBNB and `0x3fee6...`.
- There is no subsequent storage write that changes the owner or rewires the beneficiary to an unprivileged address.

Therefore:

- Any call from an EOA other than `0x3fee6...` to `0xe4c61b84` or `0xf4f3b200` will **revert at the owner check**.  
- Even hypothetically bypassing the owner check, the withdrawal beneficiary is **not caller-supplied**; it is read from storage, so an arbitrary EOA cannot redirect funds to itself.

This means the profitable sequence is **not replicable by arbitrary actors**. The system exposes **no ACT opportunity**; it simply allows the owner to operate a leveraged router/TokenHolder position and realize WBNB-denominated gains.

## 5. Adversary Flow Analysis

### 5.1 Adversary Strategy Summary

The owner EOA `0x3fee6...` executes a **four-tx, single-chain sequence**:

1. Deploy an owner-only router/holder contract `0xe82F...` wired to WBNB and the owner.  
2. Configure the router/holder with the leveraged router address.  
3. Use an owner-only leveraged entrypoint to draw WBNB from TokenHolder, pay protocol fees, and hold the residual WBNB on `0xe82F...`.  
4. Use an owner-only withdrawal function to sweep the accumulated WBNB from `0xe82F...` to the owner EOA.

### 5.2 Adversary-Related Accounts

**Adversary cluster:**

- **EOA**: `0x3fee6d8aaea76d06cf1ebeaf6b186af215f14088`  
  - Deploys `0xe82F...`.  
  - Sends the config, leveraged, and withdrawal transactions.  
  - Receives the final 19.2 WBNB.  
- **Contract**: `0xe82Fc275B0e3573115eaDCa465f85c4F96A6c631`  
  - Owner-only router/holder; owner stored in slot 0.  
  - Hosts leveraged and withdrawal logic that orchestrates interactions with router and TokenHolder.

**Stakeholder / victim-candidate contracts:**

- **Leveraged router**: `0x616B36265759517AF14300Ba1dD20762241a3828`  
- **BorrowerOperationsV6 / TokenHolder**: `0x8c7f...`, `0x2EeD...`, `0x3403...`  
  - Verified sources show a leveraged position and fee routing system with explicit role-based access control; only configured routers/token holders may invoke privilegedLoan and related paths.  
- **Fee address**: `0x8432CD30C4d72Ee793399E274C482223DCA2bF9e`  
  - Receives 0.8 WBNB fee in the seed tx.

The flows observed in traces match the intended role-based design; none of these contracts behaves as an exploited victim in this sequence.

### 5.3 Lifecycle Stages and Transactions

The root_cause.json adversary lifecycle is:

1. **Router deployment and configuration**  
   - `0xba473228bd61e8ba4bd8c8c9f411d863a24091fb301d6f25c63b693a2d325bf6` (block 63856624, contract_creation)  
     - Deploys `0xe82F...`; constructor stores WBNB and owner addresses in storage.  
   - `0x6598c2c962e5a019abedb40f1480c3e7bf0e09a8aaa7bdc549c36239dd7ee406` (block 63856691, configuration_call)  
     - Invokes selector `0x57964aaf` on `0xe82F...`. Trace shows:

```text
0xe82F...::57964aaf(0x616B...)
  ├─ storage changes:
  │   @ 1: 0 → 0x000000000000000000000000616b36265759517af14300ba1dd20762241a3828
  └─ ← [Stop]
```

     - This writes router address `0x616B...` into storage slot 1, wiring the leveraged router used in the seed tx.

2. **Leveraged operation via owner-only entrypoint (seed tx)**  
   - `0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6` (block 63856735, mechanism: leveraged_loan_and_sell)  
   - Owner calls `0xe82F...::e4c61b84(...)` with no native value.  
   - Trace and ERC‑20 logs show:
     - 20 WBNB loan from TokenHolder.  
     - 0.8 WBNB fee to `0x8432...`.  
     - 19.2 WBNB net deposited into `0xe82F...`.

3. **Owner withdrawal of accumulated WBNB**  
   - `0xa9f735df65cc26f2bda9a51ac46824fdb09dd5092d869c9690d7b273a51c164e` (block 63856871, mechanism: withdrawERC20)  
   - Owner calls `0xe82F...::withdrawERC20(WBNB)`.  
   - Trace shows `WBNB::transfer(0x3fee6..., 1.92e19)` and ERC‑20 balance diffs confirm the 19.2 WBNB movement from `0xe82F...` to the owner EOA.

Over the full sequence, there are **no external participants** whose behavior is required for success; it is entirely under the owner’s control.

## 6. Impact & Losses

The `Impact & Losses` section of root_cause.json reports:

- `total_loss_overview`:  
  - `token_symbol`: `WBNB`  
  - `amount`: `0`

Interpretation and evidence:

- No protocol-level or third-party user losses are attributed to this sequence.  
- The owner gains 19.2 WBNB, funded by the leveraged TokenHolder flow and consistent with the system’s fee and loan design.  
- WBNB and BNB movements match the intended behavior of the BorrowerOperationsV6 / TokenHolder stack and the fee routing arrangements; no invariants are violated and no unexpected drains occur.

In summary, **there is no victim** in the usual exploit sense; this is an owner-operated leveraged position and fee routing configuration that produces a positive payoff for the owner EOA.

## 7. References

Key evidence artifacts used in this analysis:

- **[1] Seed transaction trace (0xc291…64c6)**  
  `artifacts/root_cause/seed/56/0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6/trace.cast.log`  
  Shows the leveraged operation, including the 20 WBNB loan, 0.8 WBNB fee to `0x8432...`, and accumulation of 19.2 WBNB on `0xe82F...`.

- **[2] ERC‑20 balance-of diffs for seed and withdraw txs**  
  `artifacts/root_cause/data_collector/iter_3/tx/56/0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6/erc20_balance_diff_balanceOf.json`  
  `artifacts/root_cause/data_collector/iter_3/tx/56/0xa9f735df65cc26f2bda9a51ac46824fdb09dd5092d869c9690d7b273a51c164e/erc20_balance_diff_balanceOf.json`  
  Quantify WBNB movements into `0xe82F...` and then into the owner EOA.

- **[3] Selector analysis for router/holder 0xe82F…**  
  `artifacts/root_cause/data_collector/iter_3/contract/56/0xe82fc275b0e3573115eadca465f85c4f96a6c631/selector_analysis_e4c61b84_f4f3b200.json`  
  Demonstrates owner-only access control and storage-fixed router/token/beneficiary configuration.

- **[4] BorrowerOperationsV6 / TokenHolder and router sources**  
  - `artifacts/root_cause/data_collector/iter_1/contract/56/0x616b36265759517af14300ba1dd20762241a3828/source`  
  - `artifacts/root_cause/data_collector/iter_1/contract/56/0x8c7f34436c0037742aecf047e06fd4b27ad01117/source`  
  - `artifacts/root_cause/data_collector/iter_1/contract/56/0x2eed3dc9c5134c056825b12388ee9be04e522173/source`  
  - `artifacts/root_cause/data_collector/iter_1/contract/56/0x3403f2ba8aa448c208c2d1a41f2089c5a6f924e4/source`  
  Confirm the leveraged loan, fee routing, and role-based access patterns that align with the observed traces.

- **[5] WBNB contract source (standard implementation)**  
  `artifacts/root_cause/seed/56/0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c/src/Contract.sol`  
  Confirms WBNB’s standard wrapped-BNB behavior, allowing unambiguous interpretation of WBNB-denominated gains.

