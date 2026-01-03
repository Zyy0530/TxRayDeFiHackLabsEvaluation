# Andy Allowance Drain via Privileged Router Stack (Non-ACT)

## 1. Incident Overview TL;DR

A victim Andy (ANDY) holder, `0x382ffce2287252f930e1c8dc9328dac5bf282ba1`, granted an effectively unlimited ERC20 allowance of ANDY (`0x68bbed6a47194eff1cf514b50ea91895597fc91e`) to the Settler contract `0xdf31a70a21a1931e02033dbba7deace6c45cfd0f` on Ethereum mainnet.

After this approval, a privileged router/solver stack centered on EOA `0xc31a49d1c4c652af57cefdef248f3c55b801c649` used that allowance to move and swap `88438777696239504000000` ANDY into WETH/ETH via Settler, TokenApproveProxy, TokenApprove, and a UniswapV2-style pair, ultimately delivering ETH profits to `0xc31a49d1c4c652af57cefdef248f3c55b801c649` and `0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97`.

The key mechanism is a router entrypoint (`0x0000047b`) with hardcoded gating on `msg.sender == 0xc31...`, combined with TokenApproveProxy and TokenApprove configuration that allow this router stack to call `TokenApprove::claimTokens` on its own behalf. Because this path is effectively restricted to a specific solver/router cluster, the incident is **not** an ACT (Adversarial Composable Transaction) opportunity: arbitrary searchers cannot replicate the same drain path under the same conditions.

**ACT classification:** This incident is classified as **non-ACT**. The profit transaction is adversary-crafted by a privileged solver EOA bound into the router bytecode and proxy allowlists, rather than being a permissionless, generally reproducible MEV opportunity.

## 2. Key Background

### 2.1 Protocol and assets

- **Protocol context:** The incident occurs on Ethereum mainnet within a stack involving:
  - A mainnet Settler aggregator contract `0xdf31a70a21a1931e02033dbba7deace6c45cfd0f` (“Settler”).
  - A router contract `0xf0d539955974b248d763d60c3663ef272dfc6971` that aggregates complex actions and forwards them to Settler and downstream AMMs.
  - TokenApprove `0x40aA958dd87FC8305b97f2BA922CDdCa374bcD7f` and TokenApproveProxy `0x70cBb871E8f30Fc8Ce23609E9E0Ea87B6b222F58`, which manage ERC20 approvals and token movements for the router stack.
  - A UniswapV2-style pair `0xa1bf0e900fb272089c9fd299ea14bfccb1d1c2c0` providing ANDY/WETH liquidity.

- **Andy token:**
  - Address: `0x68bbed6a47194eff1cf514b50ea91895597fc91e`.
  - Standard ERC20-style token on Ethereum mainnet with `approve` and `transferFrom` semantics.
  - Source code is available at `artifacts/root_cause/seed/1/0x68bbed6a47194eff1cf514b50ea91895597fc91e/src/Contract.sol` and behaves as expected for ERC20 approvals and transfers.

- **Settler contract:**
  - Address: `0xdf31a70a21a1931e02033dbba7deace6c45cfd0f`.
  - Implemented as a complex onchain aggregator (MainnetSettler) with a key entrypoint:

```solidity
interface ISettlerTakerSubmitted is ISettlerBase {
    function execute(
        AllowedSlippage calldata slippage,
        bytes[] calldata actions,
        bytes32 /* zid & affiliate */
    ) external payable returns (bool);
}
```

  - The `execute` function is public and guarded by a `takerSubmitted` modifier that records the operator in transient storage but does **not** impose additional `msg.sender`-based access control; it is suitable for being called by an upstream router.

### 2.2 TokenApprove and TokenApproveProxy

- **TokenApprove:**
  - Address: `0x40aA958dd87FC8305b97f2BA922CDdCa374bcD7f`.
  - Stores configuration including an `owner` and a `tokenApproveProxy` address. Around the incident, `owner_tokenApproveProxy_state.json` shows:

```json
{
  "incident_block": 23134257,
  "calls": [
    {
      "block_number": 23134257,
      "owner_raw": "0x000000000000000000000000ace2b3e7c752d5debca72210141d464371b3b9b1",
      "tokenApproveProxy_raw": "0x00000000000000000000000070cbb871e8f30fc8ce23609e9e0ea87b6b222f58"
    }
  ]
}
```

  - This confirms that TokenApprove routes privileged token movements through TokenApproveProxy at `0x70cb...` under an owner-controlled configuration.

- **TokenApproveProxy:**
  - Address: `0x70cBb871E8f30Fc8Ce23609E9E0Ea87B6b222F58`.
  - Bytecode and `tokenApproveProxy_access_control_summary.json` reveal a mapping-based allowlist keyed by `msg.sender` and owner-only configuration of routers and proxies:

```json
{
  "selector_table": {
    "0x0a5ea466": "approve(address,uint256)",
    "0x1c6eced5": "setApproveProxyAccess(address,bool)"
  },
  "access_control_patterns": [
    {
      "pattern": "mapping-based allowlist keyed by msg.sender",
      "details": "... loads a bool from keccak256(msg.sender, slot=0x65) and reverts with 'ApproveProxy: Access restricted' if it is zero."
    }
  ]
}
```

  - Only allowlisted callers (such as the router) can route ERC20 approvals through TokenApproveProxy into downstream tokens and TokenApprove.

### 2.3 Router access control and solver binding

- **Router:**
  - Address: `0xf0d539955974b248d763d60c3663ef272dfc6971`.
  - `router_access_control_summary.json` for selector `0x0000047b` shows a hardcoded solver EOA and global CALLER gating:

```json
{
  "entrypoints": {
    "0x0000047b": {
      "description": "Aggregator-style entrypoint used in profit tx; decodes a complex actions[] payload and forwards to Settler and downstream AMMs.",
      "access_control": [
        "Global prologue compares msg.sender to hardcoded EOA 0xc31a49d1c4c652af57cefdef248f3c55b801c649 using CALLER + PUSH32 + AND + SUB + JUMPI.",
        "If msg.sender != 0xc31..., execution jumps to a separate dispatcher at PC 0x02f2 ...",
        "Within the primary dispatcher path that handles selector 0x0000047b in the observed profit tx, there are no further hardcoded EOA comparisons or allowlists."
      ]
    }
  },
  "hardcoded_addresses": [
    {
      "address": "0xc31a49d1c4c652af57cefdef248f3c55b801c649",
      "role_in_bytecode": "Only statically embedded EOA in runtime; used ... to branch between privileged (msg.sender==0xc31...) and generic (msg.sender!=0xc31...) paths."
    }
  ]
}
```

- **Implication for ACT classification:**
  - The privileged aggregator path for selector `0x0000047b` is only entered when `msg.sender == 0xc31a49d1c4c652af57cefdef248f3c55b801c649`.
  - Calls from other EOAs are diverted to a separate dispatcher whose semantics are not used to realize the observed ANDY drain and do not share the same privileged routing.
  - Combined with TokenApproveProxy’s allowlist, this means the profit transaction path is effectively restricted to the `0xc31...` solver/router cluster and is **not** permissionlessly reproducible by arbitrary searchers.

## 3. Vulnerability Analysis

### 3.1 Core vulnerability and misconfiguration

The incident stems from the interaction of three factors:

1. **High-privilege allowance by the victim:**
   - In tx `0x8df54ebe76c09cda530f1fccb591166c716000ec95ee5cb37dff997b2ee269f2`, the victim `0x382f...` approves Settler `0xdf31...` for essentially the maximum `uint256` allowance of ANDY.
   - The seed trace (`trace.cast.log`) shows this explicitly:

```text
[24660] Andy::approve(0xDf31A70a21A1931e02033dBBa7DEaCe6c45cfd0f,
                      115792089237316195423570985008687907853269984665640564039457584007913129639935)
  ├─ emit Approval(owner: 0x382fFCe2287252F930E1C8DC9328dac5BF282bA1,
                   spender: 0xDf31A70a21A1931e02033dBBa7DEaCe6c45cfd0f,
                   value: 1157920892373...639935)
```

2. **Router entrypoint privileged to a single solver:**
   - Router `0xf0d5...` enforces `msg.sender == 0xc31...` at the global prologue level for the aggregator entrypoint `0x0000047b` used in the profit transaction.
   - This ties the privileged execution path that actually consumes the allowance and routes tokens to a single solver EOA.

3. **TokenApprove/TokenApproveProxy configuration bound to the router:**
   - TokenApproveProxy `0x70cb...` implements an allowlist keyed by `msg.sender` and restricts proxy actions to configured callers.
   - TokenApprove `0x40aa...` stores `tokenApproveProxy` and uses it to authorize `claimTokens`-style operations.
   - On-chain state at block 23134257 confirms that TokenApproveProxy at `0x70cb...` is the configured proxy for TokenApprove, and the router stack is allowed through this proxy.

Given these factors, the **root cause** is not a generic, permissionless exploit of Settler or ANDY. Instead, it is a solver-specific allowance drain: the victim’s unlimited approval is combined with a router/proxy stack whose high-privilege entrypoints and token-claiming capabilities are bound to a particular solver EOA and router configuration.

### 3.2 Why this is non-ACT

- **Non-ACT characteristics:**
  - An ACT would require that any searcher or adversary, given the same on-chain state, could permissionlessly craft a transaction or bundle to realize the same profit path.
  - Here, the observed drain depends on:
    - A router entrypoint that branches on `msg.sender == 0xc31...` and only takes the privileged path for that specific EOA.
    - TokenApproveProxy allowlisting that grants proxy access to the router stack and not to arbitrary EOAs.
  - An arbitrary searcher cannot impersonate `0xc31...` at the protocol level; they cannot enter the same privileged router path nor reach `TokenApprove::claimTokens` in the same way.

- **Conclusion:** The incident is correctly classified as **non-ACT**. It is an allowance misuse tied to a particular operator/solver stack, not a broadly exploitable, composable MEV opportunity.

## 4. Detailed Root Cause Analysis

### 4.1 State definition and opportunity window

- **Block height B:** `23134257` (Ethereum mainnet).
- **Pre-state σ_B definition:**
  - Ethereum mainnet state after the victim `0x382f...` granted an unlimited ANDY allowance to Settler `0xdf31...` via tx `0x8df5...`, and **before** the router/Settler/TokenApprove profit transaction `0x33b2cb5b...` executed.
  - Evidence:
    - `artifacts/root_cause/seed/1/0x8df5.../metadata.json` (approval tx metadata).
    - `artifacts/root_cause/seed/1/0x8df5.../trace.cast.log` (approval call trace and storage changes).
    - `artifacts/root_cause/seed/1/0x68bb.../src/Contract.sol` (Andy token source).

### 4.2 Victim approval transaction (setup)

- **Transaction:** `0x8df54ebe76c09cda530f1fccb591166c716000ec95ee5cb37dff997b2ee269f2` (victim-observed).
- **Chain:** Ethereum mainnet (`chainid = 1`).
- **Effect:**
  - Victim `0x382f...` calls ANDY `approve` with:
    - `spender = 0xdf31a70a21a1931e02033dbba7deace6c45cfd0f` (Settler).
    - `value = 2^256 - 1` (effectively unlimited allowance).
  - The trace shows the Approval event and allowance slot updated to `0xffff...ffff`.

This establishes the high-privilege allowance required for any subsequent `transferFrom` by Settler (or contracts acting via Settler) to drain ANDY from the victim.

### 4.3 Router and proxy configuration

- **Historical configuration (aggregated):**
  - Router `0xf0d5...` is deployed with a hardcoded reference to solver EOA `0xc31...` and is registered in TokenApproveProxy and TokenApprove configuration.
  - In particular:
    - `router_access_control_summary.json` shows `0xc31...` as the only statically embedded EOA, used to branch between privileged and generic dispatcher paths.
    - `tokenApproveProxy_access_control_summary.json` shows a mapping-based allowlist keyed by `msg.sender`, with owner-only functions to update router mappings and proxy access.
    - `owner_tokenApproveProxy_state.json` for TokenApprove `0x40aa...` shows that TokenApproveProxy `0x70cb...` is the configured proxy around the incident block.

- **Logical effect:**
  - Router `0xf0d5...` can, when called from `0xc31...`, enter a privileged path that can ultimately trigger TokenApprove operations via TokenApproveProxy to move tokens.
  - Other EOAs, even if they copied the calldata of the profit transaction, would be routed into an alternate, generic path and would not share the same privileged access.

### 4.4 Solver executes profit transaction (drain realization)

- **Transaction:** `0x33b2cb5bc3c0ccb97f0cc21e231ecb6457df242710dfce8d1b68935f0e05773b` (adversary-crafted).
- **Chain and block:** Ethereum mainnet (`chainid = 1`), block `23134257`.
- **Sender and to:**
  - `from = 0xc31a49d1c4c652af57cefdef248f3c55b801c649` (solver EOA).
  - `to = 0xf0d539955974b248d763d60c3663ef272dfc6971` (router).

- **Call structure (from trace.cast.log):**

```text
[184441] 0xF0D5...::0000047b{value: 1620}(...)
  ├─ [54310] 0xDf31...::execute(...)
  │   ├─ [51193] Andy::transferFrom(0x382f..., 0xF0D5..., 88438777696239504000000)
  │   └─ ...
  ├─ [33298] 0xa1bF0e9...::swap(0, 1761107954470704, 0xF0D5..., 0x)
  ├─ [9180] WETH9::withdraw(1761107954470704)
  ├─ [0] 0x4838...::fallback{value: 211012241371460}()
  ├─ [0] 0xC31a...::fallback{value: 1550095713100864}()
  └─ ← [Stop]
```

- **Token flows from balance diffs:**
  - From `balance_diff.json` for tx `0x33b2...`:

```json
{
  "native_balance_deltas": [
    {
      "address": "0xc31a49d1c4c652af57cefdef248f3c55b801c649",
      "delta_wei": "1094648119380540"
    },
    {
      "address": "0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97",
      "delta_wei": "211012241593069"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0x68bbed6a47194eff1cf514b50ea91895597fc91e",
      "holder": "0x382ffce2287252f930e1c8dc9328dac5bf282ba1",
      "delta": "-88438777696239504000000"
    },
    {
      "token": "0x68bbed6a47194eff1cf514b50ea91895597fc91e",
      "holder": "0xa1bf0e900fb272089c9fd299ea14bfccb1d1c2c0",
      "delta": "88438777696239504000000"
    }
  ]
}
```

- **Interpretation:**
  - Settler `execute` uses the victim’s ANDY allowance to transfer `88438777696239504000000` ANDY from `0x382f...` to the router/liquidity path.
  - The ANDY is then swapped via the UniswapV2-style pair `0xa1bf...` into WETH/ETH.
  - WETH is withdrawn to ETH, which is then distributed to `0xc31...` and `0x4838...` as profits.

### 4.5 Profit computation and success predicate

- **Success predicate type:** `profit` (reference asset: ETH).
- **Adversary address:** Solver EOA `0xc31a49d1c4c652af57cefdef248f3c55b801c649`, with fee-recipient `0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97` considered part of the adversary cluster.
- **Profit numbers (from root_cause.json):**
  - `value_before_in_reference_asset` (cluster ETH): `22003358174177271731` wei.
  - `value_after_in_reference_asset` (cluster ETH): `22004663834538245340` wei.
  - `value_delta_in_reference_asset` (profit): `1305660360973609` wei.
  - Notes: The profit is derived directly from the combined native balance delta of `0xc31...` and `0x4838...` in tx `0x33b2...`.
  - Gas costs and the `0x654` wei transaction value field are already reflected in these net deltas and are not separated as a distinct scalar.

The success predicate is satisfied: the adversary cluster ends the transaction with a strictly higher ETH balance than before, as confirmed by on-chain balance diffs.

## 5. Adversary Flow Analysis

### 5.1 Transaction sequence

- **Sequence B (act_opportunity.transaction_sequence_b):**
  - Single adversary-crafted transaction:
    - `index = 1`.
    - `chainid = 1`.
    - `txhash = 0x33b2cb5bc3c0ccb97f0cc21e231ecb6457df242710dfce8d1b68935f0e05773b`.
    - `type = adversary-crafted`.
    - `inclusion_feasibility`: A standard Ethereum mainnet transaction from `0xc31...` to router `0xf0d5...` with sufficient gas and fee; feasibility is evidenced by its actual inclusion in block 23134257.
    - `notes`: This transaction exercises the router’s privileged aggregator entrypoint (`0x0000047b`) that is gated by a `CALLER == 0xc31...` check in the router’s bytecode. Sending the same calldata from a different EOA would be dispatched to a different code path and cannot reproduce the observed drain.

### 5.2 Call stack and roles

- **High-level flow in tx 0x33b2...:**
  1. **EOA (0xc31...) → Router (0xf0d5...), selector 0x0000047b**
     - Enters the privileged aggregator path due to `msg.sender == 0xc31...`.
  2. **Router → Settler (0xdf31...), execute(...)**
     - Router passes a complex `actions[]` payload instructing Settler to move ANDY and perform swaps.
  3. **Settler → Andy (0x68bb...), transferFrom(...)**
     - Settler uses the victim’s unlimited allowance to pull `88438777696239504000000` ANDY from `0x382f...`.
  4. **Settler/Router → TokenApprove / TokenApproveProxy → UniswapV2-style pair (0xa1bf...)**
     - Tokens are routed through TokenApprove and the pair to swap ANDY to WETH.
  5. **Pair → WETH9 (0xc02a...), transfer; WETH9 → withdraw to ETH**
     - WETH is transferred back to router and then unwrapped to ETH.
  6. **Router → EOA/fee-recipient:**
     - ETH is sent to `0xc31...` and `0x4838...` as profits, as shown by their positive native balance deltas.

The call traces and balance diffs collectively confirm that the ANDY outflow from the victim is matched by the ANDY inflow to the pair and ETH inflows to the solver cluster.

### 5.3 Adversary-related accounts

- **Solver EOA:** `0xc31a49d1c4c652af57cefdef248f3c55b801c649`.
  - Only statically embedded EOA in the router’s runtime bytecode; controls entry into the privileged aggregator path.
  - Direct beneficiary of ETH flow in the profit transaction.

- **Fee recipient:** `0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97`.
  - Receives part of the ETH proceeds from the router in the profit transaction.
  - Treated as part of the adversary profit cluster for computing net profit.

- **Router:** `0xf0d539955974b248d763d60c3663ef272dfc6971`.
  - Aggregates actions and mediates between Settler, TokenApproveProxy, TokenApprove, and AMMs.
  - Enforces `CALLER == 0xc31...` for the privileged path used in the incident.

- **TokenApproveProxy:** `0x70cBb871E8f30Fc8Ce23609E9E0Ea87B6b222F58`.
  - Enforces an allowlist of routers/clients via a `mapping[msg.sender]` in storage.

- **TokenApprove:** `0x40aA958dd87FC8305b97f2BA922CDdCa374bcD7f`.
  - Uses TokenApproveProxy to manage token approvals and claims.

- **Victim:** `0x382ffce2287252f930e1c8dc9328dac5bf282ba1`.
  - Grants unlimited ANDY allowance and suffers the ANDY loss.

Collectively, these roles are well-supported by the access-control summaries and balance diffs and align with the non-ACT classification.

## 6. Impact & Losses

### 6.1 Token loss

- **Immediate on-chain impact:**
  - Victim `0x382f...` loses:
    - **Token:** ANDY (`0x68bb...`).
    - **Amount:** `88438777696239504000000` ANDY.
  - This loss is confirmed by the ERC20 balance deltas in `balance_diff.json` for tx `0x33b2...`, which show the victim’s ANDY balance decreasing by that exact amount and the ANDY/WETH pair’s balance increasing correspondingly.

### 6.2 Adversary profit

- **Reference asset:** ETH.
- **Adversary cluster:** `{ 0xc31a49d1c4c652af57cefdef248f3c55b801c649, 0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97 }`.
- **Before / after ETH values (from root_cause.json):**
  - `value_before_in_reference_asset = 22003358174177271731` wei.
  - `value_after_in_reference_asset  = 22004663834538245340` wei.
  - `value_delta_in_reference_asset  = 1305660360973609` wei.

- **Interpretation:**
  - The combined ETH holdings of the adversary cluster increase by `1,305,660,360,973,609` wei in this single transaction.
  - These net deltas already incorporate gas costs and the transaction’s `0x654` wei value; a separate gas scalar is not required for the profit predicate.
  - The exact fiat value at execution time is outside the scope of this analysis, but the on-chain profit in ETH is precisely quantified.

## 7. References

The following on-disk artifacts and code sources underpin this analysis:

1. **[1] Seed profit transaction metadata, trace, and balance diff**  
   - Path: `artifacts/root_cause/seed/1/0x33b2cb5bc3c0ccb97f0cc21e231ecb6457df242710dfce8d1b68935f0e05773b/`  
   - Includes `metadata.json`, `trace.cast.log`, and `balance_diff.json` for tx `0x33b2...`.

2. **[2] Seed approval transaction and Andy token source**  
   - Path: `artifacts/root_cause/seed/1/0x8df54ebe76c09cda530f1fccb591166c716000ec95ee5cb37dff997b2ee269f2/` (approval tx artifacts).  
   - Andy source: `artifacts/root_cause/seed/1/0x68bbed6a47194eff1cf514b50ea91895597fc91e/src/Contract.sol`.

3. **[3] Settler mainnet source (MainnetTakerSubmittedFlat.sol)**  
   - Path: `artifacts/root_cause/data_collector/iter_1/contract/1/0xdf31a70a21a1931e02033dbba7deace6c45cfd0f/source/src/flat/MainnetTakerSubmittedFlat.sol`.

4. **[4] Router access-control summary and disassembly**  
   - Path: `artifacts/root_cause/data_collector/iter_4/contract/1/0xf0d539955974b248d763d60c3663ef272dfc6971/router_access_control_summary.json`.  
   - Supported by runtime bytecode and disassembly at the paths referenced inside this summary.

5. **[5] TokenApproveProxy access-control summary**  
   - Path: `artifacts/root_cause/data_collector/iter_4/contract/1/0x70cBb871E8f30Fc8Ce23609E9E0Ea87B6b222F58/tokenApproveProxy_access_control_summary.json`.

These references, together with the standardized transaction data in `standardized_txs.json` and the high-level `root_cause.json`, provide a complete, deterministic, and evidence-backed explanation of the incident as a **non-ACT, solver-specific Andy allowance drain via a privileged router stack**.
