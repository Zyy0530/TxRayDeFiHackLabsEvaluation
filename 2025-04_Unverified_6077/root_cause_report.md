## Incident Overview & TL;DR

On Base (chainid 8453), EOA `0xcfad03a6f9dc4007eb3716fee51f108b00d6736d` uses attacker-controlled router contract `0x780e5cb8de79846f35541b700637057c9ddded68` to drive two Uniswap V3-style swap callbacks into pool-like contract `0x607742a2adea4037020e11bb67cb98e289e3ec7d`. During these callbacks, `0x6077...` pulls **22.51 WETH** and **27,260 USDC** from victim EOA `0xddddf3d84a1e94036138cab7ff35d003c1207a77` into `0x780e...`. Subsequent helper transactions sweep the drained WETH and USDC from `0x780e...` to `0xcfad...`, which then unwraps the 22.51 WETH and swaps the 27,260 USDC to ETH via a router, producing a **net profit of 39.948333600757332573 ETH** for the adversary cluster after gas.

All steps are executed by an unprivileged onchain adversary using standard contract interfaces, publicly observable transactions, and reconstructed state from traces and prestateTracer artifacts.

The **root cause** is a protocol bug in `0x6077...`: inside its Uniswap V3-style callback, it dynamically reads `token1()` from attacker-controlled contract `0x780e...` and uses that value to decide which token to pull from the victim, instead of treating the token pair as immutable pool configuration. Because `0x780e...` can change `token1` between callbacks, a single orchestrated sequence drains multiple distinct tokens from the same victim allowances.

---

## Key Background

- Base (chainid 8453) is an EVM-compatible L2 where:
  - WETH9 is deployed at `0x4200000000000000000000000000000000000006`.
  - FiatTokenProxy / FiatTokenV2_2 (USDC) is deployed at `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`.
  - Both follow standard ERC-20 allowance and `transferFrom` semantics.

- Uniswap V3-style pools typically:
  - Treat `token0` and `token1` as **immutable configuration parameters**.
  - Expect `uniswapV3SwapCallback` to operate under the assumption that the token pair is fixed for the lifetime of the pool and does not change between callbacks in a single swap.

- Contract `0x780e5cb8de79846f35541b700637057c9ddded68` (`0x780e...`) is an unverified attacker-controlled router/adapter that:
  - Exposes a **mutable** `token1()` view.
  - Exposes privileged entrypoints:
    - `0x2248371a` — used as the seed orchestrator.
    - `0x6b784107` — used as a post-drain sweep entrypoint.
  - Enforces `require(msg.sender == 0xcfad...)` on these entrypoints, so only the adversary EOA can use them.

- Contract `0x607742a2adea4037020e11bb67cb98e289e3ec7d` (`0x6077...`) is an unverified pool-like callback target that:
  - Implements a Uniswap V3-style `uniswapV3SwapCallback`.
  - Inside the callback, **reads `token1()` from `0x780e...`** via `staticcall`.
  - Uses the **returned address** as the token to pull from the victim EOA via `transferFrom`, implicitly assuming `token1` behaves like a stable pool parameter.

- The adversary-related EOA `0xcfad...`:
  - Is initially funded with approximately `0.095205808819773694` ETH from `0x3bdb03ad7363152dfbc185ee23ebc93f0cf93fd1`.
  - Deploys and controls `0x780e...`.
  - Sends all attacker-crafted exploit transactions and finally receives the ETH profit before forwarding funds onward, as shown in address-txlist artifacts for `0xcfad...` and `0x780e...`.

> **Evidence snippet – Pseudo-spec for 0x780e... and 0x6077...**  
> Source: Collected pseudo-spec combining decompiled code and traces  
> ```json
> {
>   "contracts": {
>     "0x780e5cb8de79846f35541b700637057c9ddded68": {
>       "role": "Attacker-controlled router/adapter that exposes a configurable token1() view and a privileged entrypoint used to drive pool callbacks.",
>       "key_functions": {
>         "token1()": {
>           "semantics": "Returns an address stored in contract_780e storage (slot interpreted as token1). In traces for the seed tx, token1() initially returns WETH9 and later FiatTokenProxy/USDC."
>         },
>         "Unresolved_2248371a(address)": {
>           "entrypoint_role": "Primary entrypoint invoked by the attacker EOA to orchestrate the drain via pool-like contract 0x6077...."
>         }
>       }
>     },
>     "0x607742a2adea4037020e11bb67cb98e289e3ec7d": {
>       "role": "Pool-like callback target that implements a Uniswap V3-style swap callback and delegates token pulls based on token1 from contract_780e."
>     }
>   }
> }
> ```  
> *Caption: Pseudo-spec summarizing how `0x780e...` provides a mutable `token1()` view used by `0x6077...` during callbacks.*

---

## Vulnerability & Root Cause Analysis

### High-level vulnerability

Contract `0x6077...` delegates token selection in `uniswapV3SwapCallback` to the external contract `0x780e...`:

- On each callback, `0x6077...` calls `0x780e...::token1()` via `staticcall`.
- It treats the **returned address** as the token to pull from the victim EOA `0xdddd...` into `0x780e...` via `transferFrom`.
- Because `token1` in `0x780e...` is **mutable**, the attacker can change it between callbacks, so multiple different tokens can be drained from the same victim within a single orchestrated flow.

This behaviour violates the standard assumption that a pool’s token pair is immutable; it is not a user configuration mistake, but a logic bug in `0x6077...`’s callback design.

### Detailed root cause

1. **Attacker-controlled mutable `token1()` in 0x780e...**
   - `0x780e...` stores a token address in its own storage (slot 0) and exposes it via a `token1()` view.
   - The pseudo-spec and seed trace show that:
     - On the **first** callback, `token1()` returns WETH9 at `0x4200000000000000000000000000000000000006`.
     - On the **second** callback, after a storage write, `token1()` returns USDC at `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`.

2. **Privileged orchestrator entrypoint 0x2248371a in 0x780e...**
   - Entry point `0x2248371a(address pool)` is guarded by `require(msg.sender == 0xcfad...)`, so only the adversary EOA can invoke it.
   - When `0xcfad...` calls `0x780e...::2248371a(0x6077...)` in seed tx `0x1a6002d8aee205dff67cb2cdaf60569721655857d49ffe2ce81e10fde8c45946`, `0x6077...` receives **two** `uniswapV3SwapCallback`-style calls.

3. **Callback behaviour in 0x6077...**
   - In each callback:
     - `0x6077...` performs a `staticcall` to `0x780e...::token1()`.
     - It interprets the returned address as the token to pull from victim EOA `0xdddd...`.
     - It then executes `transferFrom(victim, 0x780e..., amount)` for that token (WETH9 or USDC).
   - `0x6077...` **does not validate** that `token1` equals any immutable pool configuration value, nor that it remains constant during a given swap.

4. **Observed multi-asset drain in the seed transaction**
   - In the **first callback**:
     - `token1()` returns WETH9.
     - WETH9’s `transferFrom` moves exactly `22510000000000000000` wei (22.51 WETH) from `0xdddd...` to `0x780e...`.
   - In the **second callback**:
     - `0x780e...` has changed storage slot 0 from WETH9 to USDC.
     - `token1()` now returns USDC.
     - FiatTokenV2_2’s `transferFrom` moves `27260000000` units (27,260 USDC) from `0xdddd...` to `0x780e...`.
   - The pool’s callback does not detect that the token has changed; it treats both transfers as valid legs of a swap.

5. **Why this is the protocol-level root cause**
   - The design flaw is in `0x6077...`’s callback integration:
     - It **trusts** an external, attacker-controlled `token1()` source for pool configuration.
     - It fails to enforce invariants about the pool’s token pair.
   - This goes beyond specific transaction parameters and instead reflects a **structural protocol bug**, meaning any similar deployment where a pool-style contract reads `token1()` dynamically from an attacker-controlled contract is vulnerable to the same multi-token drain pattern.

> **Evidence snippet – Seed tx trace showing dynamic token1 and multi-asset pull**  
> Source: Seed transaction trace for `0x1a6002d8...`  
> ```bash
> 0x780e5Cb8DE79846f35541b700637057c9dddEd68::2248371a(... 0x607742a2adea4037020e11bb67cb98e289e3ec7d)
>   ├─ 0x6077...::uniswapV3SwapCallback(..., 22510000000000000000, ...)
>   │   ├─ 0x780e...::token1() [staticcall] → 0x4200000000000000000000000000000000000006
>   │   ├─ WETH9::transferFrom(0xdddd..., 0x780e..., 22510000000000000000)
>   ├─ 0x6077...::uniswapV3SwapCallback(..., 27260000000, ...)
>   │   ├─ 0x780e...::token1() [staticcall] → 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913
>   │   ├─ FiatTokenV2_2::transferFrom(0xdddd..., 0x780e..., 27260000000)
>   ├─ storage change on 0x780e... slot 0:
>   │   0x4200000000000000000000000000000000000006 → 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913
> ```  
> *Caption: Seed transaction shows `0x6077...` calling `token1()` twice, first returning WETH9 and then USDC, and pulling both tokens from the same victim into `0x780e...`.*

---

## Adversary Flow Analysis

### Adversary-related accounts

- **Adversary cluster**
  - `0xcfad03a6f9dc4007eb3716fee51f108b00d6736d` (Base, chainid 8453)
    - Type: EOA (`is_eoa = true`, `is_contract = false`).
    - Role: Sender of all attacker-crafted transactions in the exploit sequence, deployer/controller of `0x780e...`, and final receiver of ETH profit before onward transfers.
  - `0x780e5cb8de79846f35541b700637057c9ddded68` (Base, chainid 8453)
    - Type: Contract (`is_eoa = false`, `is_contract = true`).
    - Role: Attacker-controlled router/adapter that:
      - Holds intermediate WETH and USDC drained from victim `0xdddd...`.
      - Exposes privileged entrypoints `0x2248371a` (drain orchestrator) and `0x6b784107` (post-drain sweeper), both gated to `msg.sender == 0xcfad...`.

- **Victim and other stakeholders**
  - Victim EOA funding drained positions:
    - Address: `0xddddf3d84a1e94036138cab7ff35d003c1207a77` (Base, chainid 8453).
    - Holds the WETH and USDC balances drained in the seed transaction.
  - Pool-like callback contract:
    - Address: `0x607742a2adea4037020e11bb67cb98e289e3ec7d` (Base, chainid 8453).
    - Implements the vulnerable `uniswapV3SwapCallback` that reads `token1()` dynamically from `0x780e...`.

### Lifecycle stages and transaction sequence

The adversary executes a **five-transaction sequence** on Base (chainid 8453):

1. **Seed multi-token drain via callback**
   - **Transaction:** `0x1a6002d8aee205dff67cb2cdaf60569721655857d49ffe2ce81e10fde8c45946`  
     - Block: `28791090`  
     - Role: Seed / adversary-crafted  
   - **Mechanism:**
     - `0xcfad...` sends a type-0x2 transaction with zero ETH value to `0x780e...` with input:
       - Selector `0x2248371a`
       - Argument `0x6077...` (callback target)
     - No privileged roles or non-public inputs are required; transaction conforms to Base fee rules and is included under standard mempool conditions.
   - **Effect:**
     - `0x6077...` receives two swap callbacks, each:
       - Reads `token1()` from `0x780e...`.
       - Executes `transferFrom` from victim `0xdddd...` to `0x780e...` for the returned token.
     - Net token movement in this tx:
       - **WETH9** (`0x4200...0006`):
         - Victim `0xdddd...`:
           - Before: `22517012217948887448`
           - After: `7012217948887448`
           - Delta: `-22510000000000000000` (22.51 WETH)
         - `0x780e...`:
           - Before: `0`
           - After: `22510000000000000000`
           - Delta: `+22510000000000000000`
       - **USDC** (`0x8335...2913`):
         - Victim `0xdddd...`:
           - Before: `27260506734`
           - After: `506734`
           - Delta: `-27260000000` (27,260 USDC)
         - `0x780e...`:
           - Before: `0`
           - After: `27260000000`
           - Delta: `+27260000000`
     - Gas cost for `0xcfad...` is paid entirely from its own balance; there is no privileged subsidy.

> **Evidence snippet – Consolidated state diff for the seed drain**  
> Source: `consolidated_state_diff_seed_tx.json` for tx `0x1a6002d8...`  
> ```json
> {
>   "assets": {
>     "weth9": {
>       "balances": {
>         "0xddddf3d84a1e94036138cab7ff35d003c1207a77": {
>           "before": "22517012217948887448",
>           "after": "7012217948887448",
>           "delta": "-22510000000000000000"
>         },
>         "0x780e5cb8de79846f35541b700637057c9ddded68": {
>           "before": "0",
>           "after": "22510000000000000000",
>           "delta": "22510000000000000000"
>         }
>       }
>     },
>     "fiattoken_proxy_usdc": {
>       "balances": {
>         "0xddddf3d84a1e94036138cab7ff35d003c1207a77": {
>           "before": "27260506734",
>           "after": "506734",
>           "delta": "-27260000000"
>         },
>         "0x780e5cb8de79846f35541b700637057c9ddded68": {
>           "before": "0",
>           "after": "27260000000",
>           "delta": "27260000000"
>         }
>       }
>     }
>   }
> }
> ```  
> *Caption: State diff confirms that 22.51 WETH and 27,260 USDC move from the victim EOA to the attacker-controlled contract in the seed tx.*

2. **Sweeping drained WETH and USDC to the EOA**
   - **Transactions:**
     - `0xe5592253cf9d8dcc4a686368167b2a6584687d148b2be16d9802a40880f48b64`  
       - Block: `28791152`  
       - Mechanism: ERC-20 transfer  
     - `0x91c8ef9583fedb15ddb4438eef5fc76edc8f8b40fdf77a9c54e534d5a29d2d68`  
       - Block: `28791350`  
       - Mechanism: ERC-20 transfer
   - **Mechanism:**
     - `0xcfad...` calls `0x780e...::6b784107(WETH9)` and later `0x780e...::6b784107(USDC)`.
     - `0x780e...`:
       - Reads its own token balance via `balanceOf(address(this))`.
       - If non-zero, calls `transfer(attacker_eoa, balance)`.
   - **Effect:**
     - From the WETH sweep tx (`0xe559...`):
       - `0x780e...` calls `WETH9::transfer(0xcfad..., 22510000000000000000)`.
       - Event logs show WETH moving from `0x780e...` to `0xcfad...` for exactly `22510000000000000000` wei.
     - From the USDC sweep tx (`0x91c8...)`:
       - `0x780e...` calls USDC `transfer(0xcfad..., 27260000000)`.
       - Logs show USDC moving from `0x780e...` to `0xcfad...` for exactly `27260000000` units.
     - After these two helper txs, all WETH and USDC drained in the seed tx reside on the adversary EOA `0xcfad...`.

> **Evidence snippet – Helper trace for WETH sweep**  
> Source: `debug_trace_callTracer.json` for tx `0xe5592253...`  
> ```json
> {
>   "from": "0xcfad03a6f9dc4007eb3716fee51f108b00d6736d",
>   "to": "0x780e5cb8de79846f35541b700637057c9ddded68",
>   "input": "0x6b784107...0000000000000000000000004200000000000000000000000000000000000006",
>   "calls": [
>     {
>       "to": "0x4200000000000000000000000000000000000006",
>       "type": "CALL",
>       "input": "0xa9059cbb...cfad03a6f9dc4007eb3716fee51f108b00d6736d...1386395bca60b0000",
>       "logs": [
>         {
>           "address": "0x4200000000000000000000000000000000000006",
>           "topics": [
>             "0xddf252ad...",
>             "0x...780e5cb8de79...",
>             "0x...cfad03a6f9dc..."
>           ],
>           "data": "0x...0000000000000001386395bca60b0000"
>         }
>       ]
>     }
>   ]
> }
> ```  
> *Caption: Helper tx shows `0x780e...` reading its WETH balance and transferring the full 22.51 WETH to `0xcfad...`.*

3. **Unwrapping WETH and swapping USDC to ETH**
   - **Transactions:**
     - `0x9f602e3e843e5207168e1b45e270fdfd7154268b339739fb5038e3359479273d`  
       - Block: `28791392`  
       - Mechanism: WETH9 unwrap (`withdraw`)  
     - `0xdb57009e69e49a1a2b5308f1d359d5f712f7291955f178dbf55ee350c451cae3`  
       - Block: `28791482`  
       - Mechanism: Router-based USDC→ETH swap
   - **Mechanism and effect:**
     - In tx `0x9f60...`:
       - `0xcfad...` calls `WETH9.withdraw(22510000000000000000)`.
       - prestateTracer diff shows:
         - WETH9’s native balance decreases by `22510000000000000000` wei.
         - `0xcfad...`’s native balance increases by `22509999902594337777` wei net of gas.
       - This fully unwraps the 22.51 WETH into ETH.
     - In tx `0xdb57...`:
       - `0xcfad...` calls a UniversalRouter-style contract (`UniversalRouter::3593564c(...)`) that:
         - Uses Permit2 to set an allowance for USDC.
         - Calls a Uniswap V3 pool’s `swap(...)` to trade `27260000000` USDC for WETH.
         - Withdraws WETH to ETH and sends ETH to `0xcfad...`.
       - prestateTracer diff shows:
         - USDC:
           - `0xcfad...` decreases from `27260000000` to `0` (delta `-27260000000`).
           - The Uniswap pool `0xd0b53d9277642d899df5c87a3966a349a798f224` increases by `27260000000`.
         - ETH:
           - `0xcfad...`’s native balance increases by `17438334359250124515` wei (≈ 17.438334359250124515 ETH), net of gas.
     - Summing across the sequence, the adversary cluster realizes a profit of **39.948333600757332573 ETH-equivalent**, using WETH and USDC drained from the victim.

> **Evidence snippet – PrestateTracer diff for WETH unwrap tx**  
> Source: `balance_diff_prestate_tracer.json` for tx `0x9f602e3e...`  
> ```json
> {
>   "native_balance_deltas": [
>     {
>       "address": "0x4200000000000000000000000000000000000006",
>       "delta_wei": "-22510000000000000000"
>     },
>     {
>       "address": "0xcfad03a6f9dc4007eb3716fee51f108b00d6736d",
>       "before_wei": "95205080701368554",
>       "after_wei": "22605204983295706331",
>       "delta_wei": "22509999902594337777"
>     }
>   ]
> }
> ```  
> *Caption: WETH9 withdraw tx converts the full 22.51 WETH into ETH on `0xcfad...` with the expected balance delta.*

> **Evidence snippet – PrestateTracer and trace for USDC→ETH swap tx**  
> Source: `balance_diff_prestate_tracer.json` and `trace.cast.log` for tx `0xdb57009e...`  
> ```json
> {
>   "erc20_balance_deltas": [
>     {
>       "token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
>       "holder": "0xcfad03a6f9dc4007eb3716fee51f108b00d6736d",
>       "before": "27260000000",
>       "after": "0",
>       "delta": "-27260000000"
>     }
>   ],
>   "native_balance_deltas": [
>     {
>       "address": "0xcfad03a6f9dc4007eb3716fee51f108b00d6736d",
>       "delta_wei": "17438334359250124515"
>     }
>   ]
> }
> ```  
> *Caption: Router tx spends the 27,260 USDC held by `0xcfad...` and yields ≈17.4383 ETH net, finalizing the adversary’s profit.*

---

## Impact & Losses

### Quantified token losses and profit

From the analyzed artifacts and state diffs:

- **Victim losses (seed tx 0x1a60...)**
  - `22.51 WETH`
  - `27,260 USDC`
  - Both are transferred from victim EOA `0xdddd...` to attacker-controlled contract `0x780e...`.

- **Adversary profit (over full lifecycle)**
  - The sequence of unwrap and swap converts the drained WETH and USDC into ETH on the adversary EOA `0xcfad...`.
  - Net ETH-equivalent profit for the adversary cluster (after gas):
    - `39.948333600757332573 ETH`

### Systemic impact

- The exploit:
  - Does not impact global liveness of Base or the canonical USDC token.
  - Does not require privileged roles, admin keys, or non-public information.
  - Demonstrates a **reusable exploit vector**:
    - Any pool-like contract that reads `token1()` dynamically from an attacker-controlled contract inside a swap callback and then uses that value to drive `transferFrom` from user balances is vulnerable to multi-token drains from a single victim.

---

## References

Key artifacts used in this analysis:

- **[1] Seed tx metadata and trace for 0x1a6002d8aee205dff67cb2cdaf60569721655857d49ffe2ce81e10fde8c45946**  
  - Origin: Seed transaction metadata and `cast run -vvvvv` style trace showing the twin callbacks and dynamic `token1()` behaviour.

- **[2] Pseudo-spec for 0x780e... and 0x6077... (dynamic token1 callback design)**  
  - Origin: Combined decompiler outputs and traces for `0x780e...` and `0x6077...`, summarizing `token1()`, `0x2248371a`, `0x6b784107`, and `uniswapV3SwapCallback`.

- **[3] Consolidated state diff for seed drain tx 0x1a6002d8aee205dff67cb2cdaf60569721655857d49ffe2ce81e10fde8c45946**  
  - Origin: prestateTracer-based state diff aggregating WETH and USDC balance changes for the victim, attacker contract, and related addresses.

- **[4] WETH9.withdraw prestateTracer diff for tx 0x9f602e3e843e5207168e1b45e270fdfd7154268b339739fb5038e3359479273d**  
  - Origin: prestateTracer native balance diff quantifying the WETH→ETH unwrap on `0xcfad...`.

- **[5] UniversalRouter.execute prestateTracer diff for tx 0xdb57009e69e49a1a2b5308f1d359d5f712f7291955f178dbf55ee350c451cae3**  
  - Origin: prestateTracer balance diff capturing the USDC→ETH swap and associated pool and router flows.

- **[6] Address txlists for adversary-related accounts 0xcfad... and 0x780e...**  
  - Origin: consolidated txlists for the adversary EOA and contract, showing deployment and control relationships and the final consolidation of profits.

