# HYDT initialMint Flash-Loan Price-Manipulation Exploit on BSC

**Protocol:** HYDT (High Yield Dollar Stable Token, `HYDT`)  
**Category:** Protocol bug (price-oracle / minting logic)  
**Chain:** BNB Smart Chain (BSC, chainid 56)  
**Exploit transaction:** `0xa9df1bd97cf6d4d1d58d3adfbdde719e46a1548db724c2e76b4cd4c3222f22b3` (BSC block `0x28fe75f`)  
**Primary adversary EOA:** `0x4645863205b47a0a3344684489e8c446a437d66c`  
**Executor contract:** `0x8f921e27e3af106015d1c3a244ec4f48dbfcad14`

The analysis below is based solely on the deterministic root-cause artifacts (seed transaction trace, balance diffs, collected contract sources, and executor disassembly) under the provided root cause directory.

---

## Incident Overview & TL;DR

An adversary used a single, adversary-crafted transaction on BSC to exploit HYDT’s initial minting path. The attacker-controlled executor contract `0x8f92…`:

- Borrowed a large amount of USDT from a Pancake V3 pool as a flash-loan.  
- Used that USDT to heavily skew the WBNB/USDT price in a Pancake V2 pair.  
- Immediately called HYDT’s `initialMint` flow, which computes minted HYDT based on the manipulated AMM reserves.  
- Received a large amount of HYDT at a mispriced rate, then sold it back into USDT and WBNB.  
- Repaid the flash-loan and kept the remaining WBNB as profit.

The core of the incident is:

- **Incident brief:** In the exploit transaction, EOA `0x4645…` calls its pre-deployed executor `0x8f92…` with ~3.05 BNB and selector `0x3c9c2087`. The executor takes a USDT flash-loan from Pancake V3 pool `0x92b7…`, routes the USDT into Pancake V2 WBNB/USDT pair `0x16b9…` to push the price, and then triggers HYDT’s `initialMint` via contract `0xA2268…`. This call mints **60,961.921249934820691479 HYDT** to the executor at the manipulated price.

- **Root cause brief:** The `initialMint` logic in contract `0xA2268…` (with helper `0xc516…`) directly uses the **instantaneous** reserves of the Pancake V2 WBNB/USDT pair `0x16b9…` inside the very same transaction, without any TWAP, delay, or flash-loan protection. As a result, a single flash-loan and AMM swap can over-mint HYDT against a relatively small WBNB deposit, yielding a net on-chain gain of approximately **7.114672836091882172 BNB-equivalent** for the adversary.


## Key Background

### HYDT token and minting model

HYDT is an ERC20 token deployed at `0x9810512be701801954449408966c630595d0cd51`. The HYDT source code shows:

- Minting is controlled by an `AccessControl`-based role (`CALLER_ROLE`).  
- Only addresses with `CALLER_ROLE` can invoke `mint(to, amount)`.  
- HYDT itself does **not** contain price logic; it simply mints the amount requested by authorized caller contracts.

**Evidence snippet 1 – HYDT mint function (HYDT token source, verified contract `0x9810…`):**

```solidity
// HYDT.sol
bytes32 public constant CALLER_ROLE = keccak256(abi.encodePacked("Caller"));

function mint(address to, uint256 amount)
    external
    override
    onlyRole(CALLER_ROLE)
    returns (bool)
{
    _mint(to, amount);
    return true;
}
```

*Caption: HYDT grants `CALLER_ROLE` to external control contracts and blindly mints the requested `amount` for them; all economic safeguards must therefore reside in those caller contracts, not in HYDT itself.*

In the collected HYDT source, the initializer is expected to grant `CALLER_ROLE` to “Control” and “Earn” style contracts. The analysis artifacts and traces show that the `initialMint` contract `0xA2268…` is one such privileged caller that can mint HYDT on behalf of depositors.

### HYDT initialMint and helper/oracle contracts

Two key contracts front HYDT’s minting:

- **HYDT initialMint / control contract**: `0xA2268Fcc2FE7A2Bb755FbE5A7B3Ac346ddFeDB9B`  
  - Exposes an `initialMint{value: ...}` entry point.  
  - In the exploit trace, it:
    - Reads the WBNB/USDT pair address from Pancake V2 factory `0xcA143Ce3…`.  
    - Calls `PancakePair 0x16b9…::getReserves()`.  
    - Calls `HYDT::mint(0x8f92…, 60961921249934820691479)` and emits an `InitialMint` event capturing depositor, deposit (11 BNB), and minted HYDT amount.

- **HYDT oracle/helper contract**: `0xc5161aE3437C08036B98bDb58cfE6bBfF876c177`  
  - Receives the same 11 BNB via its fallback during `initialMint`.  
  - Also queries the Pancake factory `0xcA143Ce3…` and `PancakePair 0x16b9…::getReserves()`.  
  - Emits an `In(...)` event that logs the depositor (`0xA2268…`), the 11 BNB deposit, and values derived from those reserves.

These two contracts together implement the price-based mint calculation for HYDT’s initial minting flow, based on the external AMM reserves.

### Executor contract and privileged EOA

The executor contract at `0x8f921e27e3af106015d1c3a244ec4f48dbfcad14` is an unverified contract whose disassembly reveals:

- A dispatcher on several custom 4-byte selectors.  
- Hard-coded checks that **`CALLER` and/or `ORIGIN` must equal `0x4645…`**, i.e., the adversary EOA.  
- Logic to build calldata for:
  - Pancake V3 pool `0x92b7…::flash`.  
  - Pancake V3 SwapRouter `0x1b81…` for `exactInputSingle` / `swapExactTokensForTokens`.  
  - WBNB deposit/withdraw operations.  
  - Generic ERC20 `transfer` / `transferFrom` calls.

**Evidence snippet 2 – Executor disassembly showing hard-coded privileged caller (executor `0x8f92…` disassembly):**

```text
// 0x8f92… disassembly
0000007b: JUMPDEST
0000007c: CALLVALUE
...
000000ab: PUSH20 0x4645863205b47a0a3344684489e8c446a437d66c
000000c0: DUP1
000000c1: CALLER
000000c2: EQ
...
000001bd: JUMPDEST
000001be: SWAP1
000001bf: POP
000001c0: ORIGIN
000001c1: EQ
```

*Caption: The executor enforces that the caller/origin is the EOA `0x4645…`, binding the exploit logic to the adversary-controlled account.*

### Pre-state and transaction opportunity

The analysis defines a pre-state `σ_B` as the canonical BSC state immediately before block `0x28fe75f`, including:

- HYDT token `0x9810…`.  
- HYDT initialMint contract `0xA2268…` and helper `0xc516…`.  
- Executor contract `0x8f92…`.  
- Pancake V3 pool `0x92b7…` (USDT/WBNB), Pancake V3 SwapRouter `0x1b81…`.  
- Pancake V2 WBNB/USDT pair `0x16b9…`.  
- Balances and allowances for BEP20USDT `0x55d3…` and WBNB `0xbb4c…`.

Within this pre-state, the exploit is a **single, feasible transaction**:

- EOA `0x4645…` can send a transaction on BSC with standard gas, calling `0x8f92…` with call value `3.050065320913977748 BNB`.  
- All downstream interactions are with permissionless contracts (Pancake pools/routers, HYDT token, `initialMint` and helper contracts, WBNB).

The seed trace confirms that the transaction executes successfully and is included in block `0x28fe75f`.


## Vulnerability & Root Cause Analysis

### High-level vulnerability

The vulnerable design is:

- HYDT’s front-end minting contracts `0xA2268…` (initialMint) and `0xc516…` (helper/oracle) **compute the HYDT mint amount for an `initialMint` deposit using the instantaneous reserves** of the Pancake V2 WBNB/USDT pair `0x16b9…`.  
- These reserves can be **arbitrarily skewed within the same transaction** using flash-loaned USDT.  
- There is no time-weighted averaging, delay, or other flash-loan mitigation.

Consequently, an unprivileged adversary contract can:

1. Borrow USDT via flash-loan.  
2. Trade against `0x16b9…` to distort the WBNB/USDT price.  
3. Immediately call `initialMint` in the same transaction.  
4. Receive far more HYDT than would be minted at the pre-manipulation price.

### Concrete exploit sequence and price oracle misuse

The exploit transaction follows a clear chain of calls and state changes:

1. **USDT flash-loan and initial price impact on `0x16b9…`**
   - Executor `0x8f92…` calls Pancake V3 pool `0x92b7…::flash`, borrowing **12,000,000 USDT**.  
   - Inside the flash callback, `0x8f92…` routes this USDT via Pancake V3 SwapRouter `0x1b81…` into Pancake V2 WBNB/USDT pair `0x16b9…` using `swapExactTokensForTokens([USDT, WBNB])`.  
   - `PancakePair 0x16b9…::swap` transfers **6.735053427848041558630e21 WBNB** to `0x8f92…` and emits a `Sync` event with updated reserves, showing a significant change in the WBNB/USDT ratio.

   **Evidence snippet 3 – Flash-loan and price manipulation of `0x16b9…` (seed transaction trace):**

   ```text
   // Seed tx trace (cast run -vvvvv)
   ├─ 0x92b7807bF19b7DDdf89b706143896d05228f3121::flash(
   │     0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14,
   │     12000000000000000000000000, 0, ...
   │  )
   ...
   │   ├─ PancakePair::swap(
   │   │     amount0In: 12000000000000000000000000,
   │   │     amount1Out: 6735053427848041558630,
   │   │     to: 0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14
   │   ├─ emit Sync(reserve0: 17665016750073905818899339,
   │   │           reserve1: 3187484584912433711217)
   ```

   *Caption: The Pancake V3 flash-loan and subsequent swap heavily alter the WBNB/USDT reserves of pair `0x16b9…` in the same transaction, establishing a manipulated spot price.*

2. **Conversion of WBNB to 11 BNB and call to `initialMint`**
   - After accumulating WBNB, `0x8f92…` calls `WBNB::withdraw(11000000000000000000)` to unwrap **11 BNB**.
   - With those 11 BNB as call value, `0x8f92…` calls `0xA2268…::initialMint{value: 11 BNB}`.
   - Inside `initialMint`:
     - It calls Pancake factory `0xcA143Ce3…::getPair(WBNB, USDT)` to resolve `0x16b9…`.  
     - It then calls `PancakePair 0x16b9…::getReserves()`, receiving the **already manipulated** reserves.  
     - It invokes helper `0xc516…` via `fallback{value: 11 BNB}`, which repeats the factory and `getReserves` calls and emits an `In(...)` event with the 11 BNB deposit and derived values.

   **Evidence snippet 4 – Withdraw and initialMint using manipulated reserves (seed transaction trace):**

   ```text
   // Seed tx trace (cast run -vvvvv)
   ├─ WBNB::withdraw(11000000000000000000)
   │   ├─ emit Withdrawal(src: 0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14,
   │   │                 wad: 11000000000000000000)
   ...
   ├─ 0xA2268Fcc2FE7A2Bb755FbE5A7B3Ac346ddFeDB9B::initialMint{value: 11000000000000000000}()
   │   ├─ 0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73::getPair(WBNB, BEP20USDT)
   │   ├─ PancakePair 0x16b9…::getReserves()
   │   │   └─ ← [Return] 17665016750073905818899339, 3187484584912433711217
   │   ├─ 0xc5161aE3437C08036B98bDb58cfE6bBfF876c177::fallback{value: 11000000000000000000}()
   │   │   ├─ getPair(WBNB, BEP20USDT)
   │   │   ├─ PancakePair 0x16b9…::getReserves()
   │   │   ├─ emit In(0xA2268…, 11000000000000000000, 136341426462748958778, 755603209375080131240403)
   ```

   *Caption: `initialMint` and its helper repeatedly read `0x16b9…` reserves, but they do so **after** the attacker’s price-impacting swap, inheriting the manipulated spot price.*

3. **Over-minting HYDT based on manipulated price**
   - Having read the distorted reserves, `initialMint` calls HYDT:
     - `HYDT::mint(0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14, 60961921249934820691479)`  
   - An `InitialMint` event is emitted with:
     - `param0` (beneficiary): `0x8f92…`  
     - `param1` (deposit): `11000000000000000000` (11 BNB)  
     - `param2` (HYDT minted): `60961921249934820691479` (~60,961.921 HYDT)  
     - `param3`: `1000000000000000000` (1e18)

   **Evidence snippet 5 – HYDT mint and InitialMint event (seed transaction trace):**

   ```text
   // Seed tx trace (cast run -vvvvv)
   ├─ HYDT::mint(0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14,
   │             60961921249934820691479)
   │   ├─ emit Transfer(
   │   │     from: 0x0000000000000000000000000000000000000000,
   │   │     to:   0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14,
   │   │     value: 60961921249934820691479
   │   └─ ← [Return] true
   ├─ emit InitialMint(
   │     param0: 0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14,
   │     param1: 11000000000000000000,
   │     param2: 60961921249934820691479,
   │     param3: 1000000000000000000
   )
   ```

   *Caption: HYDT mints ~60.96k HYDT to the executor for an 11 BNB deposit, with no internal price logic; the mint amount is entirely determined by `initialMint`’s reserve-based calculation.*

4. **Flash-loan sensitivity and missing safeguards**
   - HYDT’s own contract enforces only that callers have `CALLER_ROLE`. It does **not** validate prices or check invariants.  
   - The `initialMint` and helper contracts:
     - Use a **single-block spot price** from an external AMM as a price oracle.  
     - Perform reserve reads **after** the attacker’s flash-loan-driven swap.  
     - Have no TWAP, cross-block delay, or minimum-out requirement tied to pre-manipulation prices.

This combination makes HYDT’s initial minting path *inherently flash-loan-sensitive*: any adversary with access to USDT liquidity via flash-loans and a suitable AMM pool can over-mint HYDT in a single transaction.

### Vulnerable components

From the collected artifacts and traces, the following components are demonstrably involved and vulnerable:

- **HYDT token (`0x9810…`)**  
  - Role-gated minter via `CALLER_ROLE`.  
  - Used as the back-end mint target for `initialMint`.  
  - In the exploit trace, `HYDT::mint(0x8f92…, 60961921249934820691479)` executes successfully.

- **HYDT initialMint contract (`0xA2268…`)**  
  - Exposes `initialMint{value: uint256}`.  
  - Reads Pancake V2 pair `0x16b9…` reserves (via factory `0xcA143Ce3…`).  
  - Calls HYDT `mint` with the amount computed from those reserves, which in the exploit run are manipulated.

- **HYDT helper/oracle contract (`0xc516…`)**  
  - Receives deposit BNB via `fallback{value: ...}`.  
  - Mirrors factory and `getReserves` calls to `0x16b9…`.  
  - Emits the `In(...)` event encoding values derived from the manipulated reserves.

### Exploit preconditions

The exploit is possible under the following concrete conditions (all observed in the artifacts):

- The `initialMint` pathway derives HYDT mint amounts from the **current** spot reserves of Pancake V2 WBNB/USDT pair `0x16b9…`, without TWAP or other cross-block oracle hardening.  
- The `initialMint` contract `0xA2268…` is:
  - Callable by arbitrary senders supplying BNB as `msg.value`.  
  - Granted `CALLER_ROLE` on HYDT, allowing its `HYDT::mint` call to succeed.
- Pancake V2 pair `0x16b9…` has sufficient USDT/WBNB liquidity for a large USDT→WBNB swap to materially shift the price.  
- Pancake V3 pool `0x92b7…` offers flash-loan-like functionality (`flash`) over BEP20USDT `0x55d3…`, enabling the adversary to borrow 12M USDT within a single transaction.

### Security principles violated

The design violates several standard DeFi security principles:

- **Use of manipulable spot AMM price as oracle:**  
  The contracts treat a single-block AMM reserve snapshot (Pancake V2 pair `0x16b9…`) as a trusted oracle for minting a protocol-native asset. This is explicitly discouraged because AMM reserves are trivially manipulable via flash-loans.

- **Missing invariants around minting and AMM interaction:**  
  There is no invariant that ties HYDT minting to robust, cross-block price information or to multiple independent price sources. Instead, minting is tightly coupled to a single pool’s reserves within the same transaction that can trade against that pool.

- **Over-reliance on access control without economic constraints:**  
  While HYDT uses `AccessControl` to restrict minting to `CALLER_ROLE`, it does not constrain the economic behavior of those callers. A misdesigned caller (`0xA2268…`) that bases minting on manipulable AMM reserves effectively undermines the safety of the access control.


## adversary Flow Analysis

### Strategy summary

The adversary’s strategy is to:

1. Use a **USDT flash-loan** to gain temporary, large capital.  
2. **Manipulate the WBNB/USDT price** in Pancake V2 pair `0x16b9…` using that capital.  
3. **Invoke HYDT’s initialMint path** while the manipulated price is in effect to over-mint HYDT to their executor.  
4. **Sell the minted HYDT** into USDT and WBNB across multiple pools.  
5. **Repay the flash-loan** and keep the remaining WBNB as pure profit, returning the original BNB call value to an internal address.

### Adversary-controlled accounts

The artifacts identify an adversary cluster on BSC:

- **EOA `0x4645863205b47a0a3344684489e8c446a437d66c`**
  - Sender of the exploit transaction `0xa9df1b…`.  
  - Hard-coded privileged caller/origin in executor `0x8f92…` (per disassembly).  
  - Ultimate recipient of **10.16806792500585992 WBNB** via `WBNB::transfer` at the end of the exploit trace.  
  - Balance deltas show a net outflow of roughly the initial BNB value minus gas and plus WBNB profit.

- **Executor contract `0x8f921e27e3af106015d1c3a244ec4f48dbfcad14`**
  - Contract called by `0x4645…` in the seed transaction.  
  - Orchestrates:
    - Pancake V3 `flash` call to `0x92b7…`.  
    - Swaps via Pancake V3 SwapRouter `0x1b81…`.  
    - `WBNB::withdraw` to unwrap to BNB.  
    - `0xA2268…::initialMint` to mint HYDT to itself.  
    - HYDT approvals and swaps through various pools.  
    - Final WBNB transfer of profit to `0x4645…` and BNB refund fallback to `0x4848…`.

### Victim and infrastructure contracts

The following contracts are directly involved and/or impacted:

- **HYDT token (`0x9810512be701801954449408966c630595d0cd51`)** – Verified token minting contract that ultimately mints the inflated HYDT supply to the adversary-controlled executor.  
- **HYDT initialMint / control contract (`0xA2268Fcc2FE7A2Bb755FbE5A7B3Ac346ddFeDB9B`)** – Oracle-dependent mint front-end that is granted `CALLER_ROLE` on HYDT and bases its minting logic on AMM reserves.  
- **HYDT oracle/helper contract (`0xc5161aE3437C08036B98bDb58cfE6bBfF876c177`)** – Helper that reads AMM reserves and emits the `In(...)` event used for minting calculations.  
- **Pancake V3 USDT/WBNB pool (`0x92b7807bf19b7dddf89b706143896d05228f3121`)** – Provides the USDT flash-loan used to kick-start the exploit.  
- **Pancake V2 WBNB/USDT pair (`0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae`)** – AMM whose reserves are manipulated and then read by `initialMint` as a price oracle.

### Lifecycle stages

#### Stage 1 – Flash-loan and price manipulation

- **Mechanism:** Pancake V3 `flash` loan and USDT→WBNB swap.  
- **Transaction:** `0xa9df1b…` (block `0x28fe75f`, BSC).

In this stage:

- Executor `0x8f92…` calls `PancakeV3Pool 0x92b7…::flash`, borrowing **12,000,000 USDT**.  
- Within `pancakeV3FlashCallback`, it calls `Pancake V3 SwapRouter 0x1b81…::swapExactTokensForTokens([USDT, WBNB])` targeting the V2 pair `0x16b9…`.  
- `PancakePair 0x16b9…::swap`:
  - Sends **6.735053427848041558630e21 WBNB** to `0x8f92…`.  
  - Emits a `Sync` event with new reserves, confirming a material change in price.

**Evidence snippet 6 – Flash-loan lifecycle and Sync (seed transaction trace):**

```text
└─ PancakePair::swap(
     amount0In: 12000000000000000000000000,
     amount1Out: 6735053427848041558630,
     to: 0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14
   )
   ├─ emit Sync(
   │     reserve0: 17665016750073905818899339,
   │     reserve1: 3187484584912433711217
   │   )
```

*Caption: The Sync event on `0x16b9…` reflects the post-manipulation reserves from which the subsequent `initialMint` price is derived.*

#### Stage 2 – Mispriced HYDT mint via initialMint

- **Mechanism:** Spot-reserve-based oracle used to calculate mint amount.  
- **Transaction:** Same as Stage 1 (`0xa9df1b…`).

Actions observed:

- `0x8f92…` unwraps part of its WBNB position:
  - `WBNB::withdraw(11000000000000000000)` → obtains 11 BNB (see snippet 4).  
- It then calls `0xA2268…::initialMint{value: 11 BNB}`.  
- Inside `initialMint` and helper `0xc516…`:
  - `getPair(WBNB, USDT)` returns `0x16b9…`.  
  - `getReserves()` returns the manipulated reserve values.  
  - `In(...)` event is emitted with the deposit and computed parameters.  
- Finally, `HYDT::mint(0x8f92…, 60961921249934820691479)` is executed and `InitialMint` is emitted with the same HYDT amount.

This stage is where the protocol bug manifests: the minting logic trusts the current reserves of `0x16b9…` without any flash-loan-resistant design.

#### Stage 3 – HYDT sell-off, loan repayment, and profit realization

- **Mechanism:** HYDT dumping via multiple pools and flash-loan repayment.  
- **Transaction:** Same as Stage 1 (`0xa9df1b…`).

The executor then unwinds its position:

- Approves Pancake V3 SwapRouter `0x1b81…` to spend HYDT.  
- Routes HYDT through a series of pools:
  - V3 pool at `0xD5f0…`: swaps **21,578.592647575947411327 HYDT** for **20,801.440045608164984189 USDT**.  
  - V2 pair at `0xBB8a…`: swaps **23,629.997161415323968091 HYDT** for **12.421323513597163913 WBNB**.  
  - Another pool at `0x03fe…`: swaps **15,753.331440943549312061 HYDT** for **4,719.617398612016169843 USDT**.
- Uses the resulting USDT and part of the WBNB position to:
  - Pay **12,001,200 USDT** back to Pancake V3 pool `0x92b7…` as flash-loan repayment plus fee.  
- Leaves **10.16806792500585992 WBNB** with `0x8f92…`, which is then transferred to the EOA `0x4645…`.  
- A final fallback with `value: 3.050065320913977748 BNB` to `0x4848…` returns the original call value, closing the position.

**Evidence snippet 7 – Final WBNB transfer to EOA and balance deltas (trace + balance_diff):**

```text
// Seed tx trace (end of execution)
├─ WBNB::transfer(0x4645863205b47a0A3344684489e8c446a437D66C,
│                10168067925005859920)
│   ├─ emit Transfer(
│   │     from: 0x8f921E27e3AF106015D1C3a244eC4F48dBFcAD14,
│   │     to:   0x4645863205b47a0A3344684489e8c446a437D66C,
│   │     value: 10168067925005859920
│   )
```

```json
// Seed balance_diff.json (selected entries)
{
  "native_balance_deltas": [
    {
      "address": "0x4645863205b47a0a3344684489e8c446a437d66c",
      "before_wei": "93096695723533900889",
      "after_wei":  "90043300634619923141",
      "delta_wei":  "-3053395088913977748"
    },
    {
      "address": "0x4848489f0b2bedd788c696e2d79b6b69d7484848",
      "delta_wei": "3050065320913977748"
    }
  ],
  "erc20_transfers": [
    {
      "token": "0x9810512be701801954449408966c630595d0cd51",
      "from":  "0x0000000000000000000000000000000000000000",
      "to":    "0x8f921e27e3af106015d1c3a244ec4f48dbfcad14",
      "value": "60961921249934820691479"
    },
    {
      "token": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "from":  "0x8f921e27e3af106015d1c3a244ec4f48dbfcad14",
      "to":    "0x4645863205b47a0a3344684489e8c446a437d66c",
      "value": "10168067925005859920"
    }
  ]
}
```

*Caption: The final WBNB transfer to `0x4645…` and the native balance deltas show the adversary exiting with WBNB profit while recovering the original BNB call value at an internal address.*

### Economic outcome and impact

Using BNB as the reference asset and treating WBNB as BNB-equivalent (consistent with observed `WBNB::withdraw` calls), the analysis concludes:

- **Reference asset:** BNB.  
- **Adversary address:** `0x4645863205b47a0a3344684489e8c446a437d66c`.  
- **Gas fees:** `0.003329768` BNB (from 3,329,768 gas at 1 gwei).  
- **Call value sent to executor:** `3.050065320913977748` BNB.  
- **WBNB received back:** `10.16806792500585992` WBNB (transfer to `0x4645…`).  

Net BNB-equivalent change attributable to this transaction:

```text
10.16806792500585992  (WBNB out to adversary)
− 3.050065320913977748 (initial BNB call value)
− 0.003329768          (gas fees)
= 7.114672836091882172 BNB
```

This is a strictly positive on-chain gain, computed solely from intra-transaction flows (trace and balance diffs), without relying on any external price feeds.

In terms of protocol impact:

- **HYDT dilution:** 60,961.921249934820691479 HYDT are minted to an adversary-controlled contract based on a temporarily distorted AMM price.  
- **Value transfer:** Economic value is transferred from HYDT holders and/or the protocol treasury (depending on HYDT’s design) to the adversary.  
- **Reproducibility:** As long as the `initialMint` path remains available and continues to rely on the same manipulable AMM reserves, the attack is **permissionless and reproducible** by any party capable of executing similar flash-loan and swap sequences.


## References

The following artifact groups underpin the above analysis. They are not required to understand the report but can be consulted for independent verification:

- **[1] Seed transaction metadata, trace, and balance diffs**  
  - Source: seed artifacts for tx `0xa9df1b…` (metadata, `trace.cast.log`, `balance_diff.json`).  
  - Content: Full transaction trace (cast run with high verbosity), pre/post balances, and gas usage.

- **[2] HYDT token source and ABI**  
  - Source: Collected project for HYDT token `0x9810512be701801954449408966c630595d0cd51`.  
  - Content: Solidity source (`HYDT.sol` and interfaces) and compiled ABI, confirming the `CALLER_ROLE`-gated `mint` function.

- **[3] Executor `0x8f92…` disassembly and selector decoding**  
  - Source: Disassembly logs and decoded selectors for executor contract `0x8f921e27e3af106015d1c3a244ec4f48dbfcad14`.  
  - Content: Bytecode-level control flow and hard-coded privileged caller/origin address `0x4645…`, along with references to Pancake pools/routers, WBNB, and generic ERC20 calls used in the exploit.

