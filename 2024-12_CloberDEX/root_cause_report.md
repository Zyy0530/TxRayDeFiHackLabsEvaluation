# Clober Rebalancer WETH/0xd3c8 Pool Drain via Attacker‑Controlled Token and Flash‑Loan Mint/Burn (Base, chainid 8453)

## Metadata

- **Protocol name:** Clober v2 Rebalancer  
- **Incident category:** protocol_bug  
- **ACT candidate:** `is_act = true` (single adversary‑crafted tx satisfying a clear profit predicate)

This report analyzes exploit transaction `0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04` on Base (chainid 8453), where a Clober Rebalancer pool pairing WETH9 with an attacker‑controlled ERC20 (`0xd3c8d0cd07Ade92df2d88752D36b80498cA12788`) is drained of 133.7 WETH9 backing via a flash‑loan‑funded mint/burn sequence.

## Incident Overview & TL;DR

**Incident brief**

On Base (8453), an unprivileged adversary cluster consisting of:

- EOA `0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025`, and  
- Attacker contract `0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1`

executes a single flash‑loan‑funded transaction `0x8fcdfc...c04` that drains **133.7 WETH9** from a Clober v2 Rebalancer pool pairing WETH9 (`0x4200…0006`) with attacker‑controlled token `0xd3c8d0cd07Ade92df2d88752D36b80498cA12788`.

The attacker:

- Borrows **267.4 WETH9** via Morpho.  
- Uses token `0xd3c8…` and Rebalancer’s mint/burn logic to reduce the WETH9 reserves backing the pool’s LP supply by exactly **133.7 WETH9**.  
- Repays the flash loan.  
- Withdraws the surplus as native ETH and sends it to the EOA `0x012F…6025`.

**Root cause brief**

Rebalancer and BookManager treat an attacker‑controlled ERC20 (`0xd3c8…`) as a fully trusted pool asset in WETH9/0xd3c8 LP accounting.

Because:

- The ERC20 is controlled by the attacker contract and can arbitrarily mint, and  
- LP accounting and BookManager currency deltas do not enforce a hard conservation constraint that ties WETH9 reserves to honest value on the 0xd3c8 side,

the adversary can, in a single flash‑loan‑triggered `open/mint/rebalance/burn` sequence, mint `0xd3c8…` both to Rebalancer and to themselves at no ETH cost, while extracting **133.7 WETH9 more than contributed**. Subsequent LP `burn()` calls for this pool become insolvent on the WETH9 side and revert.

## Key Background

### Core contracts and roles

- **BookManager (`0x382C…6776`)**  
  Clober v2 BookManager manages orderbooks and *currency deltas* for base/quote token pairs. It exposes a `lock()` + `settle()` interface; lockers must leave all currency deltas at zero after their operations.

- **Rebalancer (`0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895`)**  
  Rebalancer sits on top of BookManager, opening pools for token pairs (here WETH9 and `0xd3c8…`), minting ERC6909 LP tokens, and using strategies such as SimpleOracleStrategy to place and clear orders. Its `burn()` function relies on:
  - Internal reserves, plus  
  - BookManager currency deltas,  
  to redeem LP shares into underlying tokens.

- **SimpleOracleStrategy (`0x9092…dda5`)**  
  A strategy contract computing desired order sizes from an oracle and Clober tick math. It never moves tokens directly; custody is always via Rebalancer and BookManager.

**Rebalancer contract snippet (verified source on Base)**

_Origin: Collected verified Rebalancer.sol for `0x6A0b87…F3895` (Base chain)._

```solidity
// Collected Clober Rebalancer implementation (excerpt)
contract Rebalancer is IRebalancer, ILocker, Ownable2Step, ERC6909Supply {
    using BookIdLibrary for IBookManager.BookKey;
    using SafeERC20 for IERC20;

    IBookManager public immutable bookManager;

    mapping(bytes32 key => Pool) private _pools;
    mapping(BookId => BookId) public bookPair;
    // ...
}
```

This structure confirms that each pool is keyed only by token addresses and strategy parameters, and that Rebalancer manages LP issuance/redemption while delegating orderbook storage and currency deltas to BookManager.

### Attacker‑controlled token 0xd3c8…

Token `0xd3c8d0cd07Ade92df2d88752D36b80498cA12788` acts like an ERC20:

- Its **slot 0** stores an owner/admin address, and  
- Its **slot 1 mapping** records balances for addresses such as Rebalancer.

Collected storage for slot 0 shows that the owner is the attacker contract:

_Origin: Collected storage read (slot 0) for token `0xd3c8…` at the exploit block._

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x00000000000000000000000032fb1bedd95bf78ca2c6943ae5aeaeaafc0d97c1"
}
```

This proves that `0x32Fb1B…97C1` controls the token.

State diffs around the exploit transaction show that, within a single tx, the slot‑1 balance mapping for:

- Rebalancer `0x6A0b87…F3895`, and  
- Attacker contract `0x32Fb1B…97C1`

are both increased without any ETH inflow, confirming that 0xd3c8… can mint arbitrarily in‑tx to both the pool and the attacker.

### Summary of preliminary knowledge

- BookManager enforces settlement of currency deltas to zero but trusts the ERC20s themselves.  
- Rebalancer’s pool logic, including LP `mint()` and `burn()`, assumes that both tokens in a pair (here WETH9 and 0xd3c8…) are honest, externally priced assets.  
- SimpleOracleStrategy configures order placement but does not add custody checks.  
- Token `0xd3c8…` is fully attacker‑controlled and can mint balances at will, including to Rebalancer, within a single transaction and without external collateral.

## ACT Opportunity and Exploit Predicate

### Pre‑state and block

- **Block height B:** `23514451` on Base (chainid 8453).  
- **Pre‑state `σ_B`:** The Base chain state immediately before block 23514451, including:
  - Rebalancer `0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895`,  
  - BookManager `0x382CCccbD3b142D7DA063bF68cd0c89634767F76`,  
  - WETH9 `0x4200000000000000000000000000000000000006`,  
  - Attacker contract `0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1`,  
  - Attacker‑controlled token `0xd3c8d0cd07Ade92df2d88752D36b80498cA12788`, and  
  - Strategy `0x9092e5f62b27c3ed78feb24a0f2ad6474d26dda5`,  
  as they stood immediately before tx `0x8fcdfc…c04`.

This pre‑state is supported by:

- Seed transaction metadata for the exploit tx.  
- A prestateTracer state diff around the exploit tx.  
- Historical txlists for the attacker EOA and attacker contract, confirming deployment, ownership, and prior interactions.

### Transaction sequence starting from σ_B

There is a single adversary‑crafted transaction in the relevant sequence:

1. **Tx index 1 – exploit transaction**
   - `chainid`: `8453`  
   - `txhash`: `0x8fcdfc…c04`  
   - `type`: `adversary-crafted`  
   - **Inclusion feasibility:**  
     Signed and sent by unprivileged EOA `0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025` with a standard gas price and no special permissions. Any adversary can:
     - Deploy the same attacker contract,  
     - Configure the same Rebalancer pool and strategy, and  
     - Submit the same flash‑loan‑funded transaction starting from `σ_B`.
   - **Notes:**  
     A single‑tx flash‑loan exploit that:
     - Borrows **267.4 WETH9** from Morpho,  
     - Uses attacker‑controlled token `0xd3c8…` in a Clober Rebalancer WETH9/0xd3c8 pool to execute an `open/mint/rebalance/burn` sequence, and  
     - Repays the flash loan and withdraws a net **133.7 WETH9** to the attacker EOA.

### Exploit predicate: profit in ETH

- **Type:** `profit`  
- **Reference asset:** ETH  
- **Adversary address (cluster representative):** `0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025`

**Portfolio values (ETH‑equivalent, chainid 8453):**

- `value_before_in_reference_asset = 1.153475443767715212` ETH  
- `value_after_in_reference_asset  = 134.693976726830078597` ETH  
- `fees_paid_in_reference_asset    = 0.159498624789241704` ETH (gas fees from tx receipt)  
- `value_delta_in_reference_asset  = 133.540501283062363385` ETH (net profit after fees)

**Valuation method:**

- The cluster’s portfolio is computed by summing native ETH and WETH9‑backed balances.  
- Pre/post native balances for `0x012F…6025` are taken from a balance‑diff artifact and the prestateTracer diff; the attacker contract `0x32Fb1B…97C1` has zero native balance both before and after.  
- WETH9 `Transfer` logs for the exploit tx show:
  - A net **+133.7 WETH9** to the adversary cluster, and  
  - A matching **–133.7 WETH9** from WETH9’s underlying native backing.  
- Gas usage and gas price from the tx receipt yield the fee amount above.

The adversary’s ETH‑denominated portfolio value strictly increases by **133.540501283062363385 ETH**, and the cluster also gains additional 0xd3c8… units, so the profit predicate is satisfied.

The **non‑monetary** oracle fields (`oracle_name`, `oracle_definition`, `oracle_evidence`) are intentionally empty, as no non‑monetary predicate is needed.

## Vulnerability & Root Cause Analysis

### Vulnerability brief

The vulnerable pool is a Rebalancer WETH9/0xd3c8 pool in which:

- The non‑WETH asset (`0xd3c8…`) is fully attacker‑controlled and can mint arbitrarily.  
- Rebalancer’s mint/burn logic and BookManager’s currency‑delta tracking treat the resulting WETH9/0xd3c8 position as fully backed.  

This allows a single flash‑loan transaction to withdraw **133.7 WETH9 more than contributed**, while leaving LP supply and 0xd3c8 balances intact, thereby breaking the expected conservation of WETH9 backing for LPs.

### Root cause detail

1. **Pool creation and trust boundary**
   - Verified Rebalancer and BookManager code show that pools are created from token addresses and strategy parameters only.  
   - There is no restriction requiring:
     - Protocol ownership of either asset, or  
     - Immutability / external price source guarantees.  
   - As a result, the WETH9/0xd3c8 pool pairs WETH9 with a fully attacker‑controlled ERC20.

2. **Attacker control over 0xd3c8…**
   - Token `0xd3c8…` is controlled by attacker contract `0x32Fb1B…97C1` (confirmed by slot 0 storage).  
   - Its balance mapping at slot 1 records balances for addresses including Rebalancer and the attacker contract.  
   - PrestateTracer state diff for the exploit tx shows that:
     - The balance entry for Rebalancer `0x6A0b87…F3895` at slot 1 increases from `0` to `2.674e20` (i.e., 267.4 units).  
     - The balance entry for the attacker contract `0x32Fb1B…97C1` increases from `1.0e22` to `1.01337e22` (i.e., an additional 133.7 units).  
   - These increases occur within the exploit tx and are not backed by any ETH inflow, demonstrating arbitrary in‑tx minting to both the pool and the attacker.

3. **WETH9 inflow/outflow mismatch**
   - WETH9 `Transfer` logs and the debug trace of the exploit tx show that:
     - The attacker borrows **267.4 WETH9** from Morpho.  
     - The attacker sends **267.4 WETH9** into Rebalancer as part of the mint/rebalance/burn sequence.  
     - Rebalancer sends **401.1 WETH9** out to the attacker (equal to 267.4 + 133.7).  
     - The attacker repays **267.4 WETH9** to Morpho and finally unwraps WETH9 to native ETH into the EOA.

   _Origin: Debug call trace for exploit tx `0x8fcdfc…c04` (Base)._

   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "result": {
       "calls": [
         {
           "from": "0x32fb1bedd95bf78ca2c6943ae5aeaeaafc0d97c1",
           "to": "0x4200000000000000000000000000000000000006",
           "type": "STATICCALL",
           "input": "0x70a08231…",   // WETH9.balanceOf(Rebalancer)
           "output": "…"
         },
         {
           "from": "0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb",
           "to": "0x4200000000000000000000000000000000000006",
           "type": "CALL",
           "input": "0xa9059cbb…",   // Morpho -> attacker (267.4 WETH9)
           "logs": [
             {
               "address": "0x4200000000000000000000000000000000000006",
               "topics": ["Transfer", "…Morpho", "…attacker"]
             }
           ]
         },
         {
           "calls": [
             {
               "from": "0x6a0b87d6b74f7d5c92722f6a11714dbeda9f3895",
               "to": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
               "type": "CALL",
               "input": "0xa9059cbb…", // Rebalancer -> attacker, WETH9.transfer
               "logs": [ "Transfer 401.1 WETH9 to attacker cluster" ]
             }
           ]
         }
       ]
     }
   }
   ```

   Combined with the state diff for WETH9’s underlying native balance, this establishes a **net 133.7 WETH9 loss** from WETH9’s backing and a matching gain for the adversary.

4. **BookManager currency delta settlement**
   - BookManager’s design requires that, over a `lock()`/`settle()` cycle, currency deltas for each currency are brought back to zero.  
   - The exploit tx completes without reverting at the BookManager level, confirming that all currency deltas—including for WETH9 and 0xd3c8…—are internally consistent according to its accounting rules.
   - Therefore, the only consistent interpretation is that Rebalancer’s internal pool representation and LP accounting allow attacker‑controlled 0xd3c8… balances to stand in for genuine value on one side of the pair, enabling an honest‑looking settlement of deltas while WETH9 reserves are actually under‑collateralized.

5. **Broken invariant as seen by victims**
   - After the exploit, LP holder `0x919dF0eD50391F58D50A69fA68e2F5dC5907d1ce` attempts to call Rebalancer `burn()` for this WETH9/0xd3c8 pool.
   - In both victim txs (`0x2d91df5b…bafb` and `0x7cc6b347…905f`), the call trace shows:
     - Rebalancer unwinding orders via BookManager, and  
     - A subsequent call to WETH9 `transfer(0x919dF0eD…, amount)` that **reverts** with `"ERC20: transfer amount exceeds balance"`.

   _Origin: Debug call trace for victim burn tx `0x2d91df5b…bafb`._

   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "result": {
       "calls": [
         {
           "from": "0x6a0b87d6b74f7d5c92722f6a11714dbeda9f3895",
           "to": "0x4200000000000000000000000000000000000006",
           "type": "CALL",
           "input": "0xa9059cbb…",  // WETH9.transfer(0x919dF0eD…, amount)
           "error": "execution reverted"
         }
       ]
     }
   }
   ```

   This proves that the invariants “LP `burn()` is fully collateralized by pool WETH9 reserves” and “BookManager currency deltas plus internal reserves cover LP redemptions” are **violated** as a direct consequence of the exploit sequence.

### Vulnerable components

- **Rebalancer (`0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895`)**  
  Functions `open()`, `mint()`, `_burn()`, `_settleCurrency()`, and the LP accounting for the WETH9/0xd3c8 pool key `0xc8cbe608c82ee9c4c30f01d7c0eefd977538ac396ed34430aa3993bfe0d363ae` are involved.

- **BookManager (`0x382CCccbD3b142D7DA063bF68cd0c89634767F76`)**  
  Currency delta tracking and `settle()`/`withdraw()` integration with Rebalancer for WETH9 and 0xd3c8 in book IDs `0x87a120` and `0x87a184`.

- **SimpleOracleStrategy (`0x9092…dda5`)**  
  Strategy configuration for this WETH9/0xd3c8 pool, relying on token decimals and oracle prices while implicitly assuming that 0xd3c8 behaves like a standard asset.

- **Attacker‑controlled ERC20 (`0xd3c8d0cd07Ade92df2d88752D36b80498cA12788`)**  
  Used as the non‑WETH side of the pool despite being fully controlled by the adversary contract.

### Exploit preconditions

The exploit requires that:

1. A Rebalancer pool is created for WETH9 (`0x4200…0006`) paired with attacker‑controlled ERC20 `0xd3c8…` **without any whitelist or provenance checks** on the non‑WETH token.  
2. The attacker can deploy and control token `0xd3c8…` such that its slot‑1 balance mapping for Rebalancer and the attacker can be increased within a single transaction, **without any ETH or trusted collateral inflow**.  
3. The WETH9/0xd3c8 pool is configured with SimpleOracleStrategy and BookManager such that LP `mint()`/`burn()` mechanics rely on internal reserves plus orderbook liquidity but do **not** enforce a strict conservation constraint binding WETH9 reserves to attacker‑controlled 0xd3c8 balances.  
4. A flash‑loan provider (Morpho `0xBBBB…FCb`) is available to lend the WETH9 principal needed so the exploit can be conducted atomically and repaid within the same transaction.

### Security principles violated

- **Trust boundary between protocol‑owned and attacker‑controlled tokens**  
  The system treats 0xd3c8… as a normal reserve asset, despite it being mintable by the adversary.

- **Conservation of WETH9 value in the pool**  
  LP `burn()` is expected to be fully collateralized by WETH9 reserves. After the exploit, the pool becomes under‑collateralized by exactly 133.7 WETH9.

- **Assumption of honest ERC20 behavior in strategies**  
  Strategies and LP accounting assume that any ERC20 paired with WETH9 behaves like a standard, externally priced asset, rather than being fully attacker‑controlled.

## Adversary Flow Analysis

### Adversary‑related accounts

**Adversary cluster**

1. **EOA `0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025` (Base, 8453)**  
   - `is_eoa = true`, `is_contract = false`  
   - Sender of:
     - The deployment tx `0x4fe2383c…0290` for the attacker contract, and  
     - The exploit tx `0x8fcdfc…c04`.  
   - Receives the final **133.7 ETH‑equivalent** withdrawn from WETH9 after unwrapping.

2. **Attacker contract `0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1` (Base, 8453)**  
   - `is_eoa = false`, `is_contract = true`  
   - Deployed by `0x012F…6025` and used as:
     - Receiver of the Morpho flash loan, and  
     - Caller into Rebalancer.  
   - Owns token `0xd3c8…` via slot‑0 storage and orchestrates the `open/mint/rebalance/burn` sequence.

3. **Attacker‑controlled ERC20 `0xd3c8d0cd07Ade92df2d88752D36b80498cA12788` (Base, 8453)**  
   - `is_eoa = false`, `is_contract = true`  
   - Slot‑0 owner is `0x32Fb1B…97C1`.  
   - Slot‑1 balance mapping mints:
     - **267.4 tokens to Rebalancer**, and  
     - **133.7 tokens to the attacker contract**,  
     during the exploit tx, with no ETH inflow.

**Victim and protocol components**

1. **Clober Rebalancer** – `0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895` (Base, 8453), verified.  
2. **Clober BookManager** – `0x382CCccbD3b142D7DA063bF68cd0c89634767F76` (Base, 8453), verified.  
3. **SimpleOracleStrategy** – `0x9092e5f62b27c3ed78feb24a0f2ad6474d26dda5` (Base, 8453), verified.  
4. **WETH9** – `0x4200000000000000000000000000000000000006` (Base, 8453), verified.  
5. **Victim LP holder** – `0x919dF0eD50391F58D50A69fA68e2F5dC5907d1ce` (Base, 8453), `is_verified = unknown`, but clearly observed as the LP attempting burn() calls that revert.

### Lifecycle stages

#### 1. Adversary contract deployment and token control

- **Tx:** `0x4fe2383c6dc0f03e53ea5ad4dd3b87c058c960234e57855fb49a9935a810a290` (Base, 8453, block 23514451)  
- **Mechanism:** other  

Effect:

- EOA `0x012F…6025` deploys attacker contract `0x32Fb1B…97C1`.  
- Later storage of token `0xd3c8…` shows `0x32Fb1B…97C1` as slot‑0 owner/admin.  
- This establishes that the adversary controls both:
  - The execution contract that will call Rebalancer, and  
  - The ERC20 used as the pool’s non‑WETH asset.

Evidence used:

- Txlist for `0x012F…6025`, including the attacker‑contract deployment tx.  
- Storage read of token `0xd3c8…` slot 0 confirming owner `0x32Fb1B…97C1`.

#### 2. Exploit execution via flash‑loan mint/rebalance/burn

- **Tx:** `0x8fcdfc…c04` (Base, 8453, block 23514451)  
- **Mechanism:** `flashloan`  

Effect (per debug trace, state diff, and Rebalancer code):

1. The attacker contract obtains a **267.4 WETH9** flash loan from Morpho (`0xBBBB…FCb`).  
2. Using `open()` and `mint()` on Rebalancer, it creates and mints into a WETH9/0xd3c8 pool governed by SimpleOracleStrategy.  
3. Within this sequence, token `0xd3c8…`:
   - Mints **267.4 units** to Rebalancer, and  
   - Mints **133.7 units** to the attacker contract,  
   at no ETH cost, as proven by the state diff and slot‑1 mapping layout.  
4. The attacker immediately calls `burn()` on the Rebalancer LP. BookManager and Rebalancer treat the 0xd3c8 balances as real value and clear book positions accordingly.  
5. Rebalancer sends **401.1 WETH9** to the attacker (267.4 + 133.7), while it only received 267.4 WETH9 from the attacker earlier in the tx.  
6. The attacker repays **267.4 WETH9** to Morpho and unwraps the remaining 133.7 WETH9 to ETH, sending it to EOA `0x012F…6025`.

Evidence used:

- **Debug_callTracer trace** for `0x8fcdfc…c04`, showing:
  - Flash loan from Morpho,  
  - WETH9 transfers into and out of Rebalancer, and  
  - Unwrap of WETH9 to native ETH.  
- **PrestateTracer state diff** for the same tx, showing:
  - 0xd3c8 balance mapping entries for Rebalancer and attacker increasing by 267.4 and 133.7 respectively, and  
  - WETH9’s underlying balance decreasing by 133.7e18 wei.  
- **Rebalancer.sol** (verified) for `0x6A0b87…F3895`, confirming that the observed call sequence aligns with `open()`, `mint()`, and `burn()` flows and that it relies on BookManager’s currency deltas without additional trust checks on 0xd3c8….

#### 3. Victim LP burn failures

- **Tx 1:** `0x2d91df5bc6d8f7733331aad5fc986dbf3d6c42948ae135e7205b8714efcbbafb` (Base, 8453, block 23514825)  
- **Tx 2:** `0x7cc6b3475f2ed221110e232a53819a989e2cc27c3a66d7a4e74b854b2754905f` (Base, 8453, block 23514835)  
- **Mechanism:** `other`  

Effect:

- LP holder `0x919dF0eD…` attempts to burn Rebalancer LP for the **same WETH9/0xd3c8 pool key** used in the exploit.  
- In both transactions, the call trace shows that:
  - Rebalancer unwinds orders through BookManager, and  
  - Then calls `WETH9.transfer(0x919dF0eD…, amount)`.  
- WETH9 **reverts** with `"ERC20: transfer amount exceeds balance"`, indicating that the WETH9 reserves at the Rebalancer/BookManager side are insufficient to cover the LP’s claim.

Evidence used:

- Debug_callTracer traces for both victim txs, each showing the final WETH9 `transfer` call reverting with `ERC20: transfer amount exceeds balance`.  
- Correlation with the prior exploit tx’s WETH9 and 0xd3c8 state changes, confirming that the under‑collateralization arises directly from the earlier flash‑loan attack.

These stages together describe an end‑to‑end adversary flow: contract deployment and control, the exploit execution, and the observable impact on honest LPs.

## Impact & Losses

### Quantified losses

- **Token:** WETH (WETH9 on Base, `0x4200…0006`)  
- **Amount:** `133.7` WETH

### Impact summary

- The WETH9/0xd3c8 Rebalancer pool loses **133.7 WETH9** of backing relative to its LP supply.  
- This is evidenced by:
  - WETH9 `Transfer` logs in the exploit tx,  
  - Native balance diffs for WETH9 (and the adversary EOA), and  
  - Subsequent WETH9 `transfer` reverts in victim LP `burn()` attempts.
- At least one LP address, `0x919dF0eD50391F58D50A69fA68e2F5dC5907d1ce`, is unable to redeem WETH9 from this pool.  
- Other Clober pools and system components do **not** show observable impact in the traces and artifacts reviewed.

## References

Key supporting artifacts used in this analysis include:

1. **[1] Exploit tx debug trace and state diff (`0x8fcdfc…c04`)**  
   - A debug_callTracer execution trace and a prestateTracer state diff for the exploit transaction on Base (8453).  
   - Used to reconstruct:
     - The flash‑loan flow through Morpho,  
     - WETH9 transfers into and out of Rebalancer,  
     - 0xd3c8 balance mapping updates for Rebalancer and the attacker, and  
     - Net WETH9 and native balance changes.

2. **[2] Rebalancer.sol and BookManager.sol verified source**  
   - Verified source code for Rebalancer `0x6A0b87…F3895` and BookManager `0x382C…6776` on Base.  
   - Used to confirm:
     - How pools are keyed and opened,  
     - How LP mint/burn interacts with BookManager and currency deltas, and  
     - That no trust boundary exists preventing an attacker‑controlled ERC20 from being used as the non‑WETH side of a pool.

3. **[3] 0xd3c8… token storage and owner control**  
   - Storage reads for token `0xd3c8d0c…2788`, including slot 0 (owner/admin) and slot‑1 balance mapping entries.  
   - Used to establish attacker control over the token and to quantify the minted balances (267.4 to Rebalancer and 133.7 to the attacker) during the exploit tx.

## All Relevant Transactions (Summary)

The analysis considers the following on‑chain transactions on Base (chainid 8453):

1. `0x4fe2383c6dc0f03e53ea5ad4dd3b87c058c960234e57855fb49a9935a810a290` – **related**  
   - Attacker contract deployment by EOA `0x012F…6025`.

2. `0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04` – **adversary-crafted**  
   - Single‑tx flash‑loan exploit draining 133.7 WETH9 from the WETH9/0xd3c8 Rebalancer pool.

3. `0x2d91df5bc6d8f7733331aad5fc986dbf3d6c42948ae135e7205b8714efcbbafb` – **victim-observed**  
   - Post‑incident LP `burn()` attempt by `0x919dF0eD…` that reverts in WETH9 `transfer`.

4. `0x7cc6b3475f2ed221110e232a53819a989e2cc27c3a66d7a4e74b854b2754905f` – **victim-observed**  
   - Subsequent LP `burn()` attempt by the same LP address, also reverting in WETH9 `transfer`.

Together, these transactions and the associated code and storage evidence fully support the root cause conclusion: **the protocol’s LP accounting and currency‑delta model permit an attacker‑controlled ERC20 to be used as a trusted reserve asset, enabling a flash‑loan‑funded mint/burn sequence that drains 133.7 WETH9 and leaves honest LPs insolvent.**

