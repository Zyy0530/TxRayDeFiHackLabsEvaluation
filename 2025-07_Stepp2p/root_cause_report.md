# Stepp2p USDT Escrow Drain via Double-Withdraw Bug on BNB Chain

## 1. Incident Overview TL;DR

On BNB Chain (chainid 56), the Stepp2p escrow contract at `0x99855380e5f48db0a6babeae312b80885a816dce` suffered a deterministic protocol bug that allowed an adversary to withdraw the same USDT escrowed amount twice in a single transaction.

In transaction `0xe94752783519da14315d47cde34da55496c39546813ef4624c94825e2d69c6a8` (block `54653987`), an attacker-controlled helper contract `0x399eff46b7d458575ebbbb572098e62e38f3c993` used a 50,000 USDT flash loan from Pancake V3 pool `0x4f31fa980a675570939b737ebdde0471a4be40eb` to:
- Call `Stepp2p.createSaleOrder(43_782.4059282857)` to create a new sale `saleId = 4796`, depositing `43_782.4059282857` USDT into Stepp2p.
- Immediately call `Stepp2p.cancelSaleOrder(4796)` and then `Stepp2p.modifySaleOrder(4796, 43_782.4059282857, false)` within the same transaction.

Because of a logic bug in Stepp2p’s sale lifecycle, the contract transferred `43_782.4059282857` USDT to the attacker contract on `cancelSaleOrder` and another `43_782.4059282857` USDT on `modifySaleOrder`, even though only one such amount had been deposited. The second withdrawal was funded entirely by Stepp2p’s pre-existing escrowed balance belonging to prior sellers. After repaying the flash loan plus a 25 USDT fee, the attacker contract retained `43_757.4059282857` USDT.

In a follow-up transaction `0xe716c763310532a8768fd6489ccea211ba30ed71cdad8ba806ee88535f7d529a` (block `54655876`), EOA `0xd3f0cf7445b223060ce23dbc1c42f8338d1c2c49` called the helper contract to swap the `43_757.4059282857` USDT into `58.704346449303744276` WBNB on PancakeSwap, realizing the profit.

Overall, Stepp2p’s escrow balance in USDT went from `43_782.4059282857` to `0` in the exploit transaction, and this entire amount was diverted out of the protocol’s escrow and into attacker-controlled addresses, minus the 25 USDT flash-loan fee.

## 2. Key Background

Stepp2p is an Ownable, ReentrancyGuard escrow contract for BEP20 USDT (`0x55d398326f99059ff775485246999027b3197955`) deployed on BNB Chain (chainid 56). It maintains per-sale escrow positions in a `sales` mapping indexed by `saleId`, with each `Sale` struct containing:
- `seller`: address that owns the sale and escrowed funds.
- `totalAmount`: total nominal amount associated with the sale.
- `remaining`: the amount of USDT still available to be sold or refunded.
- `receivedFee`: fees already collected on this sale.
- `sellFee`: fee rate in basis points / 10.
- `active`: a boolean indicating whether the sale is considered active.

The contract also tracks seller-centric indices:
- `sellerSales[address]`: array of saleIds created by each seller.
- `lastSellerSaleId[address]`: last saleId per seller.
- `lastSaleId`: global last saleId.

The core escrow flow is:
- `createSaleOrder(amount)`: transfers `amount` USDT from `msg.sender` to Stepp2p, computes and transfers any fee to `feeAccount`, stores a new `Sale` with `seller = msg.sender`, `totalAmount = amount`, `remaining = amount - fee`, and `active = true`, and emits `SaleRegistered`.
- `cancelSaleOrder(saleId)`: intended to allow the seller (or the contract owner) to cancel an active sale, returning the `remaining` amount (and possibly an associated fee refund) to the seller and marking the sale as inactive.
- `modifySaleOrder(saleId, modifyAmount, isPositive)`: intended to let the seller adjust the sale. When `isPositive = true`, the seller deposits more USDT to increase `totalAmount` and `remaining`. When `isPositive = false`, the function reduces `totalAmount` and `remaining` and transfers `modifyAmount` USDT back to `msg.sender`.

The *intended invariant* is that Stepp2p’s USDT balance always equals the sum of `remaining` amounts for all active sales, plus any accrued fees held in the contract. Under this invariant, every seller’s escrowed USDT is fully backed by the contract’s on-chain USDT balance.

The attack interacts with two additional contracts:
- Pancake V3 pool at `0x4f31fa980a675570939b737ebdde0471a4be40eb`, which provides a permissionless 50,000 USDT flash loan.
- A custom attacker helper contract at `0x399eff46b7d458575ebbbb572098e62e38f3c993`, deployed by EOA `0xd7235d08a48cbd3f63b9faa16130f2fdb50f2341`, which sequences the flash loan, Stepp2p interactions, and later USDT→WBNB swap.

## 3. Vulnerability Analysis

### 3.1 Stepp2p sale lifecycle bug

The root cause is a protocol-level accounting and state machine bug in the Stepp2p contract. The relevant functions are:

```solidity
function createSaleOrder(
    uint256 _amount
) external nonReentrant returns (uint256) {
    require(_amount > 0, "Amount must be greater than 0");
    lastSaleId++;

    USDT.safeTransferFrom(msg.sender, address(this), _amount);

    uint256 feeAmount = sellFee > 0 ? (_amount * sellFee) / 1000 : 0;
    uint256 saleAmount = _amount - feeAmount;

    if (feeAmount > 0) {
        USDT.safeTransfer(feeAccount, feeAmount);
    }

    sales[lastSaleId] = Sale({
        seller: msg.sender,
        totalAmount: _amount,
        remaining: saleAmount,
        receivedFee: feeAmount,
        sellFee: sellFee,
        active: true
    });
    ...
}

function modifySaleOrder(
    uint256 _saleId,
    uint256 _modifyAmount,
    bool isPositive // true: add, false: sub
) external nonReentrant {
    require(_modifyAmount > 0, "Amount must be greater than 0");
    require(sales[_saleId].seller == msg.sender);

    uint256 feeAmount = sellFee > 0 ? (_modifyAmount * sellFee) / 1000 : 0;

    if (isPositive) {
        ... deposit more and increase remaining ...
    } else {
        require(
            sales[_saleId].remaining >= _modifyAmount,
            "Insufficient balance"
        );
        sales[_saleId].totalAmount -= _modifyAmount;
        sales[_saleId].remaining -= _modifyAmount;
        if (feeAmount > 0 && sales[_saleId].receivedFee > 0) {
            sales[_saleId].receivedFee -= feeAmount;
            USDT.safeTransferFrom(
                feeAccount,
                sales[_saleId].seller,
                feeAmount
            );
        }
        USDT.safeTransfer(msg.sender, _modifyAmount);
    }
    ...
}

function cancelSaleOrder(uint256 _saleId) external nonReentrant {
    Sale storage sale = sales[_saleId];
    require(
        sale.seller == msg.sender || msg.sender == owner(),
        "Not authorized"
    );
    require(sale.remaining > 0 && sale.active, "Invalid sale");

    uint256 refundAmount = sale.remaining;
    uint256 refundFeeAmount = sale.sellFee > 0
        ? (refundAmount * sale.sellFee) / 1000
        : 0;
    sale.active = false;

    if (refundFeeAmount > 0 && sale.receivedFee > 0) {
        USDT.safeTransferFrom(feeAccount, sale.seller, refundFeeAmount);
    }
    USDT.safeTransfer(sale.seller, refundAmount);
    emit SaleCanceled(_saleId);
}
```

Key properties of this implementation:
- `cancelSaleOrder` **does not** set `sale.remaining` to `0`. It only sets `sale.active = false` and transfers `refundAmount = sale.remaining` from the contract to the seller.
- `modifySaleOrder` with `isPositive = false` **does not** check that the sale is still active. It only checks `sales[_saleId].seller == msg.sender` and that `remaining >= _modifyAmount`.
- When `modifySaleOrder` is called with `isPositive = false`, it reduces `totalAmount` and `remaining` and transfers `_modifyAmount` USDT from the contract to `msg.sender`.

Together, these behaviors mean:
- After a sale is cancelled, `sale.active = false` but `sale.remaining` remains unchanged.
- The seller can still call `modifySaleOrder` with `isPositive = false` and `_modifyAmount` equal to the stale `remaining`, because the function never checks `sale.active`.
- This allows the seller to *withdraw the same `remaining` amount a second time* from Stepp2p, even though that amount has already been returned once via `cancelSaleOrder`.

### 3.2 Security principles violated

This bug violates several core security principles:
- **Escrow accounting integrity**: Stepp2p fails to enforce that its USDT balance equals the sum of `remaining` amounts for all active sales plus fees. The second withdrawal uses USDT that previously backed other sellers’ active sales.
- **State machine consistency**: `cancelSaleOrder` and `modifySaleOrder` do not enforce a coherent state machine. Operations that should only be allowed on active sales (`modifySaleOrder` reductions) are permitted after a sale has been cancelled.
- **Separation of funds and least privilege**: A single seller, by creating and then cancelling a large sale, can spend escrowed USDT that belongs to other sellers, without going through any legitimate settlement path.

## 4. Detailed Root Cause Analysis

### 4.1 ACT opportunity and pre-state σ_B

The ACT opportunity is defined at block height `B = 54653987` on BNB Chain. Let `σ_B` be the publicly reconstructible pre-state immediately before inclusion of transaction `0xe9475278...d69c6a8` in block `54653987`.

From the prestate tracer and balance diffs:
- Stepp2p at `0x99855380e5f48db0a6babeae312b80885a816dce` holds exactly
  `43_782.4059282857` USDT backing multiple existing saleIds (up to `4795`).
- The attacker helper contract `0x399eff46b7d458575ebbbb572098e62e38f3c993` holds `0` USDT.

A representative excerpt from `balance_diff.json` for the seed transaction shows the pre/post balances and deltas:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x4f31fa980a675570939b737ebdde0471a4be40eb",
      "before": "15201159828744135175829047",
      "after": "15201184828744135175829047",
      "delta": "25000000000000000000"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x399eff46b7d458575ebbbb572098e62e38f3c993",
      "before": "0",
      "after": "43757405928285700000000",
      "delta": "43757405928285700000000"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x99855380e5f48db0a6babeae312b80885a816dce",
      "before": "43782405928285700000000",
      "after": "0",
      "delta": "-43782405928285700000000"
    }
  ]
}
```

This confirms that across the exploit transaction:
- The Pancake V3 pool gains `25` USDT (`delta = +25e18`).
- The attacker helper contract goes from `0` USDT to `43_757.4059282857` USDT.
- Stepp2p’s USDT balance goes from `43_782.4059282857` to `0`.

### 4.2 Exploit transaction (sequence b, step 1)

In transaction `0xe9475278...d69c6a8`:
- Sender: EOA `0xd7235d08a48cbd3f63b9faa16130f2fdb50b2341`.
- To: helper contract `0x399eff46b7d458575ebbbb572098e62e38f3c993`.
- Value: `0` BNB.

The Stepp2p-focused annotated trace (`stepp2p_annotated_trace.json`) records the Stepp2p calls and USDT transfers. The `usdt_transfers` array (simplified) is:

```json
{
  "usdt_transfers": [
    {
      "from": "0x4f31fa980a675570939b737ebdde0471a4be40eb",
      "to": "0x399eff46b7d458575ebbbb572098e62e38f3c993",
      "amount_raw": "50000000000000000000000"
    },
    {
      "from": "0x399eff46b7d458575ebbbb572098e62e38f3c993",
      "to": "0x99855380e5f48db0a6babeae312b80885a816dce",
      "amount_raw": "43782405928285700000000"
    },
    {
      "from": "0x99855380e5f48db0a6babeae312b80885a816dce",
      "to": "0x399eff46b7d458575ebbbb572098e62e38f3c993",
      "amount_raw": "43782405928285700000000"
    },
    {
      "from": "0x99855380e5f48db0a6babeae312b80885a816dce",
      "to": "0x399eff46b7d458575ebbbb572098e62e38f3c993",
      "amount_raw": "43782405928285700000000"
    },
    {
      "from": "0x399eff46b7d458575ebbbb572098e62e38f3c993",
      "to": "0x4f31fa980a675570939b737ebdde0471a4be40eb",
      "amount_raw": "50025000000000000000000"
    }
  ]
}
```

Interpreting these transfers:
- The helper borrows `50_000` USDT from the Pancake V3 pool.
- It transfers `43_782.4059282857` USDT to Stepp2p when calling `createSaleOrder`, creating `saleId = 4796` with `remaining = 43_782.4059282857` and `active = true`.
- Later in the same transaction, Stepp2p transfers `43_782.4059282857` USDT twice from Stepp2p to the helper:
  - Once in `cancelSaleOrder(4796)`.
  - Once in `modifySaleOrder(4796, 43_782.4059282857, false)`.
- Finally, the helper repays `50_025` USDT to the Pancake V3 pool (principal + 25 USDT fee).

The Stepp2p storage diffs for sale `4796` (from `state_diff_sales_4796_and_neighbors.json` and `prestateTracer_stepp2p.json`) show:
- Before `createSaleOrder`, `lastSaleId = 4795` and `sales[4796]` does not exist.
- After `createSaleOrder`, `lastSaleId = 4796`, and `sales[4796]` has `seller = 0x399e...c993`, `remaining = 43_782.4059282857`, and `active = true`.
- After `cancelSaleOrder(4796)`, `sales[4796].active = false` but `sales[4796].remaining` is **not** zeroed.
- After `modifySaleOrder(4796, 43_782.4059282857, false)`, `sales[4796].remaining` becomes `0`, and an additional `43_782.4059282857` USDT is transferred from Stepp2p to `0x399e...c993`.

Thus, within a single transaction, the attacker contract:
1. Deposits `43_782.4059282857` USDT into Stepp2p via `createSaleOrder(4796)`.
2. Receives `43_782.4059282857` USDT back via `cancelSaleOrder(4796)`.
3. Receives another `43_782.4059282857` USDT via `modifySaleOrder(4796, 43_782.4059282857, false)`.

Only one deposit was made for `saleId 4796`, so the second withdrawal is funded by Stepp2p’s pre-existing escrow for other sellers. This is the core double-withdraw exploit enabled by the bug described in Section 3.

### 4.3 Profit-taking transaction (sequence b, step 2)

After the exploit transaction, the helper contract `0x399e...c993` holds `43_757.4059282857` USDT. In transaction `0xe716c763310532a8768fd6489ccea211ba30ed71cdad8ba806ee88535f7d529a`:
- Sender: EOA `0xd3f0cf7445b223060ce23dbc1c42f8338d1c2c49`.
- To: helper contract `0x399e...c993`.

The trace for this tx (`trace.cast.log`) shows:

```text
0x399e...c993::5e9b6e1b(... USDT, WBNB, 43_757.4059282857 USDT, 0xd3f0cf... )
  ├─ BEP20USDT::approve(PancakeRouter, max_uint256)
  ├─ PancakeRouter::swapExactTokensForTokensSupportingFeeOnTransferTokens(
        43_757.4059282857 USDT,
        0,
        [USDT, WBNB],
        0xd3f0cf..., deadline
     )
      ├─ BEP20USDT::transferFrom(0x399e...c993 → PancakePair, 43_757.4059282857 USDT)
      ├─ PancakePair::swap(0, 58.704346449303744276 WBNB, 0xd3f0cf..., 0x)
      │   ├─ WBNB::transfer(0xd3f0cf..., 58.704346449303744276)
```

This converts the USDT proceeds from the exploit into `58.704346449303744276` WBNB for the profit-receiving EOA `0xd3f0cf...`.

### 4.4 ACT success predicate and determinism

The ACT success predicate is **profit**, measured in USDT:
- Reference asset: USDT at `0x55d398326f99059ff775485246999027b3197955`.
- Adversary asset holder for the profit measurement: helper contract `0x399eff46b7d458575ebbbb572098e62e38f3c993`.
- Pre-state value at `σ_B`: `0` USDT.
- Post-state value after tx `0xe947...c6a8`: `43_757.4059282857` USDT.
- Net delta: `+43_757.4059282857` USDT, funded entirely by draining Stepp2p’s escrow (`43_782.4059282857` USDT) minus the `25` USDT flash-loan fee.

The subsequent USDT→WBNB swap in `0xe716c7...529a` converts this deterministic USDT profit into WBNB for EOA `0xd3f0cf...`. Gas costs for the EOAs and any external portfolio context are not required to establish that the adversary cluster achieves a strictly positive economic gain funded by the victim contract’s escrow.

All steps in the two-transaction sequence `b` are permissionless and reproducible by any unprivileged searcher with access to `σ_B`:
- Deploying a helper contract and calling it from an EOA.
- Taking a flash loan from a Pancake V3 pool.
- Interacting with Stepp2p via `createSaleOrder`, `cancelSaleOrder`, and `modifySaleOrder`.
- Executing a standard PancakeSwap `swapExactTokensForTokensSupportingFeeOnTransferTokens` call.

## 5. Adversary Flow Analysis

### 5.1 Adversary-related accounts and roles

The adversary cluster consists of three related addresses on BNB Chain (chainid 56):

- **EOA `0xd7235d08a48cbd3f63b9faa16130f2fdb50b2341`**
  - Type: EOA.
  - Roles:
    - Deploys the helper contract `0x399eff46b7d458575ebbbb572098e62e38f3c993` in tx `0x9819e7f298bd7d5dc487eeb26bdbf44b5043e72804395c62a39546f7cfa04060` (block `54653788`).
    - Sends the exploit transaction `0xe947...c6a8` calling the helper contract.
  - Evidence: `txlist_normal.json` and `txlist_normal_54653987_54665000.json` for `0x399e...c993` show the creation tx and the exploit tx from this EOA.

- **Contract `0x399eff46b7d458575ebbbb572098e62e38f3c993`**
  - Type: contract.
  - Roles:
    - Attack strategy and flash-loan helper contract.
    - Borrows `50_000` USDT from Pancake V3 pool `0x4f31...40eb`.
    - Calls Stepp2p to create saleId `4796` and then perform `cancelSaleOrder` and `modifySaleOrder` to double-withdraw the escrow.
    - Repays `50_025` USDT to the flash-loan pool.
    - Later executes a USDT→WBNB swap on PancakeSwap on behalf of EOA `0xd3f0cf...`.
  - Evidence: contract creation, exploit tx, and swap tx all target this address; the disassembly (`disassembly.txt`) and traces show its role in orchestrating flash loans, Stepp2p calls, and swaps.

- **EOA `0xd3f0cf7445b223060ce23dbc1c42f8338d1c2c49`**
  - Type: EOA.
  - Roles:
    - Sends the profit-taking tx `0xe716c7...529a` to the helper contract.
    - Receives `58.704346449303744276` WBNB from a PancakeSwap pair as the final asset from the exploit flow.
  - Evidence: the swap trace shows `WBNB::transfer(0xd3f0cf..., 58.704346449303744276)` as the final step of the swap.

The victim contract is:
- **Stepp2p escrow contract `0x99855380e5f48db0a6babeae312b80885a816dce`**
  - Type: verified contract.
  - Roles:
    - Holds USDT escrow balances for multiple sellers’ sales.
    - Contains the flawed `createSaleOrder` / `cancelSaleOrder` / `modifySaleOrder` logic exploited in the attack.

### 5.2 Adversary lifecycle stages

1. **Adversary contract deployment**
   - Tx: `0x9819e7f298bd7d5dc487eeb26bdbf44b5043e72804395c62a39546f7cfa04060` (block `54653788`).
   - From: `0xd7235d0...2341`.
   - Effect: deploys the helper contract `0x399e...c993`.
   - Evidence: `txlist_normal.json` for `0x399e...c993` includes this contract-creation transaction.

2. **Flash-loan-funded double-withdraw exploit**
   - Tx: `0xe94752783519da14315d47cde34da55496c39546813ef4624c94825e2d69c6a8` (block `54653987`).
   - From: `0xd7235d0...2341` → `0x399e...c993`.
   - Mechanism: flash loan from Pancake V3 pool `0x4f31...40eb`, followed by Stepp2p interactions.
   - Effect:
     - Helper borrows `50_000` USDT from `0x4f31...40eb`.
     - Calls `Stepp2p.createSaleOrder(43_782.4059282857)` to create saleId `4796` and deposit USDT.
     - Calls `Stepp2p.cancelSaleOrder(4796)` to withdraw `43_782.4059282857` USDT.
     - Calls `Stepp2p.modifySaleOrder(4796, 43_782.4059282857, false)` to withdraw the *same* `remaining` amount again, funded by Stepp2p’s pre-existing escrow.
     - Repays `50_025` USDT to the flash-loan pool.
     - Ends with `43_757.4059282857` USDT on the helper contract.
   - Evidence: `stepp2p_annotated_trace.json` and `trace.cast.log` for this tx show the sequence of Stepp2p calls and the two identical USDT transfers from Stepp2p to `0x399e...c993`; state diffs confirm the drain of Stepp2p’s USDT balance and the storage changes for `sales[4796]`.

3. **Profit realization via USDT→WBNB swap**
   - Tx: `0xe716c763310532a8768fd6489ccea211ba30ed71cdad8ba806ee88535f7d529a` (block `54655876`).
   - From: `0xd3f0cf7445b223060ce23dbc1c42f8338d1c2c49` → `0x399e...c993`.
   - Mechanism: PancakeSwap `swapExactTokensForTokensSupportingFeeOnTransferTokens` via PancakeRouter.
   - Effect:
     - Helper approves PancakeRouter to spend its USDT.
     - Router transfers `43_757.4059282857` USDT from `0x399e...c993` to a USDT/WBNB Pancake pair.
     - Pair sends `58.704346449303744276` WBNB to `0xd3f0cf...`.
   - Evidence: `trace.cast.log` for this tx shows `BEP20USDT::approve`, `swapExactTokensForTokensSupportingFeeOnTransferTokens`, the USDT transfer from `0x399e...c993` to the Pancake pair, and `WBNB::transfer(0xd3f0cf..., 58.704346449303744276)`.

## 6. Impact & Losses

### 6.1 Quantitative loss summary

The total on-chain loss to Stepp2p’s escrow is:

- **USDT**: `43_782.4059282857` USDT
  - Token: BEP20USDT at `0x55d398326f99059ff775485246999027b3197955` on BNB Chain.

From `balance_diff.json` and the Stepp2p state diffs, we observe:
- Before tx `0xe947...c6a8`, Stepp2p’s USDT balance is `43_782.4059282857` USDT, backing multiple existing saleIds.
- After the transaction, Stepp2p’s USDT balance is `0`.
- The entire pre-state balance is transferred out during this single exploit transaction.

The economic effects are:
- Multiple sellers who previously had active sale orders backed by Stepp2p’s USDT escrow lose their backing, as their `remaining` values are no longer supported by any on-contract USDT.
- The adversary cluster captures `43_757.4059282857` USDT (net of the 25 USDT flash-loan fee) in the helper contract and then converts this into `58.704346449303744276` WBNB for EOA `0xd3f0cf...`.
- The Pancake V3 pool receives the 25 USDT fee.

Fine-grained attribution of the 43_782.4059282857 USDT loss to specific Stepp2p sellers and saleIds is not necessary to establish the ACT root cause or total protocol loss, and is out of scope for this root cause report.

### 6.2 Invariant violation

The incident directly violates Stepp2p’s intended escrow invariant that:

> contract USDT balance = sum of `remaining` amounts for all active sales + fees

At pre-state `σ_B`, this invariant holds, with `43_782.4059282857` USDT on-contract backing active sales. After the exploit transaction:
- Stepp2p’s USDT balance is `0`.
- Some sales (other than the newly created sale `4796`, which ends with `remaining = 0`) still have non-zero `remaining` amounts and are not settled to their original sellers.

The missing funds are precisely the `43_782.4059282857` USDT drained via the double-withdraw exploit, which are held temporarily by the helper contract and then swapped into WBNB for the adversary.

## 7. References

Key supporting artifacts used in this analysis include:

1. **Stepp2p.sol source code**  
   `artifacts/root_cause/data_collector/iter_1/contract/56/0x99855380e5f48db0a6babeae312b80885a816dce/source/src/Stepp2p.sol`  
   Verified contract source defining the Sale struct, `createSaleOrder`, `cancelSaleOrder`, and `modifySaleOrder` logic that contain the double-withdraw bug.

2. **Exploit transaction annotated trace (0xe947...c6a8)**  
   `artifacts/root_cause/data_collector/iter_3/tx/56/0xe94752783519da14315d47cde34da55496c39546813ef4624c94825e2d69c6a8/stepp2p_annotated_trace.json`  
   Stepp2p-focused execution trace showing the sequence of contract calls and the two identical `43_782.4059282857` USDT transfers from Stepp2p to `0x399e...c993`.

3. **Stepp2p prestate and state diffs around saleId 4796**  
   `artifacts/root_cause/data_collector/iter_3/contract/56/0x99855380e5f48db0a6babeae312b80885a816dce/prestateTracer_stepp2p.json`  
   `artifacts/root_cause/data_collector/iter_3/contract/56/0x99855380e5f48db0a6babeae312b80885a816dce/state_diff_sales_4796_and_neighbors.json`  
   Storage snapshots and diffs demonstrating creation of saleId `4796`, its cancellation, and subsequent modification, as well as Stepp2p’s escrow balance before and after the exploit.

4. **Helper contract 0x399e...c993 disassembly**  
   `artifacts/root_cause/data_collector/iter_1/contract/56/0x399eff46b7d458575ebbbb572098e62e38f3c993/disassemble/disassembly.txt`  
   Disassembly and metadata confirming that `0x399e...c993` is a contract deployed by `0xd7235d0...2341` and used for the flash-loan, Stepp2p interaction, and later swap.

5. **Profit-taking swap trace (0xe716c7...529a)**  
   `artifacts/root_cause/data_collector/iter_2/tx/56/0xe716c763310532a8768fd6489ccea211ba30ed71cdad8ba806ee88535f7d529a/trace.cast.log`  
   Execution trace showing BEP20USDT approval, the PancakeSwap `swapExactTokensForTokensSupportingFeeOnTransferTokens` call, the transfer of `43_757.4059282857` USDT from `0x399e...c993` to a Pancake pair, and the resulting `58.704346449303744276` WBNB transfer to `0xd3f0cf...`.

6. **Seed transaction metadata and balance diffs**  
   `artifacts/root_cause/seed/56/0xe94752783519da14315d47cde34da55496c39546813ef4624c94825e2d69c6a8/metadata.json`  
   `artifacts/root_cause/seed/56/0xe94752783519da14315d47cde34da55496c39546813ef4624c94825e2d69c6a8/balance_diff.json`  
   RPC metadata and ERC20 balance changes for the exploit transaction, confirming the net drain from Stepp2p and the net gain for the helper contract and flash-loan pool.

7. **Helper contract transaction history**  
   `artifacts/root_cause/data_collector/iter_1/address/56/0x399eff46b7d458575ebbbb572098e62e38f3c993/txlist_normal.json`  
   `artifacts/root_cause/data_collector/iter_2/address/56/0x399eff46b7d458575ebbbb572098e62e38f3c993/txlist_normal_54653987_54665000.json`  
   Normal transaction history demonstrating the deployment of `0x399e...c993`, the exploit transaction, and the profit-taking swap as the only interactions with this contract in the relevant window.

8. **Root cause analyzer final iteration**  
   `artifacts/root_cause/root_cause_analyzer/iter_4/current_analysis_result.json`  
   Detailed narrative that aligns with this report, confirming the exploit as a double-withdraw bug in Stepp2p’s sale lifecycle and validating that all ACT opportunity and quality criteria are satisfied.
