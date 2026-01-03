## Incident Overview TL;DR

An unprivileged EOA on Ethereum mainnet, `0x07185a9e74f8dceb7d6487400e4009ff76d1af46`, executed a single contract-based transaction (`0x23b69bef57656f493548a5373300f7557777f352ade8131353ff87a1b27e2bb3`, block `23260641`) that performed an atomic cross-venue arbitrage between a Uniswap V3 HEX/WETH pool (`0x9e0905249CeEFfFB9605E034b534544684A58BE6`) and the HEXOTC contract (`0x204B937FEaEc333E9e6d72D35f1D131f187ECeA1`).  
The adversary swapped `0.037` WETH for approximately `9.236e12` HEX on Uniswap V3 and then used HEXOTC to take two ETH-escrowed offers that overpaid for HEX relative to the pool price, receiving `0.15942` ETH in total while spending only `0.037` ETH plus gas.  
Balance diffs show the EOA’s ETH balance increasing from `5.716863215860854441` ETH to `5.839142169376423834` ETH, a net gain of `0.122278953515569393` ETH after gas, while also ending with `44,561,624,407` HEX.  
Because HEXOTC offers and Uniswap V3 prices are fully public and permissionless, this is an ACT-style opportunity: any searcher aware of the mispriced offers and pool state could have constructed the same transaction sequence to realize the same ETH profit.

## Key Background

The incident occurs on Ethereum mainnet in block `23260641`. The relevant contracts and actors in the pre-state are:

- EOA `0x07185a9e74f8dceb7d6487400e4009ff76d1af46` with `5.716863215860854441` ETH and no HEX balance.
- HEX ERC20 contract at `0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39` with standard token behavior and balances.
- WETH9 contract at `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`, used to wrap ETH into WETH.
- Uniswap V3 HEX/WETH pool at `0x9e0905249CeEFfFB9605E034b534544684A58BE6`, which at this block can swap `0.037` WETH for approximately `9.236e12` HEX without exhausting liquidity or moving the price materially.
- HEXOTC contract at `0x204B937FEaEc333E9e6d72D35f1D131f187ECeA1`, which implements an on-chain OTC market for HEX and ETH.

Immediately before block `23260641`, HEXOTC holds at least two active ETH-for-HEX offers (escrow type `1`) whose terms are fixed in contract storage:

- Offer id `0x43`: sell `0.06942` ETH in exchange for `6,942,000,000,000` HEX.
- Offer id `0x2b`: sell `0.09` ETH in exchange for `2,250,000,000,000` HEX.

The ETH side of these offers is escrowed inside HEXOTC, and the HEX side is expected from any taker who calls the appropriate function. All of this state is reconstructible from public transactions that created the offers and from querying on-chain storage prior to block `23260641`.  
The system therefore presents a classic cross-venue arbitrage surface: a Uniswap V3 pool with a current market price for HEX/WETH and an OTC contract with fixed-price ETH-for-HEX offers that may become misaligned with that market price.

## Vulnerability Analysis

The core vulnerability is an economic mispricing in HEXOTC, not a bug in Solidity semantics or access control. The HEXOTC contract allows makers to post ETH-escrowed offers that specify a fixed price `pay_amt / buy_amt` (ETH per unit of HEX) and does not enforce any relationship between that price and an external market price. Offers do not automatically expire or adjust; they remain executable as long as they are active.

The relevant HEXOTC logic for ETH-escrowed offers is in `hex-otc.sol`:

```solidity
// HEXOTC excerpt: ETH-escrowed offers and taker logic

struct OfferInfo {
    uint     pay_amt;
    uint     buy_amt;
    address  owner;
    uint64   timestamp;
    bytes32  offerId;
    uint     escrowType; // 0 HEX - 1 ETH
}

function offerETH(uint pay_amt, uint buy_amt) // amounts in wei / hearts
    public
    payable
    can_offer
    synchronized
    returns (uint id)
{
    require(pay_amt > 0, "pay_amt is 0");
    require(buy_amt > 0, "buy_amt is 0");
    require(pay_amt == msg.value, "pay_amt not equal to msg.value");
    newOffer(id, pay_amt, buy_amt, 1);
    emit LogMake(bytes32(id), msg.sender, uint(pay_amt), uint(buy_amt), uint64(now), 1);
}

function buyETH(uint id)
    public
    can_buy(id)
    synchronized
    returns (bool)
{
    OfferInfo memory offer = offers[id];
    require(offer.escrowType == 1, "Incorrect escrow type");
    require(hexInterface.balanceOf(msg.sender) >= offer.buy_amt, "Balance is less than requested spend amount");
    require(offer.buy_amt > 0 && offer.pay_amt > 0, "values are zero");
    require(hexInterface.transferFrom(msg.sender, offer.owner, offer.buy_amt), "Transfer failed");
    msg.sender.transfer(offer.pay_amt);
    emit LogTake(bytes32(id), offer.owner, msg.sender, uint(offer.pay_amt), uint(offer.buy_amt), uint64(now), offer.escrowType);
    offers[id].pay_amt = 0;
    offers[id].buy_amt = 0;
    delete offers[id];
    return true;
}

function take(bytes32 id)
    public
    payable
{
    if (msg.value > 0) {
        require(buyHEX(uint256(id)), "Buy HEX failed");
    } else {
        require(buyETH(uint256(id)), "Sell HEX failed");
    }
}
```

Key properties of this design:

- Makers post ETH-escrowed offers via `offerETH`, which locks `pay_amt` ETH in HEXOTC and records `(pay_amt, buy_amt, escrowType=1)` for the offer id.
- Takers execute `take(id)` with `msg.value == 0` for these offers, which dispatches to `buyETH(id)`.
- `buyETH` only checks:
  - The offer is active (`isActive(id)` is true).
  - `escrowType == 1`.
  - The taker’s HEX balance is at least `offer.buy_amt`.
  - `offer.pay_amt` and `offer.buy_amt` are nonzero.
- There is no mechanism to:
  - Enforce a maximum or minimum effective price relative to an external oracle or AMM price.
  - Automatically expire stale offers.
  - Restrict who may call `buyETH` beyond holding sufficient HEX.

Given these properties, any time HEXOTC contains ETH-escrowed offers whose fixed price `pay_amt / buy_amt` is higher than the contemporaneous Uniswap HEX/WETH market price, an adversary can profit by:

1. Acquiring HEX cheaply from the Uniswap pool.
2. Paying that HEX to HEXOTC makers via `buyETH`.
3. Receiving more ETH from HEXOTC than they spent (plus gas), with no special permissions.

In this incident, offers `0x43` and `0x2b` are precisely such mispriced ETH-escrowed offers, and the adversary identifies and exploits them using a single transaction.

## Detailed Root Cause Analysis

The root cause is a cross-venue price discrepancy between HEXOTC’s fixed-price ETH-escrowed offers and the live market price in the Uniswap V3 HEX/WETH pool, combined with HEXOTC’s fully permissionless taker interface.

### Pre-State Sigma_B

The pre-state `σ_B` immediately before block `23260641` includes:

- EOA `0x07185a9e74f8dceb7d6487400e4009ff76d1af46` with `5.716863215860854441` ETH and zero HEX.
- HEX contract `0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39` with balances consistent with prior transactions (including liquidity and maker balances).
- WETH9 contract `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`.
- Uniswap V3 HEX/WETH pool `0x9e0905249CeEFfFB9605E034b534544684A58BE6` with sufficient HEX/WETH liquidity to swap `0.037` WETH to roughly `9.236e12` HEX.
- HEXOTC contract `0x204B937FEaEc333E9e6d72D35f1D131f187ECeA1` with two active ETH-escrowed offers:
  - Id `0x43`: `pay_amt = 0.06942` ETH, `buy_amt = 6,942,000,000,000` HEX.
  - Id `0x2b`: `pay_amt = 0.09` ETH, `buy_amt = 2,250,000,000,000` HEX.

The existence and parameters of these offers are inferred straightforwardly from the `LogMake` and `LogTake` events emitted by HEXOTC and from the `OfferInfo` structure defined in `hex-otc.sol`.

At the same time, the Uniswap V3 pool price records that the market is willing to sell approximately `9.236e12` HEX in exchange for only `0.037` WETH. This implies that by:

- Paying `0.037` ETH into the Uniswap pool to acquire HEX, then
- Paying `8 * 10^12+` HEX into HEXOTC offers `0x43` and `0x2b` to receive `0.15942` ETH,

an adversary can generate a net ETH profit (before gas) of:

```text
0.15942 ETH (received from HEXOTC)
- 0.03700 ETH (spent at Uniswap)
= 0.12242 ETH (gross profit before gas)
```

Gas reduces this slightly; the final net profit is measured directly from balance diffs.

### Sequence b and Transaction Effects

The ACT opportunity is realized in a single adversary-crafted transaction:

- Chain: Ethereum mainnet (`chainid = 1`).
- Tx hash: `0x23b69bef57656f493548a5373300f7557777f352ade8131353ff87a1b27e2bb3`.
- From: `0x07185a9e74f8dceb7d6487400e4009ff76d1af46`.
- Value: `0.037` ETH (exactly `0x83734dd0b08000` wei).
- Gas used: `1,041,509`.
- Gas price: `135,425,123` wei.

This transaction deploys an intermediate factory contract `0x6728F1e6764081F7161e82e087581aEfa21723fc`, which then deploys the main helper contract `0x6E0113C4F1De65B98381BAA6443b20834B70D4C5`. The helper contract executes the strategy and returns profit to the EOA.

The trace for `0x23b69b...` (from `trace.cast.log`) shows the key stages:

```text
Seed transaction trace for 0x23b69b... (excerpt)

[...]
├─ new <unknown>@0x6728F1e6...(contract factory)
│  ├─ new <unknown>@0x6E0113C4F1De65B98381BAA6443b20834B70D4C5 (helper)
│  ├─ WETH9::deposit{value: 37000000000000000}()
│  ├─ UniswapV3Pool::swap(...)
│  ├─ HEX::transferFrom(0x6E0..., 0x68CB..., 6942000000000)
│  ├─ HEX::transferFrom(0x6E0..., 0xFeDc..., 2250000000000)
│  ├─ HEXOTC::take(0x43)
│  │   ├─ emit LogTake(
│  │        id: 0x43,
│  │        maker: 0x68CBc12a70A14f055110dDBEc73A7F0F5551ffDA,
│  │        taker: 0x6E0113C4F1De65B98381BAA6443b20834B70D4C5,
│  │        take_amt: 69420000000000000,
│  │        give_amt: 6942000000000,
│  │        escrowType: 1
│  │     )
│  ├─ HEXOTC::take(0x2b)
│  │   ├─ emit LogTake(
│  │        id: 0x2b,
│  │        maker: 0xFeDc84d0cd5FE6dB2B2f8aC31c7e31e49B665e5c,
│  │        taker: 0x6E0113C4F1De65B98381BAA6443b20834B70D4C5,
│  │        take_amt: 90000000000000000,
│  │        give_amt: 2250000000000,
│  │        escrowType: 1
│  │     )
│  ├─ HEX::transfer(0x6E0..., 0x0718..., 44561624407)
│  ├─ 0x0718...::fallback{value: 159420000000000000}()
│  └─ [...]
```

This trace confirms:

- `0.037` ETH is first wrapped into WETH and swapped on the Uniswap V3 pool for HEX.
- The helper contract uses `HEXOTC::take(0x43)` and `HEXOTC::take(0x2b)` to:
  - Transfer `6,942,000,000,000` HEX and `2,250,000,000,000` HEX respectively from the helper to the maker EOAs.
  - Receive `0.06942` ETH and `0.09` ETH from HEXOTC for those offers.
- A subsequent HEX transfer of `44,561,624,407` tokens from the helper contract back to the EOA.
- A final ETH transfer of `0.15942` ETH from the helper to the EOA.

### Profit Calculation and Predicate Satisfaction

The profit predicate is purely monetary in ETH. From `balance_diff.json`:

```json
{
  "native_balance_deltas": [
    {
      "address": "0x07185a9e74f8dceb7d6487400e4009ff76d1af46",
      "before_wei": "5716863215860854441",
      "after_wei": "5839142169376423834",
      "delta_wei": "122278953515569393"
    },
    {
      "address": "0x204b937feaec333e9e6d72d35f1d131f187ecea1",
      "before_wei": "159422010000000000",
      "after_wei": "2010000000000",
      "delta_wei": "-159420000000000000"
    }
  ]
}
```

Converting the EOA delta to ETH:

- `delta_wei = 122278953515569393` ≈ `0.122278953515569393` ETH.

Using the gas data from `metadata.json`:

- `gasUsed = 1,041,509`
- `gasPrice = 135,425,123` wei
- Gas fee = `1,041,509 * 135,425,123` wei = `141,046,484,430,607` wei ≈ `0.000141046484430607` ETH

The net ETH profit for the EOA is:

- `(final ETH balance) - (initial ETH balance)` = `0.122278953515569393` ETH, which already accounts for both:
  - The `0.037` ETH sent as `tx.value`.
  - The gas fee above.

Even if the residual `44,561,624,407` HEX held by the EOA at the end of the transaction were valued at zero, the ETH-only change is strictly positive. The profit predicate is therefore satisfied with reference asset `ETH`, fees fully accounted for, and net positive value verified from on-chain balance changes.

## Adversary Flow Analysis

### Adversary Cluster and Roles

The adversary-related account cluster consists of:

- EOA `0x07185a9e74f8dceb7d6487400e4009ff76d1af46`
  - Originator of transaction `0x23b69b...`.
  - Funds the transaction with `0.037` ETH and pays gas.
  - Receives the final ETH profit and residual HEX.
- Factory contract `0x6728F1e6764081F7161e82e087581aEfa21723fc`
  - Deployed by the EOA at the beginning of the seed transaction.
  - Deploys the helper contract and transfers control to it.
  - Has no observable activity outside this transaction, indicating it is specifically created for this strategy.
- Helper contract `0x6E0113C4F1De65B98381BAA6443b20834B70D4C5`
  - Deployed by the factory contract in the same transaction.
  - Its runtime bytecode is captured at:
    - `artifacts/root_cause/data_collector/iter_1/contract/1/0x6E0113C4F1De65B98381BAA6443b20834B70D4C5/bytecode/runtime_bytecode.txt`
  - The trace shows it wrapping ETH to WETH, swapping on Uniswap V3, approving HEXOTC for HEX, taking the mispriced offers, and returning ETH and HEX to the EOA.
  - Entirely controlled by the adversary via the factory and EOA.

This cluster is attributed based on deterministic deployment relationships and fund flows, without speculative control assumptions.

### Lifecycle Stages

The adversary’s strategy can be decomposed into the following stages:

1. **Priming and contract deployment**
   - The EOA `0x0718...` submits `0x23b69b...` with `0.037` ETH value.
   - Inside the transaction, an intermediate factory contract `0x6728...` is deployed.
   - The factory then deploys the helper contract `0x6E0...`.

2. **Acquire HEX via Uniswap V3**
   - The helper contract calls `WETH9::deposit` with `0.037` ETH to obtain WETH.
   - It then calls `UniswapV3Pool::swap` on pool `0x9e09...`, swapping the WETH for approximately `9,236,561,624,407` HEX.
   - The trace shows HEX moving from the pool to `0x6E0...` and WETH moving in the opposite direction, consistent with a standard Uniswap V3 swap at the current pool price.

3. **Take mispriced HEXOTC offers**
   - The helper contract approves HEXOTC to spend its HEX.
   - It calls `HEXOTC::take(0x43)` and `HEXOTC::take(0x2b)` with `msg.value == 0`, triggering `buyETH` for each offer id.
   - From the trace:
     - For `id 0x43`, `HEX::transferFrom(0x6E0..., 0x68CB...)` transfers `6,942,000,000,000` HEX, and HEXOTC sends `0.06942` ETH to the helper contract, emitting a `LogTake` with these parameters.
     - For `id 0x2b`, `HEX::transferFrom(0x6E0..., 0xFeDc...)` transfers `2,250,000,000,000` HEX, and HEXOTC sends `0.09` ETH to the helper, emitting a corresponding `LogTake` event.
   - These trades consume the mispriced offers and move the escrowed ETH from HEXOTC to the helper contract while paying HEX to the makers at the stale prices.

4. **Settlement and profit realization**
   - After the OTC trades, the helper contract:
     - Transfers `44,561,624,407` HEX to the original EOA `0x0718...` via `HEX::transfer`.
     - Forwards `0.15942` ETH to the EOA using a direct ETH transfer, visible as the EOA’s fallback function receiving `159420000000000000` wei.
   - `balance_diff.json` confirms:
     - The EOA’s ETH balance increases by `0.122278953515569393` ETH net of the initial `0.037` ETH outlay and gas.
     - HEXOTC’s ETH balance decreases by `0.15942` ETH.
     - Makers `0x68CB...` and `0xFeDc...` receive `6,942,000,000,000` and `2,250,000,000,000` HEX respectively.
   - The adversary thus ends the transaction with more ETH than before plus residual HEX, fully realizing the cross-venue arbitrage profit.

### ACT Opportunity Classification

The opportunity qualifies as an ACT-style opportunity under the given definition:

- **Unprivileged adversary:**  
  - The transaction is sent from a normal EOA with no special roles.  
  - All interacted contracts (HEX, WETH9, Uniswap V3 pool, HEXOTC) are permissionless and callable by any address.

- **Canonical on-chain data and public contract metadata only:**  
  - The pre-state `σ_B` (offers in HEXOTC, pool reserves and price in Uniswap V3, EOA balances) is fully reconstructible from:
    - Public transaction history and logs (`LogMake` and `LogTake` events).
    - Contract storage reads for HEXOTC offers and Uniswap pool state.
    - Verified contract sources or ABIs for HEX, WETH9, HEXOTC, and Uniswap V3.

- **Publicly observable transaction:**  
  - The seed transaction `0x23b69b...` is standard EIP-1559 and fits within normal gas constraints; there is no need for private orderflow or MEV relay exclusivity.
  - Any searcher monitoring the mempool and on-chain state could have constructed the same sequence (helper deployment, WETH deposit, Uniswap swap, HEXOTC takes) to capture the same ETH profit.

- **Profit predicate satisfied:**  
  - Reference asset: ETH.
  - Fees accounted for: gas is explicitly computed from on-chain metadata and included in the net balance delta.
  - Net positive value verified: the EOA’s ETH balance delta is strictly positive even if residual HEX is valued at zero.

Therefore, the opportunity is correctly classified as an ACT opportunity built on a deterministic, permissionless cross-venue arbitrage.

## Impact & Losses

Within the scope of transaction `0x23b69b...`:

- **Adversary profit (EOA 0x0718...)**
  - ETH balance increases from `5.716863215860854441` ETH to `5.839142169376423834` ETH.
  - Net ETH profit: `0.122278953515569393` ETH, after accounting for the initial `0.037` ETH spent and gas.
  - The EOA also ends with `44,561,624,407` HEX that it did not hold before.

- **HEXOTC contract**
  - ETH balance decreases by `0.15942` ETH (`159420000000000000` wei), corresponding to the payout from the two ETH-escrowed offers.
  - The offers `0x43` and `0x2b` are removed from storage.

- **Maker EOAs**
  - Maker `0x68CBc12a70A14f055110dDBEc73A7F0F5551ffDA` receives `6,942,000,000,000` HEX.
  - Maker `0xFeDc84d0cd5FE6dB2B2f8aC31c7e31e49B665e5c` receives `2,250,000,000,000` HEX.
  - These makers effectively sell ETH at a price worse than the contemporaneous Uniswap V3 HEX/WETH rate, transferring value to the arbitrageur.

From an ACT perspective, the quantifiable harm is that a searcher can deterministically extract at least `0.122278953515569393` ETH of value from the mispriced HEXOTC offers under the observed pre-state, with additional non-quantified transfer of HEX exposure (from the adversary to the makers) determined by the chosen strategy.

## References

- [1] Seed transaction metadata, trace, and balance diffs for `0x23b69bef57656f493548a5373300f7557777f352ade8131353ff87a1b27e2bb3`  
  - `artifacts/root_cause/seed/1/0x23b69bef57656f493548a5373300f7557777f352ade8131353ff87a1b27e2bb3/metadata.json`  
  - `artifacts/root_cause/seed/1/0x23b69bef57656f493548a5373300f7557777f352ade8131353ff87a1b27e2bb3/trace.cast.log`  
  - `artifacts/root_cause/seed/1/0x23b69bef57656f493548a5373300f7557777f352ade8131353ff87a1b27e2bb3/balance_diff.json`

- [2] HEXOTC contract source (`hex-otc.sol`)  
  - `artifacts/root_cause/data_collector/iter_1/contract/1/0x204B937FEaEc333E9e6d72D35f1D131f187ECeA1/source/src/hex-otc.sol`

- [3] Uniswap V3 HEX/WETH pool source (`UniswapV3Pool.sol`)  
  - `artifacts/root_cause/data_collector/iter_1/contract/1/0x9e0905249CeEFfFB9605E034b534544684A58BE6/source/src/UniswapV3Pool.sol`

- [4] Adversary helper contract runtime bytecode  
  - `artifacts/root_cause/data_collector/iter_1/contract/1/0x6E0113C4F1De65B98381BAA6443b20834B70D4C5/bytecode/runtime_bytecode.txt`

