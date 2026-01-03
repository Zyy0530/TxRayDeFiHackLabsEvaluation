# JHYToken Dividend Tracker Over-Distribution Exploit on BSC

## 1. Incident Overview & TL;DR

In block **44,857,311** on BSC (chain id 56), an adversary-controlled EOA
`0x00000000dd0412366388639b1101544FFF2dCe8D` sends a single, zero-value
transaction to an aggregator contract
`0x802a389072c4310CF78A2e654Fa50FaC8bDC1a55`.

The aggregator, together with a flash-loan helper contract
`0xAeee14beaac31e7c7c03720f1b173a3Fe110664d`, orchestrates:
- A flash loan of **25,000e18 USDT** from the Pancake USDT/WBNB pair
  `0x36696169C63e42cd08Ce11F5DeeBbCeBae652050`.
- Swaps via Pancake router `0x10ED43C718714eb63d5aA57B78B54704E256024E`.
- Add/remove-liquidity operations on the **JHY/USDT** pair
  `0x086Ecf61469c741a6f97D80F2F43342af3dBDB9B` involving **JHYToken**
  `0x30Bea8Ce5CD1BA592eb13fCCd8973945Dc8555c5`.

During these operations, a bug in **JHYToken’s dividend distribution logic**
causes the external dividend tracker
`0x40Cd735D49e43212B5cb0b19773Ec2A648aAA96c` to over-credit and pay out
JHYToken dividends to the adversary’s LP position. The value transferred
ultimately comes from the JHY/USDT pool and the tracker’s existing JHYToken
holdings.

At the end of the transaction, the adversary repays the flash loan plus fee
and realizes a **net profit of approximately 11,192.34 USDT**, funded by the
JHY/USDT pool.

### Root Cause Brief

The core protocol bug lies in **JHYToken’s `_transfer` implementation on the
sell path to the JHY/USDT pair**. When `to == uniswapPair`, the contract:

- Transfers `amount * sellDead / 100` JHY to the burn address, and
- Transfers `amount * sellLP / 100` JHY to the external dividend tracker
  `dividendLPTracker`, but
- Calls `distributeCAKEDividends(amount.mul(sellLP))` using the *full*
  `amount * sellLP`, rather than the actually transferred
  `amount * sellLP / 100`.

This mismatch causes the dividend tracker to record and later pay out
**dividends calculated from 100× more JHY than it actually receives per sell**.
In the incident transaction, the adversary’s LP position is updated via
`setBalance` and `process` around add/remove-liquidity, so the tracker pays out
large over-credited JHYToken dividends to the adversary’s contract, which then
swaps them back to USDT and extracts value from the JHY/USDT pool.

**Code snippet – JHYToken sell-path and dividend call**

_Source: Verified JHYToken `Contract.sol` (`_transfer` implementation)._  
_This snippet shows that the contract transfers `amount * sellLP / 100` JHY to
 the dividend tracker but calls `distributeCAKEDividends(amount.mul(sellLP))`._

```solidity
function _transfer(
    address from,
    address to,
    uint256 amount
) internal override {
    if (_excludedFees[from] || _excludedFees[to]) {
        super._transfer(from, to, amount);
        return;
    }

    if (to == uniswapPair) {
        super._transfer(from, _deadWalletAddress, amount.mul(sellDead).div(100));
        super._transfer(from, address(dividendLPTracker), amount.mul(sellLP).div(100));
        TokenDividendTracker(dividendLPTracker).distributeCAKEDividends(amount.mul(sellLP));
        try TokenDividendTracker(dividendLPTracker).setBalance(
            payable(from),
            IERC20(uniswapPair).balanceOf(address(from))
        ) {} catch {}
    }
    // buy path and processing omitted for brevity
}
```

This deterministic code-level behavior is the root cause of the
over-distribution: dividend accounting uses `amount * sellLP`, while only
`amount * sellLP / 100` JHY is actually deposited into the tracker.

## 2. ACT Opportunity and Pre-State

### Block Height and Pre-State

- **Block height B**: `44,857,311` on BSC.
- **Pre-state σ_B**: Publicly reconstructible state around blocks
  44,857,310–44,857,311, including balances and storage for:
  - JHYToken: `0x30Bea8Ce5CD1BA592eb13fCCd8973945Dc8555c5`
  - JHY/USDT Pancake pair: `0x086Ecf61469c741a6f97D80F2F43342af3dBDB9B`
  - USDT/WBNB pair (flash-loan source): `0x36696169C63e42cd08Ce11F5DeeBbCeBae652050`
  - Dividend tracker: `0x40Cd735D49e43212B5cb0b19773Ec2A648aAA96c`
  - Aggregator: `0x802a389072c4310CF78A2e654Fa50FaC8bDC1a55`
  - Flash-loan helper: `0xAeee14beaac31e7c7c03720f1b173a3Fe110664d`
  - Adversary EOA: `0x00000000dd0412366388639b1101544FFF2dCe8D`

**Evidence snippet – Seed transaction metadata**

_Source: Seed transaction metadata JSON for
 `0xb6a9055e3ce7f006391760fbbcc4e4bc8df8228dc47a8bb4ff657370ccc49256`._

```json
{
  "chainid": 56,
  "txhash": "0xb6a9055e3ce7f006391760fbbcc4e4bc8df8228dc47a8bb4ff657370ccc49256",
  "from": "0x00000000dd0412366388639b1101544FFF2dCe8D",
  "to": "0x802a389072c4310CF78A2e654Fa50FaC8bDC1a55",
  "block_number": 44857311,
  "value": "0",
  "gasUsed": 1184991
}
```

**Evidence snippet – Key artifacts used for σ_B**

_Source: Root cause seed and data collector artifacts._

```json
[
  "seed metadata and trace (metadata.json, trace.cast.log)",
  "balance_diff.json for token and pool deltas",
  "state_diff_prestateTracer_jhy_and_tracker.json for storage diffs",
  "JHYToken verified source Contract.sol",
  "Dividend tracker, aggregator, and helper decompiles"
]
```

### Transaction Sequence b

The ACT opportunity is realized via a single adversary-crafted transaction:

- **Index**: 1
- **Chain id**: 56 (BSC)
- **Tx hash**:
  `0xb6a9055e3ce7f006391760fbbcc4e4bc8df8228dc47a8bb4ff657370ccc49256`
- **Type**: adversary-crafted

**Inclusion feasibility**

The transaction is a standard BSC transaction:
- Sent by unprivileged EOA
  `0x00000000dd0412366388639b1101544FFF2dCe8D`.
- Targets a publicly deployed contract
  `0x802a389072c4310CF78A2e654Fa50FaC8bDC1a55`.
- Uses sufficient gas and fee.
- Calls only permissionless router, pair, and helper contracts; the trace does
  not involve privileged roles, allowlists, or non-standard inclusion rules.

**Evidence snippet – High-level call graph**

_Source: `trace.cast.log` for the seed transaction (cast run -vvvvv)._  
_This excerpt shows the EOA calling the aggregator, which in turn uses the
 helper, the USDT/WBNB pair, and the Pancake router._

```text
[1366023] 0x802a389072c4310CF78A2e654Fa50FaC8bDC1a55::3847dc7c(...)
  ├─ 0xAeee14beAac31e7c7c03720f1b173a3Fe110664d::1a94cd12(...)
  │  ├─ 0x36696169C63e42cd08Ce11F5DeeBbCeBae652050::flash(..., 25000000000000000000000, ...)
  │  ├─ BEP20USDT::transfer(0xAeee14..., 25000000000000000000000)
  │  └─ Pancake router and JHY/USDT pair interactions (swaps, add/remove-liquidity)
```

The calldata selector `0x3847dc7c` invokes an aggregator entrypoint that
orchestrates this entire sequence.

## 3. Exploit Predicate (Profit)

The exploit predicate is **profit** in a USD reference asset (USDT treated as
USD-pegged).

- **Reference asset**: USD (via BEP20 USDT
  `0x55d398326f99059fF775485246999027B3197955`).
- **Adversary address**: EOA
  `0x00000000dd0412366388639b1101544FFF2dCe8D`.
- **Fees paid**: 12.5 USDT flash-loan fee plus ~0.00131534001 BNB gas.
- **Value_before (USD)**: Not fixed in absolute terms; prior USDT holdings are
  not required to establish the transaction delta.
- **Value_after (USD)**: Value_before plus 
  `~11,204.841801912892665969` USDT net gain, minus the 12.5 USDT fee and gas.
- **Value_delta (USD)**: Approximately
  `+11,192.341801912892665969` USDT net of the 12.5 USDT fee, excluding gas.

**Evidence snippet – Balance diffs for USDT and gas**

_Source: `balance_diff.json` for the seed transaction._

```json
{
  "native_balance_deltas": [
    {
      "address": "0x00000000dd0412366388639b1101544fff2dce8d",
      "delta_wei": "-1315340010000000"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x36696169c63e42cd08ce11f5deebbcebae652050",
      "delta": "12500000000000000000"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x086ecf61469c741a6f97d80f2f43342af3dbdb9b",
      "delta": "-11217341801912892665969"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x00000000dd0412366388639b1101544fff2dce8d",
      "delta": "11204841801912892665969"
    }
  ]
}
```

Caption: The EOA pays ~0.0013 BNB in gas and ends with a net increase of
`11,204.841801912892665969` USDT. The JHY/USDT pair loses
`11,217.341801912892665969` USDT, and the USDT/WBNB pair gains `12.5` USDT,
consistent with the flash-loan fee and adversary profit described in the
profit predicate.

## 4. Vulnerability & Root Cause Analysis

### 4.1 JHYToken Sell Path and Dividend Accounting Bug

For sells into the JHY/USDT pair (`to == uniswapPair`), JHYToken’s `_transfer`
function:

1. Sends a burn fee to `_deadWalletAddress` equal to `amount * sellDead / 100`.
2. Sends a dividend fee to the external dividend tracker equal to
   `amount * sellLP / 100`.
3. Calls `TokenDividendTracker(dividendLPTracker).distributeCAKEDividends` with
   `amount.mul(sellLP)`.
4. Calls `setBalance` on the tracker with the LP balance for `from`.
5. Subtracts `amount * (sellLP + sellDead) / 100` from `amount` and completes
   the transfer to `to`.

The bug is that **the argument to `distributeCAKEDividends` is not scaled by
100**, while the actual transfer to the dividend tracker is.

- Deposited into tracker per sell: `amount * sellLP / 100` JHY.
- Used for dividend accounting per sell: `amount * sellLP` JHY.

This causes the tracker to treat each sell as if it had received 100× more
JHY than it actually did. Over time, and particularly in the exploit
transaction, the tracker’s internal accounting over-credits LP holders’ claim
amounts relative to the real JHY it holds.

### 4.2 Concrete Over-Distribution in the Incident Transaction

In the observed transaction, the aggregator adds liquidity to the JHY/USDT
pair using JHYToken and USDT. The relevant steps are:

- The aggregator uses the router to swap USDT into JHYToken.
- It then calls add-liquidity to the JHY/USDT pair, triggering
  JHYToken’s sell path.
- During this process, the dividend tracker receives a relatively small
  amount of JHY, but `distributeCAKEDividends` is called with a value that is
  larger by a factor of 100.

**Evidence snippet – Over-credited tracker vs. actual balances**

_Source: Analyzer reasoning plus `trace.cast.log` and
 `state_diff_prestateTracer_jhy_and_tracker.json`._

```text
• A transfer of approximately 3.3228e20 JHY into the tracker
  corresponds to a distributeCAKEDividends call with ~3.3228e22 JHY
  (100× the actual transfer), emitting a DividendsDistributed event
  with that larger amount.
• Subsequent process() and setBalance() calls for the aggregator’s address
  cause DividendWithdrawn and JHYToken::transfer events in which the
  tracker sends ~9.8905e22 JHY to the aggregator, while the tracker’s own
  JHY balance decreases by ~9.6251e22 JHY and the JHY/USDT pair and burn
  address balances increase.
```

These quantities match the storage and balance diffs:

- Dividend tracker JHY balance delta:
  `-96251363077418779632524` (`~9.6251e22` JHY).
- JHY/USDT pair JHY balance increases by
  `90943493991270018344100` JHY.
- Burn address JHY balance increases by
  `5307869086148761288424` JHY.

**Evidence snippet – JHY deltas for tracker, pair, and burn**

_Source: `balance_diff.json` (JHYToken entries)._  
_This shows the tracker losing ~9.63e22 JHY, with corresponding gains to the
 pair and burn address._

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x30bea8ce5cd1ba592eb13fccd8973945dc8555c5",
      "holder": "0x086ecf61469c741a6f97d80f2f43342af3dbdb9b",
      "delta": "90943493991270018344100"
    },
    {
      "token": "0x30bea8ce5cd1ba592eb13fccd8973945dc8555c5",
      "holder": "0x000000000000000000000000000000000000dead",
      "delta": "5307869086148761288424"
    },
    {
      "token": "0x30bea8ce5cd1ba592eb13fccd8973945dc8555c5",
      "holder": "0x40cd735d49e43212b5cb0b19773ec2a648aaa96c",
      "delta": "-96251363077418779632524"
    }
  ]
}
```

The combination of JHYToken’s `_transfer` logic and these diffs is sufficient
to attribute the over-distribution deterministically to the token contract’s
buggy call to `distributeCAKEDividends`.

### 4.3 Dividend Tracker and Aggregator Roles

- The dividend tracker contract `0x40Cd735D49e43212B5cb0b19773Ec2A648aAA96c`
  maintains LP balances and processes dividend distributions and withdrawals.
  Its decompiled code and storage diffs show it reacting to
  `distributeCAKEDividends`, `setBalance`, and `process` calls from JHYToken.
- The aggregator `0x802a389072c4310CF78A2e654Fa50FaC8bDC1a55` and helper
  `0xAeee14beaac31e7c7c03720f1b173a3Fe110664d` coordinate the flash loan,
  router calls, liquidity operations, and the final swap of JHY dividends back
  to USDT.

Together, these components implement a strictly permissionless sequence that
exercises the JHYToken dividend accounting bug to drain value.

## 5. Adversary Flow Analysis

This section walks through the lifecycle stages of the adversary’s flow.

### 5.1 Flash Loan and Initial Swaps

- The helper contract calls the USDT/WBNB pair’s `flash` function to borrow
  `25,000e18` USDT.
- The helper and aggregator route this USDT through PancakeSwap to obtain
  JHYToken and to position liquidity in the JHY/USDT pair.

**Evidence snippet – Flash loan and transfer to helper**

_Source: `trace.cast.log` for the seed transaction._

```text
0x36696169C63e42cd08Ce11F5DeeBbCeBae652050::flash(
  0xAeee14beAac31e7c7c03720f1b173a3Fe110664d,
  25000000000000000000000,
  0,
  ...
)
  ├─ BEP20USDT::transfer(0xAeee14..., 25000000000000000000000)
  ├─ ... router swaps and JHY/USDT liquidity operations ...
```

Caption: The pair lends exactly `2.5e22` USDT to the helper, matching the
flash-loan principal described in the profit calculation.

### 5.2 Adversary Liquidity Operations and Dividend Over-Crediting

- The aggregator adds liquidity to the JHY/USDT pair using JHYToken and USDT.
- This triggers JHYToken’s `_transfer` sell path, sending JHY tokens to the
  burn address and the dividend tracker and calling
  `distributeCAKEDividends(amount.mul(sellLP))`.
- `setBalance` and `process` are invoked for the aggregator’s LP address,
  aligning its LP balance with the tracker’s internal accounting.
- Because the tracker uses the larger `amount * sellLP` figure for dividends
  while only receiving `amount * sellLP / 100` per sell, it credits and
  withdraws JHYToken dividends that draw heavily on its pre-existing balance.

**Evidence snippet – USDT profit transfer to EOA**

_Source: `trace.cast.log` near the end of the transaction._

```text
BEP20USDT::transfer(0x00000000dd0412366388639B1101544FFF2dCe8D,
                    11204841801912892665969)
  └─ emit Transfer(
       from: 0x802a389072c4310CF78A2e654Fa50FaC8bDC1a55,
       to:   0x00000000dd0412366388639B1101544FFF2dCe8D,
       value: 11204841801912892665969
     )
```

Caption: This matches the USDT delta in `balance_diff.json` and represents the
adversary’s gross USDT proceeds from the exploit.

### 5.3 Profit Realization and Flash-Loan Repayment

- The aggregator swaps the received JHYToken dividends 
  (approximately `1.01964224351023876573954e23` JHY in total) back into USDT
  on the JHY/USTS pair.
- It repays the `25,000e18` USDT flash loan plus a `12.5e18` USDT fee to the
  USDT/WBNB pair.
- It then transfers the remaining USDT to the adversary EOA.

Net result:

- The EOA realizes a **profit of ~11,192.34 USDT** after fees.
- The JHY/USDT pool loses the same USDT (up to rounding and the fee paid to
  the flash-loan pair).
- The dividend tracker’s JHY balance is significantly reduced.

## 6. Impact & Losses

### 6.1 Aggregate Losses

- **Total USDT loss (pool)**: Approximately
  `11,217.341801912892665969` BEP20USDT.
- **Adversary USDT gain**: Approximately
  `11,204.841801912892665969` BEP20USDT net of the flash-loan fee.

From `root_cause.json`:

```json
"total_loss_overview": [
  {
    "token_symbol": "BEP20USDT",
    "amount": "11217.341801912892665969"
  }
]
```

### 6.2 Per-Component Effects

- **JHY/USDT PancakeSwap pool** (`0x086Ecf...3dBDB9B`):
  - Loses ~`11,217.341801912892665969` USDT over the transaction.
- **Adversary EOA** (`0x00000000dd0412366388639b1101544FFF2dCe8D`):
  - Gains ~`11,204.841801912892665969` USDT, minus gas.
- **Dividend tracker** (`0x40Cd735D49e43212B5cb0b19773Ec2A648aAA96c`):
  - JHYToken balance decreases by ~`9.6251363077418779632524e22` JHY.
- **JHY/USDT pair and burn address**:
  - Receive JHY increments consistent with fee routing and the tracker’s
    over-distribution during the exploit.

These effects collectively represent a direct value transfer from the pool and
tracker to the adversary cluster, driven by the misconfigured dividend
accounting in JHYToken.

## 7. Adversary-Related Accounts

The analysis identifies a clear adversary cluster:

- **EOA (primary adversary)**:
  - `0x00000000dd0412366388639b1101544FFF2dCe8D`
  - Sends the seed transaction and receives the final USDT profit.
- **Aggregator contract**:
  - `0x802a389072c4310CF78A2e654Fa50FaC8bDC1a55`
  - Direct callee of the seed transaction; orchestrates swaps and liquidity
    operations.
- **Flash-loan helper**:
  - `0xAeee14beaac31e7c7c03720f1b173a3Fe110664d`
  - Obtains the USDT flash loan from `0x36696169...` and interacts with the
    router and JHY/USDT pair on behalf of the aggregator.

On-chain traces and balance flows link these addresses tightly:

- The EOA funds the transaction and receives the final USDT balance increase.
- The aggregator and helper perform all intermediate operations, including the
  flash loan, JHY/USDT liquidity operations, dividend over-distribution, and
  final swap back to USDT.

## 8. References

The following artifacts support the analysis and can be consulted for
full detail:

1. **Seed transaction metadata and trace**  
   `artifacts/root_cause/seed/56/0xb6a9055e3ce7f006391760fbbcc4e4bc8df8228dc47a8bb4ff657370ccc49256/`

2. **JHYToken verified source (`Contract.sol`)**  
   `artifacts/root_cause/seed/_contracts/56/0x30bea8ce5cd1ba592eb13fccd8973945dc8555c5/source/src/Contract.sol`

3. **Dividend tracker decompile**  
   `artifacts/root_cause/data_collector/iter_1/contract/56/0x40Cd735D49e43212B5cb0b19773Ec2A648aAA96c/decompile/0x40Cd735D49e43212B5cb0b19773Ec2A648aAA96c-decompiled.sol`

4. **Aggregator and helper decompiles**  
   `artifacts/root_cause/data_collector/iter_1/contract/56/`

5. **State diff for JHYToken and dividend tracker**  
   `artifacts/root_cause/data_collector/iter_1/tx/56/0xb6a9055e3ce7f006391760fbbcc4e4bc8df8228dc47a8bb4ff657370ccc49256/state_diff_prestateTracer_jhy_and_tracker.json`

---

This report is fully consistent with `root_cause.json` and the on-chain
artifacts, and describes a deterministic ACT-style profit opportunity driven
by a protocol bug in JHYToken’s dividend distribution logic.
