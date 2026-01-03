# AaveBoost brAAVE Zero-Amount Reward Extraction

## 1. Incident Overview & TL;DR

- **Protocol:** AaveBoost / brAAVE Pool on Ethereum mainnet
- **Key contracts:**
  - AaveBoost: `0xd2933c86216dc0c938ffafeca3c8a2d6e633e2ca`
  - AavePool: `0xf36f3976f288b2b4903aca8c177efc019b81d88b`
  - brAAVE wrapper token: `0x740836c95c6f3f49cccc65a27331d1f225138c39`
  - Router used by adversary: `0x8fa5cf0aa8af0e5adc7b43746ea033ca1b8e68de`
  - Adversary EOA: `0x5d4430d14ae1d11526ddac1c1ef01da3b1dae455`

**TL;DR:**

A public router contract uses AaveBoost and AavePool to drain 48.9 AAVE of pre-funded rewards from AaveBoost in a single transaction without contributing any AAVE. It does this by repeatedly calling `AaveBoost::proxyDeposit` with `amount = 0`, which still grants a fixed AAVE REWARD each time, minting brAAVE receipt tokens to the router. After accumulating 48.9 brAAVE, the router calls `AavePool::withdraw` to burn the brAAVE and receive 48.9 AAVE, then immediately transfers the entire 48.9 AAVE to the adversary EOA.

This pattern is **ACT-positive**: relative to the defined pre-state, the adversary cluster `{EOA, router}` starts with 0 AAVE in this system and ends with 48.9 AAVE, funded entirely by AaveBoost’s reward balance.

## 2. ACT Opportunity and Pre-State (σ
a

### 2.1 Block and State Definition

- **Block height B:** `22685444` (Ethereum mainnet)
- **Pre-state σ
a:** Ethereum state just before block 22685444 with the following properties:
  - AaveBoost holds a positive AAVE balance funded by earlier reward top-ups and user deposits.
  - The adversary cluster `{EOA 0x5d4430..., router 0x8fa5...}` has **no prior AAVE transfers involving AaveBoost or AavePool**.

This is established by inspecting AAVE ERC20 transfer logs for AaveBoost, AavePool, the router, and the EOA.

```json
// AAVE ERC20 transfer history for adversary EOA and router (excerpt)
[
  {
    "from": "0x984731878f8533f6580dddf8806a1712f2c672de",
    "to":   "0x5d4430d14ae1d11526ddac1c1ef01da3b1dae455",
    "value": "34592226785448109"
  },
  {
    "from": "0x5d4430d14ae1d11526ddac1c1ef01da3b1dae455",
    "to":   "0x74de5d4fcbf63e00296fd95d33236b9794016631",
    "value": "34592226785448109"
  },
  {
    "from": "0x8fa5cf0aa8af0e5adc7b43746ea033ca1b8e68de",
    "to":   "0xd2933c86216dc0c938ffafeca3c8a2d6e633e2ca",
    "value": "0"
  }
]
```

*Caption: Excerpt from AAVE ERC20 histories showing no non-zero AAVE transfers between the adversary cluster and AaveBoost/AavePool prior to the exploit transaction; the only interaction with AaveBoost from the router uses zero AAVE value.*

### 2.2 Transaction Sequence **b** (Adversary Path)

The ACT opportunity is realized by a single adversary-crafted transaction:

- **Chain:** Ethereum mainnet (`chainid = 1`)
- **Tx hash:** `0xc4ef3b5e39d862ffcb8ff591fbb587f89d9d4ab56aec70cfb15831782239c0ce`
- **Sender (EOA):** `0x5d4430d14ae1d11526ddac1c1ef01da3b1dae455`
- **Target:** Router `0x8fa5cf0aa8af0e5adc7b43746ea033ca1b8e68de`
- **ETH value:** 0
- **Inclusion feasibility:** The router function is public, all contracts are already deployed, and no privileged roles or non-standard infrastructure are used. Any searcher can construct and submit an equivalent transaction.

Within this transaction, the router:

1. Repeatedly calls `AaveBoost::proxyDeposit(asset = AAVE, recipient = router, amount = 0)`.
2. After accumulating 48.9 brAAVE on the router, calls `AavePool::withdraw(asset = AAVE, recipient = router, amount = 48.9 AAVE, claim = true)`.
3. Transfers the resulting 48.9 AAVE from the router to the EOA.

```json
// Seed transaction metadata (simplified)
{
  "txhash": "0xc4ef3b5e39d862ffcb8ff591fbb587f89d9d4ab56aec70cfb15831782239c0ce",
  "from":   "0x5d4430d14ae1d11526ddac1c1ef01da3b1dae455",
  "to":     "0x8fa5cf0aa8af0e5adc7b43746ea033ca1b8e68de",
  "value":  "0"
}
```

*Caption: Seed transaction metadata showing the EOA calling the router with 0 ETH, which orchestrates the full exploit flow.*

## 3. Root Cause: Protocol Bug in AaveBoost and AavePool

### 3.1 AaveBoost Reward Logic (Fixed REWARD on Every Deposit)

AaveBoost is designed to subsidize deposits into AavePool by topping up each qualifying deposit with a fixed AAVE reward (`REWARD`) from AaveBoost’s own balance.

```solidity
// AaveBoost.sol (AaveBoost 0xd2933...)
function proxyDeposit(
    IERC20 asset,
    address recipient,
    uint128 amount
) external {
    if (aave.balanceOf(address(this)) >= REWARD) {
        aave.safeTransferFrom(msg.sender, address(this), amount);
        pool.deposit(asset, recipient, amount + REWARD, false);
    } else {
        // fallback to a normal deposit
        pool.deposit(asset, recipient, amount, false);
    }
}
```

*Caption: Verified AaveBoost source showing that as long as AaveBoost holds at least `REWARD` AAVE, it unconditionally adds `REWARD` to every deposit and funds `amount + REWARD` from its own AAVE balance.*

Key observations:

- The `if` branch condition only checks `aave.balanceOf(address(this)) >= REWARD`.
- It does **not** require `amount > 0`.
- When the condition holds, AaveBoost transfers `amount` AAVE from the caller (which can be zero) and calls `pool.deposit` with `amount + REWARD`, funded by AaveBoost.

This means that if AaveBoost is pre-funded with AAVE, a caller can repeatedly invoke `proxyDeposit` with `amount = 0` to farm `REWARD` AAVE into AavePool on behalf of an arbitrary recipient without contributing any AAVE.

### 3.2 AavePool Wrapper Logic (brAAVE Mint and Burn)

AavePool wraps AAVE (and stkAAVE) deposits into wrapper tokens that track claimable balances. For AAVE deposits, it mints `wrapperAaveToken` (brAAVE), and on withdrawal burns wrapper tokens and returns AAVE.

```solidity
// AavePool.sol (AavePool 0xf36f3...)
function deposit(
    IERC20 asset,
    address recipient,
    uint128 amount,
    bool claim
) external override whenNotPaused nonReentrant {
    if (asset == aaveToken) {
        _deposit(asset, wrapperAaveToken, recipient, amount, claim);
    } else {
        _deposit(stkAaveToken, wrapperStkAaveToken, recipient, amount, claim);
    }
}

function withdraw(
    IERC20 asset,
    address recipient,
    uint128 amount,
    bool claim
) external override nonReentrant {
    if (asset == aaveToken) {
        _withdraw(asset, wrapperAaveToken, recipient, amount, claim);
    } else {
        _withdraw(stkAaveToken, wrapperStkAaveToken, recipient, amount, claim);
    }
}
```

*Caption: AavePool entry points for deposits and withdrawals, delegating AAVE flows to the `wrapperAaveToken` (brAAVE) wrapper.*

Internally, `_deposit` mints brAAVE to the `recipient` proportional to the AAVE amount supplied. `_withdraw` burns brAAVE from the caller and transfers the requested AAVE amount to `recipient`.

Combined with AaveBoost’s logic, this means that when AaveBoost calls `pool.deposit` with `asset = AAVE` and `amount = REWARD` but the external caller supplied `amount = 0`, AavePool will still mint `REWARD` brAAVE to the chosen `recipient`, backed entirely by AaveBoost’s AAVE.

### 3.3 Vulnerability Summary

The vulnerability is a **protocol bug** arising from:

1. **AaveBoost** granting a fixed AAVE REWARD in `proxyDeposit` whenever it has enough balance, regardless of whether the external `amount` is zero.
2. **AavePool** minting brAAVE for any AAVE amount transferred from AaveBoost, with no awareness that the external caller supplied no AAVE.
3. The ability of an unprivileged router to loop `proxyDeposit(amount = 0)` and then withdraw the accumulated brAAVE into raw AAVE for itself.

This creates a direct path for any caller to convert AaveBoost’s pre-funded rewards into AAVE for themselves without providing AAVE.

## 4. Adversary Flow and Wrapper-Token Reconciliation

### 4.1 Zero-Amount proxyDeposit Loop

In the exploit transaction `0xc4ef3b5e...`, the router repeatedly calls:

```solidity
// Conceptual call from router
AaveBoost.proxyDeposit(AAVE, router, 0);
```

Each successful call causes:

- AaveBoost to send `0.3 AAVE` from its own balance to AavePool.
- AavePool to mint `0.3 brAAVE` to the router.

From ERC20 logs in the seed transaction and reward-deposit summary:

```json
// AaveBoost -> AavePool AAVE transfers in tx 0xc4ef... (excerpt)
[
  { "from": "0xd2933c86216dc0c938ffafeca3c8a2d6e633e2ca", "to": "0xf36f3...", "value": "300000000000000000" },
  { "from": "0xd2933c86216dc0c938ffafeca3c8a2d6e633e2ca", "to": "0xf36f3...", "value": "300000000000000000" },
  "... many similar entries ..."
]
```

*Caption: AaveBoost-funded AAVE transfers of 0.3 AAVE each to AavePool in the exploit transaction, corresponding to repeated zero-amount `proxyDeposit` calls.*

### 4.2 brAAVE Minting and Burning for the Router

The brAAVE ERC20 history for the router shows many 0.3 brAAVE mints from the zero address and a final 48.9 brAAVE burn back to the zero address in the same transaction:

```json
// brAAVE transfers for router in tx 0xc4ef... (excerpt)
[
  { "from": "0x0000000000000000000000000000000000000000", "to": "0x8fa5cf0a...", "value": "300000000000000000" },
  { "from": "0x0000000000000000000000000000000000000000", "to": "0x8fa5cf0a...", "value": "300000000000000000" },
  "... many similar mints ...",
  { "from": "0x8fa5cf0a...", "to": "0x0000000000000000000000000000000000000000", "value": "48900000000000000000" }
]
```

*Caption: brAAVE wrapper-token history for the router in the exploit transaction: repeated 0.3 brAAVE mints culminating in a 48.9 brAAVE burn when the router withdraws AAVE from AavePool.*

This is consistent with:

- Total brAAVE minted to router: **48.9 brAAVE**.
- Final brAAVE burn: **48.9 brAAVE**.

The net brAAVE balance for the router after the transaction is zero, and all brAAVE has been converted into AAVE via `AavePool::withdraw`.

### 4.3 AAVE Withdraw and Payout to EOA

The AAVE ERC20 transfer history shows:

1. AavePool sends 48.9 AAVE to the router.
2. The router sends 48.9 AAVE to the EOA.

```json
// AAVE transfers in tx 0xc4ef... for AavePool, router, and EOA
[
  { "from": "0xf36f3976f288b2b4903aca8c177efc019b81d88b", "to": "0x8fa5cf0aa8af0e5adc7b43746ea033ca1b8e68de", "value": "48900000000000000000" },
  { "from": "0x8fa5cf0aa8af0e5adc7b43746ea033ca1b8e68de", "to": "0x5d4430d14ae1d11526ddac1c1ef01da3b1dae455", "value": "48900000000000000000" }
]
```

*Caption: AAVE transfer log for the exploit tx: AavePool pays 48.9 AAVE to the router, which forwards all 48.9 AAVE to the adversary EOA.*

The balance-diff tracer for the seed transaction confirms that the EOA only pays ETH gas and does not send out any AAVE in this transaction.

```json
// Seed transaction balance diff (excerpt)
{
  "native_balance_deltas": [
    {
      "address": "0x5d4430d14ae1d11526ddac1c1ef01da3b1dae455",
      "delta_wei": "-13322486924693596"
    }
  ],
  "erc20_balance_deltas": []
}
```

*Caption: Balance diff for tx 0xc4ef... showing the EOA only loses ETH for gas; AAVE deltas are captured via ERC20 logs and show a net gain of 48.9 AAVE for the EOA.*

### 4.4 Wrapper-Token Reconciliation for Other Recipients

The analysis also reconciles AaveBoost-funded deposits with wrapper-token lifecycles for other recipients using:

- `aaveboost_reward_deposits.json` (AaveBoost -> AavePool reward transfers), and
- `wrapper_tokentx_summary.json` (per-recipient histories for `wrapperAaveToken` and `wrapperStkAaveToken`).

A key example is address `0xb27607d0954752d8029a9c1ec0b65f92e8011e58`, which previously appeared suspicious.

From brAAVE logs for this address:

```json
// brAAVE history for 0xb27607d0...
[
  {
    "from": "0x0000000000000000000000000000000000000000",
    "to":   "0xb27607d0954752d8029a9c1ec0b65f92e8011e58",
    "value": "1200006000000000000000"  // 1,200.006 brAAVE
  },
  {
    "from": "0x0000000000000000000000000000000000000000",
    "to":   "0xb27607d0954752d8029a9c1ec0b65f92e8011e58",
    "value": "800304000000000000000"  // 800.304 brAAVE
  },
  {
    "from": "0xb27607d0954752d8029a9c1ec0b65f92e8011e58",
    "to":   "0x0000000000000000000000000000000000000000",
    "value": "2000310000000000000000" // 2,000.31 brAAVE burn
  }
]
```

*Caption: brAAVE lifecycle for 0xb27607..., showing 1,200.006 + 800.304 brAAVE minted and a single 2,000.31 brAAVE burn during withdrawal.*

Cross-checking AAVE ERC20 transfers between this address and AavePool:

- Direct deposit: `1,200.006 AAVE` from `0xb27607...` to AavePool.
- AaveBoost-funded deposit: `800.304 AAVE` from AaveBoost to AavePool on behalf of `0xb27607...`.
- Withdraw: `2,000.31 AAVE` from AavePool to `0xb27607...`.

This matches exactly: total brAAVE minted (2,000.31) equals total AAVE that can be withdrawn, and the withdrawn AAVE equals direct deposit plus AaveBoost-funded rewards. There is **no unexplained surplus** for this or other recipients; any AaveBoost-funded rewards are either still locked in outstanding brAAVE positions or matched by the recipients’ own deposits.

## 5. ACT Determination and Profit Computation

### 5.1 Reference Asset and Adversary Cluster

- **Reference asset:** AAVE
- **Adversary cluster:** `{ EOA 0x5d4430..., router 0x8fa5... }`

The ACT analysis is scoped to on-chain AAVE transfers involving this cluster and the victim contracts AaveBoost and AavePool.

### 5.2 Pre-State Value (Before σ
a)

By inspecting historical AAVE ERC20 logs:

- There are **no AAVE transfers** between the cluster and AaveBoost or AavePool before block 22685444.
- The router’s only interactions with AaveBoost are zero-value AAVE transfers in the exploit transaction.
- The EOA has AAVE activity with other protocols (e.g., aggregators, Balancer), but none with AaveBoost or AavePool.

Therefore, relative to this reward system:

- `value_before_in_reference_asset = 0 AAVE` for the adversary cluster.

### 5.3 Post-State Value (After σ
a + b)

From the exploit transaction logs:

- AavePool pays **48.9 AAVE** to the router.
- The router forwards **48.9 AAVE** to the EOA.
- No AAVE leaves the cluster in this transaction.

Thus, after the transaction sequence **b**:

- `value_after_in_reference_asset = 48.9 AAVE` for the cluster.

### 5.4 Profit and Fees

- `fees_paid_in_reference_asset = 0` (gas is paid in ETH only).
- `value_delta_in_reference_asset = 48.9 AAVE - 0 AAVE = 48.9 AAVE`.

The analysis concludes, and the evidence confirms, that:

- The adversary cluster extracts **48.9 AAVE** funded entirely by AaveBoost’s reward balance.
- No part of this 48.9 AAVE is sourced from the cluster’s own AAVE contributions to AavePool or AaveBoost.
- No other wrapper-token or AAVE flows undermine this conclusion.

This satisfies the ACT criteria: the adversary’s profit in the reference asset is clear, deterministically computed from on-chain data, and attributable to the protocol bug.

## 6. Impact and Losses

### 6.1 Quantitative Impact

- **Victim token:** AAVE
- **Total loss:** `48.9 AAVE`

The loss arises from AaveBoost’s AAVE balance decreasing while the adversary EOA’s AAVE balance increases:

- AaveBoost funds multiple 0.3 AAVE transfers to AavePool in the exploit transaction.
- AavePool converts the corresponding brAAVE into 48.9 AAVE for the router.
- The router pays all 48.9 AAVE to the EOA.

### 6.2 Distribution of Losses and Non-Adversarial Users

Reconciliation using `aaveboost_reward_deposits.json` and `wrapper_tokentx_summary.json` shows that for all other reward recipients:

- Either they have withdrawn no more AAVE than the sum of their own AAVE deposits plus AaveBoost-funded rewards, **or**
- They still hold outstanding brAAVE positions representing their remaining claim on AaveBoost-funded AAVE.

The only address that realizes an unambiguous net AAVE profit from AaveBoost’s rewards without providing AAVE is the adversary cluster `{EOA 0x5d4430..., router 0x8fa5...}` via the zero-amount proxyDeposit loop.

## 7. References and Evidence Index

- **[1] Seed transaction metadata and trace**
  - Source: Collected seed artifacts for tx `0xc4ef3b5e39d862ffcb8ff591fbb587f89d9d4ab56aec70cfb15831782239c0ce`.
  - Includes transaction metadata, execution trace, and balance diff.

- **[2] AaveBoost verified source and ABI**
  - Source: Verified contract bundle for `0xd2933c86216dc0c938ffafeca3c8a2d6e633e2ca`.
  - Shows the `proxyDeposit` implementation and REWARD logic.

- **[3] AavePool verified source and ABI**
  - Source: Verified contract bundle for `0xf36f3976f288b2b4903aca8c177efc019b81d88b`.
  - Shows wrapper token initialization and deposit/withdraw mechanics.

- **[4] AaveBoost-funded deposits and per-recipient mapping**
  - Source: Derived data summarizing AaveBoost → AavePool AAVE transfers and tying them to recipients.

- **[5] Wrapper-token ERC20 histories for reward recipients, router, AavePool, and AaveBoost**
  - Source: Per-address histories for `wrapperAaveToken` and `wrapperStkAaveToken` (including the adversary router and key recipients like `0xb27607...`).

Together, these artifacts fully support the ACT-positive conclusion: a protocol bug in AaveBoost and AavePool allowed an unprivileged adversary to realize a deterministic profit of **48.9 AAVE** by stripping pre-funded rewards via zero-amount deposits.
