# Incident Overview TL;DR

On BSC (chainid 56), helper contract `0xB5CB0555c4A333543DbE0b219923C7B3e9D84a87`, deployed and controlled by EOA
`0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c`, executed three transactions that drained the full token and vToken
portfolios of vault contracts `0xb5cb0555c0c51e603ead62c6437da65372e4e1b0` and
`0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c` into `0xd5c6…`. The helper repeatedly invoked the vault drain function
with selector `0x0243f5a2` via Venus Unitroller/PolicyFacet and `VBep20Delegate::transfer`, transferring all tracked
balances for specified assets in each call. In each transaction the adversary address paid only BNB gas while receiving
large quantities of BEP20 and vToken assets, as shown by the balance diffs.

The direct root cause is privileged use of an authorization-gated drain interface on the vault contracts by helper
contract `0xB5CB0555c4A3…` after it was explicitly authorized by governance and operator addresses. Traces and state
diffs show that the drain function is restricted to authorized callers. The sequence therefore represents misuse of
privileged withdrawal authority (operator/key error), not a permissionless smart-contract exploit under the ACT
adversary model.

---

## Key Background

- The Venus Protocol on BSC uses vault-like contracts `0xb5cb0555c0c51e603ead62c6437da65372e4e1b0` and
  `0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c` to aggregate positions in multiple BEP20 tokens and vTokens, including
  assets such as USDT, USDC, BTCB, ETH, BUSD, and protocol-specific tokens.
- Vault contracts maintain an authorization set in storage that is updated via functions decoded as `authorize(address)`
  (selector `0x268a066f`) and revoke-like operations. This set controls which EOAs or helper contracts can call
  powerful functions such as the `0x0243f5a2` drain interface.
- Governance or administrative contract `0x3801410dcea87efa2141ecc866ecad5e020028dc` and operator EOA
  `0x7aa5fdb97a2923b082305ca66f2e7bd7ea2452b1` send transactions that add and remove helper addresses from the vault
  authorization set, as confirmed by txlists and state diffs.
- Helper contract `0xB5CB0555c4A333543DbE0b219923C7B3e9D84a87` is deployed by adversary EOA `0xd5c6…` and, after being
  authorized, can call `0x0243f5a2` on the vaults to transfer entire token portfolios for specified assets to
  `0xd5c6…` in single transactions.

A representative on-chain snippet for the vault contract `0xb5cb0555c0c5…`, obtained from
`state_diff_prestate_full.json` for authorization-management tx `0x8e7e1960fcf7fdff7b382ee736c1e45eacc79182b006bbe9fb9153b5884b7c77`,
shows the deployed bytecode and confirms the presence of `authorize` and drain selectors:

```solidity
// Disassembled vault bytecode excerpt (BSC, 0xb5cb0555c0c51e603ead62c6437da65372e4e1b0)
// Selectors visible in the dispatcher include:
//   0x0243f5a2  // drain interface used to move full portfolios
//   0x268a066f  // authorize(address) for managing the helper authorization set
//   ...         // additional vault management functions
// The storage snapshot shows authorization state at slot
//   0xf67c83c47782efdccd49b3d84f0499c130ebbd12804c0e45b3431c05b19ed74f
// toggling between 0x1 and 0x0 as helper authorization is granted and revoked.
```

The ACT opportunity is defined over BSC block `52052493`, just prior to the first draining transaction
`0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44`. The pre-state is reconstructed using
`metadata.json` and `balance_diff.json` for the three draining transactions under `artifacts/root_cause/seed/56/`.

---

## Vulnerability Analysis

The relevant system components and permissions are:

- **Vault 1 – B5CB vault `0xb5cb0555c0c5…`**: Venus BSC vault contract that aggregates vToken and token positions for a
  portfolio of assets. It exposes an authorization-gated drain function with selector `0x0243f5a2` and management
  functions including `authorize(address)` and revoke-like controls.
- **Vault 2 – B5CB vault `0xb5cb0555a1d…`**: Second Venus BSC vault contract with the same drain and authorization
  pattern, holding a different portfolio (including ETH, USDT, BTCB, USDC, TUSD, and StablecoinV2).
- **Helper contract `0xB5CB0555c4A3…`**: Deployed by adversary EOA `0xd5c6…`, this contract is granted vault
  authorization and then used to execute full-balance drains against both vaults in three transactions.
- **Governance/administrative contract `0x3801410dcea87efa2141ecc866ecad5e020028dc` and operator EOA
  `0x7aa5fdb97a2923b082305ca66f2e7bd7ea2452b1`**: These addresses manage the vault authorization set and enable
  helper contracts like `0xB5CB0555c4A3…` to acquire drain authority.

The key violated security principles are:

- **Least privilege and separation of duties**: A single helper address is able to transfer entire vault portfolios in
  one call, concentrating withdrawal authority and bypassing granular limits.
- **Robust governance and key management**: Governance and operator flows grant and maintain powerful permissions for
  the helper such that it can drain entire vaults without additional safeguards such as time locks, multi-party
  approvals, or rate limits.

The vulnerability is therefore not a bug in the on-chain enforcement logic of the vault contracts. Instead, it is an
operator/governance-level failure to maintain strict controls over a highly privileged drain interface that behaves as
implemented.

---

## Detailed Root Cause Analysis

### ACT adversary model and feasibility

Under the ACT adversary model, an exploit must be reproducible by an **unprivileged** on-chain actor starting from
public pre-state at the chosen block. For this incident, the following conditions would need to hold for an
ACT-style exploit:

1. The vault authorization set would need to accept additions or drain-capable calls from senders that do **not**
   already hold governance or operator rights.
2. The `0x0243f5a2` drain interface would need to be callable by arbitrary EOAs without prior inclusion in the
   authorization set.

The collected traces and state diffs contradict these conditions:

- Authorization updates and drain calls are observed only from governance, operators, and explicitly authorized helper
  contracts.
- Available txlists and traces show that successful drain calls originate from addresses in the authorization set, with
  corresponding storage updates.

As a result, the incident does **not** meet the ACT opportunity definition for a permissionless adversary. Instead, it
is a case of privileged misuse.

### Helper authorization mechanism

Authorization for helper contract `0xB5CB0555c4A3…` on vault `0xb5cb0555c0c5…` is controlled via an
`authorize(address)`-style function with selector `0x268a066f`. The authorization-management transaction
`0x8e7e1960fcf7fdff7b382ee736c1e45eacc79182b006bbe9fb9153b5884b7c77` shows the revocation of this authorization:

```json
// State diff for vault 0xb5cb0555c0c51e603ead62c6437da65372e4e1b0
// tx 0x8e7e1960fcf7fdff7b382ee736c1e45eacc79182b006bbe9fb9153b5884b7c77
{
  "chainid": 56,
  "txhash": "0x8e7e1960fcf7fdff7b382ee736c1e45eacc79182b006bbe9fb9153b5884b7c77",
  "contract_address": "0xb5cb0555c0c51e603ead62c6437da65372e4e1b0",
  "storage_diff": {
    "0xf67c83c47782efdccd49b3d84f0499c130ebbd12804c0e45b3431c05b19ed74f": {
      "from": "0x0000000000000000000000000000000000000000000000000000000000000001",
      "to": "0x0"
    }
  }
}
```

The associated trace for the same transaction confirms the use of selector `0x268a066f` on the vault and shows the
authorization flag toggling from `1` to `0` at the authorization slot:

```json
// Trace excerpt for tx 0x8e7e19… (authorize/address management)
"Traces": [
  "[5459] 0xB5CB0555C0C51e603eaD62C6437dA65372e4E1B0::268a066f(000000000000000000000000b5cb0555c4a333543dbe0b219923c7b3e9d84a87)",
  "  storage changes:",
  "    @ 0xf67c83c4…: 1 → 0",
  "  ← [Stop]"
]
```

Earlier governance/operator actions grant authorization to the helper by setting this storage slot to `1`, allowing the
helper to call the drain interface. The draining transactions occur while the helper is in the authorization set.

### Drain mechanism and balance movements

The three draining transactions are:

- `0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44` (vToken drain on vault `0xb5cb0555c0c5…`)
- `0xf9025e317ce71bc8c055a511fccf0eb4eafd0b8c613da4d5a8e05e139966d6ff` (underlying token drain on vault
  `0xb5cb0555c0c5…`)
- `0x8c026c3939f7e2d0376d13e30859fa918a5a567348ca1329836df88bef30c73e` (underlying token drain on vault
  `0xb5cb0555a1d…`)

#### Example 1: vToken drain (tx 0x7708aa…)

A representative excerpt from the trace for `0x7708aa…` shows the helper deploying and calling into the Venus stack to
transfer vTokens from the vault to the adversary:

```bash
# Seed transaction trace (cast run -vvvvv) for 0x7708aa…
Traces:
  [1619980] → new <unknown>@0xC269cd69CcCB1BBEDB44f93c612905219F424c11(...)
  ...
  │   ├─ PolicyFacet::transfer(0xfd5840cd36d94d7229439859c0112a4185bc0255, 0xB5CB0555C0C51e603eaD62C6437dA65372e4E1B0, 0xd5c6f3B71bCcEb2eF8332bd8225f5F39E56A122c, 1630935807678191) [delegatecall]
  │   │   ├─ TransparentUpgradeableProxy::fallback(0xB5CB0555C0C51e603eaD62C6437dA65372e4E1B0, 0xfd5840cd36d94d7229439859c0112a4185bc0255)
  │   │   │   └─ VBep20Delegate::transfer(...)
  │   │   └─ ← [Return]
  ...
```

The corresponding `balance_diff.json` confirms that the vault’s vToken holdings drop to zero and identical amounts
appear at the adversary address:

```json
// balance_diff.json snippet for tx 0x7708aa…
{
  "native_balance_deltas": [
    {
      "address": "0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c",
      "delta_wei": "-175994600000000"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0xfd5840cd36d94d7229439859c0112a4185bc0255",
      "holder": "0xb5cb0555c0c51e603ead62c6437da65372e4e1b0",
      "before": "1630935807678191",
      "after": "0",
      "delta": "-1630935807678191"
    },
    {
      "token": "0xfd5840cd36d94d7229439859c0112a4185bc0255",
      "holder": "0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c",
      "before": "0",
      "after": "1630935807678191",
      "delta": "1630935807678191"
    },
    {
      "token": "0xeca88125a5adbe82614ffc12d0db554e2e2867c8",
      "holder": "0xb5cb0555c0c51e603ead62c6437da65372e4e1b0",
      "before": "800365645822131",
      "after": "0",
      "delta": "-800365645822131"
    },
    {
      "token": "0xeca88125a5adbe82614ffc12d0db554e2e2867c8",
      "holder": "0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c",
      "before": "0",
      "after": "800365645822131",
      "delta": "800365645822131"
    },
    ...
  ]
}
```

#### Example 2: Underlying token drain (tx 0x8c026c…)

For `0x8c026c…`, the `balance_diff.json` for vault `0xb5cb0555a1d…` shows its underlying token balances dropping to
zero while identical amounts accrue to `0xd5c6…`:

```json
// balance_diff.json snippet for tx 0x8c026c…
{
  "native_balance_deltas": [
    {
      "address": "0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c",
      "delta_wei": "-219091000000000"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0x2170ed0880ac9a755fd29b2688956bd959f933f8",
      "holder": "0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c",
      "before": "1507949072622558765",
      "after": "0",
      "delta": "-1507949072622558765"
    },
    {
      "token": "0x2170ed0880ac9a755fd29b2688956bd959f933f8",
      "holder": "0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c",
      "before": "0",
      "after": "1507949072622558765",
      "delta": "1507949072622558765"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c",
      "before": "5713628230222816841140",
      "after": "0",
      "delta": "-5713628230222816841140"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c",
      "before": "3140940704698193",
      "after": "5713631371163521539333",
      "delta": "5713628230222816841140"
    },
    ...
  ]
}
```

Across the three transactions, every affected token shows a negative delta on one of the two vaults and a matching
positive delta on the adversary, while the adversary’s BNB balance decreases only by the summed gas costs.

### Success predicate and profit computation

The success predicate is **profit**, defined purely from observed on-chain balances:

- **Adversary address**: `0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c`.
- **Fees paid**: cumulative BNB gas outflow of `544106600000000` wei across the three draining transactions, equal to
  the sum of `native_balance_deltas` for the adversary in the corresponding `balance_diff.json` files.
- **Value before**: for each affected token, the pre-incident balances held by vault addresses
  `0xb5cb0555c0c51e603ead62c6437da65372e4e1b0` and `0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c`, as given by the
  `before` fields in their ERC20 balance entries.
- **Value after**: post-incident balances for the same tokens, with the two vaults’ balances set to zero and the
  adversary address holding the corresponding `after` values.
- **Delta**: for each asset, the adversary’s positive delta equals the magnitude of the vault’s negative delta; the
  only native token movement from the adversary is the gas burn.

Concrete gains per transaction, taken from the `valuation_notes`, include:

- **Tx 0x7708aa…**: gains vTokens with amounts such as `1630935807678191` units of
  `0xfd5840cd36d94d7229439859c0112a4185bc0255`, `800365645822131` units of
  `0xeca88125a5adbe82614ffc12d0db554e2e2867c8`, `329293631993` units of
  `0xf508fcd89b8bd15579dc79a6827cb4686a3592c8`, and `14631336015` units of
  `0x882c173bc7ff3b7786ca16dfed3dfffb9ee7847b`.
- **Tx 0x8c026c…**: gains underlying tokens including `1507949072622558765` units of
  `0x2170ed0880ac9a755fd29b2688956bd959f933f8` (ETH), `5713628230222816841140` units of
  `0x55d398326f99059ff775485246999027b3197955` (USDT), `4253611958524052045623` units of
  `0x40af3827f39d0eacbf4a168f8d4ee67c121d11c9` (BscTrueUSD), `32017839076702731` units of
  `0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c` (BTCB), `2028106822073140120333` units of
  `0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d` (USDC), and `1523817415577564055735` units of
  `0xc5f0f7b66764f6ec8c8dff7ba683102295e16409` (StablecoinV2).
- **Tx 0xf9025e…**: gains `4938898747065` units of `0xa07c5b74c9b40447a954e1466938b865b6bbea36` (VBNB),
  `363924239113942121542` units of `0xe6df05ce8c8301223373cf5b969afcb1498c5528` (KogeToken), `4439768743215238075224`
  units of `0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82` (CAKE), and `3688064818698799499583` units of
  `0xe9e7cea3dedca5984780bafc599bd69add087d56` (BUSD).

The incident is therefore fully profitable for the adversary: large positive ERC20/vToken deltas versus small, fixed
BNB gas costs.

---

## Adversary Flow Analysis

### Adversary strategy summary

The adversary deploys an authorized helper contract and then sends three straightforward transactions from EOA
`0xd5c6…` invoking the helper’s `printMoney`-like entrypoint. The helper in turn calls the vault drain function
`0x0243f5a2` through the Venus Unitroller/PolicyFacet and `VBep20Delegate::transfer` stack, moving complete token
portfolios from the two vaults into `0xd5c6…` while paying only standard BNB gas fees.

### Adversary-related accounts and roles

- **Adversary EOA**: `0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c` (BSC)
  - Sender of the three draining transactions.
  - Immediate recipient of all drained token balances according to the `balance_diff.json` files.
- **Adversary helper contract**: `0xB5CB0555c4A333543DbE0b219923C7B3e9D84a87` (BSC)
  - Deployed by `0xd5c6…` in tx `0x7708aa…`.
  - Direct caller of the vault drain function `0x0243f5a2` in all three draining transactions.
- **Victim vaults**:
  - `0xb5cb0555c0c51e603ead62c6437da65372e4e1b0` – Venus BSC vault drained of vToken and underlying holdings.
  - `0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c` – Venus BSC vault drained of underlying holdings.
- **Governance/administration**:
  - `0x3801410dcea87efa2141ecc866ecad5e020028dc` – Venus governance/administrative contract managing vault
    authorization history.

### Lifecycle stages

1. **Helper deployment and initial vToken drain on vault `0xb5cb0555c0c5…`**
   - **Tx**: `0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44` (BSC, block `52052493`).
   - **Action**: EOA `0xd5c6…` deploys helper contract `0xB5CB0555c4A3…` and, via constructor and `printMoney`, calls
     `0x0243f5a2` on vault `0xb5cb0555c0c5…` to transfer its vToken positions in several assets to `0xd5c6…`.
   - **Effect**: vToken balances on the vault drop to zero, and matching increases are recorded on `0xd5c6…` in
     `balance_diff.json`.

2. **Underlying token drain on vault `0xb5cb0555c0c5…`**
   - **Tx**: `0xf9025e317ce71bc8c055a511fccf0eb4eafd0b8c613da4d5a8e05e139966d6ff` (BSC, block `52052539`).
   - **Action**: Helper `0xB5CB0555c4A3…` calls `0x0243f5a2` on the same vault to transfer underlying holdings in
     VBNB, KogeToken, CAKE, and BUSD to `0xd5c6…`.
   - **Effect**: Vault `0xb5cb0555c0c5…` ends with zero balances in these underlying tokens, and `0xd5c6…` gains equal
     amounts, as shown in `balance_diff.json`.

3. **Underlying token drain on vault `0xb5cb0555a1d…`**
   - **Tx**: `0x8c026c3939f7e2d0376d13e30859fa918a5a567348ca1329836df88bef30c73e` (BSC, block `52052680`).
   - **Action**: Helper `0xB5CB0555c4A3…` calls `0x0243f5a2` on vault `0xb5cb0555a1d…` to transfer its portfolio in
     ETH, USDT, BTCB, USDC, TUSD, and StablecoinV2 to `0xd5c6…`.
   - **Effect**: Vault `0xb5cb0555a1d…` ends with zero balances for these assets; `balance_diff.json` shows matching
     positive deltas on `0xd5c6…`.

Throughout these stages, the helper remains in the vault authorization set, and there is no evidence of drain calls
from arbitrary, unprivileged EOAs in the provided artifacts.

---

## Impact & Losses

The incident drains the **entire portfolios** of the two B5CB vault contracts across three transactions. All listed
token balances are transferred to adversary address `0xd5c6…` while only `544106600000000` wei of BNB is spent on gas.
At the end of the sequence, the two vault accounts hold **zero** balances for the affected assets.

Token-level losses (amounts represent units of each token transferred from the vaults to `0xd5c6…`):

- `token_0xfd5840cd36d9…` (VBep20Delegate underlying): `1630935807678191`
- `token_0xeca88125a5ad…` (VBep20Delegate underlying): `800365645822131`
- `token_0xf508fcd89b8b…` (VBep20Delegate underlying): `329293631993`
- `token_0x882c173bc7ff…` (VBep20Delegate underlying): `14631336015`
- `ETH` (`0x2170ed0880ac…`): `1507949072622558765`
- `USDT` (`0x55d398326f99…`): `5713628230222816841140`
- `BscTrueUSD` (`0x40af3827f39d…`): `4253611958524052045623`
- `BTCB` (`0x7130d2a12b9b…`): `32017839076702731`
- `USDC` (`0x8ac76a51cc95…`): `2028106822073140120333`
- `StablecoinV2` (`0xc5f0f7b66764…`): `1523817415577564055735`
- `VBNB` (`0xa07c5b74c9b4…`): `4938898747065`
- `KogeToken` (`0xe6df05ce8c83…`): `363924239113942121542`
- `CAKE` (`0x0e09fabb73bd…`): `4439768743215238075224`
- `BUSD` (`0xe9e7cea3dedc…`): `3688064818698799499583`

These figures align with the ERC20 balance deltas for the two vault addresses and the adversary EOA in the three
`balance_diff.json` files.

---

## References

1. **Draining transaction 0x7708aa… trace and balance diffs**  
   `artifacts/root_cause/seed/56/0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44`
2. **Draining transaction 0xf9025e… trace and balance diffs**  
   `artifacts/root_cause/seed/56/0xf9025e317ce71bc8c055a511fccf0eb4eafd0b8c613da4d5a8e05e139966d6ff`
3. **Draining transaction 0x8c026c… trace and balance diffs**  
   `artifacts/root_cause/seed/56/0x8c026c3939f7e2d0376d13e30859fa918a5a567348ca1329836df88bef30c73e`
4. **Vault authorization and governance transaction history (0x3801410d…)**  
   `artifacts/root_cause/data_collector/iter_3/address/56/0x3801410dcea87efa2141ecc866ecad5e020028dc`
5. **Vault authorize(address) state diffs for helper 0xB5CB0555c4A3…**  
   `artifacts/root_cause/data_collector/iter_3/tx/56/0x8e7e1960fcf7fdff7b382ee736c1e45eacc79182b006bbe9fb9153b5884b7c77`

