## BNB Chain Router Helper Drain via Unguarded Helper 0x4fde…

### Incident Overview & TL;DR

On BNB Chain (chainid 56), router `0x5c952063c7fc8610ffdb798152d69f0b9550762b` (a proxy-style router/launchpad with implementation `0x328aee1995ed2f3c86d6bac34dda06dd3a74e8ce`) is combined with three helper contracts:

- `0xbf26e147918a07cb8d8cf38d260edf346977686c`
- `0x06799f7b09a455c1cf6a8e7615ece04b31a9d051`
- `0x4fdebcA823b7886c3A69fA5fC014104F646D9591`

These contracts implement a strategy that:

- Configures a Pancake V3 pool for token `0x4abfd9a204344bd81a276c075ef89412c9fd2f64` (abbreviated as `0x4abf...`).
- Adds liquidity to that pool via the router.
- Executes pool‑controller trades against the pool.
- Finally drains router‑held ERC20 balances into helper `0x4fde...`.

Across the four‑transaction seed sequence, router `0x5c95...` loses about **23.99732673211327 BNB** and large balances of multiple ERC20 tokens, while helper `0x4fde...` accumulates these ERC20 balances. The adversary‑related EOAs

- `0xf91848a076efaa6b8ecc9d378ab6d32bd506dc79`,
- `0x935d6cf073eab37ca2b5878af21329d5dbf4f4a5`,
- `0x010fc97cb0a4d101dce20dab37361514bd59a53a`

together realize a net profit of **0.8495587125116998 BNB** after fees over the same sequence, while EOA `0x74d86638f359bdff6ec55d78a97f294747f8f5b3` (the LP) incurs a small BNB loss.

**Root cause (brief):** helper contract `0x4fde...` exposes an externally callable function with selector `0x0483ee44` (`Unresolved_0483ee44`) that, given the router configuration at `0x5c95...`, instructs the router to transfer large ERC20 balances from router custody to `0x4fde...` **without any msg.sender or role‑based checks** on the caller. Once token metadata and pools are configured, any unprivileged EOA can invoke this helper entrypoint under the same pre‑state to drain router‑held tokens, creating an ACT opportunity that the observed adversary cluster executes.

---

### Key Background

#### Router and Implementation: 0x5c95… / 0x328a…

Router `0x5c952063c7fc8610ffdb798152d69f0b9550762b` on BNB Chain is a proxy‑style router or launchpad whose logic resides in implementation `0x328aee1995ed2f3c86d6bac34dda06dd3a74e8ce`. The decompiled implementation shows:

- User‑facing trading and liquidity functions such as `buyToken`, `buyTokenAMAP`, `sellToken`, `addLiquidity`, and `createToken`.
- Role‑management and upgrade functions such as `grantDeployer`, `grantOperator`, `grantRole`, `hasRole`, `owner`, `transferOwnership`, and `upgradeTo`.
- State related to token templates and router‑managed token configuration.

**Router implementation layout (decompiled snippet, 0x328a…):**

```solidity
// Decompiled router implementation for 0x328a...
contract DecompiledContract {
    uint256 public constant STATUS_ADDING_LIQUIDITY = 2;
    uint256 public constant STATUS_TRADING = 0;
    uint256 public constant STATUS_HALT = 1;
    uint256 public constant DEFAULT_ADMIN_ROLE = 0;
    uint256 public constant ROLE_DEPLOYER = 1540146...;
    uint256 public constant ROLE_OPERATOR = 7700424...;
    ...
    address public owner;
    address public _feeRecipient;
    uint256 public _tradingFeeRate;
    uint256 public _tokenCount;
    ...
}
```

*Caption: Decompiled router implementation for `0x328a...` showing router status constants, role identifiers, and ownership/custody‑related storage fields, consistent with a custodial router / launchpad that temporarily holds ERC20 and BNB balances on behalf of users.*

Pre‑incident transaction lists for `0x5c95...` in blocks `46,554,000–46,555,600` show many distinct EOAs using these functions in a way consistent with a router/launchpad pattern where users send BNB and/or ERC20 tokens and the router temporarily takes custody.

#### Helper 0xbf26…: Pool Configuration

Helper contract `0xbf26e147918a07cb8d8cf38d260edf346977686c` reads token configuration from router `0x5c95...` via storage such as `_tokenInfoEx1s` and calls the Pancake `NonfungiblePositionManager::createAndInitializePoolIfNecessary` function to deploy Pancake V3 pools.

In the seed transaction `0x4235b006b94a79219181623a173a8a6aadacabd01d6619146ffd6fbcbb206dff` (abbreviated `0x4235...`), this helper:

- Queries `_tokenInfoEx1s` from router `0x5c95...`.
- Deploys a new Pancake V3 pool `0xa610cC0d657bbFe78c9D1eA638147984B2F3C05c` (abbreviated `0xa610...`) for token `0x4abf...` against WBNB with fee tier `10000`.
- Initializes the pool with the configured initial price.

**Pool creation via helper 0xbf26… (seed trace snippet for tx 0x4235…):**

```bash
# Seed trace for 0x4235... (BNB Chain)
0xBf26E147918A07CB8D8CF38D260EDF346977686C::d416ce7f(...)
  ├─ 0x5c952063c7fc8610FFDB798152D69F0B9550762b::_tokenInfoEx1s(0x4AbfD9a2...)
  ├─ 0x46A15B0b27311cedF172AB29E4f4766fbE7F4364::createAndInitializePoolIfNecessary(
  │     0x4AbfD9a2..., 0xbb4CdB9C..., 10000, 1e40
  │   )
  │   ├─ PancakeV3Factory::createPool(...) → new PancakeV3Pool@0xa610cC0d657bbFe78c9D1eA638147984B2F3C05c
  │   └─ PancakeV3Pool::initialize(1e40)
```

*Caption: Seed transaction `0x4235...` shows helper `0xbf26...` reading router token configuration and creating the Pancake V3 pool `0xa610...` for `0x4abf...` vs WBNB under router control.*

#### Helper 0x0679…: Pool Controller

Helper contract `0x06799f7b09a455c1cf6a8e7615ece04b31a9d051` acts as a pool‑controller for Uniswap/Pancake‑style pools. Its decompiled code references checks such as `"not pool controller"`, `"not pool"`, and `"not owner"`, and interacts with token0(), token1(), and ERC20 transfer calls.

In seed transaction `0x2902f93a0e0e32893b6d5c907ee7bb5dabc459093efa6dbc6e6ba49f85c27f61` (`0x2902...`), this helper:

- Receives `0x4abf...` tokens.
- Calls `PancakeV3Pool::swap` on pool `0xa610...`.
- Drives a swap that converts approximately `1.603243002223e21` units of `0x4abf...` into WBNB and accrues BNB‑denominated value to adversary EOAs.

**Pool‑controller trade (seed trace snippet for tx 0x2902…):**

```bash
# Seed trace for 0x2902... (BNB Chain)
0x06799F7b09A455c1cF6a8E7615Ece04B31A9D051::aafea2da(...)
  ├─ 0x0679...::02c60726(...)
  │   ├─ Token::transfer(0x0679..., 1603243002223000000000 [1.603e21])
  │   │   └─ emit Transfer(from: 0x4FdEBcA823b7..., to: 0x0679..., value: 1.603e21)
  ├─ 0xa610cC0d657bbFe78c9D1eA638147984B2F3C05c::swap(
  │     0x0679..., true, 1603243002223000000000, 4295128740, 0x
  │   )
  │   ├─ WBNB::transfer(0x0679..., 23425920040311988396 [2.342e19])
  │   │   └─ emit Transfer(from: 0xa610..., to: 0x0679..., value: 2.342e19)
  │   └─ 0x0679...::pancakeV3SwapCallback(...)
```

*Caption: Seed transaction `0x2902...` shows pool‑controller `0x0679...` swapping `0x4abf...` for WBNB on pool `0xa610...`, with value flowing into the adversary‑controlled pool controller and then to the adversary cluster.*

#### Helper 0x4fde…: Unguarded Router‑Drain Entry Point

Helper contract `0x4fdebcA823b7886c3A69fA5fC014104F646D9591` exposes several functions. In the decompile, some functions enforce msg.sender‑based access control with explicit revert strings:

- `Unresolved_3d1ce835` and `Unresolved_87223677` heavily gate behavior with `"not owner"` checks.
- `Unresolved_7ea0ac04` includes `"not swapper"` checks tied to `msg.sender`.
- `Unresolved_70bd8d40` also enforces `"not owner"` checks.

In contrast, function selector `0x0483ee44` (`Unresolved_0483ee44`) is declared `public pure` and contains **no msg.sender or role check**, only arithmetic preconditions.

**Helper 0x4fde… access‑control contrast (decompile snippet):**

```solidity
// Functions with msg.sender-based checks
/// @custom:selector    0x3d1ce835
function Unresolved_3d1ce835(uint256 arg0, uint256 arg1, uint256 arg2) public view {
    if (!0 < store_a) {
        require(!(0 < store_a), "not owner");
        ...
    }
    ...
    var_f = 0x6e6f74206f776e65720000000000000000000000000000000000000000000000; // "not owner"
}

/// @custom:selector    0x7ea0ac04
function Unresolved_7ea0ac04(uint256 arg0, uint256 arg1, uint256 arg2) public view {
    require((arg2 == ((arg2 * store_d) / store_d)) | !store_d, "not swapper");
    ...
    require(address(store_e + (arg2 * store_d)) == (address(msg.sender)), "not swapper");
}

/// @custom:selector    0x0483ee44
function Unresolved_0483ee44(uint256 arg0, uint256 arg1) public pure {
    require(!arg0 > 0xffffffffffffffff);
    require(!(arg0) > 0xffffffffffffffff);
    ...
    require(!arg1 > 0xffffffffffffffff);
}
```

*Caption: Decompiled helper `0x4fde...` shows multiple functions with explicit `"not owner"` / `"not swapper"` checks tied to `msg.sender`, but selector `0x0483ee44` lacks any msg.sender or role checks, making it externally callable by arbitrary EOAs.*

When invoked via selector `0x0483ee44`, `0x4fde...` orchestrates a sequence of calls that:

- Invoke router `0x5c95...` functions such as `buyTokenAMAP`.
- Cause multiple ERC20 `Token::transfer` calls where the **from** address is `0x5c95...` and the **to** address is `0x4fde...`.
- Result in large ERC20 inflows to `0x4fde...` from router custody.

#### Adversary Cluster

The adversary‑related accounts form a coherent cluster on BNB Chain:

- EOA `0xf91848a076efaa6b8ecc9d378ab6d32bd506dc79`: sends tx `0xdb5d...` to helper `0x4fde...`, is the only observed caller of `0x4fde...` via selector `0x0483ee44` in the examined pre‑incident tx lists, and participates in positive BNB P&L.
- EOA `0x935d6cf073eab37ca2b5878af21329d5dbf4f4a5`: sends tx `0x2902...` to pool‑controller `0x0679...`, receives BNB‑denominated value from swaps, and has a strictly positive net BNB delta.
- EOA `0x010fc97cb0a4d101dce20dab37361514bd59a53a`: sends tx `0x4235...` to helper `0xbf26...`, configures pool `0xa610...` using router token metadata, and has a strictly positive net BNB delta; pre‑incident tx lists show repeated exclusive use of `0xbf26...` by this EOA.
- Helper contract `0x4fde...`: receives large ERC20 balances from router `0x5c95...` in tx `0xdb5d...`, controlled by EOA `0xf918...` via calls to selector `0x0483ee44`, and holds the drained ERC20 tokens according to ERC20 balance diffs.
- Helper contract `0xbf26...`: reads token configuration from router `0x5c95...` and creates Pancake V3 pool `0xa610...` in tx `0x4235...` under the control of EOA `0x010f...`.
- Pool‑controller contract `0x0679...`: orchestrates swaps in tx `0x2902...`, receiving `0x4abf...` tokens and sending out WBNB, with net BNB value accruing to adversary EOAs.

Victim‑related entities are:

- Router `0x5c95...` itself, which loses BNB and multiple ERC20 balances.
- EOA `0x74d86638f359bdff6ec55d78a97f294747f8f5b3` (`0x74d8...`), an LP interacting via the router and incurring a small BNB loss; identity verification status is not established on‑chain.

---

### Vulnerability & Root Cause Analysis

#### Vulnerability Brief

Router `0x5c95...` delegates custody of user ERC20 balances to an implementation that can be controlled by helper contracts. Helper `0x4fde...` exposes an externally callable function with selector `0x0483ee44` (`Unresolved_0483ee44`) that uses this router to transfer arbitrary ERC20 balances from router custody to `0x4fde...` **without enforcing privileged roles or msg.sender checks**. Once the relevant token metadata and pools are configured, any unprivileged EOA can call this helper selector and drain router‑held tokens.

#### Root Cause Detail

The exploit relies on a specific integration of router configuration, helper contracts, and missing access control:

1. **Router configuration and token custody**
   - The implementation behind router `0x5c95...` (contract `0x328a...`) maintains token configuration in storage, including structures like `_tokenInfoEx1s`.
   - The router holds ERC20 balances and BNB on behalf of users, consistent with a launchpad/router model, and exposes helper integration points.

2. **Pool creation using router‑owned balances**
   - Helper `0xbf26...` reads token metadata from router storage (`_tokenInfoEx1s`) and uses `NonfungiblePositionManager::createAndInitializePoolIfNecessary` to deploy Pancake V3 pool `0xa610...` for token `0x4abf...` and WBNB.
   - This operation uses router‑owned token balances as the basis for initial liquidity and configuration.

3. **Pool‑controller trades under adversary control**
   - Helper `0x0679...` acts as a pool controller; under EOA `0x935d...`’s control in tx `0x2902...`, it:
     - Receives `0x4abf...` tokens (from the helper/router setup).
     - Swaps roughly `1.603243002223e21` units of `0x4abf...` on pool `0xa610...` for approximately `2.3425920040311988396e19` wei of WBNB.
     - Distributes WBNB‑denominated value to the adversary cluster.

4. **Helper 0x4fde… drives router‑funded ERC20 transfers**
   - Helper `0x4fde...` is wired so that its function `Unresolved_0483ee44` orchestrates a sequence of calls into router `0x5c95...` and then into ERC20 tokens held by the router.
   - The decompiled code for `0x4fde...` shows `"not owner"` and `"not swapper"` checks on several selectors but **no msg.sender or role check on selector `0x0483ee44`**.
   - In transaction `0xdb5d43317ab8e5d67cdd5006b30a6f2ced513237ac189eb1e57f0f06f630d582` (`0xdb5d...`), an unprivileged EOA `0xf918...` calls `0x4fde...` via selector `0x0483ee44`. The prestate‑based trace shows:
     - `0x4fde...` calling router `0x5c95...` (e.g., `buyTokenAMAP`).
     - Multiple ERC20 `Token::transfer` calls where the **from** address is `0x5c95...` and the **to** address is `0x4fde...` for more than ten ERC20 tokens, including token‑like contracts:
       - `0x4abf...`, `0xe2039b...`, `0xffb980...`, `0x525e25...`, `0x470e25...`, `0xb8fdaf...`, `0xb4dde7...`, and others.

**Helper‑driven router drain (seed trace snippet for tx 0xdb5d…):**

```bash
# Seed trace for 0xdb5d... (BNB Chain)
0x4FdEBcA823b7886c3A69fA5fC014104F646D9591::0483ee44{value: 0.0027 BNB}(...)
  ├─ 0x4FdE...::e793f35b(..., 0x5c952063c7fc8610ffdb798152d69f0b9550762b, ...)
  │   ├─ 0x5c952063c7fc8610FFDB798152D69F0B9550762b::buyTokenAMAP{value: 0.0001 BNB}(...)
  │   │   ...
  │   │   ├─ 0x42EAe438217c93efCEE83e0B9006E65648b33d06::transfer(0x4FdE..., 8006342102370000000000 [8.006e21])
  │   │   │   └─ emit Transfer(
  │   │   │        from: 0x5c952063c7fc8610FFDB798152D69F0B9550762b,
  │   │   │        to:   0x4FdEBcA823b7886c3A69fA5fC014104F646D9591,
  │   │   │        value: 8006342102370000000000
  │   │   ...
  │   │   ├─ Token::transfer(0x4FdE..., 1.06e22)   # repeated across many token contracts
```

*Caption: Seed transaction `0xdb5d...` shows EOA `0xf918...` calling helper `0x4fde...::0483ee44`, which in turn calls router `0x5c95...` and multiple ERC20 tokens, producing a sequence of `Token::transfer` events from router `0x5c95...` into helper `0x4fde...` across many ERC20 contracts.*

5. **Balance diff evidence of large ERC20 drains**
   - Prestate‑based balance diffs and consolidated P&L (`cluster_balance_diff_pnl.json`) show:
     - Large negative ERC20 deltas on router `0x5c95...` for multiple token contracts.
     - Matching positive ERC20 deltas on helper `0x4fde...`.

**Sample ERC20 balance diff (cluster P&L snippet):**

```json
{
  "sample_tokens": [
    "0x0b7d67bafa821cd81bbd0a79d81c87d8b697ca00",
    "0x258620b44c0f3ca2313d0d6b547515f595a3f535",
    "0x2c38bb609386286aef73d3c2ec6a5d8c3b7c9229"
  ],
  "first_token": {
    "0x5c952063c7fc8610ffdb798152d69f0b9550762b": {
      "total_delta": -11841879616093000000000,
      "per_tx": {
        "0xdb5d43317ab8e5d67cdd5006b30a6f2ced513237ac189eb1e57f0f06f630d582": -11841879616093000000000
      }
    },
    "0x4fdebca823b7886c3a69fa5fc014104f646d9591": {
      "total_delta": 11841879616093000000000,
      "per_tx": {
        "0xdb5d43317ab8e5d67cdd5006b30a6f2ced513237ac189eb1e57f0f06f630d582": 11841879616093000000000
      }
    }
  }
}
```

*Caption: Consolidated ERC20 P&L for a sample token shows router `0x5c95...` losing `1.184e22` units and helper `0x4fde...` gaining the same amount in tx `0xdb5d...`, illustrating the helper‑driven router drain.*

Putting these points together, the protocol‑level bug is:

- **Design flaw:** a helper contract (`0x4fde...`) is empowered to instruct a custodial router (`0x5c95...`) to transfer router‑held ERC20 balances to the helper.
- **Access‑control failure:** the crucial helper entrypoint (`0x0483ee44`) that triggers this behavior is missing msg.sender or role checks, in contrast with other functions in the same helper.
- **Integration risk:** the router’s design allows helper logic to bypass router‑level role checks and move custodial funds, violating separation‑of‑duties and least‑privilege.

#### Vulnerable Components

The vulnerable components are:

1. **Router proxy and implementation**
   - Proxy router `0x5c952063c7fc8610ffdb798152d69f0b9550762b`.
   - Implementation `0x328aee1995ed2f3c86d6bac34dda06dd3a74e8ce`.
   - These contracts hold user ERC20 and BNB balances and integrate with helper contracts for pool deployment, trading, and token creation.

2. **Helper 0x4fde… selector 0x0483ee44**
   - Function selector `0x0483ee44` (`Unresolved_0483ee44`) on `0x4fde...` is an unguarded helper entrypoint.
   - It can be called by arbitrary EOAs and, via router integration, moves router‑held ERC20 balances into `0x4fde...`.

3. **Helper 0xbf26…**
   - Contract `0xbf26...` reads router token metadata and creates Pancake V3 pools such as `0xa610...`, setting up the pool that the later exploit uses.

4. **Helper 0x0679…**
   - Contract `0x0679...` drives swaps on the Pancake V3 pool `0xa610...`, converting `0x4abf...` into WBNB and shuttling BNB‑denominated value to the adversary cluster.

#### Exploit Conditions

For the exploit to work, the following conditions hold (and are satisfied under the reconstructed pre‑state `σ_B` at block `46555590`):

1. Router `0x5c95...` holds nontrivial ERC20 balances for multiple token contracts, configured in `_tokenInfoEx1s` and accessible to helper contracts.
2. Helper contracts `0xbf26...`, `0x0679...`, and `0x4fde...` are deployed, wired to router `0x5c95...`, and externally callable.
3. Function selector `0x0483ee44` on helper `0x4fde...` is callable from arbitrary EOAs and executes without checking `msg.sender` or any on‑chain role assignments.
4. An adversary‑controlled EOA (or cluster of EOAs) holds enough BNB to pay gas for txs `0x4235...`, `0x2902...`, and `0xdb5d...`, and has access to contract ABIs or decompiled bytecode to construct the required calldata.
5. The pre‑state `σ_B` on BNB Chain retains the same router configuration and ERC20 balances as seen in the observed exploit sequence, so replaying the calldata under `σ_B` yields the same exploit outcome.

#### Security Principles Violated

The design violates several core security principles:

- **Missing access control on a helper that moves funds:** The helper entrypoint `0x0483ee44` can cause router `0x5c95...` to transfer ERC20 balances out of custody without any msg.sender or role checking.
- **Violation of separation‑of‑duties:** Configuration and pool‑management helpers are granted effective control over funds custody, rather than being strictly limited to configuration or routing logic.
- **Failure of least privilege on cross‑contract integrations:** A small helper contract (`0x4fde...`) is granted broad authority to move large ERC20 balances from router custody, enabling a single helper call from an unprivileged EOA to drain significant value.

---

### Adversary Flow Analysis

#### ACT Opportunity and Pre‑State σ_B

The ACT opportunity is defined relative to a publicly reconstructible pre‑state on BNB Chain:

- **Chain:** BNB Chain (chainid 56).
- **Reference block height `B`:** `46555590`.
- **Pre‑state `σ_B`:** The on‑chain state immediately before the four‑transaction seed sequence that:
  - Configures the Pancake V3 pool.
  - Adds liquidity.
  - Executes the pool‑controller trade.
  - Triggers the helper‑driven router drain.

This state is reconstructed from prestate‑based traces and balance diffs around blocks `46,554,000–46,555,600`, specifically before txs:

- `0x4235b006b94a79219181623a173a8a6aadacabd01d6619146ffd6fbcbb206dff` (`0x4235...`),
- `0xe0daa3bf68c1a714f255294bd829ae800a381624417ed4b474b415b9d2efeeb5` (`0xe0da...`),
- `0x2902f93a0e0e32893b6d5c907ee7bb5dabc459093efa6dbc6e6ba49f85c27f61` (`0x2902...`),
- `0xdb5d43317ab8e5d67cdd5006b30a6f2ced513237ac189eb1e57f0f06f630d582` (`0xdb5d...`).

**Evidence used for reconstructing σ_B:**

- `cast run -vvvvv` traces for each seed transaction.
- Prestate‑based balance diffs for each seed transaction.
- Consolidated P&L across the seed cluster.

**Pre‑state evidence (JSON snippet):**

```json
{
  "definition": "Publicly reconstructible pre-state on BNB Chain (chainid 56) immediately before the four-seed transaction sequence ... before txs 0x4235..., 0xe0da..., 0x2902..., and 0xdb5d....",
  "evidence": [
    "seed/56/0x4235.../trace.cast.log",
    "seed/56/0xe0da.../trace.cast.log",
    "seed/56/0x2902.../trace.cast.log",
    "seed/56/0xdb5d.../trace.cast.log",
    "data_collector/iter_2/tx/56/0x4235.../balance_diff_prestate_tracer.json",
    "data_collector/iter_2/tx/56/0xe0da.../balance_diff_prestate_tracer.json",
    "data_collector/iter_2/tx/56/0x2902.../balance_diff_prestate_tracer.json",
    "data_collector/iter_2/tx/56/0xdb5d.../balance_diff_prestate_tracer.json",
    "data_collector/iter_2/cluster_balance_diff_pnl.json"
  ]
}
```

*Caption: Pre‑state `σ_B` is reconstructed from seed traces and prestate‑based balance diffs, forming the reference state for evaluating the ACT opportunity.*

#### Transaction Sequence B (Four‑Tx Seed Sequence)

The ACT opportunity is realized via a four‑transaction sequence on BNB Chain, all reproducible under the pre‑state `σ_B` by unprivileged EOAs:

1. **Tx 1 – Pool configuration via helper 0xbf26…**
   - **Index:** 1
   - **Chainid:** 56
   - **Txhash:** `0x4235b006b94a79219181623a173a8a6aadacabd01d6619146ffd6fbcbb206dff`
   - **Type:** adversary‑crafted
   - **Caller:** EOA `0x010fc97cb0a4d101dce20dab37361514bd59a53a`.
   - **Behavior:**
     - Sends a standard BNB Chain transaction to helper `0xbf26...` using function selector `0xd416ce7f`.
     - Helper reads router token metadata and calls `NonfungiblePositionManager::createAndInitializePoolIfNecessary` to deploy the Pancake V3 pool `0xa610...` for token `0x4abf...` against WBNB.
   - **Inclusion feasibility:** The decompiled code and trace show no msg.sender‑based access control on helper `0xbf26...` and no dependency on privileged roles at `0x5c95...`. Any unprivileged EOA that reproduces the same calldata, gas, and fee parameters under `σ_B` will obtain the same pool creation and initialization.
   - **Effect (lifecycle stage):** Establishes the Pancake V3 pool `0xa610...` where later swaps will occur.

2. **Tx 2 – Liquidity provisioning by third‑party LP via router 0x5c95…**
   - **Index:** 2
   - **Chainid:** 56
   - **Txhash:** `0xe0daa3bf68c1a714f255294bd829ae800a381624417ed4b474b415b9d2efeeb5`
   - **Type:** victim‑observed
   - **Caller:** LP EOA `0x74d86638f359bdff6ec55d78a97f294747f8f5b3`.
   - **Behavior:**
     - Sends a normal user transaction through router `0x5c95...`, which delegatecalls into implementation `0x328a...` to mint liquidity on pool `0xa610...`.
     - The trace and P&L show standard routing and liquidity‑mint behavior with no special privileges and a small net BNB loss for `0x74d8...`.
     - Approximately `1` unit of `0x4abf...` and `2.352e19` wei of BNB (via WBNB) are deposited from `0x5c95...` into pool `0xa610...`.
   - **Inclusion feasibility:** Any searcher or adversary observing this transaction in the public mempool can include it unchanged in a bundle or a block and obtain the same state transition under `σ_B`.
   - **Effect (lifecycle stage):** Provides liquidity to the pool, using router balances and user funds, and sets up liquidity that the pool controller later trades against.

3. **Tx 3 – Pool‑controller trade via helper 0x0679…**
   - **Index:** 3
   - **Chainid:** 56
   - **Txhash:** `0x2902f93a0e0e32893b6d5c907ee7bb5dabc459093efa6dbc6e6ba49f85c27f61`
   - **Type:** adversary‑crafted
   - **Caller:** EOA `0x935d6cf073eab37ca2b5878af21329d5dbf4f4a5`.
   - **Behavior:**
     - Calls pool‑controller contract `0x0679...` (function `aafea2da` and related internal calls).
     - `0x0679...` receives `0x4abf...` tokens, interacts with pool `0xa610...`, and distributes WBNB‑denominated proceeds.
   - **Inclusion feasibility:** The pool‑controller contract `0x0679...` is deployed as a normal contract and accepts external calls without restricting `msg.sender` to any privileged address. The trace shows standard gas and fee settings and no role‑based dependencies. Any unprivileged EOA that submits the same calldata under `σ_B` gets the same swap and BNB flows.
   - **Effect (lifecycle stage):** Swaps about `1.603243002223e21` units of `0x4abf...` for approximately `2.3425920040311988396e19` wei of WBNB and redistributes BNB‑denominated value to cluster addresses including `0x935d...`.

4. **Tx 4 – Helper‑driven router drain via 0x4fde::0483ee44**
   - **Index:** 4
   - **Chainid:** 56
   - **Txhash:** `0xdb5d43317ab8e5d67cdd5006b30a6f2ced513237ac189eb1e57f0f06f630d582`
   - **Type:** adversary‑crafted
   - **Caller:** EOA `0xf91848a076efaa6b8ecc9d378ab6d32bd506dc79`.
   - **Behavior:**
     - Calls helper contract `0x4fde...` using function selector `0x0483ee44`.
     - The decompiled code shows msg.sender‑based checks on other selectors but **no msg.sender or role check on `Unresolved_0483ee44`**.
     - The trace for `0xdb5d...` shows an unprivileged EOA successfully driving router `0x5c95...` to transfer large ERC20 balances from `0x5c95...` to `0x4fde...`.
   - **Inclusion feasibility:** There is no dependency on privileged roles at `0x5c95...` or `0x4fde...` for this call. Any unprivileged EOA that sends the same calldata to `0x4fde...` under pre‑state `σ_B` causes the same ERC20 transfers from router custody to `0x4fde...`.
   - **Effect (lifecycle stage):** Triggers helper `0x4fde...` to call into router `0x5c95...` and transfer large ERC20 balances — including token‑like contracts `0x4abf...`, `0xe2039b...`, `0xffb980...`, `0x525e25...`, `0x470e25...`, `0xb8fdaf...`, `0xb4dde7...`, and others — from `0x5c95...` to `0x4fde...`, as reflected by matching negative ERC20 deltas on `0x5c95...` and positive deltas on `0x4fde...` in the consolidated P&L.

#### Adversary Lifecycle Stages

The exploit lifecycle can be summarized in three stages:

1. **Stage 1 – Pool configuration via helper 0xbf26…**
   - **Stage name:** Pool configuration via helper 0xbf26...
   - **Txs:** `{ chainid: 56, tx: 0x4235..., mechanism: other }`.
   - **Effect:** Helper `0xbf26...` uses router token metadata at `0x5c95...` to deploy Pancake V3 pool `0xa610...` for token `0x4abf...` against WBNB with fee tier `10000`, establishing the venue for later swaps.
   - **Evidence:** Seed trace for `0x4235...` and decompile of helper `0xbf26...`.

2. **Stage 2 – Liquidity provisioning by third‑party LP via router 0x5c95…**
   - **Stage name:** Liquidity provisioning by third‑party LP via router 0x5c95...
   - **Txs:** `{ chainid: 56, tx: 0xe0da..., mechanism: mint }`.
   - **Effect:** EOA `0x74d8...` provides liquidity through router `0x5c95...`, causing router and `NonfungiblePositionManager 0x46A15...` to mint a position in pool `0xa610...`. This transfers approximately `1` unit of `0x4abf...` and `2.352e19` wei of BNB (via WBNB) from `0x5c95...` into the pool, while `0x74d8...` pays gas and ends with a small net BNB loss.
   - **Evidence:** Seed trace for `0xe0da...` and native deltas in `cluster_balance_diff_pnl.json` for `0x74d8...` and `0x5c95...`.

3. **Stage 3 – Pool‑controller trade and helper‑driven router drain**
   - **Stage name:** Pool‑controller trade and helper-driven router drain
   - **Txs:** `{ chainid: 56, tx: 0x2902..., mechanism: other }` and `{ chainid: 56, tx: 0xdb5d..., mechanism: other }`.
   - **Effect:**
     - In `0x2902...`, pool‑controller `0x0679...` swaps ~`1.603243002223e21` units of `0x4abf...` on pool `0xa610...` for approximately `2.3425920040311988396e19` wei of WBNB, distributing BNB‑denominated value to adversary EOAs including `0x935d...`.
     - In `0xdb5d...`, helper `0x4fde...`, called by EOA `0xf918...` via selector `0x0483ee44`, calls router `0x5c95...` and then multiple ERC20 contracts, producing a sequence of `Token::transfer` calls where the **from** address is `0x5c95...` and the **to** address is `0x4fde...` for more than ten ERC20 tokens. Consolidated P&L shows large negative ERC20 deltas on `0x5c95...`, matching positive ERC20 deltas on `0x4fde...`, and a strictly positive net BNB delta for the adversary cluster.
   - **Evidence:** Seed traces for `0x2902...` and `0xdb5d...`, prestate balance diffs for `0xdb5d...`, and `cluster_balance_diff_pnl.json`.

#### Adversary Profit Predicate

The exploit meets a clear profit predicate:

- **Type:** Profit in BNB.
- **Reference asset:** BNB.
- **Adversary address set:** `{0xf91848a076efaa6b8ecc9d378ab6d32bd506dc79, 0x935d6cf073eab37ca2b5878af21329d5dbf4f4a5, 0x010fc97cb0a4d101dce20dab37361514bd59a53a}`.
- **Value delta (reference asset):** `>= 0.8495587125116998 BNB`.
- **Fees, initial, and final values:** Calculated directly from prestate‑based balance diffs; fees and pre/post BNB values are embedded in the P&L, but the analysis focuses on the net BNB gain.

**Native P&L snippet (cluster_balance_diff_pnl.json, native field):**

```json
{
  "0xf918...": {
    "total_delta_wei": 280406658503900100,
    "per_tx": {
      "0x2902...": 292824000503899840,
      "0xdb5d...": -12417341999999772
    }
  },
  "0x935d...": {
    "total_delta_wei": 291311013503899840,
    "per_tx": {
      "0x2902...": 291311013503899840
    }
  },
  "0x010f...": {
    "total_delta_wei": 277841040503899840,
    "per_tx": {
      "0x2902...": 292824000503899840,
      "0x4235...": -14982960000000000
    }
  },
  "0x74d8...": {
    "total_delta_wei": -1100676000000000,
    "per_tx": {
      "0xe0da...": -1100676000000000
    }
  },
  "0x5c95...": {
    "total_delta_wei": -23997326732113270000,
    "per_tx": {
      "0xdb5d...": 2673267326732473,
      "0xe0da...": -23999999999440000000
    }
  }
}
```

*Caption: Native P&L shows the adversary EOAs jointly gaining `0.8495587125116998 BNB`, LP EOA `0x74d8...` losing `0.001100676 BNB`, and router `0x5c95...` losing `23.99732673211327 BNB`, confirming the profit predicate and identifying the victim roles.*

The ERC20 component of the P&L shows additional value flowing from router `0x5c95...` to helper `0x4fde...` in the form of large ERC20 balances (for more than ten ERC20 tokens). These ERC20 units represent additional economic value in favor of the adversary cluster, but this report does not convert them to BNB or USD; the profit predicate is satisfied purely from the strictly positive BNB delta.

No non‑monetary oracle or utility predicate is required; the observed behavior is a straightforward value extraction from a custodial router to an adversary cluster.

---

### Impact & Losses

#### Total Loss Overview

The impact can be summarized as follows:

- **BNB loss:**
  - Router `0x5c95...` loses **23.998427408113272 BNB** in total, with the seed cluster accounting for **23.99732673211327 BNB** of net router BNB loss.
  - EOA `0x74d8...` (the LP) loses **0.001100676 BNB** through the liquidity‑provision transaction.
- **ERC20 token losses:**
  - Multiple ERC20 tokens (token‑like contracts including `0x4abf...`, `0xe2039b...`, `0xffb980...`, `0x525e25...`, `0x470e25...`, `0xb8fdaf...`, `0xb4dde7...`, and others) exhibit per‑token losses in the range of approximately `7.5e21–14.5e21` units from router `0x5c95...` to helper `0x4fde...`.
  - These per‑token losses are recorded in `cluster_balance_diff_pnl.json`. The analysis does **not** assign BNB or USD prices to these units; they are treated as raw ERC20 balance deltas.

#### Detailed Impacts

- **Router 0x5c95…**
  - Loses **23.99732673211327 BNB** across the four seed transactions.
  - Experiences large negative ERC20 deltas across more than ten ERC20 token contracts, with matching positive deltas on helper `0x4fde...`.
  - Functions as a custodial router/launchpad, so these losses represent user or protocol funds drained from router custody.

- **Helper 0x4fde…**
  - Accumulates large balances of ERC20 tokens transferred from router `0x5c95...` in tx `0xdb5d...`.
  - Receives these balances via `Token::transfer` calls where `0x5c95...` is the `from` address and `0x4fde...` is the `to` address.

- **Adversary EOAs (0xf918..., 0x935d..., 0x010f...)**
  - Jointly realize a **net native gain of 0.8495587125116998 BNB**, after accounting for gas and protocol flows, aggregated over txs `0x2902...`, `0x4235...`, and `0xdb5d...`.
  - Benefit indirectly from ERC20 inflows to `0x4fde...`, which holds the drained tokens.

- **LP EOA 0x74d8…**
  - Suffers a **net loss of 0.001100676 BNB** while providing liquidity via router `0x5c95...` in tx `0xe0da...`.
  - Acts as a third‑party victim whose funds are used to support liquidity and later value extraction by the adversary cluster.

- **Protocol‑level effect**
  - The router, intended to safely custody user tokens while performing trading and liquidity functions, is effectively drained of both BNB and ERC20 balances through a helper‑driven, unguarded entrypoint.
  - Users and protocol stakeholders relying on router `0x5c95...` for secure custody suffer losses with no on‑chain evidence that the withdrawal was authorized by any privileged role.

---

### References

This analysis is based on the following on‑chain artifacts and decompiled code:

- **[R1] Seed transaction traces (BNB Chain, chainid 56)**
  - High‑verbosity (`cast run -vvvvv`) execution traces for the four seed transactions:
    - `0x4235b006b94a79219181623a173a8a6aadacabd01d6619146ffd6fbcbb206dff`
    - `0xe0daa3bf68c1a714f255294bd829ae800a381624417ed4b474b415b9d2efeeb5`
    - `0x2902f93a0e0e32893b6d5c907ee7bb5dabc459093efa6dbc6e6ba49f85c27f61`
    - `0xdb5d43317ab8e5d67cdd5006b30a6f2ced513237ac189eb1e57f0f06f630d582`
  - Used to reconstruct call stacks, identify helper/ router interactions, and confirm ERC20 transfer flows.

- **[R2] Prestate‑based balance diffs and consolidated P&L**
  - `cluster_balance_diff_pnl.json`:
    - Contains prestate‑based native and ERC20 balance deltas for the seed cluster.
    - Used to quantify:
      - Net BNB gains for adversary EOAs (`0.8495587125116998 BNB` total).
      - Net BNB losses for router `0x5c95...` and LP `0x74d8...`.
      - Per‑token ERC20 losses from router `0x5c95...` to helper `0x4fde...`.

- **[R3] Router implementation decompile (0x328a...)**
  - Decompiled solidity for implementation `0x328aee1995ed2f3c86d6bac34dda06dd3a74e8ce`.
  - Used to understand:
    - Router state (token configs, templates, fee parameters).
    - Ownership and role‑management functions.
    - Overall structure of trading and liquidity functions.

- **[R4] Helper 0x4fde… decompile**
  - Decompiled solidity for helper contract `0x4fdebcA823b7886c3A69fA5fC014104F646D9591`.
  - Used to:
    - Identify functions with `"not owner"` / `"not swapper"` checks.
    - Confirm that selector `0x0483ee44` (`Unresolved_0483ee44`) lacks any msg.sender or role gate.
    - Establish the missing access‑control root cause.

- **[R5] Helper 0xbf26… and pool‑controller 0x0679… decompiles**
  - Decompiled solidity for:
    - Helper `0xbf26e147918a07cb8d8cf38d260edf346977686c`.
    - Pool‑controller `0x06799f7b09a455c1cf6a8e7615ece04b31a9d051`.
  - Used to:
    - Confirm pool‑creation logic via `NonfungiblePositionManager::createAndInitializePoolIfNecessary`.
    - Characterize pool‑controller interactions with token0(), token1(), and `swap` callbacks.

- **[R6] Post‑incident tx index and prestate balance diffs for helper 0x4fde…**
  - Prestate balance diff artifacts and txhash index focusing on helper `0x4fde...`.
  - Used to:
    - Confirm the volume and direction of ERC20 transfers from router `0x5c95...` to helper `0x4fde...` in tx `0xdb5d...`.
    - Corroborate that helper `0x4fde...` holds the drained ERC20 balances post‑incident.

---

### Summary of Root Cause

The incident is driven by a **protocol bug** in a helper‑integrated router system on BNB Chain:

- Router `0x5c95...` is designed as a custodial router/launchpad that temporarily holds ERC20 and BNB balances and delegates logic to an implementation and helper contracts.
- Helper `0x4fde...` exposes an externally callable function `0x0483ee44` that, once token metadata and pools are configured, instructs the router to transfer large ERC20 balances from router custody to `0x4fde...`, without enforcing any msg.sender or role‑based access control.
- Adversary EOAs `0x010f...`, `0x935d...`, and `0xf918...` form a cluster that:
  - Configures a Pancake V3 pool via helper `0xbf26...`.
  - Reuses third‑party LP liquidity via router `0x5c95...`.
  - Executes pool‑controller trades via `0x0679...` to collect WBNB.
  - Invokes helper `0x4fde...::0483ee44` to drain router‑held ERC20 balances into an adversary‑controlled helper contract.

Under the publicly reconstructible pre‑state `σ_B`, the four‑transaction sequence is reproducible by any unprivileged EOA. The key failure is the **unguarded helper entrypoint on `0x4fde...` (selector `0x0483ee44`) combined with router‑level custodial authority**, which together allow arbitrary EOAs to drain router‑held ERC20 tokens and extract BNB‑denominated profit from the system.

