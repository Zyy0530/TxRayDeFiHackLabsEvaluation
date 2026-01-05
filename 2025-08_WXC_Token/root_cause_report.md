## Incident Overview TL;DR

On BNB Chain, externally owned account (EOA) `0x476954c752a6ee04b68382c97f7560040eda7309` uses an ERC1967 proxy at `0x798465b25b68206370d99f541e11eea43288d297`, its implementation `0x4c100d30d9c511b8bb9d1c951bbc1be489a0172f`, and a helper contract `0x1266c6be60392a8ff346e8d5eccd3e69dd9c5f20` to run a multi-transaction strategy. The strategy routes WBNB, USDT, USDC.e, and MetyaMET through PancakeSwap pools and Venus markets. All four key transactions are initiated by the same operator EOA and execute through proxy entrypoints that check `msg.sender`, so the behavior is operator-specific rather than permissionless. The root cause is an operator-managed liquidation and routing strategy wired through a proxy whose high-value entrypoints are restricted to EOA `0x4769...`, combined with standard behavior of PancakeSwap and Venus contracts. No anyone-can-take (ACT) opportunity exists because unprivileged adversaries cannot call the same entrypoints with the same privileges.

## Key Background

The incident occurs on BNB Chain (chainid 56) and involves several well-known protocols:

- WBNB at `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c` is the canonical wrapped BNB token on BNB Chain; its verified source is included in the local seed artifacts.
- PancakeSwap pools, including the WBNB pair at `0xda5c7ea4458ee9c5484fa00f2b8c933393bac965`, provide AMM-based swaps and flash-swap style callbacks (`pancakeCall`) that allow contracts such as `0x7984...` to borrow assets intra-transaction and repay them by the end of execution.
- Venus markets, including the USDC.e market at `0xecA88125a5ADbe82614ffc12D0DB554E2e2867C8` and VBNB at `0xA07c5b74C9B40447a954e1466938b865b6BBea36`, support collateralized borrowing and liquidation flows where liquidators repay debt and seize collateral using flash loans and external liquidity.
- MetyaMET at `0xa5b000d453143b357dba63f4ee83f2f6fda832b8` is an ERC20 token with on-chain source captured in the local data-collector artifacts; it is used as collateral or a traded asset within the Venus leg of the strategy.

The on-chain corpus for this incident consists of one earlier seed transaction and three later transactions, all from EOA `0x4769...` to proxy `0x7984...` with method selector `0x32e4d6f3`:

- Seed transaction `0x1397bc7f0d284f8e2e30d0a9edd0db1f3eb0dd284c75e30d226b02bf09ad068f` in block `57177438`.
- Transaction `0x601292e5aa67286d44d3f7b2cd4e94d443557f36e1de1bb1bfb17358adbc0b68` in block `60818374`.
- Transaction `0x34b2288e9aec886f69fdba2bba76ffcde7b426df883ee01a922ac073102ded28` in block `60854217`.
- Transaction `0x8eeddccd1e3d8ec3819267c163a7d76025d0072b1010445c6ac4993726099288` in block `60887279`.

Traces and balance diffs for these transactions show coordinated routing of WBNB, USDT, USDC.e, and MetyaMET across PancakeSwap and Venus, always under the control of EOA `0x4769...` through the proxy and helper contracts.

## Vulnerability Analysis

No protocol-level invariant violation is demonstrated for WBNB, PancakeSwap, Venus, or MetyaMET. Each contract behaves in line with its deployed logic given the operator’s privileges. The contracts that orchestrate the strategy are:

- ERC1967 proxy `0x798465b25b68206370d99f541e11eea43288d297`, which receives all `0x32e4d6f3` calls from `0x4769...` and delegates execution to implementation `0x4c10...`.
- Implementation `0x4c100d30d9c511b8bb9d1c951bbc1be489a0172f`, which implements an ERC20-like token with role-based access control (including an operator role) and hooks into DEX and lending protocols.
- Helper contract `0x1266c6be60392a8ff346e8d5eccd3e69dd9c5f20`, which receives BNB from `0x4769...` and interacts with Venus VBNB and USDC.e during the liquidation leg.

Decompiled proxy code exposes several payable entrypoints that guard execution with checks of the form `require(msg.sender == 0x4769...)`, sometimes combined with constraints on `tx.origin`. These checks ensure that high-value orchestration functions are callable only by EOA `0x4769...`.

An illustrative excerpt from the decompiled proxy (human-labeled) shows the operator-only restriction:

```solidity
// Decompiled proxy 0x7984..., representative pattern
function Unresolved_xxx(...) external payable {
    require(msg.sender == 0x476954c752a6ee04b68382c97f7560040eda7309);
    // route funds across DEX and lending protocols
}
```

Under the ACT framework, a vulnerability would require a permissionless path for an arbitrary EOA to trigger the same high-value behavior. The available code and traces instead show that these entrypoints are hard-wired to the operator EOA, so there is no ACT-style exploitable surface.

## Detailed Root Cause Analysis

From an ACT perspective, no ACT opportunity is identified. The proxy and implementation contracts route value through AMMs and Venus, but the key proxy entrypoints are bound to a specific operator EOA, so an unprivileged adversary cannot reproduce the strategy using only public calls.

The detailed root cause is as follows:

- EOA `0x4769...` is the sole external sender of the four key transactions, all of which target proxy `0x7984...` with selector `0x32e4d6f3`.
- The ERC1967 proxy delegates to implementation `0x4c10...`, which provides token and orchestration logic with role-based access control and integrations to DEX and lending protocols.
- Decompiled proxy code exposes multiple payable entrypoints that enforce `require(msg.sender == 0x4769...)`, and in some cases also check `tx.origin`, so the observed high-level calls that drive PancakeSwap swaps and Venus liquidations pass through an operator-only surface.
- Because these high-value entrypoints are restricted to a single EOA, there is no sequence of transactions that an arbitrary unprivileged adversary can submit to obtain the same behavior from the pre-incident state `sigma_B`.

The components involved in this operator strategy are:

- Proxy `0x798465b25b68206370d99f541e11eea43288d297` and implementation `0x4c100d30d9c511b8bb9d1c951bbc1be489a0172f`, which centralize control in EOA `0x4769...` and orchestrate swaps and liquidations across external protocols.
- PancakeSwap WBNB pair `0xda5c7ea4458ee9c5484fa00f2b8c933393bac965` and related pools that provide intra-transaction liquidity to the operator contracts via swaps and flash-swap callbacks.
- Venus USDC.e market `0xecA88125a5ADbe82614ffc12D0DB554E2e2867C8` and VBNB `0xA07c5b74C9B40447a954e1466938b865b6BBea36`, which supply liquidation and collateral flows leveraged by the operator.
- MetyaMET token `0xa5b000d453143b357dba63f4ee83f2f6fda832b8`, which participates as collateral or a transferred asset in the Venus liquidation leg.

The ACT exploit-conditions are therefore not satisfied:

- ACT feasibility would require at least one high-value entrypoint on proxy `0x7984...` or implementation `0x4c10...` to be callable by an arbitrary EOA without special privileges. The decompiled code instead shows operator-only checks.
- ACT success would require a deterministic profit or non-monetary harm predicate achievable by an unprivileged adversary. The observed profit-like flows arise from an operator-controlled execution path and not from an exposed, repeatable opportunity that others can take.

In summary, the root cause is not a permissionless bug or misconfiguration but the existence and use of an operator-only orchestration surface that allows EOA `0x4769...` to run a complex liquidation and routing strategy across PancakeSwap and Venus.

## Adversary Flow Analysis

The strategy is operator-managed and multi-stage. EOA `0x4769...` uses proxy `0x7984...`, implementation `0x4c10...`, and helper `0x1266...` to obtain DEX liquidity, move WBNB and stablecoins through PancakeSwap, fund a helper contract with BNB, and execute a Venus USDC.e liquidation that shifts USDC.e and MetyaMET balances between Venus and external addresses. Every leg is initiated by `0x4769...`, and no transaction in the sequence is sent by an arbitrary third-party EOA.

### Adversary-related accounts

The operator/adversary cluster is:

- `0x476954c752a6ee04b68382c97f7560040eda7309` (BNB Chain, EOA): sole external sender of the four key transactions and initiator of all observed strategy legs.
- `0x798465b25b68206370d99f541e11eea43288d297` (BNB Chain, contract): ERC1967 proxy that receives all `0x32e4d6f3` calls from `0x4769...` and delegates execution to implementation `0x4c10...`.
- `0x4c100d30d9c511b8bb9d1c951bbc1be489a0172f` (BNB Chain, contract): implementation behind proxy `0x7984...` that contains role-based access control and DEX/LP hooks, invoked via `delegatecall` in all key transactions.
- `0x1266c6be60392a8ff346e8d5eccd3e69dd9c5f20` (BNB Chain, contract): helper contract that receives BNB from `0x4769...` and interacts with Venus VBNB and USDC.e during the liquidation leg.

Victim-candidate contracts involved in the flows are:

- WBNB (`0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`), with verified source.
- PancakeSwap WBNB pair (`0xda5c7ea4458ee9c5484fa00f2b8c933393bac965`).
- Venus USDC.e market (`0xecA88125a5ADbe82614ffc12D0DB554E2e2867C8`).
- MetyaMET token (`0xa5b000d453143b357dba63f4ee83f2f6fda832b8`), whose source is locally available and treated as verified in this context.

### Lifecycle stages and key transactions

**Stage 1: Initial WBNB routing via PancakeSwap**

- Transaction: `0x1397bc7f0d284f8e2e30d0a9edd0db1f3eb0dd284c75e30d226b02bf09ad068f` (BNB Chain, block `57177438`, mechanism `flashloan`).
- Behavior: Proxy `0x7984...` routes WBNB value from the WBNB contract into PancakePair `0xda5c7...`, then to addresses `0x2739...` and `0x4848...`, while sender `0x4769...` pays gas and loses native value overall in this transaction.

Seed transaction trace and balance diffs show these movements:

```json
// Seed transaction 0x1397... trace (excerpt, human-labeled)
{
  "from": "0x476954c752a6ee04b68382c97f7560040eda7309",
  "to": "0x798465b25b68206370d99f541e11eea43288d297",
  "input": "0x32e4d6f3...",
  "calls": [
    {
      "to": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "method": "transfer",
      "value_delta": "-4.3479e18 WBNB"
    },
    {
      "to": "0xda5c7ea4458ee9c5484fa00f2b8c933393bac965",
      "method": "swap",
      "beneficiaries": ["0x2739...", "0x4848..."]
    }
  ]
}
```

This excerpt, derived from the local `trace.cast.log` and `balance_diff.json` for `0x1397...`, illustrates that the proxy controls WBNB flows into PancakeSwap and distributes value to downstream addresses while the operator pays gas.

**Stage 2: Additional WBNB and stablecoin routing**

- Transactions:
  - `0x601292e5aa67286d44d3f7b2cd4e94d443557f36e1de1bb1bfb17358adbc0b68` (BNB Chain, block `60818374`, mechanism `flashloan`).
  - `0x34b2288e9aec886f69fdba2bba76ffcde7b426df883ee01a922ac073102ded28` (BNB Chain, block `60854217`, mechanism `transfer`).
- Behavior: The operator repeats a WBNB and stablecoin routing leg via PancakeSwap in transaction `0x6012...`, creating positive WBNB-native and stablecoin deltas for `0x4769...` and `0x4848...`. Separately, in transaction `0x34b2...`, about `1.441e18` wei BNB is transferred from `0x4769...` to helper `0x1266...` to fund later Venus activity.

Iter-3 balance diffs highlight these value movements:

```json
// 0x6012... balance_diff (simplified)
{
  "WBNB": {
    "0xbb4c...": "-8503830837677907",
    "0x4769...": "+3660754839838495",
    "0x4848489f...": "+4431965997839412"
  }
}
```

This confirms that the routing leg produces positive WBNB deltas for the operator cluster while drawing from WBNB reserves and liquidity pools.

**Stage 3: Venus USDC.e liquidation and MetyaMET movement**

- Transaction: `0x8eeddccd1e3d8ec3819267c163a7d76025d0072b1010445c6ac4993726099288` (BNB Chain, block `60887279`, mechanism `liquidation`).
- Behavior: Proxy `0x7984...` and helper `0x1266...` draw a large USDC.e amount, interact with Venus USDC.e and VBNB markets, and move USDC.e and MetyaMET between Venus contracts and addresses `0xcb06...`, `0x0bc5...`, and `0x4769...`, while shifting WBNB between the WBNB contract, VBNB, and `0x1266...`.

The local trace and balance diffs for `0x8eed...` show the liquidation leg:

```json
// 0x8eed... trace (excerpt, human-labeled)
{
  "calls": [
    {
      "to": "0xecA88125a5ADbe82614ffc12D0DB554E2e2867C8",
      "method": "liquidateBorrow",
      "token": "USDC.e",
      "participants": ["0xcb06...", "0x4769..."]
    },
    {
      "to": "0xA07c5b74C9B40447a954e1466938b865b6BBea36",
      "method": "redeem",
      "token": "VBNB",
      "beneficiary": "0x1266..."
    }
  ]
}
```

These traces demonstrate that the strategy uses Venus liquidation and redemption flows, with the operator-controlled proxy and helper directing the movement of collateral and debt.

Across all stages, the only external sender is EOA `0x4769...`, and all on-chain execution routes through proxy `0x7984...` into implementation `0x4c10...` and helper `0x1266...`. No transaction in this corpus is sent by an arbitrary third-party EOA, and no artifact shows a permissionless public entrypoint with the same payoff structure.

## Impact & Losses

The strategy redistributes WBNB, USDT, USDC.e, MetyaMET, and Venus vTokens between the operator cluster and protocol-related addresses, including a Venus liquidation that seizes collateral and repays debt. The report does not compute numeric protocol or user loss figures in a single reference asset. Instead, it focuses on demonstrating that:

- The observed flows arise from an operator-only execution path.
- There is no permissionless exploitability under the ACT definition.

A summary line in the underlying JSON records the total loss overview as an “USD-equivalent” amount that is not computed, reflecting the absence of consolidated price data across all legs and tokens in the local artifacts.

## References

Evidence for this analysis is drawn from the following local artifacts:

- [1] Seed transaction metadata and balance diff for `0x1397bc7f...`: local seed project under `artifacts/root_cause/seed/56/0x1397bc7f0d284f8e2e30d0a9edd0db1f3eb0dd284c75e30d226b02bf09ad068f/`.
- [2] Iteration-3 traces and balance diffs for `0x6012...`, `0x34b2...`, and `0x8eed...`: local data-collector outputs under `artifacts/root_cause/data_collector/iter_3/tx/56/`.
- [3] Decompiled proxy and implementation code for `0x7984...` and `0x4c10...`: local decompilation outputs under `artifacts/root_cause/data_collector/iter_2/contract/56/`.
- [4] WBNB verified source project: local seed project for `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c/`.
- [5] MetyaMET source project (local build from on-chain contract `0xa5b0...`): local contracts under `artifacts/root_cause/data_collector/iter_3/tx/56/0x8eeddccd1e3d8ec3819267c163a7d76025d0072b1010445c6ac4993726099288/_seed_session/_contracts/56/0xa5b000d453143b357dba63f4ee83f2f6fda832b8/`.

