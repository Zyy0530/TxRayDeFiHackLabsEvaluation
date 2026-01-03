# Unrestricted ERC20 Mint Drains AMM Stablecoin Liquidity on BSC

## Incident Overview & TL;DR

On BSC (chainid 56), an adversary-controlled helper contract `0xbfd7280b11466bc717eb0053a78675aed2c2e388` abused a publicly accessible mint function on ERC20 token `0xc3b1b45e5784a8efececfc0be2e28247d3f49963` to create a very large amount of that token. The helper then routed the freshly minted tokens through an AMM pair `0x794ed5e8251c4a8d321ca263d9c0bc8ecf5fa1ff`, swapping them for a substantial quantity of a stablecoin-like ERC20 token `0x55d398326f99059ff775485246999027b3197955`.

The root cause is a protocol-level bug in token `0xc3b1…`: it exposes a publicly callable mint function (selector `0xa7c861da`) that directly increases `totalSupply` and a chosen recipient’s balance without any access control. Any unprivileged caller can therefore mint arbitrary amounts of the token and use AMM liquidity pools to drain external collateral (here, stablecoin `0x55d3…`) backing the pool.

The core exploit transaction is `0xc29c98da0c14f4ca436d38f8238f8da1c84c4b1ee6480c4b4facc4b81a013438` in block 4,428,0829, sent by EOA `0xce21c6e4fa557a9041fa98dff59a4401ef0a18ac` to the helper contract. A follow-up withdrawal transaction `0xb3b5f67e80529b95aff2983932ee72b543ce29b2838d7166760c09ce760044bc` moves the drained stablecoin from the helper back to the EOA.

## Key Background

- The AMM pair `0x794ed5e8251c4a8d321ca263d9c0bc8ecf5fa1ff` exposes a Uniswap V2–style interface (events `Sync`, `Transfer`; functions `mint`, `skim`, `sync`, `token0`, `token1`, `permit`). Collected ABI data and the exploit transaction’s receipt and trace confirm that it acts as a liquidity pool between token `0xc3b1…` and stablecoin `0x55d3…`.
- Router contract `0x10ed43c718714eb63d5aa57b78b54704e256024e` behaves as a Uniswap V2 router: the call trace shows it querying reserves on the pair via selector `0x0902f1ac` and invoking the pair with selector `0x022c0d9f` as part of the swap path that trades minted `0xc3b1…` for `0x55d3…`.
- Token `0xc3b1b45e5784a8efececfc0be2e28247d3f49963` is ERC20-like, emitting standard `Transfer` and `Approval` events and including LayerZero- and owner-configuration functions. Critically, its function with selector `0xa7c861da` directly increases `totalSupply` and a specified address’s balance without checking `msg.sender` against any owner or role, making minting effectively permissionless.
- Helper contract `0xbfd7280b11466bc717eb0053a78675aed2c2e388`, deployed by EOA `0xce21…`, exposes functions with selectors `0x09b8790a` and `0xbfbaa190`. Decompiled code shows `0x09b8790a` orchestrating calls to the factory, token `0xc3b1…`, router `0x10ed…`, and AMM pair `0x794e…` to perform the mint-and-swap, while `0xbfbaa190` reads the helper’s token balance with `balanceOf` (`0x70a08231`) and then calls the token’s `transfer` (`0xa9059cbb`) to send the entire balance to `msg.sender`.
- EOA `0xce21c6e4fa557a9041fa98dff59a4401ef0a18ac` deploys helper contract `0xbfd7…` in tx `0x2775abd1518de94a27b53260767ea5834c21fcaaff62ed93c618c96712ff7204`, and then sends the exploit tx `0xc29c…` and withdrawal tx `0xb3b5…` to it within the same block range. Collected address txlists show this tight coupling between the EOA and its helper.
- Seed-analysis of tx `0xc29c98da0c14f4ca436d38f8238f8da1c84c4b1ee6480c4b4facc4b81a013438` (block 4,428,0829) shows ERC20 balance changes consistent with minting a large supply of `0xc3b1…`, sending it to the AMM pair, and receiving `0x55d3…` into the helper contract. Balance-diff artifacts, the receipt’s `Transfer` logs, and the call trace all agree on the direction and approximate magnitude of these flows.

## Vulnerability & Root Cause Analysis

### ACT Opportunity and Pre-State

The ACT opportunity is defined at block height **B = 4,428,0828** on BSC (chainid 56), just before the exploit block. In this pre-state:

- ERC20 token `0xc3b1b45e5784a8efececfc0be2e28247d3f49963` has been deployed with a public mint function (`0xa7c861da`) that increases `totalSupply` and an arbitrary recipient’s balance without any access control.
- AMM pair contract `0x794ed5e8251c4a8d321ca263d9c0bc8ecf5fa1ff` holds a liquidity pool between token `0xc3b1…` and stablecoin-like token `0x55d398326f99059ff775485246999027b3197955`.
- Router `0x10ed43c718714eb63d5aa57b78b54704e256024e` and factory `0xca143ce32fe78f1f7019d7d551a6402fc5350c73` are deployed and wired to the pair so that swaps between `0xc3b1…` and `0x55d3…` are possible.
- Helper contract `0xbfd7280b11466bc717eb0053a78675aed2c2e388` has already been deployed by EOA `0xce21c6e4fa557a9041fa98dff59a4401ef0a18ac` and configured to target this token/pair/router combination.

In this pre-state, the protocol has already embedded the critical invariant violation: the mint function on `0xc3b1…` permits arbitrary third-party minting. No on-chain defense (such as an allowlist, owner-only modifier, or off-chain guardian) prevents an attacker from minting large supplies and dumping them into existing liquidity pools.

### Unrestricted Mint Function on Token 0xc3b1…

Decompiled code for token `0xc3b1…` shows the problematic mint function corresponding to selector `0xa7c861da`:

_Decompiled mint function for token 0xc3b1…, showing arbitrary recipient minting with no caller access control (collected contract source, decompiled from on-chain bytecode for `0xc3b1…`):_

```solidity
/// @custom:selector    0xa7c861da
/// @custom:signature   Unresolved_a7c861da(uint16 arg0, address arg1, uint256 arg2, uint256 arg3) public
function Unresolved_a7c861da(uint16 arg0, address arg1, uint256 arg2, uint256 arg3) public {
    require(arg0 == (uint16(arg0)));
    require(arg1 == (address(arg1)));
    require(!arg3 > 0xffffffffffffffff);
    require(!(arg3 > 0xffffffffffffffff), "ERC20: mint to the zero address");
    ...
    require(address(arg1), "ERC20: mint to the zero address");
    require(!(totalSupply > ~(arg2)), "ERC20: mint to the zero address");
    totalSupply = totalSupply + arg2;
    address var_a = address(arg1);
    storage_map_b[var_a] = arg2 + storage_map_b[var_a];
    emit Transfer(0, address(arg1), arg2);
}
```

Key observations:

- The function is marked `public` and never checks `msg.sender` against `owner`, a minter role, or any other privileged set; it is therefore callable by any address.
- It takes an arbitrary `address arg1` and `uint256 arg2`, verifies only that `arg1` is not the zero address and that the mint does not overflow, then adds `arg2` to `totalSupply` and to `arg1`’s balance, emitting a `Transfer(0, arg1, arg2)` event.
- There is no cap on `arg2`, no per-address limit, and no linkage to any on-chain collateral or locking mechanism.

This is a textbook **unrestricted mint** vulnerability: any unprivileged address can mint unbounded token supply to itself or a helper contract.

### How the Vulnerability Enables Stablecoin Drain via AMM

Given a liquid AMM pool between the vulnerable token `0xc3b1…` and stablecoin `0x55d3…`, an attacker can:

1. Mint an arbitrarily large amount of `0xc3b1…` into an address they control (here, the helper contract).
2. Approve/spend those tokens into the AMM pair via a router.
3. Swap the minted tokens for `0x55d3…`, pushing the pool price to near-zero for `0xc3b1…` while extracting valuable `0x55d3…` reserves.

The collected call trace for the exploit tx `0xc29c…` shows exactly this pattern. A simplified excerpt of the `debug_traceTransaction` callTracer output illustrates the main calls:

_Call trace excerpt for exploit tx 0xc29c…, showing factory query, unrestricted mint on `0xc3b1…`, and router-mediated swap into `0x55d3…` (callTracer result for tx `0xc29c…` on BSC):_

```json
{
  "to": "0xca143ce32fe78f1f7019d7d551a6402fc5350c73",
  "input": "0xe6a43905000000000000000000000000c3b1b45e5784a8efececfc0be2e28247d3f4996300000000000000000000000055d398326f99059ff775485246999027b3197955"
}
{
  "to": "0xc3b1b45e5784a8efececfc0be2e28247d3f49963",
  "input": "0xa7c861da0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bfd7280b11466bc717eb0053a78675aed2c2e3880000000000000000000000000000000000000000000531e553441b2d50bac038..."
}
{
  "to": "0x10ed43c718714eb63d5aa57b78b54704e256024e",
  "input": "0x5c11d7950000000000000000000000000000000000000000000531e553441b2d50bac038..."
}
{
  "to": "0x55d398326f99059ff775485246999027b3197955",
  "input": "0x70a08231000000000000000000000000bfd7280b11466bc717eb0053a78675aed2c2e388"
}
```

From this trace and the transaction’s receipt/balance diff:

- The helper contract calls the factory to obtain the pair address for `(0xc3b1…, 0x55d3…)`.
- It then calls token `0xc3b1…` with selector `0xa7c861da`, minting a large amount of `0xc3b1…` to itself (`0xbfd7…`).
- It interacts with the router, which pulls `0xc3b1…` from the helper and executes a swap on the pair, after which the helper’s `0x55d3…` balance is non-zero and the pair’s `0x55d3…` reserves are decreased.

### Evidence from Balance Diffs and Logs

The seed balance-diff analysis for tx `0xc29c…` summarizes ERC20 transfer effects:

_Seed balance diff for tx 0xc29c…, showing minted `0xc3b1…` and drained `0x55d3…` (derived from pre/post state diffs and ERC20 `Transfer` events):_

```json
{
  "erc20_transfers": [
    {
      "token": "0xc3b1b45e5784a8efececfc0be2e28247d3f49963",
      "from": "0x0000000000000000000000000000000000000000",
      "to": "0xbfd7280b11466bc717eb0053a78675aed2c2e388",
      "value": "6280255360077122982559800"
    },
    {
      "token": "0xc3b1b45e5784a8efececfc0be2e28247d3f49963",
      "from": "0xbfd7280b11466bc717eb0053a78675aed2c2e388",
      "to": "0x794ed5e8251c4a8d321ca263d9c0bc8ecf5fa1ff",
      "value": "6280255360077122982559800"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "from": "0x794ed5e8251c4a8d321ca263d9c0bc8ecf5fa1ff",
      "to": "0xbfd7280b11466bc717eb0053a78675aed2c2e388",
      "value": "31538624555626362308555"
    }
  ]
}
```

These diffs match the receipt’s `Transfer` logs for:

- `0xc3b1…` mint from `0x0` to `0xbfd7…` and subsequent transfer from `0xbfd7…` to `0x794e…`.
- `0x55d3…` transfer from `0x794e…` (the pair) to `0xbfd7…` (the helper).

Together with the decompiled mint function, this establishes that the attacker exploited a **public, unrestricted mint** to inject synthetic `0xc3b1…` into the AMM and extract real `0x55d3…` collateral.

### Root Cause Classification

- **Category:** Protocol bug in token contract `0xc3b1…`.
- **Scope:** The bug resides entirely within the ERC20 token’s mint logic; the AMM, router, and helper logic behave as designed given their inputs.
- **Fix direction:** Restrict `0xa7c861da` to a privileged minter role or remove it; additionally, downstream protocols should gate-list or risk-screen tokens with unrestricted mint capabilities before listing them in collateral-bearing pools.

## Adversary Flow Analysis

### Stage 1 – Helper Contract Deployment and Configuration

- **Transaction:** `0x2775abd1518de94a27b53260767ea5834c21fcaaff62ed93c618c96712ff7204` (block 4,428,0781).
- **Actor:** EOA `0xce21c6e4fa557a9041fa98dff59a4401ef0a18ac`.
- **Effect:** Deploys helper contract `0xbfd7280b11466bc717eb0053a78675aed2c2e388`. The constructor bytecode embeds references to the key protocol addresses, including `0x55d3…` (USDT-like token), factory `0xca143c…`, router `0x10ed…`, and AMM-related contracts such as `0x4f31…`.
- **Evidence:** Collected txlist for the EOA shows this tx as a contract creation that results in `contractAddress = 0xbfd7…`, with the input data containing multiple hard-coded addresses matching the factory, router, and token addresses used later in the exploit.

This stage prepares a reusable helper that centralizes exploit logic: minting via the vulnerable token, interacting with the AMM, and later withdrawing stolen tokens.

### Stage 2 – Unlimited Mint and AMM Swap Draining Stablecoin into Helper

- **Transaction:** `0xc29c98da0c14f4ca436d38f8238f8da1c84c4b1ee6480c4b4facc4b81a013438` (block 4,428,0829).
- **Actor:** EOA `0xce21…` calling helper `0xbfd7…`.
- **Mechanism:** `mint_and_swap`.
- **High-level effect:** The helper mints `6,280,255,360,077,122,982,559,800` units of `0xc3b1…` to itself using the unrestricted mint function `0xa7c861da`, sends those tokens to the AMM pair `0x794e…`, and receives `31,538,624,555,626,362,308,555` units of `0x55d3…` from the pair, depleting its `0x55d3…` reserves.

The `debug_traceTransaction` callTracer and receipt logs together show:

- A staticcall from `0xbfd7…` to factory `0xca143c…` (`0xe6a43905`) that returns the pair address `0x794e…` for `(0xc3b1…, 0x55d3…)`.
- A call from `0xbfd7…` to token `0xc3b1…` with selector `0xa7c861da` and `arg1 = 0xbfd7…`, `arg2 = 0x0531e553441b2d50bac038` (the minted amount), immediately followed by ERC20 `Transfer(0x0 → 0xbfd7…, value = 6280255360…9800)` and `Transfer(0xbfd7… → 0x794e…, value = 6280255360…9800)` logs for `0xc3b1…`.
- A call from `0xbfd7…` to router `0x10ed…`, which:
  - Calls `0xc3b1…` with selector `0x23b872dd` to transfer the minted tokens from `0xbfd7…` to the pair.
  - Queries the pair’s reserves via `0x0902f1ac`.
  - Calls the pair with selector `0x022c0d9f`, producing a `Transfer(0x794e… → 0xbfd7…)` log on token `0x55d3…` and a `Swap`-like event on the pair.

The balance diff quoted earlier shows the net inventory change: the helper’s `0x55d3…` balance increases by `31538624555626362308555` units, exactly matching the amount transferred out of the pair.

### Stage 3 – Post-Exploit Withdrawal from Helper to Adversary EOA

- **Transaction:** `0xb3b5f67e80529b95aff2983932ee72b543ce29b2838d7166760c09ce760044bc` (block 4,428,0859).
- **Actor:** EOA `0xce21…` calling helper `0xbfd7…`.
- **Mechanism:** `withdraw_call`.
- **High-level effect:** The EOA instructs the helper to forward its entire balance of token `0x55d3…` to the EOA. This consolidates the stolen stablecoin into the adversary’s externally owned account.

The helper’s decompiled withdraw function (selector `0xbfbaa190`) implements a straightforward “withdraw all balance to caller” pattern:

_Decompiled withdraw function on helper 0xbfd7…, showing `balanceOf(this)` followed by `transfer(msg.sender, balance)` (collected contract source, decompiled from on-chain bytecode for `0xbfd7…`):_

```solidity
/// @custom:selector    0xbfbaa190
/// @custom:signature   Unresolved_bfbaa190(uint256 arg0, address arg1) public payable
function Unresolved_bfbaa190(uint256 arg0, address arg1) public payable {
    require(!arg0 > 0xffffffffffffffff);
    require(arg1 == (address(arg1)));
    address var_h = address(this);
    (bool success, bytes memory ret0) = address(arg1).Unresolved_70a08231(var_h); // staticcall balanceOf(this)
    ...
    address var_j = address(msg.sender);
    (bool success, bytes memory ret1) = address(arg1).Unresolved_a9059cbb(var_j); // call transfer(msg.sender, balance)
}
```

The address-level txlist for `0xbfd7…` shows tx `0xb3b5…` with:

- `from = 0xce21…`
- `to = 0xbfd7…`
- `methodId = 0xbfbaa190`
- the first argument set to token `0x55d3…`.

This strongly supports the interpretation that `0xb3b5…` is a withdrawal of the helper’s `0x55d3…` balance to the adversary’s EOA. However, note the following limitation:

- **Limitation:** Logs and balance-diff artifacts for tx `0xb3b5…` are not present in the collected dataset, so the profit attribution for the adversary relies primarily on the helper’s decompiled code and the fact that the helper already held the stolen `0x55d3…` balance after tx `0xc29c…`.

## Impact & Losses

### Quantitative Impact

- The AMM pair `0x794ed5e8251c4a8d321ca263d9c0bc8ecf5fa1ff` loses **31,538,624,555,626,362,308,555 units** of token `0x55d398326f99059ff775485246999027b3197955` to the helper contract `0xbfd7…` during the exploit tx `0xc29c…`.
- The same amount of `0x55d3…` becomes controlled by the adversary via helper `0xbfd7…` and, subsequently, the EOA `0xce21…` after the withdrawal tx `0xb3b5…`.
- Concurrently, the supply of token `0xc3b1…` is inflated by **6,280,255,360,077,122,982,559,800 units**, with that supply first held by the helper and then largely residing in the AMM pair as worthless collateral from the perspective of stablecoin liquidity providers.

Decimals for these tokens are not explicitly provided in the artifacts; if `0x55d3…` behaves like common 18-decimal ERC20 tokens, the nominal loss would be on the order of 31.5386e6 “whole units”, but this report confines itself to the raw on-chain units recorded in the evidence.

### Affected Parties

- **Primary victim:** Liquidity providers (LPs) or protocol vaults backing the `0xc3b1…`/`0x55d3…` pool on `0x794e…`, who suffer direct depletion of their `0x55d3…` collateral.
- **Secondary risk:** Any protocol or strategy that treats `0xc3b1…` as having a fixed or capped supply, or that uses it as collateral elsewhere, is exposed to dilution and price collapse due to the unbounded minting capability.

## References

- [1] Seed transaction metadata and balance diff for exploit tx `0xc29c98da0c14f4ca436d38f8238f8da1c84c4b1ee6480c4b4facc4b81a013438` (includes `balance_diff.json` and associated metadata summarizing ERC20 transfers and native balance changes).
- [2] Execution trace and receipt for seed tx `0xc29c…` (`debug_traceTransaction` callTracer output and `receipt.json`, containing detailed call stack and ERC20 `Transfer`/`Swap` logs).
- [3] Decompiled and ABI artifacts for token `0xc3b1b45e5784a8efececfc0be2e28247d3f49963` (supporting identification of the unrestricted mint function and ERC20 behavior).
- [4] Decompiled and ABI artifacts for helper contract `0xbfd7280b11466bc717eb0053a78675aed2c2e388` (supporting reconstruction of the mint-and-swap orchestration and withdraw-to-caller pattern).
- [5] Address-level txlists around block 4,428,0829 for EOA `0xce21…` and helper contract `0xbfd7…` (supporting lifecycle reconstruction: deployment, exploit invocation, and withdrawal).

