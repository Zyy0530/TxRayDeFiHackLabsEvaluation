## Incident Overview TL;DR

An attacker-controlled helper contract on Ethereum mainnet abused the Size LeverageUp zap and DexSwap GenericRoute aggregator to steal 20,000e18 PendlePrincipalToken (PT) from a victim EOA. The victim, `0x83eccb05386b2d10d05e1baea8ac89b5b7ea8290`, held PT `0x23e60d1488525bf4685f53b3aa8e676c30321066` and had opened a leveraged Size position at market `0x1b367622b8c516adc4f903bb6148446bb1f23ae3`, granting a 20,000e18 PT allowance to the LeverageUp zap `0xf4a21ac7e51d17a0e1c8b59f7a98bb7a97806f14`. The attacker deployed a helper contract `0xa6dc1fc33c03513a762cdf2810f163b9b0fd3a71` that masqueraded as a Size market and also served as a DexSwap GenericRoute router. LeverageUp/DexSwap treated this router as trusted, force-approved it for the victim’s PT, and executed attacker-supplied calldata that invoked `transferFrom` to move 20,000e18 PT from the victim to the helper, followed by a withdrawal transaction that sent the stolen PT to attacker EOA `0xa7e9b982b0e19a399bc737ca5346ef0ef12046da`.

The root cause is a protocol bug in the GenericRoute design of LeverageUp + DexSwap: given only the victim’s PT allowance to LeverageUp, the system grants an arbitrary router unlimited PT spending power and executes arbitrary calldata on that router, without constraining the router address to a vetted set. This creates a deterministic ACT opportunity: any unprivileged adversary who can convince a victim to approve PT to LeverageUp while GenericRoute is enabled can deploy a compatible helper and drain the victim’s PT balance.

## Key Background

At pre-state `σ_B` (Ethereum mainnet immediately before block `23145764`), the relevant system state is:
- Victim EOA `0x83eccb05386b2d10d05e1baea8ac89b5b7ea8290` holds PendlePrincipalToken `0x23e60d1488525bf4685f53b3aa8e676c30321066`.
- The victim has previously used Pendle router `0x888888888889758f76e7103c6cbf23abbf58f946` to acquire PT and then opened a leveraged Size position at market `0x1b367622b8c516adc4f903bb6148446bb1f23ae3` using PT as collateral.
- The victim has granted a PT allowance of 20,000e18 to the LeverageUp zap `0xf4a21ac7e51d17a0e1c8b59f7a98bb7a97806f14`.

These facts are established by:
- Victim PT acquisition and balance movements in:
  - `artifacts/root_cause/data_collector/iter_5/tx/1/0x38e14a04e5336d02c0484ed979a493feb8bce29de5799ee264aed1f75230187a/balance_diff.json`
  - `artifacts/root_cause/data_collector/iter_5/tx/1/0xb78a530feaf50f5566301f79aca1d0aa9f2f8a3bf0726bd84373bcfd58d03653/balance_diff.json`
- Size leveraged position setup in:
  - `artifacts/root_cause/data_collector/iter_4/tx/1/0xbc07ccce7974a6232d87bc7f812eaa19919c8ac4c3ec5b80eae337961923ec38/trace_callTracer.json`
  - `artifacts/root_cause/data_collector/iter_4/tx/1/0xbc07ccce7974a6232d87bc7f812eaa19919c8ac4c3ec5b80eae337961923ec38/balance_diff.json`
- Victim transaction history confirming the allowance and activity window:
  - `artifacts/root_cause/data_collector/iter_2/address/1/0x83eccb05386b2d10d05e1baea8ac89b5b7ea8290/txlist_23144000_23148000.json`

PendlePrincipalToken `0x23e60d1488525bf4685f53b3aa8e676c30321066` is an ERC20-like principal token with standard allowance and `transferFrom` semantics, as defined in the verified source:

```solidity
// Seed contract source for PendlePrincipalToken (0x23e60d1488…)
// artifacts/root_cause/seed/1/0x23e60d1488525bf4685f53b3aa8e676c30321066/src/pendle/contracts/core/YieldContracts/PendlePrincipalToken.sol
contract PendlePrincipalToken is PendleERC20, Initializable, IPPrincipalToken {
    address public immutable SY;
    address public immutable factory;
    uint256 public immutable expiry;
    address public YT;
    ...
}
```

Size market `0x1b367622b8c516adc4f903bb6148446bb1f23ae3` accepts PT as collateral and issues non-transferable tokens to represent deposits and debt. The victim uses this market to lever a PT position, as shown by the Size multicall trace and balances in tx `0xbc07ccce…`.

LeverageUp and DexSwap are implemented in the verified source tree:
- `artifacts/root_cause/data_collector/iter_1/contract/1/0xf4a21ac7e51d17a0e1c8b59f7a98bb7a97806f14/source`
  - `src/zaps/LeverageUp.sol`
  - `src/liquidator/DexSwap.sol`

These contracts define:
- `LeverageUp.leverageUpWithSwap`, which opens leveraged positions using a Size market and optional swaps.
- `DexSwap._swapGenericRoute`, which implements the GenericRoute swap method and is the key vulnerable component.

## Vulnerability Analysis

The vulnerability is an unsafe GenericRoute design in LeverageUp + DexSwap that combines:
- An arbitrary router address, supplied by the caller through swap parameters.
- A forced, unlimited ERC20 approval from LeverageUp/DexSwap to this router for the victim’s tokens.
- Execution of arbitrary calldata on the router, without restricting the router to a vetted set of trusted contracts.

DexSwap decodes GenericRoute parameters and then grants the router unlimited allowance on the input token before executing a low-level call:

```solidity
// DexSwap._swapGenericRoute
// artifacts/root_cause/data_collector/iter_1/contract/1/0xf4a21ac7…/source/src/liquidator/DexSwap.sol
function _swapGenericRoute(bytes memory data) internal {
    GenericRouteParams memory params = abi.decode(data, (GenericRouteParams));

    // Approve router to spend collateral token
    IERC20(params.tokenIn).forceApprove(params.router, type(uint256).max);

    // Execute swap via low-level call
    (bool success,) = params.router.call(params.data);
    if (!success) {
        revert PeripheryErrors.GENERIC_SWAP_ROUTE_FAILED();
    }
}
```

LeverageUp’s core zap function pulls tokens from the user into LeverageUp and then calls `_swap`, which dispatches to `_swapGenericRoute` when the `SwapMethod.GenericRoute` enum is selected:

```solidity
// LeverageUp.leverageUpWithSwap (excerpt)
// artifacts/root_cause/data_collector/iter_1/contract/1/0xf4a21ac7…/source/src/zaps/LeverageUp.sol
function leverageUpWithSwap(
    ISize size,
    SellCreditMarketParams[] memory sellCreditMarketParamsArray,
    address tokenIn,
    uint256 amount,
    uint256 leveragePercent,
    uint256 borrowPercent,
    SwapParams[] memory swapParamsArray
) external {
    ...
    IERC20Metadata(tokenIn).safeTransferFrom(msg.sender, address(this), amount);
    if (tokenIn != address(dataView.underlyingCollateralToken)) {
        _swap(swapParamsArray);
    }
    ...
}
```

In the GenericRoute configuration, the key properties are:
- The victim grants PT allowance to LeverageUp.
- LeverageUp pulls PT into its own balance under that allowance.
- DexSwap, called via LeverageUp, reassigns effective spending power over PT to whichever router address is provided in `GenericRouteParams`.
- The router calldata is opaque to LeverageUp/DexSwap and can invoke arbitrary ERC20 functions, including `transferFrom` from victim-controlled allowances.

The vulnerable components identified in the analysis are:
- `DexSwap._swapGenericRoute`, which force-approves an arbitrary `router` for `tokenIn` and executes `router.call(params.data)` without restricting the router address.
- `LeverageUp.leverageUpWithSwap`, which passes user funds and allowances into `DexSwap._swapGenericRoute` when `SwapMethod.GenericRoute` is selected, with router and route data effectively attacker-controlled.
- The victim’s PT allowance from EOA `0x83eccb05386b2d10d05e1baea8ac89b5b7ea8290` to LeverageUp `0xf4a21ac7…`, which provides the approval that `_swapGenericRoute` effectively delegates to the helper router.

Security principles violated:
- **Least privilege**: DexSwap grants an arbitrary router unlimited PT allowance instead of restricting approvals to known, audited router contracts.
- **Separation of roles**: The design allows a single attacker-controlled helper to appear both as the Size market and as the GenericRoute router, collapsing distinct trust domains into one contract.
- **Authorization correctness**: The victim’s PT allowance to LeverageUp is consumed in a way that allows a router the victim never interacted with directly to perform `transferFrom` on the victim’s PT balance.
- **Call-target validation**: DexSwap and LeverageUp do not restrict the router address to a curated registry or to the actual Size market associated with the victim’s position.

## Detailed Root Cause Analysis

### Pre-state and ACT conditions

The ACT opportunity is defined at block height `B = 23145763` with pre-state `σ_B` having:
- Victim EOA `0x83eccb05386b2d10d05e1baea8ac89b5b7ea8290` holding a nonzero PT balance in token `0x23e60d1488525bf4685f53b3aa8e676c30321066`.
- A PT allowance of 20,000e18 from the victim to LeverageUp `0xf4a21ac7…`.
- A Size leveraged position at market `0x1b367622b8c516adc4f903bb6148446bb1f23ae3`, where PT is used as collateral and the victim’s credit/debt state is established.

The analysis lists explicit exploit conditions that are satisfied in this state:
- The victim holds PT and has granted LeverageUp a PT allowance large enough to cover the theft.
- An unprivileged attacker can deploy a helper contract implementing the minimal ISize-like interface expected by LeverageUp and can use this helper as a router for GenericRoute.
- The attacker can submit a transaction that calls the helper, which in turn calls `LeverageUp.leverageUpWithSwap` with parameters `size = helper`, `swapParams.method = GenericRoute`, `router = helper`, and `route.data` encoding calldata that will call `PendlePrincipalToken.transferFrom(victim, helper, amount)`.
- All contracts involved (Pendle PT, LeverageUp, DexSwap, Size market) are publicly deployed and callable on Ethereum mainnet.

### Transaction sequence and call flow

The adversary’s main transaction sequence `b` consists of:
1. **Helper deployment**
   - Tx `0x17846acccd832432dba32bf1008797377324a1bd8bd8ef8e52ec8171afc99a81` (block `23145240`).
   - Type: adversary-crafted.
   - From attacker EOA `0xa7e9b982b0e19a399bc737ca5346ef0ef12046da`.
   - Deploys helper contract `0xa6dc1fc33c03513a762cdf2810f163b9b0fd3a71`.
   - Evidence: `artifacts/root_cause/data_collector/iter_3/tx/1/0x17846ac…/trace_callTracer.json`, `.../tx.json`, `.../receipt.json`, `.../deployed_code.json`.

2. **Helper initialization**
   - Tx `0xda91d19080f799f609eb5c513439945afce65601caa066e32098efd32fbeb1b9` (block `23145689`).
   - Type: adversary-crafted.
   - From the same attacker EOA to helper `0xa6dc1f…`.
   - Initializes internal configuration so the helper satisfies LeverageUp’s expectations (ISize-like functions, router behavior).
   - Evidence: `artifacts/root_cause/data_collector/iter_3/tx/1/0xda91d1…/trace_callTracer.json`, `artifacts/root_cause/data_collector/iter_4/tx/1/0xda91d1…/prestateTracer_diff.json`.

3. **Core exploit: GenericRoute-driven PT theft**
   - Tx `0xc7477d6a5c63b04d37a39038a28b4cbaa06beb167e390d55ad4a421dbe4067f8` (block `23145764`).
   - Type: adversary-crafted.
   - From attacker EOA `0xa7e9b9…` to helper `0xa6dc1f…`.
   - Inclusion feasibility: Type-2 transaction with zero ETH value and standard gas/fee parameters; all called contracts are already deployed and publicly callable.

   The exploit call flow, as shown in the Foundry trace log:

```bash
# Seed transaction trace (Foundry) for exploit tx 0xc7477d6a…
# artifacts/root_cause/seed/1/0xc7477d6a…/trace.cast.log (excerpt)
0xA6dc1F…::4d564d73(...)
  ├─ PendlePrincipalToken::balanceOf(0x83eCCb05386B2d10D05e1BaEa8aC89b5B7EA8290)
  ├─ PendlePrincipalToken::allowance(0x83eC…, 0xF4a21A…) → 20000000000000000000000
  ├─ 0xF4a21A…::cd3607df(...)  # LeverageUp.leverageUpWithSwap
  │   ...
  │   ├─ PendlePrincipalToken::approve(0xA6dc1F…, 2^256-1)
  │   ├─ PendlePrincipalToken::transferFrom(0x83eC…, 0xA6dc1F…, 20000000000000000000000)
  │   │   ├─ emit Approval(owner: 0x83eC…, spender: 0xF4a21A…, value: 0)
  │   │   ├─ emit Transfer(from: 0x83eC…, to: 0xA6dc1F…, value: 20000000000000000000000)
  │   ...
  └─ …
```

This trace shows:
- The helper contract reads the victim’s PT `balanceOf` and `allowance` to LeverageUp.
- LeverageUp (`0xf4a21A…`) is called with parameters that select `SwapMethod.GenericRoute` and `router = 0xa6dc1f…`.
- Inside DexSwap `_swapGenericRoute`, PT is force-approved for router `0xa6dc1f…`.
- The router executes calldata that calls `PendlePrincipalToken.transferFrom(0x83eC…, 0xA6dc1F…, 20000000000000000000000)`.

The balance change for this tx is encoded in:
- `artifacts/root_cause/seed/1/0xc7477d6a…/balance_diff.json`
- `artifacts/root_cause/data_collector/iter_2/tx/1/0xc7477d6a…/state_diff_0x23e60d….json`
- `artifacts/root_cause/data_collector/iter_2/tx/1/0xc7477d6a…/state_diff_0xa6dc1f….json`

4. **Withdrawal and profit realization**
   - Tx `0x23ccb2f1dc6700c2f077bb400fb84dbf4d786390fe8fba6a5e4e1c1864221ace` (block `23145790`).
   - Type: adversary-crafted.
   - From attacker EOA `0xa7e9b9…` to helper `0xa6dc1f…`.
   - Calls a withdraw function (e.g., `withdrawERC20`) on the helper to transfer the stolen PT to the attacker EOA.

The ERC20 balance changes for PT in this withdrawal tx are:

```json
// Withdrawal tx 0x23ccb2f1… balance diff (excerpt)
// artifacts/root_cause/data_collector/iter_3/tx/1/0x23ccb2f1…/balance_diff.json
{
  "erc20_balance_deltas": [
    {
      "token": "0x23e60d1488525bf4685f53b3aa8e676c30321066",
      "holder": "0xa6dc1fc33c03513a762cdf2810f163b9b0fd3a71",
      "before": "20000000000000000000000",
      "after": "0",
      "delta": "-20000000000000000000000",
      "contract_name": "PendlePrincipalToken"
    },
    {
      "token": "0x23e60d1488525bf4685f53b3aa8e676c30321066",
      "holder": "0xa7e9b982b0e19a399bc737ca5346ef0ef12046da",
      "before": "0",
      "after": "20000000000000000000000",
      "delta": "20000000000000000000000",
      "contract_name": "PendlePrincipalToken"
    }
  ]
}
```

The adversary lifecycle stages in the analysis align with this sequence:
- Helper deployment and initialization (txs `0x17846ac…`, `0xda91d1…`).
- GenericRoute-driven PT theft (tx `0xc7477d6a…`).
- Withdrawal and profit realization (tx `0x23ccb2f1…`), plus downstream liquidation or swap txs (`0x9baa60de…`, `0xa928703a…`, `0xa994b34a…`).

### Success predicate

The success predicate is defined as a profit in PT units for the adversary:
- Reference asset: `PendlePrincipalToken(0x23e60d1…)`.
- Adversary address: `0xa7e9b982b0e19a399bc737ca5346ef0ef12046da`.
- Fees paid in PT: `0`.
- Value before in PT: `0`.
- Value after in PT: `20000e18`.
- Value delta in PT: `+20000e18`.

This is supported by:
- Exploit tx `0xc7477d6a…` moving 20,000e18 PT from victim `0x83eccb…` to helper `0xa6dc1f…`.
- Withdrawal tx `0x23ccb2f1…` moving 20,000e18 PT from helper `0xa6dc1f…` to attacker EOA `0xa7e9b9…`.
- Only ETH gas is spent by the attacker; no PT leaves attacker-controlled addresses in these steps.

Therefore the adversary’s PT-denominated portfolio change is strictly positive, satisfying the profit-based success predicate.

## Adversary Flow Analysis

### Strategy summary

The adversary’s strategy is:
1. Deploy a helper contract `0xa6dc1f…` that:
   - Implements the ISize-like interface required by LeverageUp’s `size` parameter.
   - Also acts as a router for DexSwap.GenericRoute.
2. Initialize the helper so that it can be used as both the Size market and router in LeverageUp calls.
3. Submit the exploit tx `0xc7477d6a…` that:
   - Calls the helper with parameters causing it to invoke `LeverageUp.leverageUpWithSwap(size = helper, swapParams.method = GenericRoute, router = helper, route.data = calldata that calls PT.transferFrom)`.
   - Causes DexSwap `_swapGenericRoute` to force-approve the helper for PT using LeverageUp’s PT balance derived from the victim’s allowance.
   - Executes attacker-specified calldata in the helper that calls `PendlePrincipalToken.transferFrom(victim, helper, 20000e18)`.
4. Submit the withdrawal tx `0x23ccb2f1…` that:
   - Calls a withdraw function on the helper to transfer the 20,000e18 PT to the attacker EOA.
5. Optionally perform liquidation or swap transactions to convert PT into other assets; these are not necessary to satisfy the PT-denominated profit predicate.

### Adversary-related accounts

**Adversary cluster**
- `0xa7e9b982b0e19a399bc737ca5346ef0ef12046da` (EOA, contract flag false)
  - Sender of helper deployment tx `0x17846ac…`, helper init tx `0xda91d1…`, exploit tx `0xc7477d6a…`, withdraw tx `0x23ccb2f1…`, and subsequent liquidation/swap txs.
  - Final holder of the stolen 20,000e18 PT after withdrawal (per `0x23ccb2f1…` balance diff).
- `0xa6dc1fc33c03513a762cdf2810f163b9b0fd3a71` (contract, EOA flag false)
  - Deployed by attacker EOA in tx `0x17846ac…`.
  - Used as the `size` and `router` parameter in the exploit tx `0xc7477d6a…`.
  - Temporarily holds the stolen PT before sending it to the attacker in tx `0x23ccb2f1…`.

**Victim and key protocol contracts**
- Victim EOA user:
  - `0x83eccb05386b2d10d05e1baea8ac89b5b7ea8290` (Ethereum mainnet, is_verified = false).
- Size market:
  - `0x1b367622b8c516adc4f903bb6148446bb1f23ae3` (Ethereum mainnet, is_verified = true).
- LeverageUp zap + DexSwap:
  - `0xf4a21ac7e51d17a0e1c8b59f7a98bb7a97806f14` (Ethereum mainnet, is_verified = true).
- Pendle router:
  - `0x888888888889758f76e7103c6cbf23abbf58f946` (Ethereum mainnet, is_verified = true).
- PendlePrincipalToken:
  - `0x23e60d1488525bf4685f53b3aa8e676c30321066` (Ethereum mainnet, is_verified = true).

### Lifecycle stages

1. **Helper deployment and initialization**
   - Txs:
     - `0x17846acccd832432dba32bf1008797377324a1bd8bd8ef8e52ec8171afc99a81` (deploy helper).
     - `0xda91d19080f799f609eb5c513439945afce65601caa066e32098efd32fbeb1b9` (initialize helper).
   - Effect:
     - Attacker EOA deploys `0xa6dc1f…` and configures it so that LeverageUp accepts it as a valid Size market and router.
   - Evidence:
     - `artifacts/root_cause/data_collector/iter_3/tx/1/0x17846ac…/*`
     - `artifacts/root_cause/data_collector/iter_3/tx/1/0xda91d1…/*`

2. **GenericRoute-driven PT theft**
   - Tx:
     - `0xc7477d6a5c63b04d37a39038a28b4cbaa06beb167e390d55ad4a421dbe4067f8` (exploit).
   - Effect:
     - Helper `0xa6dc1f…`, invoked by attacker EOA, calls `LeverageUp.leverageUpWithSwap` with itself as both Size market and router.
     - DexSwap `_swapGenericRoute` force-approves `0xa6dc1f…` for PT and executes a malicious GenericRoute that calls `PendlePrincipalToken.transferFrom(victim, helper, 20000e18)`.
     - 20,000e18 PT moves from victim EOA to helper in a single transaction.
   - Evidence:
     - `artifacts/root_cause/seed/1/0xc7477d6a…/trace.cast.log`
     - `artifacts/root_cause/data_collector/iter_2/tx/1/0xc7477d6a…/trace_callTracer.json`
     - Associated state diffs for `0xa6dc1f…` and `0x23e60d…`.
     - PT balance movement in `.../balance_diff.json`.

3. **Withdrawal and profit realization**
   - Tx:
     - `0x23ccb2f1dc6700c2f077bb400fb84dbf4d786390fe8fba6a5e4e1c1864221ace` (withdraw).
   - Effect:
     - Helper `0xa6dc1f…` sends the 20,000e18 PT to attacker EOA `0xa7e9b9…`, placing the stolen PT directly under adversary control.
     - Later transactions (`0x9baa60de…`, `0xa928703a…`, `0xa994b34a…`) may liquidate PT into other assets but are not required to satisfy the profit predicate.
   - Evidence:
     - `artifacts/root_cause/data_collector/iter_3/tx/1/0x23ccb2f1…/trace_callTracer.json`
     - `artifacts/root_cause/data_collector/iter_3/tx/1/0x23ccb2f1…/balance_diff.json`
     - Downstream swap traces in:
       - `artifacts/root_cause/data_collector/iter_4/tx/1/0x9baa60de…/*`
       - `artifacts/root_cause/data_collector/iter_4/tx/1/0xa928703a…/*`
       - `artifacts/root_cause/data_collector/iter_4/tx/1/0xa994b34a…/*`

## Impact & Losses

The primary asset loss in this incident is:
- **20,000e18 PendlePrincipalToken (PT)** transferred from victim EOA `0x83eccb05386b2d10d05e1baea8ac89b5b7ea8290` to attacker EOA `0xa7e9b982b0e19a399bc737ca5346ef0ef12046da` via helper contract `0xa6dc1fc33c03513a762cdf2810f163b9b0fd3a71` in:
  - Exploit tx `0xc7477d6a…` (victim → helper).
  - Withdrawal tx `0x23ccb2f1…` (helper → attacker).

Impact summary:
- The attacker gains direct control over 20,000e18 PT that previously belonged to the victim.
- The PT-denominated portfolio of the attacker increases by 20,000e18 units after accounting for gas, verifying a strictly positive profit.
- The exploit path depends only on:
  - Public allowances and balances.
  - Publicly deployed contracts (LeverageUp, DexSwap, Size market, PT, Pendle router).
  - On-chain transaction ordering consistent with public mempool rules.
- Any user who grants a PT allowance to LeverageUp while GenericRoute is enabled is exposed to the same theft pattern, until mitigations such as:
  - Disabling GenericRoute.
  - Constraining router addresses to a vetted registry.
  - Avoiding force-approving arbitrary routers for user tokens.

## References

The following on-disk artifacts support the analysis and conclusions:

1. **Seed exploit tx metadata, trace, and balance diff**
   - `artifacts/root_cause/seed/1/0xc7477d6a5c63b04d37a39038a28b4cbaa06beb167e390d55ad4a421dbe4067f8/`
   - Contains Foundry `trace.cast.log`, metadata, and `balance_diff.json` for the core exploit tx.

2. **LeverageUp + DexSwap source tree**
   - `artifacts/root_cause/data_collector/iter_1/contract/1/0xf4a21ac7e51d17a0e1c8b59f7a98bb7a97806f14/source`
   - Includes `src/zaps/LeverageUp.sol` and `src/liquidator/DexSwap.sol` defining `leverageUpWithSwap` and `_swapGenericRoute`.

3. **PendlePrincipalToken verified source**
   - `artifacts/root_cause/seed/1/0x23e60d1488525bf4685f53b3aa8e676c30321066/src/pendle/contracts/core/YieldContracts/PendlePrincipalToken.sol`
   - Defines PT’s ERC20-like semantics used in the exploit.

4. **Victim PT acquisition traces and balance diffs**
   - `artifacts/root_cause/data_collector/iter_5/tx/1/0x38e14a04e5336d02c0484ed979a493feb8bce29de5799ee264aed1f75230187a/`

5. **Size leveraged position multicall trace and balance diff**
   - `artifacts/root_cause/data_collector/iter_4/tx/1/0xbc07ccce7974a6232d87bc7f812eaa19919c8ac4c3ec5b80eae337961923ec38/`

6. **Helper deployment, init, and withdraw traces**
   - `artifacts/root_cause/data_collector/iter_3/tx/1/`
   - Includes traces for helper deployment (`0x17846ac…`), initialization (`0xda91d1…`), and withdrawal (`0x23ccb2f1…`).

