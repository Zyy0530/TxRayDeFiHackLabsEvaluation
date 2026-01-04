## Incident Overview TL;DR

On Ethereum mainnet block 23,504,546, the attacker EOA `0x1aaade3e9062d124b7deb0ed6ddc7055efa7354d` deployed a helper contract at `0xB8e0A4758Df2954063Ca4ba3d094f2d6EdA9B993` and, within the same transaction (`0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6`), used it to call two Abracadabra PrivilegedCauldronV4-based MIM lending pools with a crafted `cook([5,0],[0,0],datas)` sequence. This sequence recorded large MIM-denominated debt for the helper contract while it held zero collateral, withdrew MIM from the shared DegenBox vault, swapped that MIM through Curve and Uniswap into WETH/ETH, and self-destructed the helper to pay ETH back to the attacker EOA. The protocol was left with uncompensated MIM debt and a persistent solvency gap.

The root cause is a logic bug in the CauldronV4 `cook` / `_additionalCookAction` flow: a trailing unknown/custom cook action resets `CookStatus.needsSolvencyCheck` and prevents the final `_isSolvent` check from running. This allows any unprivileged caller to perform `ACTION_BORROW` (ID 5) followed by an unknown action ID (such as `0`) and end a cook sequence with positive debt and zero collateral without reverting, enabling borrow-without-collateral against publicly accessible Cauldrons.

## Key Background

Abracadabra’s MIM Cauldrons are lending markets backed by a shared MIM DegenBox vault at `0xd96f48665a1410c0cd669a88898eca36b9fc2cce`. Each Cauldron tracks users’ `userBorrowPart` (debt) and `userCollateralShare` (collateral) and is expected to enforce solvency via a final `_isSolvent` check inside `cook()`. The Cauldron clones exploited in this incident are PrivilegedCauldronV4 instances at:

- `0x6bcd99D6009ac1666b58CB68fB4A50385945CDA2`
- `0xC6D3b82f9774Db8F92095b5e4352a8bB8B0dC20d`

Both clones share a common implementation at `0xA9B386dcd598acf3cE53460631FeEFbBa730cBf3`, whose verified source includes `CauldronV4` and `PrivilegedCauldronV4`. In this design, the `cook` entrypoint sequences high-level actions (such as add collateral, borrow, repay) and uses a `CookStatus` struct with a `needsSolvencyCheck` flag plus `updateExchangeRate()` / `_isSolvent()` to ensure borrowers remain overcollateralized after any sequence of actions.

To support protocol-specific extensions, `CauldronV4` defines a virtual `_additionalCookAction` hook that is invoked for unrecognized action IDs. The default implementation returns an all-zero `CookStatus` struct, and `cook` unconditionally assigns this return value back to `status`. As a result, if a borrow action is followed by an unknown action ID that routes into `_additionalCookAction`, the final solvency check can be silently disabled.

The targeted Cauldrons and the DegenBox vault are permissionless to interact with for generic EOAs and arbitrary contracts: `cook` is callable without whitelisting, and access-control probing confirms that the attacker’s addresses are not blocked and that borrow limits do not prevent the observed borrow amounts. This makes the bug an ACT opportunity: any searcher capable of constructing equivalent calldata at or before block 23,504,546 could have executed the same strategy.

## Vulnerability Analysis

The core invariant Abracadabra intends to enforce is that any user with nonzero MIM debt must be solvent relative to their posted collateral at the end of a `cook` sequence. In `CauldronV4`, this is implemented by setting `status.needsSolvencyCheck = true` when actions such as `ACTION_BORROW` or `ACTION_REMOVE_COLLATERAL` are executed and, after all actions have run, calling `updateExchangeRate()` followed by a `_isSolvent(msg.sender, _exchangeRate)` check if `needsSolvencyCheck` is still true. `_isSolvent` itself enforces that users with `userBorrowPart > 0` and `userCollateralShare == 0` are insolvent and should cause the transaction to revert.

However, `cook` also supports a generic extension mechanism via `_additionalCookAction` for unrecognized action IDs. The default implementation of `_additionalCookAction` in `CauldronV4` returns a zero-initialized `CookStatus`, and `cook` overwrites its local `status` with this return value. This design implicitly trusts extension hooks to preserve critical invariants such as `needsSolvencyCheck` but does not enforce any constraint on the returned status.

In the incident configuration, the attacker exploited this by using a trailing unknown action ID (`0`) that falls into the `_additionalCookAction` path. After `ACTION_BORROW` sets `status.needsSolvencyCheck = true`, the subsequent unknown action causes `cook` to assign the zeroed `CookStatus` returned by `_additionalCookAction` back to `status`, thereby clearing `needsSolvencyCheck`. The final `if (status.needsSolvencyCheck) { ... _isSolvent(...) ... }` block never executes, so the normal solvency enforcement is skipped.

This is a deterministic logic bug in the protocol implementation, not a configuration or parameter tuning issue. It violates standard security principles for financial smart contracts, including:

- Always enforcing solvency or collateralization invariants after state-changing debt operations.
- Treating unknown or extension actions conservatively (reverting or treating them as no-ops) rather than trusting them to preserve core safety checks.
- Avoiding patterns where extension hooks can reset or bypass critical security flags without explicit validation in the core contract.

## Detailed Root Cause Analysis

The relevant `CauldronV4` logic can be summarized by the following excerpt from the verified source at implementation `0xA9B386dcd598acf3cE53460631FeEFbBa730cBf3`:

```solidity
struct CookStatus {
    bool needsSolvencyCheck;
    bool hasAccrued;
}

function _additionalCookAction(
    uint8 action,
    CookStatus memory,
    uint256 value,
    bytes memory data,
    uint256 value1,
    uint256 value2
) internal virtual returns (bytes memory, uint8, CookStatus memory) {}

function cook(
    uint8[] calldata actions,
    uint256[] calldata values,
    bytes[] calldata datas
) external payable returns (uint256 value1, uint256 value2) {
    CookStatus memory status;

    for (uint256 i = 0; i < actions.length; i++) {
        uint8 action = actions[i];
        if (!status.hasAccrued && action < 10) {
            accrue();
            status.hasAccrued = true;
        }
        if (action == ACTION_REMOVE_COLLATERAL) {
            ...
            status.needsSolvencyCheck = true;
        } else if (action == ACTION_BORROW) {
            ...
            (value1, value2) = _borrow(to, _num(amount, value1, value2));
            status.needsSolvencyCheck = true;
        } else {
            (bytes memory returnData, uint8 returnValues, CookStatus memory returnStatus) =
                _additionalCookAction(action, status, values[i], datas[i], value1, value2);
            status = returnStatus;
            ...
        }
    }

    if (status.needsSolvencyCheck) {
        (, uint256 _exchangeRate) = updateExchangeRate();
        require(_isSolvent(msg.sender, _exchangeRate), "Cauldron: user insolvent");
    }
}
```

By default, `_additionalCookAction` returns a zeroed `CookStatus`, so any unrecognized action ID that reaches this branch will reset `status.needsSolvencyCheck` to `false` unless the override implementation takes care to preserve it. The attacker’s strategy relied on this default behavior with no custom override.

The `_isSolvent` check that should protect against borrow-without-collateral is implemented as:

```solidity
function _isSolvent(address user, uint256 _exchangeRate) internal view returns (bool) {
    uint256 borrowPart = userBorrowPart[user];
    if (borrowPart == 0) return true;
    uint256 collateralShare = userCollateralShare[user];
    if (collateralShare == 0) return false;
    ...
}
```

Under normal circumstances, a user who has just borrowed MIM without posting any collateral would end `cook` with `userBorrowPart[user] > 0` and `userCollateralShare[user] == 0`, causing `_isSolvent` to return `false` and the transaction to revert. In the exploit, this invariant is broken because `status.needsSolvencyCheck` is reset to `false` by the trailing unknown action, so `_isSolvent` is never called.

On-chain state snapshots for clone `0x6bcd99D6009ac1666b58CB68fB4A50385945CDA2` around the incident block show the effect of this bug on the attacker’s helper contract `0xB8e0A4758Df2954063Ca4ba3d094f2d6EdA9B993`:

```json
{
  "23504545": {
    "userBorrowPart": { "result": "0x0" },
    "userCollateralShare": { "result": "0x0" },
    "totalBorrow": { "result": "0x...20e81646e2762881a0fa0000...1a4f7a7b3e7dc03deb04" }
  },
  "23504546": {
    "userBorrowPart": { "result": "0x...00000e773cbd816447bb39c6" },
    "userCollateralShare": { "result": "0x0" },
    "totalBorrow": { "result": "0x...33022c08a55b9effd4470000...28c6b738bfe207f924ca" }
  }
}
```

At block 23,504,545, the helper has zero debt and zero collateral. After the incident transaction in block 23,504,546, `userBorrowPart` for the helper becomes nonzero while `userCollateralShare` remains zero, and `totalBorrow.elastic` increases, indicating that new MIM-denominated debt has been recorded against an account with no collateral. No liquidation or revert occurs, confirming that the final solvency check has been skipped.

The Foundry `cast run -vvvvv` trace for the seed transaction further shows the DegenBox withdraw and subsequent MIM routing:

```bash
... DegenBox::withdraw(magicInternetMoney, 0xd96f48665a1410c0cd669a88898eca36b9fc2cce, 0xB8e0A4758Df2954063Ca4ba3d094f2d6EdA9B993, 1793766133547645084844120, 0) ...
... CurveRouter::exchange(magicInternetMoney -> Curve LP -> stablecoins) ...
... UniswapV2Pair / other pools swapping into WETH and unwrapping to ETH ...
... SELFDESTRUCT(0xB8e0A4758Df2954063Ca4ba3d094f2d6EdA9B993 -> 0x1aaade3e9062d124b7deb0ed6ddc7055efa7354d) ...
```

Together, the verified source, view snapshots, and detailed trace confirm that the protocol’s intended solvency invariant is not enforced in this transaction and that the attacker was able to create unsecured MIM debt and extract value without collateral.

## Adversary Flow Analysis

The adversary’s strategy unfolds entirely within the seed transaction `0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6` on Ethereum mainnet, and can be decomposed into three lifecycle stages:

1. **Adversary contract deployment and setup**
   - The attacker EOA `0x1aaade3e9062d124b7deb0ed6ddc7055efa7354d` sends a type-2 EIP-1559 transaction that deploys a helper contract at `0xB8e0A4758Df2954063Ca4ba3d094f2d6EdA9B993`.
   - Deployment bytecode and constructor parameters wire the helper to interact with the two PrivilegedCauldronV4 clones, the DegenBox vault, and relevant AMMs (Curve and Uniswap) within the same transaction.

2. **Unauthorized MIM borrows without collateral**
   - From the helper contract, the adversary calls each PrivilegedCauldronV4 clone at `0x6bcd99D6009ac1666b58CB68fB4A50385945CDA2` and `0xC6D3b82f9774Db8F92095b5e4352a8bB8B0dC20d` using:
     - `actions = [5, 0]` where `5` is `ACTION_BORROW` and `0` is an unknown/custom action ID.
     - `values = [0, 0]`.
     - `datas[0]` encoding a borrow of MIM to the helper contract; `datas[1]` empty.
   - In each `cook` call:
     - The first iteration executes `ACTION_BORROW`, increasing `userBorrowPart[helper]` and `totalBorrow`, and sets `status.needsSolvencyCheck = true`.
     - The second iteration uses action `0`, which is not mapped to any defined `ACTION_*` constant, so `cook` dispatches to `_additionalCookAction`. The default implementation returns an all-zero `CookStatus`, and `cook` assigns this back to `status`, clearing `needsSolvencyCheck`.
     - Because `status.needsSolvencyCheck` is now `false`, `cook` does not run `_isSolvent` at the end, and the new debt is recorded even though `userCollateralShare[helper] == 0`.
   - View snapshots around blocks 23,504,545–23,504,547 and the callTracer trace show that, after this stage, both Cauldrons record nonzero MIM-denominated debt for the helper contract while its collateral remains zero.

3. **MIM withdrawal, swap to ETH, and profit realization**
   - Using the unsecured debt created in both Cauldrons, the helper contract calls DegenBox to withdraw MIM from the shared vault at `0xd96f48665a1410c0cd669a88898eca36b9fc2cce`.
   - ERC20 balance diffs for `MagicInternetMoneyV1` (`0x99d8a9c45b2eca8864373a26d1459e3dff1e17f3`) show:
     - DegenBox vault balance decreasing by `1,793,766,133,547,645,084,844,120` MIM.
     - Intermediate aggregator and pool addresses receiving and then forwarding this MIM into liquidity pools.
   - The helper routes MIM through Curve and Uniswap pools into WETH and then unwraps WETH into native ETH.
   - Finally, the helper self-destructs, sending the accumulated ETH to the attacker EOA `0x1aaade3e9062d124b7deb0ed6ddc7055efa7354d`, and disappears with its unsecured debt left on the Cauldrons.

The key adversary-related accounts and contracts are:

- **Attacker EOA:** `0x1aaade3e9062d124b7deb0ed6ddc7055efa7354d` (recipient of final ETH profit).
- **Helper contract:** `0xB8e0A4758Df2954063Ca4ba3d094f2d6EdA9B993` (borrower, DegenBox withdrawer, swap executor, self-destruct target).
- **PrivilegedCauldronV4 clones (victims):**
  - `0x6bcd99D6009ac1666b58CB68fB4A50385945CDA2`
  - `0xC6D3b82f9774Db8F92095b5e4352a8bB8B0dC20d`
- **MIM DegenBox vault:** `0xd96f48665a1410c0cd669a88898eca36b9fc2cce`.

The sequence is fully realizable by any unprivileged adversary using only public chain state and calldata, and does not depend on private keys beyond the attacker’s own EOA.

## Impact & Losses

On the asset side, the exploit results in a large, uncompensated outflow of MIM from Abracadabra’s DegenBox vault. ERC20 balance diffs for `MagicInternetMoneyV1` show that, during the incident transaction:

- The DegenBox vault at `0xd96f48665a1410c0cd669a88898eca36b9fc2cce` loses exactly `1,793,766,133,547,645,084,844,120` MIM.
- Corresponding increases in intermediary and pool balances match the MIM being routed through Curve and Uniswap as part of the attacker’s swap path.

On the liability side, Cauldron view snapshots show that `totalBorrow.elastic` increases on both exploited Cauldrons and that `userBorrowPart[helper]` becomes nonzero while `userCollateralShare[helper]` remains zero. This means the protocol has recorded significant new MIM-denominated debt owed by the helper contract without collateral, and there is no on-chain mechanism within this transaction to recover the MIM drained from the DegenBox vault.

From the attacker’s perspective, native balance diffs and gas accounting provide a precise ETH profit:

- Attacker EOA ETH balance before the seed transaction: `173,504,352,583,541,000` wei.
- Attacker EOA ETH balance after the seed transaction: `395,232,980,108,896,905,054` wei.
- Gas used by the transaction: `2,096,704` units, with an effective gas price of `132,247,681` wei, for a fee of `277,284,241,743,424` wei.
- Net ETH gain (after gas): `395,059,475,756,313,364,054` wei.

These numbers are derived directly from the seed transaction’s metadata, balance diffs, and call traces. Taken together, they show that Abracadabra suffers a concrete loss of `1,793,766,133,547,645,084,844,120` MIM backing for the affected Cauldrons, while the attacker EOA realizes roughly `395.059` ETH in profit after fees.

## References

The following artifacts provide the primary evidence for the analysis above:

- **Seed transaction metadata and traces (tx `0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6`):**
  - `artifacts/root_cause/seed/1/0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6/metadata.json`
  - `artifacts/root_cause/seed/1/0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6/trace.cast.log`
  - `artifacts/root_cause/seed/1/0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6/balance_diff.json`
  - `artifacts/root_cause/data_collector/iter_1/tx/1/0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6/balance_diff_full.json`
  - `artifacts/root_cause/data_collector/iter_3/tx/1/0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6/debug_trace_callTracer.json`
  - `artifacts/root_cause/data_collector/iter_4/tx/1/0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6/trace.cast.log`

- **Cauldron implementation and clones:**
  - Verified `CauldronV4` and `PrivilegedCauldronV4` source and disassembly for implementation `0xA9B386dcd598acf3cE53460631FeEFbBa730cBf3`:
    - `artifacts/root_cause/data_collector/iter_4/contract/1/0xA9B386dcd598acf3cE53460631FeEFbBa730cBf3/source/src/cauldrons/CauldronV4.sol`
    - `artifacts/root_cause/data_collector/iter_4/contract/1/0xA9B386dcd598acf3cE53460631FeEFbBa730cBf3/source/src/cauldrons/PrivilegedCauldronV4.sol`
  - Access-control and configuration probes for the exploited clones:
    - `artifacts/root_cause/data_collector/iter_4/contract/1/0x6bcd99D6009ac1666b58CB68fB4A50385945CDA2/meta/access_control_probe.json`
    - `artifacts/root_cause/data_collector/iter_4/contract/1/0xC6D3b82f9774Db8F92095b5e4352a8bB8B0dC20d/meta/access_control_probe.json`

- **Cauldron state snapshots around the incident block:**
  - `artifacts/root_cause/data_collector/iter_3/contract/1/0x6bcd99D6009ac1666b58CB68fB4A50385945CDA2/view_snapshots_23504545_23504547.json`
  - `artifacts/root_cause/data_collector/iter_3/contract/1/0xC6D3b82f9774Db8F92095b5e4352a8bB8B0dC20d/view_snapshots_23504545_23504547.json`

- **Balance and state diffs for MIM and related tokens:**
  - `artifacts/root_cause/seed/1/0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6/balance_diff.json`
  - `artifacts/root_cause/data_collector/iter_1/contract/1/0x5a6a4d54456819380173272a5e8e9b9904bdf41b/source/`

These references, together with the standardized transaction and raw trace data in the incident directory, are sufficient to independently reproduce the attack flow, validate the solvency-check bypass, and confirm the reported profit and loss figures.

