## Incident Overview TL;DR

On Base (chainid 8453, block 23514451), attacker EOA `0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025` deployed a custom strategy contract `0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1` and paired WETH with an adversary-created ERC20 token `0xd3c8d0cd07Ade92df2d88752D36b80498cA12788` in a new Clober v2 Rebalancer pool. Using a 267.4 WETH flash loan from Morpho `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb`, the strategy opened and funded the pool and then executed a reentrant `burnHook` call back into `Rebalancer::burn` on the same LP position. This double-counted the pool’s reserves and allowed the attacker to withdraw `267.4 WETH + 267.4 token` and then an additional `133.7 WETH + 133.7 token`, draining `133.7 WETH` from Rebalancer’s pre-existing WETH balance. After repaying the flash loan and calling `WETH9::withdraw`, the attacker realized a net profit of exactly `133.540501283062363385 ETH` on their EOA.

At a high level, the root cause is that Rebalancer’s internal `_burn` flow calls an untrusted strategy `burnHook` before updating reserves and transferring assets, allowing a malicious strategy to re-enter `burn()` on the same key and `burnAmount` under stale accounting and withdraw more WETH than the LP position should entitle it to.

## Key Background

Clober v2 Rebalancer manages two-sided liquidity pools over an external BookManager, tracking `reserveA`/`reserveB` and LP token supply. For each pool it stores a strategy address implementing hooks such as `mintHook`, `burnHook`, and `rebalanceHook`. These hooks are untrusted: any strategy contract address can be registered via `Rebalancer.open()` as long as it is non-zero and the book pair is consistent; there is no whitelist or privileged registry.

Liquidity providers interact with Rebalancer through `mint` and `burn` flows that in turn interact with BookManager. For burns, Rebalancer exposes a public

```solidity
function burn(bytes32 key, uint256 amount, uint256 minAmountA, uint256 minAmountB)
    external
    returns (uint256 withdrawalA, uint256 withdrawalB)
{
    (withdrawalA, withdrawalB) = abi.decode(
        bookManager.lock(address(this), abi.encodeWithSelector(this._burn.selector, key, msg.sender, amount)),
        (uint256, uint256)
    );
    if (withdrawalA < minAmountA || withdrawalB < minAmountB) revert Slippage();
}
```

which delegates core accounting to an internal `_burn(bytes32 key, address user, uint256 burnAmount)` function. `_burn` clears orders via BookManager, computes withdrawal amounts from `pool.reserveA/B` and total LP supply, and then settles with BookManager before transferring tokens to the user. During this process it also invokes the strategy’s `burnHook`, giving the strategy arbitrary execution during the burn flow.

Morpho on Base provides permissionless WETH flash loans via `flashLoan`, and WETH9 on Base `0x4200000000000000000000000000000000000006` supports `withdraw()` to convert WETH into native ETH. These building blocks allow an attacker to fund and unwind the exploit in a single transaction without upfront capital: borrow WETH, manipulate a Rebalancer pool using a malicious strategy and token, repay the loan, and cash out WETH to ETH.

## Vulnerability Analysis & Root Cause Summary

The ACT root cause is a reentrancy and accounting bug in `Rebalancer::_burn`. In the verified Rebalancer source

```solidity
function _burn(bytes32 key, address user, uint256 burnAmount)
    public
    selfOnly
    returns (uint256 withdrawalA, uint256 withdrawalB)
{
    Pool storage pool = _pools[key];
    uint256 supply = totalSupply[uint256(key)];

    (uint256 canceledAmountA, uint256 canceledAmountB, uint256 claimedAmountA, uint256 claimedAmountB) =
        _clearPool(key, pool, burnAmount, supply);

    uint256 reserveA = pool.reserveA;
    uint256 reserveB = pool.reserveB;

    withdrawalA = (reserveA + claimedAmountA) * burnAmount / supply + canceledAmountA;
    withdrawalB = (reserveB + claimedAmountB) * burnAmount / supply + canceledAmountB;

    _burn(user, uint256(key), burnAmount);
    pool.strategy.burnHook(msg.sender, key, burnAmount, supply);
    emit Burn(user, key, withdrawalA, withdrawalB, burnAmount);

    IBookManager.BookKey memory bookKeyA = bookManager.getBookKey(pool.bookIdA);

    pool.reserveA = _settleCurrency(bookKeyA.quote, reserveA) - withdrawalA;
    pool.reserveB = _settleCurrency(bookKeyA.base, reserveB) - withdrawalB;

    if (withdrawalA > 0) {
        bookKeyA.quote.transfer(user, withdrawalA);
    }
    if (withdrawalB > 0) {
        bookKeyA.base.transfer(user, withdrawalB);
    }
}
```

the function:

- Reads the current `Pool` and total LP `supply`.
- Calls `_clearPool` to cancel and claim existing orders in BookManager, returning `canceledAmount*` and `claimedAmount*`.
- Reads `reserveA` and `reserveB` from storage and computes `withdrawalA/B` based on these reserves, the claimed/canceled liquidity, and `burnAmount / supply`.
- **Before** updating reserves or performing token transfers, it calls the untrusted strategy hook `pool.strategy.burnHook(msg.sender, key, burnAmount, supply)`.
- Only **after** the hook returns does it fetch the book key, settle with BookManager via `_settleCurrency`, update `pool.reserveA/B`, and transfer `withdrawalA/B` to the user.

The critical design bug is that `burnHook` is invoked while the pool still reports **original** reserves and total supply, and before any of the computed withdrawals or currency deltas are applied. Since strategies are untrusted and can call back into Rebalancer, this ordering allows a malicious strategy to re-enter `Rebalancer::burn` on the same `key` and `burnAmount`, causing multiple `_burn` executions to compute `withdrawalA/B` from the same pre-exploit reserves and LP supply. Each nested `_burn` then proceeds to withdraw funds after the hook returns, effectively double-counting the pool’s reserves.

This violates standard reentrancy-safety and invariant-preservation principles: external hooks are called before state is updated, and untrusted strategies are allowed to perform arbitrary logic—including re-entering `burn`—while accounting invariants (reserves and supply) are assumed to remain stable.

## Detailed Root Cause Analysis

### Vulnerable Components

- **Rebalancer::_burn**  
  `Rebalancer::_burn(bytes32 key, address user, uint256 burnAmount)` (verified source at `0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895`) is the core vulnerable function. It:
  - Uses `totalSupply[uint256(key)]` as `supply` for pro-rata calculations.
  - Clears on-book liquidity via `_clearPool`, which emits `Claim` and `Cancel` events and may adjust claimed/canceled amounts.
  - Computes `withdrawalA` and `withdrawalB` from `(reserveX + claimedX) * burnAmount / supply + canceledX` using the **pre-burn** `reserveA/B` values.
  - Calls `_burn` on the LP token and then calls `pool.strategy.burnHook(msg.sender, key, burnAmount, supply)` **before** any reserve updates or token transfers.
  - Only afterward settles with BookManager through `_settleCurrency` and updates `pool.reserveA/B`, then transfers `withdrawalA/B` to `user`.

- **IStrategy.burnHook**  
  The interface `IStrategy` (in the same verified source tree) defines:

  ```solidity
  function burnHook(address caller, bytes32 key, uint256 burnAmount, uint256 supply) external;
  ```

  with no restrictions on what the strategy may do. Strategies are fully untrusted and can make arbitrary calls, including re-entering Rebalancer functions.

- **Adversary Strategy Implementation**  
  The adversary’s strategy contract at `0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1` is available as decompiled code. Its `burnHook` is decompiled as:

  ```solidity
  /// @custom:selector    0xdb7c74b6
  /// @custom:signature   burnHook(address arg0, bytes32 arg1, uint256 arg2, uint256 arg3) public
  function burnHook(address arg0, bytes32 arg1, uint256 arg2, uint256 arg3) public {
      require(arg0 == (address(arg0)));
      require(0x6a0b87d6b74f7d5c92722f6a11714dbeda9f3895 == msg.sender);
      var_a = 0xfdd58e00000000000000000000000000000000000000000000000000000000;
      address var_b = address(this);
      uint256 var_c = arg1;
      (bool success, bytes memory ret0) = address(0x6a0b87d6b74f7d5c92722f6a11714dbeda9f3895).Unresolved_00fdd58e(var_b); // staticcall
      ...
      var_e = 0x0a31b95300000000000000000000000000000000000000000000000000000000;
      var_c = arg1;
      uint256 var_f = arg2;
      uint256 var_g = 0;
      uint256 var_h = 0;
      (bool success, bytes memory ret0) = address(0x6a0b87d6b74f7d5c92722f6a11714dbeda9f3895).{ value: var_g ether }Unresolved_0a31b953(var_c); // call
      ...
  }
  ```

  This shows that when `burnHook` is invoked by Rebalancer (`msg.sender == 0x6A0b87D6...`), it calls back into the same Rebalancer contract (via `Unresolved_0a31b953`, which the trace and interface correlate with `Rebalancer::burn`). The parameters include the same `key` (`arg1`) and `burnAmount` (`arg2`), matching the reentrancy description.

- **Adversary Token Implementation**  
  The adversary token at `0xd3c8d0cd07Ade92df2d88752D36b80498cA12788` is a decompiled ERC20-like contract used as the paired asset in the malicious pool. Its behavior is standard enough that it does not materially affect the exploit mechanism; it simply serves as the second leg of the WETH–token pool.

### Exploit Conditions

For the ACT opportunity to be realizable, the following on-chain conditions must hold:

1. **Permissionless Strategy Registration**  
   `Rebalancer.open()` permits any non-zero strategy address, without whitelisting. This allows an unprivileged EOA to deploy an arbitrary strategy and register it as the pool strategy.

2. **Non-zero Pre-existing WETH Reserves**  
   The victim Rebalancer pool must hold non-zero WETH reserves prior to the exploit, so that double-counting these reserves yields a real gain. The state diff confirms this: Rebalancer’s WETH ERC20 balance changes from `133.707875556674808577` to `0.007875556674808577`, a delta of `-133.7 WETH`, while the pool is otherwise funded by the flash loan and adversary token.

3. **Vulnerable Hook Ordering in _burn**  
   The deployed Rebalancer bytecode implements `_burn` exactly as in the verified source, with `burnHook` invoked before reserves are updated and before `_settleCurrency` and transfers. This is confirmed both by source and by the observed call ordering in the cast trace during the exploit.

4. **Strategy Reentrancy into burn**  
   The adversary strategy’s `burnHook` must synchronously re-enter `Rebalancer::burn` on the same pool key and `burnAmount`. The combination of the decompiled strategy code and the trace shows this behavior: when `burnHook` is called, it makes a call back into Rebalancer on the same pool, resulting in a nested `_burn` execution.

5. **Flash Loan Availability**  
   The attacker must be able to source the necessary WETH for the pool operations without upfront capital. Morpho’s permissionless flash loan function provides `267.4 WETH` to the strategy in the exploit transaction, satisfying this condition.

### Security Principles Violated

- **Reentrancy Safety in Core Accounting**  
  External hooks are invoked before invariant-critical state updates. `burnHook` is called while `reserveA/B` and `supply` still reflect pre-burn values, permitting re-entrancy that violates the implicit assumption that these values remain stable during `burn`.

- **Least Privilege and Trust Boundaries**  
  Untrusted strategies are given the ability to execute arbitrary logic in the middle of the burn flow. They can call back into `burn` and manipulate the protocol’s accounting without any reentrancy guard or role-based restriction.

- **Invariant Preservation for Pool Reserves**  
  `_burn` assumes that reserves and supply are updated atomically with the computation of `withdrawalA/B`. In reality, the strategy hook runs in between these steps, letting the attacker cause multiple withdrawals computed from the same reserves.

## Adversary Flow Analysis

### Adversary-Related Accounts and Victim Contracts

**Adversary cluster**

- `0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025` — EOA attacker  
  - Sender of the strategy deployment transaction `0x4fe2383c6dc0f03e53ea5ad4dd3b87c058c960234e57855fb49a9935a810a290`.  
  - Sender of the exploit transaction `0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04`.  
  - Final recipient of `133.540501283062363385 ETH` net profit in native balance.

- `0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1` — adversary strategy contract  
  - Deployed by `0x012F...` in `0x4fe2383c6dc0f03e53ea5ad4dd3b87c058c960234e57855fb49a9935a810a290`.  
  - Implements `setup`, `onMorphoFlashLoan`, `mintHook`, and `burnHook`.  
  - Serves as the Rebalancer pool’s strategy, receives WETH from Morpho, and executes the reentrant `burnHook`.

- `0xd3c8d0cd07Ade92df2d88752D36b80498cA12788` — adversary ERC20 token  
  - Created via `CREATE` during the deployment of `0x32Fb1B...`.  
  - Used exclusively as the paired asset in the malicious WETH–token pool.  
  - Address history shows activity only in the context of the exploit.

**Victim-side contracts**

- **Clober v2 Rebalancer** — `0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895` (verified)  
  Core pool and LP token logic, including `_burn` and strategy hooks.

- **Clober v2 BookManager** — `0x382CCccbD3b142D7DA063bF68cd0c89634767F76` (verified)  
  Order-book management, order settlement, and currency deltas used by Rebalancer.

- **Morpho WETH market** — `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb` (verified)  
  Provides the WETH flash loan that funds the exploit.

- **WETH9** — `0x4200000000000000000000000000000000000006` (verified)  
  Wrapped Ether contract used as the base asset; its `withdraw` converts WETH to ETH at the end of the exploit.

### Lifecycle Stage 1: Strategy and Token Deployment

- **Transaction**: `0x4fe2383c6dc0f03e53ea5ad4dd3b87c058c960234e57855fb49a9935a810a290` (Base, block `23514451`)  
- **Flow**:
  - EOA `0x012F...` deploys the strategy contract `0x32Fb1B...`.  
  - During deployment, `0x32Fb1B...` internally creates the ERC20-like token `0xd3c8...` via `CREATE`.  
  - Address histories for `0x32Fb1B...` and `0xd3c8...` show no prior activity, confirming they are adversary-controlled artifacts created for this attack.

### Lifecycle Stage 2: Flash Loan, Pool Open, and LP Mint

- **Transaction**: `0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04` (Base, block `23514451`)  
- **Key trace excerpt** (setup and flash loan):

```text
[782830] 0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1::setup()
  ├─ [2457] WETH9::balanceOf(Rebalancer: [0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895]) [staticcall]
  │   └─ ← [Return] 133707875556674808577 [1.337e20]
  ├─ [754387] Morpho::flashLoan(WETH9: [0x4200000000000000000000000000000000000006], 267400000000000000000 [2.674e20], ...)
  │   ├─ emit FlashLoan(...)
  │   ├─ [29701] WETH9::transfer(0x32Fb1B..., 267400000000000000000 [2.674e20])
  │   ├─ ...
  │   ├─ [714586] 0x32Fb1B...::onMorphoFlashLoan(267400000000000000000 [2.674e20], ...)
  │   │   ├─ [293031] Rebalancer::open(...)
  │   │   ├─ Rebalancer::mint(...)
  │   │   └─ ...
```

Within `setup()` and `onMorphoFlashLoan`:

- The strategy queries `WETH9::balanceOf(Rebalancer)` and sees `133.707875556674808577 WETH` already sitting on Rebalancer.
- It obtains a flash loan of `267.4 WETH` from Morpho.
- It approves Rebalancer to spend both WETH and the adversary token `0xd3c8...`.
- It calls `Rebalancer.open()` with a WETH–`0xd3c8...` book pair and sets itself (`0x32Fb1B...`) as the pool strategy.
- It then calls `Rebalancer.mint()` to deposit `267.4 WETH` and `267.4` units of `0xd3c8...`, receiving `267.4` LP tokens.

### Lifecycle Stage 3: Reentrant Burn and Profit Realization

Still within transaction `0x8fcdfc...361c04`, the strategy initiates the burn that triggers the vulnerability.

The trace (summarized) reveals:

- `Rebalancer::burn` is called with `burnAmount = 267.4 LP`.  
- Inside the `bookManager.lock` context, `Rebalancer::_burn` executes:
  - `_clearPool` cancels and claims on-book liquidity for the pool.
  - `reserveA/B` and `supply` are read from storage, and `withdrawalA/B` are computed.
  - `_burn(user, key, burnAmount)` burns the LP tokens.
  - `pool.strategy.burnHook(msg.sender, key, burnAmount, supply)` is invoked.

- While still in the first `_burn`, `burnHook` on `0x32Fb1B...` re-enters `Rebalancer::burn` on the same pool key and `burnAmount`, causing a **second** `_burn` execution before the first one has updated `pool.reserveA/B` or transferred tokens.

The cast trace documents two burn-like flows and corresponding token transfers, culminating in:

- Two `Burn` events with withdrawal amounts `(267.4, 267.4)` and `(133.7, 133.7)` for the WETH and token legs.
- `WETH9::transfer` calls from Rebalancer to `0x32Fb1B...` matching these amounts.
- Subsequent `WETH9::transferFrom` from `0x32Fb1B...` back to Morpho for `267.4 WETH` to repay the flash loan.
- A final `WETH9::withdraw(133700000000000000000)` call and ETH forwarding to the attacker EOA:

```text
├─ [457] WETH9::balanceOf(0x32Fb1B...) [staticcall]
│   └─ ← [Return] 133700000000000000000 [1.337e20]
├─ [9119] WETH9::withdraw(133700000000000000000 [1.337e20])
│   ├─ emit Withdrawal(src: 0x32Fb1B..., wad: 133700000000000000000 [1.337e20])
│   └─ ...
├─ [0] 0x012F...::fallback{value: 133700000000000000000}()
│   └─ ← [Stop]
└─ ← [Stop]
```

Throughout these nested calls, BookManager’s `settle` and `getCurrencyDelta` calls for WETH and `0xd3c8...` return zero deltas for Rebalancer, confirming that the additional withdrawal derives from Rebalancer’s pre-existing WETH reserves rather than new liquidity.

## Impact & Losses

### Quantitative Asset Impacts

From the PrestateTracer and balance diffs:

- **WETH (ERC20 balance)**  
  - Token: `WETH9` (`0x4200000000000000000000000000000000000006`)  
  - Holder: Rebalancer `0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895`  
  - Before: `133.707875556674808577 WETH`  
  - After: `0.007875556674808577 WETH`  
  - Delta: `-133.7 WETH`

- **ETH (native balance)**  
  - Address: attacker EOA `0x012Fc6377F1c5CCF6e29967Bce52e3629AaA6025`  
  - Before: `1.153475443767715212 ETH`  
  - After: `134.693976726830078597 ETH`  
  - Delta: `+133.540501283062363385 ETH` (net of gas and L1 fees)

These numbers match the ERC20 and native balance deltas in the seed transaction’s `balance_diff.json` and are fully consistent with a `133.7 WETH` withdrawal from Rebalancer and final ETH profit on the attacker.

### Qualitative Impact

The exploit:

- Drains essentially all pre-existing WETH from the targeted Rebalancer pool into the attacker’s control, leaving a dust balance of WETH.  
- Leaves the WETH–`0xd3c8...` pool undercollateralized and unusable for its intended purpose.  
- Does not show additional user-facing ERC20 losses in the analyzed state diff; the damage is concentrated in Rebalancer’s WETH position and the attacker’s profit.

## References

Key artifacts supporting this analysis:

- **[1] Rebalancer::_burn source code**  
  Verified source for the victim contract at `0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895`.  
  Path: `artifacts/root_cause/data_collector/iter_1/contract/8453/0x6A0b87D6b74F7D5C92722F6a11714DBeDa9F3895/source/src/src/Rebalancer.sol`

- **[2] Seed transaction trace for 0x8fcdfc...361c04**  
  Foundry `cast run -vvvvv` style trace for the exploit transaction on Base, including all internal calls and storage deltas.  
  Path: `artifacts/root_cause/data_collector/iter_2/tx/8453/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04/trace.cast.log`

- **[3] State and balance diffs for the seed transaction**  
  Prestate and poststate storage diffs plus aggregated balance changes for native and ERC20 tokens.  
  Path: `artifacts/root_cause/data_collector/iter_2/tx/8453/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04/state_diff_prestate.json`

- **[4] Balance diff summary including attacker and Rebalancer WETH/ETH deltas**  
  High-level balance change summary showing the attacker’s ETH profit and Rebalancer’s WETH loss.  
  Path: `artifacts/root_cause/seed/8453/0x8fcdfcded45100437ff94801090355f2f689941dca75de9a702e01670f361c04/balance_diff.json`

- **[5] Adversary strategy decompiled source**  
  Decompiled contract for `0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1`, including `setup`, `onMorphoFlashLoan`, `mintHook`, and `burnHook`, illustrating how reentrancy into Rebalancer is implemented.  
  Path: `artifacts/root_cause/data_collector/iter_1/contract/8453/0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1/decompile/0x32Fb1BedD95BF78ca2c6943aE5AEaEAAFc0d97C1-decompiled.sol`

- **[6] Adversary token decompiled source and metadata**  
  Decompiled ERC20-like contract and metadata for the adversary token `0xd3c8d0cd07Ade92df2d88752D36b80498cA12788` used as the pool’s quote/base pair with WETH.  
  Path: `artifacts/root_cause/data_collector/iter_1/contract/8453/0xd3c8d0cd07Ade92df2d88752D36b80498cA12788/decompile/0xd3c8d0cd07Ade92df2d88752D36b80498cA12788-decompiled.sol`

- **[7] Address histories for Rebalancer, BookManager, Morpho, and adversary contracts**  
  Normal and internal transaction histories on Base for differentiating long-lived protocol contracts from freshly deployed adversary contracts.  
  Path: `artifacts/root_cause/data_collector/iter_1/address/8453`

