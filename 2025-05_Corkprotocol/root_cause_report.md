## Incident Overview & TL;DR

**Report title:** Cork PSM FlashSwapRouter returnRaWithCtDs Exploit  
**Protocol:** Cork  
**Classification:** ACT (automated, repeatable profit opportunity)

An unprivileged adversary-controlled EOA `0xea6f30e360192bae715599e15e2f765b49e4da98` deployed a helper contract `0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09` and used Cork’s FlashSwapRouter and PSM core to unlock more WstETH‑backed Redemption Assets (RA) from the DS/RA reserve proxy `0xCCD90f6435dd78c4ecced1fA4Db0D7242548a2a9` than the protocol’s accounting justifies. The attacker combined a small flash‑swapped WstETH amount, PSM `returnRaWithCtDs` accounting, and `FlashSwapRouter.__afterFlashswapSell` payout logic to drain WstETH from the DS/RA reserve into the helper contract and then into the EOA via a dedicated withdrawal function.

The root cause is the interaction between the PSM library function `PsmLib._returnRaWithCtDs` and `FlashSwapRouter.__afterFlashswapSell`. Both treat CT/DS redemption from the DS/RA reserve as if the entire `ctAmount` is backed one‑to‑one by RA in the PSM’s RA balance, while the DS/RA reserve proxy also holds WstETH liquidity obtained via flash swaps. This mismatch lets an unprivileged helper unlock RA that is economically backed by DS/RA reserves and flash‑swapped WstETH and then keep the excess RA (and thus WstETH) after repaying only the flash loan, creating a deterministic, repeatable ACT profit opportunity.

---

## ACT Opportunity

### Pre‑state and block

- **Block height B:** `22581020` (Ethereum mainnet).
- **Pre‑state σ_B:** Ethereum state immediately before inclusion of tx `0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d` in block `0x1588f1c`.
- **Key actors and contracts in σ_B:**
  - Adversary EOA: `0xea6f30e360192bae715599e15e2f765b49e4da98`
  - Helper contract: `0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09`
  - WstETH: `0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0`
  - LiquidityToken: `0x05816980faec123deae7233326a1041f372f4466`
  - DS/RA WstETH reserve proxy: `0xCCD90f6435dd78c4ecced1fA4Db0D7242548a2a9`
  - CorkHook: `0x5287E8915445aee78e10190559D8Dd21E0E9Ea88`
  - PoolManager: `0x000000000004444c5dc75cB358380D2e3dE08A90`
  - FlashSwapRouter reserve contract: `0x55b90b37416dc0bd936045a8110d1af3b6bf0fc3`
  - PSM core: `0xf0da8927df8d759d5ba6d3d714b1452135d99cfc`
  - Asset tokens: `0xcd25aa56aad1bcc1bb4b6b6b08bda53007ec81ce`, `0x7ea0614072e2107c834365bea14f9b6386fb84a5`, `0x1d2724ca345e1889cecddefa5f8f83666a442c86`, `0x51f70fe94e7ccd9f2efe45a4f2ea3a7ae0c62f8c`, `0xde9d58d3347f0413772e35a5859559475008583d`.

**Pre‑state evidence (seed metadata and prestate balance diffs):**

```json
// Seed metadata for tx 0xfd89cdd0... (victim transaction)
{
  "chainid": 1,
  "txhash": "0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d",
  "etherscan": { "tx": { "result": { "from": "0xea6f30e360192bae715599e15e2f765b49e4da98",
    "to": "0x9af3dce0813fd7428c47f57a39da2f6dd7c9bb09",
    "blockNumber": "0x1588f1c"
  } } }
}
```

*Caption: Seed transaction metadata confirming chain, block, sender EOA, and helper contract target.*

### Transaction sequence (B)

From σ_B, the adversary executes the following sequence on Ethereum (chainid 1):

1. **Helper deployment**
   - **Tx:** `0xc645afdf4ff762856030ee0c3e2175007359c8e67a108ba6021386021ae7017f`
   - **Role:** Adversary‑crafted deployment tx.
   - **Effect:** EOA `0xea6f30e3...` deploys helper `0x9Af3dCE...`.
   - **Feasibility:** Standard type‑2 deployment with sufficient ETH and no privileged gatekeeping; `txlist_normal.json` shows no allowlist or role checks.

2. **WstETH approval**
   - **Tx:** `0xb54308956e58fc124503e01eaae153e54eb738fd188e476460dba78e61793b45`
   - **Role:** Adversary‑crafted.
   - **Effect:** EOA approves a large WstETH allowance from `0xea6f30e3...` to helper `0x9Af3dCE...`.
   - **Feasibility:** Simple ERC‑20 `approve` from an unprivileged EOA to WstETH `0x7f39C5...` (selector `0x095ea7b3`), publicly callable.

3. **LiquidityToken approval**
   - **Tx:** `0x89ba58edaf9f40dc0c781c40351ba392be31263faa6be3a29c2ee152f271df6d`
   - **Role:** Adversary‑crafted.
   - **Effect:** EOA approves LiquidityToken `0x0581698...` to helper `0x9Af3dCE...`, preparing `transferFrom` during the flash swap.
   - **Feasibility:** Standard ERC‑20 `approve`, no access control.

4. **Core exploit via flash‑swap and PSM**
   - **Tx:** `0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d`
   - **Role:** Adversary‑crafted.
   - **Effect:** EOA calls helper `0x9Af3dCE...` with selector `0x0f626b5a` (`Unresolved_0f626b5a`) to orchestrate a Cork flash‑swap through LiquidityToken, CorkHook, FlashSwapRouter, and PSM core. WstETH moves from `0xea6f30e3...` and DS/RA proxy `0xCCD90f...` into helper `0x9Af3dCE...`, with smaller amounts routed to PoolManager and treasury as fees and flash‑loan repayment.
   - **Feasibility:** The decompiled `Unresolved_0f626b5a` enforces only `arg0 == address(arg0)` and does not restrict `msg.sender`; downstream PSM and FlashSwapRouter entrypoints are public and unprivileged. Any EOA with the same balances and allowances in σ_B can submit an identical call.

5. **Profit withdrawal**
   - **Tx:** `0x605e653fb580a19f26dfa0a6f1366fac053044ac5004e1b10e7901b058150c50`
   - **Role:** Adversary‑crafted.
   - **Effect:** EOA `0xea6f30e3...` calls helper `0x9Af3dCE...` with selector `0xc5bb26a0` (`Unresolved_c5bb26a0`) to transfer all WstETH from helper to the EOA.
   - **Feasibility:** `Unresolved_c5bb26a0` checks `msg.sender == address(store_a / 0x01)` and then performs `balanceOf` and `transfer` to an arbitrary address. The trace shows this succeeds for `msg.sender 0xea6f30e3...`, giving the EOA full control of profit withdrawal.

### Exploit predicate and profit

- **Type:** Profit ACT (automated, repeatable).
- **Reference asset:** WstETH.
- **Adversary cluster:** `{0xea6f30e360192bae715599e15e2f765b49e4da98, 0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09}`.
- **Cluster WstETH value before:** `996592406032878584` wei.
- **Cluster WstETH value after:** `3761877955369549831945` wei.
- **Net WstETH gain:** `3760881362963516953361` wei.
- **Fees in reference asset:** 0 WstETH (fees are paid in ETH gas).

**Key balance‑diff evidence for victim tx 0xfd89cdd0... (prestate, WstETH and Asset deltas):**

```json
// Excerpt from prestate ERC20 balance diffs (iter_2, victim tx)
{
  "erc20_balance_deltas": [
    {
      "token": "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0",
      "holder": "0xea6f30e360192bae715599e15e2f765b49e4da98",
      "before": "996592406032878584",
      "after": "0",
      "delta": "-996592406032878584"
    },
    {
      "token": "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0",
      "holder": "0x9af3dce0813fd7428c47f57a39da2f6dd7c9bb09",
      "before": "0",
      "after": "3761877955369549831945",
      "delta": "3761877955369549831945"
    },
    {
      "token": "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0",
      "holder": "0xccd90f6435dd78c4ecced1fa4db0d7242548a2a9",
      "before": "3795356125293515769100",
      "after": "34474759349606697572",
      "delta": "-3760881365943909071528"
      }
  ]
}
```

*Caption: Victim transaction diff showing WstETH drained from DS/RA proxy, moved to helper, and debited from the EOA.*

**Key balance‑diff evidence for withdrawal tx 0x605e653f... (cluster profit realization):**

```json
// Excerpt from prestate balance diffs (iter_3, withdrawal tx)
{
  "erc20_balance_deltas": [
    {
      "token": "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0",
      "holder": "0x9af3dce0813fd7428c47f57a39da2f6dd7c9bb09",
      "before": "3761877955369549831945",
      "after": "0",
      "delta": "-3761877955369549831945"
    },
    {
      "token": "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0",
      "holder": "0xea6f30e360192bae715599e15e2f765b49e4da98",
      "before": "0",
      "after": "3761877955369549831945",
      "delta": "3761877955369549831945"
    }
  ]
}
```

*Caption: Withdrawal transaction diff showing all WstETH consolidated from helper to the adversary EOA.*

These diffs, combined across both txs, show a cluster WstETH gain of `3760881362963516953361` wei, exactly matching the ACT profit described in `root_cause.json`.

---

## Key Background

### DS/RA PSM architecture

- Cork’s DS/RA PSM system uses a PSM core contract (`0xf0da8927df8d759d5ba6d3d714b1452135d99cfc`) with library `PsmLib.sol` to manage:
  - Redemption Asset (RA),
  - DepegSwap (DS) token,
  - Pegged Asset (PA),
  all backed by WstETH.
- State is tracked in `State` and `PsmPoolArchive` structures.
- The DS/RA WstETH reserve is held in a proxy contract at `0xCCD90f6435dd78c4ecced1fA4Db0D7242548a2a9`.
- PSM functions lock and unlock RA and DS balances for users, coordinating deposits, redemptions, rollovers, and repurchases.

### FlashSwapRouter integration

- The FlashSwapRouter (within `ModuleCore`) is implemented in `FlashSwapRouter.sol` (`artifacts/root_cause/data_collector/iter_2/contract/1/0xf0da89.../source/src/core/flash-swaps/FlashSwapRouter.sol`).
- It provides flash‑swap functionality that can:
  - Call into the PSM via `IPSMcore.returnRaWithCtDs`,
  - Receive RA into the router,
  - Repay the PoolManager flash loan,
  - Forward any remaining RA to the flash‑swap caller.
- The helper function `__afterFlashswapSell` increases DS and CT allowances to `ModuleCore`, then calls `PSM.returnRaWithCtDs` with a `ctAmount` argument, and finally transfers RA to the flash‑swap caller and the PoolManager.

**FlashSwapRouter RA redemption and payout (key excerpt):**

```solidity
// Source: FlashSwapRouter.__afterFlashswapSell (simplified excerpt)
function __afterFlashswapSell(
    Id reserveId,
    uint256 ctAmount,
    address caller,
    address poolManager,
    uint256 actualRepaymentAmount
) internal {
    // ... DS/CT allowances set to ModuleCore ...
    uint256 received = IPSMcore(psmCore).returnRaWithCtDs(reserveId, ctAmount);
    // repay flash loan and send remainder to caller
    require(actualRepaymentAmount <= received, "insufficient RA for repayment");
    uint256 profit = received - actualRepaymentAmount;
    IERC20(raToken).transfer(poolManager, actualRepaymentAmount);
    IERC20(raToken).transfer(caller, profit);
}
```

*Caption: Router helper that calls `PSM.returnRaWithCtDs` and forwards excess RA (later converted to WstETH) to the caller.*

### Helper contract behavior

- The helper contract `0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09` is decompiled under `artifacts/root_cause/data_collector/iter_1/contract/1/0x9Af3dCE.../decompile/0x9Af3dCE...-decompiled.sol`.
- It exposes:
  - **`Unresolved_0f626b5a(address)`**: prepares aggregated calldata for a complex Cork flash‑swap and PSM interaction; it enforces only `arg0 == address(arg0)` and does not restrict `msg.sender`.
  - **`Unresolved_c5bb26a0(uint256,arg1)`**: a withdrawal function that:
    - Verifies `msg.sender == address(store_a / 0x01)`,
    - Calls `balanceOf(this)` on an ERC‑20 token,
    - Calls `transfer(recipient, fullBalance)` to send all tokens to a specified recipient.

**Helper contract decompilation (exploit‑relevant functions):**

```solidity
// Decompilation excerpt: public aggregator and withdrawal
function Unresolved_0f626b5a(address arg0) public pure {
    require(arg0 == address(arg0)); // no msg.sender gating
}

function Unresolved_c5bb26a0(uint256 arg0, address arg1) public payable {
    // ... checks ...
    require(address(msg.sender) == address(store_a / 0x01));
    // read helper's ERC20 balance and transfer full amount to arg1
    (bool ok0, bytes memory balData) = token.call(abi.encodeWithSelector(0x70a08231, address(this)));
    uint256 bal = abi.decode(balData, (uint256));
    (bool ok1,) = token.call(abi.encodeWithSelector(0xa9059cbb, arg1, bal));
    // ...
}
```

*Caption: Decompiled helper showing unrestricted aggregator and owner‑gated “drain balance” withdrawal.*

### LiquidityToken and DS/RA reserve

- LiquidityToken at `0x05816980faec123deae7233326a1041f372f4466` and the FlashSwapRouter’s reserve contract at `0x55b90b37416dc0bd936045a8110d1af3b6bf0fc3` participate in a flash swap.
- This flash swap moves LiquidityToken and Asset balances between:
  - DS/RA proxy `0xCCD90f...`,
  - PoolManager,
  - Helper contract,
  as shown in the victim tx trace and the associated balance diffs.

---

## Vulnerability & Root Cause Analysis

### High‑level vulnerability

- The combination of PSM `returnRaWithCtDs` and `FlashSwapRouter.__afterFlashswapSell` allows an unprivileged helper contract to:
  - Redeem CT/DS against the DS/RA reserve via `returnRaWithCtDs`,
  - Unlock RA directly to the FlashSwapRouter,
  - Receive RA in a way that does not fully account for how much RA is economically backed by DS/RA reserve balances and flash‑swapped WstETH,
  - Keep RA (and thus WstETH) beyond what is needed to repay the flash loan.
- The net effect is that DS/RA reserve RA/WstETH is released to the attacker in excess of economically justified backing, producing a deterministic profit.

### PSM `returnRaWithCtDs` internals

`PsmLib._returnRaWithCtDs` defines how RA is unlocked for CT/DS redemption:

```solidity
// Source: PsmLib.sol::_returnRaWithCtDs
function _returnRaWithCtDs(State storage self, DepegSwap storage ds, address owner, uint256 amount)
    internal
    returns (uint256 ra)
{
    ra = TransferHelper.fixedToTokenNativeDecimals(amount, self.info.ra);

    self.psm.balances.ra.unlockTo(owner, ra);

    ERC20Burnable(ds.ct).burnFrom(owner, amount);
    ERC20Burnable(ds._address).burnFrom(owner, amount);
}
```

*Caption: PSM library converts `amount` to RA units, unlocks RA to the `owner`, and burns both CT and DS from that owner.*

Key properties:

- RA to release is computed as `ra = fixedToTokenNativeDecimals(amount, self.info.ra)`.
- RA is immediately unlocked to `owner` via `self.psm.balances.ra.unlockTo(owner, ra)`.
- Both CT and DS tokens are burned from `owner`.

`PsmCore` exposes this behavior publicly via `returnRaWithCtDs`:

```solidity
// Source: Psm.sol::returnRaWithCtDs
function returnRaWithCtDs(
    Id id,
    uint256 amount,
    address redeemer,
    bytes calldata rawDsPermitSig,
    uint256 dsDeadline,
    bytes calldata rawCtPermitSig,
    uint256 ctDeadline
) external override nonReentrant returns (uint256 ra) {
    PSMWithdrawalNotPaused(id);

    if (rawDsPermitSig.length == 0 || dsDeadline == 0 || rawCtPermitSig.length == 0 || ctDeadline == 0) {
        revert InvalidSignature();
    }
    State storage state = states[id];
    ra = state.returnRaWithCtDs(redeemer, amount, rawDsPermitSig, dsDeadline, rawCtPermitSig, ctDeadline);

    emit Cancelled(id, state.globalAssetIdx, redeemer, ra, amount);
}
```

*Caption: PSM core forwards redemption calls to `PsmLibrary.returnRaWithCtDs`, which invokes `_returnRaWithCtDs` and unlocks RA to the given redeemer.*

This logic assumes each unit of `amount` (in CT/DS fixed decimals) is backed one‑to‑one by RA tracked in `self.psm.balances.ra`, with overall DS/RA invariants enforced at the PSM level.

### FlashSwapRouter usage of `returnRaWithCtDs`

Inside `FlashSwapRouter.__afterFlashswapSell`, the router:

1. Sets DS and CT allowances to `ModuleCore` (PSM core).
2. Calls `IPSMcore.returnRaWithCtDs(reserveId, ctAmount)` on the PSM.
3. Receives RA directly to the router.
4. Repays the PoolManager’s flash loan.
5. Forwards any remaining RA to the flash‑swap caller (the helper).

The router does not track how much of the unlocked RA is economically backed by DS/RA reserve balances vs. other internal PSM accounting (e.g., historical positions, rollover, fees). It treats `received` as safely withdrawable, subject only to repaying `actualRepaymentAmount`.

### Concrete exploit path in tx 0xfd89cdd0...

The victim transaction trace shows the helper and protocol interactions:

```text
// Excerpt from trace.cast.log for tx 0xfd89cdd0...
0x9Af3dCE...::0f626b5a(...)
  ├─ LiquidityToken::transferFrom(0xEA6f30e3..., ERC1967Proxy[0xCCD90f...], 10034249)
  ├─ WstETH::transferFrom(0xEA6f30e3..., 0x9Af3dCE..., 996592406032878584)
  ├─ ... CorkHook and rate provider calls ...
  ├─ WstETH::approve(ERC1967Proxy[0xCCD90f...], MAX_UINT)
  ├─ ERC1967Proxy[0xCCD90f...]::fallback(...)
  │    ├─ ModuleCore::depositPsm(...)
  │    ├─ PsmLibrary::63b60afb(...)   // DS/RA math and state updates
  │    ├─ WstETH::transferFrom(0x9Af3dCE..., ERC1967Proxy[0xCCD90f...], 4e15)
  │    ├─ Asset::mint(0x9Af3dCE..., 4e15)
  │    └─ ...
  ├─ ... FlashSwapRouter.__afterFlashswapSell(...)
  │    ├─ WstETH::transferFrom(0x9Af3dCE..., ERC1967Proxy[0xCCD90f...], ...)
  │    ├─ IPSMcore.returnRaWithCtDs(reserveId, ctAmount)
  │    ├─ WstETH::transferFrom(PSM/RA to helper, PoolManager, treasury)
  │    └─ ...
```

*Caption: Victim tx trace showing helper‑driven path into CorkHook, FlashSwapRouter, and PSM, culminating in `returnRaWithCtDs` and WstETH movement from DS/RA proxy to helper, PoolManager, and treasury.*

Combining the trace and balance diffs:

- DS/RA proxy `0xCCD90f...` loses `3760881365943909071528` WstETH.
- Helper `0x9Af3dCE...` gains `3761877955369549831945` WstETH.
- PoolManager and treasury gain only a small portion (`2980317610319` and `74507848` WstETH respectively) as flash‑loan fees and protocol fees.
- EOA `0xea6f30e3...` loses its initial `996592406032878584` WstETH contribution.

The sum of WstETH deltas across all involved addresses in this tx is zero, confirming conservation of WstETH while highlighting that the DS/RA proxy’s loss equals:

> helper gain + PoolManager gain + treasury gain − EOA contribution

### Profit withdrawal in tx 0x605e653f...

The follow‑up withdrawal tx executes `Unresolved_c5bb26a0` on the helper:

```text
// Excerpt from trace.cast.log for tx 0x605e653f...
0x9Af3dCE...::c5bb26a0(...)
  ├─ WstETH::balanceOf(0x9Af3dCE...)
  ├─ WstETH::transfer(0xEA6f30e3..., 3761877955369549831945)
  └─ (storage: helper WstETH balance goes to 0)
```

*Caption: Withdrawal tx trace showing helper transferring all WstETH to the adversary EOA.*

The balance diffs for this tx show:

- Helper WstETH: `3761877955369549831945 → 0`.
- EOA WstETH: `0 → 3761877955369549831945`.

Combined with the victim tx, the adversary cluster’s WstETH holdings move from `996592406032878584` to `3761877955369549831945`, a net gain of `3760881362963516953361` WstETH, while the DS/RA proxy permanently loses `3760881365943909071528` WstETH.

### Root cause: accounting mismatch between PSM and FlashSwapRouter

The core bug is a mismatch between:

- **PSM perspective:** `PsmLib._returnRaWithCtDs` unlocks RA based on CT/DS amounts, assuming that the RA it releases is fully backed by PSM RA accounting (`self.psm.balances.ra`) and that CT/DS burning maintains DS/RA invariants.
- **FlashSwapRouter perspective:** `__afterFlashswapSell` treats the returned RA as freely spendable to repay the flash loan and distribute any remainder to the caller, without enforcing constraints that bound RA release to DS/RA reserve capacity or user‑specific positions.

Because the DS/RA reserve proxy also holds WstETH liquidity obtained via flash swaps, this combination allows:

- RA to be unlocked from PSM balances in a way that indirectly draws down DS/RA proxy WstETH,
- The flash loan repayment to consume only a small portion of this RA,
- The helper to keep the remainder as profit.

The protocol’s accounting does not track, within `returnRaWithCtDs` and `__afterFlashswapSell`, how much of the unlocked RA is truly attributable to:

- Legitimate CT/DS positions,
- Fees and rollover allocations,
- Versus flash‑swapped WstETH that should remain locked in the DS/RA reserve.

This is the deterministic root cause that enables the observed exploit.

### Exploit pre‑conditions

For the exploit to be possible:

1. The DS/RA PSM core must be deployed with `PsmLib._returnRaWithCtDs` and `Psm.sol::returnRaWithCtDs` wired into `FlashSwapRouter.__afterFlashswapSell` via `IPSMcore.returnRaWithCtDs`.
2. A DS/RA reserve proxy such as `0xCCD90f...` must hold significant WstETH liquidity backing RA and DS/CT positions.
3. FlashSwapRouter and CorkHook must expose a flash‑swap path that:
   - Calls `__afterFlashswapSell` with a `ctAmount` derived from DS/CT balances,
   - Forwards RA proceeds to the flash‑swap caller after settling the PoolManager’s flash loan.
4. An unprivileged EOA must be able to:
   - Deploy a helper contract,
   - Approve WstETH and LiquidityToken to that helper,
   - Invoke the helper’s aggregator function to route through CorkHook, FlashSwapRouter, and `PSM.returnRaWithCtDs` as in tx `0xfd89cd...`.
5. The helper contract must implement a withdrawal function (like `Unresolved_c5bb26a0`) that:
   - Can be called by the EOA,
   - Transfers the exploited WstETH from the helper contract to the EOA.

### Security principles violated

- **Asset‑reserve accounting:**  
  The DS/RA PSM assumes that CT/DS redemption via `returnRaWithCtDs` unlocks RA that is fully backed by PSM balances. The interaction with FlashSwapRouter and DS/RA reserves at proxy `0xCCD90f...` allows RA (and thus WstETH) to be unlocked beyond economically justified backing.

- **Least privilege and invariant enforcement:**  
  PSM and FlashSwapRouter interfaces allow any unprivileged caller with sufficient balances and allowances to trigger the `returnRaWithCtDs` path inside a flash‑swap, without enforcing invariants that bound RA release to DS/RA reserve capacity or user‑specific positions.

- **Separation between flash‑swap mechanics and reserve management:**  
  The protocol does not enforce a constraint tying `ctAmount` in `__afterFlashswapSell` and `returnRaWithCtDs` to a safe share of the DS/RA reserve. A flash‑swap caller can structure trades that push RA withdrawal onto the DS/RA reserve while repaying only a smaller portion of WstETH to the PoolManager.

---

## Adversary Flow Analysis

### Adversary strategy summary

The adversary cluster:

1. Deploys a dedicated helper contract.
2. Grants it large WstETH and LiquidityToken allowances.
3. Uses the helper to execute a Cork flash‑swap through LiquidityToken, CorkHook, FlashSwapRouter, and `PSM.returnRaWithCtDs`, unlocking RA from the DS/RA reserve and converting it into WstETH on the helper contract.
4. Calls a withdrawal function on the helper to transfer all WstETH back to the EOA.

This realizes a net WstETH profit funded by the DS/RA reserve’s WstETH holdings.

### Adversary‑related accounts

**Adversary cluster**

- **EOA `0xea6f30e360192bae715599e15e2f765b49e4da98` (Ethereum mainnet, chainid 1)**
  - Deployer of helper contract in tx `0xc645afdf...`.
  - Approver of WstETH and LiquidityToken allowances to `0x9Af3dCE...` in txs `0xb543089...` and `0x89ba58e...`.
  - Caller of helper’s aggregator function (`Unresolved_0f626b5a`) in tx `0xfd89cd...`.
  - Caller of helper’s withdrawal function (`Unresolved_c5bb26a0`) in tx `0x605e65...`.
  - These roles are confirmed by `txlist_normal.json` and the traces and balance diffs referenced above.

- **Helper contract `0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09` (Ethereum mainnet, chainid 1)**
  - Contract whose decompiled code exposes:
    - Aggregator function `Unresolved_0f626b5a` used in tx `0xfd89cd...` to route calls into LiquidityToken, CorkHook, FlashSwapRouter, and PSM core.
    - Withdrawal function `Unresolved_c5bb26a0` used in tx `0x605e65...` to transfer all WstETH from the contract to EOA `0xea6f30e3...`, with `msg.sender` gating on `store_a` satisfied only for `0xea6f30e3...` in the observed trace.

**Victim‑side contracts**

- **DS/RA WstETH reserve proxy**
  - Address: `0xCCD90f6435dd78c4ecced1fA4Db0D7242548a2a9`
  - Ethereum, chainid 1
  - Verified role as DS/RA reserve via PSM and FlashSwapRouter interactions and balance diffs.

- **Cork PoolManager**
  - Address: `0x000000000004444c5dc75cB358380D2e3dE08A90`
  - Ethereum, chainid 1
  - Receives flash‑swap repayments and fees.

- **Cork PSM core**
  - Address: `0xf0da8927df8d759d5ba6d3d714b1452135d99cfc`
  - Ethereum, chainid 1
  - Hosts the PSM logic, including `returnRaWithCtDs`.

### Adversary lifecycle stages

1. **Adversary helper deployment**
   - **Tx:** `0xc645afdf4ff762856030ee0c3e2175007359c8e67a108ba6021386021ae7017f` (block `22580920`).
   - **Effect:** EOA `0xea6f30e3...` deploys helper contract `0x9Af3dCE...`, which contains the aggregator and withdrawal functions used later.
   - **Evidence:** `txlist_normal.json` for `0xea6f30e3...` and the decompiled helper contract.

2. **Approvals and setup**
   - **Txs:**  
     - `0xb54308956e58fc124503e01eaae153e54eb738fd188e476460dba78e61793b45` (WstETH approve)  
     - `0x89ba58edaf9f40dc0c781c40351ba392be31263faa6be3a29c2ee152f271df6d` (LiquidityToken approve)
   - **Blocks:** `22580943`, `22580971`.
   - **Effect:** EOA `0xea6f30e3...` grants helper `0x9Af3dCE...` large allowances for WstETH and LiquidityToken, enabling `transferFrom` during the exploit without further user interaction.
   - **Evidence:** `trace.cast.log` for each tx, showing `approve` from `0xea6f30e3...` to `0x9Af3dCE...`.

3. **Exploit execution via Cork flash‑swap and PSM**
   - **Tx:** `0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d` (block `22581020`).
   - **Mechanism:** Flash loan/flash swap.
   - **Effect:** EOA `0xea6f30e3...` calls helper `0x9Af3dCE...` (selector `0x0f626b5a`) to trigger:
     - LiquidityToken flash swap via CorkHook and FlashSwapRouter,
     - PSM `returnRaWithCtDs` redemption,
     - Movement of WstETH from `0xea6f30e3...` and DS/RA proxy `0xCCD90f...` into helper `0x9Af3dCE...`,
     - Payment of flash‑loan fees to PoolManager and treasury.
   - **State impact in this tx:**
     - DS/RA proxy loses `3760881365943909071528` WstETH.
     - Helper gains `3761877955369549831945` WstETH.
     - EOA loses `996592406032878584` WstETH.
   - **Evidence:** `trace.cast.log` for the tx plus `balance_diff_prestate_liquiditytoken.json` for prestate ERC‑20 diffs.

4. **Profit withdrawal**
   - **Tx:** `0x605e653fb580a19f26dfa0a6f1366fac053044ac5004e1b10e7901b058150c50` (block `22581029`).
   - **Mechanism:** Direct ERC‑20 transfer via helper.
   - **Effect:** EOA `0xea6f30e3...` calls `Unresolved_c5bb26a0` on helper `0x9Af3dCE...` to transfer `3761877955369549831945` WstETH from helper to the EOA, consolidating all exploited WstETH into an externally spendable address.
   - **Evidence:** `trace.cast.log` and `balance_diff_prestate.json` for this tx, showing `balanceOf` and `transfer` from helper to EOA and helper’s WstETH balance dropping to zero.

---

## Impact & Losses

### Quantitative impact

- **Total WstETH loss from DS/RA reserve proxy (`0xCCD90f...`):**  
  `3760881365943909071528` wei.

- **Adversary cluster net WstETH profit:**  
  `3760881362963516953361` wei.

- **Difference:**  
  A small remainder of WstETH is routed to:
  - PoolManager `0x000000000004444c5dc75cB358380D2e3dE08A90`,
  - Treasury `0xb9EEeBa3659466d251E8A732dB2341E390AA059F`,
  as deduced from the WstETH balance diffs for the victim tx.

### Qualitative impact

- The DS/RA WstETH reserve proxy’s WstETH holdings are permanently reduced, weakening the backing of DS/RA positions.
- Users whose claims depend on WstETH stored in the DS/RA reserve suffer effective value loss, since a portion of reserve assets has been redirected to the adversary cluster.
- Because the exploit path is driven entirely by public contracts and unprivileged entrypoints, and because it yields deterministic WstETH profit from a known pre‑state σ_B, it qualifies as an ACT (automated, repeatable profit opportunity).

---

## References

All references are local artifacts collected during analysis:

1. **Tx 0xfd89cd... trace and metadata**  
   `artifacts/root_cause/seed/1/0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d/`

2. **Prestate WstETH and Asset balance diffs for 0xfd89cd...**  
   `artifacts/root_cause/data_collector/iter_2/tx/1/0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d/balance_diff_prestate_liquiditytoken.json`

3. **Withdrawal tx 0x605e65... trace and balance diffs**  
   `artifacts/root_cause/data_collector/iter_3/tx/1/0x605e653fb580a19f26dfa0a6f1366fac053044ac5004e1b10e7901b058150c50/`

4. **PSM library and core source (PsmLib.sol and Psm.sol)**  
   `artifacts/root_cause/data_collector/iter_2/contract/1/0xf0da8927df8d759d5ba6d3d714b1452135d99cfc/source/src/core/`

5. **FlashSwapRouter source (flash‑swaps integration with PSM)**  
   `artifacts/root_cause/data_collector/iter_2/contract/1/0xf0da8927df8d759d5ba6d3d714b1452135d99cfc/source/src/core/flash-swaps/FlashSwapRouter.sol`

6. **Helper contract 0x9Af3dCE... decompiled code and ABI**  
   `artifacts/root_cause/data_collector/iter_1/contract/1/0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09/decompile/`

