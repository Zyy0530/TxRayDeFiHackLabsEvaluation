## Incident Overview TL;DR

An unprivileged searcher-controlled EOA `0x48f1d0f5831eb6e544f8cbde777b527b87a1be98` exploited a cross-contract accounting bug between MetaPool Staking/mpETH and `LiquidUnstakePool` on Ethereum mainnet. Using a Balancer flash loan and subsequent `swapmpETHforETH` priming trades, the adversary extracted ETH from the pool far in excess of correctly accounted backing, realizing a net ETH profit while ending with a sizable mpETH position.

The root cause is a protocol-level accounting bug: `Staking.depositETH` / `_getmpETHFromPool` forwards most user ETH into `LiquidUnstakePool` via `swapETHFormpETH` without increasing `Staking.totalUnderlying` appropriately, while `LiquidUnstakePool.totalAssets` double-counts the same underlying via `ethBalance + Staking.convertToAssets(Staking.balanceOf(pool))`. This misaligned accounting allows attackers to build a large mpETH position and then convert it into outsized ETH withdrawals.

Key facts:
- Protocol: MetaPool (Staking/mpETH & LiquidUnstakePool).
- Category: `protocol_bug`, ACT opportunity: `is_act = true`.
- ACT opportunity block state `σ_B`: Ethereum mainnet at block `22722952`.
- Net adversary ETH profit (before gas): `10.104453656669029294` ETH.
- Total gas fees paid: `0.028242175905358094` ETH.

---

## Key Background

MetaPool issues mpETH via a Staking contract deployed behind TransparentUpgradeableProxy `0x48AFbBd342F64EF8a9Ab1C143719b63C2AD81710`, with implementation at `0x3747484567119592ff6841df399cf679955a111a`. The Staking contract tracks deposited ETH in `totalUnderlying` and determines the mpETH share price via `totalAssets` and `totalSupply`, which drive functions such as `previewDeposit`, `previewMint`, and `convertToAssets`.

`LiquidUnstakePool` at `0xdF261F967E87B2aa44e18a22f4aCE5d7f74f03Cc` holds a portion of MetaPool’s assets and provides mpETH/ETH liquidity. It exposes `swapETHFormpETH` (ETH → mpETH) and `swapmpETHforETH` (mpETH → ETH), and defines:

- `totalAssets() = ethBalance + Staking.convertToAssets(Staking.balanceOf(address(this)))`.
- `ethBalance` tracks ETH held directly by the pool.
- `Staking.balanceOf(address(this))` tracks the pool’s mpETH position, valued using the global mpETH share price from Staking.

Pre-priming state at block `22722952` (σ_B) is captured in `artifacts/root_cause/data_collector/iter_3/storage_snapshots_pre_priming.json`:

- Staking/mpETH proxy `0x48AF...`:
  - `totalUnderlying ≈ 11679.3514` ETH.
  - `totalAssets ≈ 11679.3680` ETH.
  - `totalSupply ≈ 10589.9669` mpETH.
  - `Staking.balanceOf(LiquidUnstakePool) ≈ 103.9524` mpETH.
  - Implied mpETH share price: ≈ `1.10287` ETH per mpETH.
- `LiquidUnstakePool` `0xdF261F...`:
  - `ethBalance ≈ 1.2479` ETH.
  - `totalAssets ≈ 115.8940` ETH.
  - `totalSupply ≈ 96.5037` LP shares.
  - `STAKING` points to `0x48AF...`.
  - These values are consistent with `totalAssets() = ethBalance + Staking.convertToAssets(Staking.balanceOf(address(this)))`.

The pre-state σ_B definition in `root_cause.json` matches this evidence:

- Sigma_B definition: Ethereum mainnet state at block `22722952` immediately before the attacker’s mpETH/ETH priming swaps, covering:
  - MetaPool Staking/mpETH proxy `0x48AFbBd342F64EF8a9Ab1C143719b63C2AD81710`.
  - `LiquidUnstakePool` `0xdF261F967E87B2aa44e18a22f4aCE5d7f74f03Cc`.
  - `WETH9` `0xC02aa39b223FE8D0A0e5C4F27eAD9083C756Cc2`.
  - Attacker EOA `0x48f1d0f5831eb6e544f8cbde777b527b87a1be98`.

Relevant artifacts:
- Staking source: `artifacts/root_cause/seed/1/0x3747484567119592ff6841df399cf679955a111a/src/Staking.sol`.
- LiquidUnstakePool source: `artifacts/root_cause/seed/1/0x3747484567119592ff6841df399cf679955a111a/src/LiquidUnstakePool.sol`.
- Storage snapshots: `artifacts/root_cause/data_collector/iter_3/storage_snapshots_pre_priming.json`.

---

## Vulnerability Analysis

### High-level Vulnerability

A mismatch between how `Staking.depositETH` / `_getmpETHFromPool` updates `totalUnderlying` and how `LiquidUnstakePool.totalAssets` and `swapETHFormpETH` / `swapmpETHforETH` compute and value mpETH allows the pool to treat the same underlying ETH as backing both the global mpETH supply and the pool’s mpETH position. This cross-contract accounting bug enables systematic extraction of ETH: an attacker can route ETH into `LiquidUnstakePool` in a way that barely increases global `totalUnderlying`, but still inflates the pool’s `totalAssets`, and then redeem against that inflated view via `swapmpETHforETH`.

### Code Evidence: LiquidUnstakePool Accounting

Key parts of `LiquidUnstakePool.sol`:

```solidity
// Collected contract source (verified on explorer) for LiquidUnstakePool 0xdF261F...03Cc
function totalAssets() public view override returns (uint256) {
    return
        ethBalance +
        Staking(STAKING).convertToAssets(Staking(STAKING).balanceOf(address(this)));
}

function swapmpETHforETH(
    uint256 _amount,
    uint256 _minOut
) external nonReentrant returns (uint256) {
    address payable staking = STAKING;
    (uint256 amountOut, uint256 feeAmount) = getAmountOut(_amount);
    if (amountOut < _minOut) revert SwapMinOut(_minOut, amountOut);
    uint256 feeToTreasury = (feeAmount * treasuryFee) / 10000;
    ethBalance -= amountOut;
    IERC20Upgradeable(staking).safeTransferFrom(msg.sender, address(this), _amount);
    if (feeToTreasury != 0) IERC20Upgradeable(staking).safeTransfer(treasury, feeToTreasury);
    payable(msg.sender).sendValue(amountOut);
    emit Swap(msg.sender, _amount, amountOut, feeAmount, feeToTreasury);
    return amountOut;
}
```

Caption: `LiquidUnstakePool.totalAssets` and `swapmpETHforETH` show that pool `totalAssets` values its mpETH position using the global mpETH share price and pays out ETH solely based on this accounting and `ethBalance`, with no cross-check against Staking’s `totalUnderlying`.

### Vulnerable Components

From the `Vulnerability & Root Cause Analysis` section:

- MetaPool Staking proxy `0x48AFbBd342F64EF8a9Ab1C143719b63C2AD81710` / implementation `0x3747484567119592ff6841df399cf679955a111a`:
  - Functions: `depositETH`, `_deposit`, `_getmpETHFromPool`, `totalUnderlying`, `totalAssets`, `convertToAssets`.
- `LiquidUnstakePool` `0xdF261F967E87B2aa44e18a22f4aCE5d7f74f03Cc`:
  - Functions: `totalAssets`, `swapETHFormpETH`, `swapmpETHforETH`, `getAmountOut`, `getEthForValidator`.

### Exploit Preconditions

The exploit requires:

- `LiquidUnstakePool` configured as `STAKING`’s pool and holding a non-trivial mpETH balance so that `swapETHFormpETH` can move large amounts of ETH into the pool while reducing its mpETH position.
- `Staking.checkWhitelisting` effectively disabled on `depositETH` (`whitelistEnabled == false`), so any EOA or contract (including the attacker’s helper) can call `depositETH` and reach `_getmpETHFromPool`.
- mpETH share price sufficiently above 1 (≈`1.10287` ETH/mpETH at block `22722952`), so that swapping ETH for mpETH then mpETH for ETH through `LiquidUnstakePool` creates an accounting gap rather than being constrained by reserves.
- No external invariant checks or circuit breakers in `LiquidUnstakePool` to prevent paying out ETH solely based on its own `totalAssets` accounting even when that accounting double-counts backing from `Staking.totalUnderlying`.

### Violated Security Principles

- Conservation of value: the same underlying ETH is counted twice (in global mpETH backing and in `LiquidUnstakePool.totalAssets`), violating conservation of assets across accounting domains.
- Robust invariant design: `totalUnderlying` and `totalAssets` are not kept in sync across Staking and `LiquidUnstakePool`, breaking invariants such as “user claims never exceed backed ETH”.
- Least privilege / surface minimization: allowing an unwhitelisted helper contract to route large volumes of ETH through `depositETH` into `LiquidUnstakePool` without additional checks exposes a powerful, publicly callable attack surface.

---

## Detailed Root Cause Analysis

### Staking Deposit and mpETH Sourcing Logic

In `Staking.sol`, the deposit path is:

```solidity
// Collected MetaPool Staking implementation for mpETH
function depositETH(address _receiver) public payable returns (uint256) {
    uint256 _shares = previewDeposit(msg.value);
    _deposit(msg.sender, _receiver, msg.value, _shares);
    return _shares;
}

function _deposit(
    address _caller,
    address _receiver,
    uint256 _assets,
    uint256 _shares
) internal override checkWhitelisting {
    if (_assets < MIN_DEPOSIT) revert DepositTooLow(MIN_DEPOSIT, _assets);
    (uint256 sharesFromPool, uint256 assetsToPool) = _getmpETHFromPool(_shares, address(this));
    uint256 sharesToMint = _shares - sharesFromPool;
    uint256 assetsToAdd = _assets - assetsToPool;

    if (sharesToMint > 0) _mint(address(this), sharesToMint);
    totalUnderlying += assetsToAdd;
    ...
}
```

```solidity
function _getmpETHFromPool(
    uint256 _shares,
    address _receiver
) private returns (uint256 sharesFromPool, uint256 assetsToPool) {
    if (msg.sender != liquidUnstakePool) {
        sharesFromPool = MathUpgradeable.min(balanceOf(liquidUnstakePool), _shares);

        if (sharesFromPool > 0) {
            assetsToPool = previewMint(sharesFromPool);
            assert(
                LiquidUnstakePool(liquidUnstakePool).swapETHFormpETH{value: assetsToPool}(
                    _receiver
                ) == sharesFromPool
            );
        }
    }
}
```

Caption: Staking’s `_deposit` and `_getmpETHFromPool` show that only `assetsToAdd = _assets - assetsToPool` is added to `totalUnderlying`, while a potentially large `assetsToPool` amount of ETH is forwarded to `LiquidUnstakePool.swapETHFormpETH`, effectively moving backing ETH into the pool without fully reflecting it in `totalUnderlying`.

### LiquidUnstakePool Swap and Total Assets Logic

From the same LiquidUnstakePool source:

```solidity
function swapETHFormpETH(
    address _to
    ) external payable nonReentrant onlyStaking returns (uint256) {
    address payable staking = STAKING;
    uint256 mpETHToSend = Staking(staking).previewDeposit(msg.value);
    IERC20Upgradeable(staking).safeTransfer(_to, mpETHToSend);
    ethBalance += msg.value;
    return mpETHToSend;
}
```

Caption: `swapETHFormpETH` transfers mpETH to the caller based on `previewDeposit(msg.value)` and simply increments `ethBalance` by `msg.value` without altering any Staking accounting. Combined with `totalAssets()`, this means the same ETH can be reflected both in global mpETH backing (`convertToAssets`) and in the pool’s `ethBalance`.

### Mechanism of Double Counting and Exploitability

During the seed flash-loan transaction `0x57ee419a001d85085478d04dd2a73daa91175b1d7c11d8a8fb5622c56fd1fa69`, the helper contract:

1. Obtains a `200` WETH flash loan from Balancer Vault `0xBA12222222228d8Ba445958a75a0704d566BF2C8`.
2. Unwraps `107` WETH into ETH via `WETH9` `0xC02aa39b223FE8D0A0e5C4F27eAD9083C756Cc2`.
3. Calls `Staking.depositETH` via proxy `0x48AF...`.
4. Inside `depositETH`, `_getmpETHFromPool`:
   - Computes `sharesFromPool` from the pool’s existing mpETH balance.
   - Uses `previewMint(sharesFromPool)` to compute `assetsToPool`.
   - Calls `LiquidUnstakePool.swapETHFormpETH{value: assetsToPool}(_receiver)`.
5. Only `assetsToAdd = msg.value - assetsToPool` is added to `totalUnderlying`.

Trace and balance diff evidence (`artifacts/root_cause/seed/1/0x57ee.../balance_diff.json` and `debug_trace_prestate.json`) show:

- Of the `107` ETH, ≈`106.910422650390972178` ETH is forwarded to `LiquidUnstakePool` via `swapETHFormpETH`.
- `LiquidUnstakePool` sells ≈`96.938281985300295162` mpETH from its holdings.
- Staking mints only ≈`0.081221962841655763` new mpETH, so the helper receives ≈`97.019503948141950925` mpETH in total.
- `LiquidUnstakePool.ethBalance` increases sharply (from ≈`0.2237` ETH to ≈`107.1341` ETH) while its mpETH holdings decrease.
- `Staking.totalUnderlying` increases by only ≈`0.089577349609027822` ETH (the residual `assetsToAdd`).

Meanwhile, `LiquidUnstakePool.totalAssets` remains roughly unchanged because the large increase in `ethBalance` is offset by the reduction in the pool’s mpETH, both valued using the global mpETH share price via `convertToAssets`. Net effect:

- The same ETH effectively backs:
  - The global mpETH supply (through Staking’s `totalUnderlying`/`totalAssets`).
  - `LiquidUnstakePool`’s `totalAssets`, which is subsequently used to price `swapmpETHforETH` payouts.
- This double counting lets the attacker later withdraw ETH against an inflated `totalAssets` without a corresponding reduction in `totalUnderlying`.

Subsequent `swapmpETHforETH` priming trades (described below) exploit this inflated accounting, converting mpETH into more ETH than the protocol should allow.

---

## Adversary Flow Analysis

### Adversary Strategy Summary

From the `Adversary Flow Analysis` section:

- The adversary uses a Balancer flash loan and MetaPool’s misaligned accounting between Staking and `LiquidUnstakePool` to:
  1. Route a large amount of ETH into `LiquidUnstakePool` in a way that barely increases global `totalUnderlying` but inflates the pool’s `totalAssets`.
  2. Repeatedly call `swapmpETHforETH` to pull ETH out against this inflated accounting.
  3. End with a net ETH profit and a non-trivial residual mpETH position.

### Adversary-Related Accounts

Adversary cluster:

- `0x48f1d0f5831eb6e544f8cbde777b527b87a1be98`
  - Chain: Ethereum (chainid 1).
  - Type: EOA (`is_eoa = true`, `is_contract = false`).
  - Role: Attacker EOA that originates the flash-loan exploit tx `0x57ee...` and all four priming `swapmpETHforETH` transactions, and receives the final ETH and mpETH profit (confirmed via txlists and balance diffs).
- `0xC3D10bd8e051a2bE6408d18Be8464654F699a25a`
  - Chain: Ethereum (chainid 1).
  - Type: Contract (`is_eoa = false`, `is_contract = true`).
  - Role: Helper contract deployed by the attacker EOA in the seed tx; orchestrates the Balancer flash loan, WETH unwrap, Staking `depositETH` call, `LiquidUnstakePool` swaps, and Uniswap V3 trades before returning ETH to the EOA.

Victim candidates:

- MetaPool Staking/mpETH proxy:
  - Address: `0x48AFbBd342F64EF8a9Ab1C143719b63C2AD81710`.
  - Chain: Ethereum (chainid 1).
  - Verified source: `true`.
- MetaPool `LiquidUnstakePool`:
  - Address: `0xdF261F967E87B2aa44e18a22f4aCE5d7f74f03Cc`.
  - Chain: Ethereum (chainid 1).
  - Verified source: `true`.
- MetaPool Staking implementation:
  - Address: `0x3747484567119592ff6841df399cf679955a111a`.
  - Chain: Ethereum (chainid 1).
  - Verified source: `true`.

### Adversary Lifecycle Stages

Stages from `root_cause.json`:

1. **Adversary setup and contract deployment**
   - Transactions:
     - `0xc7bb2e6dc19efa4b035b419156230a2e1b91b0b7551c32146bebb346696bcf2b` (contract deployment).
     - Seed exploit tx `0x57ee419a001d85085478d04dd2a73daa91175b1d7c11d8a8fb5622c56fd1fa69`.
     - Chain: Ethereum (chainid 1).
   - Mechanism: `contract_deploy` and `flashloan_and_deposit`.
   - Effect:
     - Attacker EOA deploys helper contract `0xC3D1...`.
     - In tx `0x57ee...`, the helper:
       - Obtains a 200 WETH flash loan from Balancer Vault `0xBA1222...`.
       - Unwraps 107 WETH to ETH via WETH9 `0xC02a...`.
       - Calls `Staking.depositETH` via proxy `0x48AF...`.
     - Inside `depositETH`, `_getmpETHFromPool` sends ≈`106.91` ETH to `LiquidUnstakePool.swapETHFormpETH`, sources ≈`96.94` mpETH from the pool, mints a small amount of new mpETH, and returns ≈`97.02` mpETH to the helper.
   - Evidence:
     - `artifacts/root_cause/seed/1/0x57ee.../trace.cast.log`.
     - `artifacts/root_cause/seed/1/0x57ee.../balance_diff.json`.
     - `artifacts/root_cause/data_collector/iter_1/tx/1/0x57ee.../debug_trace_prestate.json`.

2. **Exploit execution via misaligned accounting**
   - Transaction:
     - `0x57ee419a001d85085478d04dd2a73daa91175b1d7c11d8a8fb5622c56fd1fa69`.
   - Mechanism: `deposit_and_internal_swaps`.
   - Effect:
     - Within the same flash-loan tx, helper `0xC3D1...`:
       - Deposits 107 ETH into Staking via `depositETH`.
       - `_getmpETHFromPool` forwards ≈`106.9104` ETH to `LiquidUnstakePool.swapETHFormpETH`, inflating `ethBalance` while reducing the pool’s mpETH balance.
       - Staking adds only ≈`0.0896` ETH to `totalUnderlying`.
     - This creates the accounting mismatch: `LiquidUnstakePool.totalAssets` stays roughly constant (due to ethBalance vs mpETH offset), while Staking’s `totalUnderlying` barely increases, effectively double-counting the backing.
   - Evidence:
     - Staking and `LiquidUnstakePool` source files.
     - `artifacts/root_cause/seed/1/0x57ee.../balance_diff.json`.

3. **Priming swaps and profit realization**
   - Transactions (all Ethereum, chainid 1):
     - `0x6d9c3a6a06c4cf134201b0a58f03e01d9a0711d352f1241cd33a92c7d7d05cef` (block `22722953`), mechanism `swapmpETHforETH`.
     - `0x2d2541b4e2d0e703aa574065ee17cd8b0e0da181ce72020f0504fc197b9284c1` (block `22722957`), mechanism `swapmpETHforETH`.
     - `0xd64f18032f317528c979320918b43416ea3d201275e58735a5ed147aa04485ea` (block `22722960`), mechanism `swapmpETHforETH`.
     - `0x5669c531f338a6e4a5aa5b739ba7beaeff27965c3b7ed2f94f9b3692d680d1c2` (block `22722993`), mechanism `swapmpETHforETH`.
   - Aggregate effect:
     - Attacker spends in total `1.1 + 0.09 + 0.05 + 0.01 = 1.25` mpETH (with small fees to a third address).
     - Attacker receives:
       - `1.091804585354437441` ETH.
       - `0.089188476659049504` ETH.
       - `0.049459908042643449` ETH.
       - `0.009734377693377201` ETH.
     - Aggregate attacker ETH gain: `1.240187347749507595` ETH.
     - `LiquidUnstakePool.ethBalance` decreases by ≈`1.2409` ETH.
     - `LiquidUnstakePool` mpETH holdings increase by ≈`1.2188` mpETH.
     - These swaps draw on an already inflated `LiquidUnstakePool.totalAssets`, fueled by the earlier depositETH / `_getmpETHFromPool` interaction.
   - Evidence:
     - `artifacts/root_cause/data_collector/iter_2/tx/1/0x6d9c3.../balance_diff_prestate.json`.
     - `.../0x2d2541.../balance_diff_prestate.json`.
     - `.../0xd64f18.../balance_diff_prestate.json`.
     - `.../0x5669c5.../balance_diff_prestate.json`.

   Example trace snippet (first priming swap):

```json
{
  "chainid": 1,
  "txhash": "0x6d9c3a6a06c4cf134201b0a58f03e01d9a0711d352f1241cd33a92c7d7d05cef",
  "native_balance_deltas": [
    {
      "address": "0xdf261f967e87b2aa44e18a22f4ace5d7f74f03cc",
      "before_wei": "1247917464397876056",
      "after_wei": "155953800521207831",
      "delta_wei": "-1091963663876668225"
    },
    {
      "address": "0x48f1d0f5831eb6e544f8cbde777b527b87a1be98",
      "before_wei": "10537779214453064010",
      "after_wei": "11629583799807501451",
      "delta_wei": "1091804585354437441"
    }
  ]
}
```

Caption: Seed transaction trace (prestate balance diff) for priming `swapmpETHforETH` tx `0x6d9c3...` showing `LiquidUnstakePool` losing ≈`1.0919` ETH while the attacker EOA gains ≈`1.0918` ETH.

4. **Post-exploit cleanup and partial redemptions**
   - Transaction:
     - `0xe58cd72c700d54ea6e94c48b0d5b622fa88c539ca95684a9b97c51240ab7ab84` (block `22723311`), mechanism `redeem`.
   - Effect:
     - Attacker burns 33 mpETH and receives a small amount of ETH plus mpETH.
     - Balance diffs show attacker ETH balance changes by only ≈`-0.000195372422454402` ETH, not materially affecting overall profit.
   - Evidence:
     - `artifacts/root_cause/data_collector/iter_2/tx/1/0xe58cd7.../balance_diff_prestate.json`.

### Transaction Sequence b and Feasibility

Transaction sequence b (all on Ethereum, chainid 1):

1. Index 1 — `0x57ee419a001d85085478d04dd2a73daa91175b1d7c11d8a8fb5622c56fd1fa69`
   - Type: `adversary-crafted`.
   - Inclusion feasibility:
     - Unprivileged attacker EOA `0x48f1...` can deploy helper `0xC3D1...`.
     - Helper can request a 200 WETH flash loan from Balancer Vault `0xBA1222...`.
     - Can unwrap WETH via WETH9 `0xC02a...`.
     - Can call MetaPool `Staking.depositETH` via proxy `0x48AF...`.
     - All contracts are publicly deployed and callable with arbitrary calldata and gas price.
   - Notes: Flash-loan-backed exploit transaction performing the deposit and initial swaps.

2. Index 2 — `0x6d9c3a6a06c4cf134201b0a58f03e01d9a0711d352f1241cd33a92c7d7d05cef`
   - Type: `adversary-crafted`.
   - Inclusion feasibility:
     - `LiquidUnstakePool.swapmpETHforETH` is permissionless and relies only on on-chain state.
     - Any EOA with mpETH can reproduce the trade with the same calldata and gas price.
   - Notes: First priming swap; attacker spends `1.1` mpETH, receives `~1.0918` ETH; pool’s mpETH balance increases by `~1.0725` mpETH.

3. Index 3 — `0x2d2541b4e2d0e703aa574065ee17cd8b0e0da181ce72020f0504fc197b9284c1`
   - Type: `adversary-crafted`.
   - Inclusion feasibility: Same as other priming trades; permissionless `swapmpETHforETH`.
   - Notes: Second priming swap; attacker gains `0.089188476659049504` ETH while `LiquidUnstakePool` loses slightly more ETH and its mpETH holdings increase by `~0.0877545` mpETH.

4. Index 4 — `0xd64f18032f317528c979320918b43416ea3d201275e58735a5ed147aa04485ea`
   - Type: `adversary-crafted`.
   - Inclusion feasibility: Same as other priming swaps.
   - Notes: Third priming swap; attacker gains `0.049459908042643449` ETH and spends `0.05` mpETH; `LiquidUnstakePool.ethBalance` decreases by `~0.049629197867783873` ETH while its mpETH holdings increase by `0.04875` mpETH.

5. Index 5 — `0x5669c531f338a6e4a5aa5b739ba7beaeff27965c3b7ed2f94f9b3692d680d1c2`
   - Type: `adversary-crafted`.
   - Inclusion feasibility: Permissionless call to `swapmpETHforETH` once attacker holds mpETH.
   - Notes: Fourth priming swap; attacker gains `0.009734377693377201` ETH and spends `0.01` mpETH; `LiquidUnstakePool.ethBalance` falls by `~0.009925839808773673` ETH and its mpETH balance increases by `0.00975` mpETH.

All transactions in sequence b are feasible for an unprivileged attacker under standard Ethereum transaction rules.

---

## Impact & Losses

### Quantified Profit Predicate

The ACT opportunity’s success predicate is of type `profit` with reference asset `ETH`. From `success_predicate.profit`:

- Reference asset: `ETH`.
- Adversary address: `0x48f1d0f5831eb6e544f8cbde777b527b87a1be98`.
- `fees_paid_in_reference_asset`: `0.028242175905358094` ETH (gas fees).
- `value_before_in_reference_asset`: `1.673583796061396325` ETH.
- `value_after_in_reference_asset`: `11.778037452730425619` ETH.
- `value_delta_in_reference_asset`: `10.104453656669029294` ETH.

Valuation notes (summarized):

- Reference asset is native ETH on Ethereum mainnet.
- `value_before` is the attacker EOA’s ETH balance immediately before tx `0x57ee...`, obtained from `balance_diff_prestate.json` as `1673583796061396325` wei.
- `value_delta` is computed as the sum of the attacker’s `native_balance_deltas` across the five adversary-crafted transactions (flash-loan tx plus four priming swaps), totaling `10.104453656669029294` ETH.
- `value_after` is `value_before + value_delta`, yielding `11.778037452730425619` ETH.
- Gas fees for these five txs are computed from `normal_txs.json` as the sum of `gasUsed * gasPrice`, giving `0.028242175905358094` ETH.

Consistency check:

- `value_after - value_before = 11.778037452730425619 - 1.673583796061396325 = 10.104453656669029294` ETH, matching `value_delta`.
- Net ETH gain after gas: `10.104453656669029294 - 0.028242175905358094 = 10.0762114807636712` ETH (approx).

### Protocol Impact

From the “Impact & Losses” section:

- Total loss overview:
  - Token: `ETH`.
  - Amount: `10.104453656669029294` ETH.
- Narrative impact:
  - Across the identified adversary-crafted sequence b, MetaPool’s `LiquidUnstakePool` and `WETH9` collectively transfer approximately `10.104453656669029294` ETH of net value to the attacker cluster, after accounting for internal flows.
  - These amounts are realized entirely via public calls driven by a protocol accounting bug.
  - Any other searcher observing the same state could replicate the strategy as long as the vulnerability remains unpatched and sufficient liquidity is present.

The `all_relevant_txs` list in `root_cause.json` matches the described transactions:

- `0x57ee419a001d85085478d04dd2a73daa91175b1d7c11d8a8fb5622c56fd1fa69` — adversary-crafted (seed exploit).
- `0x6d9c3a6a06c4cf134201b0a58f03e01d9a0711d352f1241cd33a92c7d7d05cef` — adversary-crafted (priming swap 1).
- `0x2d2541b4e2d0e703aa574065ee17cd8b0e0da181ce72020f0504fc197b9284c1` — adversary-crafted (priming swap 2).
- `0xd64f18032f317528c979320918b43416ea3d201275e58735a5ed147aa04485ea` — adversary-crafted (priming swap 3).
- `0x5669c531f338a6e4a5aa5b739ba7beaeff27965c3b7ed2f94f9b3692d680d1c2` — adversary-crafted (priming swap 4).
- `0xe58cd72c700d54ea6e94c48b0d5b622fa88c539ca95684a9b97c51240ab7ab84` — related (representative redeem).

---

## References

The following references correspond exactly to `root_cause.json.sections["References"].refs`:

- `[1]` Seed exploit tx `0x57ee...` trace and balance diff  
  - `artifacts/root_cause/seed/1/0x57ee419a001d85085478d04dd2a73daa91175b1d7c11d8a8fb5622c56fd1fa69`

- `[2]` Priming `swapmpETHforETH` txs `balance_diff_prestate.json`  
  - `artifacts/root_cause/data_collector/iter_2/tx/1`

- `[3]` MetaPool Staking and LiquidUnstakePool source code  
  - `artifacts/root_cause/seed/1/0x3747484567119592ff6841df399cf679955a111a/src`

- `[4]` Pre-priming storage snapshots for Staking and LiquidUnstakePool  
  - `artifacts/root_cause/data_collector/iter_3/storage_snapshots_pre_priming.json`

- `[5]` Attacker EOA normal and internal txlists  
  - `artifacts/root_cause/data_collector/iter_1/address/1`

