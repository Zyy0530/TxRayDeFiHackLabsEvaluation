## Incident Overview & TL;DR

On Ethereum mainnet, externally owned account (EOA) `0xEA6f30e360192bae715599E15e2F765B49E4da98` executed transaction `0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d` to router contract `0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09`. The router spent the user’s LiquidityToken and WstETH balances via CorkHook `0x5287E8915445aee78e10190559D8Dd21E0E9Ea88` and the Uniswap v4 PoolManager, minted Asset token balances for protocol-related addresses, and transferred `0.01589276` ETH to `0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97`. The sender ended the transaction with zero WstETH, reduced ETH, and exposure to Asset tokens instead of liquid WstETH. No evidence of an ACT-style, repeatable adversarial profit opportunity is present in the collected on-chain data.

The root cause is a user-initiated router swap into a CorkHook/Asset configuration that is economically unfavorable for the user, leaving them with protocol-side Asset positions rather than liquid WstETH, without any unprivileged adversary transaction sequence satisfying the ACT definition.

## Key Background

- CorkHook `0x5287E8915445aee78e10190559D8Dd21E0E9Ea88` is a Uniswap v4 hook that manages pools between a reserve asset (WstETH) and claim tokens, using LiquidityToken and Asset ERC20 contracts. Its implementation is available under `artifacts/root_cause/data_collector/iter_1/contract/1/0x5287E8915445aee78e10190559D8Dd21E0E9Ea88/source/lib/Cork-Hook/src` and defines how WstETH flows are converted into Asset positions.
- HookForwarder `0xCCd90F6435dd78C4ECCED1FA4db0D7242548a2a9` is constructed by CorkHook and exposes operational functions such as `initializePool`, `swap`, `forwardToken`, and `CorkCall`, restricted by `onlyOwner` so that only CorkHook can invoke them, as shown in `Forwarder.sol` in the same source tree.
- Router `0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09` is the `to` address for the main swap transaction and forwards user parameters into CorkHook and the Uniswap v4 PoolManager. Its bytecode is present in `artifacts/root_cause/data_collector/iter_1/contract/1/0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09/code_check.json`; no verified source directory for this router is included in the artifacts.
- Seed transactions:
  - `0x89ba58edaf9f40dc0c781c40351ba392be31263faa6be3a29c2ee152f271df6d` and `0xb54308956e58fc124503e01eaae153e54eb738fd188e476460dba78e61793b45` are ERC20 approvals from `0xEA6f30e360192bae715599E15e2F765B49E4da98` to router `0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09` for LiquidityToken `0x05816980faec123deae7233326a1041f372f4466` and WstETH `0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0`.
  - `0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d` is the main router swap executed by the same EOA.

## Vulnerability Analysis & Root Cause Summary

- The analyzed incident consists of a single user EOA granting allowances and then calling a router that executes a CorkHook swap. There is no additional transaction sequence that forms an adversarial, permissionless strategy meeting the ACT criteria.
- The swap converts the user’s WstETH and LiquidityToken balances into Asset token positions held by protocol-related addresses, while the user exits with no WstETH and a net negative ETH change due to gas and small direct transfers.
- On-chain traces, balance diffs, and address txlists do not reveal any unprivileged adversary account or cluster with a net positive portfolio change in ETH, WstETH, or the Asset tokens that can be linked to this incident as a realizable ACT strategy.
- The root cause is therefore classified as “other”: a user-initiated router interaction that realizes an economically unfavorable outcome for the user, not an ACT opportunity.

## Detailed Root Cause Analysis

### Victim transaction and token flows

The primary victim transaction is:

- Chain: Ethereum mainnet (chainid 1)
- Tx: `0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d`
- From: `0xEA6f30e360192bae715599E15e2F765B49E4da98`
- To: router `0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09`

From the transaction metadata (`metadata.json`) and balance diff (`balance_diff.json`) for this tx:

- Native ETH deltas:
  - `0xEA6f30e360192bae715599E15e2F765B49E4da98`: `-0.041062287111204062` ETH
  - `0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97`: `+0.01589276` ETH
- WstETH deltas:
  - User `0xEA6f30e...`: `-0.996592406032878584` WstETH (entire balance removed)
  - Router `0x9Af3dCE...`: `+3.761877955369549831945` WstETH
  - CorkHook/forwarder-related addresses show internal WstETH movements consistent with routing through CorkHook and the forwarder.

The corresponding ERC20 balance diffs show Asset token mints and transfers:

- Asset `0x7ea0614072e2107c834365bea14f9b6386fb84a5` (Asset):
  - Router `0x9Af3dCE...`: `+0.373903773359104917` Asset
  - Proxy/forwarder `0xCCd90F64...`: `+0.001221975810202920` Asset
  - Treasury-like `0x000000000004444c5dc75cb358380d2e3de08a90`: `+1.000000000000001` Asset
  - `0x55b90b37416dc0bd936045a8110d1af3b6bf0fc3`: `-3.761257491693078379366` Asset
- Additional Asset contracts `0x1d2724ca345e1889cecddefa5f8f83666a442c86`, `0x51f70fe94e7ccd9f2efe45a4f2ea3a7ae0c62f8c`, and `0xde9d58d3347f0413772e35a5859559475008583d` mint or redistribute balances primarily among `0x9Af3dCE...`, `0x55b90b37...`, and `0x000000000004444c5dc75cb358380d2e3de08a90`.

The net effect is:

- The user’s WstETH balance decreases from `0.996592406032878584` to `0`.
- The user’s ETH decreases by `0.041062287111204062` ETH (gas and value transfers).
- Protocol-related addresses and the router receive Asset balances and WstETH, and `0x4838b1...` receives `0.01589276` ETH.

### Trace-based execution path

The Foundry trace `trace.cast.log` for the victim tx shows the high-level execution path:

```text
0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09::0f626b5a(...)
  ├─ LiquidityToken::balanceOf(0xEA6f30e3...)
  ├─ LiquidityToken::transferFrom(0xEA6f30e3..., ERC1967Proxy: [0xCCd90F64...], 10034249)
  ├─ WstETH::balanceOf(0xEA6f30e3...)
  ├─ WstETH::transferFrom(0xEA6f30e3..., 0x9Af3dCE..., 996592406032878584)
  ├─ ERC1967Proxy::fallback(..., AssetFactory::getDeployedSwapAssets(...))
  ├─ WstETH::approve(ERC1967Proxy: [0xCCd90F64...], max)
  ├─ ERC1967Proxy::fallback(..., ModuleCore::depositPsm(...))
  │   ├─ ExchangeRateProvider::rate(...)
  │   ├─ Asset::exchangeRate()
  │   ├─ WstETH::transferFrom(0x9Af3dCE..., ERC1967Proxy: [0xCCd90F64...], 4000000000000000)
  │   ├─ Asset::mint(0x9Af3dCE..., 4000000000000000)
  └─ ...
```

This trace confirms:

- The router pulls LiquidityToken and WstETH from the user via `transferFrom`.
- WstETH is passed into the CorkHook ecosystem via the ERC1967 proxy and `ModuleCore::depositPsm`, which consults an `ExchangeRateProvider` and mints Asset tokens.
- Asset tokens are minted to the router and other protocol-related addresses, consistent with the ERC20 balance diffs.

### CorkHook behavior and design

The CorkHook implementation under `CorkHook.sol` shows how swaps are mediated between reserve assets and claim tokens:

```solidity
function swap(address ra, address ct, uint256 amountRaOut, uint256 amountCtOut, bytes calldata data)
    external
    onlyInitialized(ra, ct)
    returns (uint256 amountIn)
{
    SortResult memory sortResult = sortPacked(ra, ct, amountRaOut, amountCtOut);
    sortResult = normalize(sortResult);

    _ensureValidAmount(sortResult.amount0, sortResult.amount1);

    bool zeroForOne = sortResult.amount0 <= 0;
    uint256 out = zeroForOne ? sortResult.amount1 : sortResult.amount0;

    {
        PoolState storage self = pool[toAmmId(sortResult.token0, sortResult.token1)];
        (amountIn,) = _getAmountIn(self, zeroForOne, out);
    }

    amountIn = toNative(zeroForOne ? sortResult.token0 : sortResult.token1, amountIn);
    out = toNative(zeroForOne ? sortResult.token1 : sortResult.token0, out);

    IPoolManager.SwapParams memory ammSwapParams =
        IPoolManager.SwapParams(zeroForOne, int256(out), Constants.SQRT_PRICE_1_1);

    SwapParams memory params;
    PoolKey memory key = getPoolKey(sortResult.token0, sortResult.token1);
    params = SwapParams(data, ammSwapParams, key, msg.sender, out, amountIn);

    poolManager.unlock(abi.encode(Action.Swap, params));
}
```

In conjunction with the forwarder and Asset contracts, this logic routes WstETH into Asset positions based on pool state and exchange rates. The victim tx uses the router and proxy to drive this CorkHook behavior, resulting in user WstETH being consumed and Asset tokens minted to protocol-related addresses.

### Classification as non-ACT

The ACT opportunity definition requires a permissionless, attacker-realizable strategy based on public on-chain data and observable transactions, yielding a positive profit or non-monetary success predicate for an adversary cluster, independent of cooperation from the victim.

From:

- `balance_diff.json` for `0xfd89cdd0...`,
- txlists under `artifacts/root_cause/data_collector/iter_3/address/1`,
- exchange rate and state snapshots under `artifacts/root_cause/data_collector/iter_3/state/1`,

we observe:

- The only entity taking a net negative WstETH position is the user EOA.
- Asset and WstETH flows among protocol addresses (`0x9Af3dCE...`, `0xCCd90F64...`, `0x55b90b37...`, `0x000000000004444c5dc75cb358380d2e3de08a90`) are consistent with protocol operations and treasury management.
- Address `0x4838b1...` receives `0.01589276` ETH in the victim tx and, in the sampled window, predominantly sends small ETH transfers to many unrelated addresses, consistent with a payment or payout sink rather than a targeted exploit beneficiary.
- No additional transactions in the collected window form a cycle where an unprivileged adversary invests assets, interacts with the protocol, and withdraws more value than invested in a repeatable strategy tied to this incident.

Therefore, the incident is correctly classified as non-ACT.

## Adversary Flow Analysis

### Participants and roles

The relevant accounts and contracts include:

- Victim EOA: `0xEA6f30e360192bae715599E15e2F765B49E4da98`
- Router: `0x9Af3dCE0813FD7428c47F57A39da2F6Dd7C9bb09`
- CorkHook: `0x5287E8915445aee78e10190559D8Dd21E0E9Ea88`
- HookForwarder (ERC1967 proxy): `0xCCd90F6435dd78C4ECCED1FA4db0D7242548a2a9`
- Asset-related addresses:
  - `0x55b90b37416dc0bd936045a8110d1af3b6bf0fc3`
  - `0x000000000004444c5dc75cb358380d2e3de08a90`
  - Asset contracts `0x7ea06140...`, `0x1d2724ca...`, `0x51f70fe9...`, `0xde9d58d3...`
- ETH recipient: `0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97`

### Lifecycle stages

1. **User ERC20 approvals to router**
   - Tx `0x89ba58edaf9f40dc0c781c40351ba392be31263faa6be3a29c2ee152f271df6d`:
     - Approves LiquidityToken `0x05816980faec123deae7233326a1041f372f4466` to router `0x9Af3dCE...`.
   - Tx `0xb54308956e58fc124503e01eaae153e54eb738fd188e476460dba78e61793b45`:
     - Approves WstETH `0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0` to router `0x9Af3dCE...`.
   - These approvals are standard ERC20 allowance transactions initiated by the user and necessary for the router to pull tokens in the subsequent swap.

2. **User router swap through CorkHook**
   - Tx `0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d`:
     - Router `0x9Af3dCE...` calls into CorkHook and the proxy `0xCCd90F64...`.
     - WstETH and LiquidityToken are transferred from the user to router and proxy.
     - `ModuleCore::depositPsm` and related Asset logic are invoked to convert WstETH into Asset positions.
     - Asset tokens are minted and redistributed among protocol-related addresses and the router.
     - `0x4838b1...` receives `0.01589276` ETH.

### Adversary cluster assessment

Using:

- `balance_diff.json` for the victim tx,
- txlists under `artifacts/root_cause/data_collector/iter_3/address/1`,

we see:

- `0xEA6f30e...` never receives compensating inflows that offset the WstETH and ETH loss in the analyzed window.
- `0x9Af3dCE...`, `0xCCd90F64...`, `0x55b90b37...`, and `0x000000000004444c5dc75cb358380d2e3de08a90` behave as infrastructure or protocol addresses (router, proxy, treasury-like holdings and Asset positions) rather than as an adversary-controlled profit-taking set.
- `0x4838b1...` exhibits high-volume, small ETH payments to many addresses in `txlist.json`, consistent with a generic payout or distribution pattern; there is no evidence of a targeted strategy to repeatedly exploit users of this router.
- No cluster of addresses shows a net positive portfolio change in ETH, WstETH, or Assets that can be systematically tied to this user’s loss in a way that would constitute a permissionless ACT opportunity.

Accordingly, no adversary account set matching the ACT criteria is identified.

## Impact & Losses

From `balance_diff.json` and state snapshots:

- **Victim EOA (`0xEA6f30e...`)**
  - WstETH: `-0.996592406032878584`
  - ETH: `-0.041062287111204062`
  - Net position: entirely loses its WstETH balance and spends additional ETH on gas and small value transfers in the swap.
- **ETH recipient (`0x4838b1...`)**
  - Receives `+0.01589276` ETH in the victim tx.
- **Protocol and pool-related addresses**
  - Hold increased Asset balances and WstETH/Asset state consistent with protocol-side accounting of the CorkHook swap.
  - No protocol treasury or pool contract shows a net negative ETH or WstETH change in the main swap that would classify it as the primary victim in this incident.

Overall, the economic loss is borne by the user EOA, which converts its WstETH into exposure to Asset tokens and ends with lower liquid ETH and no WstETH.

## References

- [1] Main swap transaction artifacts for `0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d`:
  - `artifacts/root_cause/seed/1/0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d/metadata.json`
  - `artifacts/root_cause/seed/1/0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d/trace.cast.log`
  - `artifacts/root_cause/seed/1/0xfd89cdd0be468a564dd525b222b728386d7c6780cf7b2f90d2b54493be09f64d/balance_diff.json`
- [2] Approval transaction metadata for LiquidityToken and WstETH:
  - `artifacts/root_cause/seed/1/0x89ba58edaf9f40dc0c781c40351ba392be31263faa6be3a29c2ee152f271df6d/metadata.json`
  - `artifacts/root_cause/seed/1/0xb54308956e58fc124503e01eaae153e54eb738fd188e476460dba78e61793b45/metadata.json`
- [3] CorkHook, HookForwarder, LiquidityToken, and Asset contract source:
  - `artifacts/root_cause/data_collector/iter_1/contract/1/0x5287E8915445aee78e10190559D8Dd21E0E9Ea88/source`
- [4] Address txlists and Asset state snapshots:
  - `artifacts/root_cause/data_collector/iter_3/address/1`
  - `artifacts/root_cause/data_collector/iter_3/state/1`

