# Gradient GRAY Pool Mis-Accounting Exploit via Pre-Funded LP Zero-Share Bug

## Incident Overview TL;DR

An adversary-controlled EOA used a custom helper contract to drain protocol-funded ETH from the
Gradient GRAY pool in a single flash-loan-assisted transaction, then consolidated GRAY profits to
the EOA and sold them for ETH via public DEX routers. The exploit relies on a mis-accounting bug in
GradientMarketMakerPool where protocol-owned liquidity is added to
totalEth/totalToken/totalLiquidity without minting LP shares, allowing the first market maker to
withdraw almost all protocol ETH while only contributing a small amount of ETH and GRAY.

GradientMarketMakerPool treats a pool with totalLPShares == 0 as empty even when it contains
protocol-funded liquidity, minting LP shares only for the attacker deposit but allowing
withdrawLiquidity to claim a pro-rata share of the entire pool (including protocol funds), which
enables a deterministic, permissionless drain of pre-funded pools by any unprivileged attacker.

## Key Background

GradientMarketMakerPool is a pool-based market maker where each token has a PoolInfo struct
(totalEth, totalToken, totalLiquidity, totalLPShares, accRewardPerShare, rewardBalance, uniswapPair)
and per-address MarketMaker entries tracking shares and entry values. Liquidity providers normally
receive LP shares proportional to their deposits, and withdrawLiquidity burns shares in exchange for
a proportional share of the pool's ETH and token balances.

Protocol-owned liquidity is injected into pools by Gradient's orderbook/registry contracts via
receiveETHFromOrderbook and receiveTokenFromOrderbook, which increase
totalEth/totalToken/totalLiquidity but intentionally do not mint LP shares, so the protocol retains
a non-withdrawable cushion of liquidity if accounting is correct.

The exploited GRAY pool was pre-funded by the protocol before the adversary's attack: decoded state
shows totalEth=3.022481813096655000 ETH, totalToken=0, totalLiquidity=3.022481813096655000, and
totalLPShares=0 immediately before the seed exploit tx, meaning all liquidity belonged to the
protocol but was unprotected by LP share accounting.

UniswapV2-style pair 0x0846F55387ab118B4E59eee479f1a3e8eA4905EC provides public GRAY/WETH liquidity;
contract source for this pair is available under
artifacts/root_cause/data_collector/iter_1/contract/1/0x0846F5.../source, confirming it is a
standard UniswapV2 pair and enabling deterministic interpretation of reserve changes during the
exploit.

## Vulnerability Analysis

GradientMarketMakerPool mis-accounts protocol-owned liquidity by adding it to
totalEth/totalToken/totalLiquidity without minting LP shares, while provideLiquidity treats any pool
with totalLPShares == 0 as empty and mints LP shares only for the new depositor, enabling that
depositor to withdraw a share of the entire pool that exceeds their contribution.

Key vulnerable components:
- GradientMarketMakerPool.sol::receiveETHFromOrderbook
- GradientMarketMakerPool.sol::receiveTokenFromOrderbook
- GradientMarketMakerPool.sol::provideLiquidity
- GradientMarketMakerPool.sol::withdrawLiquidity

Exploit conditions:
- A GradientMarketMakerPool token pool must be pre-funded by protocol-owned liquidity via receiveETHFromOrderbook/receiveTokenFromOrderbook such that totalEth and/or totalToken are non-zero while totalLPShares remains 0.
- An unprivileged attacker must be able to acquire the pool's token (here, GRAY) from public markets (e.g., Uniswap GRAY/WETH pair) and call provideLiquidity and withdrawLiquidity without additional access controls.
- The pool’s provideLiquidity logic must treat totalLPShares == 0 as a signal of an empty pool and mint all LP shares to the first external depositor, instead of recognizing existing protocol liquidity and minting corresponding shares to a protocol-owned address.

Security principles violated:
- Conservation of value for LP share accounting: the protocol allows totalLiquidity to include value that is not backed by corresponding LP shares, breaking the invariant that shares represent proportional claims on pool assets.
- Separation of protocol-owned liquidity from user-owned liquidity: protocol-funded cushion capital is not protected by dedicated accounting and can be withdrawn by arbitrary users.
- Least-privilege and access-control expectations: a permissionless function (provideLiquidity) combined with incorrect accounting allows any unprivileged account to extract protocol funds.

## Detailed Root Cause Analysis

GradientMarketMakerPool maintains per-token PoolInfo and per-address MarketMaker structs. Protocol
components add liquidity for a token via receiveETHFromOrderbook and receiveTokenFromOrderbook,
which increment totalEth, totalToken, and totalLiquidity but deliberately do not increase
totalLPShares or any MarketMaker.shares. When an external user later calls provideLiquidity for that
token and totalLPShares == 0, the contract follows an 'initial LP' branch that sets newShares equal
to the minimum of the ETH and token contributions and mints those shares entirely to the caller,
implicitly treating all existing liquidity as if it were contributed by the caller. Subsequent
withdrawLiquidity computes the amounts of ETH and tokens to return as (pool.totalEth * sharesToBurn
/ pool.totalLPShares, pool.totalToken * sharesToBurn / pool.totalLPShares). In the incident, the
GRAY pool was pre-funded by the protocol with 3.022481813096655000 ETH and 0 GRAY, but totalLPShares
was still 0. The attacker acquired 1,000 GRAY via Uniswap, paid 0.632090074270700494 ETH and 950
GRAY into provideLiquidity as the first external market maker, and received LP shares equal to their
contribution while totalLiquidity was effectively the sum of protocol liquidity and attacker
deposits. Because totalLPShares now reflected only attacker shares, withdrawLiquidity allowed the
attacker to pull almost the entire pool's ETH (3.010899131704627093 ETH) out to WETH9 while leaving
the pool with only dust ETH and some GRAY, effectively converting protocol-funded liquidity into
attacker-owned assets.

### Illustrative Code and State Evidence

Gradient GRAY pool pre/post state around the exploit seed transaction (decoded PoolInfo):

```json
{
  "txhash": "0xb5cfa3f86ce9506e2364475dc43c44de444b079d4752edbffcdad7d1654b1f67",
  "pool_address": "0x37ea5f691bce8459c66ffceeb9cf34ffa32fdadc",
  "token": "0xa776a95223c500e81cb0937b291140ff550ac3e4",
  "pools_slot_index": 3,
  "marketMakers_slot_index": 4,
  "pool_slot_base": "0x35a35a0941ccfe30d19d7cda394e8682691c0bd19cb185f20ca3325520fac704",
  "pool_info": {
    "before": {
      "totalEth": 3022481813096655000,
      "totalToken": null,
      "totalLiquidity": 3022481813096655000,
      "totalLPShares": null,
      "accRewardPerShare": null,
      "rewardBalance": null,
      "uniswapPair": null
    },
    "after": {
      "totalEth": 11582681392027907,
      "totalToken": 3010899131704627094,
      "totalLiquidity": 3022481813096655001,
      "totalLPShares": null,
      "accRewardPerShare": null,
      "rewardBalance": null,
      "uniswapPair": null
    }
  },
  "market_makers": {
    "0xcb4059bb021f4cf9d90267b7961125210cedb792": {
      "before": {
        "tokenAmount": null,
        "ethAmount": null,
        "lpShares": null,
        "rewardDebt": null,
        "pendingReward": null
      },
      "after": {
        "tokenAmount": null,
        "ethAmount": null,
        "lpShares": null,
        "rewardDebt": 2251710443441616,
        "pendingReward": null
      }
    }
  },
  "notes": "MarketMakers include CB4059..., 37Ea5f..., 1234..., plus any GRAY ERC20 holders from balance diff with non-zero MarketMaker state."
}
```

This snapshot shows the GRAY pool starting with protocol-funded ETH, zero GRAY, and totalLPShares=0, then
ending with most ETH drained and GRAY concentrated while totalLPShares remains zero, matching the described bug.

Excerpt from the Gradient token contract (context for GRAY ERC20 and ownership):

```solidity
/* 

Gradient - Creating efficient markets beyond AMMs.

Website - https://gradient.trade
Telegram - https://t.me/useGradient
X - https://x.com/useGradient

*/

// File: @openzeppelin/contracts/utils/Context.sol


// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

pragma solidity ^0.8.20;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

// File: @openzeppelin/contracts/access/Ownable.sol


// OpenZeppelin Contracts (last updated v5.0.0) (access/Ownable.sol)

pragma solidity ^0.8.20;


/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * The initial owner is set to the address provided by the deployer. This can
 * later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    /**
     * @dev The caller account is not authorized to perform an operation.
     */
    error OwnableUnauthorizedAccount(address account);

    /**
     * @dev The owner is not a valid owner account. (eg. `address(0)`)
     */
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.
     */
    constructor(address initialOwner) {
```

## Adversary Flow Analysis

The adversary performs a single flash-loan-assisted pool drain to move protocol ETH into WETH and
GRAY, then consolidates the GRAY to the EOA and sells it for ETH via standard routers while paying
modest gas costs, achieving a net ETH profit using only permissionless contract calls.

Adversary-related accounts:
- 0x1234567a98230550894bf93e2346a8bc5c3b36e3 (EOA): Seed EOA that deploys helper contract 0x58117e82Fa6522703493878f27c85c1702FedcCA in the exploit tx, originates all attacker-crafted transactions in sequence b, and receives the final ETH profit.
- 0x58117e82Fa6522703493878f27c85c1702FedcCA (contract): Helper contract deployed by the seed EOA in tx 0xb5cfa3f8..., hard-codes addresses for WETH9, Gradient token, UniswapV2 router, and flash-loan provider, and forwards control to 0xCB4059Bb021F4cf9d90267B7961125210CeDb792 for the exploit sequence.
- 0xCB4059Bb021F4cf9d90267B7961125210CeDb792 (contract): Attacker-controlled execution helper contract whose bytecode includes an ORIGIN check requiring tx.origin == 0x1234567a98230550894bf93e2346a8bc5c3b36e3 and which executes GradientMarketMakerPool and Uniswap interactions, holds intermediate GRAY and WETH balances, and exposes withdraw(address,uint256) used in the post-incident GRAY withdrawal tx.

Victim and protocol contracts:
- GradientMarketMakerPool (GRAY pool) at 0x37Ea5f691bCe8459C66fFceeb9cf34ffa32fdadC (chainid 1)
- Gradient token (GRAY) at 0xa776a95223c500e81cb0937b291140ff550ac3e4 (chainid 1)
- UniswapV2 GRAY/WETH pair at 0x0846F55387ab118B4E59eee479f1a3e8eA4905EC (chainid 1)

Lifecycle stages and key transactions:
- **Adversary initial funding**
  - Tx 0x164df9ffaf0b5406b5ce229764babc6d045a1eaf4b13b0db931e317dbcaaa2d7 (block 22764977, transfer)
  EOA 0x1234... receives 0.026784106232113316 ETH from 0x5babe600b9fcd5fb7b66c0611bf4896d967b23a1,
  providing sufficient gas to execute the subsequent exploit transactions.

- **Adversary contract deployment and pool drain**
  - Tx 0xb5cfa3f86ce9506e2364475dc43c44de444b079d4752edbffcdad7d1654b1f67 (block 22765114, flashloan)
  The EOA deploys helper contract 0x58117e..., which immediately borrows 3 WETH via a flash loan,
  acquires 1,000 GRAY on Uniswap GRAY/WETH pair 0x0846F5..., and becomes the first LP in the
  pre-funded GRAY pool by depositing 0.632090074270700494 ETH and 950 GRAY. Due to mis-
  accounting, withdrawLiquidity then returns 3.010899131704627093 ETH from
  GradientMarketMakerPool to WETH9 while the pool’s totalLiquidity remains essentially
  unchanged, effectively converting protocol-funded ETH into attacker-controlled WETH and GRAY.

- **Consolidation of GRAY to EOA**
  - Tx 0xc68f673ac67420ef31ade43dba59a994b3675cb5ca5af391dc061281a5a4707d (block 22766253, other)
  The EOA calls 0xCB4059...::withdraw(Gradient, 946.989100868295372906 GRAY), moving all GRAY from
  the helper contract to the EOA without affecting ETH balances, while paying
  0.000114480355275875 ETH in gas.

- **Approvals and disposal of GRAY into ETH**
  - Tx 0x6d33aa1371f10d41ce7cff23a1ecd40785c3bbb7526b9c6a93689302a2fbcdb2 (block 22766264, other)
  - Tx 0x9cd6c268b698dc8820db51ea1c08bf7b085436c2aedd43a95fcb13654e4ad463 (block 22766316, other)
  - Tx 0x1dd527c792a91752f90b7e6a0c1bab836dd99f3c85cdc90898b13fac6a244c90 (block 22766318, transfer)
  The EOA approves two routers/aggregators to spend GRAY, then uses Uniswap UniversalRouter to
  swap 946.989100868295372906 GRAY into WETH and unwrap to ETH. The Uniswap GRAY/WETH pair
  receives 899.639645824880604261 GRAY, Gradient retains 47.349455043414768645 GRAY as tax,
  WETH9 sends 0.583780033629788420 ETH to UniversalRouter, and after paying 0.000627894810216921
  ETH in gas the EOA's ETH balance increases by 0.583152138819571499 ETH, consolidating the
  exploit proceeds into native ETH.

Key trace excerpt from the UniversalRouter disposal tx 0x1dd527c7... (GRAY→WETH swap and ETH withdrawal):

```text
Warning: This is a nightly build of Foundry. It is recommended to use the latest stable version. To mute this warning set `FOUNDRY_DISABLE_NIGHTLY_WARNING` in your environment. 

Executing previous transactions from the block.
Traces:
  [184325] UniversalRouter::3593564c(000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000006859291600000000000000000000000000000000000000000000000000000000000000040a08060c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000032000000000000000000000000000000000000000000000000000000000000003a00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000a776a95223c500e81cb0937b291140ff550ac3e4000000000000000000000000ffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000006880aef0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066a9893cc07d91d95644aedd05d03f95e1dba8af00000000000000000000000000000000000000000000000000000000685928f800000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000418d1b62d39fcf8a5a45e47c91c80d98cfa1247cf664f7a443c324299b4322a6e16b0e240b2d87f1485f165cea11640e48ba6aefbaaf0f26db9b47696e59c262631b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000033561d21e05d4eb06a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a776a95223c500e81cb0937b291140ff550ac3e4000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000000000000000060000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c000000000000000000000000000000000000000000000000000000000000001900000000000000000000000000000000000000000000000000000000000000400000000000000000000000001234567a98230550894bf93e2346a8bc5c3b36e3000000000000000000000000000000000000000000000000080faf54b7fd3b460c)
    ├─ [30786] Permit2::permit(0x1234567a98230550894BF93e2346A8Bc5c3B36E3, PermitSingle({ details: PermitDetails({ token: 0xa776A95223C500E81Cb0937B291140fF550ac3E4, amount: 1461501637330902918203684832716283019655932542975 [1.461e48], expiration: 1753263856 [1.753e9], nonce: 0 }), spender: 0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af, sigDeadline: 1750673656 [1.75e9] }), 0x8d1b62d39fcf8a5a45e47c91c80d98cfa1247cf664f7a443c324299b4322a6e16b0e240b2d87f1485f165cea11640e48ba6aefbaaf0f26db9b47696e59c262631b)
    │   ├─ [3000] PRECOMPILES::ecrecover(0x9c3b43a2d54729903c3d4a280abf04e09a760f2401e0c33b0c6cc692ebf18e8d, 27, 63824498597510340941818609668802006086358181657525161860934211642194552596193, 48422459421539275365759427334597166216303548104162319189105332117936399344227) [staticcall]
    │   │   └─ ← [Return] 0x1234567a98230550894BF93e2346A8Bc5c3B36E3
    │   ├─ emit Permit(owner: 0x1234567a98230550894BF93e2346A8Bc5c3B36E3, token: Gradient: [0xa776A95223C500E81Cb0937B291140fF550ac3E4], spender: UniversalRouter: [0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af], amount: 1461501637330902918203684832716283019655932542975 [1.461e48], expiration: 1753263856 [1.753e9], nonce: 0)
    │   ├─  storage changes:
    │   │   @ 0xb98279c4344edab6354c09389c31f7a2b7a3c360b08872b34b9774532ff4d879: 0 → 0x00000000000100006880aef0ffffffffffffffffffffffffffffffffffffffff
    │   └─ ← [Return]
    ├─ [40749] Permit2::transferFrom(0x1234567a98230550894BF93e2346A8Bc5c3B36E3, UniswapV2Pair: [0x0846F55387ab118B4E59eee479f1a3e8eA4905EC], 946989100868295372906 [9.469e20], Gradient: [0xa776A95223C500E81Cb0937B291140fF550ac3E4])
    │   ├─ [37042] Gradient::transferFrom(0x1234567a98230550894BF93e2346A8Bc5c3B36E3, UniswapV2Pair: [0x0846F55387ab118B4E59eee479f1a3e8eA4905EC], 946989100868295372906 [9.469e20])
    │   │   ├─ emit Transfer(from: 0x1234567a98230550894BF93e2346A8Bc5c3B36E3, to: Gradient: [0xa776A95223C500E81Cb0937B291140fF550ac3E4], value: 47349455043414768645 [4.734e19])
    │   │   ├─ emit Transfer(from: 0x1234567a98230550894BF93e2346A8Bc5c3B36E3, to: UniswapV2Pair: [0x0846F55387ab118B4E59eee479f1a3e8eA4905EC], value: 899639645824880604261 [8.996e20])
    │   │   ├─  storage changes:
    │   │   │   @ 0x061558f016714118e1cd8f9d9a80f96946f360e9763797e5923117ec44d3d5aa: 0x0000000000000000000000000000000000000000000037a0eb0760ac61521751 → 0x0000000000000000000000000000000000000000000037d1b009740e53900bb6
    │   │   │   @ 0x0a99401d96d3b920ba1afefd4356a0ef3aff5e978c5aeb4fa43ccb3718df978f: 0x000000000000000000000000000000000000000000000033561d21e05d4eb06a → 0
    │   │   │   @ 0xa4b4190d8bafe712099837e0b9c5475432646a43ebd5a1223e470e8b80911e5c: 0x00000000000000000000000000000000000000000000001b33a30a622ba3580a → 0x00000000000000000000000000000000000000000000001dc4be18e096b4140f
    │   │   └─ ← [Return] true
    │   └─ ← [Return]
    ├─ [2534] WETH9::balanceOf(UniversalRouter: [0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [2504] UniswapV2Pair::getReserves() [staticcall]
    │   └─ ← [Return] 262698571220841248462673 [2.626e23], 171992932050909988785 [1.719e20], 1750671683 [1.75e9]
    ├─ [919] Gradient::balanceOf(UniswapV2Pair: [0x0846F55387ab118B4E59eee479f1a3e8eA4905EC]) [staticcall]
    │   └─ ← [Return] 263598210866666129066934 [2.635e23]
    ├─ [60738] UniswapV2Pair::swap(0, 585243141483497162 [5.852e17], UniversalRouter: [0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af], 0x)
    │   ├─ [27962] WETH9::transfer(UniversalRouter: [0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af], 585243141483497162 [5.852e17])
    │   │   ├─ emit Transfer(from: UniswapV2Pair: [0x0846F55387ab118B4E59eee479f1a3e8eA4905EC], to: UniversalRouter: [0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af], value: 585243141483497162 [5.852e17])
    │   │   ├─  storage changes:
    │   │   │   @ 0xfb437cb06df854b0e9a5f9c071f54ee63d1407c751de4e81c7cb3a621a923fa3: 0 → 0x000000000000000000000000000000000000000000000000081f3389535b86ca
    │   │   │   @ 0x34b392e05a937f8f09f5fcd3dc1d06c072265e9e9a5ffc1f6146d1d8606172fd: 0x00000000000000000000000000000000000000000000000952e1a471546307b1 → 0x0000000000000000000000000000000000000000000000094ac270e8010780e7
    │   │   └─ ← [Return] true
    │   ├─ [919] Gradient::balanceOf(UniswapV2Pair: [0x0846F55387ab118B4E59eee479f1a3e8eA4905EC]) [staticcall]
    │   │   └─ ← [Return] 263598210866666129066934 [2.635e23]
    │   ├─ [534] WETH9::balanceOf(UniswapV2Pair: [0x0846F55387ab118B4E59eee479f1a3e8eA4905EC]) [staticcall]
    │   │   └─ ← [Return] 171407688909426491623 [1.714e20]
    │   ├─ emit Sync(reserve0: 263598210866666129066934 [2.635e23], reserve1: 171407688909426491623 [1.714e20])
    │   ├─ emit Swap(sender: UniversalRouter: [0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af], amount0In: 899639645824880604261 [8.996e20], amount1In: 0, amount0Out: 0, amount1Out: 585243141483497162 [5.852e17], to: UniversalRouter: [0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af])
    │   ├─  storage changes:
    │   │   @ 10: 0x00000000000000000000000000031b5952ea797629eecad9d19c2a0a2008fa60 → 0x00000000000000000000000000031b5e5ba4901598a5334de7abe10d7c636770
    │   │   @ 9: 0x0000000000000000000000000000000002ff794c95563161334fb73773d29f68 → 0x0000000000000000000000000000000002ff9d809851fb7c22f1581c2e144468
    │   │   @ 8: 0x6859214300000000000952e1a471546307b10000000037a0eb0760ac61521751 → 0x6859221b0000000000094ac270e8010780e70000000037d1b009740e53900bb6
    │   └─ ← [Stop]
    ├─ [534] WETH9::balanceOf(UniversalRouter: [0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af]) [staticcall]
    │   └─ ← [Return] 585243141483497162 [5.852e17]
    ├─ [534] WETH9::balanceOf(UniversalRouter: [0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af]) [staticcall]
    │   └─ ← [Return] 585243141483497162 [5.852e17]
    ├─ [8062] WETH9::transfer(0x000000fee13a103A10D593b9AE06b3e05F2E7E1c, 1463107853708742 [1.463e15])
    │   ├─ emit Transfer(from: UniversalRouter: [0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af], to: 0x000000fee13a103A10D593b9AE06b3e05F2E7E1c, value: 1463107853708742 [1.463e15])
    │   ├─  storage changes:
    │   │   @ 0x69d4b4ad61a248c9c09011fa9f24ebdc295eaab0719dc261fc601f40cffadeaa: 0x00000000000000000000000000000000000000000000000018687d177a9a4147 → 0x000000000000000000000000000000000000000000000000186dafc7d27daf0d
    │   │   @ 0xfb437cb06df854b0e9a5f9c071f54ee63d1407c751de4e81c7cb3a621a923fa3: 0x000000000000000000000000000000000000000000000000081f3389535b86ca → 0x000000000000000000000000000000000000000000000000081a00d8fb781904
    │   └─ ← [Return] true
    ├─ [534] WETH9::balanceOf(UniversalRouter: [0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af]) [staticcall]
    │   └─ ← [Return] 583780033629788420 [5.837e17]
    ├─ [9249] WETH9::withdraw(583780033629788420 [5.837e17])
    │   ├─ [109] UniversalRouter::receive{value: 583780033629788420}()
    │   │   └─ ← [Stop]
    │   ├─ emit Withdrawal(src: UniversalRouter: [0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af], wad: 583780033629788420 [5.837e17])
    │   ├─  storage changes:
    │   │   @ 0xfb437cb06df854b0e9a5f9c071f54ee63d1407c751de4e81c7cb3a621a923fa3: 0x000000000000000000000000000000000000000000000000081a00d8fb781904 → 0
    │   └─ ← [Stop]
    ├─ [0] 0x1234567a98230550894BF93e2346A8Bc5c3B36E3::fallback{value: 583780033629788420}()
    │   └─ ← [Stop]
    └─ ← [Stop]


Transaction successfully executed.
Gas used: 186069
```

## Impact & Losses

In the exploited GRAY pool, the protocol lost 3.010899131704627093 ETH of pool-held liquidity, which
was transformed into attacker-controlled WETH and then ETH and GRAY. After consolidating GRAY and
performing the UniversalRouter swap sequence, the adversary EOA achieved a net increase of
0.580815249038105371 ETH in native balance after accounting for all gas costs across the attacker-
crafted sequence b, and still held 2.346098333159028268 WETH received during the initial flash-loan
cycle (valued conservatively at 0 in the reference profit calculation). The exploit demonstrates a
clear ACT opportunity: any unprivileged actor observing the same public state and contract code at
block 22765114 can reproduce the same transaction sequence b under standard Ethereum inclusion rules
to drain protocol-funded ETH from the pre-funded GRAY pool.

Realized profit components:
- ETH: 0.580815249038105371

## References

- [1] Seed exploit tx trace and balance diffs: `artifacts/root_cause/seed/1/0xb5cfa3f86ce9506e2364475dc43c44de444b079d4752edbffcdad7d1654b1f67/trace.cast.log`
- [2] Decoded GRAY pool state before and after exploit: `artifacts/root_cause/data_collector/iter_3/tx/1/0xb5cfa3f86ce9506e2364475dc43c44de444b079d4752edbffcdad7d1654b1f67/pool_gray_state_decoded.json`
- [3] GradientMarketMakerPool and registry/orderbook source: `artifacts/root_cause/data_collector/iter_2/contract/1/0x893D41635725d8EA6F528D3f3F3DF3E9e8076934/source`
- [4] Attacker helper contract 0xCB4059... disassembly: `artifacts/root_cause/data_collector/iter_1/contract/1/0xCB4059Bb021F4cf9d90267B7961125210CeDb792/disassemble/disassembly_stdout.txt`
- [5] Post-incident GRAY withdraw tx trace and balance diffs: `artifacts/root_cause/data_collector/iter_2/tx/1/0xc68f673ac67420ef31ade43dba59a994b3675cb5ca5af391dc061281a5a4707d`
- [6] UniversalRouter disposal tx trace and balance diffs: `artifacts/root_cause/data_collector/iter_3/tx/1/0x1dd527c792a91752f90b7e6a0c1bab836dd99f3c85cdc90898b13fac6a244c90`
- [7] EOA 0x1234... txlist including approvals and funding: `artifacts/root_cause/data_collector/iter_1/address/1/0x1234567a98230550894bf93e2346a8bc5c3b36e3/txlist.json`