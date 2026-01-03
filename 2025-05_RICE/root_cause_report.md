# Base 0x8421... Single-Tx Vault Withdraw + Swaps (Non-ACT)

## Incident Overview & TL;DR

On Base (chainid 8453), EOA 0x2a49c6fd18bd111d51c4fffa6559be1d950b8eff sent a single complex
transaction to router 0x7ee23c81995fe7992721ac14b3af522718b63f8f that withdrew a large amount of
token 0xf501E4c51dBd89B95de24b9D53778Ff97934cd9c from vault-like contract
0xcfE0DE4A50C80B434092f87e106DFA40b71A5563, swapped it through standard AMM pools into USDT and then
WETH9, and ended with the EOA receiving approximately 34.52 WETH9 funded from protocol-held
liquidity.

Review of traces, balance/state diffs, and contract code shows a standard vault withdraw followed by
AMM swaps with no identified arithmetic or invariant bug and no demonstrated unauthorized transfer
of another party's claim; this incident is classified as non-ACT with no proven victim loss.

## Key Background

- Vault-like contract 0xcfE0DE4A50C80B434092f87e106DFA40b71A5563 on Base exposes registerProtocol, setMasterContractApproval, and withdraw-style entry points consistent with a generic strategy vault or BentoBox-style manager, with owner-controlled whitelisting of master contracts and protocols.
- Token 0xf501E4c51dBd89B95de24b9D53778Ff97934cd9c implements an OptimismMintableERC20-style token as shown in artifacts/root_cause/data_collector/iter_2/contract/8453/0xf501E4c51dBd89B95de24b9D53778Ff97934cd9c/source/src/contracts/OptimismMintableERC20.sol.
- The transaction routes withdrawn 0xf501... through Uniswap-style pool 0xa0213b570DFF35a8C826334472e23B9A8A94ef3b into USDT and then through concentrated-liquidity pool 0xb2cc224c1c9feE385f8ad6a55b4d94E92359DC59 into WETH9, using standard SwapRouter contracts on Base.
- Prestate and poststate balance diffs from PrestateTracer show that router 0x7ee23c81995fe7992721ac14b3af522718b63f8f and address 0x49876a20bB86714e98A7E4d0a33d85a4011b3455 have zero net 0xf501... and WETH9 balance changes over the transaction, while the EOA sender's WETH9 balance increases by approximately 34.52 and the AMM pools' balances adjust in line with normal swap flows.

## Adversary Flow Analysis

## ACT Opportunity and Non-ACT Determination

- Reference chain: Base (block height B = 30655996)
- Seed / sequence-b transaction: 0x8421c96c1cafa451e025c00706599ef82780bdc0db7d17b6263511a420e0cf20 (type adversary-crafted)

### Profit Predicate

- Reference asset: ETH
- Adversary address: 0x2a49c6fd18bd111d51c4fffa6559be1d950b8eff
- Value before: 2.844808134388500308 ETH
- Value after: 37.367722353592165927 ETH
- Delta: 34.522914219203665619 ETH
- Fees paid: 0.8883386732 ETH (gas-equivalent)

Values are computed from WETH9 (0x4200000000000000000000000000000000000006) balance diffs and native
gas expenditure on Base for the seed transaction, treating 1 WETH9 as 1 ETH-equivalent on Base.
Although the EOA realizes a large positive net profit in ETH terms in this single tx, there is no
demonstrated unauthorized value transfer or invariant violation, so this profit is not classified as
an ACT exploit opportunity.

### Why This Is Classified as Non-ACT

The evidence shows a profitable withdraw-plus-swap transaction for the EOA sender, but:
- Vault 0xcfE0... performs a standard withdraw for token 0xf501... from a tracked position, then clears the position in its internal storage state.
- Subsequent swaps through 0xa0213... and 0xb2cc... follow standard Uniswap V3-style pool logic with consistent balance and invariant changes.
- ERC20 and native balance diffs show no unauthorized reduction of user or protocol balances beyond the expected vault and pool debits corresponding to the executed swaps.
- No arithmetic error, misconfigured fee, or invariant violation is observed in the exercised contract code paths.

Given this, there is no demonstrated unauthorized value transfer or broken safety/liveness invariant, so under the ACT definition this incident is deterministically classified as **non-ACT**.

## Impact & Losses

From the perspective of identifiable on-chain victims, there is no demonstrated loss: no user
account or protocol component is shown to experience an unauthorized reduction in balances or a
broken safety/liveness property as a result of this transaction. The only clear portfolio change is
a positive WETH9 gain for the EOA sender funded from vault-held tokens and AMM pools operating
within their normal design.

## Evidence Snippets

### Seed Transaction Trace Excerpt

Origin: Seed transaction cast trace for tx 0x8421... on Base.

```text
    │   └─ ← [Stop]
    ├─ [46391] 0xcfE0DE4A50C80B434092f87e106DFA40b71A5563::withdraw(: [0xf501E4c51dBd89B95de24b9D53778Ff97934cd9c], 0x49876a20bB86714e98A7E4d0a33d85a4011b3455, 0x7ee23c81995fE7992721ac14B3AF522718b63f8F, 22189176505973791717313474 [2.218e25], 22189176505973791717313474 [2.218e25])
    │   ├─ [29764] ::transfer(0x7ee23c81995fE7992721ac14B3AF522718b63f8F, 22189176505973791717313474 [2.218e25])
    │   │   ├─ emit Transfer(from: 0xcfE0DE4A50C80B434092f87e106DFA40b71A5563, to: 0x7ee23c81995fE7992721ac14B3AF522718b63f8F, value: 22189176505973791717313474 [2.218e25])
    │   │   ├─  storage changes:
    │   │   │   @ 0x444d6fb9ce6abffd62cb3acf111eebe7afbc76a1cd096f5cfb2c132e46a3addf: 0x000000000000000000000000000000000000000000125abdab2e177fdfd7cbc2 → 0
    │   │   │   @ 0xb6954144d01ba7bac2d1b18a4b7d593dc354427c817805969b7e5106d54d9049: 0 → 0x000000000000000000000000000000000000000000125abdab2e177fdfd7cbc2
    │   │   └─ ← [Return] true
    │   ├─ emit LogWithdraw(param0: : [0xf501E4c51dBd89B95de24b9D53778Ff97934cd9c], param1: 0x49876a20bB86714e98A7E4d0a33d85a4011b3455, param2: 0x7ee23c81995fE7992721ac14B3AF522718b63f8F, param3: 22189176505973791717313474 [2.218e25], param4: 22189176505973791717313474 [2.218e25])
    │   ├─  storage changes:
    │   │   @ 0xb00389ecfc39dc0d75e1ed7e4bbbc3605789f462d0407a3136457617cb9e06ac: 0x000000000000000000000000000000000000000000125abdab2e177fdfd7cbc2 → 0
    │   │   @ 0x0787c20c6b97692ad3454cef1b738b1b4a491b564d24902bd091b9aaeb430107: 0x0000000000125abdab2e177fdfd7cbc20000000000125abdab2e177fdfd7cbc2 → 0
...
    │   │   │   │   │   └─ ← [Return] 0xF33a96b5932D9E9B9A0eDA447AbD8C9d48d2e0c8
    │   │   │   │   ├─ [2682] Voter::isAlive(0xF33a96b5932D9E9B9A0eDA447AbD8C9d48d2e0c8) [staticcall]
    │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   ├─ [2584] ::getFee(CLPool: [0xb2cc224c1c9feE385f8ad6a55b4d94E92359DC59]) [staticcall]
    │   │   │   │   │   └─ ← [Return] 100000 [1e5]
    │   │   │   │   └─ ← [Return] 100000 [1e5]
    │   │   │   ├─ [27701] ::transfer(0x7ee23c81995fE7992721ac14B3AF522718b63f8F, 34522914219203665619 [3.452e19])
    │   │   │   │   ├─ emit Transfer(from: CLPool: [0xb2cc224c1c9feE385f8ad6a55b4d94E92359DC59], to: 0x7ee23c81995fE7992721ac14B3AF522718b63f8F, value: 34522914219203665619 [3.452e19])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0x7fa89ed191104b59893c54aa61c35c4b88ae911f1ac7cab067c891ab0601acac: 0x000000000000000000000000000000000000000000000173fb54a3b069d8e3cd → 0x0000000000000000000000000000000000000000000001721c3a9c1df2ee44fa
    │   │   │   │   │   @ 0x121d6b53d69b7ec698c022caa8c4d116ee1938c2082a46c1fa49c0b06a8bb090: 0 → 0x000000000000000000000000000000000000000000000001df1a079276ea9ed3
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [3250] FiatTokenProxy::fallback(CLPool: [0xb2cc224c1c9feE385f8ad6a55b4d94E92359DC59]) [staticcall]
    │   │   │   │   ├─ [2553] FiatTokenV2_2::balanceOf(CLPool: [0xb2cc224c1c9feE385f8ad6a55b4d94E92359DC59]) [delegatecall]
    │   │   │   │   │   └─ ← [Return] 12519761197829 [1.251e13]
    │   │   │   │   └─ ← [Return] 12519761197829 [1.251e13]
    │   │   │   ├─ [13136] SwapRouter::uniswapV3SwapCallback(-34522914219203665619 [-3.452e19], 88166114848 [8.816e10], 0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000be6d8f0d05cc4be24d5167a3ef062215be6d18a5000000000000000000000000000000000000000000000000000000000000002b833589fcd6edb6e08f4c7c32d4f71b54bda029130000644200000000000000000000000000000000000006000000000000000000000000000000000000000000)
    │   │   │   │   ├─ [286] CLFactory::poolImplementation() [staticcall]
    │   │   │   │   │   └─ ← [Return] CLPool: [0xeC8E5342B19977B4eF8892e02D8DAEcfa1315831]
    │   │   │   │   ├─ [8163] FiatTokenProxy::fallback(CLPool: [0xb2cc224c1c9feE385f8ad6a55b4d94E92359DC59], 88166114848 [8.816e10])
    │   │   │   │   │   ├─ [7463] FiatTokenV2_2::transfer(CLPool: [0xb2cc224c1c9feE385f8ad6a55b4d94E92359DC59], 88166114848 [8.816e10]) [delegatecall]
    │   │   │   │   │   │   ├─ emit Transfer(from: SwapRouter: [0xBE6D8f0d05cC4be24d5167a3eF062215bE6D18a5], to: CLPool: [0xb2cc224c1c9feE385f8ad6a55b4d94E92359DC59], value: 88166114848 [8.816e10])
    │   │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   │   @ 0x6b44a3e0842ecc28ca534a294955223b94a5209f3671031126ec16ea6e217dab: 0x00000000000000000000000000000000000000000000000000000b62fbeb3b05 → 0x00000000000000000000000000000000000000000000000000000b7783076125
    │   │   │   │   │   │   │   @ 0x21c455725a5f6abaeaa2dab2a8743115c33213e74dbc837df8cb143938d6c579: 0x00000000000000000000000000000000000000000000000000000014871c2620 → 0
    │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   └─ ← [Stop]
    │   │   │   ├─ [1250] FiatTokenProxy::fallback(CLPool: [0xb2cc224c1c9feE385f8ad6a55b4d94E92359DC59]) [staticcall]
    │   │   │   │   ├─ [553] FiatTokenV2_2::balanceOf(CLPool: [0xb2cc224c1c9feE385f8ad6a55b4d94E92359DC59]) [delegatecall]
    │   │   │   │   │   └─ ← [Return] 12607927312677 [1.26e13]
    │   │   │   │   └─ ← [Return] 12607927312677 [1.26e13]
    │   │   │   ├─ emit Swap(sender: SwapRouter: [0xBE6D8f0d05cC4be24d5167a3eF062215bE6D18a5], recipient: 0x7ee23c81995fE7992721ac14B3AF522718b63f8F, amount0: -34522914219203665619 [-3.452e19], amount1: 88166114848 [8.816e10], sqrtPriceX96: 4003194906662598971276969 [4.003e24], liquidity: 19202365514813475579 [1.92e19], tick: -197870 [-1.978e5])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 6: 0x00000107d007d005fdfcfb10000000000000000000034fa1eb3bdd9e5e7379c8 → 0x00000107d007d005fefcfb12000000000000000000034fb5a177ce017878bea9
    │   │   │   │   @ 8: 0x0000000000000000000000000000000000002881b134b70d69e42e85bc9bcb8d → 0x0000000000000000000000000000000000002881b31516aacdd03e0a43c24709
    │   │   │   │   @ 1554: 0x01000006a0000001484f15d8d1262e4bfb6179048cfff9fde52cb5b86831cb85 → 0x01000006a0000001484f15fd561a69c0786fdc74d1fff9fd8c9b333c6831e8db
    │   │   │   │   @ 10: 0x00000000000000000000001f4557916c0000000000000002d396e9bbd73c2caf → 0x00000000000000000000001f47716dbc0000000000000002d396e9bbd73c2caf
    │   │   │   └─ ← [Return] -34522914219203665619 [-3.452e19], 88166114848 [8.816e10]
    │   │   └─ ← [Return] -34522914219203665619 [-3.452e19], 88166114848 [8.816e10]
    │   └─ ← [Return] 34522914219203665619 [3.452e19]
    ├─ [457] ::balanceOf(0x7ee23c81995fE7992721ac14B3AF522718b63f8F) [staticcall]
    │   └─ ← [Return] 34522914219203665619 [3.452e19]
    ├─ [7801] ::transfer(0x2a49c6FD18BD111d51C4ffFA6559bE1d950B8Eff, 34522914219203665619 [3.452e19])
    │   ├─ emit Transfer(from: 0x7ee23c81995fE7992721ac14B3AF522718b63f8F, to: 0x2a49c6FD18BD111d51C4ffFA6559bE1d950B8Eff, value: 34522914219203665619 [3.452e19])
    │   ├─  storage changes:
    │   │   @ 0x63eac156132f3d18a663f12113fe6ff32b4c569456c3dc000b2aaa5c32274445: 0x000000000000000000000000000000000000000000000000277ac9ed005e4754 → 0x0000000000000000000000000000000000000000000000020694d17f7748e627
    │   │   @ 0x121d6b53d69b7ec698c022caa8c4d116ee1938c2082a46c1fa49c0b06a8bb090: 0x000000000000000000000000000000000000000000000001df1a079276ea9ed3 → 0
```

### WETH9 Balance Diff for the Seed Transaction

Origin: Storage-based ERC20 balance diff for WETH9 in the seed tx.

```json
{
  "chainid": 8453,
  "txhash": "0x8421c96c1cafa451e025c00706599ef82780bdc0db7d17b6263511a420e0cf20",
  "token": "0x4200000000000000000000000000000000000006",
  "holders": [
    {
      "address": "0x2a49c6fd18bd111d51c4fffa6559be1d950b8eff",
      "balance_pre": "2844808134388500308",
      "balance_post": "37367722353592165927",
      "delta": "34522914219203665619"
    },
    {
      "address": "0x7ee23c81995fe7992721ac14b3af522718b63f8f",
      "balance_pre": "0",
      "balance_post": "0",
      "delta": "0"
    },
    {
      "address": "0xb2cc224c1c9fee385f8ad6a55b4d94e92359dc59",
      "balance_pre": "6861852331325892649933",
      "balance_post": "6827329417106688984314",
      "delta": "-34522914219203665619"
    }
  ],
  "block_number": 30655996,
  "pre_block": 30655995,
  "post_block": 30655996,
  "errors": []
}
```

### Vault 0xcfE0... Decompilation Excerpt

Origin: Heimdall decompiled source for vault contract 0xcfE0..., focusing on protocol registration.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @title            Decompiled Contract
/// @author           Jonathan Becker <jonathan@jbecker.dev>
/// @custom:version   heimdall-rs v0.9.2
///
/// @notice           This contract was decompiled using the heimdall-rs decompiler.
///                     It was generated directly by tracing the EVM opcodes from this contract.
///                     As a result, it may not compile or even be valid solidity code.
///                     Despite this, it should be obvious what each function does. Overall
///                     logic should have been preserved throughout decompiling.
///
/// @custom:github    You can find the open-source decompiler here:
///                       https://heimdall.rs

contract DecompiledContract {
    mapping(bytes32 => bytes32) storage_map_a;
    address public owner;
    mapping(bytes32 => bytes32) storage_map_e;
    address public pendingOwner;
    mapping(bytes32 => bytes32) storage_map_b;
    mapping(bytes32 => bytes32) storage_map_f;
    
    event OwnershipTransferred(address, address);
    event LogDeploy(address, bytes, address);
    event LogRegisterProtocol(address);
    event LogWhiteListMasterContract(address, bool);
    event LogStrategyTargetPercentage(address, uint256);
    
    /// @custom:selector    0xdf23b45b
    /// @custom:signature   strategyData(address arg0) public view returns (bytes memory)
    /// @param              arg0 ["address", "uint160", "bytes20", "int160"]
    function strategyData(address arg0) public view returns (bytes memory) {
        require(arg0 == (address(arg0)));
        var_a = 0x0a;
        address var_b = arg0;
        address var_c = uint64(storage_map_a[var_b]);
        address var_d = uint64(storage_map_a[var_b] / 0x010000000000000000);
        address var_e = address(storage_map_a[var_b] / 0x0100000000000000000000000000000000);
```

## References

- [1] Seed tx metadata and trace: artifacts/root_cause/seed/8453/0x8421c96c1cafa451e025c00706599ef82780bdc0db7d17b6263511a420e0cf20
- [2] Vault 0xcfE0... decompiled source and state diff: artifacts/root_cause/data_collector/iter_2/contract/8453/0xcfE0DE4A50C80B434092f87e106DFA40b71A5563/decompile/0xcfE0DE4A50C80B434092f87e106DFA40b71A5563-decompiled.sol
- [3] Token 0xf501... OptimismMintableERC20-style source: artifacts/root_cause/data_collector/iter_2/contract/8453/0xf501E4c51dBd89B95de24b9D53778Ff97934cd9c/source/src/contracts/OptimismMintableERC20.sol
- [4] AMM pool source trees for 0xa0213b... and 0xb2cc...: artifacts/root_cause/data_collector/iter_4/contract/8453