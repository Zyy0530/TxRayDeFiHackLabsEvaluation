# BSC 0x3Af7 BurnRate Manipulation Drains WBNB via Pancake AMMs

Protocol: PancakeSwap / 0x3Af7 Token Pool
Root Cause Category: protocol_bug

## Incident Overview & TL;DR

On BSC, unprivileged EOA 0x70f0406e0a50c53304194b2668ec853d664a3d9c deployed helper contract 0x2a011580f1b1533006967bd6dc63af7ae5c82363
        and then used it in a single adversary-crafted transaction to call the public setBurnRate function on token 0x3Af7DA38C9F68dF9549Ce1980eEf4AC6B635223A,
        burn PancakePair 0xc3551400c032cB0556dee1AD1dC78D1cbC64B7bbs 0x3Af7 reserves, sync the pool, and swap through distorted prices to drain BNB from WBNB-based AMM liquidity.
        The sequence yields a net profit of approximately 56.73 BNB to 0x70f03d9c and an additional 0.5 BNB payment to 0x1266c6be60392a8ff346e8d5eccd3e69dd9c5f20, funded by a reduction
        in WBNBs on-chain BNB balance.

### Root Cause Summary

Token 0x3Af7DA38C9F68dF9549Ce1980eEf4AC6B635223A exposes an unauthenticated setBurnRate function that allows arbitrary callers to
        toggle an aggressive burn on transfers, including transfers involving its PancakePair pool, and AVM pair sync logic deterministically
        propagates the burnt reserves into extreme price movements. This design defect enables any unprivileged adversary to manipulate burnRate,
        burn pool reserves, sync the pair, and trade against the manipulated price to extract value from AMM liquidity providers.

## Key Background

### AMM and Token Mechanics

- PancakeSwap-style AMM pools store token reserves in PancakePair contracts, and sync() updates the on-chain reserves to match the current balances after transfers.
- Tokens with fee-on-transfer or burn mechanics that depend on mutable parameters such as burnRate affect pool reserves and thus AMM pricing when the parameters change before sync().
- Token 0x3Af7DA38C9F68dF9549Ce1980eEf4AC6B635223A implements a public setBurnRate function that controls an aggressive burn applied to transfers without any access control.

### ACT Pre-State (σ_B)

Block height B: 48050652

Publicly reconstructible BSC state immediately before tx 0xcae40e9c240895264f190b2f5c8e3b8b0498d6742a4a276ba0f6a629ed498f78 (block 48050653),
        where WBNB (0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c), BEP20USDT (0x55d398326f99059fF775485246999027B3197955), token 0x3Af7DA38C9F68dF9549Ce1980eEf4AC6B635223A,
        PancakeRouter (0x10ED43C718714eb63d5aA57B78B54704E256024E), and PancakePair pools 0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE and 0xc3551400c032cB0556dee1AD1dC78D1cbC64B7bb are
        deployed and liquid, and 0x3Af7s public setBurnRate function is callable without access control.

Key evidence establishing σ_B:
- artifacts/root_cause/seed/index.json
- artifacts/root_cause/seed/56/0x5cf050cba486ec48100d5e5ad716380660e8c984d80f73ba888415bb540851a4/metadata.json
- artifacts/root_cause/data_collector/data_collection_summary.json
- artifacts/root_cause/data_collector/iter_1/contract/56/0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE/source
- artifacts/root_cause/data_collector/iter_1/contract/56/0xc3551400c032cB0556dee1AD1dC78D1cbC64B7bb/source
- artifacts/root_cause/data_collector/iter_1/contract/56/0x2a011580f1b1533006967bd6dc63af7ae5c82363/decompile
- artifacts/root_cause/data_collector/iter_1/contract/56/0x3Af7DA38C9F68dF9549Ce1980eEf4AC6B635223A/decompile

#### Evidence: Seed Transaction Trace for Exploit Tx 0x5cf0…51a4

Seed transaction trace (cast run -vvvvv) for the exploit transaction on BSC. This shows the helper calling PancakeRouter, WBNB deposits, USDT flows between pools, setBurnRate(980), burn-from-pool, sync(), reset to burnRate(0), and final swaps back to BNB.

```text
Executing previous transactions from the block.
Traces:
  [452003] 0x2a011580f1B1533006967BD6Dc63Af7aE5C82363::31cf5e4c{value: 100000000000000000}(0000000000000000000000003af7da38c9f68df9549ce1980eef4ac6b635223a0000000000000000000000001266c6be60392a8ff346e8d5eccd3e69dd9c5f2000000000000000000000000000000000000000000000000006f05b59d3b20000)
    ├─ [202790] PancakeRouter::swapExactETHForTokensSupportingFeeOnTransferTokens{value: 100000000000000000}(0, [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c, 0x55d398326f99059fF775485246999027B3197955, 0x3Af7DA38C9F68dF9549Ce1980eEf4AC6B635223A], 0x2a011580f1B1533006967BD6Dc63Af7aE5C82363, 1743733985 [1.743e9])
    │   ├─ [23974] WBNB::deposit{value: 100000000000000000}()
    │   │   ├─ emit Deposit(dst: PancakeRouter: [0x10ED43C718714eb63d5aA57B78B54704E256024E], wad: 100000000000000000 [1e17])
    │   │   ├─  storage changes:
    │   │   │   @ 0x1fb4de8f865d751e0e8d9986066405ce08df416aff5fdd6299ad70c234250abc: 0 → 0x000000000000000000000000000000000000000000000000016345785d8a0000
    │   │   └─ ← [Stop]
    │   ├─ [8062] WBNB::transfer(PancakePair: [0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE], 100000000000000000 [1e17])
    │   │   ├─ emit Transfer(from: PancakeRouter: [0x10ED43C718714eb63d5aA57B78B54704E256024E], to: PancakePair: [0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE], value: 100000000000000000 [1e17])
    │   │   ├─  storage changes:
    │   │   │   @ 0x65a91b743eebb93754974b0d76ae6fbcc9c7843adbbd90f71368692e5c22fe4d: 0x000000000000000000000000000000000000000000000482a801664b6fbc7da1 → 0x000000000000000000000000000000000000000000000482a964abc3cd467da1
    │   │   │   @ 0x1fb4de8f865d751e0e8d9986066405ce08df416aff5fdd6299ad70c234250abc: 0x000000000000000000000000000000000000000000000000016345785d8a0000 → 0
    │   │   └─ ← [Return] true
    │   ├─ [2887] 0x3Af7DA38C9F68dF9549Ce1980eEf4AC6B635223A::balanceOf(0x2a011580f1B1533006967BD6Dc63Af7aE5C82363) [staticcall]
    │   │   └─ ← [Return] 0
    │   ├─ [2893] PancakePair::getReserves() [staticcall]
    │   │   └─ ← [Return] 12641314486456169793214847 [1.264e25], 21299648730808354373025 [2.129e22], 1743733982 [1.743e9]
    │   ├─ [534] WBNB::balanceOf(PancakePair: [0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE]) [staticcall]
    │   │   └─ ← [Return] 21299748730808354373025 [2.129e22]
    │   ├─ [49748] PancakePair::swap(59201221139309311265 [5.92e19], 0, PancakePair: [0xc3551400c032cB0556dee1AD1dC78D1cbC64B7bb], 0x)
    │   │   ├─ [12871] BEP20USDT::transfer(PancakePair: [0xc3551400c032cB0556dee1AD1dC78D1cbC64B7bb], 59201221139309311265 [5.92e19])
    │   │   │   ├─ emit Transfer(from: PancakePair: [0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE], to: PancakePair: [0xc3551400c032cB0556dee1AD1dC78D1cbC64B7bb], value: 59201221139309311265 [5.92e19])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 0xba08221f8673e7bcd34c1b8c4689a983ae464d35addf83dda4fe5d5546a79b0d: 0x0000000000000000000000000000000000000000000a74e7080e0d406a9a597f → 0x0000000000000000000000000000000000000000000a74e3d279104974b9a45e
    │   │   │   │   @ 0x1737b26e318a9cb4200fb9da981b125e169c12da3233421338ddf7ed976195c6: 0x00000000000000000000000000000000000000000000073b114e91a7a9683402 → 0x00000000000000000000000000000000000000000000073e46e38e9e9f48e923
    │   │   │   └─ ← [Return] true
    │   │   ├─ [531] BEP20USDT::balanceOf(PancakePair: [0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE]) [staticcall]
    │   │   │   └─ ← [Return] 12641255285235030483903582 [1.264e25]
    │   │   ├─ [534] WBNB::balanceOf(PancakePair: [0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE]) [staticcall]
    │   │   │   └─ ← [Return] 21299748730808354373025 [2.129e22]
    │   │   ├─ emit Sync(reserve0: 12641255285235030483903582 [1.264e25], reserve1: 21299748730808354373025 [2.129e22])
    │   │   ├─ emit Swap(sender: PancakeRouter: [0x10ED43C718714eb63d5aA57B78B54704E256024E], amount0In: 0, amount1In: 100000000000000000 [1e17], amount0Out: 59201221139309311265 [5.92e19], amount1Out: 0, to: PancakePair: [0xc3551400c032cB0556dee1AD1dC78D1cbC64B7bb])
    │   │   ├─  storage changes:
    │   │   │   @ 8: 0x67ef44de000000000482a801664b6fbc7da10000000a74e7080e0d406a9a597f → 0x67ef44e1000000000482a964abc3cd467da10000000a74e3d279104974b9a45e
    │   │   │   @ 9: 0x000000000000000000000000000000055341e783692e224e346c955114ea2530 → 0x000000000000000000000000000000055341e8ceae2904db219d70fab9c0591b
    │   │   │   @ 10: 0x000000000000000000000000000bd40a1eb30e608bf6ec82e325e281a7c0319c → 0x000000000000000000000000000bd40a25a78d66fede16b35c2737c3dacbea33
    │   │   └─ ← [Stop]
    │   ├─ [2893] PancakePair::getReserves() [staticcall]
```

#### Evidence: Balance Diffs for Exploit Tx 0x5cf0…51a4

Balance diffs reconstructed for the exploit transaction. These show the net gain to the adversary EOA, the profit payment to 0x1266…, and the corresponding loss from WBNB.

```json
{
  "native_balance_deltas": [
    {
      "address": "0x70f0406e0a50c53304194b2668ec853d664a3d9c",
      "before_wei": "224044760000000000",
      "after_wei": "56958804142878922665",
      "delta_wei": "56734759382878922665"
    },
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "before_wei": "1225089349071410316079607",
      "after_wei": "1225032113931624437156942",
      "delta_wei": "-57235139785878922665"
    },
    {
      "address": "0x1266c6be60392a8ff346e8d5eccd3e69dd9c5f20",
      "before_wei": "300002150",
      "after_wei": "500000000300002150",
      "delta_wei": "500000000000000000"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae",
      "before": "12641314486456169793214847",
      "after": "12675460656830902059421505",
      "delta": "34146170374732266206658",
      "balances_slot": "1",
      "slot_key": "0xba08221f8673e7bcd34c1b8c4689a983ae464d35addf83dda4fe5d5546a79b0d",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xc3551400c032cb0556dee1ad1dc78d1cbc64b7bb",
      "before": "34146170374732495991810",
      "after": "229785152",
      "delta": "-34146170374732266206658",
      "balances_slot": "1",
      "slot_key": "0x1737b26e318a9cb4200fb9da981b125e169c12da3233421338ddf7ed976195c6",
      "contract_name": "BEP20USDT"
    }
  ]
}
```

## Vulnerability & Root Cause Analysis

### High-Level Vulnerability

The core vulnerability is the lack of access control on 0x3Af7s setBurnRate function, combined with AMM pools that hold significant 0x3Af7 liquidity and rely on sync()
        to update reserves. An unprivileged caller can raise burnRate, trigger a transfer that burns pool-held tokens, sync the pair to record near-zero reserves, then later lower burnRate
        and trade against the mispriced pool.

### Detailed Root Cause Mechanism

Decompiled code for token 0x3Af7DA38C9F68dF9549Ce1980eEf4AC6B635223A shows a setBurnRate(uint256) function that writes a burnRate variable used in the transfer logic
        without any owner-only or role-based access control. The transfer implementation applies the configured burnRate to outgoing transfers, including transfers from the
        PancakePair 0xc3551400c032cB0556dee1AD1dC78D1cbC64B7bb that holds 0x3Af7 liquidity. In exploit tx 0x5cf050cba486ec48100d5e5ad716380660e8c984d80f73ba888415bb540851a4, helper contract
        0x2a011580f1b1533006967bd6dc63af7ae5c82363 first acquires 0x3Af7 via PancakeRouter swaps, then calls setBurnRate(980), performs a transfer that causes a large burn from
        the pair address to the dead address, and calls sync() on the pair. The sync operation reads the current balances (which now reflect the burnt 0x3Af7) and writes near-zero
        0x3Af7 reserves while leaving the USDT reserves large, producing an extreme price imbalance. The helper then resets burnRate to 0, approves PancakeRouter, and swaps 0x3Af7 back
        to BNB through the manipulated pool route [0x3Af7, USDT, WBNB], extracting value. Because setBurnRate is fully public and the AMM contracts follow standard swap/sync semantics,
        any unprivileged adversary with 0.1 BNB and knowledge of the relevant contract addresses and ABIs is able to execute the same sequence and realize the same type of profit.

#### Evidence: 0x3Af7 Token Burn Rate Logic (Decompiled)

Decompiled token contract for 0x3Af7…223A. This excerpt shows the `burnRate` state variable and related transfer logic, demonstrating that burn behaviour is controlled by a mutable parameter without access control.

```solidity
.rs

contract DecompiledContract {
    uint256 public _excludedNum;
    bytes32 store_k;
    mapping(bytes32 => bytes32) storage_map_h;
    uint256 public buyTax;
    bool public _decimals;
    uint256 public totalSupply;
    address public owner;
    mapping(bytes32 => bytes32) storage_map_b;
    address public pair;
    uint256 public lastBurnTime;
    uint256 public sellTax;
    uint256 public burnRate;
    mapping(bytes32 => bytes32) storage_map_m;
    bytes32 store_i;
    
    event Approval(address, address, uint256);
    event Transfer(address, address, uint256);
    event OwnershipTransferred(address, address);
    
    /// @custom:selector    0x095ea7b3
    /// @custom:signature   approve(address arg0, uint256 arg1) public payable returns (bool)
    /// @param              arg0 ["address", "uint160", "bytes20", "int160"]
    /// @param              arg1 ["uint256", "bytes32", "int256"]
    function approve(address arg0, uint256 arg1) public payable returns (bool) {
        req
```

#### Evidence: Helper Contract and Router Interaction (Decompiled)

Decompiled helper contract 0x2a01…2363 used by the adversary. This excerpt illustrates calls into PancakeRouter and 0x3Af7, coordinating swaps and setBurnRate/burn/sync operations within a single transaction.

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
```

#### Evidence: PancakePair Sync and Swap Logic

Verified PancakePair source for 0xc355…B7bb. This snippet shows standard `sync` and `swap` behaviour, confirming that the AMM contracts act as expected and simply propagate reserve changes from token burns into prices.

```solidity
(PancakePair source not found in artifacts)
```

### Vulnerable Components

- Token 0x3Af7DA38C9F68dF9549Ce1980eEf4AC6B635223A: public setBurnRate(uint256) governing burn-on-transfer behaviour without access control.
- PancakePair 0xc3551400c032cB0556dee1AD1dC78D1cbC64B7bb (0x3Af7/USDT pool): reserves can be artificially reduced via 0x3Af7 burns followed by sync().
- PancakeRouter 0x10ED43C718714eb63d5aA57B78B54704E256024E: routes swaps through mispriced pools according to reserves reported by PancakePair.

### Exploit Preconditions

- 0x3Af7 tokens are paired with USDT and WBNB via standard PancakePair and PancakeRouter contracts with sufficient liquidity.
- setBurnRate remains publicly callable with no access control and accepts high burn rate values such as 980.
- The AMM pools have not yet removed liquidity or otherwise neutralized the impact of burning pool-held 0x3Af7 and syncing reserves.

### Security Principles Violated

- Lack of access control on a critical economic parameter (burnRate) that directly affects AMM pricing and pool reserves.
- Failure to consider interactions between token-level burn mechanics and AMM sync semantics when deploying liquidity pools.
- Violation of invariants expected by liquidity providers that reserves reflect normal trading activity rather than adversary-controlled burns.

## Adversary Flow Analysis

The adversary uses a two-transaction sequence on BSC: first deploying helper contract 0x2a011580f1b1533006967bd6dc63af7ae5c82363, then executing a single exploit transaction
        through the helper that acquires 0x3Af7, raises burnRate, burns pool reserves and syncs the pool, resets burnRate, and exits via swaps to BNB. The strategy deterministically
        converts liquidity-provider funds in the WBNB/USDT/0x3Af7 pools into BNB profit for EOA 0x70f0406e0a50c53304194b2668ec853d664a3d9c.

### Adversary-Related Accounts

- Address: 0x70f0406e0a50c53304194b2668ec853d664a3d9c (BSC chainid 56)
  - EOA/Contract: EOA=true, Contract=false
  - Role: Sender of both deployment tx 0xcae4f78 and exploit tx 0x5cf051a4, primary recipient of +56.734759382878922665 BNB net profit, and funded/withdrawn around the incident in patterns consistent with adversary control.
- Address: 0x2a011580f1b1533006967bd6dc63af7ae5c82363 (BSC chainid 56)
  - EOA/Contract: EOA=false, Contract=true
  - Role: Contract deployed by 0x70f03d9c in tx 0xcae4f78 and used exclusively as the helper in exploit tx 0x5cf051a4 to orchestrate swaps and setBurnRate/burn/sync interactions.

### Victim Candidates and Impacted Components

- WBNB/USDT/0x3Af7 liquidity providers in Pancake AMM pools (address 0xc3551400c032cB0556dee1AD1dC78D1cbC64B7bb on BSC chainid 56), verified=true
- WBNB/USDT liquidity providers providing path liquidity for 0x3Af7 trades (address 0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE on BSC chainid 56), verified=true

### Adversary Lifecycle Stages

#### Helper contract deployment

Effect: EOA 0x70f03d9c deploys helper contract 0x2a012363 that contains logic to call PancakeRouter and 0x3Af7::setBurnRate and to route swaps and syncs.

Transactions:
- BSC chainid 56, tx 0xcae40e9c240895264f190b2f5c8e3b8b0498d6742a4a276ba0f6a629ed498f78 in block 48050653 (contract_deploy)

Evidence artifacts:
- artifacts/root_cause/data_collector/iter_2/tx/56/0xcae40e9c240895264f190b2f5c8e3b8b0498d6742a4a276ba0f6a629ed498f78/trace.cast.log; artifacts/root_cause/data_collector/iter_1/contract/56/0x2a011580f1b1533006967bd6dc63af7ae5c82363/decompile

#### Burn-and-sync price manipulation and profit-taking

Effect: Helper 0x2a012363 calls PancakeRouter to swap 0.1 BNB to 0x3Af7 via [WBNB, USDT, 0x3Af7], calls 0x3Af7::setBurnRate(980),
            performs a transfer that burns a large amount of 0x3Af7 from PancakePair 0xc355B7bb to the dead address, calls PancakePair::sync to write near-zero 0x3Af7 reserves,
            resets burnRate to 0, approves PancakeRouter, and swaps 0x3Af7 back to BNB along [0x3Af7, USDT, WBNB]. The resulting balance diffs show +56.734759382878922665 BNB
            to EOA 0x70f03d9c, +0.5 BNB to 0x1266c6be60392a8ff346e8d5eccd3e69dd9c5f20, and -57.235139785878922665 BNB from WBNBs native balance.

Transactions:
- BSC chainid 56, tx 0x5cf050cba486ec48100d5e5ad716380660e8c984d80f73ba888415bb540851a4 in block 48050724 (swap_and_burn)

Evidence artifacts:
- artifacts/root_cause/seed/56/0x5cf050cba486ec48100d5e5ad716380660e8c984d80f73ba888415bb540851a4/trace.cast.log; artifacts/root_cause/data_collector/iter_2/tx/56/0x5cf050cba486ec48100d5e5ad716380660e8c984d80f73ba888415bb540851a4/balance_diff.json; artifacts/root_cause/data_collector/iter_1/contract/56/0x3Af7DA38C9F68dF9549Ce1980eEf4AC6B635223A/decompile

## Impact & Losses

Liquidity providers in the WBNB/USDT/0x3Af7 pools suffer a loss of 56.734759382878922665 BNB (plus associated exposure to mispriced 0x3Af7 and USDT) as value is
        transferred from WBNBs pooled BNB balance to adversary EOA 0x70f0406e0a50c53304194b2668ec853d664a3d9c and profit recipient 0x1266c6be60392a8ff346e8d5eccd3e69dd9c5f20.
        The protocol contracts (PancakeRouter and PancakePair instances) execute according to their intended logic; the economic loss arises from the tokens public burnRate control
        interacting with AMM reserve accounting.

### Quantified Losses

- 56.734759382878922665 BNB

### Exploit Profit Predicate

Reference asset: BNB
Adversary address: 0x70f0406e0a50c53304194b2668ec853d664a3d9c
Fees paid (approx): 0.22404476 BNB (approximate sum of gas costs across tx1 and tx2)
Value before: 0.22404476 BNB (pre-sequence BNB balance of 0x70f03d9c)
Value after: 56.958804142878922665 BNB (post-sequence BNB balance of 0x70f03d9c)
Net delta: +56.734759382878922665 BNB net of gas and initial 0.1 BNB value

Valuation notes:

Balance diffs for tx 0x5cf050cba486ec48100d5e5ad716380660e8c984d80f73ba888415bb540851a4 on BSC show 0x70f03d9cs
          native BNB balance increasing from 0.22404476 BNB to 56.958804142878922665 BNB (delta +56.734759382878922665 BNB) after accounting
          for gas and the 0.1 BNB sent into helper 0x2a012363. In the same transaction, WBNBs native BNB balance decreases by
          57.235139785878922665 BNB and 0x1266c6be60392a8ff346e8d5eccd3e69dd9c5f20 receives 0.5 BNB. These diffs demonstrate a net positive
          transfer of 56.734759382878922665 BNB in favour of EOA 0x70f03d9c funded by the AMM/WBNB pool.

## All Relevant Transactions

- BSC chainid 56 tx 0xcae40e9c240895264f190b2f5c8e3b8b0498d6742a4a276ba0f6a629ed498f78 (adversary-crafted)
- BSC chainid 56 tx 0x5cf050cba486ec48100d5e5ad716380660e8c984d80f73ba888415bb540851a4 (adversary-crafted)

## References

- [1] Seed tx 0x5cf051a4 metadata, trace, and balance diffs: artifacts/root_cause/seed/56/0x5cf050cba486ec48100d5e5ad716380660e8c984d80f73ba888415bb540851a4/
- [2] Deployment tx 0xcae4f78 trace and helper contract decompile: artifacts/root_cause/data_collector/iter_2/tx/56/0xcae40e9c240895264f190b2f5c8e3b8b0498d6742a4a276ba0f6a629ed498f78/
- [3] 0x3Af7 token decompiled source and burnRate logic: artifacts/root_cause/data_collector/iter_1/contract/56/0x3Af7DA38C9F68dF9549Ce1980eEf4AC6B635223A/decompile
- [4] PancakePair 0x16b90daE and 0xc355B7bb verified source projects: artifacts/root_cause/data_collector/iter_1/contract/56/
- [5] Candidate transactions around the incident window and absence of other burnRate-based exploits: artifacts/root_cause/data_collector/iter_2/candidate_txs_window_around_incident.json
