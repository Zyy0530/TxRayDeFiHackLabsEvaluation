# RANTToken Non-AMM Sell-Burn Path Flash-Loan Drain on BSC

## Incident Overview TL;DR

At BSC block 52,974,382, EOA 0xAD2Cb8f48E74065a0B884aF9C5a4ecbba101be23 deployed helper contract 0x1e2D48E640243b04a9Fa76Eb49080E9aB110b4ac and executed a single transaction that used a WBNB flash loan, Pancake swaps, and RANTToken's non-AMM transfer-to-self path to drain RANT from the RANT/WBNB pair 0x42A93C3aF7Cb1BBc757dd2eC4977fd6D7916Ba1D and convert RANT into BNB via RantCenter. Balance diffs show that this transaction increases the adversary EOA's BNB balance by exactly 311.475873604407652863 BNB and transfers an additional 0.1 BNB to EOA 0xD3b0d838cCCEAe7ebF1781D11D1bB741DB7Fe1A7.


## Key Background

- RANTToken 0xc321ac21a07b3d593b269acdace69c3762ca2dd0 on BSC is an Ownable ERC20 that integrates an external RantCenter (proxy at 0x9AdB8c52f0d845739Fd3e035Ed230F0D4cBa785a) and a rant_node address 0x1e619DbeA18F5E0e66D1c2dF3f14416d3c804809; its constructor creates a Pancake V2 pair against WBNB and enables a non-AMM transfer path controlled by openSellBurn and openBurn flags.
- The non-AMM transfer path in RANTToken's _transfer function activates when neither sender nor recipient is a pair address and the recipient is RANTToken itself; under these conditions, the contract calls _autoBurnLiquidityPairTokens and _sellBurnLiquidityPairTokens, moves part of the LP's RANT balance to 0x000000000000000000000000000000000000dEaD and rant_node, and then routes the transfer amount through RantCenter::sell_rant to perform a sell into WBNB.
- RANTToken's owner EOA 0x2373241ec958124cbd3636fc9561f7ec623adbe3 configured rant_center and rant_node via changeBuyCenter and changeRant_node before the incident, and then renounced ownership; after this point, the transfer-to-self sell-burn behavior is fully permissionless and can be used by any RANT holder.
- PancakeV3Pool 0x172fcD41E0913e95784454622d1c3724f546f849 and PancakeRouter 0x10ED43C718714eb63d5aA57B78B54704E256024E provide public flash-loan and swap primitives that any unprivileged EOA or contract can call to borrow WBNB and route RANT/WBNB liquidity through DEX paths.

## Vulnerability Analysis

The root cause is a design flaw in RANTToken's non-AMM transfer-to-self path, which lets any RANT holder call transfer(address(this), amount) to trigger LP RANT burns and RantCenter-driven sells without restrictions, allowing an unprivileged adversary to combine this with a flash loan and DEX swaps to drain RANT/WBNB liquidity and realize BNB profit.

RANTToken overrides the standard ERC20 _transfer function. When neither sender nor recipient is flagged as a pair address and the recipient equals address(this), _transfer enters a non-AMM branch that (1) calls _autoBurnLiquidityPairTokens(), (2) calls _sellBurnLiquidityPairTokens(amount) when openSellBurn is true and lockburn is false, and (3) transfers amount RANT from sender to rant_center before invoking rant_center.sell_rant(amount, sender). In _sellBurnLiquidityPairTokens, the contract computes liquidityPairBalance = this.balanceOf(uniswapPair), where balanceOf aggregates the usual _balances mapping with rant_center.earnedToken(account). If liquidityPairBalance > amount and openSellBurn is true, the function splits amount into deadAmount and noteAmount according to burnToSellDeadRate and burnToNoteRate, transfers deadAmount of RANT from the RANT/WBNB pair 0x42A93C3aF7Cb1BBc757dd2eC4977fd6D7916Ba1D to 0x000000000000000000000000000000000000dEaD, transfers noteAmount from the pair to rant_node 0x1e619DbeA18F5E0e66D1c2dF3f14416d3c804809, calls rant_node.depositBonusToken(noteAmount), and finally calls pair.sync(). The verified source contains no owner-only guard, whitelist restriction, or volume limit on this path beyond requiring that liquidityPairBalance > amount. The RANTToken owner configured rant_center and rant_node and then renounced ownership before the incident, so these behaviors are fixed and publicly usable. In the seed transaction 0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99, helper contract 0x1e2D48E640243b04a9Fa76Eb49080E9aB110b4ac uses a WBNB flash loan from PancakeV3Pool 0x172fcD41E0913e95784454622d1c3724f546f849 to acquire RANT from the RANT/WBNB pair via PancakeRouter, then repeatedly calls RANTToken.transfer(address(this), amount) through 0xFd9267eE6594bD8E82e8030c353870fA1773F7f8 to trigger _sellBurnLiquidityPairTokens and RantCenter::sell_rant. The balance diff shows that the RANT/WBNB pair loses exactly 102509423181903444010952438 base units of RANTToken, with 9660573064263151791608375 base units moved to 0x000000000000000000000000000000000000dEaD, 1073397007140350199067597 base units moved to rant_node, and 91775453110499942020276462 base units moved to helper contract 0xFd9267eE6594bD8E82e8030c353870fA1773F7f8. RantCenter::sell_rant then sells the helper's RANT position back into WBNB via PancakeRouter, repays the flash loan, and leaves a net gain of 311.475873604407652863 BNB in the adversary EOA. Because the transfer-to-self path is fully public and the configuration of rant_center and rant_node is fixed, any RANT holder at or before block 52,974,382 could replicate this multi-call strategy using only public on-chain information and standard DEX infrastructure.

### Vulnerable Components
- RANTToken 0xc321ac21a07b3d593b269acdace69c3762ca2dd0 on BSC: custom _transfer non-AMM branch that calls _sellBurnLiquidityPairTokens and RantCenter::sell_rant on transfer(address(this), amount) without access control or per-call limits.
- RANT/WBNB Pancake V2 pair 0x42A93C3aF7Cb1BBc757dd2eC4977fd6D7916Ba1D: provides the RANT liquidity that _sellBurnLiquidityPairTokens can move to 0x000000000000000000000000000000000000dEaD, rant_node, and attacker-controlled contracts.
- RantCenter TransparentUpgradeableProxy 0x9AdB8c52f0d845739Fd3e035Ed230F0D4cBa785a (implementation 0x559Bee76eC549e70630E451d46cB442eF5c230fD): exposes sell_rant() and earnedToken() used by RANTToken's transfer and balanceOf logic.
- rant_node 0x1e619DbeA18F5E0e66D1c2dF3f14416d3c804809: receives noteAmount from LP and participates in bonus accounting during the sell-burn process.

### Exploit Preconditions (ACT)
- RANTToken openSellBurn and openBurn flags remain enabled, and the owner has configured rant_center to 0x9AdB8c52f0d845739Fd3e035Ed230F0D4cBa785a and rant_node to 0x1e619DbeA18F5E0e66D1c2dF3f14416d3c804809, then renounced ownership so that these settings cannot be tightened before block 52,974,382.
- The RANT/WBNB Pancake pair 0x42A93C3aF7Cb1BBc757dd2eC4977fd6D7916Ba1D holds sufficient RANTToken balance such that liquidityPairBalance > amount for each transfer(address(this), amount) call in the exploit sequence.
- Public Pancake flash-loan and swap primitives (PancakeV3Pool 0x172fcD41E0913e95784454622d1c3724f546f849 and PancakeRouter 0x10ED43C718714eb63d5aA57B78B54704E256024E) remain available so that an unprivileged contract can scale the exploit using borrowed WBNB.
- The adversary can deploy a helper contract and send a high-gas transaction that chains the flash loan, RANT acquisitions, transfer(address(this), amount) calls into RANTToken, RantCenter::sell_rant calls, and final WBNB repayment in a single atomic execution.

### Security Principles Violated
- Failure to restrict powerful liquidity-draining and burning operations to privileged roles or narrow caller sets: any RANT holder can trigger _sellBurnLiquidityPairTokens and RantCenter::sell_rant via transfer(address(this), amount).
- Failure to enforce quantitative invariants or limits on how much LP RANT can be removed per call or per block, enabling a single transaction to move over 1e26 base units of RANT out of the RANT/WBNB pair.
- Coupling of reward-distribution mechanics (rant_node and bonus tokens) with a publicly callable sell-burn path that directly interacts with external DEX liquidity, creating a surface where reward logic can be repurposed into a drain.

## Detailed Root Cause Analysis

### Code and Mechanism Evidence

```solidity
// RANTToken core transfer and sell-burn logic (excerpt)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

library EnumerableSet {
    // To implement this library for multiple types with as little code
    // repetition as possible, we write it in terms of a generic Set type with
    // bytes32 values.
    // The Set implementation uses private functions, and user-facing
    // implementations (such as AddressSet) are just wrappers around the
    // underlying Set.
    // This means that we can only create new EnumerableSets for types that fit
    // in bytes32.

    struct Set {
        // Storage of set values
        bytes32[] _values;
        // Position of the value in the `values` array, plus 1 because index 0
        // means a value is not in the set.
        mapping(bytes32 => uint256) _indexes;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function _add(Set storage set, bytes32 value) private returns (bool) {
        if (!_contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._indexes[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function _remove(Set storage set, bytes32 value) private returns (bool) {
        // We read and store the value's index to prevent multiple reads from the same storage slot
        uint256 valueIndex = set._indexes[value];

        if (valueIndex != 0) {
            // Equivalent to contains(set, value)
            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
            // the array, and then remove the last element (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 toDeleteIndex = valueIndex - 1;
            uint256 lastIndex = set._values.length - 1;

            if (lastIndex != toDeleteIndex) {
                bytes32 lastValue = set._values[lastIndex];

                // Move the last value to the index where the value to delete is
                set._values[toDeleteIndex] = lastValue;
                // Update the index for the moved value
                set._indexes[lastValue] = valueIndex; // Replace lastValue's index to valueIndex
            }

            // Delete the slot where the moved value was stored
            set._values.pop();

            // Delete the index for the deleted slot
            delete set._indexes[value];

            return true;
        } else {
            return false;
        }
    }

    /**
```

The excerpt above shows how `transfer(address(this), amount)` can trigger `_sellBurnLiquidityPairTokens` and `rant_center.sell_rant` without additional access control, enabling any holder to invoke the LP drain and bonus mechanics.

```json
// Seed transaction balance diffs for key participants (excerpt)
{
  "native_balance_deltas": [
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "before_wei": "1324621476041869697330651",
      "after_wei": "1324309898776178289677788",
      "delta_wei": "-311577265691407652863"
    },
    {
      "address": "0xad2cb8f48e74065a0b884af9c5a4ecbba101be23",
      "before_wei": "386299926958507069",
      "after_wei": "311862173531366159932",
      "delta_wei": "311475873604407652863"
    },
    {
      "address": "0xd3b0d838ccceae7ebf1781d11d1bb741db7fe1a7",
      "before_wei": "414908463653815053",
      "after_wei": "514908463653815053",
      "delta_wei": "100000000000000000"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0xc321ac21a07b3d593b269acdace69c3762ca2dd0",
      "holder": "0x42a93c3af7cb1bbc757dd2ec4977fd6d7916ba1d",
      "before": "107339710714035019906756623",
      "after": "4830287532131575895804185",
      "delta": "-102509423181903444010952438",
      "balances_slot": "1",
      "slot_key": "0x09eaa18053374877effa79e43d30db7f5a5c941b151d56f286259aa839cb197c",
      "contract_name": "RANTToken"
    },
    {
      "token": "0xc321ac21a07b3d593b269acdace69c3762ca2dd0",
      "holder": "0xfd9267ee6594bd8e82e8030c353870fa1773f7f8",
      "before": "0",
      "after": "91775453110499942020276462",
      "delta": "91775453110499942020276462",
      "balances_slot": "1",
      "slot_key": "0x9f0259e6bcecebdcd12b77d5c0ab3b58990aab05e8695d9758755652bfe558ff",
      "contract_name": "RANTToken"
    },
    {
      "token": "0xc321ac21a07b3d593b269acdace69c3762ca2dd0",
      "holder": "0x000000000000000000000000000000000000dead",
      "before": "43376232340740758940993948",
      "after": "53036805405003910732602323",
      "delta": "9660573064263151791608375",
      "balances_slot": "1",
      "slot_key": "0xb34209a263f6c38fe55f099e9e70f9d67e93982480ff3234a5e0108028ad164d",
      "contract_name": "RANTToken"
    },
    {
      "token": "0xc321ac21a07b3d593b269acdace69c3762ca2dd0",
      "holder": "0x1e619dbea18f5e0e66d1c2df3f14416d3c804809",
      "before": "4819581371193417660110274",
      "after": "5892978378333767859177871",
      "delta": "1073397007140350199067597",
      "balances_slot": "1",
      "slot_key": "0x1243704dc60c5e556e84b2a5aaa18897ecb29f4728ac27c52dc1516a9c97ab69",
      "contract_name": "RANTToken"
    },
    {
      "token": "0xc321ac21a07b3d593b269acdace69c3762ca2dd0",
      "holder": "0x9adb8c52f0d845739fd3e035ed230f0d4cba785a",
      "before": "1000000000000001266",
      "after": "1000000000000001270",
      "delta": "4",
      "balances_slot": "1",
      "slot_key": "0x5f18843c683af17d68c4d3cd3967e16db7ff85316aaf6adf6b39a9f4ecb7aac6",
      "contract_name": "RANTToken"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae",
      "before": "15566728307002876740730411",
      "after": "15566728214261518988727764",
      "delta": "-92741357752002647",
      "balances_slot": "1",
      "slot_key": "0xba08221f8673e7bcd34c1b8c4689a983ae464d35addf83dda4fe5d5546a79b0d",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x418d045493860a45f97f8d89e60b900862679d8f",
      "before": "870536957809485698619",
      "after": "870605978490196239633",
      "delta": "69020680710541014",
      "balances_slot": "1",
      "slot_key": "0xd8197aebc1677ed1f22e19208ebe8816f09ebae01a36f6ff342717ec9b7f489d",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x1e619dbea18f5e0e66d1c2df3f14416d3c804809",
      "before": "1157866317838460131284",
      "after": "1157880849655847472921",
      "delta": "14531817387341637",
      "balances_slot": "1",
      "slot_key": "0x1243704dc60c5e556e84b2a5aaa18897ecb29f4728ac27c52dc1516a9c97ab69",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x96522adc8d063b75d993bd9f7ea99a3ab19625c5",
      "before": "385927601535320099130",
      "after": "385932243764581324162",
      "delta": "4642229261225032",
      "balances_slot": "1",
      "slot_key": "0xfe119f95e0f5e26f254d64879cd69c7e6b1997bac02fa4193e17dabe0a15946a",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x0a5c6e7be1bd17e928ce128a356064831d8cbaeb",
      "before": "385913694595962540563",
      "after": "385918241226355435527",
      "delta": "4546630392894964",
      "balances_slot": "1",
      "slot_key": "0xb37ece418e56b907653aeb542c19a1266e53f604e8e07e60b5be9b06500c9501",
      "contract_name": "BEP20USDT"
    }
  ]
}
```

These diffs confirm the exact BNB profit for the adversary and the precise RANT and USDT flows out of the RANT/WBNB pair into the dead address, `rant_node`, the helper contract, and other stakeholders.

## Adversary Flow Analysis

Single BSC transaction combining helper-contract deployment, WBNB flash loan, DEX swaps, RANTToken's non-AMM transfer-to-self path, and RantCenter::sell_rant to drain RANT/WBNB liquidity and realize BNB profit.

### Adversary and Victim Accounts

**Adversary cluster:**
- 0xad2cb8f48e74065a0b884af9c5a4ecbba101be23 (EOA=true, contract=false): Sender of the seed transaction 0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99, deployer of helper contract 0x1e2D48E640243b04a9Fa76Eb49080E9aB110b4ac, and direct recipient of 311.475873604407652863 BNB according to balance_diff.json.
- 0x1e2d48e640243b04a9fa76eb49080e9ab110b4ac (EOA=false, contract=true): Contract created in the seed transaction by EOA 0xAD2Cb8f48E74065a0B884aF9C5a4ecbba101be23 that orchestrates the flash loan, DEX swaps, and calls into helper contract 0xFd9267eE6594bD8E82e8030c353870fA1773F7f8 and RANTToken.
- 0xfd9267ee6594bd8e82e8030c353870fa1773f7f8 (EOA=false, contract=true): Helper contract that receives the WBNB flash loan, interacts with the RANT/WBNB pair 0x42A93C3aF7Cb1BBc757dd2eC4977fd6D7916Ba1D, and accumulates 91775453110499942020276462 base units of RANTToken before selling via RantCenter::sell_rant; its behavior is fully driven by the adversary's seed transaction.

**Victim candidates:**
- RANTToken LP providers in RANT/WBNB pair 0x42A93C3aF7Cb1BBc757dd2eC4977fd6D7916Ba1D — 0x42a93c3af7cb1bbc757dd2ec4977fd6d7916ba1d (verified=false)
- RANTToken holders exposed to RantCenter and rant_node bonus mechanics — 0xc321ac21a07b3d593b269acdace69c3762ca2dd0 (verified=true)
- WBNB depositors using WBNB contract 0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c — 0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c (verified=true)

### Adversary Lifecycle Stages
#### Victim token configuration and ownership renounce

Transactions: 0xdeb1d333cdc90280ceed046213927b9e0045e92b57d5f8d2924a0de021e5d013 (block 52727325, mechanism=other), 0x8e8e89a2fc4eb9ca170051265a497546a25d02762e5589c975afcf3704573f00 (block 52727326, mechanism=other).

EOA 0x2373241ec958124cbd3636fc9561f7ec623adbe3, the RANTToken owner, calls changeBuyCenter to set rant_center to 0x9AdB8c52f0d845739Fd3e035Ed230F0D4cBa785a and changeRant_node to set rant_node to 0x1e619DbeA18F5E0e66D1c2dF3f14416d3c804809, then later renounces ownership. These transactions lock in a configuration where transfer(address(this), amount) will drive LP burns and sales through RantCenter and rant_node under fully public access.

Evidence: RANTToken source at artifacts/root_cause/seed/56/0xc321ac21a07b3d593b269acdace69c3762ca2dd0/src/TEST/RANT.sol and traces under artifacts/root_cause/data_collector/iter_2/tx/56/0xdeb1d333cdc90280ceed046213927b9e0045e92b57d5f8d2924a0de021e5d013/trace.cast.log and artifacts/root_cause/data_collector/iter_2/tx/56/0x8e8e89a2fc4eb9ca170051265a497546a25d02762e5589c975afcf3704573f00/trace.cast.log.

#### Adversary helper-contract deployment and flash-loan setup

Transactions: 0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99 (block 52974382, mechanism=flashloan).

EOA 0xAD2Cb8f48E74065a0B884aF9C5a4ecbba101be23 sends a type-2 contract-creation transaction that deploys helper contract 0x1e2D48E640243b04a9Fa76Eb49080E9aB110b4ac and invokes PancakeV3Pool 0x172fcD41E0913e95784454622d1c3724f546f849::flash to borrow WBNB into helper contract 0xFd9267eE6594bD8E82e8030c353870fA1773F7f8.

Evidence: Seed transaction metadata at artifacts/root_cause/seed/56/0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99/metadata.json, trace at artifacts/root_cause/seed/56/0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99/trace.cast.log, and PancakeV3Pool source at artifacts/root_cause/data_collector/iter_1/contract/56/0x172fcD41E0913e95784454622d1c3724f546f849/source/src/PancakeV3Pool.sol.

#### Exploit execution and BNB profit realization

Transactions: 0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99 (block 52974382, mechanism=other).

Within the same transaction, helper contract 0xFd9267eE6594bD8E82e8030c353870fA1773F7f8 routes WBNB through PancakeRouter 0x10ED43C718714eb63d5aA57B78B54704E256024E and the RANT/WBNB pair 0x42A93C3aF7Cb1BBc757dd2eC4977fd6D7916Ba1D to acquire RANT, calls RANTToken.transfer(address(this), amount) to trigger _sellBurnLiquidityPairTokens and move RANT out of the LP into 0x000000000000000000000000000000000000dEaD, rant_node, and the helper contract, then invokes RantCenter::sell_rant to sell RANT for WBNB, repays the flash loan, and forwards BNB to EOA 0xAD2C… and 0.1 BNB to EOA 0xD3b0….

Evidence: Seed transaction trace and balance diff at artifacts/root_cause/seed/56/0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99/trace.cast.log and artifacts/root_cause/seed/56/0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99/balance_diff.json, plus RANTToken source at artifacts/root_cause/seed/56/0xc321ac21a07b3d593b269acdace69c3762ca2dd0/src/TEST/RANT.sol and state diff at artifacts/root_cause/data_collector/iter_2/tx/56/0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99/state_diff_prestateTracer.json.

## Impact & Losses

### Quantified Losses
- BNB: 311.577265691407652863
- RANTToken base units from RANT/WBNB pair: 102509423181903444010952438

Native balance diffs show that WBNB contract 0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c loses exactly 311.577265691407652863 BNB during the seed transaction, while adversary EOA 0xAD2Cb8f48E74065a0B884aF9C5a4ecbba101be23 gains exactly 311.475873604407652863 BNB and EOA 0xD3b0d838cCCEAe7ebF1781D11D1bB741DB7Fe1A7 gains exactly 0.1 BNB, leaving 0.001392087000000000 BNB accounted for by protocol-level fees and residual flows. RANTToken balance diffs attribute a loss of exactly 102509423181903444010952438 base units of RANT from the RANT/WBNB Pancake pair 0x42A93C3aF7Cb1BBc757dd2eC4977fd6D7916Ba1D, of which 9660573064263151791608375 base units are sent to 0x000000000000000000000000000000000000dEaD, 1073397007140350199067597 base units are sent to rant_node 0x1e619DbeA18F5E0e66D1c2dF3f14416d3c804809, 91775453110499942020276462 base units are sent to helper contract 0xFd9267eE6594bD8E82e8030c353870fA1773F7f8, and 4 base units are sent to RantCenter proxy 0x9AdB8c52f0d845739Fd3e035Ed230F0D4cBa785a. These transfers reduce RANT liquidity in the RANT/WBNB pair and shift a large portion of RANT supply into a burn address and the protocol's rant_node bonus pool while routing BNB value to the adversary.

## References

- [1] Seed transaction trace 0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99 — `artifacts/root_cause/seed/56/0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99/trace.cast.log`
- [2] Seed transaction balance diffs for native and ERC20 tokens — `artifacts/root_cause/seed/56/0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99/balance_diff.json`
- [3] RANTToken verified source code — `artifacts/root_cause/seed/56/0xc321ac21a07b3d593b269acdace69c3762ca2dd0/src/TEST/RANT.sol`
- [4] RANTToken.changeBuyCenter and changeRant_node traces — `artifacts/root_cause/data_collector/iter_2/tx/56`
- [5] QuickNode prestateTracer state diff for seed transaction — `artifacts/root_cause/data_collector/iter_2/tx/56/0x2d9c1a00cf3d2fda268d0d11794ad2956774b156355e16441d6edb9a448e5a99/state_diff_prestateTracer.json`
