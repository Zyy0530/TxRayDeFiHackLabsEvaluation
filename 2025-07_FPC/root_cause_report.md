# FPC Token LP-burn Logic Exploit on BSC

## 1. Incident Overview TL;DR

On BSC, an unprivileged adversary used a helper contract and a single flash-loan-powered transaction to exploit FPC Token's LP-burn fee logic against its FPC/USDT Pancake pair, draining millions of USDT from the pool and realizing large profits in both USDT and BNB.


Root Cause (summary): The root cause is a protocol-level bug in FPC Token's LP-burn and fee mechanism that lets an attacker, via carefully structured sells and pool syncs, move a large portion of LP-held FPC to treasury/reward addresses and then trade against misaligned reserves, allowing extraction of disproportionate USDT from the FPC/USDT pool.


## 2. Key Background

- FPC Token at 0xb192d4a737430aa61cea4ce9bfb6432f7d42592f implements custom sell handling in its _update function and an LP-burn mechanism in burnLpToken, which transfers a configurable percentage of LP-held FPC from the usdtPool address to treasuryAddress and rewardPoolAddress before synchronizing reserves in the FPC/USDT Pancake pair.
- The FPC/USDT pair at 0xa1e08e10eb09857a8c6f2ef6cca297c1a081ed6b is a PancakePair-style AMM whose verified source is stored under artifacts/root_cause/data_collector/iter_1/contract/56/0xa1e08e10eb09857a8c6f2ef6cca297c1a081ed6b/source, and it is used as the primary liquidity pool for FPC/USDT trades.
- PancakeV3Pool 0x92b7807bf19b7dddf89b706143896d05228f3121 provides the USDT flash loan used to seed the exploit path, and PancakeRouter 0x10ED43C718714eb63d5aA57B78B54704E256024E routes part of the extracted USDT into BNB via USDT/WBNB liquidity that ultimately credits profits to EOA 0x421fa2f1fe768d9f7c95be7949bee96d3e3d6fe2.

## 3. Vulnerability Analysis

FPC Token's LP-burn logic incorrectly assumes that moving LP-held FPC to treasury/reward addresses and then synchronizing reserves preserves a safe price relationship; in reality, this sequence lets an attacker desynchronize pool reserves and then perform a large swap at a mispriced rate, draining USDT from the pool.

- FPC Token 0xb192d4a737430aa61cea4ce9bfb6432f7d42592f: _update and burnLpToken logic governing sells and LP-burn behaviour for the usdtPool address.
- FPC/USDT PancakePair 0xa1e08e10eb09857a8c6f2ef6cca297c1a081ed6b: AMM pool whose reserves are manipulated via FPC Token's LP-burn and sync sequence.
- Helper contract 0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3: orchestrates the flash loan, the sequence of sells and swaps, and routes the resulting USDT into BNB for the profit address.
- FPC Token deployed with LP-burn configuration that moves a significant fraction of LP-held FPC from the usdtPool to treasury/reward addresses during sells and then calls sync on the FPC/USDT pair without compensating USDT adjustments.
- Sufficient USDT liquidity in the FPC/USDT pair at 0xa1e08e10eb09857a8c6f2ef6cca297c1a081ed6b so that, after LP-burn and sync, a large FPC->USDT swap can extract substantial USDT at the mispriced rate.
- Availability of flash-loan or equivalent temporary USDT liquidity (here via PancakeV3Pool 0x92b7807bf19b7dddf89b706143896d05228f3121) to drive the necessary trade size within a single transaction while repaying the loan.
- Conservation-of-value across AMM reserve updates: the LP-burn and sync sequence allows reserves to be manipulated in a way that breaks the implicit assumption that AMM pricing reflects actual circulating supply and backing assets.
- Robust accounting of protocol-owned liquidity: moving LP-held FPC out of the pool to treasury/reward addresses without carefully adjusting or compensating the paired USDT reserves creates a hidden transfer of value from LP liquidity to protocol-controlled addresses and exposes traders/LProviders to extractable loss.
- Single-transaction exploitability: the design does not require time-delayed governance, multi-block observation, or complex on-chain orchestration; an unprivileged searcher can realize the opportunity in a single flash-loan transaction, making the ACT exposure practical for MEV-style adversaries.

### 3.1 FPC Token LP-burn and fee logic

```solidity
    function _update(
        address from,
        address to,
        uint256 value
    ) internal override {
        require(value > 0, "Invalid value");

        if (whitelisted[from] || whitelisted[to]) {
            super._update(from, to, value);
            emit TransferWithFee(from, to, value, 0);
            return;
        }
```


## 4. Detailed Root Cause Analysis

- R
- e
- v
- i
- e
- w
-  
- o
- f
-  
- a
- r
- t
- i
- f
- a
- c
- t
- s
- /
- r
- o
- o
- t
- _
- c
- a
- u
- s
- e
- /
- s
- e
- e
- d
- /
- 5
- 6
- /
- 0
- x
- b
- 1
- 9
- 2
- d
- 4
- a
- 7
- 3
- 7
- 4
- 3
- 0
- a
- a
- 6
- 1
- c
- e
- a
- 4
- c
- e
- 9
- b
- f
- b
- 6
- 4
- 3
- 2
- f
- 7
- d
- 4
- 2
- 5
- 9
- 2
- f
- /
- s
- r
- c
- /
- f
- u
- t
- u
- r
- e
- /
- t
- o
- k
- e
- n
- .
- s
- o
- l
-  
- s
- h
- o
- w
- s
-  
- t
- h
- a
- t
-  
- F
- P
- C
-  
- T
- o
- k
- e
- n
- '
- s
-  
- _
- u
- p
- d
- a
- t
- e
-  
- f
- u
- n
- c
- t
- i
- o
- n
-  
- r
- o
- u
- t
- e
- s
-  
- s
- e
- l
- l
- s
-  
- i
- n
- t
- o
-  
- a
-  
- p
- a
- t
- h
-  
- t
- h
- a
- t
-  
- c
- a
- l
- l
- s
-  
- b
- u
- r
- n
- L
- p
- T
- o
- k
- e
- n
-  
- f
- o
- r
-  
- t
- h
- e
-  
- u
- s
- d
- t
- P
- o
- o
- l
-  
- a
- d
- d
- r
- e
- s
- s
- .
-  
- b
- u
- r
- n
- L
- p
- T
- o
- k
- e
- n
-  
- m
- o
- v
- e
- s
-  
- a
-  
- f
- r
- a
- c
- t
- i
- o
- n
-  
- o
- f
-  
- L
- P
- -
- h
- e
- l
- d
-  
- F
- P
- C
-  
- o
- u
- t
-  
- o
- f
-  
- t
- h
- e
-  
- F
- P
- C
- /
- U
- S
- D
- T
-  
- p
- a
- i
- r
-  
- a
- t
-  
- 0
- x
- a
- 1
- e
- 0
- 8
- e
- 1
- 0
- e
- b
- 0
- 9
- 8
- 5
- 7
- a
- 8
- c
- 6
- f
- 2
- e
- f
- 6
- c
- c
- a
- 2
- 9
- 7
- c
- 1
- a
- 0
- 8
- 1
- e
- d
- 6
- b
-  
- t
- o
-  
- t
- r
- e
- a
- s
- u
- r
- y
- A
- d
- d
- r
- e
- s
- s
-  
- a
- n
- d
-  
- r
- e
- w
- a
- r
- d
- P
- o
- o
- l
- A
- d
- d
- r
- e
- s
- s
- ,
-  
- a
- n
- d
-  
- t
- h
- e
- n
-  
- t
- r
- i
- g
- g
- e
- r
- s
-  
- a
-  
- s
- y
- n
- c
-  
- o
- n
-  
- t
- h
- e
-  
- p
- a
- i
- r
- .
-  
- T
- h
- i
- s
-  
- c
- o
- m
- b
- i
- n
- a
- t
- i
- o
- n
-  
- m
- e
- a
- n
- s
-  
- t
- h
- a
- t
-  
- t
- h
- e
-  
- A
- M
- M
-  
- r
- e
- s
- e
- r
- v
- e
- s
-  
- f
- o
- r
-  
- F
- P
- C
-  
- a
- n
- d
-  
- U
- S
- D
- T
-  
- b
- e
- c
- o
- m
- e
-  
- i
- n
- c
- o
- n
- s
- i
- s
- t
- e
- n
- t
-  
- w
- i
- t
- h
-  
- t
- h
- e
-  
- t
- r
- u
- e
-  
- f
- l
- o
- a
- t
- :
-  
- a
-  
- l
- a
- r
- g
- e
-  
- a
- m
- o
- u
- n
- t
-  
- o
- f
-  
- F
- P
- C
-  
- i
- s
-  
- r
- e
- m
- o
- v
- e
- d
-  
- f
- r
- o
- m
-  
- t
- h
- e
-  
- p
- o
- o
- l
-  
- w
- i
- t
- h
- o
- u
- t
-  
- a
-  
- c
- o
- r
- r
- e
- s
- p
- o
- n
- d
- i
- n
- g
-  
- a
- d
- j
- u
- s
- t
- m
- e
- n
- t
-  
- t
- o
-  
- U
- S
- D
- T
- ,
-  
- y
- e
- t
-  
- t
- h
- e
-  
- A
- M
- M
-  
- p
- r
- i
- c
- e
-  
- r
- e
- m
- a
- i
- n
- s
-  
- b
- a
- s
- e
- d
-  
- o
- n
-  
- t
- h
- e
-  
- n
- e
- w
- ,
-  
- l
- o
- w
- e
- r
-  
- F
- P
- C
-  
- r
- e
- s
- e
- r
- v
- e
- .
-  
- I
- n
-  
- t
- h
- e
-  
- e
- x
- p
- l
- o
- i
- t
-  
- t
- r
- a
- n
- s
- a
- c
- t
- i
- o
- n
-  
- 0
- x
- 3
- a
- 9
- d
- d
- 2
- .
- .
- .
- f
- 5
- 9
- 3
- 7
- ,
-  
- t
- h
- e
-  
- h
- e
- l
- p
- e
- r
-  
- c
- o
- n
- t
- r
- a
- c
- t
-  
- 0
- x
- b
- f
- 6
- e
- 7
- 0
- 6
- d
- 5
- 0
- 5
- e
- 8
- 1
- a
- d
- 1
- f
- 7
- 3
- b
- b
- c
- 0
- b
- a
- b
- f
- e
- 2
- b
- 4
- 1
- 4
- b
- a
- 3
- e
- b
- 3
-  
- t
- a
- k
- e
- s
-  
- a
-  
- 2
- 3
- ,
- 0
- 2
- 0
- ,
- 0
- 0
- 0
-  
- U
- S
- D
- T
-  
- f
- l
- a
- s
- h
-  
- l
- o
- a
- n
-  
- f
- r
- o
- m
-  
- P
- a
- n
- c
- a
- k
- e
- V
- 3
- P
- o
- o
- l
-  
- 0
- x
- 9
- 2
- b
- 7
- 8
- 0
- 7
- b
- f
- 1
- 9
- b
- 7
- d
- d
- d
- f
- 8
- 9
- b
- 7
- 0
- 6
- 1
- 4
- 3
- 8
- 9
- 6
- d
- 0
- 5
- 2
- 2
- 8
- f
- 3
- 1
- 2
- 1
- ,
-  
- e
- x
- e
- c
- u
- t
- e
- s
-  
- s
- e
- l
- l
-  
- f
- l
- o
- w
- s
-  
- i
- n
- t
- o
-  
- t
- h
- e
-  
- F
- P
- C
- /
- U
- S
- D
- T
-  
- p
- a
- i
- r
-  
- t
- h
- a
- t
-  
- i
- n
- v
- o
- k
- e
-  
- _
- u
- p
- d
- a
- t
- e
-  
- a
- n
- d
-  
- b
- u
- r
- n
- L
- p
- T
- o
- k
- e
- n
- ,
-  
- a
- n
- d
-  
- t
- h
- e
- n
-  
- p
- e
- r
- f
- o
- r
- m
- s
-  
- a
-  
- l
- a
- r
- g
- e
-  
- F
- P
- C
- -
- >
- U
- S
- D
- T
-  
- s
- w
- a
- p
-  
- a
- g
- a
- i
- n
- s
- t
-  
- t
- h
- e
-  
- n
- o
- w
- -
- m
- i
- s
- a
- l
- i
- g
- n
- e
- d
-  
- r
- e
- s
- e
- r
- v
- e
- s
- .
-  
- B
- a
- l
- a
- n
- c
- e
-  
- d
- i
- f
- f
- s
-  
- i
- n
-  
- a
- r
- t
- i
- f
- a
- c
- t
- s
- /
- r
- o
- o
- t
- _
- c
- a
- u
- s
- e
- /
- s
- e
- e
- d
- /
- 5
- 6
- /
- 0
- x
- 3
- a
- 9
- d
- d
- 2
- 1
- 6
- f
- b
- 6
- 3
- 1
- 4
- c
- 0
- 1
- 3
- f
- a
- 8
- c
- 4
- f
- 8
- 5
- b
- f
- b
- b
- e
- 0
- e
- d
- 0
- a
- 7
- 3
- 2
- 0
- 9
- f
- 5
- 4
- c
- 5
- 7
- c
- 1
- a
- a
- b
- 0
- 2
- b
- a
- 9
- 8
- 9
- f
- 5
- 9
- 3
- 7
- /
- b
- a
- l
- a
- n
- c
- e
- _
- d
- i
- f
- f
- .
- j
- s
- o
- n
-  
- s
- h
- o
- w
-  
- t
- h
- e
-  
- p
- a
- i
- r
-  
- l
- o
- s
- i
- n
- g
-  
- 4
- ,
- 6
- 7
- 3
- ,
- 8
- 8
- 3
- .
- 5
- 2
- 7
- 1
- 4
- 0
- 2
- 0
- 1
- 0
- 1
- 1
- 2
- 0
- 5
- 3
- 2
- 1
-  
- U
- S
- D
- T
-  
- a
- n
- d
-  
- 7
- 1
- 5
- ,
- 9
- 4
- 6
- .
- 6
- 1
- 9
- 2
- 5
- 9
- 2
- 5
- 1
- 8
- 5
- 1
- 6
- 0
- 0
- 4
- 1
- 7
-  
- F
- P
- C
-  
- w
- h
- i
- l
- e
-  
- t
- h
- e
-  
- a
- t
- t
- a
- c
- k
- e
- r
-  
- c
- l
- u
- s
- t
- e
- r
-  
- g
- a
- i
- n
- s
-  
- U
- S
- D
- T
-  
- a
- n
- d
-  
- B
- N
- B
- ,
-  
- c
- o
- n
- f
- i
- r
- m
- i
- n
- g
-  
- t
- h
- a
- t
-  
- t
- h
- e
-  
- L
- P
- -
- b
- u
- r
- n
-  
- l
- o
- g
- i
- c
-  
- p
- e
- r
- m
- i
- t
- t
- e
- d
-  
- e
- x
- t
- r
- a
- c
- t
- i
- o
- n
-  
- o
- f
-  
- U
- S
- D
- T
-  
- b
- e
- y
- o
- n
- d
-  
- w
- h
- a
- t
-  
- a
-  
- n
- o
- r
- m
- a
- l
-  
- c
- o
- n
- s
- t
- a
- n
- t
- -
- p
- r
- o
- d
- u
- c
- t
-  
- A
- M
- M
-  
- w
- o
- u
- l
- d
-  
- a
- l
- l
- o
- w
-  
- u
- n
- d
- e
- r
-  
- c
- o
- n
- s
- e
- r
- v
- a
- t
- i
- o
- n
- -
- o
- f
- -
- v
- a
- l
- u
- e
-  
- a
- s
- s
- u
- m
- p
- t
- i
- o
- n
- s
- .

## 5. Adversary Flow Analysis

The adversary executes a single BSC transaction via a helper contract that takes a USDT flash loan, drives FPC Token's LP-burn logic on its FPC/USDT pool to desynchronize reserves, performs a large FPC->USDT swap to extract USDT, and routes part of the proceeds into BNB before repaying the loan and consolidating profit at a dedicated profit address.


### 5.1 Adversary roles and accounts

- 0x18dd258631b23777c101440380bf053c79db3d9d (cluster_member): EOA=true, contract=false. Reason: Seed sender EOA that deploys helper contract 0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3 (see artifacts/root_cause/data_collector/iter_2/address/56/0x18dd258631b23777c101440380bf053c79db3d9d/txlist.json) and submits the exploit transaction 0x3a9dd2...f5937 while paying gas.
- 0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3 (cluster_member): EOA=false, contract=true. Reason: Helper/orchestrator contract deployed by 0x18dd258631b23777c101440380bf053c79db3d9d that receives the exploit call, initiates the USDT flash loan, executes the sequence of swaps and LP-burn-triggering sells, and routes funds, as summarized in artifacts/root_cause/data_collector/iter_3/contract/56/0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3/function_0x1921e20f_summary.json.
- 0x421fa2f1fe768d9f7c95be7949bee96d3e3d6fe2 (cluster_member): EOA=true, contract=false. Reason: Primary profit-receiving EOA that ends the exploit transaction with 731.533618044520680054 BNB and 4,171,581.527140201011205321 USDT gained, as shown in artifacts/root_cause/seed/56/0x3a9dd216fb6314c013fa8c4f85bfbbe0ed0a73209f54c57c1aab02ba989f5937/balance_diff.json and the cluster P/L summary in artifacts/root_cause/data_collector/iter_3/summary/cluster_pl_summary_usdt_bnb.json.
- Victim candidate FPC Token at 0xb192d4a737430aa61cea4ce9bfb6432f7d42592f (verified=true)
- Victim candidate FPC/USDT PancakePair at 0xa1e08e10eb09857a8c6f2ef6cca297c1a081ed6b (verified=true)
- Victim candidate USDT/WBNB liquidity used for routing at 0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae (verified=false)

### 5.2 Lifecycle stages and key transactions

**Stage: Adversary funding and helper deployment**
- Tx 0xebc04e9d47f56ae591256448734f199e7c3a3056b37f62f99ef8b2ea09e5c8ec on BSC (chainid 56), block 52624678, mechanism transfer
- Tx 0x4e82a46d0ac8edc89f5f1fbef4a9b6b181d92bbeee1f3195d411d3299abcb7e0 on BSC (chainid 56), block 52624696, mechanism contract_deployment
  - Effect: EOA 0x18dd258631b23777c101440380bf053c79db3d9d receives initial BNB funding and deploys helper contract 0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3, preparing the infrastructure needed to execute the exploit.
  - Evidence: artifacts/root_cause/data_collector/iter_2/address/56/0x18dd258631b23777c101440380bf053c79db3d9d/txlist.json
**Stage: Flash loan and LP-burn manipulation**
- Tx 0x3a9dd216fb6314c013fa8c4f85bfbbe0ed0a73209f54c57c1aab02ba989f5937 on BSC (chainid 56), block 52624701, mechanism flashloan_and_swaps
  - Effect: Helper contract 0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3 borrows 23,020,000 USDT from PancakeV3Pool 0x92b7807bf19b7dddf89b706143896d05228f3121, executes sells into the FPC/USDT pair that trigger FPC Token's LP-burn and sync behaviour, and then performs a large FPC->USDT swap against the mispriced pool.
  - Evidence: artifacts/root_cause/seed/56/0x3a9dd216fb6314c013fa8c4f85bfbbe0ed0a73209f54c57c1aab02ba989f5937/trace.cast.log; artifacts/root_cause/data_collector/iter_3/contract/56/0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3/function_0x1921e20f_summary.json; artifacts/root_cause/seed/56/0xb192d4a737430aa61cea4ce9bfb6432f7d42592f/src/future/token.sol
**Stage: Profit routing and loan repayment**
- Tx 0x3a9dd216fb6314c013fa8c4f85bfbbe0ed0a73209f54c57c1aab02ba989f5937 on BSC (chainid 56), block 52624701, mechanism swaps_and_repayment
  - Effect: The helper contract routes part of the extracted USDT through USDT/WBNB liquidity at 0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae and PancakeRouter 0x10ED43C718714eb63d5aA57B78B54704E256024E into BNB, repays the USDT flash loan, and leaves the adversary profit address 0x421fa2f1fe768d9f7c95be7949bee96d3e3d6fe2 with net-positive BNB and USDT balances while the sender EOA only pays gas.
  - Evidence: artifacts/root_cause/seed/56/0x3a9dd216fb6314c013fa8c4f85bfbbe0ed0a73209f54c57c1aab02ba989f5937/balance_diff.json; artifacts/root_cause/data_collector/iter_1/summary/pl_summary_usdt_bnb.json; artifacts/root_cause/data_collector/iter_3/summary/cluster_pl_summary_usdt_bnb.json

### 5.3 Seed transaction balance changes

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xa1e08e10eb09857a8c6f2ef6cca297c1a081ed6b",
      "before": "4673883534817151619771979",
      "after": "7676950608566658",
      "delta": "-4673883527140201011205321",
      "balances_slot": "1",
      "slot_key": "0xa245752947cb058e83573a27d64340f11069e0b476f372a2d0e222b804e06a3f",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x421fa2f1fe768d9f7c95be7949bee96d3e3d6fe2",
      "before": "0",
      "after": "4171581527140201011205321",
      "delta": "4171581527140201011205321",
      "balances_slot": "1",
      "slot_key": "0x505b65567f6433981ead2c3285f8bb1821c5716eb9e984ac2fcaa6556670c194",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0xb192d4a737430aa61cea4ce9bfb6432f7d42592f",
      "holder": "0xa1e08e10eb09857a8c6f2ef6cca297c1a081ed6b",
      "before": "951015731552334769101823",
      "after": "235069112293082917501406",
      "delta": "-715946619259251851600417",
      "balances_slot": "0",
      "slot_key": "0x5d521245d4cd41381ead1692a7a510e45fa5c687cce56c8d7852427912accc0d",
      "contract_name": "Token"
    },
    {
      "token": "0xb192d4a737430aa61cea4ce9bfb6432f7d42592f",
      "holder": "0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3",
      "before": "0",
      "after": "542737799722769701862543",
      "delta": "542737799722769701862543",
      "balances_slot": "0",
      "slot_key": "0xfe9488ccc2b814d1d8bb429ea9c816bde94be735acb010188376d3705e37fd07",
      "contract_name": "Token"
    }
  ]
}
```


## 6. Impact & Losses

- Total loss in USDT: 4673883.527140201011205321

Balance diffs for the exploit transaction show that the FPC/USDT pair at 0xa1e08e10eb09857a8c6f2ef6cca297c1a081ed6b loses 4,673,883.527140201011205321 USDT and 715,946.619259251851600417 FPC, while the adversary cluster ends with 4,171,581.527140201011205321 USDT and 731.533618044520680054 BNB at address 0x421fa2f1fe768d9f7c95be7949bee96d3e3d6fe2 and 542,737.799722769701862543 FPC at helper contract 0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3. This represents a significant extraction of value from LPs and traders in the FPC/USDT pool, expressed directly in token units without external price conversion.

```json
{
  "chainid": 56,
  "txhash": "0x3a9dd216fb6314c013fa8c4f85bfbbe0ed0a73209f54c57c1aab02ba989f5937",
  "cluster_addresses": [
    "0x18dd258631b23777c101440380bf053c79db3d9d",
    "0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3",
    "0x421fa2f1fe768d9f7c95be7949bee96d3e3d6fe2"
  ],
  "native_pl": {
    "total_delta_wei": "731533563628020680054",
    "total_delta_bnb": "731.533563628020680054"
  },
  "per_address": {
    "0x18dd258631b23777c101440380bf053c79db3d9d": {
      "delta_native_wei": "-54416500000000",
      "delta_native_bnb": "-0.0000544165",
      "gas_paid_wei": "54416500000000",
      "gas_paid_bnb": "0.0000544165"
    },
    "0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3": {
      "delta_native_wei": "0",
      "delta_native_bnb": "0",
      "gas_paid_wei": "0",
      "gas_paid_bnb": "0"
    },
    "0x421fa2f1fe768d9f7c95be7949bee96d3e3d6fe2": {
      "delta_native_wei": "731533618044520680054",
      "delta_native_bnb": "731.533618044520680054",
      "gas_paid_wei": "0",
      "gas_paid_bnb": "0"
    }
  },
  "erc20_deltas": {
    "0x421fa2f1fe768d9f7c95be7949bee96d3e3d6fe2": {
      "0x55d398326f99059ff775485246999027b3197955": {
        "delta_wei": "4171581527140201011205321",
        "delta_token_units": "4171581.527140201011205321",
        "contract_name": "BEP20USDT"
      }
    },
    "0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3": {
      "0xb192d4a737430aa61cea4ce9bfb6432f7d42592f": {
        "delta_wei": "542737799722769701862543",
        "delta_token_units": "542737.799722769701862543",
        "contract_name": "Token"
      }
    }
  },
  "notes": {
    "usdt_equivalent": "Not computed here; would require price data for BNB and Token at block 0x322FD3D."
  }
}
```


## 7. References

- [1] Seed transaction metadata and balance diff: artifacts/root_cause/seed/56/0x3a9dd216fb6314c013fa8c4f85bfbbe0ed0a73209f54c57c1aab02ba989f5937/
- [2] FPC Token source (token.sol): artifacts/root_cause/seed/56/0xb192d4a737430aa61cea4ce9bfb6432f7d42592f/src/future/token.sol
- [3] FPC/USDT PancakePair source: artifacts/root_cause/data_collector/iter_1/contract/56/0xa1e08e10eb09857a8c6f2ef6cca297c1a081ed6b/source
- [4] Cluster P/L summary in BNB and token units: artifacts/root_cause/data_collector/iter_3/summary/cluster_pl_summary_usdt_bnb.json
