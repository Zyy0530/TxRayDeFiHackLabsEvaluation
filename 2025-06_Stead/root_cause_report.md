# Arbitrum aeWETH–USDT Single-Tx Flash-Loan MEV Arbitrage


## 1. Incident Overview TL;DR

On Arbitrum One (chainid 42161), an unprivileged searcher EOA 0x5fb0b8584b34e56e386941a65dbe455ad43c5a23 used a custom solver contract 0x34c7c354c823af400696febdc4f31c4df0175828 to execute a single-tx Balancer flash-loan arbitrage in tx 0x32dbfce2253002498cd41a2d79e249250f92673bc3de652f3919591ee26e8001. The solver borrowed aeWETH, routed through SteadToken/USDT and aeWETH/USDT-like Uniswap V3 pools, withdrew aeWETH to native ETH, repaid the flash loan, and left the EOA with roughly 5.9454 ETH net profit funded by a reduction in aeWETH's ETH backing.


## 2. Key Background


## 3. Vulnerability Analysis


## 4. Detailed Root Cause Analysis


```solidity
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2020, Offchain Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

pragma solidity ^0.6.11;

import "./L2GatewayToken.sol";
import "./IWETH9.sol";

/// @title Arbitrum extended WETH
contract aeWETH is L2GatewayToken, IWETH9 {
    function initialize(
        string memory _name,
        string memory _symbol,
        uint8 _decimals,
        address _l2Gateway,
        address _l1Address
    ) external {
        L2GatewayToken._initialize(_name, _symbol, _decimals, _l2Gateway, _l1Address);
    }

    function bridgeMint(address account, uint256 amount) external virtual override {
        // we want weth to always be fully collaterized
        revert("NO_BRIDGE_MINT");
    }

```

Seed contract source for aeWETH, showing deposit/withdraw backing behavior that makes aeWETH fully collateralized by ETH and allows burning tokens for native ETH.


```text
Warning: This is a nightly build of Foundry. It is recommended to use the latest stable version. To mute this warning set `FOUNDRY_DISABLE_NIGHTLY_WARNING` in your environment. 

Executing previous transactions from the block.
Traces:
  [333620] 0x34c7c354c823af400696FEBDC4F31c4DF0175828::solve_108B1F57E(80883131041954079627928762629810011289044651237123881883579266236416 [8.088e67], 59745900059881997244017092646751465273185764037227916908800009736089044213876 [5.974e76])
    ├─ [319015] 0xBA12222222228d8Ba445958a75a0704d566BF2C8::flashLoan(0x34c7c354c823af400696FEBDC4F31c4DF0175828, [0x82aF49447D8a07e3bd95BD0d56f35241523fBab1], [876541714919625 [8.765e14]], 0x)
    │   ├─ [9796] TransparentUpgradeableProxy::fallback(0xBA12222222228d8Ba445958a75a0704d566BF2C8) [staticcall]
    │   │   ├─ [2553] aeWETH::balanceOf(0xBA12222222228d8Ba445958a75a0704d566BF2C8) [delegatecall]
    │   │   │   └─ ← [Return] 1017655273221995556063 [1.017e21]
    │   │   └─ ← [Return] 1017655273221995556063 [1.017e21]
    │   ├─ [2350] 0xce88686553686DA562CE7Cea497CE749DA109f9F::getFlashLoanFeePercentage() [staticcall]
    │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    │   ├─ [11800] TransparentUpgradeableProxy::fallback(0x34c7c354c823af400696FEBDC4F31c4DF0175828, 876541714919625 [8.765e14])
    │   │   ├─ [11054] aeWETH::transfer(0x34c7c354c823af400696FEBDC4F31c4DF0175828, 876541714919625 [8.765e14]) [delegatecall]
    │   │   │   ├─ emit Transfer(from: 0xBA12222222228d8Ba445958a75a0704d566BF2C8, to: 0x34c7c354c823af400696FEBDC4F31c4DF0175828, value: 876541714919625 [8.765e14])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 0xbe6f39c14d3251d91e4c56e8710198e2e3a2787a1dac0dbc1c448869b41b8f56: 0x00000000000000000000000000000000000000000000000000000000077f2f39 → 0x00000000000000000000000000000000000000000000000000031d35cd0ba002
    │   │   │   │   @ 0x8e136277087394ae84bd88b3538db688c3763bf01dc7ed78e5235dc311d5959c: 0x0000000000000000000000000000000000000000000000372acdcf3a0822ecdf → 0x0000000000000000000000000000000000000000000000372acab20442967c16
    │   │   │   └─ ← [Return] true
    │   │   └─ ← [Return] true
    │   ├─ [273344] 0x34c7c354c823af400696FEBDC4F31c4DF0175828::receiveFlashLoan([0x82aF49447D8a07e3bd95BD0d56f35241523fBab1], [876541714919625 [8.765e14]], [0], 0x)
    │   │   ├─ [60051] 0xf9FF933f51bA180a474634440a406c95DfB27596::16fb27ce(0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001)
    │   │   │   ├─ [55091] 0xca9d57Cd258731A07C56c01CA353e8B0e2798E25::16fb27ce(0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001) [delegatecall]
    │   │   │   │   ├─ [9393] 0x3e0340eA2F0077eeC8cBf6494A534AAfd1AFCCB4::getContractAddress("SteadToken") [staticcall]
    │   │   │   │   │   ├─ [4436] 0xB8222Af89e412AafA887C751B56380f2Ca273aD5::getContractAddress("SteadToken") [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 0x00000000000000000000000042f4e5fcd12d59e879dbcb908c76032a4fb0303b
    │   │   │   │   │   └─ ← [Return] 0x00000000000000000000000042f4e5fcd12d59e879dbcb908c76032a4fb0303b
    │   │   │   │   ├─ [7932] 0x42F4e5Fcd12D59e879dbcB908c76032a4fb0303b::balanceOf(0xf9FF933f51bA180a474634440a406c95DfB27596) [staticcall]
    │   │   │   │   │   ├─ [2984] 0x5beD8d4EC3efE8746E07ed790D32F4352159a106::balanceOf(0xf9FF933f51bA180a474634440a406c95DfB27596) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 135000000000 [1.35e11]
    │   │   │   │   │   └─ ← [Return] 135000000000 [1.35e11]
    │   │   │   │   ├─ [29140] 0x42F4e5Fcd12D59e879dbcB908c76032a4fb0303b::transfer(0x34c7c354c823af400696FEBDC4F31c4DF0175828, 135000000000 [1.35e11])
    │   │   │   │   │   ├─ [28689] 0x5beD8d4EC3efE8746E07ed790D32F4352159a106::transfer(0x34c7c354c823af400696FEBDC4F31c4DF0175828, 135000000000 [1.35e11]) [delegatecall]
    │   │   │   │   │   │   ├─ emit Transfer(from: 0xf9FF933f51bA180a474634440a406c95DfB27596, to: 0x34c7c354c823af400696FEBDC4F31c4DF0175828, value: 135000000000 [1.35e11])
    │   │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   │   @ 0x1fea4e7573d0ff19ef90bc20e44279b78512d13bf14ff02f296db744c7a23e04: 0 → 0x0000000000000000000000000000000000000000000000000000001f6ea08600
    │   │   │   │   │   │   │   @ 0x14670814a42fdc10e2738cb9010804a7e105018d0a8ed654e074713ce4fc9be1: 0x0000000000000000000000000000000000000000000000000000001f6ea08600 → 0
    │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   └─ ← [Stop]
    │   │   │   └─ ← [Return]
    │   │   ├─ [171016] 0x641C00A822e8b671738d32a431a4Fb6074E5c79d::swap(0x34c7c354c823af400696FEBDC4F31c4DF0175828, false, 14484878986 [1.448e10], 1461446703485210103287273052203988822378723970341 [1.461e48], 0x)
    │   │   │   ├─ [9000] TransparentUpgradeableProxy::fallback(0x34c7c354c823af400696FEBDC4F31c4DF0175828, 5945405436886901223 [5.945e18])
    │   │   │   │   ├─ [8254] aeWETH::transfer(0x34c7c354c823af400696FEBDC4F31c4DF0175828, 5945405436886901223 [5.945e18]) [delegatecall]
    │   │   │   │   │   ├─ emit Transfer(from: 0x641C00A822e8b671738d32a431a4Fb6074E5c79d, to: 0x34c7c354c823af400696FEBDC4F31c4DF0175828, value: 5945405436886901223 [5.945e18])
    │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   @ 0x94d15705f6bff62f10a25815acfbecf67ad26084447c11b4f67826708268c366: 0x0000000000000000000000000000000000000000000000823b1442a3be037144 → 0x000000000000000000000000000000000000000000000081e891efe516b18f5d
    │   │   │   │   │   │   @ 0xbe6f39c14d3251d91e4c56e8710198e2e3a2787a1dac0dbc1c448869b41b8f56: 0x00000000000000000000000000000000000000000000000000031d35cd0ba002 → 0x00000000000000000000000000000000000000000000000052856ff4745d81e9
    │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [9934] 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9::balanceOf(0x641C00A822e8b671738d32a431a4Fb6074E5c79d) [staticcall]
    │   │   │   │   ├─ [2603] 0x3263CD783823d04a6B9819517E0E6840d37cA3F4::balanceOf(0x641C00A822e8b671738d32a431a4Fb6074E5c79d) [delegatecall]
    │   │   │   │   │   └─ ← [Return] 4311400548008 [4.311e12]
    │   │   │   │   └─ ← [Return] 4311400548008 [4.311e12]
    │   │   │   ├─ [77465] 0x34c7c354c823af400696FEBDC4F31c4DF0175828::uniswapV3SwapCallback(-5945405436886901223 [-5.945e18], 14484878986 [1.448e10], 0x)
    │   │   │   │   ├─ [72551] 0x3e08920C0Ab3B590186B1E8eB84e66EE274C383f::swap(0x641C00A822e8b671738d32a431a4Fb6074E5c79d, true, 135000000000 [1.35e11], 4295128740 [4.295e9], 0x)
    │   │   │   │   │   ├─ [13921] 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9::transfer(0x641C00A822e8b671738d32a431a4Fb6074E5c79d, 14484878986 [1.448e10])
    │   │   │   │   │   │   ├─ [13087] 0x3263CD783823d04a6B9819517E0E6840d37cA3F4::transfer(0x641C00A822e8b671738d32a431a4Fb6074E5c79d, 14484878986 [1.448e10]) [delegatecall]
    │   │   │   │   │   │   │   ├─ emit Transfer(from: 0x3e08920C0Ab3B590186B1E8eB84e66EE274C383f, to: 0x641C00A822e8b671738d32a431a4Fb6074E5c79d, value: 14484878986 [1.448e10])
    │   │   │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   │   │   @ 0x94d15705f6bff62f10a25815acfbecf67ad26084447c11b4f67826708268c366: 0x000000000000000000000000000000000000000000000000000003ebd37f86a8 → 0x000000000000000000000000000000000000000000000000000003ef32dd3d32
    │   │   │   │   │   │   │   │   @ 0x104cff047a1f01e82d513d5b50083fcd4816f16356fb40829169faeb8dc0a56b: 0x00000000000000000000000000000000000000000000000000000006ada9cac6 → 0x000000000000000000000000000000000000000000000000000000034e4c143c
    │   │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   ├─ [3432] 0x42F4e5Fcd12D59e879dbcB908c76032a4fb0303b::balanceOf(0x3e08920C0Ab3B590186B1E8eB84e66EE274C383f) [staticcall]
    │   │   │   │   │   │   ├─ [2984] 0x5beD8d4EC3efE8746E07ed790D32F4352159a106::balanceOf(0x3e08920C0Ab3B590186B1E8eB84e66EE274C383f) [delegatecall]
    │   │   │   │   │   │   │   └─ ← [Return] 134087070323 [1.34e11]
    │   │   │   │   │   │   └─ ← [Return] 134087070323 [1.34e11]
    │   │   │   │   │   ├─ [8909] 0x34c7c354c823af400696FEBDC4F31c4DF0175828::uniswapV3SwapCallback(135000000000 [1.35e11], -14484878986 [-1.448e10], 0x)
    │   │   │   │   │   │   ├─ [7240] 0x42F4e5Fcd12D59e879dbcB908c76032a4fb0303b::transfer(0x3e08920C0Ab3B590186B1E8eB84e66EE274C383f, 135000000000 [1.35e11])
    │   │   │   │   │   │   │   ├─ [6789] 0x5beD8d4EC3efE8746E07ed790D32F4352159a106::transfer(0x3e08920C0Ab3B590186B1E8eB84e66EE274C383f, 135000000000 [1.35e11]) [delegatecall]
    │   │   │   │   │   │   │   │   ├─ emit Transfer(from: 0x34c7c354c823af400696FEBDC4F31c4DF0175828, to: 0x3e08920C0Ab3B590186B1E8eB84e66EE274C383f, value: 135000000000 [1.35e11])
    │   │   │   │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   │   │   │   @ 0x1fea4e7573d0ff19ef90bc20e44279b78512d13bf14ff02f296db744c7a23e04: 0x0000000000000000000000000000000000000000000000000000001f6ea08600 → 0
    │   │   │   │   │   │   │   │   │   @ 0x2bd6f78e7540a12f9c9c81e47ddebbcb0dbc965efdad19f4e86edcf9b859c40b: 0x0000000000000000000000000000000000000000000000000000001f38365273 → 0x0000000000000000000000000000000000000000000000000000003ea6d6d873
    │   │   │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   ├─ [1432] 0x42F4e5Fcd12D59e879dbcB908c76032a4fb0303b::balanceOf(0x3e08920C0Ab3B590186B1E8eB84e66EE274C383f) [staticcall]
    │   │   │   │   │   │   ├─ [984] 0x5beD8d4EC3efE8746E07ed790D32F4352159a106::balanceOf(0x3e08920C0Ab3B590186B1E8eB84e66EE274C383f) [delegatecall]
```

Seed transaction trace for 0x32dbfce2…, illustrating the Balancer flashLoan, SteadToken/USDT and aeWETH/USDT pool swaps, aeWETH withdraw, and ETH transfer to the adversary EOA.


```json
{
  "chainid": 42161,
  "txhash": "0x32dbfce2253002498cd41a2d79e249250f92673bc3de652f3919591ee26e8001",
  "native_balance_deltas": [
    {
      "address": "0x5fb0b8584b34e56e386941a65dbe455ad43c5a23",
      "before_wei": "32032755668553193844",
      "after_wei": "37978157719535870740",
      "delta_wei": "5945402050982676896"
    },
    {
      "address": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
      "before_wei": "202049621142453137525713",
      "after_wei": "202043675737016124848817",
      "delta_wei": "-5945405437012676896"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
      "holder": "0x34c7c354c823af400696febdc4f31c4df0175828",
      "before": "125775673",
      "after": "0",
      "delta": "-125775673",
      "balances_slot": "51",
      "slot_key": "0xbe6f39c14d3251d91e4c56e8710198e2e3a2787a1dac0dbc1c448869b41b8f56",
      "layout_address": "0x8b194beae1d3e0788a1a35173978001acdfba668",
      "contract_name": "aeWETH"
    },
    {
      "token": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
      "holder": "0x641c00a822e8b671738d32a431a4fb6074e5c79d",
      "before": "2402333830401048670532",
      "after": "2396388424964161769309",
      "delta": "-5945405436886901223",
      "balances_slot": "51",
      "slot_key": "0x94d15705f6bff62f10a25815acfbecf67ad26084447c11b4f67826708268c366",
      "layout_address": "0x8b194beae1d3e0788a1a35173978001acdfba668",
      "contract_name": "aeWETH"
    },
```

Prestate native and ERC20 balance diffs for the seed tx, showing ETH flowing from aeWETH to the adversary EOA and aeWETH being drained from the aeWETH/USDT-like pool.


## 5. Adversary Flow Analysis


## 6. Impact & Losses

Total loss: 5.945398664952676896 ETH (reference asset)

Native ETH backing held by the aeWETH contract 0x82aF49447D8A07E3Bd95BD0d56F35241523fBab1 decreases by 5.945405437012676896 ETH while the adversary EOA gains a net 5.945398664952676896 ETH after gas (as shown by prestate native balance deltas and gas accounting), with the remainder of the backing lost to sequencer/fee recipients. ERC20 balance deltas show that Uniswap V3 pool 0x641C00A822e8b671738d32a431a4Fb6074E5c79d loses 5.945405436886901223 aeWETH units and gains 14484878986 ArbitrumExtensionV2 USDT, and SteadToken/USDT pool 0x3e08920C0Ab3B590186B1E8eB84e66EE274C383f shifts USDT in the opposite direction; these changes represent a redistribution of value from aeWETH backing and Uniswap LPs to the adversary and to fee recipients rather than a protocol logic failure.


## 7. References

[1] Seed tx metadata (Arbitrum 42161, 0x32dbfce2...) – artifacts/root_cause/seed/42161/0x32dbfce2253002498cd41a2d79e249250f92673bc3de652f3919591ee26e8001/metadata.json

[2] Seed tx trace (flash loan and swaps) – artifacts/root_cause/seed/42161/0x32dbfce2253002498cd41a2d79e249250f92673bc3de652f3919591ee26e8001/trace.cast.log

[3] Prestate native and ERC20 balance diffs – artifacts/root_cause/data_collector/iter_1/tx/42161/0x32dbfce2253002498cd41a2d79e249250f92673bc3de652f3919591ee26e8001/balance_diff_prestate.json

[4] Adversary EOA full tx history – artifacts/root_cause/data_collector/iter_2/address/42161/0x5fb0b8584b34e56e386941a65dbe455ad43c5a23/etherscan_normal_txlist_full.json

[5] aeWETH, SteadToken, ArbitrumExtensionV2 source – artifacts/root_cause/seed/42161/0x8b194beae1d3e0788a1a35173978001acdfba668

[6] Uniswap V3 pool sources (SteadToken/USDT and aeWETH/USDT-like) – artifacts/root_cause/data_collector/iter_1/contract/42161/0x3e08920C0Ab3B590186B1E8eB84e66EE274C383f/source
