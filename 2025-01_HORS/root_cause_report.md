# HORS helper LP burn on BSC

## Incident Overview TL;DR

On BSC (chainid 56), an unprivileged EOA 0x8efb9311700439d70025d2b372fb54c61a60d5df deployed helper-orchestrator contract 0x75ff620ff0e63243e86b99510cdbad1d5e76524e and used a single flash-loan-assisted transaction 0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7 to drain protocol-owned HORS/WBNB liquidity. The orchestrator called public function f78283c7 on helper contract 0x6f3390c6c200e9be81b32110ce191a293dc0eaba, which held all HORS/WBNB PancakePair LP tokens created from the project’s own assets. f78283c7 transferred the entire LP balance to PancakeRouter 0x10ed43c718714eb63d5aa57b78b54704e256024e, burned it, and sent the underlying HORS and WBNB reserves to 0x75ff..., which repaid the flash loan and forwarded 14.799349453861436868 WBNB of profit to the EOA.


**Root Cause (Brief):** Public helper function f78283c7 on 0x6f3390c6c200e9be81b32110ce191a293dc0eaba enables any caller to burn the helper’s long-lived HORS/WBNB PancakePair LP position and withdraw the underlying reserves to an arbitrary recipient, turning protocol-owned liquidity into a permissionless payout.

## Key Background

- HORS is an ERC-20 token on BSC at 0x1bb30f2ad8ff43bcd9964a97408b74f1bc6c8bc0, with verified source included in the seed artifacts.
- The HORS/WBNB PancakePair 0xd5868b2e2b510a91964abafc2d683295586a8c70 was originally created by helper contract 0x6f3390c6c200e9be81b32110ce191a293dc0eaba using PancakeRouter::addLiquidity with 500000000000000000000000000000000 HORS and 10 WBNB, after which 70,710,678,118,654,752,440,083,436 LP tokens were minted back to the helper.
- Helper contract 0x6f3390c6c200e9be81b32110ce191a293dc0eaba retains this LP position and exposes function f78283c7, which takes token addresses and a recipient as parameters and interacts with PancakeRouter and PancakePair according to bytecode and disassembly in iter_1 artifacts.
- EOA 0x8efb9311700439d70025d2b372fb54c61a60d5df is funded by 0x975d9bd9928f398c7e01f6ba236816fa558cd94b at block 38061566 and later deploys orchestrator 0x75ff620ff0e63243e86b99510cdbad1d5e76524e before executing the profit transaction.

**ACT Opportunity Context (Pre-State c3_B):**
BSC (chainid 56) state immediately before transaction 0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7 in block 45587949, where helper contract 0x6f3390c6c200e9be81b32110ce191a293dc0eaba holds 70,710,678,118,654,752,440,083,436 HORS/WBNB PancakePair LP tokens minted from its own balances of 500,000,000,000,000,000,000,000,000,000,000,000 HORS and 10 WBNB, and the HORS/WBNB pair 0xd5868b2e2b510a91964abafc2d683295586a8c70 has reserves matching those deposits plus subsequent fee growth.

## Vulnerability Analysis

Public helper function f78283c7 on 0x6f3390c6c200e9be81b32110ce191a293dc0eaba enables any caller to burn the helper’s long-lived HORS/WBNB PancakePair LP position and withdraw the underlying reserves to an arbitrary recipient, turning protocol-owned liquidity into a permissionless payout.

Helper contract 0x6f3390c6c200e9be81b32110ce191a293dc0eaba disassembly (entrypoint selectors and f78283c7 dispatch):
```text
00000000: PUSH1 0x80
00000002: PUSH1 0x40
00000004: MSTORE
00000005: PUSH1 0x04
00000007: CALLDATASIZE
00000008: LT
00000009: PUSH2 0x0034
0000000c: JUMPI
0000000d: PUSH1 0x00
0000000f: CALLDATALOAD
00000010: PUSH1 0xe0
00000012: SHR
00000013: DUP1
00000014: PUSH4 0x7494d122
00000019: EQ
0000001a: PUSH2 0x0039
0000001d: JUMPI
0000001e: DUP1
0000001f: PUSH4 0xc1459c03
00000024: EQ
00000025: PUSH2 0x0064
00000028: JUMPI
00000029: DUP1
0000002a: PUSH4 0xf78283c7
0000002f: EQ
00000030: PUSH2 0x0086
00000033: JUMPI
00000034: JUMPDEST
00000035: PUSH1 0x00
00000037: DUP1
00000038: REVERT
00000039: JUMPDEST
0000003a: CALLVALUE
0000003b: DUP1
0000003c: ISZERO
0000003d: PUSH2 0x0045
00000040: JUMPI
00000041: PUSH1 0x00
00000043: DUP1
00000044: REVERT
```

## Detailed Root Cause Analysis

Trace 0x4df582ed2cb6783a37096c5e204c2f8759d2e7fcbf7db9bce925457d2cdab826 shows that helper 0x6f3390c6c200e9be81b32110ce191a293dc0eaba originally calls HORS::approve and WBNB::approve on PancakeRouter 0x10ed43c718714eb63d5aa57b78b54704e256024e and adds liquidity for the HORS/WBNB pair, depositing 500000000000000000000000000000000 HORS and 10 WBNB. PancakeFactory then creates PancakePair 0xd5868b2e2b510a91964abafc2d683295586a8c70 and mints 70710678118654752440083436 LP tokens directly to 0x6f3390..., making that address the sole LP holder. Disassembly and later traces confirm that helper function f78283c7 is externally callable, checks no ownership or role-based access, and can be invoked with arbitrary addresses for the token pair and the final recipient. In the exploit transaction 0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7, orchestrator 0x75ff620ff0e63243e86b99510cdbad1d5e76524e triggers helper::f78283c7 with HORS 0x1bb30f2ad8ff43bcd9964a97408b74f1bc6c8bc0, WBNB 0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c, PancakePair 0xd5868b2e2b510a91964abafc2d683295586a8c70, and itself as the recipient. f78283c7 moves all 70,710,678,118,654,752,440,083,436 LP tokens from 0x6f3390... to PancakeRouter, which calls PancakePair::burn and returns 347242535196129895429273744913820 HORS and 14799359453861436868 WBNB to 0x75ff.... Neither helper nor pair enforces any restriction tying LP burning to a project-controlled account. As a direct result, any unprivileged adversary who knows these public addresses can deterministically recreate the sequence, burn the helper-owned LP, and redirect the HORS and WBNB reserves to a chosen recipient, turning this logic bug into an ACT-compatible profit opportunity.

Seed transaction trace (helper LP creation, tx 0x4df582ed2cb6783a37096c5e204c2f8759d2e7fcbf7db9bce925457d2cdab826):
```text
    ├─ [3449487] PancakeRouter::addLiquidity(WBNB: [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c], HORS: [0x1Bb30f2AD8Ff43BCD9964a97408B74f1BC6C8bc0], 10000000000000000000 [1e19], 500000000000000000000000000000000 [5e32], 10000000000000000000 [1e19], 500000000000000000000000000000000 [5e32], 0x6f3390c6C200e9bE81b32110CE191a293dc0eaba, 1620789056 [1.62e9])
    │   ├─ [155432] PancakePair::mint(0x6f3390c6C200e9bE81b32110CE191a293dc0eaba)
    │   │   ├─ emit Mint(sender: PancakeRouter: [0x10ED43C718714eb63d5aA57B78B54704E256024E], amount0: 500000000000000000000000000000000 [5e32], amount1: 10000000000000000000 [1e19])
```

## Adversary Flow Analysis

Exploit transaction trace (flash loan, helper call, LP burn, reserve transfers; tx 0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7):
```text
    ├─ [392812] 0x172fcD41E0913e95784454622d1c3724f546f849::flash(0x75ff620FF0e63243e86b99510cDbaD1D5e76524E, 0, 100000000000000000 [1e17], 0x000000000000000000000000172fcd41e0913e95784454622d1c3724f546f849000000000000000000000000000000000000000000000000016345785d8a000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000064f78283c70000000000000000000000001bb30f2ad8ff43bcd9964a97408b74f1bc6c8bc000000000000000000000000075ff620ff0e63243e86b99510cdbad1d5e76524e000000000000000000000000d5868b2e2b510a91964abafc2d683295586a8c7000000000000000000000000000000000000000000000000000000000)
    │   ├─ [326417] 0x75ff620FF0e63243e86b99510cDbaD1D5e76524E::pancakeV3FlashCallback(0, 10000000000000 [1e13], 0x000000000000000000000000172fcd41e0913e95784454622d1c3724f546f849000000000000000000000000000000000000000000000000016345785d8a000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000064f78283c70000000000000000000000001bb30f2ad8ff43bcd9964a97408b74f1bc6c8bc000000000000000000000000075ff620ff0e63243e86b99510cdbad1d5e76524e000000000000000000000000d5868b2e2b510a91964abafc2d683295586a8c7000000000000000000000000000000000000000000000000000000000)
    │   │   ├─ [87816] 0x6f3390c6C200e9bE81b32110CE191a293dc0eaba::f78283c7(0000000000000000000000001bb30f2ad8ff43bcd9964a97408b74f1bc6c8bc000000000000000000000000075ff620ff0e63243e86b99510cdbad1d5e76524e000000000000000000000000d5868b2e2b510a91964abafc2d683295586a8c70)
    │   │   │   ├─ [141949] PancakePair::burn(0x75ff620FF0e63243e86b99510cDbaD1D5e76524E)
    │   │   ├─ [8062] WBNB::transfer(0x8Efb9311700439d70025d2B372fb54c61a60d5DF, 14799349453861436868 [1.479e19])
```

**Adversary Profit Summary (WBNB):**
- Reference asset: WBNB
- Adversary address: 0x8efb9311700439d70025d2b372fb54c61a60d5df
- Value before: 0 WBNB
- Value after: 14.799349453861436868 WBNB
- Fees paid: 0.000338203 WBNB
- Value delta: 14.799011250861436868 WBNB

## Impact & Losses

**Total Loss Overview:**
- WBNB: 14.799359453861436868
- HORS: 347242535196129895429273744913820

The HORS/WBNB PancakePair 0xd5868b2e2b510a91964abafc2d683295586a8c70 loses 14799359453861436868 WBNB and 347242535196129895429273744913820 HORS when helper-owned LP tokens are burned and the reserves are redirected to orchestrator 0x75ff620ff0e63243e86b99510cdbad1d5e76524e. After repaying the 0.1 WBNB principal and 0.00001 WBNB fee on the flash loan, 0x75ff... forwards 14799349453861436868 WBNB (14.799349453861436868 WBNB) to EOA 0x8efb9311700439d70025d2b372fb54c61a60d5df, while the EOA spends 338203000000000 wei of BNB gas (0.000338203 BNB) to execute the exploit. The protocol-owned LP position in HORS/WBNB is effectively destroyed, leaving HORS liquidity fragmented and shifting the drained WBNB value to the adversary.

## References

- [1] Seed transaction trace 0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7 — `artifacts/root_cause/seed/56/0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7/trace.cast.log`
- [2] Balance diffs for seed transaction 0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7 — `artifacts/root_cause/seed/56/0xc8572846ed313b12bf835e2748ff37dacf6b8ee1bab36972dc4ace5e9f25fed7/balance_diff.json`
- [3] Helper LP creation trace 0x4df582ed2cb6783a37096c5e204c2f8759d2e7fcbf7db9bce925457d2cdab826 — `artifacts/root_cause/data_collector/iter_3/tx/56/0x4df582ed2cb6783a37096c5e204c2f8759d2e7fcbf7db9bce925457d2cdab826/trace.cast.log`
- [4] Address txlist for adversary EOA 0x8efb9311700439d70025d2b372fb54c61a60d5df — `artifacts/root_cause/data_collector/iter_2/address/56/0x8efb9311700439d70025d2b372fb54c61a60d5df/txlist.json`
- [5] Bytecode and disassembly for helper 0x6f3390c6c200e9be81b32110ce191a293dc0eaba — `artifacts/root_cause/data_collector/iter_1/contract/56/0x6f3390c6c200e9be81b32110ce191a293dc0eaba/disassemble.txt`
