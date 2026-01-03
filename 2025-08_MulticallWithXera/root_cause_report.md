# LUXERA Multicall3 Allowance Drain on BNB Chain

## Incident Overview TL;DR

On BNB Chain, an adversary-controlled origin EOA 0x00b700b9da0053009cb84400ed1e8fe251002af3 used an unverified helper contract 0x90bE00229fE8000000009e007743A485d400C3B7 and the public Multicall3 contract 0xcA11bde05977b3631167028862bE2a173976CA11 to execute a single aggregate3 call that spent the victim's unlimited LUXERA allowance. The call transferred 27,900,000 LUXERA from victim EOA 0x9a619Ae8995A220E8f3A1Df7478A5c8d2afFc542 into the LUXERA/WBNB PancakeSwap pair 0x231075E4AA60d28681a2d6D4989F8F739BAC15a0, swapped into 41.034748173552867045 WBNB, unwrapped to BNB, and distributed BNB to adversary addresses 0x90bE... and 0x4848..., while the origin EOA paid only 0.000050604058269347 BNB in gas.

### Root Cause Summary

The loss results from an ACT opportunity created when the victim EOA granted Multicall3 0xcA11bde05977b3631167028862bE2a173976CA11 an unlimited LUXERA allowance and both the LUXERA token and Multicall3 implementations allowed any caller to route LUXERA::transferFrom through Multicall3 using that allowance without additional authorization checks. The observed exploit transaction demonstrates an unprivileged EOA using this allowance path to drain the victim's LUXERA into a PancakeSwap swap and extract BNB profit.

## Key Background

- LUXERA (0x93e99ae6692b07a36e7693f4ae684c266633b67d) is an ERC20-style token on BNB Chain whose Token.sol constructor mints the initial supply to EOA 0x9a619Ae8995A220E8f3A1Df7478A5c8d2afFc542 and hands ownership to the same address; Token.sol integrates a DividendTracker but leaves transferFrom with standard ERC20 semantics based solely on allowance and balance.
- The Multicall3 contract at 0xcA11bde05977b3631167028862bE2a173976CA11 implements aggregate3 as a public function that iterates over Call3 structs and executes target.call(callData) for each entry with msg.sender set to Multicall3, without access control or hard-coded restrictions on which targets or functions can be called.
- PancakeSwap provides the LUXERA/WBNB pair 0x231075E4AA60d28681a2d6D4989F8F739BAC15a0 and a router that the victim used to add liquidity with LUXERA and BNB, so a large LUXERA position sat in the AMM pool and enabled swaps for WBNB when transferFrom moved LUXERA into the pair.
- The victim address 0x9a619Ae8995A220E8f3A1Df7478A5c8d2afFc542 performed normal owner actions including addLiquidityETH and a later approve to Multicall3 shortly before the exploit transaction, while adversary-related addresses 0x00b7..., 0x90bE..., and 0x4848... do not appear as LUXERA owners but receive BNB during the exploit.

## Vulnerability Analysis

The ACT root cause is the combination of (a) an unlimited LUXERA allowance from the victim EOA to the public Multicall3 contract 0xcA11..., and (b) standard ERC20 transferFrom semantics and Multicall3 aggregate3 behavior that allow any unprivileged caller to execute LUXERA::transferFrom via Multicall3 using that allowance. The exploit transaction shows an adversary EOA using helper contract 0x90bE... and Multicall3 to execute transferFrom from the victim into the LUXERA/WBNB pair, immediately swap the stolen LUXERA for WBNB, unwrap to BNB, and retain 41.034697569552867045 BNB of net profit in adversary-controlled addresses after gas.

### ACT Opportunity Conditions

- The victim holds a substantial LUXERA balance and has provided LUXERA/WBNB liquidity so that transferring LUXERA into the AMM pool results in a large WBNB outflow.
- The victim grants Multicall3 0xcA11bde05977b3631167028862bE2a173976CA11 an effectively unlimited LUXERA allowance via LUXERA::approve.
- Multicall3 remains publicly callable and executes aggregate3 without access control, and LUXERA::transferFrom honors allowances granted to 0xcA11... without additional authorization checks or owner-specific protections.
- The LUXERA/WBNB pool has sufficient liquidity to swap 27,900,000 LUXERA into WBNB at a rate that produces positive BNB proceeds for the adversary after gas when unwound through WBNB::withdraw and value transfers.

### Security Principles Violated

- Allowance hygiene and least privilege: the victim EOA granted an unlimited ERC20 allowance to a widely used, public aggregator contract, exposing its entire LUXERA balance to any unprivileged caller that prepares appropriate calldata.
- Defense-in-depth around aggregators: the combination of a public Multicall3 with unrestricted aggregate3 and an ERC20 token that performs no additional authorization checks on transferFrom from the owner left the victim dependent solely on correct approval management for safety.
- Principle of minimizing externally controlled call paths: routing sensitive ERC20 transferFrom operations through a generic aggregator contract introduced an additional unprotected control path that adversaries exploited.

### Vulnerable Components

- LUXERA token contract 0x93e99ae6692b07a36e7693f4ae684c266633b67d on BNB Chain, whose Token.sol implements standard ERC20 transferFrom behavior based solely on allowance and balance and integrates DividendTracker side effects.
- Multicall3 contract 0xcA11bde05977b3631167028862bE2a173976CA11 on BNB Chain, which exposes aggregate3 as a permissionless aggregator that executes arbitrary target.call(callData) without checking the identity or intent of the caller.
- Victim EOA 0x9a619Ae8995A220E8f3A1Df7478A5c8d2afFc542 and its unlimited LUXERA approval transaction 0x8bcc020c663d39855890c159aa2a2e18eebd6d00fffbe87113f690bedde0a78a to Multicall3.
- PancakeSwap LUXERA/WBNB pair 0x231075E4AA60d28681a2d6D4989F8F739BAC15a0, which held the victim's liquidity and swapped the stolen LUXERA into WBNB and then BNB.

#### Key LUXERA ERC20 Implementation Snippet

```solidity
// Extract from LUXERA Token.sol transferFrom path (abridged)
function _spendAllowance(address owner, address spender, uint256 amount) internal virtual override {
    uint256 currentAllowance = allowance(owner, spender);
    if (currentAllowance != type(uint256).max) {
        require(currentAllowance >= amount, "ERC20: insufficient allowance");
        _approve(owner, spender, currentAllowance - amount);
    }
}
```

_Seed contract source for 0x93e9... on BNB Chain, demonstrating standard allowance-based transferFrom semantics._

#### Multicall3 aggregate3 Snippet

```solidity
function aggregate3(Call3[] calldata calls) public payable returns (Result[] memory returnData) {
    uint256 length = calls.length;
    returnData = new Result[](length);
    Call3 calldata calli;
    for (uint256 i = 0; i < length;) {
        Result memory result = returnData[i];
        calli = calls[i];
        (result.success, result.returnData) = calli.target.call(calli.callData);
        unchecked { ++i; }
    }
}
```

_Verified Multicall3 implementation on BNB Chain at 0xcA11..., showing permissionless call aggregation without caller-specific access control._

## Detailed Root Cause Analysis

Token.sol for LUXERA defines an ERC20-like token with additional fee and dividend logic but preserves standard transferFrom semantics: any address with sufficient allowance and the from-address not blacklisted can move tokens from that address to an arbitrary recipient. The victim EOA 0x9a619Ae8995A220E8f3A1Df7478A5c8d2afFc542 first added LUXERA/WBNB liquidity in transaction 0x82da7b7a29ba41e1c67bc58ba802e546ca9438664905d7bcfdfc03d79c860c23, which transferred 3,100,000 LUXERA into the pair 0x231075E4AA60d28681a2d6D4989F8F739BAC15a0 and minted LP tokens. Two blocks before the exploit, in transaction 0x8bcc020c663d39855890c159aa2a2e18eebd6d00fffbe87113f690bedde0a78a, the victim called LUXERA::approve with spender 0xcA11bde05977b3631167028862bE2a173976CA11 and amount 2^256-1, writing the allowance storage slot from 0 to 0xffff...ffff and emitting an Approval event, thereby granting the public Multicall3 contract full spend authority over the victim's LUXERA balance. The verified Multicall3 implementation at 0xcA11... exposes aggregate3 as an unrestricted entry point that executes arbitrary target.call(callData) on behalf of Multicall3, so any unprivileged EOA can prepare calldata for LUXERA::transferFrom(from=victim, to=LUXERA/WBNB pair, amount=X) and submit it to aggregate3. In the seed exploit transaction 0xed6fd61c1eb2858a1594616ddebaa414ad3b732dcdb26ac7833b46803c5c18db, origin EOA 0x00b7... called unverified helper contract 0x90bE..., which called Multicall3::aggregate3 with a single Call3 targeting LUXERA::transferFrom(from=victim, to=pair, amount=27,900,000 LUXERA). Multicall3 executed transferFrom using the victim's allowance, moving 27.9M LUXERA from the victim to the pair. The pair then executed swap with amount0In=27,900,000 LUXERA and amount1Out=41.034748173552867045 WBNB to 0x90bE..., WBNB unwrapped to BNB, and 0x90bE... forwarded 20.517302684356598552 BNB to profit-sink EOA 0x4848..., leaving 20.51744548925453784 BNB on 0x90bE..., while origin 0x00b7... paid 0.000050604058269347 BNB in gas. Balance diffs show WBNB with a -41.034748173552867045 BNB native delta and the adversary cluster with a +41.034697569552867045 BNB net native delta, tying the profit directly to the Multicall3-mediated transferFrom of victim-owned LUXERA into the swap.

### Seed Exploit Transaction Trace

```text
Warning: This is a nightly build of Foundry. It is recommended to use the latest stable version. To mute this warning set `FOUNDRY_DISABLE_NIGHTLY_WARNING` in your environment. 

Executing previous transactions from the block.
Traces:
  [491660] 0x90bE00229fE8000000009e007743A485d400C3B7::00dd0000{value: 58269347}(0164001c01800bb90194013005cc019417ec01a401b4003082ad56cb00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000093e99ae6692b07a36e7693f4ae684c266633b67d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000006423b872dd0000000000000000000000009a619ae8995a220e8f3a1df7478a5c8d2affc542000000000000000000000000231075e4aa60d28681a2d6d4989f8f739bac15a000000000000000000000000000000000000000000017140e07d688b2a580000000000000000000000000000000000000000000000000000000000000ca11bde05977b3631167028862be2a173976ca1100000000000000023978b60d6c3a56e500000000000000011cbc48d6180943184848489f0b2bedd788c696e2d79b6b69d7484848)
    ├─ [415413] 0xcA11bde05977b3631167028862bE2a173976CA11::aggregate3([(0x93E99aE6692b07A36E7693f4ae684c266633b67d, false, 0x23b872dd0000000000000000000000009a619ae8995a220e8f3a1df7478a5c8d2affc542000000000000000000000000231075e4aa60d28681a2d6d4989f8f739bac15a000000000000000000000000000000000000000000017140e07d688b2a5800000)])
    │   ├─ [410528] LUXERA::transferFrom(0x9a619Ae8995A220E8f3A1Df7478A5c8d2afFc542, PancakePair: [0x231075E4AA60d28681a2d6D4989F8F739BAC15a0], 27900000000000000000000000 [2.79e25])
    │   │   ├─ emit Transfer(from: 0x9a619Ae8995A220E8f3A1Df7478A5c8d2afFc542, to: PancakePair: [0x231075E4AA60d28681a2d6D4989F8F739BAC15a0], value: 27900000000000000000000000 [2.79e25])
    │   │   ├─ [4739] DividendTracker::setBalance(0x9a619Ae8995A220E8f3A1Df7478A5c8d2afFc542, 0)
    │   │   │   └─ ← [Stop]
    │   │   ├─ [2739] DividendTracker::setBalance(PancakePair: [0x231075E4AA60d28681a2d6D4989F8F739BAC15a0], 28852613793756048742258591 [2.885e25])
    │   │   │   └─ ← [Stop]
    │   │   ├─ [348316] DividendTracker::process(300000 [3e5])
    │   │   │   ├─ [29971] BEP20USDT::transfer(0x2f89ebBa798fc0815DbcA9f906C529c6C6d18638, 326905038968135611295 [3.269e20])
    │   │   │   │   ├─ emit Transfer(from: DividendTracker: [0x02055174DbC8ebdFc0b2accBb21da5deDc29956D], to: 0x2f89ebBa798fc0815DbcA9f906C529c6C6d18638, value: 326905038968135611295 [3.269e20])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0xc5d8200936ec5793a4b64d8088c6a2420f0955934a1e0111c29c8f8beb98a4de: 0x00000000000000000000000000000000000000000000005f4d582e35b97f7f3f → 0x00000000000000000000000000000000000000000000004d94a02d49148b8ba0
    │   │   │   │   │   @ 0xda47edae6f6f41d999d07a1e9c43fcb6e1493f47b5b8abb8a238bda2bad40ae7: 0 → 0x000000000000000000000000000000000000000000000011b8b800eca4f3f39f
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ emit DividendWithdrawn(to: 0x2f89ebBa798fc0815DbcA9f906C529c6C6d18638, weiAmount: 326905038968135611295 [3.269e20])
    │   │   │   ├─ [25171] BEP20USDT::transfer(0xf19C71cad03a283cD006781dD1ccF327C552E39E, 114120526445618263992 [1.141e20])
    │   │   │   │   ├─ emit Transfer(from: DividendTracker: [0x02055174DbC8ebdFc0b2accBb21da5deDc29956D], to: 0xf19C71cad03a283cD006781dD1ccF327C552E39E, value: 114120526445618263992 [1.141e20])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0xb847799fbc48f749e58b57c430fe27fae81b7e83a788ba6382e6eed4923c2217: 0 → 0x0000000000000000000000000000000000000000000000062fbd8e2a73a5f7b8
    │   │   │   │   │   @ 0xc5d8200936ec5793a4b64d8088c6a2420f0955934a1e0111c29c8f8beb98a4de: 0x00000000000000000000000000000000000000000000004d94a02d49148b8ba0 → 0x00000000000000000000000000000000000000000000004764e29f1ea0e593e8
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ emit DividendWithdrawn(to: 0xf19C71cad03a283cD006781dD1ccF327C552E39E, weiAmount: 114120526445618263992 [1.141e20])
    │   │   │   ├─ [25171] BEP20USDT::transfer(0x700a21330c151b69aCc3324a08A5668d7569E5D0, 251652439047672188188 [2.516e20])
    │   │   │   │   ├─ emit Transfer(from: DividendTracker: [0x02055174DbC8ebdFc0b2accBb21da5deDc29956D], to: 0x700a21330c151b69aCc3324a08A5668d7569E5D0, value: 251652439047672188188 [2.516e20])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0xc5d8200936ec5793a4b64d8088c6a2420f0955934a1e0111c29c8f8beb98a4de: 0x00000000000000000000000000000000000000000000004764e29f1ea0e593e8 → 0x000000000000000000000000000000000000000000000039c0818f1e17c146cc
    │   │   │   │   │   @ 0x53fa991513f9efebe64469f36a47964a069f32f23a18734fe165323e07f7bd3d: 0 → 0x00000000000000000000000000000000000000000000000da461100089244d1c
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ emit DividendWithdrawn(to: 0x700a21330c151b69aCc3324a08A5668d7569E5D0, weiAmount: 251652439047672188188 [2.516e20])
    │   │   │   ├─ [25171] BEP20USDT::transfer(0x4FD342fDe1ffC3d63cf6D7Ceed5A239001E95b88, 82671384030868573242 [8.267e19])
    │   │   │   │   ├─ emit Transfer(from: DividendTracker: [0x02055174DbC8ebdFc0b2accBb21da5deDc29956D], to: 0x4FD342fDe1ffC3d63cf6D7Ceed5A239001E95b88, value: 82671384030868573242 [8.267e19])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0xc5d8200936ec5793a4b64d8088c6a2420f0955934a1e0111c29c8f8beb98a4de: 0x000000000000000000000000000000000000000000000039c0818f1e17c146cc → 0x0000000000000000000000000000000000000000000000354535cd5a6deeba92
    │   │   │   │   │   @ 0x0f92b703dd0a5134c1127212d9b210997c23a1141296758660dd88d47ededee3: 0 → 0x0000000000000000000000000000000000000000000000047b4bc1c3a9d28c3a
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ emit DividendWithdrawn(to: 0x4FD342fDe1ffC3d63cf6D7Ceed5A239001E95b88, weiAmount: 82671384030868573242 [8.267e19])
    │   │   │   ├─ emit ProcessedDividendTracker(iterations: 4, claims: 4)
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 0x29d983a7d4af44e656b547fa56b6eeabbedaa29b1d286db4ac2e1b2a3dd401af: 0 → 0x00000000000000000000000000000000000000000000000da461100089244d1c
    │   │   │   │   @ 0x4459c45870e3db36970321a6f3b861198bb105473004d93fc31779debfad4ab4: 0 → 0x0000000000000000000000000000000000000000000000000000000068a5dbcb
    │   │   │   │   @ 0xc418f29a83d247d6f9e8214f34149b8549c8801e7552c7a5c0210251d0fe18c1: 0 → 0x0000000000000000000000000000000000000000000000000000000068a5dbcb
    │   │   │   │   @ 0x4c2e7a6c3d3d538b543d17e4bec343080dfa4fdc5a1b7d2bafa337edd05b0598: 0 → 0x0000000000000000000000000000000000000000000000062fbd8e2a73a5f7b8
    │   │   │   │   @ 14: 4 → 8
    │   │   │   │   @ 0x4cd06bca9d6d53498c3d6cc6935d28c4f2bb734155c66db16a239274c36a71d4: 0 → 0x0000000000000000000000000000000000000000000000000000000068a5dbcb
    │   │   │   │   @ 0x37b39030465e6bc23540ea3bb2ea56520e55558fe6dc0fac017e8207c18f3c43: 0 → 0x0000000000000000000000000000000000000000000000047b4bc1c3a9d28c3a
    │   │   │   │   @ 0x053c2a09b7a0713000b147abfcf54a405d8b4d2720fce8e3aeb553a01b4629ae: 0 → 0x0000000000000000000000000000000000000000000000000000000068a5dbcb
    │   │   │   │   @ 0x087ac54173f67665b83759c5830b12858c9da1aad18a580f4037dfe875338cf7: 0 → 0x000000000000000000000000000000000000000000000011b8b800eca4f3f39f
    │   │   │   └─ ← [Return] 4, 4
    │   │   ├─  storage changes:
    │   │   │   @ 0x3d1f07773efa76bbc651738df6f123acc0876c9296714cf23a83db1fe4137c98: 0x00000000000000000000000000000000000000000017140e07d688b2a5800000 → 0
    │   │   │   @ 0xad41570b02f02196b45c2fb3a5da07fa2acfe40ac767479fd71c952485edcf79: 0x00000000000000000000000000000000000000000000c9b94c17b0ef710d979f → 0x00000000000000000000000000000000000000000017ddc753ee39a2168d979f
    │   │   └─ ← [Return] true
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001
    ├─ [51831] PancakePair::swap(0, 41034748173552867045 [4.103e19], 0x90bE00229fE8000000009e007743A485d400C3B7, 0x)
    │   ├─ [12862] WBNB::transfer(0x90bE00229fE8000000009e007743A485d400C3B7, 41034748173552867045 [4.103e19])
    │   │   ├─ emit Transfer(from: PancakePair: [0x231075E4AA60d28681a2d6D4989F8F739BAC15a0], to: 0x90bE00229fE8000000009e007743A485d400C3B7, value: 41034748173552867045 [4.103e19])
    │   │   ├─  storage changes:
    │   │   │   @ 0x40e188e1c0a702b7884c1b4dfac7aabed68676b7a9d64b8397740229f7234898: 0x000000000000000000000000000000000000000000000000000004f053e8969c → 0x0000000000000000000000000000000000000000000000023978bafdc022ed81
    │   │   │   @ 0xa55e97232265616e929b01c6dfda6306d29ef0913604abe663d430bf7954ec7f: 0x0000000000000000000000000000000000000000000000024cf957a29404f898 → 0x0000000000000000000000000000000000000000000000001380a19527caa1b3
    │   │   └─ ← [Return] true
    │   ├─ [623] LUXERA::balanceOf(PancakePair: [0x231075E4AA60d28681a2d6D4989F8F739BAC15a0]) [staticcall]
    │   │   └─ ← [Return] 28852613793756048742258591 [2.885e25]
    │   ├─ [534] WBNB::balanceOf(PancakePair: [0x231075E4AA60d28681a2d6D4989F8F739BAC15a0]) [staticcall]
    │   │   └─ ← [Return] 1405300745729384883 [1.405e18]
    │   ├─ emit Sync(reserve0: 28852613793756048742258591 [2.885e25], reserve1: 1405300745729384883 [1.405e18])
    │   ├─ emit Swap(sender: 0x90bE00229fE8000000009e007743A485d400C3B7, amount0In: 27900000000000000000000000 [2.79e25], amount1In: 0, amount0Out: 0, amount1Out: 41034748173552867045 [4.103e19], to: 0x90bE00229fE8000000009e007743A485d400C3B7)
    │   ├─  storage changes:
    │   │   @ 8: 0x68a562280000000000024cf957a29404f89800000000c9b94c17b0ef710d979f → 0x68a5dbcb0000000000001380a19527caa1b300000017ddc753ee39a2168d979f
    │   │   @ 9: 0x0000000000000000000000000000000000042201c06995791568d6e9688d31ad → 0x0000000000000000000000000000000000058526704fd17dc397db84d663f6cf
    │   │   @ 10: 0x000000000000000000000000000308a993bbcb7dabc95f44d22af69f8971d9b7 → 0x00000000000000000000000000033252b24b07879d29c3f56f7ad78c7269423f
    │   └─ ← [Stop]
    ├─ [9155] WBNB::withdraw(41034748173552867045 [4.103e19])
    │   ├─ [15] 0x90bE00229fE8000000009e007743A485d400C3B7::fallback{value: 41034748173552867045}()
    │   │   └─ ← [Stop]
    │   ├─ emit Withdrawal(src: 0x90bE00229fE8000000009e007743A485d400C3B7, wad: 41034748173552867045 [4.103e19])
    │   ├─  storage changes:
```

_Seed transaction trace for 0xed6fd61c..., showing helper contract 0x90bE... calling Multicall3::aggregate3, which invokes LUXERA::transferFrom from the victim to the LUXERA/WBNB pair and drives the downstream swap and BNB distribution._

## Adversary Flow Analysis

The adversary used a single on-chain transaction sequence centered on a helper contract and Multicall3 to spend the victim's unlimited LUXERA allowance into a PancakeSwap swap and realize BNB profit, without interacting directly with the LUXERA token from the origin EOA.

### Adversary-Related Accounts

- **0x00b700b9da0053009cb84400ed1e8fe251002af3** (chainid 56): Originator of the exploit transaction 0xed6fd61c1eb2858a1594616ddebaa414ad3b732dcdb26ac7833b46803c5c18db, which calls helper contract 0x90bE..., pays gas, and participates in a net-positive BNB balance delta for the adversary cluster.
- **0x90bE00229fE8000000009e007743A485d400C3B7** (chainid 56): Unverified helper contract that receives the external call from origin 0x00b7..., invokes Multicall3::aggregate3 to execute LUXERA::transferFrom, receives 41.034748173552867045 WBNB (later BNB) from the LUXERA/WBNB pair, and retains 20.51744548925453784 BNB after forwarding part of the proceeds.
- **0x4848489f0b2BEdd788c696e2D79b6b69D7484848** (chainid 56): EOA that receives 20.517302684356598552 BNB from helper contract 0x90bE... in the exploit transaction and shows a concentrated inflow of BNB consistent with acting as a profit sink for the adversary cluster.

### Victim and Related Contracts

- **LUXERA token** at 0x93e99ae6692b07a36e7693f4ae684c266633b67d on BNB Chain (verified: true)
- **Victim EOA** at 0x9a619Ae8995A220E8f3A1Df7478A5c8d2afFc542 on BNB Chain (verified: false)
- **PancakeSwap LUXERA/WBNB pair** at 0x231075E4AA60d28681a2d6D4989F8F739BAC15a0 on BNB Chain (verified: false)
- **Multicall3** at 0xcA11bde05977b3631167028862bE2a173976CA11 on BNB Chain (verified: true)

### Adversary Lifecycle Stages

#### Victim LUXERA liquidity provisioning

**Transactions:** 0x82da7b7a29ba41e1c67bc58ba802e546ca9438664905d7bcfdfc03d79c860c23 (block 58269313)

**Effect:** The victim EOA added LUXERA/WBNB liquidity via PancakeRouter::addLiquidityETH, transferring 3,100,000 LUXERA into the pair 0x231075E4AA60d28681a2d6D4989F8F739BAC15a0, depositing 13 BNB as WBNB, and receiving LP tokens, which established a sizable LUXERA position in the AMM pool.

**Code / Trace Evidence:** artifacts/root_cause/data_collector/iter_2/tx/56/0x82da7b7a29ba41e1c67bc58ba802e546ca9438664905d7bcfdfc03d79c860c23/trace.cast.log and balance_diff.json

#### Victim grants Multicall3 unlimited LUXERA allowance

**Transactions:** 0x8bcc020c663d39855890c159aa2a2e18eebd6d00fffbe87113f690bedde0a78a (block 58269337)

**Effect:** The victim EOA called LUXERA::approve with spender 0xcA11bde05977b3631167028862bE2a173976CA11 and amount 2^256-1, creating an effectively unlimited LUXERA allowance for the public Multicall3 contract and enabling Multicall3 to act as spender in transferFrom calls from the victim.

**Code / Trace Evidence:** artifacts/root_cause/data_collector/iter_2/tx/56/0x8bcc020c663d39855890c159aa2a2e18eebd6d00fffbe87113f690bedde0a78a/trace.cast.log and balance_diff.json, plus Token.sol allowance implementation at artifacts/root_cause/seed/56/0x93e99ae6692b07a36e7693f4ae684c266633b67d/src/Token.sol and Multicall3 aggregate3 implementation at artifacts/root_cause/data_collector/iter_1/contract/56/0xcA11bde05977b3631167028862bE2a173976CA11/source/src/Contract.sol

#### Adversary executes Multicall3 aggregate3 and realizes BNB profit

**Transactions:** 0xed6fd61c1eb2858a1594616ddebaa414ad3b732dcdb26ac7833b46803c5c18db (block 58269339)

**Effect:** Origin EOA 0x00b7... called helper contract 0x90bE..., which called Multicall3::aggregate3 targeting LUXERA::transferFrom(from=victim, to=LUXERA/WBNB pair, amount=27,900,000 LUXERA). This spent the victim's allowance to move 27.9M LUXERA into the pair, triggered DividendTracker processing, swapped the LUXERA into 41.034748173552867045 WBNB, unwrapped to BNB, and distributed BNB such that 0x90bE... gained 20.51744548925453784 BNB, 0x4848... gained 20.517302684356598552 BNB, and origin 0x00b7... paid 0.000050604058269347 BNB in gas.

**Code / Trace Evidence:** artifacts/root_cause/seed/56/0xed6fd61c1eb2858a1594616ddebaa414ad3b732dcdb26ac7833b46803c5c18db/trace.cast.log and balance_diff.json, together with Multicall3 and LUXERA source code referenced in earlier stages


## Impact & Losses

The exploit drained 27,900,000 LUXERA from the victim EOA into the LUXERA/WBNB pair and swapped it into WBNB and then BNB, resulting in a 41.034697569552867045 BNB net gain for the adversary cluster after gas and a corresponding loss of token value and purchasing power for the victim, while leaving the core LUXERA and Multicall3 contracts operational but exposed to the same allowance pattern.

### Quantified Losses

- 27900000000000000000000000 LUXERA
- 41.034697569552867045 BNB (adversary net profit)

## References

- [1] Seed exploit transaction metadata, trace, and balance diff for 0xed6fd61c1eb2858a1594616ddebaa414ad3b732dcdb26ac7833b46803c5c18db — artifacts/root_cause/seed/56/0xed6fd61c1eb2858a1594616ddebaa414ad3b732dcdb26ac7833b46803c5c18db/
- [2] Victim addLiquidityETH transaction 0x82da7b7a29ba41e1c67bc58ba802e546ca9438664905d7bcfdfc03d79c860c23 trace and balance diff — artifacts/root_cause/data_collector/iter_2/tx/56/0x82da7b7a29ba41e1c67bc58ba802e546ca9438664905d7bcfdfc03d79c860c23/
- [3] Victim Multicall3 approval transaction 0x8bcc020c663d39855890c159aa2a2e18eebd6d00fffbe87113f690bedde0a78a trace and balance diff — artifacts/root_cause/data_collector/iter_2/tx/56/0x8bcc020c663d39855890c159aa2a2e18eebd6d00fffbe87113f690bedde0a78a/
- [4] LUXERA Token.sol implementation and DividendTracker integration — artifacts/root_cause/seed/56/0x93e99ae6692b07a36e7693f4ae684c266633b67d/src/Token.sol
- [5] Multicall3 Contract.sol implementation on BNB Chain — artifacts/root_cause/data_collector/iter_1/contract/56/0xcA11bde05977b3631167028862bE2a173976CA11/source/src/Contract.sol
- [6] Data collection summary for the incident — artifacts/root_cause/data_collector/data_collection_summary.json