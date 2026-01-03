# Pledge MFT treasury drain via public swapTokenU

**Protocol:** Pledge

## Incident Overview & TL;DR



### ACT Opportunity and Seed Transaction

BNB Chain (chainid 56) pre-state immediately before inclusion of the seed transaction 0x63ac9bc4e53dbcfaac3a65cb90917531cfdb1c79c0a334dda3f06e42373ff3a0 in block 44555338, where Pledge 0x061944c0f3c2d7DABafB50813Efb05c4e0c952e1 holds 989644233342705000000000000 MFT and the MFT/BEP20USDT pair 0x8b98e36dFF7E5aD41b304FFF2aCf1D3D2368384A holds 375000000000000000000000 MFT and 15000000000000000000000 BEP20USDT.

Key attacker-crafted transactions:

- Tx 0x63ac9bc4e53dbcfaac3a65cb90917531cfdb1c79c0a334dda3f06e42373ff3a0 on chain 56 (adversary-crafted): Helper 0x4AA0548019bFECd343179d054b1c7Fa63e1e0B6c reads Pledge's MFT balance and calls Pledge::swapTokenU(989644232342705000000000000, 0x59367B057055FD5d38AB9c5F0927f45dC2637390), which causes PancakeRouter 0x10ED43C718714eb63d5aA57B78B54704E256024E to swap that MFT amount from Pledge into the MFT/BEP20USDT pair 0x8b98e36dFF7E5aD41b304FFF2aCf1D3D2368384A and send 14994304057732608091714 BEP20USDT to the attacker EOA.
- Tx 0x7d03f5c01c65c9c8803627fc27b99219baccdbff2d6f2a43e54ccb21b32d534 on chain 56 (adversary-crafted): Second call to helper 0x4AA0548019bFECd343179d054b1c7Fa63e1e0B6c using selector 0x280d41a0 against the now-drained Pledge balance; the call path reverts after burning gas and does not change USDT or BNB balances.
- Tx 0x1cc1d6b5ec2e65bba008a043c1027896f3b4a4b85e2590fd01d05a54f200bf5 on chain 56 (adversary-crafted): Attacker EOA authorizes a 1inch/Augustus helper contract to spend 14994304057732608091714 BEP20USDT from the attacker's balance.
- Tx 0xe1499b7f8ffc9036cc990c8132f6cfb0bf4dc8df7f73b0a45ad73be1e748d70f on chain 56 (adversary-crafted): AugustusSwapper consumes 14994304057732608091714 BEP20USDT from the attacker, executes a routed swap through intermediate addresses, and transfers 20352512992267751396 wei BNB to the attacker EOA.

## Key Background

## Vulnerability & Root Cause Analysis

### Vulnerability Brief

swapTokenU is a public function that lets any caller instruct Pledge to approve PancakeRouter for MAX allowance on MFT and swap contract-owned MFT into BEP20USDT for an arbitrary recipient without checking caller authorization or constraining the recipient.

### Root Cause Detail

In Contract.sol, function swapTokenU(uint256 amount, address _target) is declared public and does not reference msg.sender or any access-control variables. The function unconditionally calls IERC20(_token).approve(_swapRouter, MAX), constructs a two-element path [MFT, BEP20USDT], and invokes _swapRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(amount, 0, path, _target, block.timestamp). Because Pledge holds MFT in its own balance and does not restrict the allowed amount or recipient, any unprivileged caller can read Pledge's MFT balance, pass that amount as the swapTokenU amount, and route the resulting BEP20USDT to any address, including an attacker-controlled EOA. This behavior matches the seed transaction trace, where helper 0x4AA0548019bFECd343179d054b1c7Fa63e1e0B6c reads Pledge's MFT balance and calls swapTokenU with nearly the full balance and recipient 0x59367B057055FD5d38AB9c5F0927f45dC2637390, resulting in a large BEP20USDT transfer from the MFT/BEP20USDT pair to the attacker.

### Vulnerable Components

- Pledge Contract.sol at 0x061944c0f3c2d7DABafB50813Efb05c4e0c952e1 :: swapTokenU(uint256 amount, address _target)

### Exploit Preconditions

- Pledge holds a non-trivial MFT balance in its own address.
- The MFT/BEP20USDT PancakeSwap pair has sufficient liquidity to execute the swap for the chosen amount.
- swapTokenU remains callable as a public function without caller authorization checks or recipient restrictions.

### Security Principles Violated

- Lack of access control on a function that spends contract-owned treasury assets.
- Unrestricted approval of MAX allowance to an external DEX router for contract-owned tokens.

**Pledge swapTokenU implementation (verified source)**

```solidity
function swapTokenU(uint256 amount, address _target) public {
    IERC20(_token).approve(address(_swapRouter), MAX);
    address[] memory path = new address[](2);
    path[0] = _token;
    path[1] = _USDT;
    _swapRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount,
            0,
            path,
            _target,
            block.timestamp
    );
}
```

This snippet shows that any caller can invoke `swapTokenU` to spend Pledge-held MFT through a DEX router to an arbitrary `_target` without access control.

## Adversary Flow Analysis

Single-EOA, multi-transaction sequence on BNB Chain that uses a helper contract to trigger Pledge's unprotected swapTokenU treasury swap, then routes the resulting USDT through a DeFi aggregator into BNB.

### Adversary-Related Accounts

Adversary cluster:
- 0x59367B057055FD5d38AB9c5F0927f45dC2637390 (chain 56): Sender of the attacker-crafted treasury-drain, approval, and aggregator transactions and direct recipient of BEP20USDT and BNB proceeds.
- 0x4AA0548019bFECd343179d054b1c7Fa63e1e0B6c (chain 56): Deployed by the attacker EOA and used to read Pledge's MFT balance and call Pledge::swapTokenU with the attacker as recipient.

Victim and related protocol components:
- Pledge at 0x061944c0f3c2d7DABafB50813Efb05c4e0c952e1 on chain 56
- MFT/BEP20USDT PancakeSwap pair at 0x8b98e36dFF7E5aD41b304FFF2aCf1D3D2368384A on chain 56

### Adversary Lifecycle Stages

#### Adversary helper deployment and setup

Attacker EOA 0x59367B057055FD5d38AB9c5F0927f45dC2637390 deploys helper contract 0x4AA0548019bFECd343179d054b1c7Fa63e1e0B6c, which provides a function (selector 0x280d41a0) that reads Pledge's MFT balance and calls Pledge::swapTokenU with parameters controlled by the attacker.

Transactions:
- 0x0b7f41f2933d36fb24fd95b2fb6734e19dbc0e1ce8a1950a3184a5ff68ecae08 (block 44555321, mechanism contract_deploy)

Evidence artifacts: artifacts/root_cause/data_collector/iter_1/address/56/0x59367B057055FD5d38AB9c5F0927f45dC2637390/txlist_44500000_44600000.json; artifacts/root_cause/root_cause_challenger/root_cause_challenge_result.json

#### Treasury drain via Pledge::swapTokenU

Helper 0x4AA0548019bFECd343179d054b1c7Fa63e1e0B6c calls Pledge::swapTokenU with amount 989644232342705000000000000 and recipient 0x59367B057055FD5d38AB9c5F0927f45dC2637390, causing PancakeRouter 0x10ED43C718714eb63d5aA57B78B54704E256024E to move 989644232342705000000000000 MFT from Pledge into the MFT/BEP20USDT pair and transfer 14994304057732608091714 BEP20USDT from the pair to the attacker, while Pledge's MFT balance falls from 989644233342705000000000000 to 1000000000000000000.

Transactions:
- 0x63ac9bc4e53dbcfaac3a65cb90917531cfdb1c79c0a334dda3f06e42373ff3a0 (block 44555338, mechanism swap)

Evidence artifacts: artifacts/root_cause/seed/56/0x63ac9bc4e53dbcfaac3a65cb90917531cfdb1c79c0a334dda3f06e42373ff3a0/trace.cast.log; artifacts/root_cause/data_collector/iter_1/contract/56/0x061944c0f3c2d7DABafB50813Efb05c4e0c952e1/source/src/Contract.sol; artifacts/root_cause/data_collector/iter_1/tx/56/0x63ac9bc4e53dbcfaac3a65cb90917531cfdb1c79c0a334dda3f06e42373ff3a0/balance_diff_prestate.json

#### USDT to BNB conversion and profit realization

Attacker EOA 0x59367B057055FD5d38AB9c5F0927f45dC2637390 approves a 1inch/Augustus helper to spend 14994304057732608091714 BEP20USDT and then calls AugustusSwapper to swap that USDT into BNB. The aggregator path transfers BEP20USDT from the attacker to AugustusSwapper, routes through intermediate addresses, and results in a net transfer of 20352512992267751396 wei BNB from WBNB to the attacker, increasing the EOA's BNB balance from 0.394351272 to 20.746442473267751396 BNB.

Transactions:
- 0x1cc1d6b5ec2e65bba008a043c1027896f3b4a4b85e2590fd01d05a54f200bf5 (block 44588061, mechanism approve)
- 0xe1499b7f8ffc9036cc990c8132f6cfb0bf4dc8df7f73b0a45ad73be1e748d70f (block 44588067, mechanism swap)

Evidence artifacts: artifacts/root_cause/data_collector/iter_1/tx/56/0x1cc1d6b5ec2e65bba008a043c1027896f3b4a4b85e2590fd01d05a54f200bf5/trace.cast.log; artifacts/root_cause/data_collector/iter_1/tx/56/0x1cc1d6b5ec2e65bba008a043c1027896f3b4a4b85e2590fd01d05a54f200bf5/balance_diff_prestate.json; artifacts/root_cause/data_collector/iter_1/tx/56/0xe1499b7f8ffc9036cc990c8132f6cfb0bf4dc8df7f73b0a45ad73be1e748d70f/trace.cast.log; artifacts/root_cause/data_collector/iter_1/tx/56/0xe1499b7f8ffc9036cc990c8132f6cfb0bf4dc8df7f73b0a45ad73be1e748d70f/balance_diff_prestate.json

**Seed transaction trace around Pledge::swapTokenU**

```text
  [180889] 0x4AA0548019bFECd343179d054b1c7Fa63e1e0B6c::280d41a0(...)
    ├─ [2583] MFT::balanceOf(Pledge: [0x061944c0f3c2d7DABafB50813Efb05c4e0c952e1]) [staticcall]
    ├─ [171895] Pledge::swapTokenU(989644232342705000000000000, 0x59367B057055FD5d38AB9c5F0927f45dC2637390)
    │   ├─ [24674] MFT::approve(PancakeRouter: [0x10ED43C718714eb63d5aA57B78B54704E256024E], MAX)
    │   ├─ [136083] PancakeRouter::swapExactTokensForTokensSupportingFeeOnTransferTokens(...)
    │   │   ├─ [20806] MFT::transferFrom(Pledge, PancakePair, 989644232342705000000000000)
    │   │   ├─ [96597] PancakePair::swap(0, 14994304057732608091714, attacker, 0x)
```

This cast trace segment shows the helper calling Pledge::swapTokenU, which approves PancakeRouter, transfers MFT from Pledge to the MFT/BEP20USDT pair, and swaps into BEP20USDT sent to the attacker EOA.

## Impact & Losses

### Quantitative Summary

- MFT: 989644232342705000000000000
- BNB (attacker net profit): 20.300333287267751396

### On-Chain Impact Detail

Pledge's on-chain MFT balance at address 0x061944c0f3c2d7DABafB50813Efb05c4e0c952e1 decreases from 989644233342705000000000000 to 1000000000000000000 during the treasury-drain transaction, while the MFT/BEP20USDT pair 0x8b98e36dFF7E5aD41b304FFF2aCf1D3D2368384A receives the corresponding MFT and transfers 14994304057732608091714 BEP20USDT to attacker EOA 0x59367B057055FD5d38AB9c5F0927f45dC2637390. Over the four transactions in b, the attacker's BNB balance increases from 0.446109186 to 20.746442473267751396 BNB, a net gain of 20.300333287267751396 BNB after accounting for 0.052179705 BNB of gas fees, as shown in the prestate balance diffs.

## References

[1] Pledge Contract.sol source: artifacts/root_cause/data_collector/iter_1/contract/56/0x061944c0f3c2d7DABafB50813Efb05c4e0c952e1/source/src/Contract.sol
[2] Seed tx metadata and trace: artifacts/root_cause/seed/56/0x63ac9bc4e53dbcfaac3a65cb90917531cfdb1c79c0a334dda3f06e42373ff3a0/trace.cast.log
[3] Prestate balance diffs for seed and aggregator txs: artifacts/root_cause/data_collector/iter_1/tx/56/0x63ac9bc4e53dbcfaac3a65cb90917531cfdb1c79c0a334dda3f06e42373ff3a0/balance_diff_prestate.json
[4] Attacker EOA txlist in incident window: artifacts/root_cause/data_collector/iter_1/address/56/0x59367B057055FD5d38AB9c5F0927f45dC2637390/txlist_44500000_44600000.json
