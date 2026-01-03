# RareStakingV1 permissionless Merkle-root update and RARE drain

Protocol: SuperRare / RareStakingV1 staking

## Incident Overview TL;DR

An adversary-controlled EOA on Ethereum mainnet uses a custom router and helper contract to call RareStakingV1::updateMerkleRoot and ::claim against a staking proxy, setting a Merkle root that encodes a single-leaf tree paying the entire on-contract RARE balance to an adversary-controlled address and then immediately claiming that amount in the same transaction. The staking proxy’s entire RARE balance of 11907874713019104529057960 tokens is transferred to the helper, while the adversary only expends gas in ETH.

RareStakingV1’s updateMerkleRoot function is guarded by a require condition that reverts for the intended authorized callers but permits arbitrary callers, effectively leaving Merkle-root updates permissionless and enabling any unprivileged adversary to install a malicious root and drain the staking contract via claim.

## Key Background

- RareStakingV1 is an upgradable staking contract deployed behind an ERC1967 proxy at 0x3f4d749675b3e48bccd932033808a7079328eb48 on Ethereum mainnet, with implementation address 0xffb512b9176d527c5d32189c3e310ed4ab2bb9ec resolved from the implementation slot (implementation_slot_23016423.json and impl_metadata_summary.json).
- The staking contract manages RARE (SuperRareToken, 0xba5bde662c17e2adff1075610382b9b691296350), tracking a Merkle root currentClaimRoot that defines which addresses and amounts are entitled to claim, and emitting NewClaimRootAdded and TokensClaimed events during updates and claims (RareStakingV1.sol and seed trace.cast.log).
- MerkleProof.verify is used by RareStakingV1 to validate claim proofs against currentClaimRoot; when the root equals keccak256(abi.encodePacked(recipient, amount)) and the provided proof is an empty array, MerkleProof.verify([], root, leaf) returns true, so a degenerate single-leaf tree allows a claim with an empty proof for that recipient and amount.
- The adversary deploys and controls a router/orchestrator contract at 0x2073111e6ebb6826f7e9c6192c6304aa5af5e340 and a helper contract at 0x08947cedf35f9669012bda6fda9d03c399b017ab, using them to structure the exploit call sequence that updates the staking Merkle root and then claims RARE (pseudocode summaries for 0x2073... and 0x0894..., plus address histories in normal_txlist.json and internal_txlist.json).

## Vulnerability Analysis


Key RareStakingV1 functions (updateMerkleRoot and claim) from verified implementation 0xffb5...:

```solidity

    function verifyProof(
        bytes32 leaf,
        bytes32[] memory proof
    ) internal view returns (bool) {
        return MerkleProof.verify(proof, currentClaimRoot, leaf);
    }

    function updateMerkleRoot(bytes32 newRoot) external override {
        require((msg.sender != owner() || msg.sender != address(0xc2F394a45e994bc81EfF678bDE9172e10f7c8ddc)), "Not authorized to update merkle root");
        if (newRoot == bytes32(0)) revert EmptyMerkleRoot();
        currentClaimRoot = newRoot;
        currentRound++;
        emit NewClaimRootAdded(newRoot, currentRound, block.timestamp);
    }

    function updateTokenAddress(address _newToken) external override onlyOwner {
        if (_newToken == address(0)) revert ZeroTokenAddress();
        _token = IERC20(_newToken);
    }

    /// @dev Required by the OZ UUPS module
    function _authorizeUpgrade(address) internal override onlyOwner {}

    function upgradeTo(address newImplementation) public onlyProxy onlyOwner {
        upgradeToAndCall(newImplementation, new bytes(0));
    }
}
```

## Detailed Root Cause Analysis


Seed transaction trace for exploit tx 0xd813751bfb98a51912b8394b5856ae4515be6a9c6e5583e06b41d9255ba6e3c1 (router -> helper -> RareStakingV1::updateMerkleRoot + claim):

```text
    │   ├─ [1373] TransparentUpgradeableProxy::fallback(ERC1967Proxy: [0x3f4D749675B3e48bCCd932033808a7079328Eb48]) [staticcall]
    │   │   ├─ [542] SuperRareToken::balanceOf(ERC1967Proxy: [0x3f4D749675B3e48bCCd932033808a7079328Eb48]) [delegatecall]
    │   │   │   └─ ← [Return] 11907874713019104529057960 [1.19e25]
    │   │   └─ ← [Return] 11907874713019104529057960 [1.19e25]
    │   ├─ [15406] ERC1967Proxy::fallback(0x93f3c0d0d71a7c606fe87524887594a106b44c65d46fa72a42d80bd6259ade7e)
    │   │   ├─ [14935] RareStakingV1::updateMerkleRoot(0x93f3c0d0d71a7c606fe87524887594a106b44c65d46fa72a42d80bd6259ade7e) [delegatecall]
    │   │   │   ├─ emit NewClaimRootAdded(root: 0x93f3c0d0d71a7c606fe87524887594a106b44c65d46fa72a42d80bd6259ade7e, round: 3, timestamp: 1753690919 [1.753e9])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 2: 2 → 3
    │   │   │   │   @ 0: 0x9bddda3825a4928a2bf9c0919e5179e621a7f8784dcff371d3b52d67807725b1 → 0x93f3c0d0d71a7c606fe87524887594a106b44c65d46fa72a42d80bd6259ade7e
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [63044] ERC1967Proxy::fallback(11907874713019104529057960 [1.19e25], [])
    │   │   ├─ [62564] RareStakingV1::claim(11907874713019104529057960 [1.19e25], []) [delegatecall]
    │   │   │   ├─ [29320] TransparentUpgradeableProxy::fallback(0x08947cedf35f9669012bDA6FdA9d03c399B017Ab, 11907874713019104529057960 [1.19e25])
    │   │   │   │   ├─ [28486] SuperRareToken::transfer(0x08947cedf35f9669012bDA6FdA9d03c399B017Ab, 11907874713019104529057960 [1.19e25]) [delegatecall]
    │   │   │   │   │   ├─ emit Transfer(from: ERC1967Proxy: [0x3f4D749675B3e48bCCd932033808a7079328Eb48], to: 0x08947cedf35f9669012bDA6FdA9d03c399B017Ab, value: 11907874713019104529057960 [1.19e25])
    │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   @ 0x34319f46e12da4e414dc9d755180427129775ba9d65381f08f52016a8fc29aed: 0x00000000000000000000000000000000000000000009d9972e8262b432cd88a8 → 0
    │   │   │   │   │   │   @ 0xbb6d0121e99dbd8a36c6db18f1d7e2e39181c8afe56d28107e052f614968d590: 0 → 0x00000000000000000000000000000000000000000009d9972e8262b432cd88a8
    │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ emit TokensClaimed(root: 0x93f3c0d0d71a7c606fe87524887594a106b44c65d46fa72a42d80bd6259ade7e, addr: 0x08947cedf35f9669012bDA6FdA9d03c399B017Ab, amount: 11907874713019104529057960 [1.19e25], round: 3)
```

ERC20 balance differences for RARE during exploit tx 0xd81375...e3c1:

```json
{
  "chainid": 1,
  "txhash": "0xd813751bfb98a51912b8394b5856ae4515be6a9c6e5583e06b41d9255ba6e3c1",
  "native_balance_deltas": [
    {
      "address": "0xdadb0d80178819f2319190d340ce9a924f783711",
      "before_wei": "19492051153079716569",
      "after_wei": "19506771246611786313",
      "delta_wei": "14720093532069744"
    },
    {
      "address": "0x5b9b4b4dafbcfceea7afba56958fcbb37d82d4a2",
      "before_wei": "980744559207118177",
      "after_wei": "965695013266440369",
      "delta_wei": "-15049545940677808"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0xba5bde662c17e2adff1075610382b9b691296350",
      "holder": "0x3f4d749675b3e48bccd932033808a7079328eb48",
      "before": "11907874713019104529057960",
      "after": "0",
      "delta": "-11907874713019104529057960",
      "balances_slot": "101",
      "slot_key": "0x34319f46e12da4e414dc9d755180427129775ba9d65381f08f52016a8fc29aed",
      "layout_address": "0x31acaaea0529894e7c3a5c70d3f9ee6d7804684f",
      "contract_name": "SuperRareToken"
    },
    {
      "token": "0xba5bde662c17e2adff1075610382b9b691296350",
      "holder": "0x08947cedf35f9669012bda6fda9d03c399b017ab",
      "before": "0",
      "after": "11907874713019104529057960",
      "delta": "11907874713019104529057960",
      "balances_slot": "101",
      "slot_key": "0xbb6d0121e99dbd8a36c6db18f1d7e2e39181c8afe56d28107e052f614968d590",
      "layout_address": "0x31acaaea0529894e7c3a5c70d3f9ee6d7804684f",
      "contract_name": "SuperRareToken"
    }
  ],
  "erc20_balance_delta_errors": [],
  "source_code": [
    {
      "layout_addr": "0x31acaaea0529894e7c3a5c70d3f9ee6d7804684f",
      "path": "seed/1/0x31acaaea0529894e7c3a5c70d3f9ee6d7804684f",
      "token": "0xba5bde662c17e2adff1075610382b9b691296350",
      "contract_name": "SuperRareToken"
    }
  ],
  "errors": []
}
```

## Adversary Flow Analysis

Adversary lifecycle stages:

- **Adversary router deployment**
  - Effect: EOA 0x5b9b4b4dafbcfceea7afba56958fcbb37d82d4a2 deploys router/orchestrator contract 0x2073..., establishing adversary-owned infrastructure that will later deploy the helper and route calls to RareStakingV1.
  - Tx 0x544f309fad462f3347cf8a5f9428cf33e7242ddf642d5f53faedcdf91a70c910 on chainid 1 (block 23016420, mechanism contract_deployment)
  - Evidence: artifacts/root_cause/data_collector/iter_2/tx/1/0x544f309fad462f3347cf8a5f9428cf33e7242ddf642d5f53faedcdf91a70c910/trace.cast.log; artifacts/root_cause/data_collector/iter_1/address/1/0x2073111e6ebb6826f7e9c6192c6304aa5af5e340/normal_txlist.json

- **Helper deployment and Merkle-root update**
  - Effect: Within the seed tx, router 0x2073... creates helper 0x0894..., which calls RareStakingV1::updateMerkleRoot on proxy 0x3f4d..., setting currentClaimRoot to 0x93f3c0d0d71a7c606fe87524887594a106b44c65d46fa72a42d80bd6259ade7e that encodes a single-leaf Merkle tree for the helper and the full staking balance.
  - Tx 0xd813751bfb98a51912b8394b5856ae4515be6a9c6e5583e06b41d9255ba6e3c1 on chainid 1 (block 23016423, mechanism router_orchestration_and_helper_creation)
  - Evidence: artifacts/root_cause/seed/1/0xd813751bfb98a51912b8394b5856ae4515be6a9c6e5583e06b41d9255ba6e3c1/trace.cast.log; artifacts/root_cause/data_collector/iter_2/contract/1/0x08947cedf35f9669012bda6fda9d03c399b017ab/pseudocode_summary.md

- **RARE claim and profit realization**
  - Effect: After setting the malicious Merkle root, helper 0x0894... calls RareStakingV1::claim(11907874713019104529057960, []), causing SuperRareToken (RARE) to transfer exactly 11907874713019104529057960 tokens from staking proxy 0x3f4d... to helper 0x0894..., as recorded in balance_diff.json and ERC20 Transfer events; the helper ends the transaction holding the full previous staking balance in RARE.
  - Tx 0xd813751bfb98a51912b8394b5856ae4515be6a9c6e5583e06b41d9255ba6e3c1 on chainid 1 (block 23016423, mechanism claim_and_token_transfer)
  - Evidence: artifacts/root_cause/seed/1/0xd813751bfb98a51912b8394b5856ae4515be6a9c6e5583e06b41d9255ba6e3c1/trace.cast.log; artifacts/root_cause/seed/1/0xd813751bfb98a51912b8394b5856ae4515be6a9c6e5583e06b41d9255ba6e3c1/balance_diff.json

## Impact & Losses

- Total loss: 11907874713019104529057960 RARE

The adversary drains the entire RARE balance held by the RareStaking proxy 0x3f4d749675b3e48bccd932033808a7079328eb48, moving 11907874713019104529057960 RARE to helper contract 0x08947cedf35f9669012bda6fda9d03c399b017ab in a single Ethereum transaction. The loss is confined to the staking contract’s RARE holdings and does not depend on cross-chain interactions or external oracles, though the precise distribution of that loss across staking participants and protocol-owned positions is not determined from on-chain state alone.

## References

- [1] Seed tx metadata, trace, and balance diff for RARE drain: artifacts/root_cause/seed/1/0xd813751bfb98a51912b8394b5856ae4515be6a9c6e5583e06b41d9255ba6e3c1
- [2] RareStakingV1 implementation source and proxy implementation slot resolution: artifacts/root_cause/data_collector/iter_3/contract/1/0xffb512b9176d527c5d32189c3e310ed4ab2bb9ec
- [3] Helper and router contract behavior summaries: artifacts/root_cause/data_collector/iter_2/contract/1
- [4] SuperRareToken (RARE) ERC20 source and layout: artifacts/root_cause/seed/1/0x31acaaea0529894e7c3a5c70d3f9ee6d7804684f