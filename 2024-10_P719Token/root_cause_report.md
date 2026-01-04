# P719 treasury payout on BNB Chain

## 1. Incident Overview TL;DR

Protocol: P719 treasury / payout on BNB Chain (chainid 56).
Root cause category: other. ACT classification: is_act = false.

On BNB Chain (chainid 56), a single transaction from EOA 0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6 uses a 4,000 WBNB flash loan to interact with the P719 treasury/payout contract 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc, causing BNB and P719 token balances to decrease in that contract while three hard-coded payout addresses receive BNB and one of them plus a helper contract receive P719.

The behavior is a privileged, owner-gated treasury payout path in the P719 contract with hard-coded recipients and no profitable, permissionless ACT opportunity for an unprivileged adversary; the candidate adversary/operator cluster ends with a net BNB loss.

Seed / victim-observed transaction: 0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3 in block 43023423 on chainid 56.

## 2. Key Background

- The incident occurs on BNB Chain (chainid 56) and centers on ERC20-like token P719, whose treasury/payout logic is implemented in contract 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc.
- Contract 0x172fcD41E0913e95784454622d1c3724f546f849 provides a 4,000 WBNB flash loan, which is unwrapped to BNB via the canonical WBNB contract 0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c and later repaid.
- An orchestrator contract 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98 and a helper contract 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8 coordinate approvals and calls into the P719 contract to execute its payout logic.
- Short-window P&L analysis for blocks 43023422–43023423 shows that the P719 contract loses BNB and P719, three hard-coded addresses (0x99cd55d6a838f465caeba3b64e267adf29516e62, 0x0e074d49b4dc31d304ed22c3f154db61462161aa, 0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b) gain BNB, one of them gains P719, the helper gains only P719, and the orchestrator cluster has a net BNB decrease.

Pre-state definition:

- BNB Chain state immediately before block 43023423, reconstructed from the provided seed metadata, trace, and short-window balance diffs.

Evidence used to reconstruct the pre-state:

- artifacts/root_cause/seed/index.json
- artifacts/root_cause/seed/56/0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3/metadata.json
- artifacts/root_cause/seed/56/0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3/trace.cast.log
- artifacts/root_cause/data_collector/iter_3/pnl/56/dr_18_pnl_summary.json
- artifacts/root_cause/data_collector/iter_3/contract/56/0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc/dr_17_raw_snippets.txt
- artifacts/root_cause/data_collector/iter_3/contract/56/0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc/dr_19_storage_mapping_summary.json

## 3. Vulnerability Analysis

The root cause is an owner/admin-gated treasury payout mechanism in P719 that distributes BNB and tokens from a treasury address to a fixed set of hard-coded recipients when internal mode flags and per-caller flags are enabled; this mechanism is not accessible as a profitable, permissionless strategy to an unprivileged adversary under the ACT model.

Vulnerable or treasury-critical components:

- P719 treasury/payout contract 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc: owner/admin-gated mode flags and hard-coded payout recipients govern treasury outflows.
- Orchestrator contract 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98: coordinates flash loan, helper deployment, approvals, and calls into the P719 treasury.
- Helper contract 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8: deployed with the P719 address as a constructor argument, grants allowance to the orchestrator, and receives P719 tokens.
- Flash-loan pool 0x172fcD41E0913e95784454622d1c3724f546f849 and WBNB token 0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c: provide and wrap/unwrap 4,000 WBNB but do not themselves introduce an anyone-can-take exploit path.

Conditions governing whether the payout path can be exercised:

- The P719 payout path requires internal mode flags in storage slot 6 to be enabled and per-caller flags in the slot-11 mapping to be set; these gating conditions are controlled by privileged actors rather than arbitrary unprivileged searchers.
- Payout recipients are fixed at compile time as 0x99cd55d6a838f465caeba3b64e267adf29516e62, 0x0e074d49b4dc31d304ed22c3f154db61462161aa, and 0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b; the orchestrator cannot choose or modify them using public calldata.
- Short-window P&L shows that the orchestrator cluster pays BNB fees and ends with a non-positive net BNB change, so there is no deterministic, permissionless profit predicate for this cluster based solely on the observed on-chain behavior.

Security principles and risk characterization:

- No protocol-level safety invariant for unprivileged users is violated; the evidence instead reflects a privileged treasury/payout mechanism whose configuration and beneficiary set are governed by owner/admin controls.
- The main risk is governance and treasury configuration rather than a permissionless exploit: changes to payout mode flags and hard-coded recipient sets can cause large on-chain transfers, but these are not triggered by an unprivileged ACT adversary in the observed transaction.

ACT success predicate evaluation (profit type):

- Reference asset: BNB.
- Adversary/operator cluster: cluster:{0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6,0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98,0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8}.
- Fees in reference asset: Positive, reflected in the approximately 0.199009357672029392 BNB net decrease for EOA 0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6 over blocks 43023422–43023423..
- Value before: For 0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6, the P&L summary reports a pre-window BNB balance of 1.084163492061724712..
- Value after: For 0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6, the P&L summary reports a post-window BNB balance of 0.885154134389695320..
- Value delta: Across the same window, the candidate adversary/operator cluster has a non-positive net BNB change: 0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6 loses 0.199009357672029392 BNB, while 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98 and 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8 have zero BNB change..
- Valuation notes: Because the candidate adversary/operator cluster pays gas and flash-loan costs and receives no BNB inflows, its net BNB position decreases and there is no profitable anyone-can-take sequence satisfying the ACT profit predicate within the provided evidence..

Non-monetary oracle predicate:

- No on-chain non-monetary oracle predicate is defined in the evidence; the analysis is purely monetary in BNB terms.

## 4. Detailed Root Cause Analysis

### 4.1 Pre-state and Observed Transaction Sequence

Observed transaction sequence_b (victim-observed leg):

- Index: 1, chainid: 56, txhash: 0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3.
- Type: victim-observed.
- Inclusion feasibility: Standard BNB Chain transaction from EOA 0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6 with sufficient balance and gas, included in block 43023423..
- Operational notes: Coordinates a 4,000 WBNB flash loan, deploys helper contract 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8, configures approvals toward treasury contract 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc, triggers the BNB payout path, and repays the flash loan; the candidate adversary/operator cluster ends with a net BNB loss and P719 exposure..

Seed transaction trace excerpt (Foundry `cast run -vvvvv` for the victim tx):

```text
Executing previous transactions from the block.
Traces:
  [22591290] 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98::510a82a9(0000000000000000000000006beee2b57b064eac5f432fc19009e3e78734eabc0000000000000000000000000000000000000000000000d8d726b7177a800000)
    ├─ [22554622] 0x172fcD41E0913e95784454622d1c3724f546f849::flash(0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98, 0, 4000000000000000000000 [4e21], 0x0000000000000000000000000000000000000000000000000000000000000001)
    │   ├─ [2531] BEP20USDT::balanceOf(0x172fcD41E0913e95784454622d1c3724f546f849) [staticcall]
    │   │   └─ ← [Return] 2717894576723696321518708 [2.717e24]
    │   ├─ [2534] WBNB::balanceOf(0x172fcD41E0913e95784454622d1c3724f546f849) [staticcall]
    │   │   └─ ← [Return] 5749643529911443581227 [5.749e21]
    │   ├─ [27962] WBNB::transfer(0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98, 4000000000000000000000 [4e21])
    │   │   ├─ emit Transfer(from: 0x172fcD41E0913e95784454622d1c3724f546f849, to: 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98, value: 4000000000000000000000 [4e21])
    │   │   ├─  storage changes:
    │   │   │   @ 0xed93f154226bea5228a538ddd7f6e1b8d878a5d95dc495daa8ac4679fe6b0986: 0x000000000000000000000000000000000000000000000137b055378996a2e92b → 0x00000000000000000000000000000000000000000000005ed92e80721c22e92b
    │   │   │   @ 0xaffd977f4a0a8e6abda768a03600991a04e0f9b25d9e15b5855c21ba595b172c: 0 → 0x0000000000000000000000000000000000000000000000d8d726b7177a800000
    │   │   └─ ← [Return] true
    │   ├─ [22488251] 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98::pancakeV3FlashCallback(0, 400000000000000000 [4e17], 0x0000000000000000000000000000000000000000000000000000000000000001)
    │   │   ├─ [9195] WBNB::withdraw(4000000000000000000000 [4e21])
    │   │   │   ├─ [55] 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98::fallback{value: 4000000000000000000000}()
    │   │   │   │   └─ ← [Stop]
    │   │   │   ├─ emit Withdrawal(src: 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98, wad: 4000000000000000000000 [4e21])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 0xaffd977f4a0a8e6abda768a03600991a04e0f9b25d9e15b5855c21ba595b172c: 0x0000000000000000000000000000000000000000000000d8d726b7177a800000 → 0
    │   │   │   └─ ← [Stop]
    │   │   ├─ [2382] 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc::totalSupply() [staticcall]
    │   │   │   └─ ← [Return] 180276286853251591367869 [1.802e23]
    │   │   ├─ [401316] → new <unknown>@0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8(0x608060405234801561001057600080fd5b50604051610944380380610944833981810160405281019061003291906101dd565b326000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555080600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663095ea7b3337fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6040518363ffffffff1660e01b8152600401610130929190610232565b6020604051808303816000875af115801561014f573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906101739190610293565b50506102c0565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006101aa8261017f565b9050919050565b6101ba8161019f565b81146101c557600080fd5b50565b6000815190506101d7816101b1565b92915050565b6000602082840312156101f3576101f261017a565b5b6000610201848285016101c8565b91505092915050565b6102138161019f565b82525050565b6000819050919050565b61022c81610219565b82525050565b6000604082019050610247600083018561020a565b6102546020830184610223565b9392505050565b60008115159050919050565b6102708161025b565b811461027b57600080fd5b50565b60008151905061028d81610267565b92915050565b6000602082840312156102a9576102a861017a565b5b60006102b78482850161027e565b91505092915050565b610675806102cf6000396000f3fe60806040526004361061002d5760003560e01c8063a6f2ae3a14610039578063e4849b321461004357610034565b3661003457005b600080fd5b61004161006c565b005b34801561004f57600080fd5b5061006a60048036038101906100659190610427565b610195565b005b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163273ffffffffffffffffffffffffffffffffffffffff16146100c457600080fd5b6000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163460405161010c90610485565b60006040518083038185875af1925050503d8060008114610149576040519150601f19603f3d011682016040523d82523d6000602084013e61014e565b606091505b5050905080610192576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610189906104f7565b60405180910390fd5b50565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163273ffffffffffffffffffffffffffffffffffffffff16146101ed57600080fd5b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663a9059cbb600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16836040518363ffffffff1660e01b815260040161026c929190610567565b6020604051808303816000875af115801561028b573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906102af91906105c8565b506102b947610303565b3373ffffffffffffffffffffffffffffffffffffffff166108fc479081150290604051600060405180830381858888f193505050501580156102ff573d6000803e3d6000fd5b5050565b6103998160405160240161031791906105f5565b6040516020818303038152906040527ff82c50f1000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505061039c565b50565b6103b3816103ab6103b66103d7565b63ffffffff16565b50565b60006a636f6e736f6c652e6c6f679050600080835160208501845afa505050565b6103e2819050919050565b6103ea610610565b565b600080fd5b6000819050919050565b610404816103f1565b811461040f57600080fd5b50565b600081359050610421816103fb565b92915050565b60006020828403121561043d5761043c6103ec565b5b600061044b84828501610412565b91505092915050565b600081905092915050565b50565b600061046f600083610454565b915061047a8261045f565b600082019050919050565b600061049082610462565b9150819050919050565b600082825260208201905092915050565b7f626162652063616c6c206661696c656400000000000000000000000000000000600082015250565b60006104e160108361049a565b91506104ec826104ab565b602082019050919050565b60006020820190508181036000830152610510816104d4565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061054282610517565b9050919050565b61055281610537565b82525050565b610561816103f1565b82525050565b600060408201905061057c6000830185610549565b6105896020830184610558565b9392505050565b60008115159050919050565b6105a581610590565b81146105b057600080fd5b50565b6000815190506105c28161059c565b92915050565b6000602082840312156105de576105dd6103ec565b5b60006105ec848285016105b3565b91505092915050565b600060208201905061060a6000830184610558565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052605160045260246000fdfea26469706673582212206980c7c8b418dd94322501c60892a6a98d235d45b32bba1506b5561157f7a65964736f6c634300081100330000000000000000000000006beee2b57b064eac5f432fc19009e3e78734eabc)
    │   │   │   ├─ [24718] 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc::approve(0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98, 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77])
    │   │   │   │   ├─ emit Approval(owner: 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8, spender: 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98, value: 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0x8c51ddde35a343148d5fc85cab39be4cb4536b3e8d79541b26251bffb95c8ee3: 0 → 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 0: 0 → 0x000000000000000000000000feb19ae8c0448f25de43a3afcb7b29c9cef6eff6
    │   │   │   │   @ 1: 0 → 0x0000000000000000000000006beee2b57b064eac5f432fc19009e3e78734eabc
    │   │   │   └─ ← [Return] 0x60806040526004361061002d5760003560e01c8063a6f2ae3a14610039578063e4849b321461004357610034565b3661003457005b600080fd5b61004161006c565b005b34801561004f57600080fd5b5061006a60048036038101906100659190610427565b610195565b005b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163273ffffffffffffffffffffffffffffffffffffffff16146100c457600080fd5b6000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163460405161010c90610485565b60006040518083038185875af1925050503d8060008114610149576040519150601f19603f3d011682016040523d82523d6000602084013e61014e565b606091505b5050905080610192576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610189906104f7565b60405180910390fd5b50565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163273ffffffffffffffffffffffffffffffffffffffff16146101ed57600080fd5b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663a9059cbb600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16836040518363ffffffff1660e01b815260040161026c929190610567565b6020604051808303816000875af115801561028b573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906102af91906105c8565b506102b947610303565b3373ffffffffffffffffffffffffffffffffffffffff166108fc479081150290604051600060405180830381858888f193505050501580156102ff573d6000803e3d6000fd5b5050565b6103998160405160240161031791906105f5565b6040516020818303038152906040527ff82c50f1000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505061039c565b50565b6103b3816103ab6103b66103d7565b63ffffffff16565b50565b60006a636f6e736f6c652e6c6f679050600080835160208501845afa505050565b6103e2819050919050565b6103ea610610565b565b600080fd5b6000819050919050565b610404816103f1565b811461040f57600080fd5b50565b600081359050610421816103fb565b92915050565b60006020828403121561043d5761043c6103ec565b5b600061044b84828501610412565b91505092915050565b600081905092915050565b50565b600061046f600083610454565b915061047a8261045f565b600082019050919050565b600061049082610462565b9150819050919050565b600082825260208201905092915050565b7f626162652063616c6c206661696c656400000000000000000000000000000000600082015250565b60006104e160108361049a565b91506104ec826104ab565b602082019050919050565b60006020820190508181036000830152610510816104d4565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061054282610517565b9050919050565b61055281610537565b82525050565b610561816103f1565b82525050565b600060408201905061057c6000830185610549565b6105896020830184610558565b9392505050565b60008115159050919050565b6105a581610590565b81146105b057600080fd5b50565b6000815190506105c28161059c565b92915050565b6000602082840312156105de576105dd6103ec565b5b60006105ec848285016105b3565b91505092915050565b600060208201905061060a6000830184610558565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052605160045260246000fdfea26469706673582212206980c7c8b418dd94322501c60892a6a98d235d45b32bba1506b5561157f7a65964736f6c63430008110033
    │   │   ├─ [204441] 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8::buy{value: 10000000000000000000}()
    │   │   │   ├─ [196929] 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc::fallback{value: 10000000000000000000}()
    │   │   │   │   ├─ [4564] 0x1Ca9144d9573b6bCe95D177667039B46a3f7BE29::58cde42d(000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000006) [staticcall]
    │   │   │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000000000000000000000081a
```

### 4.2 P719 Treasury Contract Mechanics and Gating

Disassembly and storage-mapping analysis of 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc show that storage slot 6 encodes mode flags controlling payout behavior and slot 11 holds a mapping keyed by keccak(caller, 0x11) that marks privileged callers. The dispatcher checks CALLDATASIZE and a low-byte mask of slot 6; for empty calldata, it either stops or jumps into a dedicated payout region only when the relevant bit in slot 6 is enabled. Within that region, the code emits a custom payout event (topic 0x49926bbebe8474393f434dfa4f78694c0923efa07d19f2284518bfabd06eb737) and transfers BNB to three hard-coded addresses 0x99cd55d6a838f465caeba3b64e267adf29516e62, 0x0e074d49b4dc31d304ed22c3f154db61462161aa, and 0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b. These recipients are embedded via PUSH32 constants in the runtime bytecode and are not derived from calldata, so the orchestrator cannot redirect payouts to arbitrary addresses. During the seed transaction, the orchestrator takes a 4,000 WBNB flash loan from 0x172fcD41E0913e95784454622d1c3724f546f849, unwraps to BNB, deploys helper 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8, and calls the P719 contract, which has already been configured into a payout-enabled mode by privileged actors outside the observed window. The helper sets an unlimited allowance for the orchestrator and receives a large P719 balance; 0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b also receives both BNB and P719. After repaying the flash loan, the orchestrator cluster {0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6, 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98, 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8} has no BNB profit and holds only P719 exposure, while the treasury contract’s balances decrease in line with a configured payout.

Disassembly excerpt around the CALLVALUE-based dispatcher and payout gating for contract 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc:

```text
--- context around CALLVALUE ---
902f1ac
0000026d: EQ
0000026e: PUSH2 0x030f
00000271: JUMPI
00000272: DUP1
00000273: PUSH4 0x095ea7b3
00000278: EQ
00000279: PUSH2 0x0339
0000027c: JUMPI
0000027d: DUP1
0000027e: PUSH4 0x0cc54e93
00000283: EQ
00000284: PUSH2 0x0369
00000287: JUMPI
00000288: DUP1
00000289: PUSH4 0x11106ee2
0000028e: EQ
0000028f: PUSH2 0x038d
00000292: JUMPI
00000293: PUSH1 0x00
00000295: DUP1
00000296: REVERT
00000297: JUMPDEST
00000298: CALLDATASIZE
00000299: PUSH2 0x02b1
0000029c: JUMPI
0000029d: PUSH1 0x06
0000029f: SLOAD
000002a0: PUSH1 0xff
000002a2: AND
000002a3: ISZERO
000002a4: PUSH2 0x02af
000002a7: JUMPI
000002a8: PUSH2 0x02af
000002ab: PUSH2 0x099b
000002ae: JUMP
000002af: JUMPDEST
000002b0: STOP
000002b1: JUMPDEST
000002b2: PUSH1 0x00
000002b4: DUP1
000002b5: REVERT
000002b6: JUMPDEST
000002b7: CALLVALUE
000002b8: DUP1
000002b9: ISZERO
000002ba: PUSH2 0x02c2
000002bd: JUMPI
000002be: PUSH1 0x00
000002c0: DUP1
000002c1: REVERT
000002c2: JUMPDEST
000002c3: POP
000002c4: PUSH1 0x07
000002c6: SLOAD
000002c7: PUSH2 0x02d3
000002ca: SWAP1
000002cb: PUSH4 0xffffffff
000002d0: AND
000002d1: DUP2
000002d2: JUMP
000002d3: JUMPDEST
000002d4: PUSH1 0x40
000002d6: MLOAD
000002d7: PUSH4 0xffffffff
000002dc: SWAP1
000002dd: SWAP2
000002de: AND
000002df: DUP2
000002e0: MSTORE
000002e1: PUSH1 0x20
000002e3: ADD
000002e4: JUMPDEST
000002e5: PUSH1 0x40
000002e7: MLOAD
000002e8: DUP1
000002e9: SWAP2
000002ea: SUB
000002eb: SWAP1
```

Storage mapping summary (state diff) for P719 balances and totalSupply around the incident:

```json
{
  "chainid": 56,
  "contract": "0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc",
  "candidate_balance_mapping_slots": {
    "0": [
      {
        "address": "0x1bea54b0c39140d5ae4414150b2fff0bd64fd6b8",
        "slot": 0,
        "storage_key": "0x8ff044139c51349c43dab588366ad5bbd84cacd34df258f29fd620e5b644d5ef",
        "from": "0x0",
        "to": "0x0000000000000000000000000000000000000000000000325172fa38890091d4"
      },
      {
        "address": "0x2222000000000000000000000000000000000000",
        "slot": 0,
        "storage_key": "0xa4efa37ed7846dbaf04315286d552ba5c336bda087c55e1cedec2b7be2e513cf",
        "from": "0x0000000000000000000000000000000000000000000000219a4ce56c22331504",
        "to": "0x00000000000000000000000000000000000000000000014ffa63010f3277b9fe"
      },
      {
        "address": "0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b",
        "slot": 0,
        "storage_key": "0x161be2ea61ab77429cc46d6050649e6e6a864d4f47fe4722ad74db99661b78b6",
        "from": "0x0000000000000000000000000000000000000000000001f6f40a63fe46af28e9",
        "to": "0x0000000000000000000000000000000000000000000002538a550b4d895debee"
      }
    ],
    "11": [
      {
        "address": "0x1bea54b0c39140d5ae4414150b2fff0bd64fd6b8",
        "slot": 11,
        "storage_key": "0xf3962d968aa91c4b1794e60033c5e9127479f4e2693606b042e190676bb8d8e3",
        "from": "0x0",
        "to": "0x0000000000000000000000000000000000000000000000325172fa38890091d4"
      }
    ],
    "12": [
      {
        "address": "0x1bea54b0c39140d5ae4414150b2fff0bd64fd6b8",
        "slot": 12,
        "storage_key": "0x1e6408c37da0c5f8976f3e847cdb2e0838028dc9bbe22edfd9ec3018f542c5bc",
        "from": "0x0",
        "to": "0x0000000000000000000000000000000000000000000000000000000000000001"
      }
    ]
  },
  "per_address_balances": {},
  "candidate_totalSupply_slots": [
    {
      "slot": 2,
      "value": "0x000000000000000000000000000000000000000000001fb238f64ca035a3fac4"
    }
  ],
  "notes": []
}
```

### 4.3 Helper Deployment, Approvals, and Orchestrator Behavior

Constructor bytecode excerpt for helper contract 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8 (Etherscan contract_creation result), showing embedding of the P719 address and allowance setup:

```text
0x608060405234801561001057600080fd5b50604051610944380380610944833981810160405281019061003291906101dd565b326000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555080600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663095ea7b3337fffffffffffffffffffffff
```

## 5. Adversary Flow Analysis

A single BNB Chain transaction uses a 4,000 WBNB flash loan to activate and run the P719 treasury payout path, paying BNB to three hard-coded recipients and leaving the orchestrator cluster with P719 tokens and a net BNB loss.

Adversary/operator cluster accounts and roles:

- 0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6 (chainid 56): Sender of the seed transaction that initiates the flash loan and orchestrator flow; pays gas and funds the strategy.
- 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98 (chainid 56): Orchestrator contract called by 0xfeb19ae8... that requests the flash loan, unwraps WBNB, interacts with the P719 contract, and repays the loan.
- 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8 (chainid 56): Helper contract deployed during the seed transaction; constructed with the P719 contract address, grants allowance to the orchestrator, and receives a large P719 balance.

Victim and beneficiary candidates:

- P719 treasury/payout contract 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc on BNB Chain (chainid 56).
- Flash-loan pool 0x172fcD41E0913e95784454622d1c3724f546f849 on BNB Chain (chainid 56).
- WBNB token contract 0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c on BNB Chain (chainid 56).
- Hard-coded payout recipient 0x99cd55d6a838f465caeba3b64e267adf29516e62 on BNB Chain (chainid 56).
- Hard-coded payout recipient 0x0e074d49b4dc31d304ed22c3f154db61462161aa on BNB Chain (chainid 56).
- Hard-coded payout recipient 0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b on BNB Chain (chainid 56).

Lifecycle stages for the orchestrated flow:

### 5.1 Flash-loan setup and funding

Primary transaction(s): ['0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3']

Orchestrator contract 0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98 calls flash() on 0x172fcD41E0913e95784454622d1c3724f546f849 to borrow 4,000 WBNB, receives WBNB via transfer, and unwraps it to 4,000 BNB via WBNB::withdraw, funding the subsequent interactions.

Evidence artifacts: artifacts/root_cause/seed/56/0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3/trace.cast.log, artifacts/root_cause/data_collector/iter_1/contract/56/0x172fcD41E0913e95784454622d1c3724f546f849/source

### 5.2 Helper deployment and approvals

Primary transaction(s): ['0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3']

During the flash-loan callback, 0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6 deploys helper 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8 with the P719 contract address in its constructor, which stores the EOA and P719 addresses and calls approve(0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98, 2^256-1) on the P719 contract.

Evidence artifacts: artifacts/root_cause/seed/56/0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3/trace.cast.log, artifacts/root_cause/data_collector/iter_1/contract/56/0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8/contract_creation.json

### 5.3 Treasury payout execution and unwind

Primary transaction(s): ['0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3']

The orchestrator sends multiple fallback calls with 10 BNB each to the P719 contract, which, due to enabled mode flags and caller flags, executes its payout path, transferring BNB to the hard-coded recipients {0x99cd55d6a838f465caeba3b64e267adf29516e62, 0x0e074d49b4dc31d304ed22c3f154db61462161aa, 0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b} and distributing P719 to 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8 and 0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b. The flash loan is repaid, leaving the orchestrator cluster with P719 tokens and a net BNB loss.

Evidence artifacts: artifacts/root_cause/data_collector/iter_3/contract/56/0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc/dr_17_raw_snippets.txt, artifacts/root_cause/data_collector/iter_3/pnl/56/dr_18_pnl_summary.json, artifacts/root_cause/data_collector/iter_3/contract/56/0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc/dr_19_storage_mapping_summary.json

Cluster-level BNB outcome under the ACT model:

- Adversary/operator cluster cluster:{0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6,0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98,0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8} has a non-positive net BNB change over the analysis window, so there is no on-chain profit predicate satisfied for this cluster.

## 6. Impact & Losses

- BNB: 575799074208829188341 wei outflow from 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc (approximately 575.799074208829188341 BNB), matched by inflows of 14 BNB to 0x99cd55d6a838f465caeba3b64e267adf29516e62 and 7 BNB each to 0x0e074d49b4dc31d304ed22c3f154db61462161aa and 0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b.
- P719: 50419871114448106447140 unit decrease at 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc, with 928206232070618386900 units flowing to 0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8 and 1707930106994107532037 units to 0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b.

From an on-chain perspective, the primary impact is a treasury-style redistribution of BNB and P719 from the P719 contract 0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc to three hard-coded payout addresses and a helper address; the candidate adversary/operator cluster pays net BNB and holds P719 exposure, so there is no realized anyone-can-take profit under the ACT model.

Short-window P&L summary for key addresses (blocks 43023422–43023423):

```json
{
  "chainid": 56,
  "seed_tx_block": 43023423,
  "block_window": [
    43023422,
    43023423
  ],
  "addresses": {
    "0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6": {
      "before": {
        "bnb_wei": 1084163492061724712,
        "wbnb": 0,
        "token_6b": 0
      },
      "after": {
        "bnb_wei": 885154134389695320,
        "wbnb": 0,
        "token_6b": 0
      },
      "delta": -199009357672029392,
      "wbnb_delta": 0,
      "token_6b_delta": 0
    },
    "0x3f32c7cfb0a78ddea80a2384ceb4633099cbdc98": {
      "before": {
        "bnb_wei": 0,
        "wbnb": 0,
        "token_6b": 0
      },
      "after": {
        "bnb_wei": 0,
        "wbnb": 0,
        "token_6b": 0
      },
      "delta": 0,
      "wbnb_delta": 0,
      "token_6b_delta": 0
    },
    "0x1bea54b0c39140d5ae4414150b2fff0bd64fd6b8": {
      "before": {
        "bnb_wei": 0,
        "wbnb": 0,
        "token_6b": 0
      },
      "after": {
        "bnb_wei": 0,
        "wbnb": 0,
        "token_6b": 928206232070618386900
      },
      "delta": 0,
      "wbnb_delta": 0,
      "token_6b_delta": 928206232070618386900
    },
    "0x6beee2b57b064eac5f432fc19009e3e78734eabc": {
      "before": {
        "bnb_wei": 675766160064604403325,
        "wbnb": 0,
        "token_6b": 63653242351510302981331
      },
      "after": {
        "bnb_wei": 99967085855775214984,
        "wbnb": 0,
        "token_6b": 13233371237062196534191
      },
      "delta": -575799074208829188341,
      "wbnb_delta": 0,
      "token_6b_delta": -50419871114448106447140
    },
    "0x99cd55d6a838f465caeba3b64e267adf29516e62": {
      "before": {
        "bnb_wei": 3944599872434505019,
        "wbnb": 0,
        "token_6b": 0
      },
      "after": {
        "bnb_wei": 17944599872434505019,
        "wbnb": 0,
        "token_6b": 0
      },
      "delta": 14000000000000000000,
      "wbnb_delta": 0,
      "token_6b_delta": 0
    },
    "0x0e074d49b4dc31d304ed22c3f154db61462161aa": {
      "before": {
        "bnb_wei": 275287594541901313719,
        "wbnb": 0,
        "token_6b": 0
      },
      "after": {
        "bnb_wei": 282287594541901313719,
        "wbnb": 0,
        "token_6b": 0
      },
      "delta": 7000000000000000000,
      "wbnb_delta": 0,
      "token_6b_delta": 0
    },
    "0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b": {
      "before": {
        "bnb_wei": 104745603049905979167,
        "wbnb": 0,
        "token_6b": 9277850502640975161577
      },
      "after": {
        "bnb_wei": 111745603049905979167,
        "wbnb": 0,
        "token_6b": 10985780609635082693614
      },
      "delta": 7000000000000000000,
      "wbnb_delta": 0,
      "token_6b_delta": 1707930106994107532037
    }
  },
  "tokens": {
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": {
      "symbol": " \u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0004WBNB",
      "decimals": 18
    },
    "0x6beee2b57b064eac5f432fc19009e3e78734eabc": {
      "symbol": " \u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0004P719",
      "decimals": 18
    }
  },
  "notes": [],
  "seed_native_balance_diff": [
    {
      "address": "0x99cd55d6a838f465caeba3b64e267adf29516e62",
      "before_wei": "3944599872434505019",
      "after_wei": "17944599872434505019",
      "delta_wei": "14000000000000000000"
    },
    {
      "address": "0x0e074d49b4dc31d304ed22c3f154db61462161aa",
      "before_wei": "275287594541901313719",
      "after_wei": "282287594541901313719",
      "delta_wei": "7000000000000000000"
    },
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "before_wei": "1333859571519572002319287",
      "after_wei": "1334407370593780831507628",
      "delta_wei": "547799074208829188341"
    },
    {
      "address": "0x6beee2b57b064eac5f432fc19009e3e78734eabc",
      "before_wei": "675766160064604403325",
      "after_wei": "99967085855775214984",
      "delta_wei": "-575799074208829188341"
    },
    {
      "address": "0xfeb19ae8c0448f25de43a3afcb7b29c9cef6eff6",
      "before_wei": "1084163492061724712",
      "after_wei": "885154134389695320",
      "delta_wei": "-199009357672029392"
    },
    {
      "address": "0x3d5d1e06e9e67908f940059d13fc0a655f81dd0b",
      "before_wei": "104745603049905979167",
      "after_wei": "111745603049905979167",
      "delta_wei": "7000000000000000000"
    }
  ]
}
```

## 7. References

- [1] Seed transaction metadata and trace: artifacts/root_cause/seed/56/0x9afcac8e82180fa5b2f346ca66cf6eb343cd1da5a2cd1b5117eb7eaaebe953b3/{metadata.json,trace.cast.log}
- [2] P&L summary for BNB and P719 around the incident window: artifacts/root_cause/data_collector/iter_3/pnl/56/dr_18_pnl_summary.json
- [3] P719 contract assembly, payout code, and storage mapping: artifacts/root_cause/data_collector/iter_3/contract/56/0x6bEee2B57b064EAC5F432FC19009E3E78734Eabc/{contract_assembly.txt,dr_17_raw_snippets.txt,dr_19_storage_mapping_summary.json}
- [4] Orchestrator and helper contract artifacts: artifacts/root_cause/data_collector/iter_1/contract/56/0x3F32c7cfb0a78DDEA80a2384CEB4633099CbDC98, artifacts/root_cause/data_collector/iter_1/contract/56/0x1bea54B0c39140D5Ae4414150B2FFF0bd64fD6b8
- [5] Flash-loan pool and WBNB contract artifacts: artifacts/root_cause/data_collector/iter_1/contract/56/0x172fcD41E0913e95784454622d1c3724f546f849, artifacts/root_cause/data_collector/iter_1/contract/56/0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c