## Incident Overview TL;DR

On BSC, an operator-controlled cluster centered on EOA `0xe2336b08a43f87a4ac8de7707ab7333ba4dbaf7c` uses unverified helper contracts to route USDT through the verified Grizzifi staking contract and a dispatcher, ultimately paying large USDT amounts back to `0xe2336...`. All observed profitable flows are initiated by the operator via owner-gated helper contracts and standard ERC20 allowances; there is no anyone-can-take (ACT) opportunity for an unprivileged adversary.

The root cause classification is therefore **non-ACT**: the incident reflects centralized operator fund routing and fee extraction using owner-controlled infrastructure, not a permissionless exploit or MEV-style strategy that a generic adversary could reproduce from public on-chain state.

## Key Background

- **Chain and asset**: Binance Smart Chain (chainid 56), BEP20 USDT token at `0x55d398326f99059ff775485246999027b3197955` (“BEP20USDT”).
- **Core staking contract (victim-side protocol)**: Grizzifi staking contract at `0x21ab8943380b752306abf4d49c203b011a89266b` with verified source code.
- **Operator EOA**: `0xe2336b08a43f87a4ac8de7707ab7333ba4dbaf7c`, which initiates all seed and payout transactions in this analysis.
- **Helper contracts (operator-controlled)**:
  - Dispatcher at `0x03ba640c955ebb07520a31ea1ef572c404a3f9ae`.
  - Orchestrator at `0xed35746f389177ecd52a16987b2aac74aa0c1128`.
  Both are unverified, but disassembly and state show an owner slot at storage index 0 that is set to `0xe2336...`, and their key functions enforce owner-based checks, so they are controlled by the operator.
- **Grizzifi owner**: `0xe06d57958de23e1013567a1b00f0a37c9862dec6`, which receives platform fees from Grizzifi in USDT.
- **Seed transactions** (from `all_relevant_txs` and analyzer metadata):
  - `0x36438165d701c883fd9a03631ee0cdeec35a138153720006ab59264db7e075c1` (block 57482334): operator calls orchestrator `0xed3574...`, which interacts with Grizzifi.
  - `0x4302de51c8126e7934da9be1affbde73e5153fe1f9d0200a738a269fe07d22c7` (block 57478534): operator calls dispatcher `0x03ba64...`, which redistributes USDT to many recipients.
- **Related payout transactions**:
  - `0x4fc9be48f0a479cda9585ce5e64ba207d43f6524df07535d4be3ff5e297dde54`.
  - `0x23cc69289bfa1b7e0c431b329f8fb8773b0f0453ee180485b8576e54edabc2a2`.
  These show USDT flowing from the dispatcher back to `0xe2336...`.

Grizzifi is a fee-charging USDT staking protocol where users approve USDT to the contract and then call `harvestHoney` to deposit funds into a selected plan. The contract charges a configurable platform fee and pays that fee to its owner while tracking user investments and rewards.

The ACT modeling in `root_cause.json` focuses on block height **B = 57478534**, around the dispatcher and orchestrator flows, and explicitly encodes that there is no ACT adversary and no ACT-style success predicate.

## Vulnerability Analysis

### Grizzifi staking behavior

The verified Grizzifi contract at `0x21ab...266b` implements standard ERC20-based staking with a platform fee. The relevant portion of the `harvestHoney` function is:

```solidity
function harvestHoney(uint256 _planId, uint256 _amount, address _referrer) external {
    require(startUNIX > 0, "We are not live yet!");
    require(_planId < totalPlans, "Invalid plan ID");
    require(plans[_planId].isActive, "Plan not active");
    require(_amount >= plans[_planId].minDeposit, "Below minimum");
    require(_amount > 0, "Amount must be > 0");

    // ... registration and referral logic omitted ...

    uint256 feeAmount = (_amount * platformFee) / 10000;
    require(USDT.transferFrom(msg.sender, address(this), _amount), "USDT transfer failed");

    if (feeAmount > 0) {
        require(USDT.transfer(owner, feeAmount), "Fee transfer failed");
    }

    // ... record Investment and accounting ...
}
```

This code matches the on-chain traces in the seed transaction `0x3643...75c1`, where each donor:
- Approves Grizzifi to spend USDT.
- Calls `Grizzifi::harvestHoney`.
- Transfers `_amount` USDT in to Grizzifi.
- Incurs a platform fee that is forwarded to the owner `0xe06d...`.

The behavior is consistent with the documented design and does not expose a reentrancy or accounting bug; Grizzifi is operating according to its own rules.

### BEP20USDT token semantics

The BEP20USDT token at `0x55d398326f99059ff775485246999027b3197955` uses standard BEP20 semantics (compatible with ERC20). The balance-diff tracer outputs for the seed transactions confirm that:
- Token transfers respect balances and allowances.
- There are no unexpected mint or burn operations in the analyzed transactions.

An example from the `balance_diff.json` for seed transaction `0x3643...75c1`:

```json
{
  "token": "0x55d398326f99059ff775485246999027b3197955",
  "holder": "0x21ab8943380b752306abf4d49c203b011a89266b",
  "before": "53135354084490740740745",
  "after": "53243354084490740740745",
  "delta": "108000000000000000000",
  "contract_name": "BEP20USDT"
}
```

This shows Grizzifi’s USDT balance increasing by **108e18** USDT across the donors’ deposits, while the Grizzifi owner’s USDT balance increases by **12e18** USDT as platform fees in the same transaction.

### Helper contracts (dispatcher and orchestrator)

The dispatcher at `0x03ba64...` and orchestrator at `0xed3574...` are unverified, but their disassembly reveals:
- A storage slot at index 0 that stores an address, read via `SLOAD`.
- Entry points that compare `msg.sender` or `tx.origin` against this owner address, enforcing an owner-only gate for core functions such as:
  - The factory-style `create2` path in the dispatcher.
  - The orchestrated interaction path that calls Grizzifi and per-user helper contracts.

In the dispatcher disassembly, the function selector range includes `0xf5eacece` (the selector used by the seed dispatcher transaction), and state initialization sets storage slot 0 to the operator address `0xe2336...`. All observed dispatcher calls in traces are initiated by `0xe2336...`, consistent with this design.

Taken together, there is **no vulnerability** in these helper contracts that allows arbitrary users to trigger their privileged flows; instead, they enforce central control by the operator.

### ACT adversary model

Under the ACT model (permissionless, unprivileged adversary using only public on-chain data and contracts), a valid opportunity must:
- Be realizable by an arbitrary EOA without secret keys or private relationships.
- Use public methods and state (balances, allowances, contract methods).
- Produce a net profit or non-monetary success that a generic adversary can achieve.

The updated ACT modeling in `root_cause.json` explicitly encodes:
- `is_act = false`.
- `act_opportunity.success_predicate.type = "none"`.
- All profit fields (values before, after, delta, fees) set to `"0"`.
- A valuation note stating that any net profit to `0xe2336...` requires owner/ORIGIN-gated helper calls and thus cannot be realized by a generic unprivileged adversary.

No path was found where a third-party EOA, without the `0xe2336...` key, can orchestrate the same flows or extract profit by front-running, back-running, or otherwise manipulating public state.

## Detailed Root Cause Analysis

### Seed transaction 1: orchestrated Grizzifi deposits and platform fees

Seed transaction `0x36438165d701c883fd9a03631ee0cdeec35a138153720006ab59264db7e075c1` (block 57482334) has:
- From: `0xe2336b08a43f87a4ac8de7707ab7333ba4dbaf7c`.
- To: `0xed35746f389177ecd52a16987b2aac74aa0c1128` (orchestrator).
- Value: 0 native BNB.

The Foundry trace (`trace.cast.log`) shows:

```text
0xEd35746F389177eCD52A16987b2aaC74AA0c1128::init(Grizzifi: [0x21ab8943380B752306aBF4D49C203B011A89266B])
  ├─ 0xfD074E6610F645c04950c8afeF4Abfa30A790933::init(Grizzifi: [...], 0x0000000000000000000000000000000000000000)
  │   ├─ BEP20USDT::approve(Grizzifi: [...], 1.157e77)
  │   ├─ Grizzifi::harvestHoney(0, 1e19, 0x0000000000000000000000000000000000000000)
  │   │   ├─ BEP20USDT::transferFrom(0xfD07..., Grizzifi: [...], 1e19)
  │   │   ├─ BEP20USDT::transfer(0xe06d57958dE23e1013567A1b00f0a37C9862DEC6, 1e18)
  │   │   ├─ emit NewInvestment(user: 0xfD07..., planId: 0, amount: 1e19, referrer: 0x0)
  │   │   └─ ...
  ├─ ... repeated pattern for five more donor addresses ...
```

The corresponding balance diffs show:
- Six donors each lose **20e18** USDT (total **120e18** USDT out of donor addresses).
- Grizzifi (`0x21ab...`) gains **108e18** USDT.
- Grizzifi owner (`0xe06d...`) gains **12e18** USDT as platform fees.

Allowance snapshots around this block (`allowances_pre_57482333_post_57482334.json`) confirm that prior to the transaction:
- Donor allowances to Grizzifi are 0.
- After the orchestrator flow, each donor has granted Grizzifi a very large allowance (`2^256 - 1`), and Grizzifi uses `transferFrom` to pull the deposit amounts.
- Donors have **no allowances granted to the dispatcher or orchestrator contracts**.

**Conclusion for seed 1**: This transaction is a centrally orchestrated series of normal Grizzifi deposits by six donors, with Grizzifi collecting deposits and paying platform fees to its owner. There is no direct USDT transfer to the operator `0xe2336...` in this transaction.

### Seed transaction 2: dispatcher distribution of USDT

Seed transaction `0x4302de51c8126e7934da9be1affbde73e5153fe1f9d0200a738a269fe07d22c7` (block 57478534) has:
- From: `0xe2336b08a43f87a4ac8de7707ab7333ba4dbaf7c`.
- To: `0x03ba640c955ebb07520a31ea1ef572c404a3f9ae` (dispatcher).
- Value: 0 native BNB.

The balance-diff tracer shows:

```json
{
  "token": "0x55d398326f99059ff775485246999027b3197955",
  "holder": "0x03ba640c955ebb07520a31ea1ef572c404a3f9ae",
  "before": "5620000000000000000000",
  "after": "5020000000000000000000",
  "delta": "-600000000000000000000",
  "contract_name": "BEP20USDT"
}
```

and a long list of 30 recipient addresses each gaining **20e18** USDT. There is **no** direct USDT balance change for `0xe2336...` in this transaction.

**Conclusion for seed 2**: The dispatcher distributes **600e18** USDT from its own pre-existing USDT balance to 30 recipients (20e18 each). This again is an operator-initiated redistribution of funds already held by the dispatcher, not a permissionless profit opportunity.

### Payout transactions: dispatcher paying back the operator

The related transactions `0x4fc9be48f0a479cda9585ce5e64ba207d43f6524df07535d4be3ff5e297dde54` and `0x23cc69289bfa1b7e0c431b329f8fb8773b0f0453ee180485b8576e54edabc2a2` show the dispatcher paying USDT back to `0xe2336...`.

From `balance_diff_prestate_tracer.json`:

```json
{
  "txhash": "0x4fc9be48f0a479cda9585ce5e64ba207d43f6524df07535d4be3ff5e297dde54",
  "erc20_balance_deltas": [
    {
      "holder": "0x03ba640c955ebb07520a31ea1ef572c404a3f9ae",
      "before": "5020000000000000000000",
      "after": "5010000000000000000000",
      "delta": "-10000000000000000000"
    },
    {
      "holder": "0xe2336b08a43f87a4ac8de7707ab7333ba4dbaf7c",
      "before": "5260000000000000000000",
      "after": "5270000000000000000000",
      "delta": "10000000000000000000"
    }
  ]
}
```

```json
{
  "txhash": "0x23cc69289bfa1b7e0c431b329f8fb8773b0f0453ee180485b8576e54edabc2a2",
  "erc20_balance_deltas": [
    {
      "holder": "0x03ba640c955ebb07520a31ea1ef572c404a3f9ae",
      "before": "5010000000000000000000",
      "after": "0",
      "delta": "-5010000000000000000000"
    },
    {
      "holder": "0xe2336b08a43f87a4ac8de7707ab7333ba4dbaf7c",
      "before": "5270000000000000000000",
      "after": "10280000000000000000000",
      "delta": "5010000000000000000000"
    }
  ]
}
```

Across these two transactions, the dispatcher’s USDT balance decreases by **5020e18** USDT, and `0xe2336...`’s USDT balance increases by **5020e18** USDT.

Both transactions are initiated by `0xe2336...` and call dispatcher methods that, per disassembly, are owner-gated. No approvals from external holders to the dispatcher are involved; the dispatcher already holds the USDT.

**Conclusion**: Dispatcher payouts to `0xe2336...` are fully controlled by the operator and depend on USDT already held by the dispatcher. There is no permissionless adversary path to re-route or steal these funds.

### ACT opportunity modeling

The `act_opportunity` section in `root_cause.json` summarizes the ACT modeling:

- `block_height_B`: `"57478534"` (covering dispatcher and related flows).
- `transaction_sequence_b`: `[]` (no ACT sequence exists).
- `success_predicate.type`: `"none"`.
- Profit fields (`fees_paid_in_reference_asset`, `value_before_in_reference_asset`, `value_after_in_reference_asset`, `value_delta_in_reference_asset`) all set to `"0"`.
- Valuation notes: “No ACT adversary is identified; any net profit to 0xe2336... requires owner/ORIGIN-gated helper calls and cannot be realized by a generic unprivileged adversary.”
- Non-monetary `oracle_name`: `"none"`, with explicit confirmation that no invariant or safety oracle is violated.

This explicitly encodes a **negative ACT result**: there is no end-to-end ACT strategy satisfying the model’s requirements.

## Adversary Flow Analysis

### Stakeholder roles

- **Operator / dispatcher-owner**: `0xe2336...` controls:
  - Dispatcher contract `0x03ba64...`.
  - Orchestrator contract `0xed3574...`.
  These contracts enforce owner checks and are only invoked by `0xe2336...` in the observed transactions.
- **Protocol contract**: Grizzifi staking contract `0x21ab...` with owner `0xe06d...`.
- **Token contract**: BEP20USDT at `0x55d3...97955`.
- **Donors / investors**: a set of EOA addresses that:
  - Hold USDT.
  - Approve Grizzifi to spend their USDT.
  - Call Grizzifi (directly or via helper contracts) to invest.
- **Recipients**: 30 EOA addresses receiving 20e18 USDT each from the dispatcher in seed transaction `0x4302...22c7`.

### Operator-controlled flow

1. **Preparation**:
   - The dispatcher accumulates a significant USDT balance (at least 5620e18 USDT before seed transaction `0x4302...22c7`), via prior operator-controlled flows not central to this ACT analysis.

2. **Dispatcher distribution (seed 2)**:
   - At block 57478534, `0xe2336...` calls dispatcher `0x03ba64...`.
   - The dispatcher transfers **600e18** USDT out, **20e18** USDT each to 30 recipient addresses.
   - The dispatcher’s USDT balance decreases from 5620e18 to 5020e18 USDT.

3. **Grizzifi deposits (seed 1)**:
   - At block 57482334, `0xe2336...` calls orchestrator `0xed3574...`.
   - The orchestrator invokes per-user helper contracts that:
     - Call `BEP20USDT::approve(Grizzifi, 2^256-1)` on behalf of each donor.
     - Call `Grizzifi::harvestHoney` to deposit **10e18** or **20e18** USDT per donor (depending on plan), resulting in:
       - Total donor losses of **120e18** USDT.
       - Grizzifi balance increase of **108e18** USDT.
       - Grizzifi owner `0xe06d...` receiving **12e18** USDT as fees.

4. **Dispatcher payouts to operator (related txs)**:
   - In `0x4fc9...7dde54`, dispatcher USDT decreases by **10e18** while `0xe2336...` gains **10e18**.
   - In `0x23cc...bc2a2`, dispatcher USDT decreases by **5010e18** while `0xe2336...` gains **5010e18**.
   - Combined, `0xe2336...` gains **5020e18** USDT and the dispatcher balance moves toward zero.

5. **Net effect under ACT model**:
   - All core steps (dispatcher distributions, orchestrator calls, dispatcher payouts) are gated on the operator’s owner privileges in unverified helper contracts.
   - Donors’ only public permission is their USDT allowance to Grizzifi, which Grizzifi uses exactly as coded.
   - No public method exists that allows a third-party EOA to cause dispatcher or orchestrator to move funds in their favor.

**Adversary conclusion**: There is no ACT adversary in this incident. The only agent capable of orchestrating the profitable flows is the operator holding the `0xe2336...` private key, acting through owner-gated helper contracts and Grizzifi’s normal API.

## Impact & Losses

From the analyzed transactions and traces:

- **Donor-to-Grizzifi flows** (seed transaction `0x3643...75c1`):
  - Six donor addresses each send **20e18** USDT to Grizzifi (total **120e18** USDT).
  - Grizzifi retains **108e18** USDT in its own balance.
  - Grizzifi owner `0xe06d...` receives **12e18** USDT in platform fees.
- **Dispatcher distributions** (seed transaction `0x4302...22c7`):
  - Dispatcher `0x03ba64...` sends **600e18** USDT out to 30 distinct recipients (20e18 each).
  - Dispatcher’s USDT balance decreases from 5620e18 to 5020e18 USDT.
- **Dispatcher payouts to operator** (related transactions):
  - `0x4fc9...7dde54`: dispatcher to `0xe2336...` of **10e18** USDT.
  - `0x23cc...bc2a2`: dispatcher to `0xe2336...` of **5010e18** USDT.
  - Combined net gain to `0xe2336...`: **5020e18** USDT.

The updated ACT modeling sets:
- `reference_asset = "USDT"`.
- `value_before_in_reference_asset = "0"`.
- `value_after_in_reference_asset = "0"`.
- `value_delta_in_reference_asset = "0"`.
for the ACT adversary, because no ACT adversary exists. All net gains accrue to an operator that is **not** an ACT adversary but a privileged stakeholder.

There is no evidence of:
- Protocol-level invariant violation.
- Unauthorized minting or burning of USDT.
- Reentrancy or overflow exploits.

The economic impact under the ACT model is therefore **zero** for any permissionless adversary, and the observed profits are operator-controlled.

## References

- **Primary root cause artifact**:
  - `root_cause.json` (this report reflects all its content).
- **Analyzer state and reasoning**:
  - `artifacts/root_cause/root_cause_analyzer/iter_4/current_analysis_result.json`.
- **Seed transactions and traces**:
  - `artifacts/root_cause/seed/56/0x36438165d701c883fd9a03631ee0cdeec35a138153720006ab59264db7e075c1/metadata.json`.
  - `artifacts/root_cause/seed/56/0x36438165d701c883fd9a03631ee0cdeec35a138153720006ab59264db7e075c1/trace.cast.log`.
  - `artifacts/root_cause/seed/56/0x36438165d701c883fd9a03631ee0cdeec35a138153720006ab59264db7e075c1/balance_diff.json`.
  - `artifacts/root_cause/seed/56/0x4302de51c8126e7934da9be1affbde73e5153fe1f9d0200a738a269fe07d22c7/metadata.json`.
  - `artifacts/root_cause/seed/56/0x4302de51c8126e7934da9be1affbde73e5153fe1f9d0200a738a269fe07d22c7/trace.cast.log`.
  - `artifacts/root_cause/seed/56/0x4302de51c8126e7934da9be1affbde73e5153fe1f9d0200a738a269fe07d22c7/balance_diff.json`.
- **Payout transactions**:
  - `artifacts/root_cause/data_collector/iter_3/tx/56/0x4fc9be48f0a479cda9585ce5e64ba207d43f6524df07535d4be3ff5e297dde54/balance_diff_prestate_tracer.json`.
  - `artifacts/root_cause/data_collector/iter_3/tx/56/0x23cc69289bfa1b7e0c431b329f8fb8773b0f0453ee180485b8576e54edabc2a2/balance_diff_prestate_tracer.json`.
- **Allowance snapshots**:
  - `artifacts/root_cause/data_collector/iter_2/storage/56/0x55d398326f99059ff775485246999027b3197955/allowances_pre_57482333_post_57482334.json`.
- **Contract sources**:
  - Grizzifi staking contract source: `artifacts/root_cause/data_collector/iter_1/contract/56/0x21ab8943380b752306abf4d49c203b011a89266b/source/src/Contract.sol`.
  - BEP20USDT token source: `artifacts/root_cause/seed/56/0x55d398326f99059ff775485246999027b3197955/src/Contract.sol`.
- **Helper contract disassembly**:
  - Dispatcher `0x03ba640c955ebb07520a31ea1ef572c404a3f9ae`: `artifacts/root_cause/data_collector/iter_1/contract/56/0x03ba640c955ebb07520a31ea1ef572c404a3f9ae/disassemble.txt`.
  - Orchestrator `0xed35746f389177ecd52a16987b2aac74aa0c1128`: `artifacts/root_cause/data_collector/iter_1/contract/56/0xed35746f389177ecd52a16987b2aac74aa0c1128/disassemble.txt`.

