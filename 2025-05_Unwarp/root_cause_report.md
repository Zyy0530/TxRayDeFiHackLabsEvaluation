# MPRO Staking Proxy unwrapWETH Flash-Loan Exploit (Base)

## Incident Overview & TL;DR

- **Protocol:** MPRO Double Reward Auto Stake on Base (chainid 8453)
- **Primary victim system:** MPRO staking proxy `0x8bEfC1d90d03011a7d0b35B3a00eC50f8E014802` fronting an implementation `MPRORewardStake` at `0xd971fD39D9714d5eb1B54B931790170A0630f131`.
- **Exploit style:** ACT-style single-transaction exploit by an unprivileged adversary using a flash loan and a protocol bug.
- **Root-cause category:** `protocol_bug` (missing access control on a value-bearing withdrawal function).

In a single adversary-crafted transaction on Base, the attacker uses a Balancer Vault WETH flash loan to temporarily inflate the MPRO staking proxy's WETH balance and then calls a publicly callable `unwrapWETH(uint256,address)` function on the proxy. Because the implementation behind the proxy has no access control on this function and forwards ETH to an arbitrary recipient, the call converts both the pre-existing reward WETH pot and the flash-loaned WETH into native ETH, sends that ETH to an attacker-controlled helper contract, repays the flash loan, and leaves the residual ETH as attacker profit.

The underlying MPRORewardStake implementation exposes `unwrapWETH(uint256,address)` as an externally callable function that (a) checks only that the requested amount is positive and that the contract's WETH balance is at least that amount, (b) calls `WETH9.withdraw(amount)`, and (c) transfers the resulting ETH to an arbitrary recipient address. With the staking proxy holding a shared reward pot in WETH, any unprivileged caller with temporary WETH liquidity (via a flash loan) can drain that pot to an arbitrary address.

## ACT Opportunity and Exploit Predicate

### Pre-state \(sigma_B) and block

- **Block height B:** Base block `30210274`.
- **Pre-state sigma_B definition:**
  - The MPRO staking proxy `0x8bEfC1d90d03011a7d0b35B3a00eC50f8E014802` is configured as a `TransparentUpgradeableProxy` delegating to `MPRORewardStake` at `0xd971fD39D9714d5eb1B54B931790170A0630f131`.
  - The proxy holds an existing **rewardToken (WETH) balance of `3.981326901636573675` WETH**.
  - WETH9 is deployed at `0x4200000000000000000000000000000000000006` on Base with standard `deposit`/`withdraw` semantics.
  - Balancer Vault is deployed at `0xBA12222222228d8Ba445958a75a0704d566BF2C8` and exposes permissionless flash loans in WETH.
  - The adversary controls:
    - EOA `0x5CC162c556092fE1d993b95D1b9E9CE58a11dBC9`, and
    - Helper contract `0x0c6A8c285d696d4D9b8dD4079a72a6460A4dA05F`.

This pre-state is reconstructed from seed metadata, traces, prestate balance diffs, and contract source/decompilation.

### Transaction sequence b

There is a single adversary-crafted transaction `b` that realizes the exploit from sigma_B:

- **Tx:** `0xac6f716c57bbb1a4c1e92f0a9531019ea2ecfcaea67794bbd27115d400ae9b41`
- **Chain:** Base (8453)
- **Type:** Standard EIP-1559 transaction
- **From:** EOA `0x5CC162c556092fE1d993b95D1b9E9CE58a11dBC9`
- **To:** Helper contract `0x0c6A8c285d696d4D9b8dD4079a72a6460A4dA05F`
- **High-level behavior:**
  - Requests a Balancer Vault flash loan of `100852657473363426325` WETH.
  - Sends the borrowed WETH to the MPRO staking proxy.
  - Calls `unwrapWETH(104833984375000000000, 0x0c6A8c285d696d4D9b8dD4079a72a6460A4dA05F)` via the proxy (delegatecall into `MPRORewardStake`).
  - Unwraps a total of `104.833984375` WETH (which includes the pre-existing `3.981326901636573675` WETH reward pot) into ETH.
  - Uses `100852657473363426325` wei of ETH to re-mint WETH and repay the flash loan.
  - Forwards the remaining ETH back to the attacker EOA as profit.

**Snippet – Seed transaction trace for exploit tx 0xac6f… (cast run -vvvvv)**

```text
0x0c6A8c285d696d4D9b8dD4079a72a6460A4dA05F::flashLoanCallback(...)
  ├─ BalancerVault.flashLoan(..., WETH9, 100852657473363426325, ...)
  │   ├─ WETH9.transfer(0x8bEfC1d90d03011a7d0b35B3a00eC50f8E014802, 100852657473363426325)
  │   └─ ...
  ├─ 0x8bEfC1d90d03011a7d0b35B3a00eC50f8E014802::unwrapWETH(104833984375000000000, 0x0c6A8c2...)
  │   ├─ 0xd971fD39D9714d5eb1B54B931790170A0630f131::unwrapWETH(104833984375000000000, 0x0c6A8c2...) [delegatecall]
  │   │   ├─ WETH9.balanceOf(0x8bEfC1d90d03011a7d0b35B3a00eC50f8E014802)
  │   │   ├─ WETH9.withdraw(104833984375000000000)
  │   │   └─ ETH sent to 0x0c6A8c2...
  ├─ WETH9.deposit{value: 100852657473363426325}()
  ├─ WETH9.transfer(0xBA12222222228d8Ba445958a75a0704d566BF2C8, 100852657473363426325)
  └─ ETH residual sent to 0x5CC162c556092fE1d993b95D1b9E9CE58a11dBC9
```

### Exploit predicate and profit

- **Predicate type:** `profit`
- **Reference asset:** ETH
- **Adversary address:** `0x5CC162c556092fE1d993b95D1b9E9CE58a11dBC9`
- **Adversary profit:** `3.980180099247068721` ETH (3,980,180,099,247,068,721 wei)
- **System-level ETH drained from WETH9:** `3.981326901636573675` ETH (3,981,326,901,636,573,675 wei)

The profit computation is grounded in the prestate-tracer balance diff for the exploit tx.

**Snippet – Native balance deltas for exploit tx (prestate tracer)**

```json
{
  "native_balance_deltas": [
    {
      "address": "0x4200000000000000000000000000000000000006",
      "delta_wei": "-3981326901636573675"
    },
    {
      "address": "0x5cc162c556092fe1d993b95d1b9e9ce58a11dbc9",
      "delta_wei": "3980180099247068721"
    },
    {
      "address": "0x4200000000000000000000000000000000000011",
      "delta_wei": "1146620000000000"
    },
    {
      "address": "0x420000000000000000000000000000000000001a",
      "delta_wei": "17596017272"
    },
    {
      "address": "0x4200000000000000000000000000000000000019",
      "delta_wei": "164793487682"
    }
  ]
}
```

The attacker EOA gains `3.980180099247068721` ETH, WETH9's ETH backing decreases by `3.981326901636573675` ETH, and the small difference is accounted for by system fee-collector addresses.

## Key Background

The following context is needed to understand the incident:

1. **MPRO staking architecture on Base**
   - The staking system uses a `TransparentUpgradeableProxy` at `0x8bEfC1d90d03011a7d0b35B3a00eC50f8E014802` that delegates to `MPRORewardStake` at `0xd971fD39D9714d5eb1B54B931790170A0630f131`.
   - The implementation manages staking rewards in WETH (WETH9). Over time, admin operations and user staking activity accumulate a **shared WETH reward pot on the proxy**.

2. **External dependencies: WETH9 and Balancer Vault**
   - WETH9 at `0x4200000000000000000000000000000000000006` is a standard wrapped-ETH contract with `deposit()` and `withdraw(uint256)` that burns WETH and releases the same amount of native ETH to the caller.
   - Balancer Vault at `0xBA12222222228d8Ba445958a75a0704d566BF2C8` provides permissionless flash loans in WETH on Base, allowing an unprivileged contract to borrow and repay WETH within a single transaction.

These components together make it possible for an attacker to temporarily swell the proxy's WETH balance and then unwrap that balance into ETH.

## Vulnerability & Root Cause Analysis

### Vulnerability summary

The core vulnerability is that **`MPRORewardStake` exposes a publicly callable `unwrapWETH(uint256,address)` function that performs only a balance check and then unconditionally unwraps WETH and sends the resulting ETH to an arbitrary recipient address.** There is no access control tying this operation to stakers, admins, or protocol-controlled recipients.

### Detailed root cause

The decompiled MPRORewardStake implementation at `0xd971fD39D9714d5eb1B54B931790170A0630f131` contains the following `unwrapWETH` logic:

**Snippet – Decompiled `unwrapWETH` implementation (MPRORewardStake)**

```solidity
function unwrapWETH(uint256 amount, address recipient) public returns (bool) {
    require(recipient == address(recipient));
    require(amount > 0);
    require(address(recipient) != address(0));
    require(address(rewardToken) != address(0));

    // Check contract's WETH balance
    uint256 bal = rewardToken.balanceOf(address(this));
    require(bal >= amount, "MPRORewardStake: Insufficient WETH balance");

    // Unwrap WETH to ETH
    rewardToken.withdraw(amount); // WETH9.withdraw(amount)

    // Send ETH to arbitrary recipient
    (bool success, ) = recipient.transfer(amount);
    require(success, "MPRORewardStake: ETH transfer failed");

    return true;
}
```

Key properties:

- **Externally callable:** There is no `onlyOwner`, `onlyStaker`, or similar modifier; any caller can invoke `unwrapWETH` through the proxy.
- **Balance-based gating only:** The function checks only that `rewardToken.balanceOf(address(this)) >= amount`. It does **not** distinguish between long-term staking rewards and transient balances (such as flash-loaned WETH).
- **Arbitrary recipient:** The ETH is sent to a caller-specified `recipient` address with no restriction that it be the proxy owner, a staking rewards contract, or any other protocol-controlled account.

As a result:

- Any unprivileged caller can cause the proxy to unwrap **all** WETH currently held by the contract, as long as the requested `amount` is less than or equal to the current WETH balance.
- Because the contract's WETH balance is the sum of the pre-existing reward pot and any temporary inflows, a flash loan can be used to pass the balance check for a large `amount` that **includes both the reward pot and the flash-loaned WETH**.
- The `withdraw` call converts this entire amount to ETH; the attacker can then repay the flash loan out of the same ETH and keep the residual as profit.
- The staking reward pot is not segregated or reserved; it is simply part of `rewardToken.balanceOf(address(this))` and is therefore fully exposed to this mechanism.

### Vulnerable components

- **MPRO staking proxy** `0x8bEfC1d90d03011a7d0b35B3a00eC50f8E014802` – a `TransparentUpgradeableProxy` front-end that routes calls (including `unwrapWETH`) to the implementation.
- **MPRORewardStake implementation** `0xd971fD39D9714d5eb1B54B931790170A0630f131` – specifically the `unwrapWETH(uint256,address)` function.

### Exploit preconditions

For the exploit to succeed, all of the following must hold:

1. **Positive WETH reward balance on the proxy** – Prior to block 30210274, the staking proxy must hold a positive `rewardToken` balance in WETH. In this incident, the relevant pot is `3.981326901636573675` WETH.
2. **Vulnerable implementation active** – The proxy's implementation must be `MPRORewardStake` at `0xd971fD39D9714d5eb1B54B931790170A0630f131` with the vulnerable `unwrapWETH` logic.
3. **Access to temporary WETH liquidity** – The attacker must have access to a flash loan or equivalent mechanism to temporarily add enough WETH to the proxy so that `rewardToken.balanceOf(address(this))` is at least the desired `amount` for unwrap.
4. **Publicly callable unwrapWETH** – The `unwrapWETH(uint256,address)` function must be callable by arbitrary addresses without role checks, and the recipient parameter must be unconstrained.

### Security principles violated

- **Missing access control on a withdrawal primitive:** A function that moves value out of the protocol (from WETH balance to external ETH recipient) is callable by anyone.
- **Failure to segregate reward balances from transient balances:** The implementation treats total WETH balance as withdrawable rewards, even when part of that balance is flash-loaned capital controlled by an attacker.
- **Implicit trust in raw token balances:** The design assumes that `rewardToken.balanceOf(address(this))` reflects legitimate, protocol-owned reward funds, which is not true under flash-loan adversaries.

## Adversary Flow Analysis

### Adversary strategy summary

The adversary executes a **single transaction** that:

1. Uses a Balancer Vault flash loan to borrow a large amount of WETH.
2. Transfers the borrowed WETH to the MPRO staking proxy to inflate its WETH balance.
3. Calls the vulnerable `unwrapWETH(uint256,address)` function on the proxy with an `amount` that includes both the existing reward pot and the flash-loaned WETH.
4. Receives the ETH produced by `WETH9.withdraw(amount)` at a helper contract.
5. Repays the flash loan in WETH re-minted from ETH.
6. Keeps the residual ETH as profit, funded entirely by the destruction of the staking proxy's WETH reward pot.

### Adversary-related accounts

**Adversary cluster:**

- **EOA 0x5CC162c556092fE1d993b95D1b9E9CE58a11dBC9**
  - Sender of the exploit transaction `0xac6f716c…`.
  - Final recipient of the residual ETH profit in the balance diffs.
- **Helper contract 0x0c6A8c285d696d4D9b8dD4079a72a6460A4dA05F**
  - Deployed by the attacker EOA.
  - Receives the Balancer flash loan.
  - Forwards WETH to the staking proxy and invokes `unwrapWETH` via the proxy.
  - Routes the residual ETH back to the attacker EOA.

**Victim-related contracts:**

- **MPRO staking proxy** – `0x8bEfC1d90d03011a7d0b35B3a00eC50f8E014802`
- **MPRORewardStake implementation** – `0xd971fD39D9714d5eb1B54B931790170A0630f131`
- **WETH9** – `0x4200000000000000000000000000000000000006`
- **Balancer Vault** – `0xBA12222222228d8Ba445958a75a0704d566BF2C8`

### Lifecycle stages

#### 1. Reward pot accumulation on the staking proxy

- Over prior blocks, admin address `0x29eb782b8707227fac7620ee7b3ab8c6a34f074b` and user activity configure the staking system and fund the reward pot.
- By sigma_B (just before block 30210274), the staking proxy holds exactly **`3.981326901636573675` WETH** as `rewardToken`.
- This amount corresponds to the difference between the total amount unwrapped (`104.833984375` WETH) and the flash-loaned amount (`100.852657473363426325` WETH).

This pre-existing reward pot becomes the funding source for the attacker's profit when combined with the flash-loaned WETH.

#### 2. Adversary helper deployment and setup

- **Tx:** `0x3acfcb1d8fef75bdaf88c9f8a49043937d5ce664631f9b5e1e5f0880b6cc2a77`
- **Block:** `26181727` on Base
- **From:** `0x5CC162c556092fE1d993b95D1b9E9CE58a11dBC9`
- **To:** (contract creation)
- **Outcome:** Deploys the helper contract `0x0c6A8c285d696d4D9b8dD4079a72a6460A4dA05F`, which exposes methods that orchestrate the Balancer flash-loan and unwrapWETH call path.

This establishes a reusable entry point the attacker later uses in the exploit transaction.

#### 3. Exploit execution via flash loan and unwrapWETH

- **Tx:** `0xac6f716c57bbb1a4c1e92f0a9531019ea2ecfcaea67794bbd27115d400ae9b41`
- **Block:** `30210274`
- **From:** `0x5CC162c556092fE1d993b95D1b9E9CE58a11dBC9`
- **To:** `0x0c6A8c285d696d4D9b8dD4079a72a6460A4dA05F`

Flow:

1. Helper calls Balancer Vault to flash-loan `100852657473363426325` WETH (token `0x4200…0006`).
2. Balancer Vault transfers the borrowed WETH to the helper, which in turn transfers **the same amount of WETH** to the MPRO staking proxy.
3. The helper calls the proxy's `unwrapWETH(uint256,address)` function with `amount = 104833984375000000000` and `recipient = 0x0c6A8c2…`.
4. The proxy delegates to `MPRORewardStake.unwrapWETH`, which:
   - Checks that the contract's WETH balance is at least `104.833984375` WETH (which holds because the balance is the sum of the pre-existing `3.981326901636573675` WETH reward pot and the `100.852657473363426325` WETH flash loan),
   - Calls `WETH9.withdraw(104833984375000000000)`, burning that much WETH and causing `104.833984375` ETH to be sent to the proxy,
   - Forwards the ETH to the helper contract.
5. The helper re-deposits `100852657473363426325` wei of ETH into WETH via `WETH9.deposit` and transfers exactly that amount of WETH back to Balancer Vault, fully repaying the flash loan.
6. The **remaining `3.981326901636573675` ETH** is forwarded to the attacker EOA, which realizes a net profit of `3.980180099247068721` ETH after protocol-level fees.

#### 4. Post-incident behavior change (patched implementation)

After the exploit, the proxy is upgraded to a new implementation at `0x8127D4532D0DA08C2DB6c36e18160d8343265b93`.

- **Tx:** `0xf91d6c36def77da30431d6648e77fdd2c17ef51d7da9fdfcc95efdae0291083a`
- **From:** EOA `0xFF8DaC673883f2BC40454c940f5f07DEe6842424`
- **To:** MPRO staking proxy `0x8bEfC1d90d03011a7d0b35B3a00eC50f8E014802`
- **Call:** `unwrapWETH(1000, 0xFF8DaC673883f2BC40454c940f5f07DEe6842424)` via the proxy.

**Snippet – Post-incident unwrapWETH attempt (debug_traceTransaction callTracer)**

```json
{
  "from": "0xff8dac673883f2bc40454c940f5f07dee6842424",
  "to": "0x8befc1d90d03011a7d0b35b3a00ec50f8e014802",
  "input": "0xe16d9ce5...000003e8...",
  "error": "execution reverted",
  "revertReason": "MPRORewardStake: Amount must be 0",
  "calls": [
    {
      "type": "DELEGATECALL",
      "to": "0x8127d4532d0da08c2db6c36e18160d8343265b93",
      "revertReason": "MPRORewardStake: Amount must be 0"
    }
  ]
}
```

This shows that in the patched implementation, `unwrapWETH` reverts when called with a nonzero amount, effectively disabling the vulnerable withdrawal path that was abused in the incident.

## Impact & Losses

### System-level loss

- **Token:** ETH (backing WETH9)
- **Total amount removed from WETH9's ETH balance:** `3.981326901636573675` ETH

During the exploit transaction:

- The MPRO staking proxy's entire WETH reward pot of `3.981326901636573675` WETH is consumed as part of the `104.833984375` WETH unwrapped via `unwrapWETH`.
- `WETH9.withdraw` converts this WETH into ETH, which is then split between repaying the flash loan and the attacker profit.
- The flash-loaned principal is fully repaid in WETH, so Balancer Vault's WETH holdings are restored; the net funding for the attack comes from the WETH pot backing MPRO staking rewards.

### Adversary profit

- **Attacker EOA:** `0x5CC162c556092fE1d993b95D1b9E9CE58a11dBC9`
- **Net native balance increase:** `3.980180099247068721` ETH

The difference between WETH9's ETH loss and the attacker's ETH gain is paid to Base system fee-collector addresses and does not represent further protocol-user loss.

### Scope of this report

This report focuses on **protocol-level impact**:

- The destruction of the shared MPRO staking reward pot held in WETH on the proxy.
- The attacker's ETH profit realized from that pot.

It **does not attempt** to apportion the drained amount across individual staker wallets or external protocols; that per-staker attribution is out of scope for this ACT-focused root-cause report.

## All Relevant Transactions

- **Exploit transaction (attacker-crafted):**
  - Chain: Base (8453)
  - Tx: `0xac6f716c57bbb1a4c1e92f0a9531019ea2ecfcaea67794bbd27115d400ae9b41`
- **Related transaction – helper deployment:**
  - Chain: Base (8453)
  - Tx: `0x3acfcb1d8fef75bdaf88c9f8a49043937d5ce664631f9b5e1e5f0880b6cc2a77`
- **Related transaction – post-incident unwrap attempt (patched revert):**
  - Chain: Base (8453)
  - Tx: `0xf91d6c36def77da30431d6648e77fdd2c17ef51d7da9fdfcc95efdae0291083a`

## References

- **Exploit transaction metadata and trace** – Seed metadata and full call trace for Base tx `0xac6f716c57bbb1a4c1e92f0a9531019ea2ecfcaea67794bbd27115d400ae9b41` (cast run with verbose call tree).
- **Prestate native balance diff** – Prestate-tracer native balance deltas for the exploit transaction, used to quantify WETH9's ETH loss and the attacker's ETH profit.
- **MPRORewardStake implementation source/decompilation** – Source for `MPRODoubleRewardAutoStake` and decompiled `MPRORewardStake` at `0xd971fD39D9714d5eb1B54B931790170A0630f131`, including the `unwrapWETH(uint256,address)` logic.
- **Post-incident unwrap revert trace** – Debug-trace callTracer output for Base tx `0xf91d6c36def77da30431d6648e77fdd2c17ef51d7da9fdfcc95efdae0291083a`, demonstrating the patched implementation's `Amount must be 0` revert.

