BNB Chain USDC Infinite-Approval Drain via MulticallWithETH
===========================================================

**Incident Overview TL;DR**

On BNB Chain (chainid 56), victim EOA `0xfb0De204791110Caa5535aeDf4E71dF5bA68A581` granted an infinite USDC allowance to the generic router `MulticallWithETH` at `0x3DA0F00d5c4E544924bC7282E18497C4A4c92046`. The victim later interacted with infrastructure that routed USDC operations through this router, leaving a large USDC balance and the infinite approval in place. Adversary EOA `0x726fb298168c89d5dce9a578668ab156c7e7be67` then deployed a short-lived helper contract `0x756D614E3d277BAea260f64CC2Ab9a3aC89877d3` whose constructor used `MulticallWithETH::aggregate` and `USDC.transferFrom` to drain `10536885633853077370507` USDC units from the victim to the adversary in a single transaction (`0x6da7be6edf3176c7c4b15064937ee7148031f92a4b72043ae80a2b3403ab6302`).

The root cause is an ACT opportunity created by a user-level infinite approval from the victim to a shared Multicall router, combined with unrestricted `MulticallWithETH` semantics and standard USDC `transferFrom` logic. Once the victim left funds in the approved account, any searcher observing the state could deterministically construct a transaction equivalent to the observed drain and realize the same profit.

**Key Background**

- USDC on BNB Chain is implemented via a TransparentUpgradeableProxy at `0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d` that delegates to `BEP20TokenImplementation` in `Contract.sol`. This implementation provides standard ERC20-style `approve`, `allowance`, `balanceOf`, and `transferFrom` behavior.
- `MulticallWithETH` at `0x3DA0F00d5c4E544924bC7282E18497C4A4c92046` is a generic router that exposes an `aggregate(Call[] calls)` function. For each `Call`, it forwards calldata and per-call value to the specified target without access control, enforcing only that the sum of `value` fields does not exceed `msg.value`.
- The victim EOA `0xfb0De204791110Caa5535aeDf4E71dF5bA68A581` interacts with DeFi infrastructure that wraps USDC operations through `MulticallWithETH`, including an infinite-approval transaction and subsequent activity that leaves a large USDC balance and allowance in place at the USDC proxy.
- The adversary EOA `0x726fb298168c89d5dce9a578668ab156c7e7be67` is an unprivileged user account on BNB Chain. It funds itself with BNB and deploys helper contract `0x756D614E3d277BAea260f64CC2Ab9a3aC89877d3` specifically to execute a constructor-time drain against the victim’s USDC allowance via `MulticallWithETH`.

The relevant contract semantics are supported by verified source code:

```solidity
// USDC BEP20TokenImplementation (excerpt) – standard ERC20 allowance/transferFrom
interface IBEP20 {
    function allowance(address _owner, address spender) external view returns (uint256);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}
```

```solidity
// MulticallWithETH (excerpt) – unrestricted aggregate helper
contract MulticallWithETH {
    struct Call {
        address target;
        bytes callData;
        uint256 value;
        bool allowFailure;
    }

    function aggregate(Call[] calldata calls) external payable returns (Result[] memory returnData) {
        uint256 length = calls.length;
        returnData = new Result[](length);
        uint256 totalSent;

        for (uint256 i = 0; i < length; i++) {
            totalSent += calls[i].value;
            (bool success, bytes memory ret) =
                calls[i].target.call{value: calls[i].value}(calls[i].callData);
            // no caller-based access control
            returnData[i] = Result(success, ret);
        }

        require(totalSent <= msg.value, "Insufficient msg.value");
    }
}
```

These implementations ensure that once an EOA grants a large allowance to `MulticallWithETH`, any call to `aggregate` that encodes a valid `USDC.transferFrom` with sufficient allowance and balance will succeed, regardless of who submits the transaction.

**Vulnerability Analysis**

The vulnerability is not a protocol-level bug in USDC or `MulticallWithETH`; both behave as designed. The failure arises from an operator-level configuration that created a reusable ACT opportunity:

- The victim EOA configured an effectively infinite USDC allowance to a shared router (`MulticallWithETH`) rather than a narrowly scoped contract controlled by the victim.
- The router’s `aggregate` function is deliberately permissionless and allows arbitrary sequences of external calls, including `USDC.transferFrom`, on behalf of any approved owner.
- The USDC implementation honors allowances set via `approve` and performs `transferFrom` solely based on balance and allowance checks, without additional restrictions tied to the identity of `msg.sender`.

This combination violates least-privilege and isolation principles for user funds. Once the infinite approval was in place and the victim’s USDC balance remained positive at the proxy, the system exposed a standing opportunity for any searcher to use the victim’s allowance through `MulticallWithETH` and drain the entire balance into an address they control.

**Detailed Root Cause Analysis**

The ACT opportunity can be described step by step:

1. **Standard USDC semantics via proxy.**  
   `BEP20TokenImplementation` in `Contract.sol` implements ERC20-style `approve`, `allowance`, and `transferFrom`. The USDC proxy at `0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d` is a TransparentUpgradeableProxy that forwards calls to this implementation without adding token-specific restrictions.

2. **Unrestricted Multicall router.**  
   `MulticallWithETH` at `0x3DA0F00d5c4E544924bC7282E18497C4A4c92046` exposes `aggregate(Call[] calls)` and forwards calldata and value to arbitrary targets. There is no sender-based access control; any EOA can invoke `aggregate` as long as the per-call value sum does not exceed `msg.value`. This makes it a generic router for composing arbitrary contract calls.

3. **Victim infinite approval.**  
   Approval history for owner `0xfb0De204791110Caa5535aeDf4E71dF5bA68A581` and spender `0x3DA0F00d5c4E544924bC7282E18497C4A4c92046` in `approval_transactions_with_receipts.json` shows that transaction `0xfb48fade581600398744b868976a6931611e1de4f480cb37e0ac8831e06841ab` calls `USDC.approve(0x3DA0…2046, max_uint256)` from the victim EOA to the USDC proxy. The decoded `Approval` event records an allowance value equal to `uint256.max`. Subsequent logs in `approval_logs_page1.json` confirm that this infinite allowance remains in effect at later blocks and is used in transaction `0xad37d3e77e930cb233a5dd3183116157182f6237d05937b4d634fff233cc7b77` when the victim interacts with infrastructure via `MulticallWithETH`.

4. **Pre-drain state (σ_B).**  
   Immediately before block `55371343`, which contains the attacker constructor transaction `0x6da7be6e…6302`, the public EVM state on BNB Chain satisfies:
   - Victim EOA `0xfb0D…A581` holds `10536885633853077370507` USDC units at the USDC proxy.
   - `allowance(owner=0xfb0D…A581, spender=0x3DA0…2046)` equals `uint256.max` due to the prior infinite-approval transaction.
   - `MulticallWithETH` and the USDC implementation code match the verified sources above.

5. **Constructor-time exploit via MulticallWithETH.**  
   Seed `trace.cast.log` for attacker transaction `0x6da7be6e…6302` shows that adversary EOA `0x726f…be67` deploys helper contract `0x756D…77d3`. During its constructor:

   ```text
   // Seed transaction trace (cast run -vvvvv) for tx 0x6da7be6e…6302
   BEP20TokenImplementation::allowance(0xfb0D…, MulticallWithETH [0x3DA0…2046]) → 115792089237316195423570985008687907853269984665640564024757584007913129639935
   BEP20TokenImplementation::balanceOf(0xfb0D…) → 10536885633853077370507
   MulticallWithETH::aggregate([Call({ target: USDC proxy 0x8AC76…, callData: transferFrom(from=0xfb0D…, to=0x726f…, amount=10536885633853077370507), value: 0, allowFailure: true })])
     └─ BEP20TokenImplementation::transferFrom(0xfb0D…, 0x726f…, 10536885633853077370507)
          emit Transfer(from: 0xfb0D…, to: 0x726f…, value: 10536885633853077370507)
          emit Approval(owner: 0xfb0D…, spender: MulticallWithETH [0x3DA0…2046], value: remaining_allowance)
   ```

   The helper constructor first performs static calls via the USDC proxy to read `allowance(owner=0xfb0D…, spender=0x3DA0…2046)` (returning `uint256.max`) and `balanceOf(0xfb0D…)` (returning `10536885633853077370507`). It then calls `MulticallWithETH::aggregate` with a single `Call` targeting the USDC proxy and calldata encoding `transferFrom(from=0xfb0D…, to=0x726f…be67, amount=10536885633853077370507)`. The USDC proxy delegates to `BEP20TokenImplementation::transferFrom`, which emits the corresponding `Transfer` and `Approval` events.

6. **Balance-diff confirmation.**  
   `balance_diff.json` for transaction `0x6da7be6e…6302` on chainid 56 records:

   ```json
   {
     "erc20_balance_deltas": [
       {
         "token": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
         "holder": "0xfb0de204791110caa5535aedf4e71df5ba68a581",
         "before": "10536885633853077370507",
         "after": "0",
         "delta": "-10536885633853077370507"
       },
       {
         "token": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
         "holder": "0x726fb298168c89d5dce9a578668ab156c7e7be67",
         "before": "0",
         "after": "10536885633853077370507",
         "delta": "10536885633853077370507"
       }
     ]
   }
   ```

   This confirms that the victim’s USDC balance drops to zero and the adversary’s balance increases by the same amount, with no intermediate holders.

7. **Deterministic ACT opportunity.**  
   Because `MulticallWithETH` imposes no sender-based access control and only uses public calldata, and because the victim pre-established an infinite allowance to this router while holding a large USDC balance at the approved address, any EOA with sufficient BNB for gas and the same calldata submitted to the public mempool at that block height would achieve the same `USDC.transferFrom` drain. The observed attacker transaction is one concrete instantiation of this strategy, demonstrating that the system-level configuration formed a deterministic ACT opportunity.

**Adversary Flow Analysis**

The adversary-related accounts and lifecycle are:

- **Adversary EOA:** `0x726fb298168c89d5dce9a578668ab156c7e7be67` (BNB Chain, chainid 56). This address is the sender of attacker constructor transaction `0x6da7be6e…6302`, deploys helper contract `0x756D…77d3`, and receives the drained USDC via `USDC.transferFrom`.
- **Helper contract:** `0x756D614E3d277BAea260f64CC2Ab9a3aC89877d3` (BNB Chain, chainid 56). Deployed in transaction `0x6da7be6e…6302`; its constructor reads the victim’s allowance and balance and then uses `MulticallWithETH::aggregate` to execute `USDC.transferFrom`, draining victim USDC into the adversary EOA.
- **Victim EOA:** `0xfb0De204791110Caa5535aeDf4E71dF5bA68A581` (BNB Chain, chainid 56). This address is the owner of the drained USDC balance and the origin of the infinite approval to `MulticallWithETH`.

The lifecycle stages are:

1. **Victim infinite approval configuration.**  
   - Transaction: `0xfb48fade581600398744b868976a6931611e1de4f480cb37e0ac8831e06841ab` (BNB Chain, block `55370679`).  
   - Mechanism: `USDC.approve` from the victim EOA to the USDC proxy, setting `allowance(owner=victim, spender=MulticallWithETH)` to `uint256.max`.  
   - Evidence: `approval_transactions_with_receipts.json` (decoded `Approval` event) and `approval_logs_page1.json` (Etherscan log API output).

2. **Victim usage of MulticallWithETH with residual allowance.**  
   - Transaction: `0xad37d3e77e930cb233a5dd3183116157182f6237d05937b4d634fff233cc7b77` (BNB Chain, block `55370684`).  
   - Mechanism: victim interacts with infrastructure via `MulticallWithETH`, using the existing allowance but leaving a significant residual USDC balance and the infinite approval in place.  
   - Evidence: additional `Approval` logs for the victim–router pair in `approval_logs_page1.json`, confirming that the allowance remains very large after this activity.

3. **Adversary helper deployment and USDC drain.**  
   - Transaction: `0x6da7be6edf3176c7c4b15064937ee7148031f92a4b72043ae80a2b3403ab6302` (BNB Chain, block `55371343`).  
   - Mechanism: adversary EOA deploys helper contract whose constructor uses `MulticallWithETH::aggregate` to call `USDC.transferFrom(from=victim, to=adversary, amount=10536885633853077370507)`.  
   - Evidence: `trace.cast.log` (constructor call stack and events) and `balance_diff.json` (USDC balance deltas for victim and adversary).

These stages form a coherent adversary strategy: observe a victim with an infinite allowance and significant balance, then craft a minimal constructor-time transaction that atomically realizes the entire opportunity.

**Impact & Losses**

- **Token drained:** USDC (BEP20 on BNB Chain, proxy `0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d`).  
- **Total amount drained:** `10536885633853077370507` USDC units.  
- **From:** victim EOA `0xfb0De204791110Caa5535aeDf4E71dF5bA68A581`.  
- **To:** adversary EOA `0x726fb298168c89d5dce9a578668ab156c7e7be67`.  
- **Mechanism:** single constructor-time transaction `0x6da7be6e…6302` using `MulticallWithETH::aggregate` and `USDC.transferFrom` to move the victim’s entire remaining USDC balance to the adversary.

The native gas fees for the exploit transaction are paid in BNB by the adversary EOA and are not converted into USDC units in this report. The profit predicate in `root_cause.json` therefore quantifies profit in terms of USDC balance change at the adversary address:

- **Reference asset:** USDC.  
- **Adversary value before (in USDC):** `0`.  
- **Adversary value after (in USDC):** `10536885633853077370507`.  
- **Value delta (in USDC):** `10536885633853077370507`.  
- **Fees in reference asset:** recorded as the literal string `not_computed_in_USDC_units`, with gas costs deterministically observable in BNB (`219010` gas used at the recorded gas price) but not converted here.

There are no protocol-level invariant violations or systemic effects beyond the victim’s balance loss; USDC and `MulticallWithETH` behave in line with their published semantics.

**References**

- [1] Seed transaction metadata and trace for attacker constructor drain (`0x6da7be6edf3176c7c4b15064937ee7148031f92a4b72043ae80a2b3403ab6302`), including `metadata.json`, `trace.cast.log`, and `balance_diff.json` under `artifacts/root_cause/seed/56/0x6da7be6e…6302`.
- [2] Approval history and receipts for victim infinite USDC approval to `MulticallWithETH`, including `approval_transactions_with_receipts.json` and `approval_logs_page1.json` under `artifacts/root_cause/data_collector/iter_2/address/56/0xfb0De20479…A581/allowance_0x8AC76…580d_to_0x3DA0…2046`.
- [3] USDC `BEP20TokenImplementation` and proxy source code, under `artifacts/root_cause/seed/56/0xba5fe23f8a3a24bed3236f05f2fcf35fd0bf0b5c/src/Contract.sol`.
- [4] `MulticallWithETH` verified source code, under `artifacts/root_cause/data_collector/iter_1/contract/56/0x3DA0F00d5c4E544924bC7282E18497C4A4c92046/source/src/MulticallWithETH.sol`.

