## Incident Overview TL;DR

Owner EOA `0x27defcfa6498f957918f407ed8a58eba2884768c` sent transaction `0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f` in Ethereum mainnet block `22157900` to contract `0xea55fffae1937e47eba2d854ab7bd29a9cc29170`, invoking function selector `0xcb01c553` (`cb01c553`). During this call, exactly `17,814,862,676` minimal units of USDC (FiatTokenV2_2 at `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`) were transferred from vault address `0xb91ae2c8365fd45030aba84a4666c4db074e53e7` to the same owner EOA. The transaction is a direct owner call with no intermediary contract controlling `tx.origin`. Subsequent transactions from `0x27defcfa6498f957918f407ed8a58eba2884768c` route portions of the withdrawn USDC through swaps and a `shield(tuple[] _shieldRequests)` call to `0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9`.

The root cause is a centralized owner-only withdrawal capability: `cb01c553` enforces equality between `tx.origin`, `msg.sender`, and a single owner address stored in storage slot `0`, so only that owner can trigger the observed vault drain. From the publicly reconstructible pre-state immediately before block `22157900`, there is no transaction sequence available to an unprivileged adversary that reproduces this effect. This incident is therefore *not* an ACT opportunity; it is an owner-privilege misuse or failure at the protocol governance level.

## Key Background

The incident centers on the following on-chain entities:

- Vault: `0xb91ae2c8365fd45030aba84a4666c4db074e53e7`
- Owner EOA (privileged signer): `0x27defcfa6498f957918f407ed8a58eba2884768c`
- Main orchestrator contract: `0xea55fffae1937e47eba2d854ab7bd29a9cc29170`
- USDC token (FiatTokenV2_2): `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`
- Shielding / L2-related contract: `0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9`

Contract `0xea55fffae1937e47eba2d854ab7bd29a9cc29170` stores a single owner address in storage slot `0` and exposes both an ERC20-like interface and a specialized entrypoint `cb01c553`. Extended semantics for this contract were reconstructed from bytecode and disassembly.

From the extended semantics summary:

```json
{
  "contract_address": "0xea55fffae1937e47eba2d854ab7bd29a9cc29170",
  "access_control": {
    "owner_storage_slot": 0,
    "owner_address_source": "storage slot 0, masked to 160 bits and compared against tx.origin in cb01c553 handler.",
    "cb01c553_access": {
      "selector": "0xcb01c553",
      "description": "Strong owner-only EOA gate: the function first loads an address from storage slot 0, masks to 160 bits, and requires tx.origin to equal this stored owner; it then separately requires msg.sender to equal tx.origin, so only the owner EOA (not contracts or proxies) can invoke cb01c553."
    }
  }
}
```

This access-control structure makes `cb01c553` callable only by the single EOA recorded in slot `0`. In the seed transaction, that EOA is `0x27defcfa6498f957918f407ed8a58eba2884768c`.

The pre-state for the incident is the Ethereum mainnet state immediately before block `22157900`, including balances, allowances, and contract storage for:

- EOA `0x27defcfa6498f957918f407ed8a58eba2884768c`
- Contract `0xea55fffae1937e47eba2d854ab7bd29a9cc29170`
- Vault `0xb91ae2c8365fd45030aba84a4666c4db074e53e7`
- USDC contract `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`

This pre-state is reconstructed from:

- `artifacts/root_cause/seed/1/0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f/metadata.json`
- `artifacts/root_cause/seed/1/0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f/balance_diff.json`
- `artifacts/root_cause/data_collector/iter_1/address/1/0x27defcfa6498f957918f407ed8a58eba2884768c/txlist.json`
- `artifacts/root_cause/data_collector/iter_4/address/1/0xb91ae2c8365fd45030aba84a4666c4db074e53e7/txlist.json`
- `artifacts/root_cause/data_collector/iter_5/address/1/0xb91ae2c8365fd45030aba84a4666c4db074e53e7/erc20_transfers_etherscan_v2.json`

USDC (`FiatTokenV2_2`) is implemented at layout address `0x43506849d7c04f9138d1a2050bbf3a0c054402dd`. The seed balance-diff attributes the USDC balance changes at the vault and owner EOA to this verified implementation.

Vault `0xb91ae2c8365fd45030aba84a4666c4db074e53e7` acts as a multi-depositor pool: ERC20 transfer logs show 310 transfers from 45 distinct senders between 20 Feb 2025 and 30 Mar 2025 UTC, with multiple EOAs depositing tokens into this address prior to the incident.

## Vulnerability Analysis

The core vulnerability is not a low-level bug such as arithmetic overflow or reentrancy; it is a governance and privilege-design issue:

- Contract `0xea55fffae1937e47eba2d854ab7bd29a9cc29170` grants a single EOA (stored in storage slot `0`) unrestricted authority to orchestrate complex DeFi operations via `cb01c553`.
- `cb01c553` is guarded only by checks that:
  - `tx.origin` equals the stored owner address, and
  - `msg.sender` equals `tx.origin`.
- There is no share-based or depositor-based limitation on how much USDC can be withdrawn from vault `0xb91ae2c8365fd45030aba84a4666c4db074e53e7` in a single owner call.
- Downstream protocols (such as Uniswap V3’s `NonfungiblePositionManager` and the APE-related delegatecall target) enforce their own invariants, but do not tie withdrawals from the vault to individual depositor share balances.

As summarized in the extended semantics:

```json
{
  "cb01c553_semantics": {
    "selector": "0xcb01c553",
    "role": "seed vault entrypoint",
    "withdrawal_conditions_for_vault_usdc": {
      "who_can_trigger": "Only the owner EOA stored in slot 0, because cb01c553 enforces ORIGIN == stored_owner and CALLER == ORIGIN.",
      "on_chain_checks_observed": [
        "No additional check ties the amount withdrawn from 0xb91a… to any explicit per-user share balance or totalSupply constraint in this contract’s storage; all observable guards are owner/origin based, not depositor-balance based."
      ]
    },
    "relationship_to_shares": "There is no clear mapping from a depositor’s share balance to a bounded withdrawal amount in the disassembly we inspected."
  }
}
```

This design means that once the owner keys are compromised or misused, all funds held at the vault can be unilaterally redirected by that owner, without any on-chain enforcement of depositor consent, multi-sig governance, or rate limits.

Critically, the owner-only nature of the gate means the incident is not a permissionless ACT opportunity:

- For any EOA other than the stored owner, the `ORIGIN == stored_owner` check fails and `cb01c553` reverts.
- Even if an attacker deploys a contract that attempts to forward calls, the `CALLER == ORIGIN` check prevents successful execution via proxy contracts.
- There is no alternative entrypoint in `0xea55fffae1937e47eba2d854ab7bd29a9cc29170` observed performing the same vault-draining transfer without these owner checks.

## Detailed Root Cause Analysis

### Pre-state and owner configuration

Immediately before block `22157900` (pre-state σ_B):

- Vault `0xb91ae2c8365fd45030aba84a4666c4db074e53e7` holds exactly `17,814,862,676` minimal units of USDC, as recorded in `balance_diff.json`.
- EOA `0x27defcfa6498f957918f407ed8a58eba2884768c` holds zero USDC at the same token contract.
- Contract `0xea55fffae1937e47eba2d854ab7bd29a9cc29170` has storage slot `0` configured with an owner address; extended semantics show that this slot is used in owner checks for `cb01c553`.

From the seed USDC balance diff:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "holder": "0xb91ae2c8365fd45030aba84a4666c4db074e53e7",
      "before": "17814862676",
      "after": "0",
      "delta": "-17814862676"
    },
    {
      "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "holder": "0x27defcfa6498f957918f407ed8a58eba2884768c",
      "before": "0",
      "after": "17814862676",
      "delta": "17814862676"
    }
  ]
}
```

This shows that the entire USDC balance at the vault is about to be moved to the owner EOA in the incident transaction.

### Execution of cb01c553 in the seed transaction

The seed trace for transaction `0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f` confirms that the call is made directly from the owner EOA to contract `0xea55fffae1937e47eba2d854ab7bd29a9cc29170` with selector `0xcb01c553`:

```bash
Traces:
  [25905063] 0xeA55fFFAe1937E47eBA2D854ab7bd29a9CC29170::cb01c553(000000000000000000000000b91ae2c8365fd45030aba84a4666c4db074e53e7...)
```

Within this handler, as summarized in the extended semantics:

- The contract loads storage slot `0`, masks it to a 160-bit address, and compares it against `ORIGIN`; if they differ, execution reverts.
- It then checks that `CALLER` equals `ORIGIN`, ensuring that the call originates directly from the EOA rather than any intermediate contract.

Because this transaction is sent directly from `0x27defcfa6498f957918f407ed8a58eba2884768c` to `0xea55fffae1937e47eba2d854ab7bd29a9cc29170`, we have:

- `tx.origin = 0x27defcfa6498f957918f407ed8a58eba2884768c`
- `msg.sender = 0x27defcfa6498f957918f407ed8a58eba2884768c`

and these values match the stored owner address in slot `0`, so the gate passes.

### Vault withdrawal mechanism

After satisfying the owner-only gate, `cb01c553` performs a series of actions:

- Deploys a new ERC20-like token (observed at `0x341c853c09b3691b434781078572f9d3ab9e3cbb`) via `CREATE`.
- Configures the new token with an initialization call.
- Sets ERC20 approvals (using `approve(address,uint256)`) to external DeFi contracts, including:
  - Uniswap V3 `NonfungiblePositionManager` at `0xc36442b4a4522e871399cd717abdd847ab11fe88`
  - Other aggregator/router addresses passed via calldata.
- Interacts with Uniswap V3 and other protocols to move USDC from vault address `0xb91ae2c8365fd45030aba84a4666c4db074e53e7` into complex positions and ultimately into the owner EOA.

The key invariant break is that this multi-step procedure transfers all USDC from the vault to the owner EOA without any on-chain check tying the withdrawn amount to depositor share balances:

- Vault USDC balance decreases from `17,814,862,676` units to `0`.
- Owner EOA USDC balance increases from `0` to `17,814,862,676` units.
- No per-user accounting or governance mechanism is enforced in the observed bytecode paths to restrict this transfer.

The root cause can therefore be stated precisely:

- **Design flaw:** On-chain logic relies solely on a single EOA owner gate (`slot 0` + `ORIGIN`/`CALLER` equality) to protect a multi-depositor vault, with no on-chain enforcement of share-based withdrawal limits or multi-sig governance.
- **Incident realization:** The privileged owner EOA used this gate to execute `cb01c553`, which orchestrated a full vault drain from `0xb91ae2c8365fd45030aba84a4666c4db074e53e7` to the owner’s own address.

## Adversary Flow Analysis

Although there is no unprivileged adversary in the ACT sense, we can still describe the observed flow of the privileged actor (owner EOA) across transactions.

### Seed vault-drain transaction

- Transaction: `0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f`
- Chain: Ethereum mainnet (`chainid = 1`)
- Role: Seed / primary incident transaction
- From: `0x27defcfa6498f957918f407ed8a58eba2884768c` (owner EOA)
- To: `0xea55fffae1937e47eba2d854ab7bd29a9cc29170`
- Function: `cb01c553`

Effect (from root cause and balance-diff evidence):

- The owner EOA invokes `cb01c553`, passes the `ORIGIN`/`CALLER` checks, and triggers a complex flow that moves `17,814,862,676` units of USDC from vault `0xb91ae2c8365fd45030aba84a4666c4db074e53e7` to the owner EOA.
- ERC20 balance diffs confirm the exact pre- and post-state for USDC at both the vault and owner addresses.

### Post-withdrawal swaps and shielding

After receiving USDC from the vault, the owner EOA performs follow-up transactions:

- Transaction: `0xd3eeb91e4dbd88d54510cfa0d96747370dc39bb97d6041174d452a49b7e2a2bb`
  - From: `0x27defcfa6498f957918f407ed8a58eba2884768c`
  - To: `0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9`
  - Function: `shield(tuple[] _shieldRequests)`
  - Role: Post-withdrawal shielding of part of the withdrawn value.

From the owner EOA txlist:

```json
{
  "hash": "0xd3eeb91e4dbd88d54510cfa0d96747370dc39bb97d6041174d452a49b7e2a2bb",
  "from": "0x27defcfa6498f957918f407ed8a58eba2884768c",
  "to": "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9",
  "methodId": "0x044a40c3",
  "functionName": "shield(tuple[] _shieldRequests)"
}
```

Balance diffs and tx metadata for this shielding transaction show that part of the withdrawn value is routed into the shielding or L2-related contract, reducing traceability of the withdrawn USDC.

Throughout this flow:

- The same EOA `0x27defcfa6498f957918f407ed8a58eba2884768c` is the initiator of the vault-drain transaction and subsequent swaps/shielding.
- No other EOA or contract is observed gaining equivalent control over the vault’s funds without the owner-only gate.

## Impact & Losses

### Quantitative impact

The incident’s direct token-level impact is:

- Token: USDC (`FiatTokenV2_2`, `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`)
- Vault address: `0xb91ae2c8365fd45030aba84a4666c4db074e53e7`
- Owner EOA: `0x27defcfa6498f957918f407ed8a58eba2884768c`

From the USDC balance diffs in the seed transaction:

- Vault USDC balance: `before = 17,814,862,676` units, `after = 0`, `delta = -17,814,862,676`
- Owner EOA USDC balance: `before = 0` units, `after = 17,814,862,676`, `delta = +17,814,862,676`

Using USDC’s 6-decimal format, this corresponds to:

- `17,814,862,676` minimal units = `17,814.862676` USDC tokens.

The loss summary in `root_cause.json` encodes this as:

- Total loss overview: USDC amount `"17814862.676"` (a decimal representation of the same underlying movement, expressed at token precision rather than raw minimal units).

### Multi-depositor impact

ERC20 transfer logs for the vault address show:

- 310 token transfer events involving the vault.
- 45 distinct sending addresses.
- Activity spanning from 20 Feb 2025 to 30 Mar 2025 UTC.

This confirms that:

- Many independent EOAs deposited tokens into vault `0xb91ae2c8365fd45030aba84a4666c4db074e53e7` before the incident.
- The owner-only withdrawal converts this multi-depositor pool into funds held solely by the owner EOA, without any on-chain mechanism ensuring proportional treatment or consent of the depositors.

### Valuation notes

The analysis explicitly does not convert the token-level loss or gas fees into a specific USD valuation:

- Reference asset: USD
- Adversary address: `0x27defcfa6498f957918f407ed8a58eba2884768c`
- `value_before_in_reference_asset`, `value_after_in_reference_asset`, and `value_delta_in_reference_asset` are marked as `not_evaluated`.
- Instead, the analysis relies on deterministic ERC20 balance diffs to quantify the incident in USDC units.

## References

Key artifacts and on-chain data supporting this analysis:

1. Seed transaction metadata for `0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f`  
   - `artifacts/root_cause/seed/1/0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f/metadata.json`

2. Seed transaction trace and USDC balance diffs  
   - Trace (cast run -vvvvv style):  
     `artifacts/root_cause/seed/1/0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f/trace.cast.log`
   - USDC balance diffs:  
     `artifacts/root_cause/seed/1/0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f/balance_diff.json`

3. Extended semantics summary for contract `0xea55fffae1937e47eba2d854ab7bd29a9cc29170`  
   - `artifacts/root_cause/data_collector/iter_4/contract/1/0xea55fffae1937e47eba2d854ab7bd29a9cc29170/extended_semantics_summary.json`

4. Vault transaction history and ERC20 deposits  
   - Vault txlist:  
     `artifacts/root_cause/data_collector/iter_4/address/1/0xb91ae2c8365fd45030aba84a4666c4db074e53e7/txlist.json`
   - Vault ERC20 transfers (Etherscan v2):  
     `artifacts/root_cause/data_collector/iter_5/address/1/0xb91ae2c8365fd45030aba84a4666c4db074e53e7/erc20_transfers_etherscan_v2.json`

5. Owner EOA transaction history, including swaps and shielding  
   - `artifacts/root_cause/data_collector/iter_1/address/1/0x27defcfa6498f957918f407ed8a58eba2884768c/txlist.json`

These artifacts collectively demonstrate that:

- The vault-drain transaction is an owner-signed call to a strictly owner-gated entrypoint.
- The entire USDC balance at the vault is transferred to the owner EOA in that transaction.
- Subsequent owner transactions route portions of the withdrawn value through swaps and shielding.

