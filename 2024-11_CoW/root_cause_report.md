# GPv2Settlement Router Allowance Drain via Helper Contract 0x6700...

## Incident Overview & TL;DR

An unprivileged adversary cluster centered on EOA `0x00baD13FA32E0000E35B8517E19986B93F000034` used a purpose-built helper contract `0x67004E26F800c5EB050000200075f049AA0090C3` together with pre-existing ERC20 allowances from `GPv2Settlement` `0x9008D19f58AAbD9eD0D60971565AA8510560ab41` to a public router `0xA58cA3013Ed560594557f02420ed77e154De0109` to drain WETH and USDC from the settlement contract without interacting with its normal order/accounting logic.

Two adversary-crafted transactions in blocks `0x142804e` (tx `0x2fc9f2fd393db2273abb9b0451f9a4830aa2ebd5490d453f1a06a8e9e5edc4f9`) and `0x142807b` (tx `0xf8053938a623dc346f67c8a0918ebae75e2aaec80d58c113ab62231bf76dc005`) convert protocol-held WETH and USDC into ETH, splitting proceeds between the miner and the attacker EOA. Throughout this sequence, `GPv2Settlement`’s own storage mappings remain unchanged, so the protocol’s internal accounting does not reflect the outflows.

At a high level, the root cause is that `GPv2Settlement`’s `executeInteractions` mechanism allows authorized solver EOAs to grant effectively unlimited WETH/USDC allowances from the settlement contract to a public router, but the protocol does not enforce on-chain constraints ensuring those allowances are used only for safe settlements. Once such allowances exist, any unprivileged address can call the router (directly or via a helper) to pull tokens from `GPv2Settlement` and realize profit, satisfying an anyone-can-take (ACT) opportunity.

## Key Background

- `GPv2Settlement` (`0x9008D1...`) is the core settlement contract for Gnosis Protocol v2. It holds user and fee balances in ERC20 tokens and exposes `settle` and `swap` entrypoints callable only by authorized solver EOAs, checked via an authenticator contract.
- Both `settle` and `swap` accept an array of `GPv2Interaction.Data` structures and forward them to an internal helper, `executeInteractions`, which performs arbitrary external calls (excluding only the Balancer vault relayer). This allows solvers to hook additional on-chain actions before, during, or after settlement.
- Helper contract `0x6700...` is a fallback-only contract that hardcodes two allowed `tx.origin` EOAs (including `0x00baD1...`), interacts with WETH9, the Balancer Vault, and other DeFi components, and sends ETH to `block.coinbase` and `tx.origin`, effectively acting as a custom router for monetizing protocol-held balances and sharing gains with miners.
- Router `0xA58cA3...` and pool `0xe0554a476A092703Abdb3ef35C80e0D76D32939f` are public DeFi contracts that accept calls from any address; they rely solely on ERC20 allowances granted by token owners and do not distinguish between protocol-internal and external callers.

### Key Contract Mechanics (GPv2Settlement)

The settlement contract exposes `settle` and `swap` functions, both restricted to authorized solvers, but internally re-uses `executeInteractions` to perform arbitrary external calls:

```solidity
// Collected contract source (verified on explorer) for GPv2Settlement 0x9008D1...
function settle(
    IERC20[] calldata tokens,
    uint256[] calldata clearingPrices,
    GPv2Trade.Data[] calldata trades,
    GPv2Interaction.Data[][3] calldata interactions
) external nonReentrant onlySolver {
    executeInteractions(interactions[0]);
    (
        GPv2Transfer.Data[] memory inTransfers,
        GPv2Transfer.Data[] memory outTransfers
    ) = computeTradeExecutions(tokens, clearingPrices, trades);
    vaultRelayer.transferFromAccounts(inTransfers);
    executeInteractions(interactions[1]);
    vault.transferToAccounts(outTransfers);
    executeInteractions(interactions[2]);
    emit Settlement(msg.sender);
}

function executeInteractions(GPv2Interaction.Data[] calldata interactions)
    internal
{
    for (uint256 i; i < interactions.length; i++) {
        GPv2Interaction.Data calldata interaction = interactions[i];
        require(
            interaction.target != address(vaultRelayer),
            "GPv2: forbidden interaction"
        );
        GPv2Interaction.execute(interaction);
        emit Interaction(
            interaction.target,
            interaction.value,
            GPv2Interaction.selector(interaction)
        );
    }
}
```

*Caption: `GPv2Settlement` internal helper `executeInteractions` forwards arbitrary external calls from solver-provided interactions, forbidding only calls to the vault relayer and not constraining ERC20 approvals or router interactions.*

### Helper Contract 0x6700... Behavior

The decompiled helper contract shows that it is a fallback-only router that gates on specific `tx.origin` values and splits ETH gains between `block.coinbase` and `tx.origin`:

```solidity
// Decompiled helper contract 0x6700... (fallback path)
fallback() external payable {
    require(!msg.data.length);
    require(
        !(tx.origin == 0xbad13fa32e0000e35b8517e19986b93f000034) |
        (tx.origin == 0x69a00033003ae85f00df00261510d5516d9c00a7)
    );
    // ... interacts with WETH (deposit/withdraw) and Balancer vault ...
    (bool success, ) = address(block.coinbase).transfer(
        ((address(this).balance - arg7) * arg11) / 0x64
    );
    (bool success2, ) = address(tx.origin).transfer(
        (address(this).balance - arg7) -
        (((address(this).balance - arg7) * arg11) / 0x64)
    );
    // ... further balance checks and transfers ...
}
```

*Caption: Decompiled fallback of helper `0x6700...` indicates a purpose-built router that only serves specific EOAs and routes WETH/ETH flows while sharing profits with miners via `block.coinbase`.*

## Vulnerability & Root Cause Analysis

### Vulnerability Summary

`GPv2Settlement`’s interaction mechanism was used by authorized solvers to grant effectively unlimited WETH9 and USDC allowances from the settlement contract to a publicly callable router (`0xA58cA3...`), and the protocol did not enforce on-chain constraints to ensure those allowances were used only within safe settlement flows. This created a standing state where any unprivileged address could invoke the router with attacker-controlled calldata to pull arbitrary amounts of protocol-held tokens from `GPv2Settlement` and convert them into ETH profit.

### How the Vulnerable State Was Created

Solver transactions preceding the incident used `executeInteractions` to call `approve` on WETH9 and USDC from the settlement contract to the router, with effectively unlimited allowances:

```json
// ERC20 approvals summary for GPv2Settlement 0x9008D1...
[
  {
    "token": "WETH9",
    "blockNumber": "0x142804d",
    "transactionHash": "0x5ee1e13401e0a67dff80e477d823ebfd3ac6d82f4092de20db4651bb76fbf2b2",
    "owner": "0x9008d19f58aabd9ed0d60971565aa8510560ab41",
    "spender": "0xa58ca3013ed560594557f02420ed77e154de0109",
    "value": { "raw": "79228162514264337593543950335" }
  },
  {
    "token": "USDC",
    "blockNumber": "0x142807a",
    "transactionHash": "0x17784b1d7d6764e2671fa6b4b08185f51a8d14481e379a29d3b9a783c7f21472",
    "owner": "0x9008d19f58aabd9ed0d60971565aa8510560ab41",
    "spender": "0xa58ca3013ed560594557f02420ed77e154de0109",
    "value": { "raw": "79228162514264337593543950335" }
  }
]
```

*Caption: ERC20 approvals summary confirms that `GPv2Settlement` approved router `0xA58cA3...` for `2^96 - 1` units of WETH9 and USDC, creating effectively unlimited allowances owned by the settlement contract.*

These allowances are standard ERC20 approvals: they are stored in WETH9 and USDC contract storage, not in `GPv2Settlement`’s own state, and they persist until explicitly reduced to zero. `GPv2Settlement` does not track or constrain these approvals at the protocol level.

### Exploit Mechanism via Public Router

Once the allowances existed, helper contract `0x6700...` could instruct router `0xA58cA3...` to perform `transferFrom` calls from `0x9008D1...` (the settlement contract) to `0x6700...`, and then convert the drained tokens into ETH. The vulnerability is thus:

- `executeInteractions` allows solvers to grant global ERC20 allowances from `GPv2Settlement` to a public router.
- There is no contract-level invariant ensuring that only solver-controlled flows can use these allowances.
- The public router and helper contract accept calls from any address and can freely consume the allowances.

Throughout the exploit, state diffs show that `GPv2Settlement`’s own accounting mappings (e.g., `filledAmount`) are unaffected; the protocol’s internal view of balances is decoupled from the ERC20-level movements, enabling unnoticed drains.

### Vulnerable Components

- `GPv2Settlement 0x9008D19f58AAbD9eD0D60971565AA8510560ab41::executeInteractions(GPv2Interaction.Data[] calldata)`
- `GPv2Settlement::settle(...)` when used with interactions that call `token.approve(router, 2^96-1)` from the settlement contract.
- WETH9 `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` and USDC `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` allowance model, when the owner is `GPv2Settlement` and the spender is public router `0xA58cA3...`.
- Helper contract `0x6700...` fallback routing logic that consumes `GPv2Settlement`’s token allowances and returns ETH profit to `tx.origin`.

### Exploit Preconditions

For the exploit to succeed, the following conditions had to hold:

1. `GPv2Settlement` held non-trivial WETH9 and/or USDC balances accumulated from user orders and fees.
2. At least one GPv2 solver transaction used `executeInteractions` to call `token.approve(router 0xA58cA3..., large_amount)` from `GPv2Settlement`, granting the router standing allowances for WETH9/USDC.
3. Router `0xA58cA3...` exposed public functions that, when called by any address, could initiate WETH9/USDC `transferFrom` from owner `0x9008D1...` to an attacker-controlled contract, consuming the allowances.
4. An attacker-controlled helper contract (`0x6700...`) could compose router calls, pool swaps via `0xe0554a...`, and WETH9 withdraws into a sequence that converts drained tokens into ETH and forwards ETH to the attacker EOA.
5. No further on-chain access control or invariant checks inside `GPv2Settlement`, the router, or the token contracts prevented such use of the allowances.

### Security Principles Violated

- **Least privilege for protocol-held ERC20 allowances:** `GPv2Settlement` granted effectively unlimited allowances on protocol-held assets to a public router, without constraining their scope or lifetime.
- **Separation between internal accounting and external token control:** External interactions moved tokens held by the settlement contract without updating internal accounting mappings or recording the movements as part of settlements.
- **Robustness against solver misbehavior:** The system relied on authorized solvers to avoid creating globally exploitable approval states, instead of enforcing protocol-level invariants that make such states impossible for unprivileged actors to exploit.

## adversary Flow Analysis

### Adversary Strategy Summary

The adversary’s strategy is to (i) rely on legitimate solver interactions to prime `GPv2Settlement` with unlimited WETH9 and USDC allowances to a public router, and then (ii) use the dedicated helper contract `0x6700...` to call that router and a liquidity pool in two short, attacker-crafted transactions that drain WETH and USDC from the settlement contract, convert them into ETH, and share profit with the miner.

### Adversary-Related Accounts

- **Adversary EOA:** `0x00baD13FA32E0000E35B8517E19986B93F000034` (Ethereum, chainid 1)  
  - Sender and sole beneficiary EOA for the two incident transactions `0x2fc9...c4f9` and `0xf8053938...`.  
  - Balance diffs show its ETH balance increasing by `3.279896010505720556` ETH across the sequence; no other EOA accumulates comparable direct profit in the relevant block window.

- **Helper Contract:** `0x67004E26F800c5EB050000200075f049AA0090C3` (Ethereum, contract)  
  - Invoked only by `0x00baD1...` in the incident window.  
  - Decompiled bytecode hardcodes `0x00baD1...` and `0x69a00033...` as allowed `tx.origin` values and implements routing and profit-splitting logic that consumes WETH9/USDC allowances from `GPv2Settlement` and pays ETH to `tx.origin` and `block.coinbase`.

### Victim and Infrastructure Accounts

- **Primary Victim – GPv2Settlement:** `0x9008D19f58AAbD9eD0D60971565AA8510560ab41`  
  - Settlement contract that holds protocol/user balances; its WETH9 and USDC balances decrease due to ERC20 `transferFrom` calls authorized by allowances it granted to router `0xA58cA3...`, while its internal storage does not register these outflows.

- **Token Contracts:**  
  - WETH9 `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` – ERC20 and wrapper from which WETH is transferred and later withdrawn; its ERC20 balance for `0x9008D1...` and its native balance both decrease as part of the exploit.  
  - USDC `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` – Stablecoin whose balance at `GPv2Settlement` decreases by `3,001.075733` USDC via `transferFrom` to `0x6700...` in the second incident transaction.

- **Routing Infrastructure:**  
  - Router `0xA58cA3013Ed560594557f02420ed77e154De0109` – public router that receives unlimited WETH9 and USDC allowances from `GPv2Settlement` via `executeInteractions`. Helper `0x6700...` uses its public entrypoints to perform `transferFrom`-based drains.  
  - Pool `0xe0554a476A092703Abdb3ef35C80e0D76D32939f` – liquidity pool used in the second transaction to swap USDC drained from `GPv2Settlement` into WETH, which is later withdrawn to ETH and paid to the attacker.

The miner/coinbase addresses `0x98ed2d46a27afeead62a5ea39d022a33ea4d25c1` (first tx) and `0x0b92619dde55c0cbf828d32993a7fb004e00c84b` (second tx) receive or lose ETH as part of normal block rewards and MEV revenue and are treated as infrastructure, not as part of the adversary cluster.

### Attack Stages and Evidence

#### Stage 1 — Allowance Priming by Authorized Solvers

- **Transactions:**  
  - `0x5ee1e13401e0a67dff80e477d823ebfd3ac6d82f4092de20db4651bb76fbf2b2` (block `0x142804d`, Ethereum)  
  - `0x17784b1d7d6764e2671fa6b4b08185f51a8d14481e379a29d3b9a783c7f21472` (block `0x142807a`, Ethereum)

- **Effect:**  
  Authorized solver EOAs call `GPv2Settlement::settle` with interactions that cause `GPv2Settlement` to call:
  - `WETH9::approve(router 0xA58cA3..., 2^96-1)` and  
  - `USDC::approve(router 0xA58cA3..., 2^96-1)`.  
  This grants the public router effectively unlimited allowances over `GPv2Settlement`’s WETH9 and USDC balances. The approvals persist in token contract storage and are not constrained to a single settlement.

- **Evidence (Approvals Summary):**

```json
// ERC20 approvals summary for GPv2Settlement (data_collector iter_6)
{
  "token": "USDC",
  "blockNumber": "0x142807a",
  "transactionHash": "0x17784b1d7d6764e2671fa6b4b08185f51a8d14481e379a29d3b9a783c7f21472",
  "owner": "0x9008d19f58aabd9ed0d60971565aa8510560ab41",
  "spender": "0xa58ca3013ed560594557f02420ed77e154de0109",
  "value": {
    "raw": "79228162514264337593543950335"
  }
}
```

*Caption: Approvals log for USDC confirms that `GPv2Settlement` approved router `0xA58cA3...` for `2^96-1` units, mirroring the WETH9 approvals and establishing the exploitable state.*

#### Stage 2 — WETH Drain from GPv2Settlement

- **Transaction:**  
  - `0x2fc9f2fd393db2273abb9b0451f9a4830aa2ebd5490d453f1a06a8e9e5edc4f9` (block `0x142804e`, Ethereum)

- **Effect:**  
  EOA `0x00baD1...` calls helper `0x6700...`, which uses router `0xA58cA3...` and the pre-existing WETH9 allowance to:
  - Execute `WETH9::transferFrom(0x9008D1..., 0x6700..., 5.373296932158610028 WETH)`;  
  - Call `WETH9::withdraw` for the same amount, burning WETH and receiving ETH;  
  - Send ETH to the miner (as a tip) and to `0x00baD1...`, resulting in a net ETH gain of `2.739493129139334075` for the EOA.

- **Evidence (Balance Diff for Seed Transaction):**

```json
// Balance diff for seed WETH-drain tx 0x2fc9...c4f9
{
  "native_balance_deltas": [
    {
      "address": "0x00bad13fa32e0000e35b8517e19986b93f000034",
      "delta_wei": "2739493129139334075"
    },
    {
      "address": "0x98ed2d46a27afeead62a5ea39d022a33ea4d25c1",
      "delta_wei": "2632915496757718913"
    },
    {
      "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "delta_wei": "-5373296932158610028"
    }
  ],
  "erc20_transfers": [
    {
      "token": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "from": "0x9008d19f58aabd9ed0d60971565aa8510560ab41",
      "to": "0x67004e26f800c5eb050000200075f049aa0090c3",
      "value": "5373296932158610028"
    }
  ]
}
```

*Caption: Seed transaction balance diff shows `5.373296932158610028` WETH (as ERC20) moving from `GPv2Settlement` to helper `0x6700...`, and the equivalent ETH amount leaving WETH9, with ETH profits split between the attacker and the miner.*

The debug trace for this transaction (not reproduced in full) confirms calls from `0x6700...` into router `0xA58cA3...` and WETH9’s `transferFrom` and `withdraw`, in line with the balance diff.

#### Stage 3 — USDC Drain and Additional Profit

- **Transaction:**  
  - `0xf8053938a623dc346f67c8a0918ebae75e2aaec80d58c113ab62231bf76dc005` (block `0x142807b`, Ethereum)

- **Effect:**  
  After USDC allowances are primed, EOA `0x00baD1...` again calls helper `0x6700...`, which:
  - Causes router `0xA58cA3...` to call `USDC::transferFrom(0x9008D1..., 0x6700..., 3,001.075733 USDC)` using the allowance;  
  - Forwards `3,001.075732` USDC to pool `0xe0554a...`, receiving `1.063530852786372608` WETH;  
  - Withdraws part of that WETH to ETH and routes the proceeds to the attacker EOA, resulting in an additional net ETH profit of `0.540402881366386481`.

- **Evidence (Transaction Logs and Balance Diff):**

```json
// Selected logs from tx 0xf8053938... showing USDC transferFrom
{
  "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
  "topics": [
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    "0x0000000000000000000000009008d19f58aabd9ed0d60971565aa8510560ab41",
    "0x00000000000000000000000067004e26f800c5eb050000200075f049aa0090c3"
  ],
  "data": "0x00000000000000000000000000000000000000000000000000000000b2e0c815"
}
```

```json
// Balance diff for USDC-drain tx 0xf8053938...
{
  "native_balance_deltas": [
    {
      "address": "0x00bad13fa32e0000e35b8517e19986b93f000034",
      "delta_wei": "540402881366386481"
    },
    {
      "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "delta_wei": "-184494670422170530"
    }
  ],
  "erc20_transfers": [
    {
      "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "from": "0x9008d19f58aabd9ed0d60971565aa8510560ab41",
      "to": "0x67004e26f800c5eb050000200075f049aa0090c3",
      "value": "3001075733"
    },
    {
      "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "from": "0x67004e26f800c5eb050000200075f049aa0090c3",
      "to": "0xe0554a476a092703abdb3ef35c80e0d76d32939f",
      "value": "3001075732"
    }
  ]
}
```

*Caption: Transaction logs and balance diff for `0xf8053938...` show USDC moving from `GPv2Settlement` to `0x6700...`, then to pool `0xe0554a...`, and WETH/ETH movements yielding a net ETH gain for the attacker and a WETH native balance decrease at WETH9.*

The debug trace confirms calls through `0x6700...` into router `0xA58cA3...` and the pool, aligning with the observed ERC20 transfers and native balance changes.

## Impact & Losses

### Token Losses from GPv2Settlement

- **WETH:**  
  - Amount: `5.373296932158610028` WETH  
  - Mechanism: `WETH9::transferFrom` from `0x9008D1...` to helper `0x6700...` in tx `0x2fc9...c4f9`, followed by `WETH9::withdraw` to ETH.

- **USDC:**  
  - Amount: `3,001.075733` USDC  
  - Mechanism: `USDC::transferFrom` from `0x9008D1...` to helper `0x6700...` in tx `0xf8053938...`, then forwarded to pool `0xe0554a...` and swapped into WETH/ETH.

### Attacker Profit and Miner Effects

- **Attacker Net Profit:**  
  - ETH gain across both incident transactions: `3.279896010505720556` ETH to EOA `0x00baD1...` after gas costs, as observed in the balance diffs.

- **Miner and Infrastructure Effects:**  
  - Miner addresses receive significant ETH as part of the routing logic and MEV practices, but these flows are consistent with the helper contract’s design and typical MEV extraction. They are not treated as malicious behavior for the purposes of this root cause analysis.

### Accounting and Observability

Because the exploit operates at the ERC20 allowance and `transferFrom` level, `GPv2Settlement`’s internal mappings (such as `filledAmount`) do not reflect the drained WETH and USDC. As a result:

- On-chain token balances at `GPv2Settlement` fall below what its internal accounting and off-chain order/fee records would imply.
- Without explicit reconciliation or invariant checks on token balances versus internal accounting, the drain could remain undetected at the contract level.

## References

The following artifacts were used as primary evidence for this root cause analysis:

- **[1] Seed transaction metadata and trace**  
  - Seed transaction `0x2fc9f2fd393db2273abb9b0451f9a4830aa2ebd5490d453f1a06a8e9e5edc4f9`, including debug trace and balance diff.  
  - Origin: Seed transaction trace and diffs from the initial incident discovery.

- **[2] Balance diffs for incident transactions**  
  - Balance diff for WETH-drain tx `0x2fc9...c4f9`.  
  - Balance diff for USDC-drain tx `0xf8053938a623dc346f67c8a0918ebae75e2aaec80d58c113ab62231bf76dc005`.  
  - Origin: Pre-computed native and ERC20 balance deltas for key incident transactions.

- **[3] GPv2Settlement verified source**  
  - Full Solidity source for `GPv2Settlement` `0x9008D19f58AAbD9eD0D60971565AA8510560ab41`.  
  - Origin: Verified contract sources collected during data collection iteration 5.

- **[4] Helper contract 0x6700... artifacts**  
  - Runtime bytecode, ABI, and decompiled Solidity for helper contract `0x67004E26F800c5EB050000200075f049AA0090C3`.  
  - Origin: Contract artifact collection and decompilation outputs (iter_3).

- **[5] ERC20 approvals search and solver transactions**  
  - Summary of ERC20 `Approval` events involving `GPv2Settlement` and router `0xA58cA3...` in the relevant block range, including solver transactions `0x5ee1e134...` and `0x17784b1d...`.  
  - Origin: Approval-log scan around the incident block window.

All referenced evidence is present in the provided root-cause artifacts directory; no external on-chain queries beyond these artifacts were used in this report.

