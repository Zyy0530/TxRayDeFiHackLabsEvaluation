# Incident Overview TL;DR

An adversary-controlled EOA on BNB Chain (0x27441c62dbe261fdf5e1feec7ed19cf6820d583b) used a freshly deployed helper contract and a LABUBU flash loan to exploit a transfer bug in the LABUBU token. Within a single transaction (0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de, block 44751945), the adversary inflated LABUBU balances via self-transfers, drained a large amount of VOVOToken from a LABUBU/VOVOToken Pancake V3 pool, and converted the drained value into WBNB and then BNB profit.  

This incident qualifies as an anyone-can-take (ACT) opportunity: the exploit uses only permissionless on-chain primitives (standard Pancake V3/V2 pools and routers, WBNB, LABUBU, VOVOToken), relies on publicly verifiable contract code or disassembly, and is executed by an unprivileged EOA paying gas. The root cause category is **protocol_bug**, specifically a non-standard ERC20-like implementation in LABUBU that breaks balance conservation under self-transfers and burns.

# Key Background

- **Protocol and environment**  
  - Chain: BNB Chain (`chainid = 56`), block `44751945`.  
  - Protocol context: LABUBU token, VOVOToken, WBNB, and PancakeSwap liquidity pools/routers.  
  - Primary victim pool: LABUBU/VOVOToken Pancake V3 pool at `0xe70294c3D81ea914A883ad84fD80473C048C028C`.  
  - Secondary routing pool: VOVOToken/WBNB Pancake V2 pair at `0xb98f5322a91019311af43cf1d938AD0c59A6148a`.

- **LABUBU token semantics**  
  - LABUBU is an ERC20-like token on BNB Chain whose `_transfer` implementation writes both sender and recipient balances even when they are the same address, and then resets any zero balance to a constant value (`16`).  
  - This breaks standard ERC20 invariants: a self-transfer (`sender == recipient`) should leave the balance unchanged, and burns should permanently reduce total supply and the burner’s balance rather than resetting to a positive constant.

- **Liquidity and routing path**  
  - The exploit path is: LABUBU/VOVOToken Pancake V3 pool → VOVOToken/WBNB Pancake V2 pair → WBNB → native BNB.  
  - Helper contracts `0x2Ff0Cc42e513535BD56bE20c3E686A58608260CA` and `0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30`, together with SmartRouter and PancakeRouter, orchestrate the flash loan, LABUBU self-transfer loop, swaps, and final BNB payout.  
  - Verified sources for the pools and routers show standard PancakeSwap logic; the misbehavior arises exclusively from LABUBU’s token semantics.

- **Scope of attribution**  
  - The analysis identifies on-chain addresses, contract roles, and value flows, and does not attempt to attribute any real-world identities.

# Vulnerability Analysis

The core vulnerability is a **non-standard token implementation in LABUBU** that allows:

- Self-transfers (`sender == recipient`) to **increase** an address’s balance by `amount` instead of leaving it unchanged.
- Burns to **reset zero balances to a positive constant** (`16` units), preventing proper destruction of value.

This behavior is observable directly in the verified LABUBU source code (`artifacts/root_cause/seed/56/0x2ff960f1d9af1a6368c2866f79080c1e0b253997/src/Contract.sol`):

```solidity
function _transfer(address sender, address recipient, uint256 amount) internal {
    require(sender != address(0), "Xfer from zero addr");
    require(recipient != address(0), "Xfer to zero addr");

    uint256 senderBalance = _balances[sender];
    uint256 recipientBalance = _balances[recipient];

    uint256 newSenderBalance = SafeMath.sub(senderBalance, amount);
    if (newSenderBalance != senderBalance) {
        _balances[sender] = newSenderBalance;
    }

    uint256 newRecipientBalance = recipientBalance.add(amount);
    if (newRecipientBalance != recipientBalance) {
        _balances[recipient] = newRecipientBalance;
    }

    if (_balances[sender] == 0) {
        _balances[sender] = 16;
    }

    emit Transfer(sender, recipient, amount);
}

function _burn(address account, uint256 amount) internal {
    require(account != address(0), "Burn from zero addr");
    _balances[account] = SafeMath.sub(_balances[account], amount);
    _totalSupply = _totalSupply.sub(amount);
    if (_balances[account] == 0) {
        _balances[account] = 16;
    }
    emit Transfer(account, address(0), amount);
}
```

Key implications:

- For `sender == recipient`, LABUBU first writes `senderBalance - amount` to `_balances[sender]`, then immediately writes `recipientBalance + amount` back to the same slot; net effect: the balance increases by `amount` instead of remaining unchanged.  
- When a transfer or burn drives the recorded balance to zero, LABUBU resets it to `16`, re-introducing value and preventing true zeroing.

Downstream, the PancakeSwap pools and routers use standard ERC20 semantics and trust the LABUBU balance accounting. The LABUBU/VOVOToken V3 pool’s pricing and invariant logic was not designed to handle an asset whose holder can locally inflate balances via self-transfers and burns. This mismatch between token semantics and DEX assumptions is the root of the protocol-level bug.

The primary vulnerable components are:

- **LABUBU token contract (`0x2ff960f1d9af1a6368c2866f79080c1e0b253997`)**: Non-standard `_transfer` and `_burn` implementations that enable balance inflation and zero-balance resurrection.  
- **LABUBU/VOVOToken Pancake V3 pool (`0xe70294c3D81ea914A883ad84fD80473C048C028C`)**: Relies on LABUBU balances that an attacker can inflate before or during swaps.  
- **VOVOToken/WBNB Pancake V2 pair (`0xb98f5322a91019311af43cf1d938AD0c59A6148a`)**: Used as a standard liquidity venue to convert the drained VOVOToken into WBNB and then BNB.

# Detailed Root Cause Analysis

## ACT opportunity and system model

- **Block height and pre-state (`σ_B`)**  
  - `block_height_B = 44751945` on BNB Chain.  
  - Pre-state includes LABUBU, VOVOToken, WBNB, the LABUBU/VOVOToken Pancake V3 pool, the VOVOToken/WBNB Pancake V2 pair, routers, and helper contracts as reflected in:  
    - Seed metadata: `artifacts/root_cause/seed/56/0xb06d...82de/metadata.json`.  
    - Full trace: `artifacts/root_cause/seed/56/0xb06d...82de/trace.cast.log`.  
    - Balance diffs: `artifacts/root_cause/seed/56/0xb06d...82de/balance_diff.json`.  
    - Verified sources for LABUBU, VOVOToken, WBNB, Pancake V3 pool, Pancake V2 pair, and helper contracts.

- **Minimal transaction sequence `b`**  
  - Sequence `b` consists of a **single adversary-crafted transaction**:
    - Index `1`, `chainid = 56`.  
    - `txhash = 0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de`.  
    - Type: `adversary-crafted`.  
    - Source: EOA `0x27441c62dbe261fdf5e1feec7ed19cf6820d583b`.  
  - **Inclusion feasibility**:  
    - The transaction originates from an unprivileged EOA paying gas in BNB.  
    - It interacts only with permissionless contracts (LABUBU, VOVOToken, WBNB, Pancake V3 pool, Pancake V2 router and pair, SmartRouter) using public ABIs.  
    - Any adversary with sufficient BNB and access to the same contracts and calldata could submit an equivalent transaction under normal mempool and block-production rules.

- **Success predicate**  
  - Type: `profit`.  
  - Reference asset: BNB.  
  - Adversary address: `0x27441c62dbe261fdf5e1feec7ed19cf6820d583b`.  
  - Fees: gas for the transaction is paid in BNB and reflected in the net native balance change.  
  - Value delta in reference asset: `17.394034359323102166` BNB net profit for the EOA.  
  - The valuation comes directly from `balance_diff.json`:

```json
{
  "native_balance_deltas": [
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "delta_wei": "-17403082890323102166"
    },
    {
      "address": "0x27441c62dbe261fdf5e1feec7ed19cf6820d583b",
      "delta_wei": "17394034359323102166"
    }
  ]
}
```

  - WBNB (`0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`) loses `17.403082890323102166` BNB while the adversary EOA gains `17.394034359323102166` BNB; the small difference corresponds to gas, so the transaction realizes a strictly positive net profit in BNB for the EOA.

## Exploit mechanics at code and trace level

1. **Helper deployment and setup**  
   - The seed transaction is a contract-creation transaction from the EOA. It deploys helper contract `0x2Ff0Cc42e513535BD56bE20c3E686A58608260CA` and immediately calls into it.  
   - Disassembly of the deployed code shows the EOA address hard-coded in access-control checks, binding the helper to the EOA.  
   - Evidence:  
     - `artifacts/root_cause/seed/56/0xb06d...82de/metadata.json`.  
     - `artifacts/root_cause/data_collector/iter_1/contract/56/0x2Ff0Cc42e513535BD56bE20c3E686A58608260CA/disassemble/bytecode_disassembly.txt`.

2. **LABUBU flash loan and self-transfer inflation loop**  
   - The helper contract calls a callback helper at `0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30`.  
   - This helper invokes `PancakeV3Pool::flash` on the LABUBU/VOVOToken pool, borrowing `415636276381601458` LABUBU.  
   - In the subsequent `pancakeV3FlashCallback`, the helper executes a long sequence of self-transfers:

```text
│   │   │   ├─ [4594] LABUBU::transfer(0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30, 415636276381601458)
│   │   │   │   ├─ emit Transfer(from: 0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30, to: 0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30, value: 415636276381601458)
│   │   │   │   ├─  storage changes:
│   │   │   │   │   @ 0xa1c48b58...: 0x...620ed2d9d95ab9d2 → 0x...67d375d79ad88884
│   │   │   │   └─ ← [Return] true
```

   - Each repetition increases the helper’s LABUBU balance because `_transfer` writes the decreased and then the increased balance to the same slot, while the zero-balance reset logic ensures balances never collapse to zero.  
   - `balance_diff.json` confirms that the helper’s LABUBU balance rises from `0` to `12023846439948514818`, while the LABUBU/VOVOToken pool’s LABUBU balance also increases (due to the flash loan repayment), without any external inflow.

3. **VOVOToken drain from the LABUBU/VOVOToken V3 pool**  
   - After the self-transfer loop, SmartRouter uses the inflated LABUBU balance held by `0x5CB7...` to execute a Pancake V3 swap:  
     - LABUBU is sent from the helper to the V3 pool.  
     - The pool sends `12608287525767706916530637084` VOVOToken to the helper.  
   - Evidence from `balance_diff.json`:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x58b26c9b2d32df1d0e505bcca2d776698c9be6b6",
      "holder": "0xe70294c3d81ea914a883ad84fd80473c048c028c",
      "delta": "-12608287525767706916530637084",
      "contract_name": "VOVOToken"
    },
    {
      "token": "0x58b26c9b2d32df1d0e505bcca2d776698c9be6b6",
      "holder": "0xb98f5322a91019311af43cf1d938ad0c59A6148a",
      "delta": "12608287525767706916530637084",
      "contract_name": "VOVOToken"
    }
  ]
}
```

   - This shows VOVOToken leaving the V3 pool and entering the V2 pair, matching the described swap path.

4. **Conversion of VOVOToken to WBNB and BNB**  
   - The helper approves VOVOToken to PancakeRouter and calls `swapExactTokensForETHSupportingFeeOnTransferTokens` with the path `[VOVOToken, WBNB]`.  
   - The entire VOVOToken amount is swapped into WBNB on the VOVOToken/WBNB V2 pair and then withdrawn to native BNB via `WBNB::withdraw`, crediting the adversary EOA’s balance.  
   - This is consistent with:  
     - VOVOToken deltas for the V2 pair in `balance_diff.json`.  
     - Native balance deltas for WBNB and the EOA (shown above).

5. **End-to-end ACT conditions**  
   - LABUBU retains its non-standard `_transfer` and `_burn` logic at block 44751945.  
   - The relevant liquidity pools (LABUBU/VOVOToken V3 and VOVOToken/WBNB V2) exist with sufficient reserves.  
   - An unprivileged EOA with enough BNB for gas can deploy the helper contract and call the same Pancake V3 flash and swap interfaces plus Pancake V2 router functions using publicly known ABIs and calldata.  

Given these facts, the exploit is repeatable by any adversary with the same public inputs and satisfies the ACT opportunity definition.

# Adversary Flow Analysis

## Strategy summary

The adversary executes a **single-transaction, multi-stage strategy**:

1. Use a fresh EOA, pre-funded via prior activity, to deploy a helper contract.  
2. Through the helper, obtain a LABUBU flash loan from the LABUBU/VOVOToken V3 pool.  
3. Run a LABUBU self-transfer inflation loop on a helper contract, exploiting LABUBU’s bug to create an enlarged LABUBU balance.  
4. Use SmartRouter to swap inflated LABUBU for VOVOToken from the V3 pool.  
5. Use PancakeRouter to swap VOVOToken to WBNB on a V2 pair, then withdraw WBNB to native BNB for the EOA.  

All stages are visible in the single seed transaction’s trace and balance diffs.

## Adversary-related accounts

- **Adversary cluster**  
  - `0x27441c62dbe261fdf5e1feec7ed19cf6820d583b` (BNB Chain, EOA):  
    - Submits the seed transaction.  
    - Funds helper deployment and exploit execution.  
    - Receives `17.394034359323102166` BNB net profit based on native balance deltas.  
  - `0x2Ff0Cc42e513535BD56bE20c3E686A58608260CA` (BNB Chain, contract):  
    - Helper contract created by the EOA in the exploit transaction.  
    - Bytecode embeds the EOA address in access-control checks.  
    - Orchestrates calls into helper `0x5CB7...`, LABUBU, VOVOToken, Pancake V3 pool, Pancake V2 router and pair, and WBNB.  
  - `0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30` (BNB Chain, contract):  
    - Helper contract called only by `0x2Ff0Cc42e...` in the exploit transaction.  
    - Implements the Pancake V3 flash callback, executes the LABUBU self-transfer loop, approves VOVOToken to PancakeRouter, runs the VOVOToken→WBNB swap, and forwards value towards the EOA.  
    - Address `txlist` for the examined block window is empty, consistent with exclusive internal use in this exploit.

- **Victim candidates**  
  - LABUBU/VOVOToken Pancake V3 pool at `0xe70294c3D81ea914A883ad84fD80473C048C028C` (verified).  
  - VOVOToken contract at `0x58b26c9b2d32df1d0e505bcca2d776698c9be6b6` (verified).

## Lifecycle stages and transactions

The adversary lifecycle is fully contained within the seed transaction `0xb06d...82de` (block 44751945, chainid 56):

1. **Adversary priming and funding**  
   - Prior to the exploit, the EOA performs a small sequence of funding transactions (e.g., deposits) to accumulate BNB required for gas and seed value.  
   - Evidence: `artifacts/root_cause/data_collector/iter_1/address/56/0x2744.../txlist_44750000_44753000.json`.

2. **Helper contract deployment and setup**  
   - Stage: helper deployment inside the exploit transaction.  
   - Transaction: `0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de` (BNB Chain, block 44751945).  
   - Effect:  
     - Deploys helper `0x2Ff0Cc42e...` with embedded EOA address.  
     - Sets up the call flow into helper `0x5CB7...`, LABUBU, VOVOToken, Pancake V3 pool, Pancake V2 router and pair, and WBNB.  
   - Evidence: metadata and helper disassembly as cited above.

3. **Exploit execution via LABUBU flash loan and swaps**  
   - Stage: flash loan, self-transfer loop, pool drain, and swaps.  
   - Transaction: same seed transaction (`0xb06d...82de`).  
   - Effect:  
     - Helper `0x2Ff0Cc42e...` calls `0x5CB7...` which initiates a LABUBU flash loan from the LABUBU/VOVOToken V3 pool.  
     - `0x5CB7...` performs the LABUBU self-transfer loop, inflating its LABUBU balance far beyond the flash amount while still repaying the flash loan.  
     - A Pancake V3 swap sends `12608287525767706916530637084` VOVOToken from the V3 pool to `0x5CB7...`.  
     - The helper approves VOVOToken to PancakeRouter, swaps it for WBNB on the VOVOToken/WBNB V2 pair, and then WBNB is withdrawn to native BNB credited to the EOA.  
   - Evidence: `trace.cast.log`, `balance_diff.json`, and verified pool/pair sources.

## All relevant transactions

All relevant transactions identified in the analysis are:

- `0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de` (BNB Chain, seed, **adversary-crafted**, profit-taking exploit).  
- `0x9b78e4f7217b19250b4b78ea073e224df712162adb8dd13e9681062a41af7fd8` (BNB Chain, related).  
- `0x8b81d2abb3c828fda87f81ed9f45c17109274f8a5837f93a951c7f3576d3a245` (BNB Chain, related).  
- `0x0da2edcd2aaf0050722c7ecf5469ea0e814926d8282fe79521f3fc0a9c48c67e` (BNB Chain, related).

The exploit itself is fully realized in the single adversary-crafted transaction; related transactions provide context and funding history.

# Impact & Losses

- **Token-level losses**  
  - VOVOToken loss from the LABUBU/VOVOToken Pancake V3 pool:  
    - `12608287525767706916530637084` VOVOToken.  
  - Flow of VOVOToken:  
    - Out of the V3 pool at `0xe70294c3D81ea914A883ad84fD80473C048C028C`.  
    - Into the VOVOToken/WBNB V2 pair at `0xb98f5322a91019311af43cf1d938AD0c59A6148a`.  
    - Then converted to WBNB and finally BNB for the adversary EOA.

- **Adversary profit**  
  - Native BNB profit for the EOA, after gas: `17.394034359323102166` BNB (per `balance_diff.json`).  
  - This is derived directly from native balance deltas for the WBNB contract and the EOA.

- **Protocol impact**  
  - Liquidity providers and users of the LABUBU/VOVOToken V3 pool suffer severe depletion of VOVOToken reserves and associated loss of value.  
  - The price of VOVOToken in that pool becomes unreliable, affecting any dependent routing and pricing logic.  
  - The exploit is purely protocol-side (LABUBU token semantics); PancakeSwap’s standard implementations behaved as designed under the assumption of ERC20-like tokens.

# References

- **Seed transaction artifacts**  
  - Seed transaction metadata for `0xb06d...82de`: `artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/metadata.json`.  
  - Seed transaction trace: `artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/trace.cast.log`.  
  - Seed transaction balance diffs: `artifacts/root_cause/seed/56/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de/balance_diff.json`.

- **Contract sources and artifacts**  
  - LABUBU token source: `artifacts/root_cause/seed/56/0x2ff960f1d9af1a6368c2866f79080c1e0b253997/src/Contract.sol`.  
  - VOVOToken source: `artifacts/root_cause/seed/56/0x58b26c9b2d32df1d0e505bcca2d776698c9be6b6/src/Contract.sol`.  
  - WBNB source: `artifacts/root_cause/seed/56/0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c/src/Contract.sol`.  
  - Pancake V3 LABUBU/VOVOToken pool source: `artifacts/root_cause/data_collector/iter_1/contract/56/0xe70294c3D81ea914A883ad84fD80473C048C028C/source/src/PancakeV3Pool.sol`.  
  - Pancake V2 VOVOToken/WBNB pair source: `artifacts/root_cause/data_collector/iter_1/contract/56/0xb98f5322a91019311af43cf1d938AD0c59A6148a/source/src/Contract.sol`.  
  - Helper contract disassembly (0x2Ff0Cc42e...): `artifacts/root_cause/data_collector/iter_1/contract/56/0x2Ff0Cc42e513535BD56bE20c3E686A58608260CA/disassemble/bytecode_disassembly.txt`.

- **Address activity**  
  - Adversary EOA txlist around the incident block: `artifacts/root_cause/data_collector/iter_1/address/56/0x27441c62dbe261fdf5e1feec7ed19cf6820d583b/txlist_44750000_44753000.json`.  
  - Helper 0x5CB7... txlist over the same block window: `artifacts/root_cause/data_collector/iter_2/address/56/0x5CB78bF21eBaa3C44f4A1E8A3a3Ee0041bb52a30/txlist_44750000_44753000.json`.

All statements in this report are derived from these on-chain artifacts and verified contract sources, without speculation or unresolved assumptions.

