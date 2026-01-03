---
title: H2O Helper-Token Reward Drain on BSC
---

## Incident Overview & TL;DR

On BSC (chainid 56), the H2O token contract at `0xe9c4d4f095c7943a9ef5ec01afd1385d011855a1` implements a helper-token reward mechanism that can be repeatedly triggered by the H2O/USDT PancakeSwap pair `0x42717781d93197247907f82482ae1d35d7bc101b`. An unprivileged EOA, `0x8842dd26fd301c74afc4df12e9cdabd9db107d1e`, deployed a custom helper contract `0x03ca8b574dd4250576f7bccc5707e6214e8c6e0d`, used a 100,000 USDT flash loan from PancakeV3Pool `0x4f31fa980a675570939b737ebdde0471a4be40eb` to enter the H2O/USDT pool, and abusively drove H2O’s `_calulate` reward logic to transfer large amounts of H2O from the token contract’s own balance into the pair and the helper. The helper then swapped H2O back to USDT inside exploit transaction `0x994abe7906a4a955c103071221e5eaa734a30dccdcdaac63496ece2b698a0fc3`, concentrating 22,688.210530453207954293 USDT on the helper contract before cashing out to the EOA via `bfbaa190(USDT)` in transaction `0x33cfa1257d85bcd77206438d5d7efdf22e6cea3c306fce646fa9aa7594b964ec`.

The root cause is a protocol bug in H2O’s `transfer()` and `_calulate()` functions: they implement an unbounded, pseudo-random helper-token reward mechanic that can be triggered an arbitrary number of times within a single transaction by a DEX pair. This allows an attacker-controlled contract to repeatedly receive reward transfers from the token contract’s own balance (`address(this)`), with no per-address or per-transaction cap, enabling a flash-loan-assisted drain of H2O-backed USDT liquidity from the H2O/USDT pool.

## ACT Opportunity and System State

### ACT Metadata

- Report title: H2O Helper-Token Reward Drain on BSC  
- Protocol name: H2O (BSC)  
- ACT flag: This incident is modeled as an ACT (Adversarial Contract Threat) opportunity.  
- Root cause category: `protocol_bug`

### Pre-state σ_B and Block Height

The ACT opportunity is evaluated at block height `47454937` on BSC (chainid 56), immediately before exploit transaction `0x994abe7906a4a955c103071221e5eaa734a30dccdcdaac63496ece2b698a0fc3`. The pre-state σ_B is the publicly reconstructible BSC state before this tx, including balances and allowances for:

- H2O token: `0xe9c4d4f095c7943a9ef5ec01afd1385d011855a1`  
- H2O/USDT PancakePair: `0x42717781d93197247907f82482ae1d35d7bc101b`  
- USDT PancakeV3Pool (flash-loan pool): `0x4f31fa980a675570939b737ebdde0471a4be40eb`  
- Helper contract: `0x03ca8b574dd4250576f7bccc5707e6214e8c6e0d`  
- Helper tokens: `0x6AC860AE21993d65b790a95Cfc1A3A4b42dd0ce3` and `0xD061A395190581cb677b5FfFF1dc38448D4976c8`  
- BEP20 USDT: `0x55d398326f99059ff775485246999027b3197955`  
- Adversary EOA: `0x8842dd26fd301c74afc4df12e9cdabd9db107d1e`

This state is reconstructed and cross-checked using:

- Seed metadata and balance diffs for the exploit tx (including prestate-based ERC20 balance deltas for USDT and H2O).  
- Additional prestate-based balance diffs for the cash-out txs `0x33cfa125...` and `0xa0688f0f...`.  
- On-chain BNB/USDT price data at the exploit block obtained from a PancakeSwap v2 WBNB/USDT pair.  
- Verified H2O source code and decompiled helper/helpertoken contracts.

### Transaction Sequence b (Adversary-Crafted)

The ACT sequence `b` consists of three adversary-crafted transactions on BSC:

1. `0x994abe7906a4a955c103071221e5eaa734a30dccdcdaac63496ece2b698a0fc3`  
   - Type: adversary-crafted exploit aggregation.  
   - Behavior: helper contract borrows 100,000 USDT from PancakeV3Pool `0x4f31fa98...`, swaps USDT into H2O on pair `0x42717781...`, repeatedly triggers `H2O._calulate` via pair-initiated transfers to move H2O from the token contract into the pair and helper, then exits the flash loan with a net 22,688.210530453207954293 USDT increase on helper `0x03ca8b57...`, while paying a 50 USDT flash-loan fee to the pool holder.

2. `0x33cfa1257d85bcd77206438d5d7efdf22e6cea3c306fce646fa9aa7594b964ec`  
   - Type: adversary-crafted cash-out.  
   - Behavior: adversary EOA `0x8842dd26...` calls `helper.bfbaa190(USDT)`, which reads `USDT.balanceOf(address(this))` on `0x03ca8b57...` and transfers that entire USDT balance to `msg.sender`. Prestate-based ERC20 balance diffs show helper USDT delta `-22,770.891449589918819435` and EOA USDT delta `+22,770.891449589918819435`.

3. `0xa0688f0f02aad1ecdbdf653c407ac9c5757a99444ee9beab7b3a60eecc59e1ae`  
   - Type: adversary-crafted noop cash-out attempt.  
   - Behavior: the EOA repeats `bfbaa190(USDT)` after the helper’s USDT balance is already zero; prestate-based ERC20 diffs show zero USDT movement for both the helper and the EOA, so only gas is spent.

### Exploit Predicate and Profit

The exploit predicate is expressed as a profit opportunity in USDT:

- Reference asset: USDT (`0x55d398326f99059ff775485246999027b3197955`).  
- Adversary primary address: EOA `0x8842dd26fd301c74afc4df12e9cdabd9db107d1e`.  
- Gross ERC20 profit (from exploit tx): helper-contract USDT delta `+22,688.210530453207954293`.  
- Flash-loan fee: 50 USDT paid from the H2O/USDT pair to the flash-loan pool holder, included in the pair’s USDT loss.  
- Gas cost across the three sequence-b txs:  
  - `0x994abe79...`: `-0.004001803` BNB (EOA).  
  - `0x33cfa125...`: `-0.0000518` BNB (EOA).  
  - `0xa0688f0f...`: `-0.0000339` BNB (EOA).  
  - Total: `-0.004087503` BNB.

Using the on-chain BNB/USDT price at block `47454937`:

```json
{
  "pair_address": "0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae",
  "token0": "0x55d398326f99059ff775485246999027b3197955",
  "token1": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
  "reserve0": "11578991082411373539449813",
  "reserve1": "19952960489260653037466",
  "price_bnb_in_usdt": 580.3144394859886
}
```

_Snippet: On-chain PancakeSwap v2 WBNB/USDT reserves and derived BNB price in USDT at the exploit block._

The BNB gas expenditure corresponds to approximately `2.372037012342296860` USDT. Combining the gross USDT gain and gas-equivalent cost yields a net adversary profit of:

- Net USDT profit: `22,685.838493440865657433` USDT.

This satisfies the ACT profit predicate in a single reference asset, computed entirely from prestate-based balance diffs and on-chain DEX pricing data.

## Key Background

H2O is a BEP20-like token on BSC with symbol `H2O` and total supply `200,000,000 * 10**18`. The contract introduces two helper tokens:

- `_o2`: `0x6AC860AE21993d65b790a95Cfc1A3A4b42dd0ce3`  
- `_h2`: `0xD061A395190581cb677b5FfFF1dc38448D4976c8`

The H2O/USDT trading pair is created on deployment using PancakeSwap’s factory, and the contract’s own balance (`address(this)`) holds half of the initial H2O supply, effectively acting as a treasury.

Whenever the H2O/USDT pair `0x42717781...` calls `H2O.transfer(to, amount)`, H2O’s transfer implementation invokes `_calulate(to, amount)` to run helper-token-based reward logic. The `_calulate` function:

- Computes `h2obalance = balanceOf(address(this))`, the remaining H2O held by the token contract itself.  
- Selects a small integer `rate` in `{1, 2, 3, 4, 5}` depending on `h2obalance` buckets.  
- Derives a pseudo-random bit `random = getRandomOnchain() % 2`, where `getRandomOnchain()` uses `keccak256(block.timestamp, msg.sender, blockhash(block.number-1))`.  
- Mints `amount * rate / 100` helper tokens to the transfer recipient on `_h2` or `_o2` depending on `random`.  
- Reads `h2balance = IBEP20(_h2).balanceOf(to)` and `o2balance = IBEP20(_o2).balanceOf(to)`; when they exceed thresholds, burns some helper tokens from the recipient and transfers H2O from the token contract’s own balance (`address(this)`) to the recipient, capped only by the current `h2obalance`.

Critically, there is no per-recipient or per-transaction cap on how many times this reward branch can execute within a single transaction. A DEX pair, acting as `msg.sender`, can repeatedly call `transfer(to=helper)` in one flash-loan callback, causing `_calulate` to fire many times for the same helper address and drain a large amount of H2O from the token contract.

The adversary’s helper contract `0x03ca8b57...` orchestrates the attack:

- It borrows USDT via a flash loan from PancakeV3Pool `0x4f31fa98...`.  
- Swaps USDT into H2O via PancakeRouter `0x10ED43C718714eb63d5aA57B78B54704E256024E` into the H2O/USDT pair.  
- Repeatedly sends H2O between itself and the pair, ensuring that each pair-to-helper transfer invokes `_calulate(to=helper)` and fuels further reward emissions.  
- Uses helper tokens as counters to trigger H2O transfers from the token contract’s treasury to the helper.  
- Exposes a simple public cash-out function `bfbaa190(USDT)` that moves all USDT held by the helper contract to `msg.sender`.

### H2O Contract Snippet (transfer and _calulate)

```solidity
function transfer(address to, uint256 amount) public virtual override returns (bool) {
    address owner = msg.sender;
    _spendAllowance(owner, to, 0);
    _transfer(owner, to, amount);
    if (pair == msg.sender) {
        _calulate(to, amount);
    }
    return true;
}

function _calulate(address to, uint256 amount) internal {
    uint256 h2obalance = balanceOf(address(this));
    uint256 rate = 0;
    if (h2obalance <= 20_000_000 * 10**18) {
        rate = 1;
    } else if (h2obalance <= 40_000_000 * 10**18) {
        rate = 2;
    } else if (h2obalance <= 60_000_000 * 10**18) {
        rate = 3;
    } else if (h2obalance <= 80_000_000 * 10**18) {
        rate = 4;
    } else if (h2obalance <= 100_000_000 * 10**18) {
        rate = 5;
    }

    uint256 random = getRandomOnchain() % 2;
    if (random == 1) {
        IBEP20(_h2).mint(to, amount * rate / 100);
    } else if (random == 0) {
        IBEP20(_o2).mint(to, amount * rate / 100);
    }
    uint256 h2balance = IBEP20(_h2).balanceOf(to);
    uint256 o2balance = IBEP20(_o2).balanceOf(to);

    if (h2balance >= 10 * 10**18 && o2balance >= 5 * 10**18) {
        if (h2balance / 2 >= o2balance) {
            IBEP20(_o2).burn(to, o2balance);
            IBEP20(_h2).burn(to, o2balance * 2);
            uint256 amountto = o2balance;
            if (amountto >= h2obalance) {
                amountto = h2obalance;
            }
            _transfer(address(this), to, amountto);
        } else if (h2balance / 2 < o2balance) {
            IBEP20(_o2).burn(to, h2balance / 2);
            IBEP20(_h2).burn(to, h2balance);
            uint256 amountto = h2balance / 2;
            if (amountto >= h2obalance) {
                amountto = h2obalance;
            }
            _transfer(address(this), to, amountto);
        }
    }
}
```

_Snippet: H2O token’s transfer and `_calulate` logic, showing how pair-initiated transfers can repeatedly move H2O from the token contract’s own balance to an attacker-controlled recipient._

## Vulnerability & Root Cause Analysis

### Vulnerability Brief

H2O’s helper-token reward logic allows an unbounded number of `_calulate()` invocations on the same recipient within a single transaction. When driven by a DEX pair, this logic can be abused to transfer large amounts of H2O from the token contract’s own balance to an attacker-controlled address. The mechanism relies on helper tokens and pseudo-randomness from `getRandomOnchain`, but it lacks any per-address or per-transaction cap or invariant that prevents the contract’s treasury from being drained during a single flash-loan cycle.

### Detailed Root Cause

From the H2O source:

- `transfer()` calls `_transfer(owner, to, amount)` and, if `msg.sender` equals the H2O/USDT pair, calls `_calulate(to, amount)`.  
- `_calulate()` mints helper tokens `_h2` or `_o2` to the recipient based on a pseudo-random bit and the transfer amount. It then uses helper-token balances as thresholds to decide when to transfer H2O from the contract’s treasury to the recipient via `_transfer(address(this), to, amountto)`.  
- The amount `amountto` is bounded only by the current `h2obalance` and `o2`/`h2` balances; there is no global limit on total H2O that can be emitted to a single recipient in one transaction.

An adversary can therefore:

- Use a helper contract to orchestrate repeated H2O transfers between itself and the pair within one flash-loan callback, causing many pair-to-helper transfers and hence many `_calulate()` calls for the same helper address.  
- Accumulate helper-token balances sufficient to repeatedly trigger reward branches.  
- Drain a large amount of H2O from `address(this)` into the helper and the pair in a single exploit tx.

The vulnerability is aggravated by:

- The use of block-dependent pseudo-randomness (`block.timestamp`, `blockhash`) that can be influenced by transaction ordering and miner/validator behavior.  
- The fact that DEX pairs can be adversarially driven via complex swap paths and flash loans, executing arbitrary internal transfer patterns within a single transaction.

### Vulnerable Components

- H2O token contract `0xe9c4d4f095c7943a9ef5ec01afd1385d011855a1`, specifically:  
  - `transfer(address,address,uint256)`  
  - `_calulate(address,uint256)`  
- Helper tokens `0x6AC860AE21993d65b790a95Cfc1A3A4b42dd0ce3` and `0xD061A395190581cb677b5FfFF1dc38448D4976c8`, whose `mint` and `burn` functions act as counters inside `_calulate`.  
- Helper contract `0x03ca8b574dd4250576f7bccc5707e6214e8c6e0d`, whose `ecf8ecb0` function orchestrates flash loans, swaps, and looping transfers that drive `_calulate`, and whose `bfbaa190` function enables USDT cash-out.

### Exploit Conditions

For the exploit to succeed, the following conditions hold at σ_B:

- Existence of the H2O/USDT pair `0x42717781...` that routes H2O transfers with `msg.sender == pair` and `to == helper`.  
- The H2O token contract’s own balance (`address(this)`) holds sufficient H2O to support large outgoing reward transfers without immediately reaching zero.  
- The adversary can borrow USDT via a flash loan from PancakeV3Pool `0x4f31fa98...` and use PancakeRouter’s `swapExactTokensForTokensSupportingFeeOnTransferTokens` to enter/exit the H2O/USDT pool.  
- The helper contract can repeatedly send H2O to the pair within a single flash-loan callback, causing the pair to send H2O back to the helper many times and thus invoke `_calulate(to=helper)` multiple times in one transaction.  
- There is no per-address reward cap or global rate limit in `_calulate`, and no restriction preventing the helper contract or the pair from being the primary reward beneficiary.

### Security Principles Violated

- The contract lacks an invariant ensuring that the token contract’s own balance cannot be drained by reward mechanics triggered via DEX interactions.  
- Economically significant transfers from the treasury are governed by unbounded, pseudo-random logic (`_calulate` + `getRandomOnchain`) without enforced caps.  
- The design fails to account for adversarially-driven DEX pairs and flash-loan-based loops that can trigger reward logic arbitrarily many times within a single transaction.

## Adversary Flow Analysis

### Adversary Strategy Summary

The adversary’s strategy is to:

1. Deploy a helper contract that can orchestrate flash loans, swaps, and looping transfers and expose a cash-out method to withdraw USDT.  
2. Use a flash-loan transaction to borrow USDT, enter the H2O/USDT pool, and repeatedly trigger H2O’s `_calulate` reward logic via pair-initiated transfers to an attacker-controlled helper contract.  
3. Convert the resulting H2O and pool imbalance into USDT profit held by the helper.  
4. Call `bfbaa190(USDT)` to transfer all USDT from the helper to the EOA, and optionally repeat cash-out when no USDT remains (incurring only gas).

This lifecycle is entirely permissionless and uses public DEX, flash-loan, and token interfaces; no privileged roles or non-standard assumptions are required.

### Adversary-Related Accounts

Identified adversary cluster:

- EOA `0x8842dd26fd301c74afc4df12e9cdabd9db107d1e` (BSC, chainid 56)  
  - Sender of all attacker-crafted sequence-b txs.  
  - Deployer of helper contract `0x03ca8b57...` (via tx `0xe57e600c...`).  
  - Final USDT profit recipient in cash-out tx `0x33cfa125...`.  

- Helper contract `0x03ca8b574dd4250576f7bccc5707e6214e8c6e0d` (BSC, chainid 56)  
  - Deployed by `0x8842dd26...`.  
  - Executes the `ecf8ecb0` exploit logic, holding intermediate USDT profit after tx `0x994abe79...`.  
  - Transfers all USDT to the EOA via `bfbaa190(USDT)` in tx `0x33cfa125...`.

Victim candidates:

- H2O token contract `0xe9c4d4f095c7943a9ef5ec01afd1385d011855a1` (verified source).  
- H2O/USDT PancakePair `0x42717781d93197247907f82482ae1d35d7bc101b`.  
- USDT PancakeV3Pool flash-loan pool `0x4f31fa980a675570939b737ebdde0471a4be40eb`.

### Helper Contract Cash-Out Snippet

```solidity
function Unresolved_bfbaa190(uint256 arg0, address arg1) public payable {
    // ...
    (bool success, bytes memory ret0) = address(arg1).Unresolved_70a08231(address(this)); // balanceOf(this)
    // ...
    (bool success, bytes memory ret1) = address(arg1).Unresolved_a9059cbb(msg.sender); // transfer(msg.sender, balance)
    // ...
}
```

_Snippet: Decompiled helper-contract `bfbaa190` function (selector `0xbfbaa190`), reading the helper’s full token balance and transferring it to `msg.sender`, used to cash out USDT to the adversary EOA._

### Lifecycle Stages

1. **Adversary deployment and setup**  
   - Tx: `0xe57e600cf8909a37833855005e5b2491414650b863329e13275806f940d17a7f` (block `47454856`, mechanism `deploy`).  
   - EOA `0x8842dd26...` deploys helper contract `0x03ca8b57...`, configuring references to:  
     - USDT `0x55d398326f99059fF775485246999027B3197955`  
     - PancakeV3Pool `0x4f31fa980a675570939b737ebdde0471a4be40eb`  
     - PancakeRouter `0x10ED43C7...`  
     - H2O token `0xe9c4d4f09...`  
     - Helper tokens `0x6AC860AE...` and `0xD061A395...`.  
   - Evidence: helper contract decompiled source and txlist confirming deployment by the EOA.

2. **Exploit execution via flash loan and helper-token rewards**  
   - Tx: `0x994abe7906a4a955c103071221e5eaa734a30dccdcdaac63496ece2b698a0fc3` (block `47454937`, mechanism `flashloan+swap`).  
   - Inside this tx, helper contract `0x03ca8b57...`:
     - Borrows 100,000 USDT from PancakeV3Pool `0x4f31fa98...`.  
     - Swaps USDT to H2O via PancakeRouter `0x10ED43C7...` into pair `0x42717781...`.  
     - Repeatedly cycles H2O between itself and the pair, so that each pair-initiated transfer to the helper invokes `H2O._calulate(to=helper)` and causes H2O transfers from `address(this)` to the helper and the pair.  
     - Ends with the helper holding `22,688.210530453207954293` more USDT than it started with, while the pair has lost `22,738.210530453207954293` USDT and gained `83,280,442,437,787,583,376,702,261` H2O; the flash-loan pool holder receives a 50 USDT fee.

   - Supporting ERC20 balance diffs (exploit tx prestate):

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x03ca8b574dd4250576f7bccc5707e6214e8c6e0d",
      "delta": "22688210530453207954293"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x42717781d93197247907f82482ae1d35d7bc101b",
      "delta": "-22738210530453207954293"
    },
    {
      "token": "0xe9c4d4f095c7943a9ef5ec01afd1385d011855a1",
      "holder": "0x42717781d93197247907f82482ae1d35d7bc101b",
      "delta": "83280442437787583376702261"
    },
    {
      "token": "0xe9c4d4f095c7943a9ef5ec01afd1385d011855a1",
      "holder": "0xe9c4d4f095c7943a9ef5ec01afd1385d011855a1",
      "delta": "-83280442437787583376702261"
    }
  ]
}
```

_Snippet: Prestate-based ERC20 balance deltas for exploit tx `0x994abe79...`, showing USDT and H2O movements between the helper, pair, and token contract._

3. **Cash-out of USDT to adversary EOA**  
   - Txs:  
     - `0x33cfa1257d85bcd77206438d5d7efdf22e6cea3c306fce646fa9aa7594b964ec` (block `47454972`, mechanism `transfer`).  
     - `0xa0688f0f02aad1ecdbdf653c407ac9c5757a99444ee9beab7b3a60eecc59e1ae` (block `47455274`, mechanism `transfer`).  

   - In `0x33cfa125...`, EOA `0x8842dd26...` calls `bfbaa190(USDT)`:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x8842dd26fd301c74afc4df12e9cdabd9db107d1e",
      "delta": "22770891449589918819435"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x03ca8b574dd4250576f7bccc5707e6214e8c6e0d",
      "delta": "-22770891449589918819435"
    }
  ]
}
```

   - This moves all USDT from the helper to the EOA.  
   - In `0xa0688f0f...`, the EOA repeats `bfbaa190(USDT)`; prestate-based ERC20 balance diffs show zero USDT delta for both the helper and EOA, confirming no additional USDT is moved and only gas is spent.

## Impact & Losses

### Total Loss Overview

- Asset: USDT (BEP20).  
- Gross profit to adversary cluster: `22,688.210530453207954293` USDT.  
- Net profit after gas, using on-chain BNB/USDT pricing: `22,685.838493440865657433` USDT.

### Detailed Impacts

From the exploit tx prestate-based balance diffs:

- H2O/USDT pair `0x42717781...` loses `22,738.210530453207954293` USDT.  
  - Of this, 50 USDT is paid as a flash-loan fee to the USDT PancakeV3Pool holder.  
  - The remaining `22,688.210530453207954293` USDT becomes adversary profit held by helper contract `0x03ca8b57...` before cash-out.  

- H2O balances:  
  - H2O token contract `0xe9c4d4f09...` loses `83,280,442,437,787,583,376,702,261` H2O from its own treasury balance (`address(this)`).  
  - H2O/USDT pair gains the same amount of H2O, leaving the pool heavily imbalanced with significantly more H2O and significantly less USDT backing.

Consequences:

- Liquidity providers in the H2O/USDT pool suffer a loss because the pool’s USDT reserves are drained while H2O reserves increase, exposing them to unfavorable post-exploit pricing and reduced liquidity.  
- The H2O contract’s internal balance is depleted, undermining any implicit or explicit reliance on the treasury for buybacks, stability, or other tokenomics, and harming H2O holders.  
- The adversary-related cluster `{0x8842dd26..., 0x03ca8b57...}` realizes a fee-adjusted net profit of approximately `22,685.8385` USDT, fully supported by prestate-based on-chain balance diffs and DEX pricing.

## All Relevant Transactions

For completeness, the following BSC transactions are relevant to this incident:

- `0x3b0891a4eb65d916bb0069c69a51d9ff165bf69f83358e37523d0c275f2739bd` — related (failed/earlier attempt).  
- `0x729c502a7dfd5332a9bdbcacec97137899ecc82c17d0797b9686a7f9f6005cb7` — related (smaller-scale attempt without durable profit).  
- `0x994abe7906a4a955c103071221e5eaa734a30dccdcdaac63496ece2b698a0fc3` — attacker-crafted exploit aggregation tx.  
- `0xd97694e02eb94f48887308a945a7e58b62bd6f20b28aaaf2978090e5535f3a8e` — related (failed exploit attempt).  
- `0xe57e600cf8909a37833855005e5b2491414650b863329e13275806f940d17a7f` — related (helper contract deployment).  
- `0x33cfa1257d85bcd77206438d5d7efdf22e6cea3c306fce646fa9aa7594b964ec` — attacker-crafted USDT cash-out to EOA.  
- `0xa0688f0f02aad1ecdbdf653c407ac9c5757a99444ee9beab7b3a60eecc59e1ae` — attacker-crafted noop cash-out attempt (gas only).

## References

- [1] H2O token `Contract.sol` source (verified on-chain contract source).  
- [2] Helper contract `0x03ca8b57...` decompiled source and ABI (Heimdall decompilation).  
- [3] Helper tokens `0x6AC860AE...` and `0xD061A395...` decompiled sources and ABIs (Heimdall decompilation).  
- [4] Exploit tx `0x994abe79...` cast trace and prestate-based balance diff, used to reconstruct the flash-loan exploit flow and exact ERC20 deltas.  
- [5] Cash-out txs `0x33cfa125...` and `0xa0688f0f...` prestate-based balance diffs, used to reconstruct USDT movements between helper and EOA.  
- [6] On-chain BNB/USDT price at the exploit block, used to convert BNB gas costs into USDT and compute fee-adjusted net profit.

