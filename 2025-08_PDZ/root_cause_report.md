## Incident Overview TL;DR

On BSC (chainid 56) at block 57744491, a fresh externally owned account (EOA) `0x48234fB95D4D3E5a09F3ec4dD57f68281B78C825` used a single adversary-crafted transaction `0x81fd00eab3434eac93bfdf919400ae5ca280acd891f95f47691bbe3cbf6f05a5` to deploy a factory and helper contract, perform a WBNB flashswap, and execute a PDZ/TOKENbnb reward cycle that drained BNB from the PDZ/TOKENbnb reward pool into the attacker while fully repaying the flashswap.  
The root cause is a protocol bug in the integrated PDZ and TOKENbnb burn/reward design: TOKENbnb, acting as PDZ’s `burnHolder`, can invoke PDZ’s `burnToholder` to pull BNB from PDZ and then redistribute those BNB rewards via `receiveRewards` without a robust invariant or cap, allowing an attacker-controlled helper to use AMM pricing and a flashswap-funded trade to concentrate BNB rewards into a single address in one transaction.

## Key Background

The PDZ/TOKENbnb ecosystem on BSC consists of:
- A PDZ ERC20 token contract at `0x50F2B2a555e5Fa9E1bb221433DbA2331E8664A69`, with a custom `burnToholder` function and a designated `burnHolder`.
- A TOKENbnb ERC20 token contract at `0x664201579057f50D23820d20558f4b61bd80BDda`, configured as PDZ’s `burnHolder` and implementing `burnToHolder` and `receiveRewards` functions that integrate AMM pricing into a burn-and-reward mechanism.
- A WBNB contract at `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`.
- A PancakeSwap V2 pair `0x231d9e7181E8479A8B40930961e93E7ed798542C` with `token0 = WBNB` and `token1 = 0xfb5b838b6cfeedc2873ab27866079ac55363d37e`, used as a flashswap source of WBNB.
- A PDZ/WBNB PancakeSwap pair `0x7b51150F5A61e97f62447E59C7947660822438ab` with `token0 = PDZ` and `token1 = WBNB`, providing PDZ pricing and liquidity.

The token0/token1 probes at block 57744491 confirm the AMM roles:

```json
// PancakePair 0x231d9e7... token0/token1 at block 57744491
{
  "pair_address": "0x231d9e7181e8479a8b40930961e93e7ed798542c",
  "token0": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
  "token1": "0xfb5b838b6cfeedc2873ab27866079ac55363d37e"
}
```

```json
// PDZ/WBNB pair 0x7b5115... token0/token1 at block 57744491
{
  "pair_address": "0x7b51150f5a61e97f62447e59c7947660822438ab",
  "token0": "0x50f2b2a555e5fa9e1bb221433dba2331e8664a69",
  "token1": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
}
```

From the verified PDZ source (`artifacts/root_cause/seed/56/0x50f2b2a555e5fa9e1bb221433dba2331e8664a69/src/Contract.sol`), PDZ exposes a `burnToholder` function callable only by `burnHolder` (set to TOKENbnb) that moves PDZ tokens from a user into the burn holder and, if PDZ’s contract BNB balance is large enough, transfers BNB from PDZ to the burn holder:

```solidity
// PDZ Contract.sol (excerpt) – burnToholder
function burnToholder(address to,uint256 amount,uint256 balance) external {
    require(msg.sender == address(burnHolder), "only burns");
    require(launch, "unlaunch");
    uint256 _amount = balanceOf(to);
    require(_amount >= amount, "not enough");
    super._transfer(to, address(burnHolder), amount);
    uint256 _balance = payable(address(this)).balance;
    if (_balance >= balance) {
        payable(address(burnHolder)).transfer(balance);
    }
}
```

From the verified TOKENbnb source (`artifacts/root_cause/seed/56/0x664201579057f50d23820d20558f4b61bd80bdda/src/Contract.sol`), TOKENbnb defines `burnToHolder` and `receiveRewards` to (a) route PDZ burns through PDZ’s `burnToholder` using AMM quotes, and (b) distribute BNB rewards:

```solidity
// TOKENbnb Contract.sol (excerpt) – burnToHolder integrates AMM pricing and PDZ.burnToholder
function burnToHolder(uint256 amount, address _invitation) external {
    require(amount >= 0, "TeaFactory: insufficient funds");

    address sender = _msgSender();
    if (Invitation[sender] == address(0) && _invitation != address(0) && _invitation != sender) {
        Invitation[sender] = _invitation;
        InvitationList[_invitation].add(sender);
    }
    if (!userList.contains(sender)) {
        userList.add(sender);
    }
    address[] memory path = new address[](2);
    path[0] = address(_burnToken);
    path[1] = uniswapRouter.WETH();
    uint256 deserved = 0;
    deserved = uniswapRouter.getAmountsOut(amount, path)[path.length - 1];
    _burnToken.burnToholder(sender, amount, deserved);
    _BurnTokenToDead(sender, amount);
    burnFeeRewards(sender, deserved);
}
```

```solidity
// TOKENbnb Contract.sol (excerpt) – receiveRewards pays BNB to callers
function receiveRewards(address payable to) external {
    address addr = msg.sender;
    uint256 balance = balanceOf(addr);
    uint256 amount = balance.sub(burnAmount[addr]);
    require(amount > 0);
    Rewards[addr] = Rewards[addr].add(amount);
    historyRewards[addr] = historyRewards[addr].add(amount);
    to.transfer(amount.mul(10**9));
    _transfer(addr, address(this), balance);
    burnAmount[addr] = 0;
    totalReceive = totalReceive.add(amount);
    emit ReceiveReward(addr, amount, totalReceive);
}
```

These contracts are integrated with PancakeRouter `0x10ED43C718714eb63d5aA57B78B54704E256024E`, enabling PDZ/TOKENbnb to use AMM pricing to compute burn and reward amounts.

## Vulnerability Analysis

The vulnerability is a protocol bug in the way PDZ and TOKENbnb integrate AMM pricing and BNB rewards:

- PDZ entrusts TOKENbnb (as `burnHolder`) with the power to call `burnToholder`, which pulls BNB from PDZ’s contract balance into TOKENbnb whenever the requested `balance` amount can be covered.
- TOKENbnb’s `burnToHolder` uses PancakeRouter’s `getAmountsOut` on the PDZ/WBNB pair to compute a `deserved` value for a given PDZ burn, then calls `PDZ.burnToholder(sender, amount, deserved)` and credits the caller with internal reward accounting via `burnFeeRewards`.
- TOKENbnb’s `receiveRewards` lets a caller withdraw BNB from TOKENbnb up to an amount proportional to their accumulated reward accounting, sending that BNB to an arbitrary payable address and resetting the caller’s internal reward state.

Critically, there is no hard invariant or cap that:
- Ties the BNB paid out in `receiveRewards` to a user’s long-term contribution beyond the internal counters manipulated by `burnToHolder`.
- Prevents a single address (or helper contract) from accumulating an outsized share of rewards within a single block.
- Guards against flashswap/flashloan amplification of the PDZ/TOKENbnb reward pipeline.

This design allows an attacker-controlled helper contract to:
- Use a flashswap to temporarily borrow WBNB.
- Convert that WBNB into PDZ via the PDZ/WBNB pair.
- Invoke TOKENbnb’s `burnToHolder` and `receiveRewards` in a tightly orchestrated pattern so that PDZ.burnToholder moves PDZ into TOKENbnb while BNB flows from PDZ into TOKENbnb and then from TOKENbnb to the attacker.
- Repay the flashswap and retain net BNB profit, all within a single transaction, provided the pre-state PDZ/TOKENbnb balances and AMM reserves match the observed configuration.

The vulnerable components are:
- **PDZ token contract (`0x50F2...`)** – `burnToholder` logic callable by TOKENbnb, transferring BNB from PDZ to TOKENbnb based on parameters supplied by TOKENbnb and allowing concentrated BNB outflows.
- **TOKENbnb token contract (`0x6642...`)** – `burnToHolder` and `receiveRewards` logic that orchestrates PDZ burns and BNB distribution, enabling a helper contract to concentrate rewards to a single recipient.
- **PDZ/WBNB PancakePair (`0x7b5115...`)** – provides PDZ pricing and liquidity used to compute `deserved` and to structure the burn/reward amounts.
- **WBNB/0xfb5b83... PancakePair (`0x231d9e7...`)** – serves as the flashswap source of WBNB that funds the attack’s initial trade.

Security principles violated include:
- **Lack of robust invariant on reward distribution** – the system allows concentration of BNB rewards into a single address without robust checks against disproportionate extraction relative to long-term contribution.
- **Cross-contract trust and integration risk** – PDZ grants TOKENbnb powerful control over BNB outflows via `burnToholder`, and their combined behavior with AMM pools is not constrained to resist flashswap-based exploitation.
- **Insufficient consideration of flashswap-based adversaries** – the protocol design treats reward flows as if they will be exercised by typical user behavior, but it exposes a profitable, single-tx flashswap strategy to any unprivileged adversary who reconstructs the pre-state.

## Detailed Root Cause Analysis

### ACT pre-state σ_B at block 57744491

The ACT opportunity is defined at pre-state σ_B: BSC just before block `57744491`. At σ_B:
- PDZ (`0x50F2...`), TOKENbnb (`0x6642...`), and WBNB (`0xbb4C...`) are deployed and integrated.
- PancakeRouter `0x10ED...` is live and connected to the relevant pairs.
- PancakePair `0x231d9e7...` is deployed and configured as WBNB/`0xfb5b83...`, as confirmed by the token0/token1 probe.
- PDZ/WBNB pair `0x7b5115...` exists with `token0 = PDZ`, `token1 = WBNB`, and its txlist up to block 57744491 shows routine activity (approvals and sync), consistent with an organic PDZ/WBNB market.

The pre-state evidence comes from:
- `artifacts/root_cause/seed/index.json` and the seed metadata for tx `0x81fd00ea...`.
- Verified PDZ and TOKENbnb sources in `artifacts/root_cause/seed/56/0x50f2.../src/Contract.sol` and `artifacts/root_cause/seed/56/0x6642.../src/Contract.sol`.
- Token0/token1 probes and txlists for the relevant Pancake pairs in `artifacts/root_cause/data_collector/iter_3/contract/56/0x231d9e7.../token0_token1_at_57744491.json`, `.../0x7b5115.../token0_token1_at_57744491.json`, and `iter_2/address/56/0x7b5115.../txlist_57000000-57744491_etherscan_v2.json`.

### Concrete ACT transaction sequence b

The transaction sequence `b` consists of a single adversary-crafted transaction:

- **b[1]**  
  - `index`: 1  
  - `chainid`: 56 (BSC)  
  - `txhash`: `0x81fd00eab3434eac93bfdf919400ae5ca280acd891f95f47691bbe3cbf6f05a5`  
  - `type`: `adversary-crafted`  
  - `role`: seed transaction in `root_cause.json.all_relevant_txs`  

Inclusion feasibility:
- The EOA `0x4823...` is unprivileged and newly funded.
- Tx `0x81fd00ea...` has `nonce = 0`, `gas = 2,984,868`, and `gasPrice = 3 gwei`, as shown in the seed metadata.
- All invoked functions are permissionless: contract deployment (CREATE), PancakePair `swap`, PancakeRouter swap functions, PDZ’s ERC20 operations, and TOKENbnb’s `burnToHolder` and `receiveRewards`.

An unprivileged adversary who reconstructs σ_B can generate identical calldata and submit a transaction equivalent to `0x81fd00ea...` with competitive gas parameters, satisfying standard BSC inclusion rules.

### Control-flow and value-flow within tx 0x81fd00ea...

The `callTracer` trace for `0x81fd00ea...` (QuickNode `debug_traceTransaction` with `callTracer`) shows the following high-level control flow:

1. **Factory deployment**  
   - From EOA `0x4823...` to CREATE factory `0x1dff...`.
2. **Helper deployment**  
   - From factory `0x1dff...` to CREATE helper contract `0x81F1...`.
3. **WBNB flashswap from PancakePair 0x231d9e7...**  
   - The root call’s `calls` array includes a `CALL` to `0x231d9e7...` with selector `0x022c0d9f` (PancakePair `swap`), which initiates a flashswap. Nested calls include a token transfer of WBNB and a callback into the helper:

```json
// callTracer excerpt for tx 0x81fd00ea...
{
  "type": "CALL",
  "to": "0x231d9e7181e8479a8b40930961e93e7ed798542c",
  "input": "0x022c0d9f...",
  "calls": [
    {
      "to": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "type": "CALL",
      "input": "0xa9059cbb..."
    },
    {
      "to": "0x81f1acd2dad2a9fe2d879e723fb80b7aecdc1337",
      "type": "CALL",
      "input": "0x84800812..."
    },
    {
      "to": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "type": "STATICCALL",
      "input": "0x70a08231..."
    },
    {
      "to": "0xfb5b838b6cfeedc2873ab27866079ac55363d37e",
      "type": "STATICCALL",
      "input": "0x70a08231..."
    }
  ]
}
```

4. **Routing borrowed WBNB into PDZ via PDZ/WBNB pair**  
   - The trace shows `CALL` and `STATICCALL` interactions involving PancakeRouter `0x10ED...`, the PDZ/WBNB pair `0x7b5115...`, and PDZ `0x50f2...`, consistent with a router-mediated swap path WBNB → PDZ via `0x7b5115...`.
5. **PDZ/TOKENbnb burn and reward operations**  
   - The trace includes calls from helper `0x81F1...` into TOKENbnb `0x6642...` with selectors matching functions in the verified source (`0xac003773...` and `0x991a7476...`), consistent with `burnToHolder` and `receiveRewards`:

```json
// callTracer excerpt – helper calling TOKENbnb
{
  "from": "0x81f1acd2dad2a9fe2d879e723fb80b7aecdc1337",
  "to": "0x664201579057f50d23820d20558f4b61bd80bdda",
  "type": "CALL",
  "input": "0xac003773..."
}
{
  "from": "0x81f1acd2dad2a9fe2d879e723fb80b7aecdc1337",
  "to": "0x664201579057f50d23820d20558f4b61bd80bdda",
  "type": "CALL",
  "input": "0x991a7476..."
}
```

   - Within these TOKENbnb calls, PDZ’s `burnToholder` is invoked under the hood, as specified by the verified PDZ and TOKENbnb code excerpts above.
6. **Flashswap repayment and settlement**  
   - After the burn/reward cycle, the WBNB that must be repaid to the flashswap lender is provided, and the transaction completes with a net BNB gain to the attacker and a matching loss from the PDZ/TOKENbnb side.

### Balance deltas and profit accounting

The `balance_diff_prestate_tracer.json` for tx `0x81fd00ea...` (QuickNode `prestateTracer` with diffMode) shows native BNB deltas:

```json
// balance_diff_prestate_tracer.json for 0x81fd00ea... (native_balance_deltas excerpt)
{
  "native_balance_deltas": [
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "before_wei": "1343456703023496533722249",
      "after_wei": "1343456953443623821473780",
      "delta_wei": "250420127287751531"
    },
    {
      "address": "0x48234fb95d4d3e5a09f3ec4dd57f68281b78c825",
      "before_wei": "98312048200000000",
      "after_wei": "3450406746912248469",
      "delta_wei": "3352094698712248469"
    },
    {
      "address": "0x664201579057f50d23820d20558f4b61bd80bdda",
      "before_wei": "3630503056723304190",
      "after_wei": "24094299723304190",
      "delta_wei": "-3606408757000000000"
    }
  ]
}
```

Interpreting these deltas:
- TOKENbnb contract `0x6642...` loses `3.606408757` BNB.
- WBNB contract `0xbb4C...` gains `0.250420127287751531` BNB.
- Attacker EOA `0x4823...` gains `3.352094698712248469` BNB.

The seed metadata and tracer outputs also show:
- Before tx `0x81fd00ea...`, the EOA held `0.0983120482` BNB.
- After tx `0x81fd00ea...`, the EOA held `3.450406746912248469` BNB.
- Gas cost was `2,984,868 * 3 gwei = 0.008954604` BNB.

Therefore, the BNB-denominated adversary portfolio change for this single transaction is:
- `ΔBNB = 3.450406746912248469 - 0.0983120482 - 0.008954604 = 3.352094698712248469` BNB, strictly positive even if all non-BNB tokens are valued at zero.

This matches the success predicate in `root_cause.json`:
- **Reference asset**: BNB.
- **Adversary address**: `0x4823...`.
- **Fees paid**: `0.008954604` BNB.
- **Value before**: `0.0983120482` BNB.
- **Value after**: `3.450406746912248469` BNB.
- **Value delta**: `3.352094698712248469` BNB.

The exploited ACT opportunity is thus:
- A single adversary-crafted transaction identical to `0x81fd00ea...` in σ_B, which any unprivileged EOA can submit, deterministically yields a BNB-denominated profit of `3.3520946987` BNB after gas, funded by a `3.606408757` BNB loss from the PDZ/TOKENbnb reward pool, with `0.2504201273` BNB accruing to the WBNB contract.

## Adversary Flow Analysis

### Adversary cluster

The adversary cluster comprises:
- **EOA `0x48234fB95D4D3E5a09F3ec4dD57f68281B78C825` (BSC, chainid 56)**  
  - Seed transaction sender for `0x81fd00ea...`.  
  - Net BNB profit recipient (`+3.3520946987` BNB) according to balance diffs.  
  - No on-chain evidence of protocol ownership or infrastructure role.
- **Factory contract `0x1dfFe35Fb021f124f04D1a654236E0879FA0CB81` (BSC, chainid 56)**  
  - Deployed by the adversary EOA within `0x81fd00ea...`.  
  - Immediately deploys helper `0x81F1...` and has no independent profit role.
- **Helper contract `0x81F1acd2DAd2A9FE2D879E723fB80b7aeCDc1337` (BSC, chainid 56)**  
  - Deployed by factory `0x1dff...` in `0x81fd00ea...`.  
  - Orchestrates the flashswap, AMM trades, and PDZ/TOKENbnb reward calls.  
  - Temporarily accumulates TOKENbnb and intermediates BNB flows on behalf of the EOA.

These links are supported by:
- Seed metadata and callTracer for `0x81fd00ea...` (`artifacts/root_cause/seed/56/0x81fd00ea.../metadata.json`, `artifacts/root_cause/data_collector/iter_1/tx/56/0x81fd00ea.../trace.callTracer.json`).
- Contract bytecode and disassembly for 0x1dff... and 0x81F1... (`artifacts/root_cause/data_collector/iter_1/contract/56/0x1dfFe35Fb021f124f04D1a654236E0879FA0CB81/...`, `.../0x81F1acd2DAd2A9FE2D879E723fB80b7aeCDc1337/...`).

The analysis also identifies related but non-adversary infrastructure:
- **Tornado-style deposit router `0x0d5550d52428e7e3175bfc9550207e4ad3859b17`** and pool `0xd47438c816c9e7f2e2888e060936a499af9582b3`, used in post-incident deposits by the attacker to obfuscate funds but not to generate additional profit.

### Adversary lifecycle stages

1. **Adversary contract deployment and setup**  
   - **Tx**: `0x81fd00ea...` (seed, block 57744491, mechanism: CREATE and internal CALLs).  
   - The EOA deploys factory `0x1dff...` and helper `0x81F1...` in the same transaction.  
   - Evidence: seed metadata and callTracer trace.

2. **Flashswap and PDZ/WBNB trade**  
   - **Tx**: `0x81fd00ea...` (mechanism: flashloan/flashswap).  
   - Helper `0x81F1...` initiates a WBNB flashswap via PancakePair `0x231d9e7...` and routes borrowed WBNB through PancakeRouter `0x10ED...` into PDZ/WBNB pair `0x7b5115...`, obtaining PDZ and setting up the state for PDZ/TOKENbnb reward operations.  
   - Evidence: `callTracer` interactions showing `CALL` to `0x231d9e7...` (swap) and nested calls to WBNB and helper; token0/token1 probes for `0x231d9e7...` and `0x7b5115...`.

3. **PDZ/TOKENbnb reward drain and settlement**  
   - **Tx**: `0x81fd00ea...` (mechanism: PDZ/TOKENbnb reward logic).  
   - Helper `0x81F1...` calls TOKENbnb `burnToHolder` and `receiveRewards`, causing PDZ.burnToholder to burn PDZ and move BNB from PDZ into TOKENbnb, and then causes TOKENbnb to send accumulated BNB rewards to the helper/EOA.  
   - The helper repays the WBNB flashswap and leaves the EOA with a net BNB gain.  
   - Evidence: verified PDZ and TOKENbnb sources; callTracer showing calls into TOKENbnb and PDZ; prestateTracer balance diffs for WBNB, TOKENbnb, and the EOA.

4. **Post-incident obfuscation via Tornado-style deposits**  
   - **Tx**: `0x6f93f1ad6e626b011e27646d4819d6b478e5a5ceafded7ae9736224f2bddd41a` and subsequent deposits.  
   - The attacker sends BNB from `0x4823...` to mixer router `0x0d5550d5...`, targeting pool `0xd47438...`. For example, the prestateTracer diff for `0x6f93f1ad...` shows:

```json
// balance_diff_prestate_tracer.json for 0x6f93f1ad... (native deltas)
{
  "native_balance_deltas": [
    {
      "address": "0xd47438c816c9e7f2e2888e060936a499af9582b3",
      "before_wei": "1935000000000000000000",
      "after_wei": "1936000000000000000000",
      "delta_wei": "1000000000000000000"
    },
    {
      "address": "0x48234fb95d4d3e5a09f3ec4dd57f68281b78c825",
      "before_wei": "3450406746912248469",
      "after_wei": "2449519925912248469",
      "delta_wei": "-1000886821000000000"
    }
  ]
}
```

   - The attacker address txlist (`artifacts/root_cause/data_collector/iter_1/address/56/0x4823.../txlist_etherscan_v2.json`) shows a series of `deposit(address _tornado, bytes32 _commitment, bytes _encryptedNote)` calls to `0x0d5550d5...`. No ERC20 deltas occur in these deposits, and balance diffs show only BNB moving from the EOA to the pool, confirming these as obfuscation rather than additional exploitation.

## Impact & Losses

The primary impact is a BNB loss from the PDZ/TOKENbnb reward pool, realized entirely within tx `0x81fd00ea...`:

- From the tracer:
  - TOKENbnb contract `0x6642...` loses `3.606408757` BNB.  
  - WBNB contract `0xbb4C...` gains `0.250420127287751531` BNB.  
  - EOA `0x4823...` gains `3.352094698712248469` BNB.

The loss and profit are summarized in `root_cause.json` as:
- **Total loss overview**: approximately `3.606408757` BNB drained from the PDZ/TOKENbnb side.
- **Attacker net profit**: `3.352094698712248469` BNB for `0x4823...`, after gas costs.

There is no evidence in the collected artifacts of further ACT-style profit beyond tx `0x81fd00ea...`:
- Subsequent Tornado-style deposits move BNB from the attacker to `0xd47438...` and burn only additional gas.
- No additional protocol drain or profitable arbitrage is observed in the attacker’s txlist in the collected window.

Thus the incident can be characterized as:
- A single-tx BNB extraction of ~3.6064 BNB from the PDZ/TOKENbnb reward pool.
- A realized BNB-denominated profit of ~3.3521 BNB to the attacker’s EOA.
- No cascading liquidations or secondary protocol breakage within the current evidence set.

## References

Key artifacts supporting this root cause analysis are:

1. **Seed metadata for tx 0x81fd00ea...**  
   - `artifacts/root_cause/seed/56/0x81fd00ea.../metadata.json`  
   - Contains transaction parameters, block data, and initial adversary balance.

2. **callTracer trace for tx 0x81fd00ea...**  
   - `artifacts/root_cause/data_collector/iter_1/tx/56/0x81fd00ea.../trace.callTracer.json`  
   - Provides the structured execution trace (CREATEs, CALLs, and nested calls) used to reconstruct control flow.

3. **PrestateTracer balance diff for tx 0x81fd00ea...**  
   - `artifacts/root_cause/data_collector/iter_1/tx/56/0x81fd00ea.../balance_diff_prestate_tracer.json`  
   - Quantifies native BNB and ERC20 deltas for TOKENbnb, WBNB, PDZ participants, and the attacker EOA.

4. **PDZ token source**  
   - `artifacts/root_cause/seed/56/0x50f2b2a555e5fa9e1bb221433dba2331e8664a69/src/Contract.sol`  
   - Defines `burnToholder` and PDZ’s BNB-handling logic.

5. **TOKENbnb token source**  
   - `artifacts/root_cause/seed/56/0x664201579057f50d23820d20558f4b61bd80bdda/src/Contract.sol`  
   - Defines `burnToHolder`, `receiveRewards`, and the reward accounting mechanisms.

6. **PancakePair 0x231d9e7... source and token0/token1**  
   - Source: `artifacts/root_cause/data_collector/iter_1/contract/56/0x231d9e7.../source/src/Contract.sol`  
   - Token roles at σ_B: `artifacts/root_cause/data_collector/iter_3/contract/56/0x231d9e7.../token0_token1_at_57744491.json`.

7. **PDZ/WBNB pair token0/token1 and txlist**  
   - Token roles at σ_B: `artifacts/root_cause/data_collector/iter_3/contract/56/0x7b5115.../token0_token1_at_57744491.json`  
   - Pre-incident txlist: `artifacts/root_cause/data_collector/iter_2/address/56/0x7b5115.../txlist_57000000-57744491_etherscan_v2.json`.

8. **Attacker address txlist and Tornado-style deposits**  
   - `artifacts/root_cause/data_collector/iter_1/address/56/0x48234fB95D4D3E5a09F3ec4dD57f68281B78C825/txlist_etherscan_v2.json`  
   - Shows the seed exploit tx followed by multiple `deposit` calls to Tornado-style router `0x0d5550d5...`.

9. **Post-incident deposit tx 0x6f93f1ad... balance diff**  
   - `artifacts/root_cause/data_collector/iter_3/tx/56/0x6f93f1ad6e626b011e27646d4819d6b478e5a5ceafded7ae9736224f2bddd41a/balance_diff_prestate_tracer.json`  
   - Confirms that this representative deposit moves exactly 1 BNB (plus gas) from the attacker EOA to pool `0xd47438...` without additional ERC20 profit.

