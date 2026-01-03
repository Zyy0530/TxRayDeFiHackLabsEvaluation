# Base Nalakuvara LotteryTicketSwap50 Pool Drain via subPool Burn

## Metadata
- Protocol: Nalakuvara / LotteryTicket50 / LotteryTicketSwap50 on Base
- Incident classification: ACT (adversarial, unprivileged transaction)
- Root cause category: protocol_bug
- Chain / block: Base (chainid 8453), block 30001613
- Primary incident transaction: 0x16a99aef4fab36c84ba4616668a03a5b37caa12e2fc48923dba4e711d2094699 (adversary-crafted)

## Incident Overview & TL;DR
- An EOA `0x3026c464d3bd6ef0ced0d49e80f171b58176ce32` used a single flash-loan-powered transaction via helper contract `0x080A4047f76Afff8E5efc53349C567f595Aa770a` to call LotteryTicketSwap50 and a modified Nalakuvara/USDC NostrSwap pair. The pair’s custom `subPool` burn function repeatedly destroyed large amounts of Nalakuvara (NATA) from the pool while UniswapV2 router flows recycled value back into USDC for the caller.
- Over this one transaction, the Nalakuvara/USDC pair lost both USDC and NATA reserves while the attacker-controlled cluster ended with a net gain of **105,470 USDC** after repaying the flash loan, satisfying a **profit-type ACT** opportunity.

**Root cause brief.** A protocol-level design bug in the interaction between LotteryTicketSwap50 and a modified UniswapV2 pair exposes a whitelisted `subPool(address,uint)` burn hook to UniswapV2 router flows. LotteryTicketSwap50’s `DestructionOfLotteryTickets` function drives `removeLiquidity` and `swapTokensForExactTokens` on the router, which in turn call `subPool` and burn Nalakuvara directly out of the LP reserves while still allowing value to be cycled back into USDC. This breaks the AMM invariant and lets an adversary with a flash loan and tickets repeatedly drain the Nalakuvara/USDC pool for USDC profit.

## ACT Opportunity

### Pre-state \(sigma_B\)
Just before block 30001613 on Base:
- The Nalakuvara/USDC UniswapV2-style pair at `0xaDcaaB077f636d74fd50FDa7f44ad41e20A21FEE` held substantial reserves of Nalakuvara (`0xb39392F4b6D92a6BD560Ed260C2c488081aAB8E9`) and USDC (FiatTokenProxy at `0x833589fCD6eDb6E08f4c7c32D4f71b54bdA02913`).
- The LotteryTicketSwap50 contract at `0x172119155a48DE766B126de95c2cb331D3A5c7C2` was deployed and wired to this pair, the LotteryTicket50 token (`0xf9260Bb78d16286270e123642ca3DE1F2289783b`), and the canonical UniswapV2 router/factory.
- The UniswapV3 USDC pool at `0xd0b53d9277642d899df5c87a3966a349a798f224` was available for flash loans to arbitrary callers.
- These conditions are fully determined by on-chain history, traces, and verified sources for the pair, LotteryTicketSwap50, and LotteryTicket50.

**Evidence used to reconstruct sigma_B.**
- Seed tx metadata and trace for the incident transaction.
- Verified source for the modified NostrSwap pair.
- Verified source for LotteryTicketSwap50.
- Verified source for LotteryTicket50.

The corresponding local artifacts are:
- `artifacts/root_cause/seed/8453/0x16a9…4699/metadata.json`
- `artifacts/root_cause/seed/8453/0x16a9…4699/trace.cast.log`
- `artifacts/root_cause/data_collector/iter_2/contract/8453/0xaDcaa…1FEE/source/src/Contract.sol`
- `artifacts/root_cause/data_collector/iter_2/contract/8453/0x1721…c7C2/source/src/Contract.sol`
- `artifacts/root_cause/seed/8453/0xf9260bb78d16286270e123642ca3de1f2289783b/src/Contract.sol`

### Transaction sequence b
There is a single transaction in the adversarial sequence:
- Index: 1
- Chainid: 8453 (Base)
- Tx hash: `0x16a99aef4fab36c84ba4616668a03a5b37caa12e2fc48923dba4e711d2094699`
- Type: adversary-crafted
- Inclusion feasibility: An unprivileged EOA can deploy a helper contract implementing the UniswapV3 flash callback and the same call pattern as `0x080A4047f76Afff8E5efc53349C567f595Aa770a`, then send a 0-value transaction invoking its entrypoint. The UniswapV3 pool, UniswapV2 router/pair, LotteryTicketSwap50, and LotteryTicket50 expose public functions that accept arbitrary callers, and the gas/fee parameters of this tx are within normal Base limits, so this transaction is includable under standard consensus rules.
- Notes: This single transaction both borrows USDC via UniswapV3 flash, engages `transferToken` and `DestructionOfLotteryTickets` on LotteryTicketSwap50, invokes the modified NostrSwap pair’s `subPool` via the router, recycles USDC from the pair into the helper contract, and repays the flash loan, leaving net profit in the adversary EOA.

### Exploit predicate
- Type: **profit**.
- Reference asset: **USDC**.
- Adversary address for valuation: `0x3026c464d3bd6ef0ced0d49e80f171b58176ce32`.
- Fees paid in reference asset: **unknown** (only gas in ETH is quantified).
- Value before in reference asset: **unknown**.
- Value after in reference asset: **unknown**.
- Value delta in reference asset: **105,470 USDC**.
- Valuation notes: ERC20 transfer log aggregation for the incident tx shows that `0x3026c4…ce32` has a net gain of `105,470,000,000` units of USDC and no offsetting losses in NATA, LotteryTicket50, or LP tokens in this transaction, while losing only `230,919,265,116,857` wei (~0.00023 ETH) in native gas. Treating USDC as the reference asset, this yields a strictly positive net gain of 105,470 USDC minus a negligible gas cost whose USDC value is not estimated.

## Key Background
The incident relies on a specific structured-product and AMM design on Base:
- **Nalakuvara (NATA)** is an ERC20 token paired with USDC in a NostrSwap/UniswapV2-style AMM.
- **LotteryTicket50** is an ERC20 ticket token used by LotteryTicketSwap50; in this tx, 2.6 billion LotteryTicket50 are minted and ultimately burned.
- **LotteryTicketSwap50** is a structured-product contract that takes USDC deposits, issues LotteryTicket50 tickets, manages NATA/USDC liquidity, and exposes `transferToken` and `DestructionOfLotteryTickets` functions.
- The **NostrSwap pair** at `0xaDcaa…1FEE` is a forked UniswapV2 pair that adds a whitelisted `subPool(address _token, uint _amount1Out)` function which can burn tokens directly from the pool to a dead address while holding the rest of the AMM logic constant.
- The **UniswapV2 router** is granted whitelist access to the pair’s `subPool` function, so router-driven flows (including those orchestrated by LotteryTicketSwap50) can trigger reserve burns.
- A **UniswapV3 USDC pool** provides large USDC flash loans to any contract implementing the expected callback.

## Vulnerability & Root Cause Analysis

### Vulnerability brief
The vulnerability arises because LotteryTicketSwap50’s ticket destruction logic (`DestructionOfLotteryTickets`) drives UniswapV2 `removeLiquidity` and `swapTokensForExactTokens` calls that, when routed through a modified NostrSwap pair, trigger the pair’s whitelisted `subPool` burn function. This function burns Nalakuvara directly from the pool reserves to a dead address, breaking the AMM invariant while still enabling the router to extract USDC, allowing an adversary to repeatedly drain the pool with a flash loan.

### Root cause detail
At a technical level, the root cause is the interaction of two unsafe design choices:
- The NostrSwap pair at `0xaDcaa…1FEE` exposes a `subPool(address _token, uint _amount1Out)` function that:
  - Is gated only by an `isWhiteListed[msg.sender]` check.
  - When called by a whitelisted address (the router), transfers `_amount1Out` of `_token` from the pair to a global `deadAddress` without updating the paired reserve in a compensating fashion.
- LotteryTicketSwap50 at `0x1721…c7C2` wires user ticket burning (`DestructionOfLotteryTickets`) into `removeLiquidity` and `swapTokensForExactTokens` calls on the UniswapV2 router, with `pairAddress` set to the Nalakuvara/USDC NostrSwap pair and `tokenUSDT`/`tokenNATA` pointing to USDC and Nalakuvara.

In `DestructionOfLotteryTickets`, a user (or helper contract) that approved LotteryTicket50 can:
- Burn whole tickets to the dead address.
- Have LotteryTicketSwap50 calculate an amount of LP tokens corresponding to a USDC amount per ticket.
- Call `removeLiquidity` to withdraw NATA and USDC from the pair.
- Call `swapTokensForExactTokens` to convert NATA to USDC with a target output.

Because the pair’s router is whitelisted for `subPool`, these router operations cause the NostrSwap pair to invoke `subPool(tokenNATA, _amount1Out)` during the flow, burning large amounts of NATA directly from the pool to the dead address before syncing and swapping. The AMM invariant is broken: NATA reserves drop sharply while USDC reserves are only partially reduced, allowing swaps and structured flows to extract USDC at artificially favorable rates.

An unprivileged adversary can use a flash loan from the UniswapV3 USDC pool to fund a `transferToken` call (minting LotteryTicket50 and seeding pool liquidity) and then execute many `DestructionOfLotteryTickets` cycles within the same transaction. This repeatedly burns NATA from the pool while routing value into USDC, enabling full flash loan repayment and leaving a large USDC profit for the adversary.

### Vulnerable components
- NostrSwap/UniswapV2 pair at `0xaDcaaB077f636d74fd50FDa7f44ad41e20A21FEE`: `subPool(address _token, uint _amount1Out)`.
- LotteryTicketSwap50 at `0x172119155a48DE766B126de95c2cb331D3A5c7C2`: `DestructionOfLotteryTickets(uint _amountTickets)`.
- LotteryTicketSwap50 at `0x172119155a48DE766B126de95c2cb331D3A5c7C2`: `transferToken(uint amount)` in combination with `DestructionOfLotteryTickets`.

### Exploit conditions
- The Nalakuvara/USDC pair must whitelist the UniswapV2 router in `isWhiteListed[msg.sender]` so router calls can invoke `subPool` during arbitrage or structured-product flows.
- LotteryTicketSwap50 must be configured with `tokenUSDT=USDC`, `tokenNATA=Nalakuvara`, `ticket=LotteryTicket50`, and `pairAddress` pointing to the same Nalakuvara/USDC pair, with its internal configuration (including `flag1`) allowing arbitrary users to call `transferToken` and `DestructionOfLotteryTickets` once approvals are in place.
- The UniswapV3 USDC pool must supply sufficient flash liquidity to fund the combined `transferToken` plus multiple `DestructionOfLotteryTickets` cycles in a single transaction so the adversary needs no upfront USDC.
- The NostrSwap pair must hold non-trivial Nalakuvara and USDC reserves so that repeated `subPool` burns and AMM swaps can convert the burned NATA into USDC payouts while repaying the flash loan.

### Security principles violated
- **AMM invariant preservation**: The `subPool` burn breaks the constant-product invariant by unilaterally reducing one reserve without compensating the other, enabling economically irrational prices exploitable by adversaries.
- **Least privilege / absence of backdoors**: Granting the router whitelist access to a reserve-burning primitive (`subPool`) effectively exposes all pool liquidity to arbitrary manipulation through any contract using the router (including LotteryTicketSwap50).
- **User fairness and LP protection**: LotteryTicketSwap50’s design enables certain users (e.g., flash-loan-powered adversaries) to extract USDC from LPs at a rate unaligned with intended market pricing or lottery economics, socializing losses onto passive LPs and other token holders.

### Key code evidence

**Snippet 1 – LotteryTicketSwap50::DestructionOfLotteryTickets ticket burn and liquidity flow**  
Origin: Verified LotteryTicketSwap50 source for `0x1721…c7C2`.

```solidity
function DestructionOfLotteryTickets(uint  _amountTickets) public returns(bool){
    IUniswapV2Router02  swapRouter = IUniswapV2Router02(ROUTER_ADDRESS);
    uint256 MIN_TICKET = 1 * 10 ** 6;
    require(_amountTickets > 0, "Amount must more than 0 TICKET");
    require(_amountTickets % MIN_TICKET == 0, "Amount must be a multiple of 1 Ticket");
    address deadAddress = 0x000000000000000000000000000000000000dEaD;
    require(coinTicket.transferFrom(msg.sender, deadAddress, _amountTickets), "Ticket transfer failed");
    // ... compute liquidity and call removeLiquidity and swapTokensForExactTokens ...
}
```

This function burns LotteryTicket50 from the caller to the dead address, then uses the UniswapV2 router to remove liquidity and swap tokens for USDC, which in turn triggers the NostrSwap pair’s `subPool` hook when wired to that pair.

**Snippet 2 – NostrSwap::subPool burn primitive**  
Origin: Verified NostrSwap pair source for `0xaDcaa…1FEE`.

```solidity
function subPool(address _token, uint _amount1Out) external lock {
    uint _balance1 = IERC20(_token).balanceOf(address(this));
    require(isWhiteListed[msg.sender], 'NostrSwap: Transfer Not Allowed');
    if (isWhiteListed[msg.sender]) {
        if (_amount1Out > 0 && _balance1 > _amount1Out) {
            _safeTransfer(_token, deadAddress, _amount1Out);
        }
    }
}
```

When called by a whitelisted router, this function burns `_amount1Out` of the specified token from the pair to a dead address, reducing reserves outside the normal AMM swap/LP mint/burn flow and breaking the expected invariant.

**Snippet 3 – Seed transaction trace showing flash loan, DestructionOfLotteryTickets, and subPool calls**  
Origin: Seed transaction trace (Foundry `cast run -vvvvv`) for the incident tx.

```text
UniswapV3Pool::flash(: [0x080A4047f76Afff8E5efc53349C567f595Aa770a], 0, 2930000000000 [2.93e12], 0x)
  ...
  LotteryTicketSwap50::DestructionOfLotteryTickets(20000000 [2e7])
  ...
  ::subPool(Nalakuvara: [0xb39392F4b6D92a6BD560Ed260C2c488081aAB8E9], 251716130567053244197297226 [2.517e26])
  ... (repeated DestructionOfLotteryTickets and subPool cycles) ...
```

The trace shows the helper contract receiving a 2.93e12-unit USDC flash loan, repeatedly calling `DestructionOfLotteryTickets(2e7)` on LotteryTicketSwap50, and triggering large `subPool` burns of Nalakuvara from the NostrSwap pair, all within the same transaction.

**Snippet 4 – ERC20 transfer-log aggregation for incident tx**  
Origin: Aggregated ERC20 balance/transfer diff for the incident tx.

```json
{
  "tokens": {
    "USDC": {
      "0x1721…c7C2": "194668858",
      "0x3026…ce32": "105470000000",
      "0xaDcaa…1FEE": "-107414668858",
      "0xd0b53…8224": "1750000000"
    },
    "Nalakuvara": {
      "0x0000…dEaD": "32720081258016852628000378466",
      "0x1721…c7C2": "19307317299937116944068009",
      "0xaDcaa…1FEE": "-32739388575316789744944446475"
    },
    "LotteryTicket50": {
      "0x0000…0000": "-2600000000",
      "0x0000…dEaD": "2600000000"
    }
  }
}
```

This aggregation (simplified from `erc20_balance_diff_transfers.json`) shows the NostrSwap pair losing 107,414.668858 USDC and ~3.2739e28 NATA, the dead address receiving all 2.6e9 LotteryTicket50 and ~3.272e28 NATA, LotteryTicketSwap50 accumulating some NATA and USDC, and the adversary EOA ending with +105,470,000,000 units of USDC.

## Adversary Flow Analysis

### Adversary strategy summary
The adversary uses a helper contract to:
- Borrow USDC via an UniswapV3 flash loan.
- Call LotteryTicketSwap50’s `transferToken` once to mint LotteryTicket50 tickets and set up NATA/USDC liquidity.
- Then repeatedly call `DestructionOfLotteryTickets` within the same transaction so that the NostrSwap pair’s `subPool` hook burns Nalakuvara from the pool while router/AMM flows convert value back into USDC.
- Fully repay the flash loan and return the residual USDC to the EOA sender as profit.

### Adversary-related accounts (cluster and victims)

**Adversary cluster**
- `0x3026c464d3bd6ef0ced0d49e80f171b58176ce32`
  - Chain: Base (8453); type: EOA (is_eoa=true, is_contract=false).
  - Role: Sender of the adversary-crafted tx and final beneficiary of 105,470,000,000 units of USDC.
  - Evidence: Only address with a large positive net USDC delta and no offsetting losses in the balance diff; pays native gas costs.
- `0x080A4047f76Afff8E5efc53349C567f595Aa770a`
  - Chain: Base (8453); type: contract (is_eoa=false, is_contract=true).
  - Role: Entry/helper contract that receives the UniswapV3 flash loan, orchestrates transfers to/from LotteryTicketSwap50 and the NostrSwap pair, and repays the flash loan.
  - Evidence: Appears as the flash loan borrower and as the caller of structured-product and AMM interactions in the trace; ends with near-zero net ERC20 deltas, consistent with a stateless helper fully controlled by the EOA.

**Victim candidates**
- Nalakuvara/USDC NostrSwap LPs
  - Pool contract: `0xaDcaaB077f636d74fd50FDa7f44ad41e20A21FEE` on Base (8453), is_verified=true.
- LotteryTicketSwap50 structured-product users
  - Contract: `0x172119155a48DE766B126de95c2cb331D3A5c7C2` on Base (8453), is_verified=true.
- Nalakuvara token holders
  - Token: `0xb39392F4b6D92a6BD560Ed260C2c488081aAB8E9` on Base (8453), is_verified=true.

### Adversary lifecycle stages

1. **Adversary initial funding via UniswapV3 flash loan**
   - Tx: same incident tx `0x16a9…4699` in block 30001613 on Base; mechanism: `flashloan`.
   - Effect: Helper contract `0x080A…770a` receives `2,930,000,000,000` units of USDC from UniswapV3 pool `0xd0b53…8224`, with an obligation to return principal plus a `1,750,000,000` USDC fee.
   - Evidence: `UniswapV3Pool::flash` call stack in the trace and USDC deltas for `0xd0b53…8224` and `0x080A…770a` in the ERC20 transfer-log aggregation.

2. **Lottery ticket minting and pool priming**
   - Tx: same incident tx, block 30001613; mechanism: `structured_product_deposit`.
   - Effect: `0x080A…770a` transfers `2,800,000,000,000` USDC into the Nalakuvara/USDC pair for an initial NATA purchase, then calls `LotteryTicketSwap50.transferToken(130,000,000,000)` USDC, which mints `2,600,000,000` LotteryTicket50 tickets to the helper and configures internal reserves/allowances for subsequent `DestructionOfLotteryTickets` cycles.
   - Evidence: Trace around `UniswapV2Pair::swap` and `LotteryTicketSwap50::transferToken`, plus the LotteryTicketSwap50 `transferToken` implementation in Contract.sol.

3. **Ticket destruction, subPool burns, and USDC extraction**
   - Tx: same incident tx, block 30001613; mechanism: `ticket_burn_and_amm_manipulation`.
   - Effect: Within the same transaction, `0x080A…770a` repeatedly calls `DestructionOfLotteryTickets(20,000,000)` on LotteryTicketSwap50, burning LotteryTicket50 to `0x0000…dEaD`. Each destruction triggers `removeLiquidity` and `swapTokensForExactTokens` on the router, which in turn (because the router is whitelisted) call `UniswapV2Pair.subPool(tokenNATA, _amount1Out)`. Large amounts of Nalakuvara are burned directly from the pair to the dead address before syncing and swapping. Over the sequence, the pair loses ~`3.27e28` NATA and `107,414.668858` USDC, LotteryTicketSwap50 accumulates NATA and some USDC, the dead address receives both NATA and all `2.6e9` LotteryTicket50 minted in this tx, and the helper contract recovers enough USDC to repay the flash loan and retain `105,470` USDC as profit.
   - Evidence: NostrSwap Contract.sol `subPool` implementation; LotteryTicketSwap50 Contract.sol `DestructionOfLotteryTickets`; trace around repeated `::DestructionOfLotteryTickets` and `::subPool` calls; `balance_diff.json` and `erc20_balance_diff_transfers.json` showing NATA, USDC, LotteryTicket50, and LP token deltas.

4. **Flash loan repayment and profit realization**
   - Tx: same incident tx, block 30001613; mechanism: `flashloan_repayment`.
   - Effect: `0x080A…770a` transfers `2,908,000,000,000` USDC back to the UniswapV3 pool, repaying principal plus fee, and forwards the remaining USDC to EOA `0x3026c4…ce32`. Final ERC20 diffs show `0x3026…ce32` with `+105,470,000,000` USDC net and no residual positions in NATA, tickets, or LP tokens; its only cost is native gas.
   - Evidence: Final `FiatTokenProxy::transfer` calls in the trace from `0x080A…770a` to the pool and then to the EOA; `erc20_balance_diff_transfers.json` USDC deltas by address.

## Impact & Losses

### Quantitative losses
- USDC: `107,414.668858` USDC lost from the Nalakuvara/USDC NostrSwap pair.
- NATA: `32,739,388,575,316,789,744,944,446,475` NATA (`3.2739388575316789744944446475e28`) burned or removed from the pair’s reserves.

### Qualitative impacts
- The Nalakuvara/USDC NostrSwap pair is heavily drained in both USDC and NATA reserves within a single transaction.
- The UniswapV3 pool gains `1,750` USDC in flash-loan fees.
- The adversary-controlled cluster earns **105,470 USDC** net profit, with only negligible gas cost.
- Nalakuvara/USDC LPs and NATA holders bear the economic loss: pool liquidity is removed and a large portion of NATA supply is burned to `0x0000…dEaD`, potentially disrupting price discovery and harming holders who did not participate in the exploit transaction.

## References
- [1] Seed tx metadata and trace for 0x16a9…4699  
  Local artifact: `artifacts/root_cause/seed/8453/0x16a9…4699`
- [2] LotteryTicketSwap50 verified source  
  Local artifact: `artifacts/root_cause/data_collector/iter_2/contract/8453/0x1721…c7C2/source/src/Contract.sol`
- [3] NostrSwap UniswapV2Pair with subPool burn  
  Local artifact: `artifacts/root_cause/data_collector/iter_2/contract/8453/0xaDcaa…1FEE/source/src/Contract.sol`
- [4] LotteryTicket50 ERC20 ticket token source  
  Local artifact: `artifacts/root_cause/seed/8453/0xf9260bb78d16286270e123642ca3de1f2289783b/src/Contract.sol`
- [5] ERC20 balance and transfer deltas for incident tx  
  Local artifact: `artifacts/root_cause/seed/8453/0x16a9…4699/balance_diff.json`
- [6] ERC20 transfer-log aggregation for USDC/NATA/ticket/LP  
  Local artifact: `artifacts/root_cause/data_collector/iter_3/tx/8453/0x16a9…4699/erc20_balance_diff_transfers.json`

## All Relevant Transactions
- Base (chainid 8453): `0x16a99aef4fab36c84ba4616668a03a5b37caa12e2fc48923dba4e711d2094699` — adversary-crafted incident transaction encompassing flash loan, exploitation, and repayment.
