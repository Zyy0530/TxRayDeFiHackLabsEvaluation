# Pump / IPShare Launch-Phase AMM Listing Exploit on BNB Chain

## Incident Overview & TL;DR

On BNB Chain, an unprivileged adversary used a single flash-loan-based contract-creation transaction (tx `0xdebaa13fb06134e63879ca6bcb08c5e0290bdbac3acf67914c0b1dcaf0bdc3dd`, block 47,169,116) to exploit the launch-phase design of Pump tokens integrated with the IPShare fee-sharing contract. The Token.sol implementation accumulates BNB from user bonding-curve buys inside the Token contract before any AMM pool exists, and then, on the first listing, uses the entire contract BNB balance to seed a PancakeSwap pool with LP tokens burned.

The attacker borrowed 100 WBNB via a Pancake V3 flash loan, executed scripted bonding-curve buys across four Pump tokens to trigger Token._makeLiquidityPool for each, then traded freshly-minted tokens against the new pools to drain the BNB that earlier users had paid into the bonding curves. After repaying the flash loan and gas, the attacker realized a net profit of **11.279016463051366537 BNB**, while the four Pump Token contracts lost essentially their entire BNB balances.

The root cause is a protocol-level design flaw: the launch-phase bonding-curve / AMM listing mechanism allows an unprivileged actor who arrives at the listing boundary to consume all accumulated BNB liquidity, with LP tokens burned, leaving ordinary token holders exposed to adverse pricing and reduced liquidity.

## Key Background

### Protocol Components

- **Pump Tokens (Token.sol)** on BNB Chain: four affected tokens share the same Token.sol implementation and are created via a Pump manager contract:
  - `0x09762e00Ce0DE8211F7002F70759447B1F2b1892`
  - `0x02E8eAd6De82c8a248eF0EebE145295116D0E4C2`
  - `0x6B7e9Be56cA035D3471dA76caa99f165449697A0`
  - `0xBa0D236fBCbd34052cdAB29c4900063F9eFE6E4F`
- **IPShare fee-sharing contract (IPShare.sol)** at `0x7B0ddC305C32AAEbabc0FE372a4460e9903e95D0`, which distributes subject and protocol fees.
- **Pump manager** at `0x5c952063c7fc8610ffdb798152d69f0b9550762b`, responsible for creating Pump tokens and configuring fee parameters.
- **PancakeSwap liquidity venues**:
  - Pancake V3 pool: `0x172fcD41E0913e95784454622d1c3724f546f849` (used for 100 WBNB flash loan).
  - Pancake V2 pairs for each Pump token (created at listing time by Token._makeLiquidityPool).
- **WBNB** at `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`.

A representative victim-user buy and the Pump manager createToken transaction are used as evidence:
- Pump manager `createToken` tx: `0x0ea24a6d9413774877eed068cf9f71a71981e68ab5f81581fc072767afe1976b` (block 46,729,477).
- Representative user `buyToken` tx: `0xa9da38df1f89568beb79c41175c1f67dbe11f8c9bc953d9aff51126478b32a2c` (block 47,165,510).

### Pre-State and Victim Lifecycle

Before the attacker transaction, the BNB Chain state (block 47,169,116−1) includes:

- Deployed Pump Token contracts for the four affected tokens.
- IPShare deployed and configured for fee sharing.
- Pump manager with configuration pointing tokens to IPShare and fee receiver.
- PancakeSwap V3 pool and prospective V2 factories/routers.
- EOAs representing the Pump subjects and fee receiver.

Users have already interacted with the Pump tokens via `Token.buyToken`, sending BNB into the bonding curve and building up BNB balances in each Token contract, while a fraction of each payment is routed to IPShare and the subject EOAs.

#### Evidence: Victim Buy Trace

Representative user buy trace for one Pump token:

```text
# Seed transaction trace for representative user buy (tx 0xa9da38df...)
[137428] Token::buyToken{value: 100000000000000000}(8971862248605525987358227 [8.971e24], 0x0000000000000000000000000000000000000000, 500, 0x0000000000000000000000000000000000000000)
  ├─ IPShare::valueCapture{value: 1000000000000000}(0xE59beA87b948Fd7462206Cfd3AE0bfd523097547)
  └─ ...
```

*Caption: User calls `Token.buyToken` with 0.1 BNB; part of the payment is routed to `IPShare.valueCapture` as subject/protocol fees, and the rest remains in the Token contract, contributing to its BNB reserves.*

### Token.sol Launch-Phase Design

The Token.sol implementation for Pump tokens has three key properties that shape the exploit:

1. **Bonding-curve buys accumulate BNB in the Token contract.** Users send BNB to `buyToken`, which splits funds into protocol fee, subject fee (via IPShare), and bonding-curve payments.
2. **Listing is triggered when the bonding curve is filled.** When cumulative purchased supply reaches `bondingCurveTotalAmount`, `buyToken` triggers `_makeLiquidityPool`.
3. **Listing uses the entire Token contract BNB balance as liquidity, with LP tokens burned.** `_makeLiquidityPool` sends all BNB in the Token contract plus a fixed token amount as liquidity to PancakeRouter, and LP tokens are minted to the burn address.

#### Evidence: Token.buyToken and _makeLiquidityPool

From a verified Pump Token.sol:

```solidity
function buyToken(
    uint256 expectAmount,
    address sellsman,
    uint16 slippage,
    address receiver
) public payable nonReentrant returns (uint256) {
    // ... split msg.value into protocol fee, subject fee, and bonding-curve funds
    uint256[2] memory feeRatio = IPump(manager).getFeeRatio();
    uint256 buyFunds = msg.value;
    uint256 tiptagFee = (msg.value * feeRatio[0]) / divisor;
    uint256 sellsmanFee = (msg.value * feeRatio[1]) / divisor;

    uint256 tokenReceived = bondingCurve
        .getBuyAmountByValue(bondingCurveSupply, buyFunds - tiptagFee - sellsmanFee);

    // when bondingCurveSupply reaches bondingCurveTotalAmount, trigger listing
    if (tokenReceived + bondingCurveSupply >= bondingCurveTotalAmount) {
        uint256 actualAmount = bondingCurveTotalAmount - bondingCurveSupply;
        uint256 usedEth = bondingCurve.getBuyPriceAfterFee(bondingCurveSupply, actualAmount);
        // ... adjust fees and refund excess, then route fees
        IIPShare(IPump(manager).getIPShare()).valueCapture{value: sellsmanFee}(sellsman);
        _makeLiquidityPool();
    }
    // ...
}
```

*Caption: `buyToken` accumulates BNB in the Token contract via the bonding curve and, when the curve is filled, routes fees and calls `_makeLiquidityPool` to list on an AMM.*

The `_makeLiquidityPool` helper (not fully reproduced here) uses the current Token contract BNB balance along with a fixed token amount (`liquidityAmount`) to call PancakeRouter `addLiquidityETH`, with LP tokens minted to the burn address `0x000000000000000000000000000000000000dEaD`. This design hard-wires that **all accumulated BNB in the Token contract is injected as liquidity at the moment of first listing, and no LP tokens remain under the control of users or the protocol**.

### IPShare Fee-Sharing Behavior

The IPShare contract is a standard fee-sharing mechanism that records subject balances and protocol fees; it does not grant any special privilege to the attacker.

#### Evidence: IPShare.valueCapture

From the verified IPShare.sol:

```solidity
function valueCapture(address subject) external payable override nonReentrant {
    uint256 protocolFee = (msg.value * donutFeePercent) / 10000;
    uint256 subjectFee = (msg.value * subjectFeePercent) / 10000;

    // update accounting and route fees
    ipshareAcc[subject] += msg.value;
    _ipshareSupply[subject] += subjectFee;

    // distribute fees
    (bool ok1, ) = donutFeeDestination.call{value: protocolFee}("");
    require(ok1, "Fee transfer failed");
    (bool ok2, ) = subject.call{value: subjectFee}("");
    require(ok2, "Subject transfer failed");
}
```

*Caption: `IPShare.valueCapture` takes a fee value, updates subject accounting, and forwards protocol and subject portions; there is no attacker-specific privilege or hidden backdoor.*

## Vulnerability & Root Cause Analysis

### Root Cause Summary

The core vulnerability is a **launch-phase design flaw** in the combination of Pump Token.sol and the listing process:

- User `buyToken` calls accumulate BNB inside the Token contract, minus the fee portions routed to IPShare and the subject.
- When cumulative purchases reach the configured threshold, `Token._makeLiquidityPool` creates a Pancake V2 pair and sends **all BNB held by the Token contract** into the liquidity pool along with a fixed amount of tokens, minting LP tokens directly to the burn address.
- This means the **entire accumulated BNB reserve is exposed in a single event and is not backed by any reclaimable LP position**.
- An unprivileged actor who reaches the listing boundary first can execute a scripted sequence of buys and swaps to position themselves optimally against the new pool and extract most of that BNB, leaving downstream users with a degraded price and lower liquidity.

This is a protocol-level economic and design bug, not an implementation bug such as reentrancy or arithmetic overflow.

### Evidence from On-Chain Traces and Balances

#### Attacker Transaction Metadata

The attacker transaction is fully captured in the seed metadata and trace:

```json
{
  "chainid": 56,
  "txhash": "0xdebaa13fb06134e63879ca6bcb08c5e0290bdbac3acf67914c0b1dcaf0bdc3dd",
  "etherscan": {
    "tx": {
      "from": "0x5d6e908c4cd6eda1c2a9010d1971c7d62bdb5cd3",
      "to": null,
      "gas": "0x70023d",
      "gasPrice": "0xb2d05e00",
      "value": "0x0",
      "type": "0x2"
    }
  }
}
```

*Caption: Metadata for the attacker tx shows a type-2 contract-creation transaction from EOA `0x5d6e90...`, with no privileged recipient and zero native value, consistent with an unprivileged deployment and execution bundle.*

#### Attacker Trace: Flash Loan and Exploit Bundle

The attacker trace shows the helper contract deploying, taking a flash loan, and executing the exploit sequence. Representative excerpt:

```text
# Seed transaction trace (tx 0xdebaa13f...)
[4067361] → new <unknown>@0x7F5CC1dA06A2bE247b7a8C3f416B9019d9356156(...)
  ├─ ... deploy helper 0x0E220c6c52d383869A5085Ef074b6028254b3462
  ├─ Pancake V3 pool 0x172fcD41E0913e95784454622d1c3724f546f849::flashLoan(100 WBNB)
  ├─ WBNB::withdraw{value: 100000000000000000000}()
  ├─ Token::buyToken(...)   # small buy for each Pump token, routes fees via IPShare
  ├─ Token::buyToken(...)   # large buy that fills bonding curve and calls _makeLiquidityPool
  ├─ PancakeRouter::addLiquidityETH(...)  # uses entire Token contract BNB balance
  ├─ PancakeRouter::swapExactTokensForTokensSupportingFeeOnTransferTokens(...)
  ├─ WBNB::deposit{value: ...}()
  ├─ WBNB::transfer(..., 100 WBNB + 0.01 WBNB fee)
  └─ send remaining BNB to 0x5d6e90...
```

*Caption: Attacker helper contract executes a full flash-loan cycle, orchestrating bonding-curve buys, liquidity creation using the Token contract’s BNB, and swaps that pull BNB from the new pools back to the attacker before repaying the loan.*

#### Balance Diff: Victims and Profit

The balance diff for the attacker transaction shows contract balances going to zero and the attacker’s BNB increasing:

```json
{
  "native_balance_deltas": [
    { "address": "0x09762e00ce0de8211f7002f70759447b1f2b1892", "delta_wei": "-2893521317894059345" },
    { "address": "0x02e8ead6de82c8a248ef0eebe145295116d0e4c2", "delta_wei": "-3109252240500162925" },
    { "address": "0x6b7e9be56ca035d3471da76caa99f165449697a0", "delta_wei": "-5626492246710979718" },
    { "address": "0xba0d236fbcbd34052cdab29c4900063f9efe6e4f", "delta_wei": "-1289879757209749671" },
    { "address": "0x7b0ddc305c32aaebabc0fe372a4460e9903e95d0", "delta_wei": "636583631546383963" },
    { "address": "0x06deb72b2e156ddd383651ac3d2dab5892d9c048", "delta_wei": "701610991758111349" },
    { "address": "0x5d6e908c4cd6eda1c2a9010d1971c7d62bdb5cd3", "delta_wei": "11279016463051366537" }
  ]
}
```

*Caption: Balance diffs for the attacker tx show the four Pump Token contracts losing their entire recorded BNB balances, IPShare and the fee receiver gaining standard fee amounts, and the attacker EOA gaining 11.279016463051366537 BNB (11279016463051366537 wei) net of gas.*

Summing all `native_balance_deltas` yields a net `-0.011878983 BNB`, matching `gasUsed * gasPrice`, confirming consistency between balances and gas accounting.

### Why the ACT Requirements Are Met

- **Unprivileged adversary:** The attacker EOA has no administrative or whitelisted role in Pump, IPShare, or the Token contracts. All interactions go through public entrypoints (Pump.createToken, Token.buyToken, IPShare.valueCapture, router functions, Pancake pools).
- **Constructible from public information:** The helper contract logic and transaction parameters reference only publicly available contracts and state (Pump tokens, IPShare, Pancake pools, WBNB). There is no dependence on private orderflow or consensus privileges.
- **Profitable outcome:** The balance diff shows the attacker’s native balance rising by 11.279016463051366537 BNB after paying gas and the flash-loan fee.

## Adversary Flow Analysis

### Attacker and Related Accounts

- **Attacker EOA:** `0x5d6e908c4cd6eda1c2a9010d1971c7d62bdb5cd3` (sender of tx `0xdebaa13f...c3dd`).
- **Helper contract:** `0x0E220c6c52d383869A5085Ef074b6028254b3462` (deployed in the attacker tx and used to orchestrate the flash loan and exploit sequence).
- **Victim Pump Tokens:** `0x0976...`, `0x02e8...`, `0x6b7e...`, `0xba0d...` (Token.sol clones).
- **IPShare contract:** `0x7B0d...` (fee-sharing).
- **Fee receiver:** `0x06Deb72b2e156Ddd383651aC3d2dAb5892d9c048`.
- **Subject EOAs:** `0xE59bea87b948fd7462206cfd3ae0bfd523097547`, `0xD46b2d47aea7E6fFE544dB4Bd13E60D6cf138B7a`, `0x499E8CcB1dbcc72609b5eEE76bd9890618d74B9f`, `0x76166B81ebBf6F4C1be871f112aeac01d2888888`.

The clustering of these addresses is supported by the attacker trace and the balance diff, which show standard fee flows to IPShare and subject EOAs, and profit accumulation at the attacker EOA.

### Lifecycle Stages

1. **Victim token deployment and configuration**
   - Pump manager `createToken` tx `0x0ea24a6d...` creates and configures Pump tokens, setting bonding-curve parameters, IPShare address, fee receiver, and subjects.
   - Result: Users can subsequently buy tokens via the bonding curve, with fees routed to IPShare and subjects.

2. **User trading and reserve accumulation**
   - Ordinary users call `Token.buyToken` (e.g., tx `0xa9da38df...`), sending BNB into the bonding curves.
   - A portion of each buy flows through `IPShare.valueCapture`, and the remainder remains in the Token contracts, building BNB reserves with no AMM pool yet created.

3. **Adversary flash-loan exploit bundle**
   - The attacker contract-creation tx `0xdebaa13f...` deploys the helper and borrows 100 WBNB from Pancake V3.
   - For each Pump token, the helper executes:
     - A small `buyToken` to route fees and prepare for listing.
     - A large `buyToken` that pushes `bondingCurveSupply` to `bondingCurveTotalAmount`, triggering `_makeLiquidityPool`.
     - `_makeLiquidityPool` sends the entire Token contract BNB balance plus a fixed token amount into `addLiquidityETH`, with LP tokens burned.
     - The helper then swaps newly minted tokens against the fresh pools using Pancake router functions, draining BNB out of the pools.
   - The helper repays the flash loan plus 0.01 BNB, unwraps remaining WBNB, and forwards the residual BNB (11.290895446051366537 BNB) back to the attacker EOA.

### Exploit PnL and Flows

- **Reference asset:** BNB.
- **Attacker address:** `0x5d6e90...`.
- **Fees paid:**
  - Gas: `0.011878983 BNB` (11878983000000000 wei).
  - Flash-loan fee: `0.01 BNB` to Pancake V3 pool `0x172f...`.
- **Value before:** `0.080195846886051890 BNB` on the attacker EOA.
- **Value after:** `11.359212309937418427 BNB` on the attacker EOA.
- **Net delta:** `+11.279016463051366537 BNB`.

Victim asset changes (from balance diffs):
- `BNB` held by Pump Token `0x0976...`: `-2.893521317894059345` BNB.
- `BNB` held by Pump Token `0x02e8...`: `-3.109252240500162925` BNB.
- `BNB` held by Pump Token `0x6b7e...`: `-5.626492246710979718` BNB.
- `BNB` held by Pump Token `0xba0d...`: `-1.289879757209749671` BNB.
- `BNB` held by IPShare `0x7B0d...`: `+0.636583631546383963` BNB.
- `BNB` held by fee receiver `0x06Deb7...`: `+0.701610991758111349` BNB.

These numbers confirm that **the Pump Token contracts are the economic victims**, losing the BNB that earlier users deposited via the bonding curve, while IPShare and subject EOAs receive only their standard fee shares.

## Impact & Losses

- **Direct on-chain loss:** Approximately **11.28 BNB** in aggregate BNB reserves drained from the four Pump Token contracts into the attacker’s account, after accounting for gas.
- **Liquidity and pricing impact:** Because LP tokens for the new Pancake V2 pairs are burned, the pools are left with reduced BNB liquidity and altered token prices after the attacker’s trades, degrading the position of remaining token holders.
- **User impact:** Users who previously bought tokens on the bonding curve funded the BNB reserves that were later siphoned by the attacker. Their effective exit prices and liquidity on PancakeSwap are materially worse than implied by the intended Pump launch design.

## References

Key supporting artifacts (from the analysis environment):

1. **Attacker tx 0xdebaa13f...c3dd trace and balance diff**
   - Seed metadata, full trace, and balance diff under the seed directory.
2. **Pump Token.sol sources for affected tokens**
   - Verified Token.sol implementations for each Pump token address.
3. **IPShare.sol verified source**
   - Verified IPShare source for address `0x7B0ddC305C32AAEbabc0FE372a4460e9903e95D0`.
4. **Pump.createToken and representative user buyToken traces**
   - `createToken` and `buyToken` traces for the Pump manager and user interactions, illustrating how BNB reserves build up before listing.

These artifacts collectively support the conclusion that the exploit arises from a launch-phase design flaw in the Pump / IPShare / Token.sol integration, rather than from a lower-level implementation bug, and that an unprivileged adversary captured a deterministic and repeatable ACT opportunity.
