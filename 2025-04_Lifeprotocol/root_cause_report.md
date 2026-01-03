# LifeProtocol USDT Drain via Mispriced Buy/Sell Under Flash Loan

## Incident Overview & TL;DR

On BNB Chain (chainid 56), a freshly deployed attacker contract obtained a DODO DPP flash loan of 110000000000000000000000 BEP20USDT and used it to repeatedly invoke LifeProtocolContract.buy(1e21) and sell(1e21), driving LifeProtocol's internal currentPrice up while draining USDT from the protocol. In a single adversary-crafted transaction (0x487fb7.. in block 48703546), LifeProtocolContract transferred a net 15114791884494874317000 USDT to the attacker EOA, while the flash-loan pool's balance returned to its pre-state.

**Root Cause (Brief):** LifeProtocol's pricing and accounting logic over-credits buyBackReserve on buys and uses that inflated buyBackReserve together with a misdefined circulatingSupply to raise currentPrice, but then honors sells at 90% of this elevated price without enforcing a consistent link between buyBackReserve, currentPrice, and actual USDT reserves, enabling a flash-loan-funded attacker to buy LIFE at progressively higher prices and immediately resell it at an even more favorable price, siphoning USDT out of the protocol.

## Key Background

- LifeProtocolContract (0x42e2..) is a custom token sale and buyback protocol that mints a fixed-supply LifeToken, holds an initial inventory of LIFE, and uses BEP20USDT as the quote asset; users buy LIFE by sending USDT and sell LIFE back to the protocol either immediately or via queued sell orders, while buyBackReserve and currentPrice track a notion of backing and price.
- LifeToken is a BEP20-style token embedded in LifeProtocolContract with totalSupply minted to the protocol; it represents the claim on USDT reserves held by LifeProtocol, but the contract's accounting logic does not maintain an invariant that buyBackReserve and currentPrice reflect actual USDT reserves.
- The protocol relies on DODO DPP at 0x6098a5638d8d7e9ed2f952d35b2b67c34ec6b476 for permissionless USDT flash loans, letting any adversary temporarily borrow large USDT amounts to trade against LifeProtocolContract without long-term capital.
- The attacker EOA 0x3026c464d3bd6ef0ced0d49e80f171b58176ce32 and helper contract 0xf6cee497dfe95a04faa26f3138f9244a4d92f942 form the core adversary cluster, with the contract orchestrating flash loans and LifeProtocol trades and the EOA deploying the contract and receiving profits.

## ACT Opportunity Reconstruction

**Pre-incident state (σ_B):** Publicly reconstructible state of BNB Chain (chainid 56) immediately before including transaction 0x487fb71e3d2574e747c67a45971ec3966d275d0069d4f9da6d43901401f8f3c0 in block 48703546, in which LifeProtocolContract (0x42e2773508e2AE8fF9434BEA599812e28449e2Cd) holds approximately 5.2702676277683292087061e22 BEP20USDT, implements the buy/sell/buyBackReserve/currentPrice logic described in its verified source, and the DODO DPP flash-loan pool 0x6098a5638d8d7e9ed2f952d35b2b67c34ec6b476 is configured with sufficient USDT liquidity to lend 110000000000000000000000 units via flashLoan().

- **Block height B:** 48703546
- **Adversary-crafted transaction b:** 0x487fb71e3d2574e747c67a45971ec3966d275d0069d4f9da6d43901401f8f3c0 on chainid 56
- **Inclusion feasibility:** An unprivileged adversary controlling EOA 0x3026c4.. (or any EOA) can deploy a helper contract similar to 0xf6cee4.., then send a 0-value transaction to that contract calling the public function corresponding to selector 0x0c96fa62 with arguments (flashLoanPool=0x6098a5.., loanAmount=110000000000000000000000, loanToken=0x55d398.., token=0x19b2834f99fb9eb4164cb5b49046ec207f894197, am1=0x32, buyer=EOA); DODO's flashLoan() is permissionless and enforces only repayment within the same transaction, and LifeProtocolContract.buy/sell are public non-owner functions with no whitelists, so standard BNB Chain transaction rules suffice to include the tx at a competitive gas price.

**Exploit predicate (profit):**
- Reference asset: USDT
- Adversary address: 0x3026c464d3bd6ef0ced0d49e80f171b58176ce32
- Value before: 0
- Value after: 15114791884494874317000
- Value delta: 15114791884494874317000
- Valuation notes: Values are taken directly from the prestate-based BEP20USDT balance diff for tx 0x487fb7.. in artifacts/root_cause/data_collector/iter_2/tx/56/0x487fb71e3d2574e747c67a45971ec3966d275d0069d4f9da6d43901401f8f3c0/balance_diff_prestate.json, which shows LifeProtocolContract losing 15114791884494874317000 USDT and the attacker EOA gaining the same amount during this transaction, while the flash-loan pool 0x6098.. has zero net USDT delta. Gas fees are paid in BNB and are not converted to USDT here, but they are small (~0.006991929 BNB) compared to the USDT profit.

## Vulnerability & Root Cause Analysis

LifeProtocol misprices LIFE relative to its USDT reserves by (a) adding the full USDT paid on buys into buyBackReserve, (b) using a circulatingSupply definition that decreases when LIFE is transferred back to the protocol, and (c) resetting currentPrice to buyBackReserve * 1e18 / circulatingSupply when buyBackReserve exceeds circulatingSupplyValue, while honoring sells at 90% of this elevated price when there is sufficient USDT on hand.

From the verified source "artifacts/root_cause/data_collector/iter_1/contract/56/0x42e2../source/src/Contract.sol", buy(uint256 lifeTokenAmount) computes totalUsdtCost = lifeTokenAmount * currentPrice / 1e18, requires it to be within [minTradeAmount, maxTradeAmount], increments buyBackReserve by totalUsdtCost, pulls that amount of USDT into the contract via UsdtToken.transferFrom, and transfers lifeTokenAmount LIFE from the protocol's inventory (remainingSupply) or from queued sell orders to the buyer. After each buy, handleRatio(totalUsdtCost) computes circulatingSupply = totalSupply - lifeToken.balanceOf(address(this)) and circulatingSupplyValue = circulatingSupply * currentPrice / 1e18; if buyBackReserve > circulatingSupplyValue it sets currentPrice = buyBackReserve * 1e18 / circulatingSupply. Sells use this currentPrice unadjusted: sell(uint256 amount) sets sellPrice = currentPrice * 90 / 100 and requiredUSDT = sellPrice * amount / 1e18, then immediately transfers amount LIFE from the seller to the protocol and requiredUSDT USDT back to the seller when UsdtToken.balanceOf(address(this)) >= requiredUSDT, while only subtracting requiredUSDT from buyBackReserve and not recomputing currentPrice.

**Vulnerable components:**
- LifeProtocolContract (0x42e2773508e2AE8fF9434BEA599812e28449e2Cd) :: buy(uint256 lifeTokenAmount)
- LifeProtocolContract (0x42e2773508e2AE8fF9434BEA599812e28449e2Cd) :: sell(uint256 amount)
- LifeProtocolContract (0x42e2773508e2AE8fF9434BEA599812e28449e2Cd) :: handleRatio(uint256 _amount)

**Exploit preconditions:**
- LifeProtocolContract must hold a large USDT reserve (on the order of 5e22 base units) so that buy() and sell() calls can be executed in sequence without hitting the minTradeAmount, maxTradeAmount, or liquidity-availability constraints.
- The attacker must be able to obtain significant USDT liquidity for a single block without bearing market risk, which is satisfied by DODO's permissionless flashLoan() on 0x6098.. lending 110000000000000000000000 USDT to 0xf6cee4.. as seen in the seed trace.
- LifeProtocol's handleRatio() must recompute currentPrice upward based on buyBackReserve and circulatingSupply after buys but must not symmetrically recompute currentPrice downward during sells; this asymmetry is present in the verified source.
- LifeProtocol's sell() must continue to treat UsdtToken.balanceOf(address(this)) as the only liquidity guard and must not recompute currentPrice downward during the sell loop; this is confirmed by the LifeProtocolContract source and the seed trace, which shows many sell(1e21) calls each paying 2343829801680218810000 USDT without any adjustment to currentPrice between sells.

**Security principles violated:**
- Lack of a conserved accounting invariant linking buyBackReserve, currentPrice, and actual USDT reserves, allowing book value to diverge arbitrarily from real backing.
- Failure to bound per-trade slippage or per-block price movement, enabling a flash-loan-funded attacker to drive currentPrice to extreme levels in a single transaction.
- Over-reliance on a single liquidity check (UsdtToken.balanceOf(address(this)) >= requiredUSDT) without reconciling price with reserves, breaking assumptions about redeemability and solvency.

**Key LifeProtocol pricing and settlement logic (excerpt):**

```solidity
    function buy(uint256 lifeTokenAmount) external nonReentrant {
        uint256 totalUsdtCost = calculateTotalCost(lifeTokenAmount);
        require(totalUsdtCost >= minTradeAmount && totalUsdtCost <= maxTradeAmount, "Invalid trade amount");

        buyBackReserve = buyBackReserve.add(totalUsdtCost);

        require(UsdtToken.transferFrom(msg.sender,address(this),totalUsdtCost),"usdt transfer failed!");

        uint256 contractTokenBalance = lifeToken.balanceOf(address(this));
        uint256 availableSupply = contractTokenBalance > queueSupply ? contractTokenBalance.sub(queueSupply) : 0;
        uint256 deficit = 0;

        if (availableSupply >= lifeTokenAmount) {
            buyFromSupply(msg.sender, lifeTokenAmount);
        } else {
            deficit = lifeTokenAmount.sub(availableSupply);
            if (availableSupply > 0) {
                buyFromSupply(msg.sender, availableSupply);
            }
            buyFromSellOrders(msg.sender, deficit);

    function sell(uint256 amount) external nonReentrant {
        require(lifeToken.balanceOf(msg.sender) >= amount, "Insufficient balance");

        bytes32 sellOrderId = generateSellOrderId();
        bytes32 previousOrderId = currentSellOrderId;

        uint256 sellPrice = currentPrice.mul(90).div(100);
        uint256 requiredUSDT = sellPrice.mul(amount).div(1e18);
        require(requiredUSDT >= minTradeAmount && requiredUSDT <= maxTradeAmount, "Invalid  Usdt trade amount");

        sellOrders[sellOrderId] = SellOrder({
            sellOrderId: sellOrderId,
            amount: amount,
            price: sellPrice,
            previous: previousOrderId,
            next: bytes32(0),
            seller: msg.sender,
            canceled: false,
            bought: false
        });

    function handleRatio(uint256 _amount) internal {
        uint256 circulatingSupply = lifeToken.totalSupply().sub(lifeToken.balanceOf(address(this)));
        uint256 circulatingSupplyValue = (circulatingSupply.mul(currentPrice)).div(1e18);

        if (buyBackReserve > circulatingSupplyValue) {
            uint256 newPrice = (buyBackReserve.mul(1e18)).div(circulatingSupply);
            currentPrice = newPrice;
            emit PriceAdjusted(newPrice);
        }else{
            uint256 priceIncrease = calculatePriceIncrease(_amount);
            currentPrice = currentPrice.add(priceIncrease);
        }
    }

    function generateSellOrderId() internal view returns (bytes32) {
        return keccak256(abi.encodePacked(block.timestamp, msg.sender, sellOrderCounter));
    }

    function updateMinMaxTradeAmount(uint256 _newMinTradeAmount, uint256 _newMaxTradeAmount) external onlyOwner {
        minTradeAmount = _newMinTradeAmount;
```

_Snippet origin: Verified LifeProtocolContract source for 0x42e2..., showing buy, sell, and handleRatio logic that couples buyBackReserve, circulatingSupply, and currentPrice._

## Adversary Flow Analysis

Single-tx, flash-loan-assisted exploit where a freshly deployed helper contract borrows USDT from a DODO DPP pool, drives LifeProtocol's internal price up via repeated buys, then drains USDT by selling at the elevated price and forwarding profits to the attacker EOA.

### Adversary Cluster & Stakeholders

- **Adversary:** 0x3026c464d3bd6ef0ced0d49e80f171b58176ce32 on BNB Chain (EOA: true, Contract: false) — Sender of the exploit transaction 0x487fb7.., deployer of attacker contract 0xf6cee4.. in tx 0x46fc9d.., and direct recipient of the net 15114791884494874317000 USDT profit as shown in balance_diff_prestate.json.
- **Adversary:** 0xf6cee497dfe95a04faa26f3138f9244a4d92f942 on BNB Chain (EOA: false, Contract: true) — Helper contract deployed by 0x3026c4.. shortly before the exploit; orchestrates DODO flashLoan, LifeProtocol buy/sell loops, and transfers USDT profits back to the EOA; decompiled code includes owner-only withdrawal to a hard-coded EOA, showing adversary control.
- **Victim candidate:** LifeProtocolContract at 0x42e2773508e2AE8fF9434BEA599812e28449e2Cd on BNB Chain (verified: true)
- **Victim candidate:** DODO DPP USDT pool at 0x6098a5638d8d7e9ed2f952d35b2b67c34ec6b476 on BNB Chain (verified: true)

### Attacker funding and priming

**Transactions:**
- BNB Chain (chainid 56), tx 0x46fc9d479b2148abfd3119ef2ba4dc476172b9899b372abfee2d2462327facc0, block 48703501, mechanism contract_deploy

The attacker EOA 0x3026c4.. deploys helper contract 0xf6cee4.. at block 48703501, establishing the adversary-controlled contract that will request the flash loan and perform LifeProtocol interactions.

_Evidence: artifacts/root_cause/data_collector/iter_2/address/56/0x3026c464d3bd6ef0ced0d49e80f171b58176ce32_tx_metadata_48703000_48704000.json; artifacts/root_cause/data_collector/iter_1/contract/56/0xf6cee497dfe95a04faa26f3138f9244a4d92f942/decompile/0xf6cee497dfe95a04faa26f3138f9244a4d92f942-decompiled.sol_

### Flash-loan acquisition and LifeProtocol price escalation

**Transactions:**
- BNB Chain (chainid 56), tx 0x487fb71e3d2574e747c67a45971ec3966d275d0069d4f9da6d43901401f8f3c0, block 48703546, mechanism flashloan

Inside the exploit transaction, 0xf6cee4.. calls DODO DPP flashLoan on 0x6098.. to borrow 110000000000000000000000 USDT, then approves LifeProtocolContract to spend its USDT and LIFE and performs multiple LifeProtocolContract.buy(1e21) calls. Each buy transfers an increasing amount of USDT from 0xf6cee4.. to LifeProtocolContract and transfers 1e21 LIFE back, increasing buyBackReserve and, via handleRatio(), pushing currentPrice higher while the contract accumulates USDT.

_Evidence: artifacts/root_cause/data_collector/iter_1/contract/56/0x6098a5638d8d7e9ed2f952d35b2b67c34ec6b476/source/src/Contract.sol (flashLoan implementation); artifacts/root_cause/seed/56/0x487fb71e3d2574e747c67a45971ec3966d275d0069d4f9da6d43901401f8f3c0/trace.cast.log (LifeProtocolContract::buy calls and increasing USDT transferFrom amounts)_

### LifeProtocol USDT drain and flash-loan repayment

**Transactions:**
- BNB Chain (chainid 56), tx 0x487fb71e3d2574e747c67a45971ec3966d275d0069d4f9da6d43901401f8f3c0, block 48703546, mechanism other

After currentPrice has been raised, 0xf6cee4.. invokes LifeProtocolContract.sell(1e21) many times; each call transfers 1e21 LIFE from 0xf6cee4.. to LifeProtocolContract and 2343829801680218810000 USDT from LifeProtocolContract to 0xf6cee4.., as shown in the trace. LifeProtocolContract does not adjust currentPrice downward during these sells, so each loop yields similar USDT proceeds. 0xf6cee4.. then repays the flash-loan principal and fees to 0x6098.. and forwards the remaining USDT to the EOA, producing a net transfer of 15114791884494874317000 USDT from LifeProtocolContract to 0x3026c4.. while leaving the flash-loan pool with no net change in balance.

_Evidence: artifacts/root_cause/seed/56/0x487fb71e3d2574e747c67a45971ec3966d275d0069d4f9da6d43901401f8f3c0/trace.cast.log (LifeProtocolContract::sell(1e21) calls and per-call USDT/LIFE transfers); artifacts/root_cause/data_collector/iter_2/tx/56/0x487fb71e3d2574e747c67a45971ec3966d275d0069d4f9da6d43901401f8f3c0/balance_diff_prestate.json (net USDT deltas for LifeProtocolContract and the EOA)_

**Seed transaction trace excerpt (cast run -vvvvv):**

```text
Executing previous transactions from the block.
Traces:
  [2638743] 0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942::0c96fa62(0000000000000000000000006098a5638d8d7e9ed2f952d35b2b67c34ec6b47600000000000000000000000000000000000000000000174b1ca8ab05a8c0000000000000000000000000000055d398326f99059ff775485246999027b319795500000000000000000000000019b2834f99fb9eb4164cb5b49046ec207f894197000000000000000000000000000000000000000000000000000000000000003200000000000000000000000042e2773508e2ae8ff9434bea599812e28449e2cd)
    ├─ [5170] 0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476::_BASE_TOKEN_() [staticcall]
    │   ├─ [2504] 0x85351262f7474Ebe23FfAcD633cf20A491F1325D::_BASE_TOKEN_() [delegatecall]
    │   │   └─ ← [Return] 0x000000000000000000000000bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c
    │   └─ ← [Return] 0x000000000000000000000000bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c
    ├─ [2560856] 0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476::flashLoan(0, 110000000000000000000000 [1.1e23], 0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942, 0x0000000000000000000000006098a5638d8d7e9ed2f952d35b2b67c34ec6b47600000000000000000000000055d398326f99059ff775485246999027b319795500000000000000000000000000000000000000000000174b1ca8ab05a8c00000)
    │   ├─ [2560645] 0x85351262f7474Ebe23FfAcD633cf20A491F1325D::flashLoan(0, 110000000000000000000000 [1.1e23], 0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942, 0x0000000000000000000000006098a5638d8d7e9ed2f952d35b2b67c34ec6b47600000000000000000000000055d398326f99059ff775485246999027b319795500000000000000000000000000000000000000000000174b1ca8ab05a8c00000) [delegatecall]
    │   │   ├─ [29971] BEP20USDT::transfer(0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942, 110000000000000000000000 [1.1e23])
    │   │   │   ├─ emit Transfer(from: 0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476, to: 0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942, value: 110000000000000000000000 [1.1e23])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 0xda240bcb2003be997a7aa4cac7bc33c203f8072b3e73229163f509befa504ab8: 0 → 0x00000000000000000000000000000000000000000000174b1ca8ab05a8c00000
    │   │   │   │   @ 0x82bcc9253272a2176c253e21a54ca24177e771a367828bd1251261eb930b899c: 0x0000000000000000000000000000000000000000000032a4dc45d89d02d1e095 → 0x000000000000000000000000000000000000000000001b59bf9d2d975a11e095
    │   │   │   └─ ← [Return] true
    │   │   ├─ [2503739] 0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942::DPPFlashLoanCall(0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942, 0, 110000000000000000000000 [1.1e23], 0x0000000000000000000000006098a5638d8d7e9ed2f952d35b2b67c34ec6b47600000000000000000000000055d398326f99059ff775485246999027b319795500000000000000000000000000000000000000000000174b1ca8ab05a8c00000)
    │   │   │   ├─ [24562] BEP20USDT::approve(LifeProtocolContract: [0x42e2773508e2AE8fF9434BEA599812e28449e2Cd], 10000000000000000000000000000000 [1e31])
    │   │   │   │   ├─ emit Approval(owner: 0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942, spender: LifeProtocolContract: [0x42e2773508e2AE8fF9434BEA599812e28449e2Cd], value: 10000000000000000000000000000000 [1e31])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0x1e642e1e5f669260912c07babb477cec60c75b0bd40c6ec271e174f85f5526ad: 0 → 0x000000000000000000000000000000000000007e37be2022c0914b2680000000
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [24739] LifeToken::approve(LifeProtocolContract: [0x42e2773508e2AE8fF9434BEA599812e28449e2Cd], 10000000000000000000000000000000 [1e31])
    │   │   │   │   ├─ emit Approval(owner: 0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942, spender: LifeProtocolContract: [0x42e2773508e2AE8fF9434BEA599812e28449e2Cd], value: 10000000000000000000000000000000 [1e31])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0x55c188064fbe546be0080eabd3553253cfdcb6cb5eccd3b06118e23f6dd23045: 0 → 0x000000000000000000000000000000000000007e37be2022c0914b2680000000
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [85457] LifeProtocolContract::buy(1000000000000000000000 [1e21])
    │   │   │   │   ├─ [10834] BEP20USDT::transferFrom(0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942, LifeProtocolContract: [0x42e2773508e2AE8fF9434BEA599812e28449e2Cd], 1583488353205082486000 [1.583e21])
    │   │   │   │   │   ├─ emit Transfer(from: 0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942, to: LifeProtocolContract: [0x42e2773508e2AE8fF9434BEA599812e28449e2Cd], value: 1583488353205082486000 [1.583e21])
    │   │   │   │   │   ├─ emit Approval(owner: 0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942, spender: LifeProtocolContract: [0x42e2773508e2AE8fF9434BEA599812e28449e2Cd], value: 9999999998416511646794917514000 [9.999e30])
    │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   @ 0xd51540a526ea40c5ed6a795989ebecdfdc610d202c1f6f8810cae8c62586a28d: 0x000000000000000000000000000000000000000000000b29048eebce86de2315 → 0x000000000000000000000000000000000000000000000b7edbdfa75dac179805
    │   │   │   │   │   │   @ 0xda240bcb2003be997a7aa4cac7bc33c203f8072b3e73229163f509befa504ab8: 0x00000000000000000000000000000000000000000000174b1ca8ab05a8c00000 → 0x0000000000000000000000000000000000000000000016f54557ef7683868b10
    │   │   │   │   │   │   @ 0x1e642e1e5f669260912c07babb477cec60c75b0bd40c6ec271e174f85f5526ad: 0x000000000000000000000000000000000000007e37be2022c0914b2680000000 → 0x000000000000000000000000000000000000007e37be1fcce9408f975ac68b10
    │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   ├─ [2651] LifeToken::balanceOf(LifeProtocolContract: [0x42e2773508e2AE8fF9434BEA599812e28449e2Cd]) [staticcall]
    │   │   │   │   │   └─ ← [Return] 14657517155429763011000525 [1.465e25]
    │   │   │   │   ├─ [651] LifeToken::balanceOf(LifeProtocolContract: [0x42e2773508e2AE8fF9434BEA599812e28449e2Cd]) [staticcall]
    │   │   │   │   │   └─ ← [Return] 14657517155429763011000525 [1.465e25]
    │   │   │   │   ├─ [27988] LifeToken::transfer(0xF6Cee497DFE95A04FAa26F3138F9244a4d92f942, 1000000000000000000000 [1e21])
```

_Snippet origin: Seed transaction trace for 0x487fb7.. showing DODO flashLoan, approvals, and the beginning of repeated LifeProtocol buy/sell calls._

## Impact & Losses

- Token: USDT, Amount: 15114791884494874317000

The exploit reduces LifeProtocolContract's BEP20USDT balance from 52702676277683292087061 to 37587884393188417770061 as recorded in balance_diff_prestate.json, a loss of 15114791884494874317000 base units (approximately 15.11 million USDT assuming 18 decimals). The DODO flash-loan pool 0x6098.. and other external protocols see no net balance change, indicating that this is a pure drain of LifeProtocol's reserves; subsequent user sell transactions after block 48703546 still succeed but are serviced from the diminished USDT pool, effectively socializing part of the losses to remaining participants.

**Prestate-based USDT balance diff (excerpt):**

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x42e2773508e2ae8ff9434bea599812e28449e2cd",
      "before": "52702676277683292087061",
      "after": "37587884393188417770061",
      "delta": "-15114791884494874317000",
      "balances_slot": "1",
      "slot_key": "0xd51540a526ea40c5ed6a795989ebecdfdc610d202c1f6f8810cae8c62586a28d",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x3026c464d3bd6ef0ced0d49e80f171b58176ce32",
      "before": "0",
      "after": "15114791884494874317000",
      "delta": "15114791884494874317000",
      "balances_slot": "1",
      "slot_key": "0x87c83e759d7b138d17b0e45f5f685f0c63524d86ad54e2a2f032a714b034a9ee",
      "contract_name": "BEP20USDT"
    }
  ]
}
```

_Snippet origin: debug_traceTransaction prestateTracer diff for the seed tx, showing LifeProtocolContract losing and the attacker EOA gaining 15114791884494874317000 USDT while the flash-loan pool has zero net USDT delta._

## References

- [1] Seed transaction trace for 0x487fb7..: artifacts/root_cause/seed/56/0x487fb71e3d2574e747c67a45971ec3966d275d0069d4f9da6d43901401f8f3c0/trace.cast.log
- [2] LifeProtocolContract and LifeToken verified source: artifacts/root_cause/data_collector/iter_1/contract/56/0x42e2773508e2AE8fF9434BEA599812e28449e2Cd/source/src/Contract.sol
- [3] Prestate-based USDT balance diff for seed tx: artifacts/root_cause/data_collector/iter_2/tx/56/0x487fb71e3d2574e747c67a45971ec3966d275d0069d4f9da6d43901401f8f3c0/balance_diff_prestate.json
- [4] Attacker EOA and contract tx metadata around incident: artifacts/root_cause/data_collector/iter_2/address/56/0x3026c464d3bd6ef0ced0d49e80f171b58176ce32_tx_metadata_48703000_48704000.json
- [5] DODO DPP flashLoan pool source: artifacts/root_cause/data_collector/iter_1/contract/56/0x6098a5638d8d7e9ed2f952d35b2b67c34ec6b476/source/src/Contract.sol