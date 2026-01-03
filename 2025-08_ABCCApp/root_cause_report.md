# ABCCApp Flash-Loan Price Manipulation Incident Root Cause Report

## Incident Overview TL;DR

On BNB Chain, an adversary EOA 0x53feee33527819bb793b72bd67dbf0f8466f7d2c used a helper contract 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24 to take a 12,500 USDT flash loan, manipulate Pancake V3 DDDD/BNB and BNB/USDT pools during a single ABCCApp::deposit call, and extract 10,062.227353368914282796 USDT of net profit (after gas, under a conservative fee valuation).

ABCCApp computes DDDD rewards from instantaneous Pancake V3 slot0 prices of thinly traded DDDD/BNB and BNB/USDT pools, without TWAP or liquidity/volatility guards, allowing a flash-loan-funded adversary to temporarily skew these spot prices within a single transaction and force ABCCApp to over-distribute DDDD that can be swapped back to USDT for deterministic profit.

## Key Background

- ABCCApp 0x1bC016C00F8d603c41A582d5Da745905B9D034e5 is a BNB Chain protocol that accepts BEP20USDT deposits and rewards users in DDDD 0x422cBee1289AAE4422eDD8fF56F6578701Bb2878 based on on-chain price feeds.
- DDDD and USDT prices in ABCCApp are derived from Pancake V3 DDDD/BNB pool 0xB7021120a77d68243097BfdE152289DB6d623407 and BNB/USDT pool 0x36696169C63e42cd08ce11f5deeBbCeBae652050 via ABCCApp.getTokenPriceInBNB() and ABCCApp.getBNBPriceInUSDT(), both of which read pool slot0 and related data directly.
- ABCCApp's reward logic allows deposit and reward calculation to occur atomically inside a single transaction, so pool state changes that occur during the transaction immediately affect the effective DDDD-per-USDT rate applied to that deposit.
- The adversary's helper contract 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24 is deployed by the adversary EOA shortly before the incident and is used to orchestrate the flash loan, the ABCCApp interaction, and the follow-up swaps on Pancake V3 pools and SwapRouter 0x1b81D678ffb9C0263b24A97847620C99d213eB14.
- Flash loans are obtained from a public frontend 0x8F73b65B4caAf64FBA2aF91cC5D4A2A1318E5D8C that interacts with Moolah 0x75C42E94dcF40e57AC267FfD4DABF63F97059686::flashLoan, which provides uncollateralized USDT borrowing within a single transaction as long as the loan and fee are repaid before the transaction ends.

## Vulnerability Analysis

ABCCApp's on-chain price oracle reads instantaneous Pancake V3 slot0 prices from DDDD/BNB and BNB/USDT pools without TWAP or liquidity/volatility guards, and uses these values directly to compute DDDD rewards for USDT deposits, making reward size fully sensitive to short-lived, flash-loan-driven price spikes within a single transaction.

ABCCApp.sol implements functions getTokenPriceInBNB() and getBNBPriceInUSDT() that query Pancake V3 DDDD/BNB pool 0xB7021120a77d68243097BfdE152289DB6d623407 and BNB/USDT pool 0x36696169C63e42cd08ce11f5deeBbCeBae652050. These functions use the pools' slot0 values and related data to compute the current DDDD/BNB and BNB/USDT exchange rates, and ABCCApp then multiplies these rates to derive a DDDD-per-USDT conversion used in its reward and claim logic. The contract does not take a time-weighted average, does not enforce minimum liquidity or price bounds, and does not separate the deposit of USDT from the reward distribution in time. As a result, any actor who can temporarily distort the Pancake V3 pools' prices during an ABCCApp::deposit call can force ABCCApp to over-issue DDDD.

In tx 0xee4eae6f..., the adversary's helper contract 0x90e076... draws a 12,500 USDT flash loan from Moolah via 0x8F73..., approves ABCCApp, and calls ABCCApp::deposit with the full flash-loaned amount. Inside this single transaction, ABCCApp pulls the USDT, reads the manipulated Pancake V3 prices, and transfers a large amount of DDDD out: balance_diff shows ABCCApp losing 2,959,187,886,413,170,131,219,626 DDDD (delta -2959187886413170131219626) to the DDDD/BNB pool and vaultAddr 0xa446DC212f4AaE662e1B5fF8729e99A4eFE7a174 combined. SwapRouter then routes part of this DDDD through the DDDD/BNB and BNB/USDT pools back into USDT. At the end of the trace, the flash loan is fully repaid and the adversary EOA holds an additional 10,062.258375072914282796 USDT.

A normal ABCCApp deposit (tx 0xbc1a33ff...) and a normal claimDDDD flow (tx 0xf477798e...) show that when pool prices are not being skewed, ABCCApp's DDDD balance increases and no immediate USDT profit is realized by the caller: DDDD moves from the DDDD/BNB pool into ABCCApp, and users accrue DDDD rather than draining the contract and the pool. The contrast between these normal traces and the flash-loan trace demonstrates that the exploited behavior is the contract's reliance on instantaneous AMM spot prices during a combined deposit-and-claim path, without any TWAP, volatility checks, or circuit breakers. This design allows a single, adversary-crafted transaction to convert a temporary AMM price spike into a large, protocol-borne transfer of DDDD that can be swapped into USDT for deterministic profit.

**Vulnerable components**
- ABCCApp 0x1bC016C00F8d603c41A582d5Da745905B9D034e5: price oracle and reward calculation in getTokenPriceInBNB(), getBNBPriceInUSDT(), and deposit/claim logic.
- Pancake V3 DDDD/BNB pool 0xB7021120a77d68243097BfdE152289DB6d623407: provides manipulable DDDD/BNB spot price used directly by ABCCApp.
- Pancake V3 BNB/USDT pool 0x36696169C63e42cd08ce11f5deeBbCeBae652050: provides manipulable BNB/USDT spot price used directly by ABCCApp.
- Flash-loan infrastructure 0x8F73b65B4caAf64FBA2aF91cC5D4A2A1318E5D8C and 0x75C42E94dcF40e57AC267FfD4DABF63F97059686: supplies transient USDT capital that makes large, within-tx price swings cheap to execute.

**ACT exploit conditions**
- ABCCApp must continue to compute the DDDD-per-USDT reward rate from instantaneous Pancake V3 DDDD/BNB and BNB/USDT slot0 readings without using TWAP, liquidity checks, or volatility constraints.
- Pancake V3 DDDD/BNB and BNB/USDT pools must have sufficient liquidity and routing support via SwapRouter for a flash-loan borrower to push prices away from fundamental levels within a single transaction and then unwind back to approximate pre-state levels after ABCCApp has computed rewards.
- Flash-loan infrastructure (Moolah and its frontend) must remain publicly accessible so that any unprivileged EOA can borrow enough USDT in a single transaction to move the AMM prices in the required direction.
- ABCCApp must allow deposit and reward computation to occur atomically inside one transaction, so that manipulated AMM prices directly determine the DDDD amount sent to the caller in that same transaction.

**Security principles violated**
- Use of raw AMM spot prices from low-liquidity pools as an oracle for protocol-critical reward calculations, instead of robust TWAP oracles or dedicated price feeds.
- Failure to account for adversarial, flash-loan-driven state changes within a single transaction, violating standard assumptions about oracle design under MEV and searcher activity.
- Lack of invariants or caps on per-deposit rewards, allowing a single deposit to drain a large fraction of the protocol's accumulated DDDD due to transient price manipulation.

## Detailed Root Cause Analysis

**ACT vs non-ACT determination**

- `is_act`: true (ACT opportunity confirmed on BNB Chain block 58615055)
- Reference asset: USDT
- Adversary address: 0x53feee33527819bb793b72bd67dbf0f8466f7d2c
- Value before: 0 USDT
- Value after: 10062.258375072914282796 USDT
- Gas fees (in USDT): 0.031021704
- Net profit: 10062.227353368914282796 USDT

Reference asset is BEP20USDT 0x55d398326f99059fF775485246999027B3197955 with 18 decimals. The balance_diff for tx 0xee4eae6f... shows EOA 0x53feee33527819bb793b72bd67dbf0f8466f7d2c changing from 0 to 10062258375072914282796 USDT units, so value_before_in_reference_asset = 0 and value_after_in_reference_asset = 10062.258375072914282796 USDT. The native_balance_deltas record that the same EOA spends 77554260000000 wei of BNB as gas in this tx, which is 0.00007755426 BNB. To express gas in USDT we adopt a conservative modeling assumption that BNB price at block 58615055 is 400 USDT per BNB, giving fees_paid_in_reference_asset = 0.00007755426 * 400 = 0.031021704 USDT. Net profit in the reference asset is value_after_in_reference_asset minus fees_paid_in_reference_asset, i.e., value_delta_in_reference_asset = 10062.227353368914282796 USDT. Under any lower BNB/USDT price at that block, the true gas fee would be smaller and the net USDT profit larger, so this computation yields a deterministic lower bound on the adversary's profit in USDT.

**Pre-state and transaction sequence**

Publicly reconstructible BNB Chain state at block 58615055 immediately before inclusion of tx 0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12, including balances and contract code for ABCCApp 0x1bC016C00F8d603c41A582d5Da745905B9D034e5, Pancake V3 pools 0xB7021120a77d68243097BfdE152289DB6d623407 (DDDD/BNB) and 0x36696169C63e42cd08ce11f5deeBbCeBae652050 (BNB/USDT), flash-loan infrastructure (0x8F73b65B4caAf64FBA2aF91cC5D4A2A1318E5D8C, 0x75C42E94dcF40e57AC267FfD4DABF63F97059686), and BEP20USDT 0x55d398326f99059fF775485246999027B3197955.

Key evidence for pre-state reconstruction:
- /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/seed/56/0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12/metadata.json
- /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/seed/56/0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12/trace.cast.log
- /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/seed/56/0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12/balance_diff.json
- /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/data_collector/iter_1/contract/56/0x1bC016C00F8d603c41A582d5Da745905B9D034e5/source/src/contract/abcc/ABCCApp.sol
- /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/data_collector/iter_1/contract/56/0xB7021120a77d68243097BfdE152289DB6d623407/source/src/PancakeV3Pool.sol
- /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/data_collector/iter_1/contract/56/0x36696169C63e42cd08ce11f5deeBbCeBae652050/source/src/PancakeV3Pool.sol
- /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/data_collector/iter_1/contract/56/0x1b81D678ffb9C0263b24A97847620C99d213eB14/source/src/SwapRouter.sol
- /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/data_collector/iter_1/contract/56/0x75C42E94dcF40e57AC267FfD4DABF63F97059686/source/src/moolah/Moolah.sol

- Tx 1 on chain 56 hash 0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12 (adversary-crafted): Any unprivileged BNB Chain EOA can submit tx 0xee4eae6f... with the same calldata to helper contract 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24, which then uses public flash-loan infrastructure (0x8F73b65B4caAf64FBA2aF91cC5D4A2A1318E5D8C, 0x75C42E94dcF40e57AC267FfD4DABF63F97059686), ABCCApp 0x1bC016C0..., and Pancake V3 pools 0xB7021120... and 0x36696169...; no whitelists or privileged roles are required, so any searcher with sufficient gas and USDT approvals can reproduce this call under standard BNB Chain rules.
  - Notes: Single transaction b[1] encompasses flash-loan drawdown, ABCCApp::deposit and reward computation using manipulated Pancake V3 prices, swaps on DDDD/BNB and BNB/USDT pools, and flash-loan repayment with residual USDT profit to adversary EOA 0x53feee33527819bb793b72bd67dbf0f8466f7d2c.

**Code and trace evidence excerpts**

Seed transaction trace excerpt for tx 0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12:

```text
Warning: This is a nightly build of Foundry. It is recommended to use the latest stable version. To mute this warning set `FOUNDRY_DISABLE_NIGHTLY_WARNING` in your environment. 

Executing previous transactions from the block.
Traces:
  [901468] 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24::b99082d3(0000000000000000000000001bc016c00f8d603c41a582d5da745905b9d034e50000000000000000000000000000000000000000000002a5a058fc295ed00000fe00000000000000000000000000000000000000000000000000000000000000)
    ├─ [869465] 0x8F73b65B4caAf64FBA2aF91cC5D4a2A1318E5D8C::flashLoan(BEP20USDT: [0x55d398326f99059fF775485246999027B3197955], 12500000000000000000000 [1.25e22], 0x0000000000000000000000001bc016c00f8d603c41a582d5da745905b9d034e50000000000000000000000000000000000000000000002a5a058fc295ed00000b99082d300000000000000000000000000000000000000000000000000000000f700000000000000000000000000000000000000000000000000000000000000)
    │   ├─ [864616] 0x75C42E94dcF40e57AC267FfD4DABF63F97059686::flashLoan(BEP20USDT: [0x55d398326f99059fF775485246999027B3197955], 12500000000000000000000 [1.25e22], 0x0000000000000000000000001bc016c00f8d603c41a582d5da745905b9d034e50000000000000000000000000000000000000000000002a5a058fc295ed00000b99082d300000000000000000000000000000000000000000000000000000000f700000000000000000000000000000000000000000000000000000000000000) [delegatecall]
    │   │   ├─ emit FlashLoan(param0: 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24, param1: BEP20USDT: [0x55d398326f99059fF775485246999027B3197955], param2: 12500000000000000000000 [1.25e22])
    │   │   ├─ [29971] BEP20USDT::transfer(0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24, 12500000000000000000000 [1.25e22])
    │   │   │   ├─ emit Transfer(from: 0x8F73b65B4caAf64FBA2aF91cC5D4a2A1318E5D8C, to: 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24, value: 12500000000000000000000 [1.25e22])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 0xc8737a1a7dc859e693c17e576af6a39e8f99898023aaf88112357c0c933ab7f1: 0x0000000000000000000000000000000000000000000ac744cf054f39b7ca3b6c → 0x0000000000000000000000000000000000000000000ac49f2eac531058fa3b6c
    │   │   │   │   @ 0xeee869046b2edce3210d5bd4957f6841e9c44a973aa8294d8b6ebbdc49f7c390: 0 → 0x0000000000000000000000000000000000000000000002a5a058fc295ed00000
    │   │   │   └─ ← [Return] true
    │   │   ├─ [816355] 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24::onMoolahFlashLoan(12500000000000000000000 [1.25e22], 0x0000000000000000000000001bc016c00f8d603c41a582d5da745905b9d034e50000000000000000000000000000000000000000000002a5a058fc295ed00000b99082d300000000000000000000000000000000000000000000000000000000f700000000000000000000000000000000000000000000000000000000000000)
    │   │   │   ├─ [24562] BEP20USDT::approve(0x8F73b65B4caAf64FBA2aF91cC5D4a2A1318E5D8C, 12500000000000000000000 [1.25e22])
    │   │   │   │   ├─ emit Approval(owner: 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24, spender: 0x8F73b65B4caAf64FBA2aF91cC5D4a2A1318E5D8C, value: 12500000000000000000000 [1.25e22])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0x6cdb81ce2fc842e94a8107333063c92cda4958f082c787651cee001db6722dc3: 0 → 0x0000000000000000000000000000000000000000000002a5a058fc295ed00000
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [24562] BEP20USDT::approve(0x1bC016C00F8d603c41A582d5Da745905B9D034e5, 12500000000000000000000 [1.25e22])
    │   │   │   │   ├─ emit Approval(owner: 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24, spender: 0x1bC016C00F8d603c41A582d5Da745905B9D034e5, value: 12500000000000000000000 [1.25e22])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0xa3cbebf59e2ebdc44992a7408107001ef3db1290be978ec6d393078b46efaef0: 0 → 0x0000000000000000000000000000000000000000000002a5a058fc295ed00000
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [460692] 0x1bC016C00F8d603c41A582d5Da745905B9D034e5::deposit(125, 0x0000000000000000000000000000000000000000)
    │   │   │   │   ├─ [27934] BEP20USDT::transferFrom(0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24, 0x1bC016C00F8d603c41A582d5Da745905B9D034e5, 12500000000000000000000 [1.25e22])
    │   │   │   │   │   ├─ emit Transfer(from: 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24, to: 0x1bC016C00F8d603c41A582d5Da745905B9D034e5, value: 12500000000000000000000 [1.25e22])
    │   │   │   │   │   ├─ emit Approval(owner: 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24, spender: 0x1bC016C00F8d603c41A582d5Da745905B9D034e5, value: 0)
    │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   @ 0xeee869046b2edce3210d5bd4957f6841e9c44a973aa8294d8b6ebbdc49f7c390: 0x0000000000000000000000000000000000000000000002a5a058fc295ed00000 → 0
    │   │   │   │   │   │   @ 0xa3cbebf59e2ebdc44992a7408107001ef3db1290be978ec6d393078b46efaef0: 0x0000000000000000000000000000000000000000000002a5a058fc295ed00000 → 0
    │   │   │   │   │   │   @ 0xd6d621cc296ef5595b3d31299dc419d27e2c3c0aee3b0d84435ba435d1a272de: 0 → 0x0000000000000000000000000000000000000000000002a5a058fc295ed00000
    │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   ├─ [2638] BEP20USDT::allowance(0x1bC016C00F8d603c41A582d5Da745905B9D034e5, SwapRouter: [0x1b81D678ffb9C0263b24A97847620C99d213eB14]) [staticcall]
    │   │   │   │   │   └─ ← [Return] 115792089237316195423570985008687907853269984665640564028857584007913129639935 [1.157e77]
    │   │   │   │   ├─ [231971] SwapRouter::exactInput(ExactInputParams({ path: 0x55d398326f99059ff775485246999027b31979550001f4bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c0009c4422cbee1289aae4422edd8ff56f6578701bb2878, recipient: 0x1bC016C00F8d603c41A582d5Da745905B9D034e5, deadline: 1755959827 [1.755e9], amountIn: 12500000000000000000000 [1.25e22], amountOutMinimum: 0 }))
    │   │   │   │   │   ├─ [134491] 0x36696169C63e42cd08ce11f5deeBbCeBae652050::swap(SwapRouter: [0x1b81D678ffb9C0263b24A97847620C99d213eB14], true, 12500000000000000000000 [1.25e22], 4295128740 [4.295e9], 0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000400000000000000000000000001bc016c00f8d603c41a582d5da745905b9d034e5000000000000000000000000000000000000000000000000000000000000002b55d398326f99059ff775485246999027b31979550001f4bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c000000000000000000000000000000000000000000)
    │   │   │   │   │   │   ├─ [25705] PancakeV3LmPool::accumulateReward(1755959527 [1.755e9])
    │   │   │   │   │   │   │   ├─ [11440] 0x556B9306565093C855AEA9AE92A594704c2Cd59e::getLatestPeriodInfo(0x36696169C63e42cd08ce11f5deeBbCeBae652050) [staticcall]
```

ABCCApp pricing logic (getDDDDValueInUSDT, getTokenPriceInBNB, getBNBPriceInUSDT):

```solidity
    event OnSettlePrice(uint, uint, uint);

    modifier isOperator() {
        require(isOperators[msg.sender], "No Operator");
        _;
    }

    constructor() Ownable(msg.sender) {
        isOperators[msg.sender] = true;
    }

   function dashboard(address target) public view returns(DashboardData memory data) {
        data.currUser = users[target];
        if(target != address(0)) {
            data.usdtBalance = USDT.balanceOf(target);
            data.ddddBalance = DDDD.balanceOf(target);
            (,uint staticUSDT,) = getCanClaimUSDT(target);
            data.powerBalance = data.currUser.remainingUSDT - staticUSDT;
            data.currUser.staticUSDT = staticUSDT;
        }
    }

    function setPartUSDT(uint target) public onlyOwner {
        partUSDT = target;
    }

    function setOperator(address target, bool flag) public onlyOwner {
        isOperators[target] = flag;
    }
    function setVaultAddr(address target) public onlyOwner {
        vaultAddr = target;
    }

    function setEnable(bool flag) public onlyOwner {
        isEnable = flag;
    }

    function getCanClaimUSDT(address target) public view returns(uint totalUSDT, uint staticUSDT, uint dynamicUSDT) {
        User memory user = users[target];
        if(user.remainingUSDT == 0) {
            return (user.dynamicUSDT, 0, user.dynamicUSDT);
        }
   
        uint diffSecond = block.timestamp + getFixedDay() - user.lastClaimTime;
        uint diffDay = diffSecond / DAY;
        staticUSDT = diffDay * user.dailyUSDT;

        staticUSDT = staticUSDT > user.remainingUSDT ? user.remainingUSDT : staticUSDT;
        dynamicUSDT = user.dynamicUSDT;
        totalUSDT = staticUSDT + dynamicUSDT;
    }

    function deposit(uint number, address referer) external {
        require(isEnable, "CLOSED");
        require(number > 0, "E0");
        User storage user = users[msg.sender];
        (uint totalUSDT, , ) = getCanClaimUSDT(msg.sender);
        require(totalUSDT == 0, "E1");

        if(user.joinTime == 0) {
            if(referer == address(0)) {
                referer = address(this);
            }
            require(referer != msg.sender, "E2");
            if(referer != address(this)) {
                require(users[referer].joinTime > 0, "E3");
                userDirects[referer].push(DirectReferral({
                    target: msg.sender,
                    timestamp: block.timestamp
                }));
                users[referer].activeCount++;
            }
            user.referer = referer;
            user.joinTime = block.timestamp;
            globalData.totalCount++;
        }

        uint payUSDT = number * partUSDT;
        USDT.transferFrom(msg.sender, address(this), payUSDT);
        if(USDT.allowance(address(this), address(swapV3Router)) < payUSDT) {
            USDT.approve(address(swapV3Router), type(uint256).max);
        }

        IUniswapV3.ExactInputParams memory params = IUniswapV3.ExactInputParams({
            path: abi.encodePacked(address(USDT), uint24(500), address(BNB), uint24(2500), address(DDDD)),
            recipient: address(this),
            deadline: block.timestamp + 300,
            amountIn: payUSDT,
            amountOutMinimum: 0
        });
```

## Adversary Flow Analysis

Single-transaction, flash-loan-assisted manipulation of Pancake V3 DDDD/BNB and BNB/USDT pools during an ABCCApp::deposit call, forcing ABCCApp to over-distribute DDDD and then swapping that DDDD back into USDT for net profit after repaying the flash loan and gas.

**Adversary-related accounts**
- BNB Chain chainid 56 address 0x53feee33527819bb793b72bd67dbf0f8466f7d2c (EOA=true, contract=false): Sender and final USDT profit recipient in tx 0xee4eae6f..., and deployer of helper contract 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24 as shown in iter_1 address-txlist.
- BNB Chain chainid 56 address 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24 (EOA=false, contract=true): Purpose-built contract deployed by 0x53feee... shortly before the incident and used exclusively to orchestrate the flash loan, ABCCApp interaction, and swaps in tx 0xee4eae6f....

**Victim candidates**
- ABCCApp on BNB Chain chainid 56 at 0x1bC016C00F8d603c41A582d5Da745905B9D034e5 (is_verified=true)
- Pancake V3 DDDD/BNB pool on BNB Chain chainid 56 at 0xB7021120a77d68243097BfdE152289DB6d623407 (is_verified=true)
- Pancake V3 BNB/USDT pool on BNB Chain chainid 56 at 0x36696169C63e42cd08ce11f5deeBbCeBae652050 (is_verified=true)
- ABCCApp DDDD vault on BNB Chain chainid 56 at 0xa446DC212f4AaE662e1B5fF8729e99A4eFE7a174 (is_verified=unknown)

**Adversary lifecycle stages**
- Adversary contract deployment
  - Tx 0x<creation-tx-hash-for-0x90e076> on BNB Chain (chainid 56) block 58614808 mechanism=contract_creation
  - Effect: EOA 0x53feee... deploys helper contract 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24 shortly before the exploit, establishing the adversary-controlled orchestration contract.
  - Evidence: artifacts/root_cause/data_collector/iter_1/address/56/0x53feee33527819bb793b72bd67dbf0f8466f7d2c_txlist.json and 0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24_txlist.json show the deployment and link the contract to the EOA.
- Flash-loan draw and ABCCApp interaction
  - Tx 0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12 on BNB Chain (chainid 56) block 58615055 mechanism=flashloan
  - Effect: Helper contract 0x90e076... obtains a 12,500 USDT flash loan from Moolah via frontend 0x8F73..., approves ABCCApp, and calls ABCCApp::deposit with the borrowed USDT, triggering ABCCApp's reward logic that reads instantaneous DDDD/BNB and BNB/USDT prices from Pancake V3 pools.
  - Evidence: flash-loan call flow and ABCCApp::deposit invocation are visible in artifacts/root_cause/seed/56/0xee4eae6f.../trace.cast.log; ABCCApp pricing and reward logic are in artifacts/root_cause/data_collector/iter_1/contract/56/0x1bC016C0.../source/src/contract/abcc/ABCCApp.sol.
- Price manipulation and DDDD extraction
  - Tx 0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12 on BNB Chain (chainid 56) block 58615055 mechanism=swap
  - Effect: Within the same transaction, SwapRouter routes trades through Pancake V3 DDDD/BNB and BNB/USDT pools to distort prices, ABCCApp transfers 2.959e24 DDDD out of its balance to the DDDD/BNB pool and vaultAddr, and the manipulated spot prices cause ABCCApp to over-reward the adversary compared to normal behavior.
  - Evidence: DDDD balance changes for ABCCApp, pool 0xB7021120..., and vaultAddr 0xa446DC2... are quantified in artifacts/root_cause/seed/56/0xee4eae6f.../balance_diff.json; normal deposit/claim behavior without such drains is shown in iter_2 tx 0xbc1a33ff... and iter_3 tx 0xf477798e..., demonstrating the deviation during the exploit.
- Flash-loan repayment and profit realization
  - Tx 0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12 on BNB Chain (chainid 56) block 58615055 mechanism=repay_and_profit
  - Effect: The helper contract repays the full 12,500 USDT flash loan to the lender, then transfers the remaining 10,062.258375072914282796 USDT to the adversary EOA. Accounting for 0.031021704 USDT of gas fees under the conservative BNB price assumption, the adversary's net profit is 10,062.227353368914282796 USDT in this single transaction.
  - Evidence: USDT and BNB balance deltas for EOA 0x53feee... in artifacts/root_cause/seed/56/0xee4eae6f.../balance_diff.json, together with metadata.json gasUsed and gasPrice, support the explicit profit calculation.

## Impact & Losses

Total quantified losses:
- 10062.227353368914282796 USDT
- 2959187886413170131219626 DDDD

The adversary realizes at least 10,062.227353368914282796 USDT of net profit in a single transaction, funded by ABCCApp's over-distribution of DDDD and the subsequent conversion of that DDDD back into USDT via Pancake V3 pools. ABCCApp's DDDD reserves decrease by 2,959,187,886,413,170,131,219,626 units, with part of this DDDD routed to the DDDD/BNB pool and part to vaultAddr 0xa446DC2..., indicating losses to ABCCApp users and to liquidity providers in the DDDD/BNB and BNB/USDT pools relative to a counterfactual trajectory without the exploit. Long-tail redistribution of these losses among protocol stakeholders depends on subsequent protocol actions but does not affect the existence of the ACT opportunity itself.

## References

- [1] Seed tx metadata and balance diff for 0xee4eae6f...: /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/seed/56/0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12/metadata.json
- [2] Seed tx trace for 0xee4eae6f...: /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/seed/56/0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12/trace.cast.log
- [3] ABCCApp.sol source code: /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/data_collector/iter_1/contract/56/0x1bC016C00F8d603c41A582d5Da745905B9D034e5/source/src/contract/abcc/ABCCApp.sol
- [4] Pancake V3 pool source codes: /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/data_collector/iter_1/contract/56/0xB7021120a77d68243097BfdE152289DB6d623407/source/src/PancakeV3Pool.sol
- [5] Normal ABCCApp deposit and claim traces: /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/data_collector/iter_2/tx/56/0xbc1a33ff01d591618a7d82d579f704cff903f7bf04863f4373846ec97dde118f/trace.cast.log
- [6] Normal ABCCApp claimDDDD trace: /home/wesley/TxRayExperiment/incident-202601020948/artifacts/root_cause/data_collector/iter_3/tx/56/0xf477798e9c5bf7231b176b0c1eee333279509898583c20c57c0281cc9770aaeb/trace.cast.log
