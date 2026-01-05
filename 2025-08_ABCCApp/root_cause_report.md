## Incident Overview TL;DR

On BSC (chainid 56), an unprivileged adversary used a custom executor contract to take a 12,500 USDT flashloan from Moolah, deposit into ABCCApp, arbitrarily time‑warp ABCCApp’s global `fixedDay` parameter via a public `addFixedDay(1e9)` call, immediately claim the full 2x `remainingUSDT` as DDDD rewards, and dump those DDDD back to USDT on Pancake V3. All of this occurred within a single transaction, `0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12` in block 58,615,055, yielding approximately 10,061 USDT net profit after gas, primarily at the expense of the Pancake V3 BNB/USDT pool and ABCCApp’s DDDD reserves. The opportunity is an ACT: any unprivileged actor with access to standard BSC RPC and public contract interfaces could repeat the same strategy as long as ABCCApp and Moolah remain configured as at block 58,615,055.

## Key Background

ABCCApp is a BSC contract at `0x1bC016C00F8d603c41A582d5Da745905B9D034e5` that accepts USDT deposits, swaps them to DDDD via a Pancake V3‑style router and pools, and tracks per‑user accounting variables in a `users` mapping, including `remainingUSDT`, `dailyUSDT`, `dynamicUSDT`, `staticUSDT`, `claimedUSDT`, `claimedDDDD`, `investUSDT`, `joinTime`, and `lastClaimTime`. A deposit is parameterized by an integer `number`, with `payUSDT = number * partUSDT` (initially `partUSDT = 100 ether`), and sets `investUSDT += payUSDT`, `remainingUSDT += 2 * payUSDT`, and `dailyUSDT` to 5–6% of `remainingUSDT` per day depending on deposit size.

The time‑based accrual logic is implemented in `getCanClaimUSDT(address)`:

```solidity
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
```

where `DAY = 86400`, and:

```solidity
uint public fixedDay = 0;

function getFixedDay() public view returns(uint) {
    return fixedDay * DAY;
}

function addFixedDay(uint target) public {
    if(target == 0) {
        fixedDay = 0;
    } else {
        fixedDay += target;
    }
}
```

Thus, `fixedDay` is a global multiplier on the perceived elapsed time for all users: `diffSecond` is computed as `block.timestamp + fixedDay * DAY - user.lastClaimTime`, so increasing `fixedDay` after a deposit artificially inflates `diffDay` and therefore `staticUSDT`, capped only by `remainingUSDT`.

DDDD rewards are paid in token DDDD using on‑chain DEX prices from a DDDD/BNB pool at `0xB7021120a77d68243097BfdE152289DB6d623407` and a BNB/USDT pool at `0x36696169C63e42cd08ce11f5deeBbCeBae652050`. ABCCApp queries Uniswap V3‑style `slot0()` and `token0()` on these pools to compute DDDD’s USDT value:

```solidity
function getDDDDValueInUSDT(uint amount) public view returns(uint) {
    uint tokenPriceInBNB = getTokenPriceInBNB();
    uint bnbPriceInUSDT = getBNBPriceInUSDT();
    uint valueInUSDT = (amount * tokenPriceInBNB * bnbPriceInUSDT) / (10**18 * 10**18);
    return valueInUSDT;
}
```

Moolah, at implementation address `0x75C42E94dcF40e57AC267FfD4DABF63F97059686` behind proxy `0x8F73b65B4caAf64FBA2aF91cC5D4A2A1318E5D8C`, is a general‑purpose lending protocol that exposes a permissionless flashloan primitive:

```solidity
function flashLoan(address token, uint256 assets, bytes calldata data) external whenNotPaused {
    require(assets != 0, ErrorsLib.ZERO_ASSETS);

    emit EventsLib.FlashLoan(msg.sender, token, assets);

    IERC20(token).safeTransfer(msg.sender, assets);

    IMoolahFlashLoanCallback(msg.sender).onMoolahFlashLoan(assets, data);

    IERC20(token).safeTransferFrom(msg.sender, address(this), assets);
}
```

This function can be called by any contract when not paused, making it a suitable financing source for atomic strategies such as the exploit here.

## Vulnerability Analysis & Root Cause Summary

The root cause is ABCCApp’s unrestricted `addFixedDay(uint)` function, which is callable by any address and directly influences the time‑based accrual logic in `getCanClaimUSDT`. Because `getCanClaimUSDT` uses `block.timestamp + getFixedDay() - user.lastClaimTime` to derive elapsed time and multiplies that by `dailyUSDT`, a large positive bump to `fixedDay` after a deposit can make the contract behave as though an arbitrarily long period has elapsed. At the same time, `deposit` sets `remainingUSDT = 2 * investUSDT`, so a fresh deposit immediately followed by a massive `addFixedDay` call allows a user to claim essentially the entire 200% of principal (`remainingUSDT`) in a single `claimDDDD` call.

The vulnerable components are:
- **ABCCApp (0x1bC016C00F8d603c41A582d5Da745905B9D034e5)**: Specifically `addFixedDay(uint)`, `getFixedDay()`, `getCanClaimUSDT(address)`, `deposit(uint,address)`, and `claimDDDD()`. These functions together implement the time‑based accrual and claiming logic and expose the unrestricted time‑warp primitive.
- **Pancake V3 pools**: DDDD/BNB pool `0xB7021120a77d68243097BfdE152289DB6d623407` and BNB/USDT pool `0x36696169C63e42cd08ce11f5deeBbCeBae652050`, whose `slot0()` outputs are treated as spot price oracles by ABCCApp’s `getTokenPriceInBNB()` and `getBNBPriceInUSDT()`. While these pools are not themselves buggy, their prices are used to monetize the mis‑accrued USDT value.
- **Moolah flashloan provider (0x8F73b65B4caAf64FBA2aF91cC5D4A2A1318E5D8C)**: Its `flashLoan(address,uint256,bytes)` function offers unprivileged access to USDT liquidity, allowing the attacker to finance the deposit without pre‑existing capital.

The exploit conditions for this ACT opportunity are:
- `addFixedDay(uint)` must be callable by arbitrary addresses (no `onlyOwner` or operator guard), with `fixedDay` low enough prior to the attack that a large increment (e.g., `1e9`) meaningfully increases `diffSecond` for the attacking user.
- ABCCApp must hold enough DDDD (from prior deposits or initial provisioning) to pay out large DDDD amounts corresponding to `totalUSDT = 2 * investUSDT` for the attacker’s user record.
- The DDDD/BNB and BNB/USDT pools must have sufficient liquidity and roughly normal pricing so that the attacker can swap out the newly minted DDDD into USDT without catastrophic slippage.
- Moolah’s `flashLoan` must be unpaused for BEP20USDT, enabling any contract to atomically borrow and repay 12,500 USDT.
- The adversary must be able to send a transaction that successfully executes the sequence `flashLoan → deposit → addFixedDay → claimDDDD → swaps → repayment` with standard gas parameters.

These behaviors violate core security principles:
- **Monotonic, governance‑controlled time**: Time‑based reward accrual should depend only on real elapsed time and controlled configuration. Here, any user can arbitrarily increase `fixedDay`, retroactively inflating perceived elapsed days in `getCanClaimUSDT` for all users.
- **Bounded interest/return accounting**: Interest or reward logic should never allow an instantaneous 200% payout from a fresh deposit. ABCCApp’s combination of `remainingUSDT = 2 * investUSDT` and globally adjustable `fixedDay` permits exactly this.
- **Safe use of DEX oracles**: On‑chain DEX prices can be used as valuation oracles only when downstream minting or claiming logic properly bounds the amount of value created. ABCCApp converts a time‑warped USDT claim into DDDD at spot prices with no guard against manipulated elapsed time, enabling extraction of real DDDD value from protocol reserves and liquidity pools.

## Detailed Root Cause Analysis

### ABCCApp Deposit and Time‑Accrual Path

In the incident transaction, the adversary’s executor contract calls `ABCCApp.deposit(125, address(0))` after obtaining a 12,500 USDT flashloan from Moolah. The deposit path in `ABCCApp.sol` is:

```solidity
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
    ...
    uint256 fullDDDD = swapV3Router.exactInput(params);

    user.buyedDDDD += fullDDDD;
    user.investUSDT += payUSDT;
    user.remainingUSDT += payUSDT * 2;
    user.lastClaimTime = block.timestamp + getFixedDay();
    ...
    if(payUSDT > 1000 ether) {
        user.dailyUSDT = user.remainingUSDT * 6 / 1000;
    } else {
        user.dailyUSDT = user.remainingUSDT * 5 / 1000;
    }
    emit OnDeposit(msg.sender, payUSDT);   
}
```

With `number = 125` and `partUSDT = 100e18`, this yields `payUSDT = 12,500e18`. Storage snapshots in `ABCCApp_users_0x90e0…_pre_post.json` show:
- `investUSDT` after tx: `0x2a5a058fc295ed00000` = 12,500e18,
- `remainingUSDT` after tx: `0x0` (because it is fully consumed by the subsequent claim),
- `claimedUSDT` after tx: `0x54b40b1f852bda00000` = 25,000e18,
- `dailyUSDT` after tx: `0x821ab0d4414980000` ≈ 150e18.

The 150e18 `dailyUSDT` is exactly `remainingUSDT * 6 / 1000` for `remainingUSDT = 2 * 12,500e18 = 25,000e18`. This confirms the analyzer’s numerical description.

### Time‑Warp via addFixedDay

The critical misdesign is in `addFixedDay(uint)` and its interaction with `getCanClaimUSDT`:

```solidity
uint public fixedDay = 0;

function getFixedDay() public view returns(uint) {
    return fixedDay * DAY;
}

function addFixedDay(uint target) public {
    if(target == 0) {
        fixedDay = 0;
    } else {
        fixedDay += target;
    }
}
```

`addFixedDay` has no access control, so any caller may increase `fixedDay` arbitrarily. In `getCanClaimUSDT`, the effective elapsed time is:

- `diffSecond = block.timestamp + getFixedDay() - user.lastClaimTime`
- `diffDay = diffSecond / DAY`
- `staticUSDT = diffDay * dailyUSDT`, capped at `remainingUSDT`.

After the deposit, `user.lastClaimTime` is set to `block.timestamp + getFixedDay()` (using the pre‑exploit `fixedDay`). If the attacker then calls `addFixedDay(1e9)`, `fixedDay` becomes `1e9` (assuming it was 0 before), so subsequent `getCanClaimUSDT` calls see:

```text
diffSecond ≈ block.timestamp + (1e9 * DAY) - (block.timestamp + 0) ≈ 1e9 * DAY
diffDay ≈ 1e9
staticUSDT ≈ 1e9 * dailyUSDT, but capped at remainingUSDT
```

Since `remainingUSDT` is 25,000e18 and `dailyUSDT` is 150e18, the cap binds and `staticUSDT` becomes the full 25,000e18 almost immediately. This is precisely the time‑warp effect the adversary relies on.

### Claim and DDDD Minting Path

The `claimDDDD` function converts the now time‑warped claimable USDT amount into DDDD at current DEX prices:

```solidity
function claimDDDD() external {
    User storage user = users[msg.sender];
    (uint totalUSDT, uint staticUSDT, ) = getCanClaimUSDT(msg.sender);
    require(totalUSDT > 0, "E0");

    user.remainingUSDT -= staticUSDT;
    user.dynamicUSDT = 0;
    user.staticUSDT = 0;
    user.claimedUSDT += totalUSDT;
    ...
    uint ddddPrice = getDDDDValueInUSDT(1 * 10 ** 18);
    uint ddddAmount =  totalUSDT * 1e18 / ddddPrice;

    if(claimFee > 0) {
        uint fee = ddddAmount * claimFee / 100;
        DDDD.transfer(vaultAddr, fee);
        ddddAmount -= fee;
    }

    DDDD.transfer(msg.sender, ddddAmount);
    user.claimedDDDD += ddddAmount;
    user.lastClaimTime = block.timestamp + getFixedDay();
    ...
    emit OnClaimed(msg.sender, ddddAmount);
}
```

In the exploit, `getCanClaimUSDT` for the executor returns `totalUSDT = 25,000e18`. The trace `trace.cast.log` shows the resulting DDDD transfers:
- `Token::transfer(ABCCApp, 303086721467231766450601)` to the vault address `0xa446DC212f4AaE662e1B5fF8729e99A4eFE7a174`,
- `Token::transfer(ABCCApp, 5758647707877403562561426)` to the executor `0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24`.

These match the reported ~303,086.72 DDDD fee and ~5,758,647.71 DDDD to the attacker. The `users[executor]` storage snapshot shows `claimedUSDT = 25,000e18` and `remainingUSDT = 0` after the claim, confirming that the full 2x of the invested USDT was realized in a single step.

### DEX Swaps and Profit Realization

`trace.cast.log` and `trace_call_tracer.json` show the executor swapping DDDD through the DDDD/BNB and BNB/USDT pools:
- ABCCApp swaps 12,500e18 USDT from the executor into DDDD during deposit via `SwapRouter` and the two pools.
- After claiming, the executor approves the Pancake V3 router and swaps ~5.76M DDDD back through the same pools, receiving 22,562.2583… USDT.

The `balance_diff.json` for the incident tx confirms the net USDT movement:
- The BNB/USDT pool at `0x36696169C63e42cd08ce11f5deeBbCeBae652050` loses `10,062.25837507291428282796` USDT.
- The adversary EOA `0x53feee33527819bb793b72bd67dbf0f8466f7d2c` gains exactly the same amount of USDT.

Gas consumption from `metadata.json` (`gasUsed = 10,397,152`, `gasPrice = 105 gwei`) combined with the on‑chain BNB/USDT price from the pool’s `slot0()` yields a gas cost of about 0.9748 USDT, aligning with the reported net profit of ~10,061.28 USDT after gas.

## Adversary Flow Analysis

### Adversary Strategy Summary

The adversary’s strategy is:
- Deploy a custom executor contract that implements the Moolah flashloan callback and can call ABCCApp and the Pancake V3 router.
- Use the executor to take a 12,500 USDT flashloan from Moolah.
- Deposit the borrowed USDT into ABCCApp to create a fresh user position with `remainingUSDT = 2 * investUSDT` and large `dailyUSDT`.
- Immediately call `addFixedDay(1e9)` to globally time‑warp the contract’s accrual logic, making `getCanClaimUSDT` treat an enormous number of days as having passed for the executor’s user.
- Call `claimDDDD` to convert the time‑warped 25,000e18 USDT claim into DDDD at current DEX prices, reducing `remainingUSDT` to 0 and minting millions of DDDD to the executor.
- Swap the DDDD back to USDT via the DDDD/BNB and BNB/USDT pools.
- Repay the flashloan principal and forward the remaining USDT profit to the adversary EOA.

All of this occurs in a single adversary‑crafted transaction, making it atomic and permissionless.

### Adversary‑Related Accounts

- **Adversary EOA**: `0x53feee33527819bb793b72bd67dbf0f8466f7d2c`
  - Sender of the incident transaction `0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12`.
  - Ultimate recipient of the USDT profit as shown in `balance_diff.json` (10,062.258375072914282796 USDT gain).
  - Deployer of the executor contract `0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24` in the earlier transaction `0x0578568a50539f1049f2ab6f40d0e6ebb6920ed19db7e7fd84a15af357379eea`, as confirmed by `txlist_normal.json`.

- **Executor Contract**: `0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24`
  - A contract account whose decompiled code (`0x90e0…-decompiled.sol`) shows logic to orchestrate Moolah flashloans, token approvals, ABCCApp interactions, and token swaps.
  - Called by the adversary EOA in the exploit tx, and in turn calls Moolah, ABCCApp, the Pancake V3 router, and ultimately returns the profit to the EOA.

### Victim Contracts

- **ABCCApp (yield protocol)**: `0x1bC016C00F8d603c41A582d5Da745905B9D034e5` (verified source `ABCCApp.sol`).
- **Pancake V3 BNB/USDT pool**: `0x36696169C63e42cd08ce11f5deeBbCeBae652050` (verified pool, used as USDT price oracle and as USDT liquidity source).
- **Pancake V3 DDDD/BNB pool**: `0xB7021120a77d68243097BfdE152289DB6d623407` (verified pool, used as DDDD price oracle and DDDD liquidity sink).

### Lifecycle Stages

1. **Adversary Contract Deployment**
   - Tx: `0x0578568a50539f1049f2ab6f40d0e6ebb6920ed19db7e7fd84a15af357379eea` (block 58,381,654).
   - The adversary EOA sends a self‑transaction that results in the creation of the contract at `0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24`, as indicated by Etherscan‑style `txlist_normal` data for the EOA.
   - Decompiled executor code shows the ability to interact with WBNB, BEP20USDT, ABCCApp, Moolah, and DEX pools, consistent with the behaviors observed in the later exploit tx.

2. **Flashloan‑Funded Deposit and FixedDay Time‑Warp**
   - Tx: `0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12` (block 58,615,055), chainid 56.
   - `trace_call_tracer.json` and `trace.cast.log` show:
     - Moolah `flashLoan` transferring 12,500e18 USDT from its reserves to the executor contract.
     - The executor approving USDT to ABCCApp, then calling `ABCCApp.deposit(125, address(0))`.
     - ABCCApp pulling 12,500e18 USDT from the executor, swapping USDT to DDDD via Pancake V3, and updating the user record with `investUSDT = 12,500e18`, `remainingUSDT = 25,000e18`, `dailyUSDT ≈ 150e18`, and `lastClaimTime = block.timestamp + getFixedDay()`.
     - The executor then calling `ABCCApp.addFixedDay(1e9)`, increasing the global `fixedDay` so that subsequent `getCanClaimUSDT` calls for the executor’s user treat an enormous number of days as elapsed, effectively enabling a full unlock of `remainingUSDT`.

3. **DDDD Claim, DEX Dump, Flashloan Repayment, and Profit Realization**
   - Still in tx `0xee4e…`:
     - The executor calls `ABCCApp.claimDDDD()`. With the time‑warped state, `getCanClaimUSDT` returns `totalUSDT = 25,000e18` for the executor.
     - ABCCApp computes `ddddPrice` from the DDDD/BNB and BNB/USDT pools, then calculates the DDDD amount corresponding to 25,000e18 USDT. It transfers ~303,086.72 DDDD to `vaultAddr = 0xa446DC212f4AaE662e1B5fF8729e99A4eFE7a174` as fee and ~5,758,647.71 DDDD to the executor contract.
     - The executor approves the Pancake V3 router and swaps all ~5.76M DDDD through the DDDD/BNB and BNB/USDT pools, receiving ~22,562.2583 USDT.
     - It repays the 12,500e18 USDT flashloan back to Moolah and then forwards the remaining 10,062.258375072914282796 USDT to the EOA `0x53feee…7d2c`.
   - `balance_diff.json` and pool `state_diff` files confirm:
     - The BNB/USDT pool loses exactly 10,062.258375072914282796 USDT.
     - ABCCApp’s DDDD balance decreases by 2,959,187.886413170131219626 DDDD, while the DDDD/BNB pool and vault receive the corresponding amounts.

## Impact & Losses

Within the single incident transaction:
- **USDT Loss**: The Pancake V3 BNB/USDT pool at `0x36696169C63e42cd08ce11f5deeBbCeBae652050` loses 10,062.258375072914282796 USDT, which is gained by the adversary EOA `0x53feee33527819bb793b72bd67dbf0f8466f7d2c`.
- **DDDD Loss / Redistribution**: ABCCApp at `0x1bC016C00F8d603c41A582d5Da745905B9D034e5` loses 2,959,187.886413170131219626 DDDD from its balance. This DDDD is split between the DDDD/BNB pool and the protocol vault:
  - ~303,086.72 DDDD is transferred to the vault address `0xa446DC212f4AaE662e1B5fF8729e99A4eFE7a174` as a claim fee.
  - ~5,758,647.71 DDDD goes to the executor, which then routes it into the DDDD/BNB pool as part of the swap path.

The primary economic loss in this transaction accrues to:
- Liquidity providers of the BNB/USDT pool, who lose 10,062.2583 USDT.
- ABCCApp’s DDDD reserves, which are drained to fuel the DEX swaps that deliver USDT profit to the attacker.

Total loss overview:
- `USDT`: `10062.258375072914282796`
- `DDDD`: `2959187.886413170131219626`

## References

- **[1] Seed tx metadata and trace**  
  `artifacts/root_cause/seed/56/0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12`  
  Contains `metadata.json`, `trace.cast.log`, and `balance_diff.json` used to reconstruct pre/post balances and the call sequence for the incident transaction.

- **[2] ABCCApp.sol source**  
  `artifacts/root_cause/data_collector/iter_1/contract/56/0x1bC016C00F8d603c41A582d5Da745905B9D034e5/source/src/contract/abcc/ABCCApp.sol`  
  Verified contract code for ABCCApp, including `deposit`, `getCanClaimUSDT`, `addFixedDay`, `claimDDDD`, and DEX oracle logic.

- **[3] Moolah flashloan implementation**  
  `artifacts/root_cause/data_collector/iter_1/contract/56/0x75C42E94dcF40e57AC267FfD4DABF63F97059686/source/src/moolah/Moolah.sol`  
  Defines the permissionless `flashLoan` used to finance the exploit.

- **[4] Pancake V3 router and pools source**  
  `artifacts/root_cause/data_collector/iter_1/contract/56`  
  Contains source for the Pancake V3 router and pools used for USDT↔BNB↔DDDD swaps and price oracles.

- **[5] ABCCApp users[executor] pre/post snapshot**  
  `artifacts/root_cause/data_collector/iter_2/storage_slot/56/ABCCApp_users_0x90e076eF0fEd49A0b63938987F2caD6B4Cd97a24_pre_post.json`  
  Shows the executor’s `User` struct before and after the exploit tx, confirming `investUSDT`, `remainingUSDT`, `claimedUSDT`, `dailyUSDT`, and `claimedDDDD` values.

- **[6] Pool storage diffs and USDT/DDDD balance diffs**  
  `artifacts/root_cause/data_collector/iter_2/state_diff` and  
  `artifacts/root_cause/seed/56/0xee4eae6f70a6894c09fda645fb24ab841e9847a788b1b2e8cb9cc50c1866fb12/balance_diff.json`  
  Provide detailed storage changes for the BNB/USDT and DDDD/BNB pools and ERC‑20 balance changes for USDT and DDDD, underpinning the quantified losses and profit.

