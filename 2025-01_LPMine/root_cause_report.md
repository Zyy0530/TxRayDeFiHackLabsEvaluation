# LPMine WTO Over-Distribution via Flash-Loan-Inflated LP Valuation

## 1. Incident Overview & TL;DR

This incident involves a liquidity-mining protocol on BSC where an unprivileged attacker abused LPMine `0x6BBeF6DF8db12667aE88519090984e4F871e5feb` and its associated reward pool to over-claim WTO rewards. The attacker used a helper contract and a large USDT flash loan to temporarily inflate AMM reserves, then repeatedly called `LPMine::extractReward(1)` while prices and reserves were distorted. Because LPMine’s reward logic was both flash-loan-sensitive and mis-accounted rewards across WTO and COAR LP legs, the reward pool `0x3200Be834b791D09017Bd924c71174e47959b087` distributed more than `4.0e26` WTO in a single exploit transaction.

At a high level:

- The helper contract first stakes a large COAR LP position into LPMine to create a sizeable `coarLpAmount` with a fresh reward timestamp.
- In the exploit transaction, the helper borrows `5,000,000` USDT via a Pancake V3 flash loan and pushes it into the ZF/USDT pool, temporarily inflating reserves and spot prices.
- While the pool is distorted, the helper calls `LPMine::extractReward(1)` many times. Each call computes WTO rewards using inflated reserves and double-counts contributions from both WTO and COAR LP legs, but only updates the WTO reward timestamp.
- RewardPool sends a total of `402,289,684,537,844,701,832,616,528` WTO out to the helper, referral/admin addresses, and the WTO/USDT pair.
- The attacker then converts a large portion of the WTO-derived USDT to BNB via a public DEX aggregator, ending with a net profit of approximately `33.815349128109987855` BNB after gas and flash-loan fees.

The root cause is a protocol bug in LPMine’s reward calculation: it values LP positions off flash-loan-sensitive reserves via `getRemoveTokens` and `getEachReward`, aggregates WTO rewards across both WTO and COAR LP legs, and allows `extractReward(1)` to repeatedly tap COAR-leg WTO rewards without updating `coarRewardTime`. All calls are available to any unprivileged user.

## 2. Key Background

- **Protocol and contracts**
  - **LPMine** (`0x6BBeF6DF8db12667aE88519090984e4F871e5feb`) is a liquidity-mining contract on BSC. It accepts LP tokens for two tokens (WTO and COAR) and rewards stakers with WTO and COAR over time. For each user it tracks:
    - `wtoLpAmount` and `coarLpAmount` (LP token balances),
    - `depositTime`, `wtoLpBackTime`, `coarLpBackTime`,
    - `wtoRewardTime` and `coarRewardTime`.
  - **RewardPool (TokenDistributor)** (`0x3200Be834b791D09017Bd924c71174e47959b087`) is a `TokenDistributor`-style contract created by LPMine’s constructor. It stores rewards (including WTO) and exposes `claimToken(token, amount, to)`, callable only by its owner/admin (LPMine), to transfer reward tokens to stakers and invitees.
- **Tokens and AMMs**
  - **WTO** (`0x692097F0d3Bd0dFBbbbb0EE35000729F05d598f5`) and **ZF** (`0x259A9FB74d6A81eE9b3a3D4EC986F08fbb42121A`) are ERC20 tokens with fee-on-transfer mechanics when interacting with their Pancake pairs. Verified sources show WTO has a burn pool and owner-controlled fee parameters, but no anti-flash-loan safeguards at the token level.
  - LPMine uses two main PancakeSwap V2 pairs to value LP positions and calculate a “monthly fee” via `PancakeRouter::getAmountsOut`:
    - **ZF/USDT pair**: `0xBE2F4D0C39416C7C4157eBFdccB65cc2FF5fb2C4`.
    - **WTO/USDT pair**: `0x6F9070D449798f4a77d43B80ddfAAcabD456d50f`.
  - A Pancake V3 pool `0x36696169C63e42cd08ce11f5deeBbCeBae652050` is later used to borrow USDT via flash loans.
- **Attacker structure**
  - **Primary EOA**: `0x593749d5414d8a735cda16e4b47cc9bfa47d5683`
    - Sender of all three key transactions (`0x11c1ef2c...`, `0x00c5a772...`, `0xf33f40ee...`).
    - Ultimate recipient of BNB profit as shown by native balance diffs.
  - **Helper contract**: `0x0557f67b2D5Dc575fe3e433E7caf71eA523979fD`
    - Interacts with routers, pools, and LPMine.
    - Orchestrates swaps, the flash loan, and repeated `LPMine::extractReward` calls.
    - Temporarily holds WTO and USDT before forwarding USDT to the EOA.

### Code snippet – LPMine and TokenDistributor structure

_Origin: collected LPMine source (verified on explorer) and embedded `TokenDistributor` for contract `0x6BBeF6DF...`._

```solidity
contract TokenDistributor {
    address public _owner;
    address public _admin;
    constructor (address admin) {
        _owner = msg.sender;
        _admin = admin;
    }

    function claimToken(address token, uint256 amount, address to) external {
        require(msg.sender == _admin || msg.sender == _owner);
        IERC20(token).transfer(to, amount);
    }
}

contract LPMine is Ownable {
    using SafeMath for uint256;
    address private immutable usdtAddress;
    IUniswapV2Router02 private immutable uniswapV2Router;
    TokenDistributor public immutable rewardPool;
    // ...
    struct PledgeInfo {
        uint256 wtoLpAmount;
        uint256 coarLpAmount;
        uint256 depositTime;
        uint256 wtoLpBackTime;
        uint256 coarLpBackTime;
        uint256 wtoRewardTime;
        uint256 coarRewardTime;
    }
    mapping(address => PledgeInfo) public userPledge;
    // ...
}
```

_Caption: LPMine deploys an internal `TokenDistributor` reward pool and tracks per-user WTO/COAR LP positions and reward timestamps used in the faulty reward calculation._

## 3. Act Opportunity and Transaction Sequence

### 3.1 Pre-state at Block 45,583,892 (σ\_B)

At block height **45,583,892** (`0x2b78e14`), the relevant public BSC state is:

- LPMine `0x6BBeF6DF...` is deployed with WTO and COAR tokens registered, `monthFee` configured, and `rewardPool` `0x3200Be83...` funded with WTO.
- The ZF/USDT pair `0xBE2F4D0...` and WTO/USDT pair `0x6F9070D4...` exist with non-zero liquidity.

This is supported by:

- Seed metadata for tx `0x11c1ef2c...` at this block.
- Verified LPMine source in `Contract.sol`.
- Verified token sources for ZF and WTO under the collected contract sources.

### 3.2 Adversary Transaction Sequence (b)

The attack unfolds through three adversary-crafted transactions on chain **BSC (56)**:

1. **Tx 1 – LP priming (index 1, `0x11c1ef2c61f5a2e41d570a1547d2d891bf916853ddd94e32097e86bcdd21cb4c`)**
   - The EOA `0x593749d5...` sends **1 BNB** to helper contract `0x0557f67b...` and calls a `pledge(uint256)`-style entrypoint.
   - The helper uses standard PancakeRouter operations to:
     - Swap BNB for USDT.
     - Add ZF/USDT liquidity into PancakePair `0xBE2F4D0...`.
   - It then stakes the resulting LP tokens into LPMine via `partakeAddLp(2, ..., 0x114FAA79...)`, creating a large `coarLpAmount` for user `0x0557f67b...` with `coarRewardTime` set to the block timestamp.
   - No privileged roles or whitelists are involved; all components are public router/pair contracts plus the unprivileged helper.

2. **Tx 2 – Core exploit (index 2, `0x00c5a772a58b117f142b2cbc8721b80d145ef7a910043ad08439863d0e78e300`)**
   - The same EOA calls helper contract `0x0557f67b...`.
   - The helper borrows **5,000,000 USDT** via `PancakeV3Pool::flash` from `0x36696169...`, a permissionless V3 pool.
   - It routes the borrowed USDT into the public ZF/USDT pair `0xBE2F4D0...`, inflating reserves and spot prices.
   - While reserves are inflated, it calls `LPMine::extractReward(1)` repeatedly, using the bugged reward logic to over-claim WTO from `rewardPool`.
   - All steps use public pool/router interfaces; flash loans, swaps, and calls to `LPMine::extractReward(1)` and `rewardPool::claimToken` are available to any user with gas.

3. **Tx 3 – Profit realization (index 3, `0xf33f40ee0da9edebdb5cb463b37ef55df38e09690d7f68e333cf4a63046dd4cd`)**
   - The same EOA calls UniversalRouter `0x1A0A18AC4BECDDbd6389559687d1A73d8927E416`.
   - The calldata uses `permit` on a helper token `0x31c2F6fc...` to authorize spending of the EOA’s USDT.
   - UniversalRouter swaps USDT into WBNB via Pancake V3 pools `0x172fcd41...` and `0xf2688Fb5...`, unwraps WBNB to BNB, and returns BNB to the EOA.
   - UniversalRouter and the pools are fully public; inclusion requires no special rights beyond owning the USDT and providing a valid permit signature.

### 3.3 Profit Predicate (π – Profit in BNB)

The exploit predicate is a **profit-based** condition in the reference asset **BNB**, measured on the attacker EOA **`0x593749d5...`** across the three transactions.

- **Reference asset**: BNB (native BSC asset).
- **Adversary address**: `0x593749d5...`.
- **Fees**: Gas and flash-loan fees are already reflected in the native balance deltas for the three transactions; they are not further decomposed.
- **Pre- and post-values**: Absolute BNB wealth before/after is not reconstructed (`value_before_in_reference_asset` and `value_after_in_reference_asset` are marked “unknown”), but the net **delta** is computed exactly from traces.

From `balance_diff.json` files:

- **Setup tx (`0x11c1ef2c...`)**
  - Native delta: `-1,001,691,652,000,000,000` wei (≈ `-1.001691652` BNB).
- **Exploit tx (`0x00c5a772...`)**
  - Native delta: `-129,234,354,000,000,000` wei (≈ `-0.129234354` BNB).
- **Aggregator tx (`0xf33f40ee...`)**
  - Native delta: `+34,946,275,134,109,987,855` wei (≈ `+34.946275134109987855` BNB).

Summing these yields:

```text
ΔBNB_EOA = -1,001,691,652,000,000,000
         + -129,234,354,000,000,000
         + 34,946,275,134,109,987,855
         = 33,815,349,128,109,987,855 wei
         ≈ +33.815349128109987855 BNB
```

Thus the attacker EOA’s net profit, after gas and flash-loan fees, is **+33.815349128109987855 BNB**.

## 4. Vulnerability & Root Cause Analysis

### 4.1 Overview of the Logic

LPMine’s reward calculation is implemented through a combination of:

- `getCanClaimed(address _user)` – computes pending WTO and COAR rewards for a user based on stored LP amounts, reward timestamps, and current pool reserves.
- `getRemoveTokens(address _pair, address _usdtAddress, address _tokenAddress, uint256 _liquidity)` – approximates the USDT and token amounts backing a given LP position using current AMM reserves.
- `getEachReward(uint256 _valueU, uint256 _monthFee, address _wtoAddress, address _coarAddress, address _usdtAddress)` – converts a USDT-denominated notional value into per-second WTO and COAR accrual rates using `PancakeRouter::getAmountsOut`.
- `extractReward(uint256 _tokenId)` – initiates reward claims for a user and updates reward timestamps.

The defect arises from:

1. Using **spot AMM reserves** that are vulnerable to flash-loan manipulation.
2. **Summing rewards** across both WTO and COAR LP legs into a single WTO reward figure.
3. **Updating only one reward timestamp** on extraction (`wtoRewardTime` when claiming WTO), leaving the COAR-leg WTO component untouched and re-claimable.

### 4.2 LP Valuation via Flash-Loan-Sensitive Reserves

Within `getCanClaimed`:

```solidity
function getCanClaimed(address _user) public view returns (uint256 _wtoAmount, uint256 _coarAmount) {
    PledgeInfo memory _pledge = userPledge[_user];
    Token memory _wtoToken = tokens[wtoTokenId];
    Token memory _coarToken = tokens[coarTokenId];
    if (_pledge.wtoLpAmount > 0) {
        (uint256 _removeUsdt,) = getRemoveTokens(_wtoToken.pair, usdtAddress, _wtoToken.tokenAddress, _pledge.wtoLpAmount);
        uint256 _valueU = _removeUsdt.mul(2);
        uint256 _rewardTime = block.timestamp.sub(_pledge.wtoRewardTime);
        (uint256 _secondWtoAmount, uint256 _secondCoarAmount) =
            getEachReward(_valueU, monthFee, _wtoToken.tokenAddress, _coarToken.tokenAddress, usdtAddress);
        _wtoAmount += _rewardTime.mul(_secondWtoAmount);
        _coarAmount += _rewardTime.mul(_secondCoarAmount);
    }
    // COAR leg handled similarly...
}
```

_Origin: collected LPMine source for `0x6BBeF6DF...`._

`getRemoveTokens` itself reads the **current** reserves of the AMM pair:

```solidity
function getRemoveTokens(address _pair, address _usdtAddress, address _tokenAddress, uint256 _liquidity)
    private
    view
    returns (uint256 _removeUsdt, uint256 _removeToken)
{
    uint _usdtAmount = IERC20(_usdtAddress).balanceOf(_pair);
    uint _tokenAmount = IERC20(_tokenAddress).balanceOf(_pair);
    uint _totalSupply = IERC20(_pair).totalSupply();
    _removeUsdt = _liquidity.mul(_usdtAmount) / _totalSupply;
    _removeToken = _liquidity.mul(_tokenAmount) / _totalSupply;
}
```

Because `_usdtAmount` and `_tokenAmount` come from the **current** pool balances, any temporary injection of USDT (such as a flash loan deposited into the pair) directly increases `_removeUsdt` and thus `_valueU = 2 * _removeUsdt`. This is true even if the user’s LP position and the underlying economics have not changed.

### 4.3 Conversion into Per-Second WTO and COAR Rewards

`getEachReward` converts `_valueU` into per-second reward rates using current spot prices:

```solidity
function getEachReward(
    uint256 _valueU,
    uint256 _monthFee,
    address _wtoAddress,
    address _coarAddress,
    address _usdtAddress
) public view returns (uint256, uint256) {
    uint256 _monthFeeAmount = calculateFee(_valueU, _monthFee);
    (, uint256 _outWtoAmount) = getAmountOut(_usdtAddress, _wtoAddress, _monthFeeAmount);
    (, uint256 _outCoarAmount) = getAmountOut(_usdtAddress, _coarAddress, _monthFeeAmount);
    uint256 _secondWtoAmount = _outWtoAmount / 30 days;
    uint256 _secondCoarAmount = _outCoarAmount / 30 days;
    return (_secondWtoAmount, _secondCoarAmount);
}
```

`getAmountOut` uses `PancakeRouter::getAmountsOut` between USDT and the target token (WTO or COAR), again at **spot prices** with no TWAP or bounds:

```solidity
function getAmountOut(address _token0, address _token1, uint256 _amountIn)
    internal
    view
    returns (address[] memory, uint256)
{
    address[] memory _path = new address[](2);
    _path[0] = _token0;
    _path[1] = _token1;
    if (IUniswapV2Factory(uniswapV2Router.factory()).getPair(_token0, _token1) == address(0)) {
        return (_path, 0);
    }
    uint256[] memory _amountOut = uniswapV2Router.getAmountsOut(_amountIn, _path);
    uint256 _out = _amountOut[1];
    return (_path, _out);
}
```

When reserves and prices are transiently inflated by a flash loan, `_outWtoAmount` and `_outCoarAmount` become artificially large, and dividing by `30 days` produces outsized per-second accrual rates.

### 4.4 Double Counting across WTO and COAR LP Legs

For a user with both `wtoLpAmount` and `coarLpAmount`:

- The WTO leg contributes to `_wtoAmount` and `_coarAmount` based on `wtoLpAmount` and `wtoRewardTime`.
- The COAR leg independently contributes again to `_wtoAmount` and `_coarAmount` based on `coarLpAmount` and `coarRewardTime`.

Thus `_wtoAmount` aggregates contributions from **both** LP legs. In the exploit, the attacker’s large COAR LP position dominates WTO entitlement.

### 4.5 One-Sided Timestamp Update in `extractReward`

`extractReward` reads the combined rewards and then updates only one timestamp, depending on which token is being claimed:

```solidity
function extractReward(uint256 _tokenId) external {
    (uint256 _wtoAmount, uint256 _coarAmount) = getCanClaimed(_msgSender());
    PledgeInfo storage _pledge = userPledge[_msgSender()];
    uint256 _canReward;
    address _tokenAddress;
    if (_tokenId == wtoTokenId) {
        _canReward = _wtoAmount;
        _tokenAddress = tokens[wtoTokenId].tokenAddress;
        _pledge.wtoRewardTime = block.timestamp;
    }
    if (_tokenId == coarTokenId) {
        _canReward = _coarAmount;
        _tokenAddress = tokens[coarTokenId].tokenAddress;
        _pledge.coarRewardTime = block.timestamp;
    }
    if (_canReward > 0) {
        rewardPool.claimToken(_tokenAddress, _canReward, _msgSender());
        rewardParent(_tokenId, _tokenAddress, _canReward, _msgSender());
    }
}
```

When a user calls `extractReward(1)` (WTO):

- `_wtoAmount` includes contributions from both WTO and COAR legs.
- Only `wtoRewardTime` is updated; `coarRewardTime` is **not**, leaving the COAR-leg WTO portion effectively untouched and re-claimable.

This asymmetric update is the key bug: it permits repeated `extractReward(1)` calls to re-consume COAR-leg WTO rewards, especially when `_secondWtoAmount` is temporarily inflated by manipulated reserves.

### 4.6 Summary of the Root Cause

The root cause is the interaction of:

- **Flash-loan-sensitive LP valuation** (`getRemoveTokens` + `getEachReward` using current AMM reserves and spot prices).
- **Aggregated WTO rewards across multiple LP legs**, so that WTO entitlement reflects both WTO and COAR contributions.
- **One-sided timestamp update** in `extractReward`, which fails to advance `coarRewardTime` when WTO is claimed via `tokenId == 1`.

RewardPool’s `claimToken` function simply transfers whatever amount LPMine instructs it to, with no hard cap tied to deposits or global emission schedules, so once the per-user reward computation is compromised, over-distribution directly drains WTO from the pool.

## 5. Adversary Flow Analysis

### 5.1 Adversary-Related Accounts

- **Adversary cluster**
  - **EOA `0x593749d5...`**
    - Originates all three key transactions (`0x11c1ef2c...`, `0x00c5a772...`, `0xf33f40ee...`).
    - Final beneficiary of BNB profit as shown by native balance deltas.
  - **Helper contract `0x0557f67b...`**
    - Called by the EOA in setup and exploit txs.
    - Executes swaps, adds liquidity, initiates the V3 flash loan, and calls `LPMine::partakeAddLp` and `LPMine::extractReward` repeatedly.
    - Receives WTO and USDT and forwards USDT to the EOA before the aggregator step.

- **Victim-side contracts and pools**
  - **LPMine** (`0x6BBeF6DF...`) – verified mining contract whose reward logic is exploited.
  - **RewardPool (TokenDistributor)** (`0x3200Be83...`) – holds WTO on behalf of LPMine and is drained via `claimToken`.
  - **ZF/USDT PancakePair** (`0xBE2F4D0C...`) – AMM whose reserves are inflated by the USDT flash loan to distort valuation.
  - **WTO/USDT PancakePair** (`0x6F9070D4...`) – AMM that receives WTO as part of reward distribution and subsequent swaps.

Other addresses:

- **Referral/admin addresses** `0x114FAA79...` and `0xa6184d66...` receive substantial WTO allocations during the exploit through referral logic and/or admin participation.
- Txlists for these addresses show no immediate forwarding of WTO back to the attacker EOA within the incident block range, so their gains are treated as separate beneficiaries rather than attacker-controlled relays.

### 5.2 Lifecycle Stages

#### Stage 1: LP Priming in LPMine (Tx `0x11c1ef2c...`, Block 45,583,892)

In the first stage, the attacker prepares a large COAR LP position in LPMine:

- The EOA `0x593749d5...` funds the helper contract `0x0557f67b...` with 1 BNB and triggers its pledge-like entrypoint.
- The helper:
  - Swaps BNB for USDT via PancakeRouter.
  - Adds ZF/USDT liquidity into pair `0xBE2F4D0...`.
  - Stakes the resulting LP into LPMine by calling:

```bash
LPMine::partakeAddLp(2, 2116514175087740339695220908, 348709159477963095424, 0x114FAA79157c6Ba61818CE2A383841e56B20250B)
```

_Origin: seed transaction trace for `0x11c1ef2c...`._

The trace records the following event:

```bash
emit AddLP(
  account: 0x0557f67b2D5Dc575fe3e433E7caf71eA523979fD,
  tokenAddress: ZF: [0x259A9FB74d6A81eE9b3a3D4EC986F08fbb42121A],
  lpAmount: 700983951491979097527157,
  time: 1736332913
)
```

_Caption: Seed transaction trace showing the helper contract staking ZF/USDT LP tokens into LPMine, establishing a large `coarLpAmount` with a fresh `coarRewardTime`._

This establishes:

- A large `coarLpAmount` for user `0x0557f67b...`.
- `coarRewardTime` ≈ block timestamp of this transaction.
- The necessary LP position that will later be used to over-claim WTO rewards.

#### Stage 2: Flash-Loan-Assisted Reward Extraction (Tx `0x00c5a772...`, Block 45,586,395)

The second stage is the core exploit:

- The helper obtains a flash loan of `5,000,000` USDT from PancakeV3Pool `0x36696169...`:

```bash
PancakeV3Pool::flash(
  0x0557f67b2D5Dc575fe3e433E7caf71eA523979fD,
  5000000000000000000000000,
  0,
  0x...03e8
)
```

_Origin: exploit transaction trace for `0x00c5a772...`._

- The helper transfers the borrowed USDT into the ZF/USDT pair `0xBE2F4D0...`, dramatically increasing USDT reserves and distorting the price of ZF and WTO relative to USDT.
- While the pool is distorted, the helper calls `LPMine::extractReward(1)` in a very tight loop. The trace shows hundreds of such calls:

```bash
LPMine::extractReward(1)
LPMine::extractReward(1)
...
```

_Origin: exploit transaction trace with repeated `LPMine::extractReward(1)` calls._

- For each call:
  - `getCanClaimed` and `getEachReward` recompute WTO and COAR rewards using the inflated reserves from `getRemoveTokens` and `getAmountsOut`.
  - Because `extractReward(1)` updates only `wtoRewardTime`, the COAR-leg WTO component based on `coarLpAmount` and `coarRewardTime` remains effectively un-reset and is re-counted in subsequent calls.
  - `rewardPool.claimToken(WTO, amount, to)` transfers WTO out to:
    - `0x0557f67b...` (helper),
    - Referral/admin addresses `0x114FAA79...` and `0xa6184d66...`,
    - WTO/USDT pair `0x6F9070D4...`.

From the high-resolution `balance_diff.json` for tx `0x00c5a772...`:

```json
{
  "token": "0x692097f0d3bd0dfbbbbb0ee35000729f05d598f5",
  "holder": "0x3200be834b791d09017bd924c71174e47959b087",
  "before": "402632180519764450575928594",
  "after": "342495981919748743312066",
  "delta": "-402289684537844701832616528",
  "contract_name": "WTO"
}
```

_Caption: Exploit transaction balance diff showing RewardPool’s WTO balance decreasing by `402,289,684,537,844,701,832,616,528` tokens._

Companion entries show the corresponding WTO increases for the recipients:

```json
{
  "holder": "0x114faa79157c6ba61818ce2a383841e56b20250b",
  "delta": "22771114219123285009393176",
  "contract_name": "WTO"
}
{
  "holder": "0xa6184d66bf2065b37d00d66774f25b383c9e99f7",
  "delta": "11385557109561642504696700",
  "contract_name": "WTO"
}
{
  "holder": "0x6f9070d449798f4a77d43b80ddfaacabd456d50f",
  "delta": "368133013209159774318526652",
  "contract_name": "WTO"
}
```

_Caption: WTO deltas to referral/admin addresses and the WTO/USDT pair, matching the claimed over-distribution path._

After securing WTO, the helper swaps a large portion into USDT and transfers exactly `24,281,504,512,615,756,400,792` USDT to the attacker EOA.

#### Stage 3: Profit Realization via UniversalRouter (Tx `0xf33f40ee...`, Block 45,586,459)

In the final stage, the EOA monetizes the USDT:

- The EOA calls UniversalRouter `0x1A0A18AC4BECDDbd6389559687d1A73d8927E416`, passing calldata that:
  - Uses `0x31c2F6fcFf4F8759b3Bd5Bf0e1084A055615c768::permit` to allow UniversalRouter to spend its USDT.
  - Executes swaps through Pancake V3 pools and unwraps WBNB to BNB.

From the trace:

```bash
UniversalRouter::execute(...)
  ├─ 0x31c2F6fc...::permit(0x593749D5..., ..., UniversalRouter, ...)
  ├─ PancakeV3Pool::swap(...)
  │   ├─ BEP20USDT::transferFrom(0x593749D5..., PancakeV3Pool 0x172fcd41..., 20812718153670648343536)
  │   ├─ BEP20USDT::transferFrom(0x593749D5..., 0x92b7807b..., 3468786358945108057256)
  ├─ WBNB::withdraw(...)
  └─ fallback{value: ...}(0x593749D5...)
```

_Origin: iter_2 `trace.cast.log` for tx `0xf33f40ee...`._

The corresponding native balance diff shows:

```json
{
  "address": "0x593749d5414d8a735cda16e4b47cc9bfa47d5683",
  "before_wei": "867743108000000000",
  "after_wei": "35814018242109987855",
  "delta_wei": "34946275134109987855"
}
```

_Caption: Aggregator transaction balance diff confirming a BNB gain of `34.946275134109987855` for the attacker EOA._

When combined with the earlier negative deltas for the setup and exploit txs, this yields the net profit of `+33.815349128109987855` BNB.

## 6. Impact & Losses

### 6.1 Token-Level Loss

The primary loss is in WTO:

- **Total WTO loss from RewardPool**:
  - `402,289,684,537,844,701,832,616,528` WTO.
  - This is the delta in RewardPool’s WTO balance during the exploit tx `0x00c5a772...` and far exceeds any legitimate earnings from the attacker’s LP deposit.

### 6.2 Distribution of Stolen WTO

From the exploit balance diff and traces:

- RewardPool `0x3200Be83...` sends WTO to:
  - Helper contract `0x0557f67b...`.
  - Referral/admin addresses `0x114FAA79...` and `0xa6184d66...`.
  - WTO/USDT pool `0x6F9070D4...`.
- This effectively drains a large portion of RewardPool’s WTO reserves and redistributes it to:
  - The attacker cluster (EOA + helper), who ultimately convert a substantial share to USDT and then to BNB.
  - Non-cluster recipients (referral/admin addresses) whose txlists show no immediate forwarding of WTO to the EOA within the incident window.

### 6.3 Attacker Profit

- The attacker cluster’s realized profit is at least **`+33.815349128109987855` BNB**, computed as the net native balance delta of the EOA across the three attacker-crafted transactions.
- This figure already accounts for:
  - All gas spent by the EOA in txs `0x11c1ef2c...`, `0x00c5a772...`, and `0xf33f40ee...`.
  - Flash-loan fees, which are reflected in the movement of assets during the exploit and aggregator transactions.

## 7. References

The analysis is supported by the following key artifacts:

- **[1] LPMine source (getCanClaimed/getEachReward/getRemoveTokens/extractReward)**
  - Collected contract source and ABI for `0x6BBeF6DF...`, including the reward calculation functions and embedded `TokenDistributor`.
- **[2] Setup tx 0x11c1ef2c... trace and balance diff**
  - Seed trace and `balance_diff.json` document the initialization of the COAR LP position via `LPMine::partakeAddLp` and the associated `AddLP` event.
- **[3] Exploit tx 0x00c5a772... trace and balance diff**
  - Iteration-1 trace and `balance_diff.json` show the flash loan, repeated `LPMine::extractReward(1)` calls, `TokenDistributor::claimToken` executions, and the full WTO/USDT redistribution.
- **[4] Aggregator tx 0xf33f40ee... trace and balance diff**
  - Iteration-2 trace and `balance_diff.json` reconstruct the UniversalRouter call tree, USDT `transferFrom` operations from the EOA, WBNB unwrap, and the final BNB credit that yields the `+34.946275134109987855` BNB delta for the EOA.

Taken together, these artifacts deterministically support the conclusion that a protocol bug in LPMine’s reward accounting, when combined with flash-loan-based reserve manipulation, allowed an unprivileged attacker to over-claim WTO from RewardPool and realize a substantial BNB profit.

