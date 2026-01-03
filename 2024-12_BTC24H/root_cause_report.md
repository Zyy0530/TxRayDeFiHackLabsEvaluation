# BTC24H Lock Claim Drain on Polygon

This report summarizes an ACT-style root cause analysis of a protocol bug in the BTC24H Lock (Polygon) time-lock contract that enabled a fully permissionless drain of 110000 BTC24H tokens via a malicious aggregator flow. The incident occurs on Polygon (chainid 137), with the ACT opportunity anchored at block 65560669 and is categorized as a **protocol_bug**.

## Incident Overview & TL;DR

An adversary-controlled aggregator contract on Polygon calls a vulnerable `Lock` contract’s `claim()` function to withdraw 110000 BTC24H tokens that were previously deposited by another address. Immediately after withdrawing the funds, the aggregator routes the BTC24H through Uniswap V3 liquidity via `UniversalRouter`, swapping into USDT and WBTC. The adversary EOA ends the exploit transaction with thousands of dollars of net profit after paying gas.

The key property making this exploit fully permissionless is that `Lock.claim()` only checks that the release time has passed and that the claim has not already been used. It does **not** restrict the withdrawal to the original depositor or any designated beneficiary. Any unprivileged actor observing the Lock’s state after `releaseDate` can call `claim()` (directly or via a helper like the observed aggregator) and perform the same DEX routing using public liquidity.

At a high level, the root cause is a logic bug in `Lock.sol`: `claim()` enforces only time-based and single-use constraints and does not authenticate the caller, allowing arbitrary addresses to drain the entire configured `Claim` amount once the release time is reached.

## Key Background

- **BTC24H token**: BTC24H (`0xea4b5c48a664501691b2ecb407938ee92d389a6f`) is an `ERC20Burnable` token on Polygon with a fixed total supply minted to its deployer and no custom transfer behavior beyond standard ERC20 semantics.
- **Lock contract**: `Lock.sol` (`0x968e1c984A431F3D0299563F15d48C395f70F719`) is a simple time-lock contract for an ERC20 token. It stores a single `Claim` `{ amount, releaseDate, claimed }` and exposes `deposit()` and `claim()` without tracking who deposited or who should be allowed to claim.
- **Routing and liquidity**: `UniversalRouter` (`0xec7BE89e9d109e7e3Fec59c222CF297125FEFda2`) and Uniswap V3 pools `0xd06cD277CD01A630dcB8C7D678529d8a4111A02A` (BTC24H/USDT) and `0x495e8f82F3941C1Fd661151E5c794745e1e31027` (BTC24H/WBTC) provide public routing paths to swap BTC24H into liquid assets such as USDT and WBTC on Polygon.
- **Adversary-controlled aggregator**: The aggregator contract `0x3cb2452c615007b9ef94d5814765eb48b71ae520` is used exclusively by EOA `0xde0a99fb39e78efd3529e31d78434f7645601163` in the relevant block window and hard-codes this address in its decompiled bytecode. This supports its role as an attacker helper contract rather than neutral infrastructure.

## ACT Opportunity & Pre-State

### ACT opportunity anchor

- **Block height B**: `65560669` on Polygon (`chainid 137`).

### Pre-state σ_B

Immediately before block 65560669, the Polygon state satisfies:

- The `Lock` contract `0x968e1c984A431F3D0299563F15d48C395f70F719` holds exactly `110000 * 1e18` BTC24H tokens deposited by EOA `0x88538ab036824f5b8b904f3e3c6015d125aa629e` in transaction `0x2cf0a8091065beb8849b219507e54121ace4b8000876611b3af2499beb44d7ed`.
- The `claims` struct in `Lock` storage is:
  - `amount = 110000 * 1e18`
  - `releaseDate = 1734220800`
  - `claimed = false`
- BTC24H, `UniversalRouter`, and the Uniswap V3 pool contracts referenced above are deployed and liquid, with standard balances.

This pre-state description is corroborated by:

- Verified BTC24H source: `artifacts/root_cause/data_collector/iter_1/contract/137/0xea4b5c48a664501691b2ecb407938ee92d389a6f/source/src/BTC24H.sol`
- Verified `Lock.sol` source: `artifacts/root_cause/data_collector/iter_1/contract/137/0x968e1c984A431F3D0299563F15d48C395f70F719/source/src/Lock.sol`
- Address-level txlist for `Lock`: `artifacts/root_cause/data_collector/iter_2/address/137/0x968e1c984A431F3D0299563F15d48C395f70F719/etherscan_txlist_0-65560669.json`
- Deposit tx trace and balance diff: `artifacts/root_cause/data_collector/iter_2/tx/137/0x2cf0a8091065beb8849b219507e54121ace4b8000876611b3af2499beb44d7ed/trace.cast.log` and `balance_diff.json`

### Transaction sequence from σ_B

From σ_B, any unprivileged EOA on Polygon can construct a valid exploit transaction:

- **Observed adversary-crafted transaction**:
  - `chainid`: `137`
  - `txhash`: `0x554c9e4067e3bc0201ba06fc2cfeeacd178d7dd9c69f9b211bc661bb11296fde`
  - `type`: adversary-crafted
  - **Feasibility**: From σ_B, any EOA can call `Lock.claim()` (directly or via its own aggregator) after `releaseDate`, using only public ABI/source and on-chain state. The observed tx is one such example, sent by EOA `0xde0a99fb39e78efd3529e31d78434f7645601163` to its aggregator `0x3cb2452c615007b9ef94d5814765eb48b71ae520` with standard gas price and zero ETH value and is valid under normal consensus rules.
  - **Behavior**: The transaction invokes the adversary-controlled aggregator, which calls `Lock.claim()` on `0x968e1c984A431F3D0299563F15d48C395f70F719` to withdraw 110000 BTC24H, then routes those tokens through `UniversalRouter` into BTC24H/USDT and BTC24H/WBTC Uniswap V3 pools so that EOA `0xde0a99…1163` receives USDT and WBTC while paying MATIC gas.

### Exploit profit predicate

The exploit is evaluated under a **profit-based** ACT predicate with USDT as the reference asset:

- **Adversary EOA**: `0xde0a99fb39e78efd3529e31d78434f7645601163`
- **Fees paid in reference asset**: `4.609899604248644410` USDT-equivalent
- **Value before in reference asset**: unknown
- **Value after in reference asset**: unknown
- **Value delta in reference asset**: `>= 4948.415489395751355` (ignoring any value from `0.76433345` WBTC proceeds)

The seed exploit transaction’s balance diff (`balance_diff.json` for tx `0x554c9e40…96fde`) shows:

- EOA `0xde0a99…1163` gains `4953025389` units of `UChildUSDT0` (USDT with 6 decimals), i.e. `4,953.025389` USDT.
- EOA `0xde0a99…1163` receives `76433345` units of WBTC (8 decimals), i.e. `0.76433345` WBTC.
- The same EOA’s native MATIC-equivalent balance decreases by `7.624397058625146765` MATIC in gas (`7624397058625146765` wei).

To value gas in USDT, a separate DEX pricing transaction (`0x6c22c0575812a7240dc16c21d24c0eaa97c21af88d3a5e7099b9cda0f3e55339`) executes within roughly 20 blocks of the exploit and shows:

- `2791.729517090832363471` MATIC swapping for `1687.948922` USDT, implying an on-chain rate of approximately `0.604624807549033232` USDT per MATIC.

Using this rate, the gas cost in the seed transaction is:

- `7.624397058625146765` MATIC × `0.604624807549033232` USDT/MATIC ≈ `4.609899604248644410` USDT.

Even valuing the WBTC proceeds at zero (a conservative assumption, given WBTC is liquid), the adversary’s net gain in the USDT reference asset is therefore **at least `4948.415489395751355` USDT**. This is a strict lower bound establishing a net-positive profit after fees.

The analysis does not use any non-monetary predicate; oracle-related fields are not applicable here.

## Vulnerability & Root Cause Analysis

### Vulnerability summary

`Lock.claim()` lacks any notion of ownership or beneficiary and allows any caller to withdraw the entire configured `Claim` amount once `releaseDate` has passed. This effectively turns the contract into a publicly drainable vault for whichever token and amount were previously deposited via `deposit()`.

### Contract-level behavior

The Lock contract is parameterized by an `IERC20` token and stores a single `Claim` struct:

- `uint256 amount`
- `uint256 releaseDate`
- `bool claimed`

In `deposit()`, the contract:

- Transfers a hard-coded `110000 * 1e18` units of the token from `msg.sender` into the contract via `SafeERC20.safeTransferFrom`.
- Unconditionally sets:
  - `claims.amount = 110000 * 1e18`
  - `claims.releaseDate = 1734220800`
  - `claims.claimed = false`

Crucially:

- `deposit()` does **not** record the depositor’s address or any beneficiary.
- `claim()` is declared `external` and callable by any address.

The core of the vulnerable logic is visible in the verified `Lock.sol` source.

_Verified Lock.sol source on Polygon (excerpt showing the vulnerable deposit/claim behavior):_

```solidity
// Lock.sol (Polygon 0x968e1c984A431F3D0299563F15d48C395f70F719)
contract Lock {
    using SafeERC20 for IERC20;

    struct Claim {
        uint256 amount;
        uint256 releaseDate;
        bool claimed;
    }

    IERC20 public token;
    address public owner;
    Claim private claims;

    function deposit() external {
        uint256 totalAmount = 110000;

        token.safeTransferFrom(
            msg.sender,
            address(this),
            totalAmount * 1 ether
        );

        claims = Claim({
            amount: 110000 * 1 ether,
            releaseDate: 1734220800,
            claimed: false
        });
    }

    function claim() external onlyOnOrAfter(claims.releaseDate) {
        require(!claims.claimed, 'Already claimed');

        claims.claimed = true;
        uint256 claimAmount = claims.amount;
        token.safeTransfer(msg.sender, claimAmount);
    }
}
```

This code shows that `claim()` transfers the full `claims.amount` to **whoever calls the function**, provided the timestamp condition and one-time-use condition pass. There is no binding between `claims` and a depositor or beneficiary.

### Root cause detail

Given the above behavior, once a victim deposits 110000 BTC24H and the `releaseDate` is reached:

- Any arbitrary caller (EOA or contract) can invoke `claim()` and have the full `110000 * 1e18` BTC24H transferred directly to themselves.
- The contract enforces the time lock, but **not** ownership of the locked funds.

This violates basic expectations of a time-locked deposit and constitutes an unambiguous **access-control failure** in the contract’s withdrawal logic:

- There is no authentication tying the claim to the depositor.
- The system behaves as a custodial vault that pays out to whoever asks at the right time.

### Exploit conditions

For the exploit to succeed, the following conditions must hold:

1. A victim address calls `deposit()` on the `Lock` contract, successfully transferring `110000 * 1e18` units of BTC24H into the contract and setting `claims.amount` and `claims.releaseDate` in storage.
2. The chain’s `block.timestamp` is at or after `claims.releaseDate` (`1734220800` for this deployment), so that the `onlyOnOrAfter` guard in `claim()` passes.
3. No prior successful call to `claim()` has flipped `claims.claimed` to `true`; otherwise the `require(!claims.claimed)` check would revert.
4. An adversary (or any unprivileged user) is able to submit a transaction calling `claim()` on `Lock`, directly from an EOA or via a helper contract such as the observed aggregator, and then route the received BTC24H through available DEX liquidity to obtain more liquid assets.

### Security principles violated

The vulnerability breaks several core security principles:

- **Broken access control**: The withdrawal function does not authenticate the caller as the depositor or an entitled beneficiary.
- **Incorrect authorization model for time-locked funds**: The contract treats a global `Claim` structure as implicitly belonging to whichever address calls `claim()`, rather than binding it to a specific principal.
- **Failure to enforce custodial invariants**: Assets deposited into `Lock` are not tied to a durable ownership record, enabling arbitrary third parties to unilaterally withdraw them once time conditions are met.

## Adversary Flow Analysis

### High-level adversary strategy

The adversary’s strategy is straightforward:

1. Identify a `Lock` contract instance holding 110000 BTC24H with a permissionless `claim()` function.
2. Wait until the configured `releaseDate` has passed.
3. Use a bespoke aggregator contract to:
   - Call `Lock.claim()` and pull the full 110000 BTC24H into the aggregator.
   - Route BTC24H through `UniversalRouter` into Uniswap V3 pools, swapping into USDT and WBTC.
4. Receive all resulting USDT and WBTC in the adversary EOA, while paying standard gas fees.

The entire exploit can be replicated by any unprivileged actor as long as similar deposits exist and `claim()` remains permissionless.

### Adversary-related accounts

The analysis identifies a clear adversary cluster and victim candidates:

- **Adversary cluster**
  - **EOA 0xde0a99fb39e78efd3529e31d78434f7645601163**
    - Chain: Polygon (137)
    - Type: EOA (`is_eoa = true`, `is_contract = false`)
    - Justification: Sender of the attacker-crafted seed transaction `0x554c9e40…96fde`. Over the relevant block window, this EOA is the exclusive user of the aggregator `0x3cb2…520` and is the direct recipient of all USDT and WBTC proceeds in the exploit transaction’s balance diff.
  - **Aggregator contract 0x3cb2452c615007b9ef94d5814765eb48b71ae520**
    - Chain: Polygon (137)
    - Type: contract (`is_contract = true`)
    - Justification: This contract receives calls from `0xde0a99…1163` and, in the seed transaction, calls `Lock.claim()` and orchestrates routing through `UniversalRouter`. An address-level txlist shows it is invoked only by `0xde0a99…1163` over blocks 65550000–65570000, and its decompiled code hard-codes `0xde0a99…1163`, supporting the conclusion that it is adversary-controlled.

_Decompiled aggregator source (excerpt showing hard-coded reference to the adversary EOA):_

```solidity
// DecompiledContract for 0x3cb2452c615007b9ef94d5814765eb48b71ae520 (excerpt)
function Unresolved_8c565ad1(uint256 arg0, address arg1) public payable {
    require(msg.value);
    require(!(msg.sender == tx.origin), "E");
    // ...
    require(!msg.sender == 0xde0a99fb39e78efd3529e31d78434f7645601163);
    // ...
}
```

This snippet illustrates that the aggregator’s decompiled logic directly references the adversary EOA, consistent with a bespoke helper contract rather than a neutral router.

- **Victim candidates**
  - **BTC24H Lock time-lock**
    - Address: `0x968e1c984A431F3D0299563F15d48C395f70F719`
    - Chain: Polygon (137)
    - Verified: true
  - **BTC24H depositor EOA**
    - Address: `0x88538ab036824f5b8b904f3e3c6015d125aa629e`
    - Chain: Polygon (137)
    - Verification status: unknown

### Adversary lifecycle stages

#### 1. Victim BTC24H deposit into Lock

- **Transaction**
  - Chain: Polygon (137)
  - Tx: `0x2cf0a8091065beb8849b219507e54121ace4b8000876611b3af2499beb44d7ed`
  - Block: `65358245`
  - Mechanism: transfer
- **Effect**
  - EOA `0x88538ab036824f5b8b904f3e3c6015d125aa629e` calls `Lock.deposit()`.
  - 110000 BTC24H are transferred from the EOA to the `Lock` contract.
  - `claims.amount` is set to `110000 * 1e18`, `claims.releaseDate` to `1734220800`, and `claims.claimed` to `false`, leaving the tokens custodied by `Lock`.
- **Evidence**
  - Deposit trace and balance diff at:
    - `artifacts/root_cause/data_collector/iter_2/tx/137/0x2cf0a8091065beb8849b219507e54121ace4b8000876611b3af2499beb44d7ed/trace.cast.log`
    - `artifacts/root_cause/data_collector/iter_2/tx/137/0x2cf0a8091065beb8849b219507e54121ace4b8000876611b3af2499beb44d7ed/balance_diff.json`
  - Verified `Lock.sol` source as quoted above.

#### 2. Adversary-controlled aggregator usage and setup

- **Transactions**
  - `0x3176f78c0e00e7aa9b308a2c6286949888c6deb8f4a9670ad0e60d20a4c0b274` (Polygon, block `65551183`, mechanism `other`)
  - `0x717a280a2b876ce80441eb09ea92c6d2cc91a0ac80a7b1d7077d6f2167f9636b` (Polygon, block `65551185`, mechanism `other`)
- **Effect**
  - In the exploit window, EOA `0xde0a99…1163` repeatedly calls aggregator `0x3cb2…520` using custom entrypoints (e.g., `buyAndFree22457070633(uint256 amount)`).
  - This pattern demonstrates that the aggregator is a bespoke helper contract used solely by this EOA rather than a shared public router.
- **Evidence**
  - Etherscan account txlist for the aggregator:
    - `artifacts/root_cause/data_collector/iter_2/address/137/0x3cb2452c615007b9ef94d5814765eb48b71ae520/etherscan_txlist_65550000-65570000.json`
  - Decompiled aggregator source/ABI:
    - `artifacts/root_cause/data_collector/iter_3/contract/137/0x3cb2452c615007b9ef94d5814765eb48b71ae520/decompile/`

#### 3. Adversary exploit execution and profit realization

- **Transaction (seed exploit)**
  - Chain: Polygon (137)
  - Tx: `0x554c9e4067e3bc0201ba06fc2cfeeacd178d7dd9c69f9b211bc661bb11296fde`
  - Block: `65560669`
  - Mechanism: transfer
- **Effect**
  - At block 65560669, after `claims.releaseDate` has passed, EOA `0xde0a99…1163` sends `0x554c9e40…96fde` to aggregator `0x3cb2…520`.
  - The aggregator calls `Lock.claim()`, pulling the full 110000 BTC24H into the aggregator pipeline.
  - The aggregator then uses `UniversalRouter` to:
    - Swap `10000` BTC24H for USDT in the BTC24H/USDT pool.
    - Swap `100000` BTC24H for WBTC in the BTC24H/WBTC pool.
  - EOA `0xde0a99…1163` receives `4953.025389` USDT and `0.76433345` WBTC while paying `7.624397058625146765` MATIC in gas.

_Seed exploit transaction trace (cast run -vvvvv excerpt showing Lock.claim and swaps):_

```text
// Trace for 0x554c9e4067e3bc0201ba06fc2cfeeacd178d7dd9c69f9b211bc661bb11296fde (excerpt)
0x3CB2452c615007B9eF94D5814765eB48b71Ae520::fulfillBasicOrder_efficient_6GL6yc()
  ├─ BTC24H::balanceOf(0x968e1c984A431F3D0299563F15d48C395f70F719)
  ├─ 0x968e1c984A431F3D0299563F15d48C395f70F719::claim()
  │   ├─ BTC24H::transfer(0x3CB2452c615007B9eF94D5814765eB48b71Ae520, 110000000000000000000000)
  ├─ BTC24H::transfer(UniversalRouter: 0xec7BE89e9d109e7e3Fec59c222CF297125FEFda2, 10000000000000000000000)
  ├─ UniversalRouter::execute(...)
  │   ├─ ... UChildUSDT0::transfer(0xDE0A99Fb39E78eFd3529e31D78434f7645601163, 4953025389)
  │   ├─ ... WBTC::transfer(0xDE0A99Fb39E78eFd3529e31D78434f7645601163, 76433345)
```

This trace shows:

- `Lock.claim()` transferring the full 110000 BTC24H from the `Lock` contract to the aggregator.
- Subsequent DEX routing via `UniversalRouter`.
- Final transfers of USDT and WBTC to the adversary EOA.

_Seed exploit balance diff (excerpt showing USDT gain and gas cost):_

```json
{
  "chainid": 137,
  "txhash": "0x554c9e4067e3bc0201ba06fc2cfeeacd178d7dd9c69f9b211bc661bb11296fde",
  "native_balance_deltas": [
    {
      "address": "0xde0a99fb39e78efd3529e31d78434f7645601163",
      "before_wei": "16350599970881081823519",
      "after_wei": "16342975573822456676754",
      "delta_wei": "-7624397058625146765"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
      "holder": "0xde0a99fb39e78efd3529e31d78434f7645601163",
      "before": "1052711368",
      "after": "6005736757",
      "delta": "4953025389",
      "contract_name": "UChildUSDT0"
    }
  ]
}
```

This confirms that:

- The adversary EOA pays ~7.62 MATIC in gas for the exploit tx.
- The same address receives ~4.953 million USDT base units (`4953025389` with 6 decimals).

The WBTC gain is also recorded in the full balance diff (not shown here), contributing additional positive value.

### All relevant transactions summary

The analysis designates the following as **all relevant transactions** for the exploit:

- `0x2cf0a8091065beb8849b219507e54121ace4b8000876611b3af2499beb44d7ed` (Polygon 137) — **victim-observed**: deposit of 110000 BTC24H into `Lock`.
- `0x554c9e4067e3bc0201ba06fc2cfeeacd178d7dd9c69f9b211bc661bb11296fde` (Polygon 137) — **adversary-crafted**: exploit transaction draining the Lock and routing via DEXs.
- `0x6c22c0575812a7240dc16c21d24c0eaa97c21af88d3a5e7099b9cda0f3e55339` (Polygon 137) — **related**: DEX pricing transaction used to infer the MATIC→USDT conversion rate for valuing gas costs.

## Impact & Losses

### Token-level losses

- **Total BTC24H lost**: `110000` BTC24H.
- These tokens were deposited by EOA `0x88538ab036824f5b8b904f3e3c6015d125aa629e` into `Lock` and subsequently withdrawn by the adversary-controlled flow.

### Impact description

- The immediate on-chain impact is that 110000 BTC24H tokens, originally deposited into the `Lock` contract as time-locked funds, are irreversibly withdrawn by an unprivileged third party.
- The withdrawn BTC24H are swapped into USDT and WBTC, leaving the original depositor with no BTC24H remaining in `Lock`.
- The adversary EOA `0xde0a99fb39e78efd3529e31d78434f7645601163` realizes a **net-positive profit** of at least ~`4948` USDT-equivalent after accounting for gas, even before valuing WBTC.
- The exploit does **not** rely on transient price manipulation; it purely abuses flawed authorization logic around `claim()` and can be replicated by any actor as long as similar deposits exist and the function remains permissionless.

## References

- **[1] Lock.sol verified source**  
  Collected verified source for the `Lock` contract on Polygon (`0x968e1c984A431F3D0299563F15d48C395f70F719`), including the vulnerable `deposit()` and `claim()` logic.
- **[2] Seed exploit tx trace and balance diff**  
  Cast trace (`trace.cast.log`) and `balance_diff.json` for the exploit transaction `0x554c9e40…96fde`, showing the call path from the aggregator through `Lock.claim()` and DEX routing, and the resulting balance changes for BTC24H, USDT, WBTC, and MATIC.
- **[3] Deposit tx into Lock trace and balance diff**  
  Trace and balance diff for the victim deposit transaction `0x2cf0a8091065beb8849b219507e54121ace4b8000876611b3af2499beb44d7ed`, confirming the movement of 110000 BTC24H into the `Lock` contract and the configuration of `claims` storage.
- **[4] DEX MATIC/USDT pricing tx trace and balance diff**  
  Trace and balance diff for transaction `0x6c22c0575812a7240dc16c21d24c0eaa97c21af88d3a5e7099b9cda0f3e55339`, used to infer the on-chain MATIC→USDT exchange rate for valuing gas costs in the exploit.
- **[5] Aggregator decompiled source and ABI**  
  Decompiled Solidity and ABI for aggregator `0x3cb2…520`, showing hard-coded references to the adversary EOA and supporting its classification as an attacker-controlled helper contract.

