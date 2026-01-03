## Incident Overview & TL;DR

At BSC block 45535986, an unprivileged adversary exploited a design flaw in the RaceCar Main contract at `0xB040D88e61EA79a1289507d56938a6AD9955349C`.  
The protocol had pre-approved the Pancake router to spend its contract-owned Token `0xc0dDfD66420ccd3a337A17dD5D94eb54ab87523F` and BEP20USDT `0x55d398326f99059fF775485246999027B3197955`, and exposed a public router wrapper `swapTokensForTokens` that spends these balances on behalf of any caller.

In the observed exploit transaction `0x61da5b502a62d7e9038d73e31ceb3935050430a7f9b7e29b9b3200db3095f91d`, attacker EOA `0x67a5f6bd9f8763c7e6c4ea0b54d1b14b9e5ee7e2` deployed a helper contract whose constructor:
- Read `Token.balanceOf(0xB040...)`, and
- Immediately invoked `Main.swapTokensForTokens` with path `[Token, USDT]`, `amountIn` equal to Main’s entire Token balance, `tokenOutMin = 0`, and `to = attacker EOA`.

The Pancake router then pulled all of Main’s Token into the Token/USDT PancakePair `0xa0ad4B45dc432e950f9e62AAA46995CE40ef4a11` and swapped it for `27,995,389,614,557,976,722,846` units of BEP20USDT, which were sent directly to the attacker.  
The attacker contributed no USDT in the same transaction and paid only BNB gas (~0.0182807 BNB), deterministically draining protocol-owned Token value and AMM USDT reserves into their own portfolio.

**Root cause (brief):**  
The Main contract pre-approved the Pancake router for effectively unlimited Token and USDT and exposed an unguarded public `swapTokensForTokens` wrapper that causes the contract itself to spend its Token/USDT balances and send swap outputs to arbitrary recipients. Under the standard ACT adversary model, any unprivileged party who observes this configuration and Main’s Token holdings can deterministically profit by calling `swapTokensForTokens` to swap protocol-held Token into USDT for their own address.

---

## ACT Opportunity

### Block height and pre-state (B, σ\_B)

- **Chain:** BSC (chainid 56)  
- **Block height B:** `45535986`

At or before block 45535986, public on-chain state shows:
- Main contract `0xB040D88e61EA79a1289507d56938a6AD9955349C`:
  - Holds a large balance of Token `0xc0dDfD66420ccd3a337A17dD5D94eb54ab87523F`.
  - Has granted effectively unlimited allowances of Token and BEP20USDT `0x55d398326f99059fF775485246999027B3197955` to the Pancake router `0x10ED43C718714eb63d5aA57B78B54704E256024E`.
- PancakePair `0xa0ad4B45dc432e950f9e62AAA46995CE40ef4a11`:
  - Holds significant Token and USDT reserves, visible from on-chain storage and the seed transaction trace.

This pre-state σ\_B is fully reconstructible from chain 56:
- The Main contract and Token are verified.
- Router allowances and pair reserves are available via standard RPC and explorer queries.

**Key evidence for σ\_B:**

- Seed transaction metadata and balance diffs for tx `0x61da5b50...f91d` (used to read pre/post balances and reserves).
- Verified source for Main `0xB040...` and PancakePair `0xa0ad4B45...`.

```json
{
  "chainid": 56,
  "txhash": "0x61da5b502a62d7e9038d73e31ceb3935050430a7f9b7e29b9b3200db3095f91d",
  "erc20_balance_deltas": [
    {
      "token": "0xc0ddfd66420ccd3a337a17dd5d94eb54ab87523f",
      "holder": "0xa0ad4b45dc432e950f9e62aaa46995ce40ef4a11",
      "before": "358066132355143794224838635",
      "after": "97913966927305448092794249824",
      "delta": "97555900794950304298569411189"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xa0ad4b45dc432e950f9e62aaa46995ce40ef4a11",
      "before": "28098400545846145078795",
      "after": "103010931288168355949",
      "delta": "-27995389614557976722846"
    }
  ]
}
```
*Caption: Seed transaction balance diff on BSC 56 showing Token inflow and USDT outflow for PancakePair 0xa0ad4B45..., used to reconstruct pre/post reserves around block 45535986.*

### Transaction sequence b

The minimal exploit sequence **b** consists of a single adversary-crafted transaction on chain 56:

1. **Tx 1 (index 1)**  
   - **Chain:** BSC (56)  
   - **Txhash:** `0x61da5b502a62d7e9038d73e31ceb3935050430a7f9b7e29b9b3200db3095f91d`  
   - **Type:** Adversary-crafted  
   - **Mechanism:** Helper contract deployment with constructor-based exploit
   - **Inclusion feasibility:**  
     Any unprivileged EOA on BSC can:
     - Deploy the same helper contract bytecode, or
     - Send a direct transaction calling `0xB040...::swapTokensForTokens` with:
       - `path = [Token, USDT]`
       - `tokenAmount = Token.balanceOf(0xB040...)`
       - `tokenOutMin = 0`
       - `to = attacker_EOA`
     using normal gas pricing, without private orderflow or privileged keys.

In the observed tx, attacker EOA `0x67a5...` deploys helper contract `0xf455...`.  
The helper constructor:
- Reads `Token.balanceOf(0xB040...)`, then
- Calls `Main.swapTokensForTokens` with the full Token balance and recipient set to the attacker EOA.

```text
Traces:
  [123965] → new <unknown>@0xf455c7...(bytecode)
    ├─ [2670] Token::balanceOf(0xB040D88e61EA79a1289507d56938a6AD9955349C) [staticcall]
    │   └─ ← [Return] 97555900794950304298569411189
    ├─ [101417] 0xB040D88e61EA79a1289507d56938a6AD9955349C::swapTokensForTokens(
    │         [Token, USDT],
    │         97555900794950304298569411189,
    │         0,
    │         0x67A5f6bd9F8763c7E6C4EA0b54D1b14B9e5ee7E2
    │   )
    │   ├─ PancakeRouter::swapExactTokensForTokensSupportingFeeOnTransferTokens(...)
    │   │   ├─ Token::transferFrom(0xB040..., PancakePair: [0xa0ad4B45...], 9755590...11189)
    │   │   ├─ PancakePair::swap(27995389614557976722846, 0, 0x67A5f6bd..., 0x)
    │   │   │   ├─ BEP20USDT::transfer(0x67A5f6bd..., 27995389614557976722846)
    │   │   │   └─ emits Swap/Sync events
```
*Caption: Seed transaction execution trace for tx 0x61da5b50...f91d showing helper constructor, Main.swapTokensForTokens, Token.transferFrom from Main, and USDT transfer from the PancakePair to the attacker EOA.*

### Exploit predicate

**Type:** Profit (monetary, in USD reference asset via USDT)

- **Reference asset:** USD (via BEP20USDT stablecoin)  
- **Adversary address:** `0x67a5f6bd9f8763c7e6c4ea0b54d1b14b9e5ee7e2`  
- **Fees paid:** ~0.0182807 BNB gas (from native balance diffs)  
- **USDT value before:** 0 BEP20USDT held by the attacker in this tx  
- **USDT value after:** `27,995,389,614,557,976,722,846` BEP20USDT units  
- **Net value delta (USDT):** Large strictly positive USDT PnL (minus negligible gas).

Evidence shows:
- The PancakePair’s USDT balance decreases by `27,995,389,614,557,976,722,846` units.
- The attacker’s USDT balance increases by the same amount.
- The attacker does not supply USDT in the same transaction; their only cost is BNB gas.
Given BEP20USDT’s USD peg, this constitutes a strictly positive net profit in the USD reference asset.

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xa0ad4b45dc432e950f9e62aaa46995ce40ef4a11",
      "delta": "-27995389614557976722846"
    }
  ],
  "native_balance_deltas": [
    {
      "address": "0x67a5f6bd9f8763c7e6c4ea0b54d1b14b9e5ee7e2",
      "delta_wei": "-18280700000000000"
    }
  ]
}
```
*Caption: Seed transaction balance summary indicating large USDT outflow from the pair and only BNB gas cost for the attacker, establishing positive USDT profit.*

---

## Key Background

### Protocol and contracts

- **Protocol:** RaceCar / Main on BSC  
- **Main contract:** `0xB040D88e61EA79a1289507d56938a6AD9955349C`  
  - Owns and manages user funds and protocol liquidity.
  - Integrates with:
    - Token `0xc0dDfD66420ccd3a337A17dD5D94eb54ab87523F` (RaceCar token-like asset).
    - BEP20USDT `0x55d398326f99059fF775485246999027B3197955`.
    - Pancake router `0x10ED43C718714eb63d5aA57B78B54704E256024E`.
    - PancakePair `0xa0ad4B45dc432e950f9e62AAA46995CE40ef4a11` (Token/USDT pair).

The protocol logic includes:
- Car purchases (`buyCar`) funded in USDT.
- Race participation and rewards (`raceCar`, `raceCarWin`).
- Guild-related features.
- Liquidity management (`addLiquidityUsdt`) and controlled withdrawals (`withdraw`, `withdrawToken`).

Main is designed to:
- Receive USDT from users.
- Swap portions of USDT into Token.
- Burn or redistribute Token.
- Add liquidity using its internal Token and USDT balances.

### Router wrapper and approvals

The Main contract inherits a local PancakeRouter wrapper that hardcodes the official router and exposes public helpers, including `swapTokensForTokens`:

```solidity
interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
}

contract PancakeRouter {
    IPancakeRouter public constant _IPancakeRouter =
        IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    function swapTokensForTokens(
        address[] memory path,
        uint256 tokenAmount,
        uint256 tokenOutMin,
        address to
    ) public {
        _IPancakeRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            tokenAmount,
            tokenOutMin,
            path,
            to,
            block.timestamp + 60
        );
    }
}
```
*Caption: Verified router wrapper for Main on BSC, exposing a public swapTokensForTokens that simply forwards to PancakeRouter using the caller’s allowances and balances.*

In `Main`’s constructor:
- USDT and Token are defined and approved for the router:

```solidity
contract Main is PancakeRouter, Ownable {
    using SafeERC20 for IERC20;
    IERC20 public constant USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 public Token = IERC20(0xc0dDfD66420ccd3a337A17dD5D94eb54ab87523F);
    // ...
    constructor(address initialOwner, uint256 time_) Ownable(initialOwner) {
        // ...
        USDT.approve(address(_IPancakeRouter), type(uint256).max);
        Token.approve(address(_IPancakeRouter), type(uint256).max);
        // ...
    }
}
```
*Caption: Main constructor pre-approving the Pancake router for effectively unlimited USDT and Token from the contract’s own balances.*

### Normal intended flows

Examples of intended protocol flows include:
- `buyCar`:
  - User pays USDT to Main.
  - Main calls `sendToken` to distribute Token rewards.
  - Main uses `swapTokensForTokens` to swap half of received USDT into Token (sent to a burn address).
  - Remaining USDT is transferred to a receiver address.
- `raceCarWin`:
  - Trusted operator (`allowRaceCarWin`) triggers Token rewards and USDT-funded liquidity provisioning via `addLiquidityUsdt`.
- `withdraw` / `withdrawToken`:
  - Whitelisted addresses (`allowanceWithdrawAddr`) can withdraw USDT or arbitrary tokens on behalf of users or treasury addresses.

These flows rely on Main holding Token and USDT in its own balances and using the router to trade them, but they assume only trusted code paths invoke the actual swaps.

---

## Vulnerability & Root Cause Analysis

### Vulnerability brief

The protocol’s router wrapper exposes a **public** `swapTokensForTokens` function that:
- Directly spends contract-owned Token and USDT (via the router),
- Is callable by any address (no access control), and
- Sends swap outputs to an arbitrary recipient address.

Because Main pre-approves the router for its own Token and USDT balances, this function effectively grants **any caller** the ability to:
- Spend Main’s Token/USDT, and
- Route the proceeds to arbitrary addresses.

This arbitrary-spend primitive over protocol-owned assets is the core vulnerability.

### Detailed root cause

1. **Unlimited allowances from Main to Pancake router**
   - In `Main`’s constructor, both USDT and Token are approved to the Pancake router address with `type(uint256).max`.
   - This means the router can always call `transferFrom` to pull Token and USDT from Main’s address, as long as the balance is sufficient.

2. **Public unguarded router wrapper**
   - `swapTokensForTokens` in the `PancakeRouter` base contract is:
     - Public.
     - Unrestricted (no `onlyOwner`, `onlyEOA`, or equivalent).
     - Not overridden or wrapped with additional checks in `Main`.
   - Calls to `Main.swapTokensForTokens` execute in the context of Main and:
     - Use Main’s allowances to the router.
     - Make the router pull tokens directly from Main’s balances.
     - Send resulting tokens to an arbitrary `to` address.

3. **No path or recipient constraints**
   - The function does not:
     - Restrict `path` to specific combinations (e.g., user-owned tokens).
     - Enforce that `to` is the Main contract, a treasury, or a controlled sink.
     - Check `msg.sender` against any allowlist.
   - This allows attackers to:
     - Choose `[Token, USDT]` as the path.
     - Set `tokenAmount` to Main’s full Token balance.
     - Set `to` to an attacker-controlled EOA.

4. **Exploit instantiation in seed tx**
   - The helper contract constructor:
     - Reads `Token.balanceOf(0xB040...)` to determine Main’s Token holdings.
     - Calls `Main.swapTokensForTokens` with:
       - `path = [Token, USDT]`
       - `tokenAmount = Token.balanceOf(Main)`
       - `tokenOutMin = 0`
       - `to = attacker EOA`.
   - Because the router is pre-approved:
     - Token is pulled from Main into the PancakePair.
     - The pair swaps Token for USDT under the AMM invariant.
     - USDT is transferred directly to the attacker EOA.

Overall, the root cause is **insecure exposure of a router wrapper that spends contract-owned assets via a pre-approved DEX router on behalf of arbitrary callers**, violating standard DeFi access control and asset separation principles.

### Vulnerable components

- **Main contract at `0xB040D88e61EA79a1289507d56938a6AD9955349C`**
  - Inherits `PancakeRouter` wrapper.
  - Exposes `swapTokensForTokens(address[] memory path, uint256 tokenAmount, uint256 tokenOutMin, address to)` as a public entrypoint.
- **Main constructor**
  - Grants unlimited Token and USDT allowances to the Pancake router `0x10ED43C718714eb63d5aA57B78B54704E256024E`.

### Exploit conditions

For the exploit to succeed, the following conditions must hold (and did hold at B, σ\_B):

1. Main holds a non-trivial balance of Token and/or USDT.
2. Main has active unlimited allowances for Token and USDT to router `0x10ED43C7...`.
3. `swapTokensForTokens` is callable by arbitrary addresses (no access control).
4. PancakePair `0xa0ad4B45...` has sufficient USDT reserves to pay out the desired amount when swapping the contract-owned Token balance.

All of these are confirmed by:
- Verified Main source code.
- PancakePair source and seed trace reserves.
- Balance diffs around the exploit transaction.

### Security principles violated

- **Least privilege:**  
  The router wrapper is granted broad allowances over protocol-owned assets, without limiting who may trigger spending or under what conditions.

- **Access control:**  
  Critical asset-moving functionality (swapping Main’s internal Token/USDT balances to arbitrary recipients) is exposed as a public function instead of being restricted to operators or internal calls.

- **Separation of funds:**  
  Protocol balances intended for controlled use in business logic are directly reusable as trading inventory for arbitrary callers via the router.

---

## Adversary Flow Analysis

### Adversary-related accounts

The primary adversary cluster consists of:

- **Attacker EOA (BSC 56):** `0x67a5f6bd9f8763c7e6c4ea0b54d1b14b9e5ee7e2`
  - Sender of the seed exploit transaction.
  - Ultimate recipient of the USDT from the PancakePair during the exploit.
  - Transaction history includes:
    - Prior BNB funding from unrelated addresses.
    - DeFi interactions and later Tornado-like deposits, consistent with an adversary address rather than a protocol operator.

- **Helper contract (BSC 56):** `0xf455c70916252939f92616C8312F131fE37D013F`
  - Deployed by the attacker EOA in the seed transaction.
  - Constructor executes:
    - `Token.balanceOf(Main)` to read Main’s Token balance.
    - `Main.swapTokensForTokens` to execute the exploit.

Victim entities:

- **RaceCar Main contract:** `0xB040D88e61EA79a1289507d56938a6AD9955349C`  
  - Protocol contract holding Token and USDT balances sourced from user interactions and internal operations.
- **Token/USDT PancakePair LPs:** `0xa0ad4B45dc432e950f9e62AAA46995CE40ef4a11`  
  - Liquidity providers for the Token/USDT pool whose USDT reserves are drained to pay the attacker.

### Lifecycle stages

#### 1. Adversary initial funding and setup

- The attacker EOA is funded with BNB by other addresses well before the exploit, as seen in `normal_txlist.json`.
- Immediately before the exploit, the attacker has sufficient BNB to:
  - Deploy the helper contract.
  - Pay for gas and subsequent obfuscation transactions (e.g., deposits into a privacy pool).

In the seed exploit transaction:
- **Mechanism:** `deploy_contract`
- **Tx:** `0x61da5b50...f91d` on chain 56
- **Effect:**  
  The attacker deploys helper contract `0xf455...` with zero ETH value, preparing a one-shot constructor-based call into `Main.swapTokensForTokens`.

Evidence: Seed transaction trace and helper bytecode in calldata show:
- The helper’s constructor reads `Token.balanceOf(Main)`.
- Immediately calls `Main.swapTokensForTokens` with the retrieved amount and attacker EOA as `to`.

#### 2. Adversary exploit execution via swapTokensForTokens

Within the same transaction:

1. Helper constructor calls `Token.balanceOf(0xB040...)`:
   - Returns `97,555,900,794,950,304,298,569,411,189` Token units.

2. Helper calls `Main.swapTokensForTokens`:
   - `path = [Token, USDT]`
   - `tokenAmount = 97,555,900,794,950,304,298,569,411,189`
   - `tokenOutMin = 0`
   - `to = 0x67a5...`

3. Inside `swapTokensForTokens`, the inherited router wrapper forwards to `swapExactTokensForTokensSupportingFeeOnTransferTokens`:
   - `Token.transferFrom(Main, PancakePair, 97,555,900,794,950,304,298,569,411,189)` executes successfully.
   - PancakePair’s reserves update as:
     - USDT reserve decreases by `27,995,389,614,557,976,722,846`.
     - Token reserve increases by the corresponding amount.
   - `BEP20USDT.transfer(0x67a5..., 27,995,389,614,557,976,722,846)` executes.

4. Post-transaction:
   - Main’s Token balance is effectively drained into the AMM.
   - The attacker EOA holds `27,995,389,614,557,976,722,846` USDT units.
   - The attacker’s BNB balance decreases only by the gas cost for the transaction (~0.0182807 BNB).

This completes a single-transaction exploit that realizes the ACT opportunity induced by the unguarded router wrapper.

---

## Impact & Losses

### Loss overview

The primary quantified loss is in BEP20USDT:

- **Token:** BEP20USDT  
- **Token address:** `0x55d398326f99059ff775485246999027b3197955`  
- **Amount lost (from AMM):** `27,995,389,614,557,976,722,846` units

From balance diffs and reserves:
- The Token/USDT PancakePair’s USDT balance drops by `27,995,389,614,557,976,722,846` units.
- The same amount is delivered to the attacker EOA.
- Main’s Token balance is fully swapped into the pair, effectively draining protocol-held Token value from Main into the AMM, then converted to USDT to the attacker.

### Victims

- **PancakePair LPs (Token/USDT):**
  - Their USDT reserves are reduced to fund the attacker’s payout, offset only by increased exposure to Token.
  - They suffer a loss equivalent to the USDT outflow minus any future recovery in Token value.

- **RaceCar Main / protocol treasury:**
  - Main’s large Token holdings are expended in a single swap not initiated by protocol operators.
  - Any protocol strategies relying on this Token balance (e.g., rewards, liquidity, treasury operations) are compromised.

While precise fiat valuation and per-LP impact allocation were not computed, the on-chain balance deltas clearly show a large transfer of USDT value from the AMM and protocol-held Token inventory into the attacker’s control.

---

## References

Key underlying evidence and artifacts used in this analysis:

1. **Seed transaction metadata and trace for tx `0x61da5b50...f91d` on BSC 56**  
   - Provides the full execution trace, gas usage, and high-precision event and state changes for the exploit transaction.

2. **Verified Main.sol source for `0xB040D88e61EA79a1289507d56938a6AD9955349C`**  
   - Shows:
     - Inheritance from `PancakeRouter` and `Ownable`.
     - Hardcoded Token and USDT addresses.
     - Constructor approvals granting unlimited Token and USDT allowances to the router.
     - Public `swapTokensForTokens` inherited without access control.
     - Business logic functions (e.g., `buyCar`, `raceCarWin`, `addLiquidityUsdt`, `withdraw`, `withdrawToken`) that rely on contract-held Token and USDT balances.

3. **Verified PancakePair-like source for `0xa0ad4B45dc432e950f9e62AAA46995CE40ef4a11`**  
   - Confirms it is a standard AMM pair with:
     - `swap`, `mint`, `burn`, `skim`, `sync` functions.
     - Constant-product invariant and fee logic.
   - No custom logic to restrict swaps initiated by the router on behalf of Main.

4. **Balance diff summary for Token and USDT in the seed transaction**  
   - Quantifies:
     - Token inflow into the pair.
     - USDT outflow from the pair.
   - Confirms the magnitude of the attacker’s USDT profit and the absence of attacker USDT input in the same transaction.

5. **Address transaction lists for attacker EOA and Main contract**  
   - **Attacker EOA `0x67a5...`:**
     - Shows BNB funding from other addresses.
     - Contains interactions with DeFi contracts and later privacy pool deposits.
     - Supports classification as an adversary-operated EOA, not a protocol operator.
   - **Main `0xB040...`:**
     - Shows historical user activity and protocol interactions accumulating Token and USDT balances before the incident.
     - Confirms Main is a victim protocol contract, not an attacker helper.

---

## Summary

The incident is an ACT-style exploit of a router wrapper design flaw in the RaceCar Main contract on BSC:
- Main pre-approved the Pancake router for unlimited Token and USDT from its own balances.
- A public, unguarded `swapTokensForTokens` wrapper allowed any caller to make Main spend those balances via the router and send outputs to arbitrary addresses.
- An unprivileged attacker deployed a helper contract whose constructor called `Main.swapTokensForTokens` with the entire Token balance and directed the USDT output to the attacker EOA.
- On-chain traces and balance diffs show a single transaction draining Main’s Token holdings into the Token/USDT PancakePair and extracting ~2.80e22 USDT units to the attacker, with only BNB gas paid.

All observed behavior, code, and traces are consistent with this root cause, and there is no remaining uncertainty about the exploit mechanics or ACT feasibility under σ\_B at block 45535986.

