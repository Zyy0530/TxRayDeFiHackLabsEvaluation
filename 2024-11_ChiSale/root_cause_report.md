# ChiSale Referral Logic Drain via Balancer Flash‑Loan

## Incident Overview & TL;DR

On Ethereum mainnet, a single Balancer flash‑loan transaction drained essentially the entire ETH balance of the legacy ChiSale contract `0x050163597d9905ba66400f7b3ca8f2ef23df702d` (“ChiSale”). The exploit transaction
`0x586a2a4368a1a45489a8a9b4273509b524b672c33e6c544d2682771b44f05e87` in block `0x1427626` (decimal block `21254758`) was sent by externally owned account (EOA)
`0xee4073183e07aa0fc1b96d6308793840f02b6e88`.

The adversary used Balancer’s permissionless `flashLoan` on the Vault `0xba12222222228d8ba445958a75a0704d566bf2c8` to borrow `25,000 WETH`, unwrapped it to ETH, and routed ETH through ChiSale via helper contracts `0x83f015cf92626fba4368a2c8489eb01fa3e6044b` and
`0x931b8905c310ab133373f50ba66feba2793f80ea`. Two calls to `ChiSale::buy(address)` with `0x931b...80ea` as the referral address forced ChiSale to pay out a large “referral reward” funded by its existing ETH balance, while almost all of the huge `msg.value` provided by the flash‑loan was immediately refunded.

The core bug is that `ChiSale::buy` computes the referral reward as a fixed percentage of the raw `msg.value`, even when the actual payable sale amount is capped and most of `msg.value` is returned as remainder. This mismatch lets a caller recycle a large notional `msg.value` through the contract to strip out pre‑existing ETH via the referral payout, with minimal net cost once the flash‑loan is repaid.

Net effect for this transaction:

- Victim: ChiSale `0x0501...702d` loses about `5.78078 ETH`, going from `5.78078 ETH` to `12 wei`.
- Adversary: EOA `0xee40...b6e88` increases its ETH balance by roughly `5.77496 ETH` after gas.
- The Balancer Vault is fully repaid; CHI token balances are redistributed but not directly cashed out in this trace.

## Key Background

- **ChiToken (CHI)** – Contract `0x71e1f8e809dc8911fcac95043bc94929a36505a5` implements an ERC‑20 token with:
  - Total supply of `10,000,000,000 CHI`.
  - `decimals = 0` (CHI is indivisible).
  - Standard `transfer`, `transferFrom`, and `approve` semantics.

  ```solidity
  contract ChiToken is ERC20 {
      string public name = 'Chi';
      string public symbol = 'CHI';
      uint256 _totalSupply = 10000000000;
      uint256 public decimals = 0;
      mapping (address => uint256) balances;
      // ...
  }
  ```

  *Snippet 1 – Collected ChiToken source for `0x71e1...05a5` (ERC‑20 token with 0 decimals and fixed 10B supply).*

- **ChiSale contract** – Contract `0x050163597d9905ba66400f7b3ca8f2ef23df702d` (“ChiSale”) is an ETH‑for‑CHI sale:
  - Fixed price `TOKEN_PRICE = 0.001 ether` per CHI (1,000 CHI per 1 ETH).
  - Multi‑tier bonus schedule implemented via `BonusTier` structures and `calculateBonusTokens`.
  - Holds a pre‑funded pool of CHI tokens and accumulates ETH from buyers.
  - Exposes:
    - `buy(address referralAddress)` – public sale entrypoint with optional referral.
    - `withdrawEther()` and `withdrawChi()` – owner‑only functions for withdrawing ETH and leftover CHI.
  - Ownership is immutable: `Owned` sets `owner = msg.sender` at deployment and never changes it.

- **Revenue sharing design** – ChiSale implements an on‑chain referral program:
  - `REVENUE_SHARE_PERCENTAGE = 22`.
  - When `buy` is called with a non‑zero, non‑self `referralAddress`, the contract intends to share 22% of the sale’s revenue with the referrer.
  - In practice, the implementation ties this payout directly to `msg.value` rather than the actual effective sale amount, which is the root of the bug.

- **Balancer and WETH environment** – The exploit relies on:
  - Balancer Vault at `0xba12222222228d8ba445958a75a0704d566bf2c8`, which offers permissionless `flashLoan` calls.
  - Standard WETH (`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`) with `deposit` and `withdraw` callable by anyone.
  - These components provide temporary access to large volumes of ETH in a single atomic transaction without requiring prior capital from the adversary.

- **Adversary contracts** – From the provided address transaction histories and constructor code:
  - EOA `0xee40...b6e88` deployed:
    - Helper/router contract `0x83f0...6044b`.
    - Flash‑loan receiver and referral contract `0x931b...80ea`.
  - These contracts hard‑code the addresses of WETH, ChiSale, and the helper into their constructor parameters, wiring a fixed routing path for the exploit.

## Vulnerability & Root Cause Analysis

### Vulnerable Logic in `ChiSale::buy`

The sale contract’s `buy` function is intended to:

1. Compute how many CHI tokens to sell based on `msg.value` and `TOKEN_PRICE`.
2. Ensure the buyer cannot purchase more than the contract is able to sell (`maxBonusThreshold`).
3. Refund any excess ETH that does not line up with an integral number of tokens.
4. Pay a referral reward as a percentage of the sale’s proceeds.

The relevant implementation (ChiSale `Contract.sol` at `0x0501...702d`) is:

```solidity
function buy(address referralAddress) external payable {
    uint256 tokensToBuy = msg.value / TOKEN_PRICE;
    uint256 tokenBalance = chiContract.balanceOf(address(this));
    uint256 remainder = msg.value % TOKEN_PRICE;

    if (maxBonusThreshold < tokenBalance) {
        maxBonusThreshold = tokenBalance;
    }

    if (tokensToBuy > maxBonusThreshold) {
        tokensToBuy = maxBonusThreshold;
        remainder = msg.value - tokensToBuy * TOKEN_PRICE;
    }

    uint256 bonusTokens = calculateBonusTokens(tokensToBuy);
    tokensSold += tokensToBuy;

    if (tokenBalance < tokensToBuy + bonusTokens) {
        chiContract.transfer(msg.sender, tokenBalance);
    } else {
        chiContract.transfer(msg.sender, tokensToBuy + bonusTokens);
    }

    if (referralAddress != address(this) && referralAddress != address(0)) {
        referralAddress.send(
            msg.value * REVENUE_SHARE_PERCENTAGE / 100
        );
    }

    if (remainder > 0) {
        msg.sender.transfer(remainder);
    }

    LogChiPurchase(msg.sender, referralAddress, tokensToBuy, now);
}
```

*Snippet 2 – Collected ChiSale source for `0x0501...702d`: referral payout is `22%` of raw `msg.value`, while ETH remainder is separately refunded.*

### Economic Bug

The core design error is that the referral reward is calculated from the nominal `msg.value`, not from the actual net ETH that the contract retains after issuing tokens and refunding any remainder:

- The maximum number of tokens that can be sold is governed by `maxBonusThreshold` and the contract’s remaining CHI balance.
- When buyers attempt to purchase more tokens than available, `tokensToBuy` is capped at `maxBonusThreshold`, and the code computes:

  - Effective purchase cost: `tokensToBuy * TOKEN_PRICE`.
  - Remainder to refund: `msg.value - tokensToBuy * TOKEN_PRICE`.

- However, the referral reward is still computed as:

  - `referralReward = msg.value * REVENUE_SHARE_PERCENTAGE / 100`.

This means:

- The contract’s net ETH change for a single `buy` call (ignoring any prior balance) is:

  - `ΔETH_contract = msg.value - referralReward - remainder`
  - `= msg.value - msg.value * 22% - (msg.value - tokensToBuy * TOKEN_PRICE)`
  - `= tokensToBuy * TOKEN_PRICE - msg.value * 22%`.

- For a large enough `msg.value` relative to the small `tokensToBuy` remaining near the end of the sale, this expression becomes **strongly negative**, i.e. the contract loses ETH instead of gaining it.
- Because `send` cannot transfer more ETH than is available, the referral payout will simply consume the contract’s pre‑existing ETH balance, up to the amount implied by `msg.value * 22%`.

In effect, a buyer who controls `referralAddress` can:

1. Provide a very large `msg.value`.
2. Receive almost all of it back immediately via `remainder`.
3. Still collect a large referral payout that is funded by the ETH already sitting in the contract from prior buyers.

### Preconditions for Exploitation

The exploit requires:

- **Positive ETH balance in ChiSale** – The contract must hold ETH from previous, honest buyers. In the seed state for the exploit transaction, the victim’s ETH balance is:

  ```json
  {
    "address": "0x050163597d9905ba66400f7b3ca8f2ef23df702d",
    "before_wei": "5780780000000000000",
    "after_wei": "12",
    "delta_wei": "-5780779999999999988"
  }
  ```

  *Snippet 3 – Native balance diff for ChiSale from seed `balance_diff.json`: victim loses ~5.78078 ETH and ends with 12 wei.*

- **Remaining CHI tokens and capped sale capacity** – The contract must still have some CHI to sell (so that `buy` does not revert or become a no‑op), but `maxBonusThreshold` and the remaining CHI supply must be small enough that `tokensToBuy` is heavily capped relative to the provided `msg.value`. In the exploit trace:
  - First `buy` transfers `2,456,112 CHI` to the helper contract.
  - Second `buy` transfers the remaining `32,505 CHI` to the flash‑loan receiver.
  - This pattern demonstrates that the sale is nearly exhausted and `tokensToBuy` is limited by the remaining inventory.

- **Control of the referral address** – The adversary must be able to choose a referral address they control. In the exploit, the referral is the adversary’s flash‑loan receiver contract `0x931b...80ea`.

- **Access to large temporary liquidity** – The adversary must be able to supply a very large `msg.value` without permanently locking capital. This is achieved by borrowing `25,000 WETH` via Balancer’s flash‑loan and unwrapping it to ETH for use in `buy`.

### Security Principles Violated

- **Incorrect economic accounting for revenue sharing** – Referral payouts are tied to nominal `msg.value` rather than the actual sale proceeds, allowing extraction of prior deposits.
- **Missing invariant between referral rewards and tokens sold** – There is no cap ensuring that referral rewards are bounded by a fraction of `tokensToBuy * TOKEN_PRICE`; a referrer can be over‑paid relative to actual value delivered.
- **Hidden, unprivileged drain path** – Even though `withdrawEther()` is restricted to `onlyOwner`, the combination of `buy` and `referralAddress.send` exposes an unguarded path for any caller to move ETH from the contract to arbitrary addresses.

## Adversary Flow Analysis

This section reconstructs the adversary’s lifecycle and transaction‑level flow, based on the provided on‑chain data.

### Accounts and Roles

- **Adversary EOA** – `0xee4073183e07aa0fc1b96d6308793840f02b6e88`
  - Sends the exploit transaction `0x586a...5e87`.
  - Deploys helper contracts `0x83f0...6044b` and `0x931b...80ea`.

- **Helper contract** – `0x83f015cf92626fba4368a2c8489eb01fa3e6044b`
  - Receives ETH from the flash‑loan receiver.
  - Calls `ChiSale::buy` on behalf of the adversary with `0x931b...80ea` as referral.

- **Flash‑loan receiver & referral** – `0x931b8905c310ab133373f50ba66feba2793f80ea`
  - Registered as Balancer flash‑loan receiver.
  - Controls routing of borrowed WETH/ETH.
  - Used as `referralAddress` for both `buy` calls and receives the drained ETH.

- **Victim contracts**:
  - ChiSale `0x0501...702d` – ETH‑for‑CHI sale contract.
  - ChiToken `0x71e1...05a5` – ERC‑20 representing CHI.

### Stage 1 – Adversary Contract Deployment

- **Transactions**:
  - `0x05b39ea61720a89e7d5eb02f032358d7aa731c1bf6b13d75de26b3b60575c4fc` (block `21132785`) – deployment of helper `0x83f0...6044b`.
  - `0xa44f33fb57285dd2d5871df33c3f064c8aa448df632e48ab74593eacd3fb84c8` (block `21132804`) – deployment of flash‑loan receiver `0x931b...80ea`.

- **Behavior**:
  - Both contracts are deployed by EOA `0xee40...b6e88`.
  - Constructor bytecode in their deployment transactions encodes the addresses of:
    - WETH (`0xc02a...56cc2`),
    - ChiSale (`0x0501...702d`),
    - Helper contract `0x83f0...6044b`.
  - This sets up a fixed call graph for the later flash‑loan transaction and ensures that `referralAddress` in `buy` will be controlled by the adversary.

### Stage 2 – Flash‑Loan Execution and ETH Routing

The exploit transaction `0x586a...5e87` calls Balancer Vault’s `flashLoan` with `25,000 WETH` as the asset.

From the seed `trace.cast.log`:

```text
0xBA1222...f2C8::flashLoan(0x931b...80eA, [0xC02a...56Cc2], [25000000000000000000000], 0x)
  ├─ WETH9::transfer(0x931b...80eA, 25000000000000000000000)
  ├─ 0x931b...80eA::receiveFlashLoan(...)
  │   ├─ WETH9::withdraw(25000000000000000000000)
  │   ├─ 0x83F0...6044b::test{value: 1993493000000000000000}(...)
  │   │   └─ 0x0501...702d::buy{value: 1993493000000000000000}(0x931b...80eA)
  │   └─ 0x0501...702d::buy{value: 18457751454545454545400}(0x931b...80eA)
  │   ├─ WETH9::deposit{value: 25000000000000000000000}()
  │   └─ WETH9::transfer(0xBA1222...f2C8, 25000000000000000000000)
  └─ ...
```

*Snippet 4 – Seed transaction trace for `0x586a...5e87`: Balancer flash‑loan to `0x931b...80ea`, WETH withdraw to ETH, two `ChiSale::buy` calls, and full WETH repayment.*

Key observations:

- Balancer lends `25,000 WETH` to `0x931b...80ea`.
- `0x931b...80ea` unwraps all WETH to ETH via `WETH9::withdraw`.
- ETH is then routed:
  - First, into helper `0x83f0...6044b::test` with `1,993.493 ETH`, which in turn calls `ChiSale::buy(referral=0x931b...80ea)` once.
  - Second, directly from `0x931b...80ea` into `ChiSale::buy(referral=0x931b...80ea)` with a much larger `18,457.7514545454545454 ETH`.
- After the two `buy` calls, `0x931b...80ea` deposists ETH back into WETH and repays the full `25,000 WETH` to Balancer.

### Stage 3 – Referral Drain and Exploit Outcome

During the two `buy` calls, ChiSale:

1. Sells its remaining CHI to the helper and receiver contracts.
2. Pays referral rewards equal to `22%` of each call’s raw `msg.value` to the referral address (`0x931b...80ea`).
3. Refunds any remainder ETH back to the caller (`0x83f0...` in the first call, `0x931b...` in the second call).

The seed `balance_diff.json` shows the net ETH flows for the exploit transaction:

```json
{
  "native_balance_deltas": [
    {
      "address": "0x931b8905c310ab133373f50ba66feba2793f80ea",
      "before_wei": "0",
      "after_wei": "1",
      "delta_wei": "1"
    },
    {
      "address": "0xee4073183e07aa0fc1b96d6308793840f02b6e88",
      "before_wei": "5285453757312471491",
      "after_wei": "11060410286296273494",
      "delta_wei": "5774956528983802003"
    },
    {
      "address": "0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97",
      "before_wei": "7625357699834662111",
      "after_wei": "7626264428053271903",
      "delta_wei": "906728218609792"
    },
    {
      "address": "0x050163597d9905ba66400f7b3ca8f2ef23df702d",
      "before_wei": "5780780000000000000",
      "after_wei": "12",
      "delta_wei": "-5780779999999999988"
    }
  ]
}
```

*Snippet 5 – Seed balance diff for tx `0x586a...5e87`: ChiSale loses ~5.78078 ETH, adversary EOA gains ~5.77496 ETH; a small amount goes to a third‑party address (likely fee recipients).*

The transaction receipt for `0x586a...5e87` confirms the CHI transfers and ChiSale events:

```json
{
  "logs": [
    {
      "address": "0x71e1f8e809dc8911fcac95043bc94929a36505a5",
      "topics": [
        "Transfer(topic0)",
        "from=0x050163597d9905ba66400f7b3ca8f2ef23df702d",
        "to=0x83f015cf92626fba4368a2c8489eb01fa3e6044b"
      ],
      "data": "0x...0000000000000000000000000000000000000000000000000000000000257a30"
    },
    {
      "address": "0x050163597d9905ba66400f7b3ca8f2ef23df702d",
      "topics": [
        "LogChiPurchase(topic0)",
        "buyer=0x83f015cf92626fba4368a2c8489eb01fa3e6044b",
        "referrer=0x931b8905c310ab133373f50ba66feba2793f80ea"
      ]
    },
    {
      "address": "0x71e1f8e809dc8911fcac95043bc94929a36505a5",
      "topics": [
        "Transfer(topic0)",
        "from=0x050163597d9905ba66400f7b3ca8f2ef23df702d",
        "to=0x931b8905c310ab133373f50ba66feba2793f80ea"
      ],
      "data": "0x...0000000000000000000000000000000000000000000000000000000000007ef9"
    },
    {
      "address": "0x050163597d9905ba66400f7b3ca8f2ef23df702d",
      "topics": [
        "LogChiPurchase(topic0)",
        "buyer=0x931b8905c310ab133373f50ba66feba2793f80ea",
        "referrer=0x931b8905c310ab133373f50ba66feba2793f80ea"
      ]
    }
  ]
}
```

*Snippet 6 – Extract from receipt `tx_receipt.json` for tx `0x586a...5e87`: two `Transfer` logs from ChiSale to helper and receiver, and two `LogChiPurchase` events with referrer `0x931b...80ea` for both buys.*

Taken together, the trace, logs, and balance deltas show:

- Two sequential `buy` calls on ChiSale using `0x931b...80ea` as the referral.
- Both calls result in significant ETH transfers to the referral (via `send`), funded by ChiSale’s existing ETH balance.
- Almost all of the large `msg.value` is returned as refunds to the helper/receiver, allowing them to rewrap sufficient ETH to repay the flash‑loan.
- The adversary EOA ends the transaction with a net ETH profit, while ChiSale’s ETH is effectively wiped out.

## Impact & Losses

### Quantified On‑Chain Loss

From the seed `balance_diff.json` and the exploit predicate:

- **Reference asset**: ETH (native token on Ethereum mainnet).
- **Victim contract**: ChiSale `0x0501...702d`.
  - Before: `5.78078 ETH` (`5,780,780,000,000,000,000 wei`).
  - After: `12 wei`.
  - Delta: `-5.780779999999999988 ETH`.
- **Adversary EOA**: `0xee40...b6e88`.
  - Before: `5.285453757312471491 ETH`.
  - After: `11.060410286296273494 ETH`.
  - Delta: `+5.774956528983802003 ETH` (net of gas costs).

The approximate **net loss** to the protocol from this incident is therefore **~5.78 ETH**, entirely borne by the legacy ChiSale contract, with the corresponding net gain accruing to the adversary EOA.

CHI token movements (from `tx_receipt.json`) show redistribution of CHI balances between ChiSale, the helper contract, and the receiver contract, but there is no evidence in the provided dataset that CHI is actively liquidated within this transaction. The economic damage stems from the ETH drained via the flawed referral logic, not from direct CHI mispricing.

### Broader Effects and Limitations

- The provided artifacts focus on the single exploit transaction. They do not include:
  - A full historical price series for CHI.
  - Off‑chain trading activity or subsequent liquidation of CHI by the adversary.
- The impact estimates above are therefore restricted to **on‑chain ETH flows** within the exploit transaction itself.

## References

All references below point to artifacts provided in the incident workspace; no external blockchain queries were performed beyond these files.

- **[1] Seed transaction trace for exploit tx**
  - *Title*: Seed trace for tx `0x586a...5e87`.
  - *Content*: Foundry `cast run -vvvvv` style execution trace showing Balancer `flashLoan`, WETH unwrap/rewrap, ChiSale `buy` calls, and internal value transfers.

- **[2] Native balance diffs for exploit tx**
  - *Title*: Balance diffs for tx `0x586a...5e87`.
  - *Content*: `balance_diff.json` summarizing before/after ETH balances for key addresses (ChiSale, adversary EOA, flash‑loan receiver).

- **[3] ChiSale contract source**
  - *Title*: ChiSale source code (`0x0501...702d`).
  - *Content*: `Contract.sol` implementing the ChiSale logic, including `buy`, referral payout, bonus tier handling, and owner withdrawals.

- **[4] ChiToken contract source**
  - *Title*: ChiToken source code (`0x71e1...05a5`).
  - *Content*: `Contract.sol` implementing the CHI ERC‑20 token with `decimals = 0` and `totalSupply = 10,000,000,000`.

- **[5] Adversary EOA transaction history**
  - *Title*: Adversary EOA txlist (`0xee40...b6e88`).
  - *Content*: `transactions_by_address.json` showing deployments of helper contracts and the exploit transaction.

- **[6] Helper contract transaction history**
  - *Title*: Helper contract txlist (`0x83f0...6044b`).
  - *Content*: `transactions_by_address.json` capturing interactions where the helper receives ETH and calls ChiSale.

- **[7] Flash‑loan receiver transaction history**
  - *Title*: Flash‑loan receiver txlist (`0x931b...80ea`).
  - *Content*: `transactions_by_address.json` showing its role as Balancer flash‑loan receiver and referral ETH sink.

- **[8] Seed metadata for exploit tx**
  - *Title*: Seed metadata for tx `0x586a...5e87`.
  - *Content*: `metadata.json` including core transaction properties (sender, target Balancer Vault, calldata, gas parameters, block number).

- **[9] Transaction receipt and logs**
  - *Title*: Receipt and logs for tx `0x586a...5e87`.
  - *Content*: `tx_receipt.json` with event logs from WETH, Balancer, ChiToken, and ChiSale, used to map internal flows (CHI transfers and `LogChiPurchase` events) to the high‑level exploit narrative.

