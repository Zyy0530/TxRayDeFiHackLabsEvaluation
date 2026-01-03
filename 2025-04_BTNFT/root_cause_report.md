## Incident Overview & TL;DR

This incident occurred on BSC mainnet and revolves around a vesting NFT system built around the BTNFT contract at `0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B` and its associated reward token BTTToken at `0xDAd4df3eFdb945358a3eF77B939Ba83DAe401DA8`. An unprivileged adversary EOA `0xbda2a27cdb2ffd4258f3b1ed664ed0f28f9e0fc3` deployed a custom helper contract `0x7A4D144307d2DFA2885887368E4cd4678dB3c27a` and then used it to call `BTNFT.transferFrom` on many victim-held NFTs. These transfers route through BTNFT’s overridden `_update(to == address(this))` branch, which triggers a reward-claiming path that sends vested BTTToken rewards to `msg.sender` without re‑enforcing ownership or approval checks.

In the first seed transaction (`0x1e90cbff665c43f91d66a56b4aa9ba647486a5311bb0b4381de4d653a9d8237d`), the helper contract batch‑calls `BTNFT.transferFrom(victim, address(BTNFT), tokenId)` across many tokenIds. Each call causes BTNFT to transfer the claimable portion of BTTToken for that NFT from BTNFT’s own balance to the helper contract, emitting `TokensClaimed` events. In the second seed transaction (`0x7978c002d12be9b748770cc31cbaa1b9f3748e4083c9f419d7a99e2e07f4d75f`), the helper contract approves and routes the harvested BTTToken into pool contract `0x1e16070a8734B3d686E0CF035c05fBBC1ba21C98` via router `0x82C7c2F46C230aabc806e3A2642F8CFbdD968ED2`, swapping BTTToken for BEP20USDT (`0x55d398326f99059ff775485246999027b3197955`) and paying out net BEP20USDT to the attacker EOA and a secondary recipient address `0xbd65ef472b7e158ff4757de18fb1f877be2b2213`.

Across these two transactions, the adversary turns vested BTTToken backing victim NFTs into BEP20USDT profit using only public entry points and approvals granted to the helper contract. This constitutes a clear ACT opportunity: an unprivileged attacker can deploy a helper contract, harvest vested BTTToken rewards from arbitrary BTNFT tokenIds for which they hold approvals, and convert those rewards into BEP20USDT at the attacker EOA.

**Key exploit transactions (ACT opportunity sequence):**

- **Tx 1 (Exploit setup, harvesting BTTToken)**  
  - Chain: BSC (chainid 56)  
  - Tx hash: `0x1e90cbff665c43f91d66a56b4aa9ba647486a5311bb0b4381de4d653a9d8237d`  
  - From: attacker EOA `0xbda2a27c...`  
  - To: helper contract `0x7A4D1443...`  
  - Role: batch harvests BTTToken from BTNFT via flawed `_update(to == address(this))` logic by repeatedly calling `BTNFT.transferFrom(victim, address(BTNFT), tokenId)`.

- **Tx 2 (Profit‑taking swap into BEP20USDT)**  
  - Chain: BSC (chainid 56)  
  - Tx hash: `0x7978c002d12be9b748770cc31cbaa1b9f3748e4083c9f419d7a99e2e07f4d75f`  
  - From: attacker EOA `0xbda2a27c...`  
  - To: helper contract `0x7A4D1443...`  
  - Role: swaps the harvested BTTToken into BEP20USDT via pool `0x1e16070a...` and router `0x82C7c2F4...`, paying out BEP20USDT to the attacker EOA and secondary address `0xbd65ef47...`.

### Evidence snippet – BTNFT transfer‑to‑self claims rewards to msg.sender

Source: collected BTNFT contract source (verified on explorer) for `0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B`.

```solidity
function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
    address previousOwner = _ownerOf(tokenId);
    if (to == address(this)) {
        claimReward(tokenId);
    } else {
        previousOwner = super._update(to, tokenId, auth);
    }

    return previousOwner;
}

function claimReward(uint256 tokenId) internal {
    VestingSchedule storage schedule = vestingSchedules[tokenId];
    require(schedule.totalAmount > 0, "No vesting schedule found for this address");
    require(block.timestamp > schedule.startTime, "Vesting period has not started");
    uint256 vestedAmount = _calculateVestedAmount(schedule);
    uint256 claimableAmount = vestedAmount.sub(schedule.claimedAmount);
    require(claimableAmount > 0, "No tokens available for claiming");

    schedule.claimedAmount = schedule.claimedAmount.add(claimableAmount);
    bttToken.transfer(msg.sender, claimableAmount);

    emit TokensClaimed(msg.sender, claimableAmount);
}
```

*Caption: BTNFT overrides `_update` so that sending an NFT to `address(this)` calls `claimReward(tokenId)` and pays BTTToken rewards to `msg.sender`, without re‑validating that `msg.sender` is the NFT owner or otherwise authorized to claim rewards, enabling an approved helper contract to withdraw rewards for victim‑owned NFTs.*

### Evidence snippet – Helper contract harvests BTTToken via BTNFT.transferFrom

Source: seed transaction trace (`cast run -vvvvv`) for exploit‑setup tx `0x1e90cbff...` on BSC.

```text
0x7A4D1443...::test(BTNFT: [0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B], BTTToken: [0xDAd4df3eFdb945358a3eF77B939Ba83DAe401DA8], 502)
  ├─ BTNFT::ownerOf(1) [staticcall]
  ├─ BTNFT::transferFrom(0xFD4b8C68..., BTNFT: [0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B], 1)
  │   ├─ BTTToken::transfer(0x7A4D1443..., 29049649923896499239)
  │   │   ├─ emit Transfer(from: BTNFT: [0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B], to: 0x7A4D1443..., value: 29049649923896499239)
  │   ├─ emit TokensClaimed(beneficiary: 0x7A4D1443..., amount: 29049649923896499239)
  ├─ BTNFT::transferFrom(0xAC89892e..., BTNFT: [0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B], 2)
  │   ├─ BTTToken::transfer(0x7A4D1443..., 224048706240487062)
  │   ├─ emit TokensClaimed(beneficiary: 0x7A4D1443..., amount: 224048706240487062)
  ├─ BTNFT::transferFrom(0x9EC935bE..., BTNFT: [0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B], 3)
  │   ├─ BTTToken::transfer(0x7A4D1443..., 223318112633181126)
  │   ├─ emit TokensClaimed(beneficiary: 0x7A4D1443..., amount: 223318112633181126)
  ...
```

*Caption: In the exploit‑setup transaction, helper contract `0x7A4D1443...` repeatedly calls `BTNFT.transferFrom(victim, address(BTNFT), tokenId)`, causing BTNFT to transfer BTTToken rewards from its own balance to the helper and emit `TokensClaimed` with the helper as beneficiary, confirming the unauthorized reward harvesting mechanism.*

---

## Key Background

This section summarizes the core contracts and system components involved in the incident.

- **BTNFT vesting NFT contract (`0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B`)**  
  - Verified ERC721‑style NFT contract on BSC.  
  - Maintains a `vestingSchedules[tokenId]` mapping for each NFT, storing vesting parameters and claimed amounts.  
  - Pays BTTToken rewards via an internal `claimReward(uint256 tokenId)` function that computes the vested amount, subtracts the already‑claimed amount, and transfers the claimable BTTToken from BTNFT to `msg.sender`.  
  - Source code was collected from the explorer and is stored under `artifacts/root_cause/data_collector/iter_1/contract/56/0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B/source/src/Contract.sol`.

- **BTTToken reward token (`0xDAd4df3eFdb945358a3eF77B939Ba83DAe401DA8`)**  
  - Verified ERC20 token on BSC that acts as the reward currency for BTNFT vesting schedules.  
  - BTNFT and other contracts hold BTTToken balances; its behavior conforms to standard ERC20 transfer and allowance semantics as seen in the collected source.

- **BEP20USDT stablecoin (`0x55d398326f99059ff775485246999027b3197955`)**  
  - Verified BEP20 stablecoin on BSC and the reference asset used to measure adversary profit in this analysis.  
  - The profit‑taking transaction swaps BTTToken into BEP20USDT and credits BEP20USDT balances to the attacker EOA and secondary address.

- **BTTToken/BEP20USDT pool contract (`0x1e16070a8734B3d686E0CF035c05fBBC1ba21C98`)**  
  - Unverified liquidity or trading contract on BSC.  
  - Collected bytecode and transaction history show that it holds BTTToken and BEP20USDT balances and interacts with router `0x82C7c2F46C230aabc806e3A2642F8CFbdD968ED2` to execute token swaps.  
  - In the profit‑taking transaction, this contract loses a large amount of BEP20USDT as it swaps BTTToken received from the helper contract into BEP20USDT for the attacker.

- **Router contract (`0x82C7c2F46C230aabc806e3A2642F8CFbdD968ED2`)**  
  - Unverified router‑style contract on BSC.  
  - Used in the profit‑taking transaction to move BTTToken and BEP20USDT between the helper contract and the pool as part of the swap path.

- **Helper contract (`0x7A4D144307d2DFA2885887368E4cd4678dB3c27a`)**  
  - Custom attacker‑controlled contract deployed by EOA `0xbda2a27c...` in transaction `0xa56a257c2a382cffbe5f59851e1f8ce833d14f47bf34a3416d593f776f415137`.  
  - Exposes a `test(address addr, address reAddr, uint256 amount)` function (selector `0xfd9ba018`) that accepts BTNFT and BTTToken addresses plus an `amount` parameter controlling how many tokenIds to process.  
  - Used in both seed transactions to orchestrate batched `BTNFT.transferFrom` calls and to route harvested BTTToken into the swap path.

### Evidence snippet – Helper contract deployment and method usage

Source: helper contract txlist (account.txlist) for `0x7A4D1443...` up to the second seed transaction.

```json
[
  {
    "blockNumber": "48472182",
    "hash": "0xa56a257c2a382cffbe5f59851e1f8ce833d14f47bf34a3416d593f776f415137",
    "from": "0xbda2a27cdb2ffd4258f3b1ed664ed0f28f9e0fc3",
    "to": "",
    "contractAddress": "0x7a4d144307d2dfa2885887368e4cd4678db3c27a"
  },
  {
    "blockNumber": "48472356",
    "hash": "0x1e90cbff665c43f91d66a56b4aa9ba647486a5311bb0b4381de4d653a9d8237d",
    "from": "0xbda2a27cdb2ffd4258f3b1ed664ed0f28f9e0fc3",
    "to": "0x7a4d144307d2dfa2885887368e4cd4678db3c27a",
    "methodId": "0xfd9ba018"
  },
  {
    "blockNumber": "48472369",
    "hash": "0x7978c002d12be9b748770cc31cbaa1b9f3748e4083c9f419d7a99e2e07f4d75f",
    "from": "0xbda2a27cdb2ffd4258f3b1ed664ed0f28f9e0fc3",
    "to": "0x7a4d144307d2dfa2885887368e4cd4678db3c27a",
    "methodId": "0x3b38007e"
  }
]
```

*Caption: The helper contract is deployed by attacker EOA `0xbda2a27c...` and then called in both seed transactions, confirming that it is an attacker‑controlled orchestrator for the exploit.*

---

## Vulnerability & Root Cause Analysis

### Vulnerability brief

BTNFT’s ERC721 transfer pipeline is modified so that when an NFT is transferred to the BTNFT contract itself, the internal `_update` hook executes `claimReward(tokenId)` and sends vested BTTToken rewards to `msg.sender` without re‑enforcing standard ownership or approval rules. As a result, any contract that has been approved as an operator for victim NFTs can call `transferFrom(victim, address(BTNFT), tokenId)` and receive BTTToken rewards associated with that NFT, even though it is not the owner or intended beneficiary.

### Detailed root cause

The verified BTNFT source code shows that BTNFT inherits ERC721 functionality and overrides the internal `_update(address to, uint256 tokenId, address auth)` hook. In this override, when `to == address(this)`, BTNFT does **not** perform a normal ownership transfer. Instead, it calls the internal `claimReward(tokenId)` function:

- `claimReward(tokenId)` reads `vestingSchedules[tokenId]`, which holds the total vesting amount, a start time, an end time, and the `claimedAmount` so far.  
- It checks that there is a vesting schedule and that the vesting period has started, then computes `vestedAmount = _calculateVestedAmount(schedule)` based on the elapsed time between `startTime` and `endTime`.  
- It calculates `claimableAmount = vestedAmount - claimedAmount` and requires that this is non‑zero.  
- It updates `schedule.claimedAmount` and calls `bttToken.transfer(msg.sender, claimableAmount)`.  
- It emits a `TokensClaimed(msg.sender, claimableAmount)` event.

Crucially, this reward‑claim path:

- Uses `msg.sender` as the beneficiary for BTTToken transfers, rather than the NFT owner.  
- Does **not** re‑validate that `msg.sender` is the NFT owner or an authorized beneficiary for `tokenId`.  
- Is reachable via `transferFrom` when the `to` address is `address(BTNFT)`, because `_update` is the internal hook used in the ERC721 transfer process.

This design means that any contract with an approval on a victim’s NFT (via `approve` or `setApprovalForAll`) can:

1. Call `BTNFT.transferFrom(victim, address(BTNFT), tokenId)`.  
2. Trigger the `_update(to == address(this))` branch, which calls `claimReward(tokenId)`.  
3. Cause BTNFT to pay the vested BTTToken rewards for that tokenId directly to `msg.sender` (the helper contract), not to the victim.

In the exploit‑setup transaction `0x1e90cbff...`, helper contract `0x7A4D1443...` uses exactly this pattern to harvest rewards across many tokenIds:

- The trace shows repeated sequences of `BTNFT::ownerOf(tokenId)` followed by `BTNFT::transferFrom(victim, BTNFT, tokenId)`.  
- Each `transferFrom` call leads to a `BTTToken::transfer(BTNFT → 0x7A4D1443..., amount)` and an emitted `TokensClaimed(beneficiary: 0x7A4D1443..., amount: ...)`.  
- The prestateTracer `balance_diff` confirms that BTNFT’s BTTToken balance decreases by `19,158,433,044,140,030,441,194` units and the helper contract’s BTTToken balance increases by the same amount in this single transaction.

The root cause is therefore:

- BTNFT couples NFT transfers to `address(this)` with reward‑claim logic that pays rewards to `msg.sender`.  
- This logic does not re‑enforce ownership or approval invariants, granting any approved operator implicit permission to withdraw all vested BTTToken associated with a victim’s NFT.  
- The exploitable entry point is the standard `transferFrom` function, used in a non‑obvious way (sending tokens to the BTNFT contract itself).

### Vulnerable components

- **BTNFT vesting NFT contract (`0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B`)**  
  - Overridden `_update(to == address(this))` hook that calls `claimReward(tokenId)` and pays BTTToken rewards to `msg.sender` without verifying that `msg.sender` is the NFT owner or intended beneficiary.

- **BTNFT.transferFrom(from, to, tokenId) when `to == address(this)`**  
  - Uses the overridden `_update` path and thus triggers the reward‑withdrawal logic whenever an NFT is sent to BTNFT, allowing an approved operator to harvest rewards for that tokenId.

### Exploit pre‑conditions (exploit conditions)

The exploit requires the following conditions to hold:

1. **BTNFT must hold backed BTTToken rewards**  
   - BTNFT must hold a non‑zero BTTToken balance corresponding to `vestingSchedules[tokenId]` entries for multiple tokenIds with claimable vested rewards.

2. **Attacker holds approvals on victim NFTs**  
   - Victim NFT holders must have previously approved the attacker‑controlled helper contract (or the attacker EOA) via `approve` or `setApprovalForAll`, so that `transferFrom(victim, address(BTNFT), tokenId)` succeeds.

3. **Attacker can send standard BSC transactions**  
   - The attacker must be able to deploy the helper contract and send normal EOA transactions on BSC with enough BNB to pay gas fees.

4. **Liquidity for profit conversion exists**  
   - Pool contract `0x1e16070a8734B3d686E0CF035c05fBBC1ba21C98` must hold both BTTToken and BEP20USDT liquidity so that swapping the harvested BTTToken into BEP20USDT through the pool and router is feasible.

### Violated security principles

- **Authorization for reward withdrawal**  
  - BTNFT’s design pays BTTToken rewards to `msg.sender` based solely on the `vestingSchedules[tokenId]` state, without confirming that `msg.sender` is the NFT owner or a designated beneficiary. This breaks standard authorization expectations for reward claiming.

- **Separation of concerns**  
  - Reward‑claiming logic is coupled to NFT transfers to `address(BTNFT)` via the `_update` hook. A transfer operation implicitly performs a reward withdrawal, conflating ownership transfer with payout logic and enabling unexpected side effects through a standard ERC721 API.

- **Least privilege**  
  - An approved operator, which should only have transfer control over an NFT, implicitly gains the ability to withdraw all vested BTTToken associated with that NFT. This exceeds the minimal privilege needed for transferring ownership and violates least‑privilege design principles.

---

## Adversary Flow Analysis

### Adversary strategy summary

The adversary executes a single‑chain, two‑transaction exploit on BSC:

1. **Harvest BTTToken rewards from BTNFT via a helper contract**  
   - Use a custom helper contract `0x7A4D1443...` to batch‑call `BTNFT.transferFrom(victim, address(BTNFT), tokenId)` across many victim tokenIds.  
   - Each call triggers BTNFT’s `_update(to == address(this))` logic and `claimReward(tokenId)`, causing BTNFT to pay BTTToken rewards to the helper contract instead of to NFT owners.

2. **Swap harvested BTTToken into BEP20USDT profit**  
   - In a second transaction, use the helper contract to approve and route the harvested BTTToken into pool `0x1e16070a...` via router `0x82C7c2F4...`.  
   - The pool swaps BTTToken into BEP20USDT, paying out BEP20USDT to the attacker EOA and secondary recipient address `0xbd65ef47...`.

### Adversary‑related accounts

**Adversary cluster (attacker‑controlled addresses)**

- **EOA `0xbda2a27cdb2ffd4258f3b1ed664ed0f28f9e0fc3` (BSC, chainid 56)**  
  - Signs the helper‑contract deployment transaction `0xa56a257c...`.  
  - Signs both exploit seed transactions `0x1e90cbff...` and `0x7978c002...`, all sent to the helper contract.  
  - Receives net BEP20USDT profit in the profit‑taking transaction according to the `balance_diff` for `0x7978c002...`.

- **Helper contract `0x7A4D144307d2DFA2885887368E4cd4678dB3c27a` (BSC, chainid 56)**  
  - Deployed by the attacker EOA in `0xa56a257c...`.  
  - Used exclusively in the exploit‑setup and profit‑taking transactions to batch `BTNFT.transferFrom` calls and to route BTTToken into pool `0x1e16070a...`.  
  - Holds the intermediate harvested BTTToken balance between the two seed transactions.

**Victim‑side contracts and addresses**

- **BTNFT vesting NFT contract (`0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B`)** – Verified ERC721‑style contract whose flawed reward‑claim behavior is the primary vulnerability.  
- **BTTToken reward token (`0xDAd4df3eFdb945358a3eF77B939Ba83DAe401DA8`)** – Verified ERC20 token from which BTNFT pays out vested rewards.  
- **BEP20USDT stablecoin (`0x55d398326f99059ff775485246999027b3197955`)** – Verified BEP20 stablecoin used as the profit‑measurement asset.  
- **Pool contract (`0x1e16070a8734B3d686E0CF035c05fBBC1ba21C98`)** – Unverified pool or trading contract that loses BEP20USDT to the attacker and secondary recipient in the profit‑taking transaction.  
- **Secondary profit recipient (`0xbd65ef472b7e158ff4757de18fb1f877be2b2213`)** – Address that receives a portion of the BEP20USDT outflow from the pool in `0x7978c002...` according to the `balance_diff`.

### Adversary lifecycle stages

1. **Helper contract deployment**

   - **Transaction:** `0xa56a257c2a382cffbe5f59851e1f8ce833d14f47bf34a3416d593f776f415137`  
   - **Block:** `48472182` (BSC)  
   - **Mechanism:** contract creation by attacker EOA.  
   - **Effect:** Attacker EOA `0xbda2a27c...` deploys helper contract `0x7A4D1443...`, which exposes functions later used to batch‑call `BTNFT.transferFrom` and to perform swaps via pool `0x1e16070a...`.  
   - **Evidence:** helper address txlist (`txlist_up_to_seed2.json`) and data collection summary confirm the deployment transaction and link it to the attacker EOA.

2. **BTTToken harvesting from BTNFT via flawed `_update` hook**

   - **Transaction:** `0x1e90cbff665c43f91d66a56b4aa9ba647486a5311bb0b4381de4d653a9d8237d`  
   - **Block:** `48472356` (BSC)  
   - **Mechanism:** adversary‑crafted call to helper contract function `0xfd9ba018` (`test(address addr, address reAddr, uint256 amount)`).  
   - **Effect:** Helper contract `0x7A4D1443...` calls `BTNFT.transferFrom` for many victim‑held tokenIds, sending each NFT from its current owner to `address(BTNFT)`. Each transfer routes through BTNFT’s overridden `_update(to == address(this))` path, which calls `claimReward(tokenId)` and transfers the claimable BTTToken amount from BTNFT to `msg.sender` (the helper contract). The QuickNode prestateTracer `balance_diff` shows BTNFT’s BTTToken balance decreasing by `19,158,433,044,140,030,441,194` units and the helper contract’s BTTToken balance increasing by the same amount in this transaction.

   - **Evidence snippet – balance‑level state diff for BTTToken in tx 0x1e90cbff...**

   Source: prestateTracer `balance_diff.json` for exploit‑setup transaction `0x1e90cbff...`.

   ```json
   {
     "0xDAd4df3eFdb945358a3eF77B939Ba83DAe401DA8": {
       "erc20": {
         "0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B": {
           "delta": "-19158433044140030441194"
         },
         "0x7A4D144307d2DFA2885887368E4cd4678dB3c27a": {
           "delta": "19158433044140030441194"
         }
       }
     }
   }
   ```

   *Caption: The prestateTracer state diff for BTTToken shows BTNFT losing and the helper contract gaining `19,158,433,044,140,030,441,194` BTTToken units in tx `0x1e90cbff...`, matching the trace‑level view that the helper contract harvests rewards from BTNFT.*

3. **BEP20USDT profit‑taking swap through pool `0x1e16070a...`**

   - **Transaction:** `0x7978c002d12be9b748770cc31cbaa1b9f3748e4083c9f419d7a99e2e07f4d75f`  
   - **Block:** `48472369` (BSC)  
   - **Mechanism:** adversary‑crafted call to helper contract function `0x3b38007e`, which orchestrates approvals and swaps via router `0x82C7c2F4...` and pool `0x1e16070a...`.  
   - **Effect:** Helper contract `0x7A4D1443...` approves BTTToken to the router and pool, then routes essentially all harvested BTTToken into `0x1e16070a...`. The pool swaps BTTToken for BEP20USDT. The `balance_diff` for this transaction shows:
     - Helper contract’s BTTToken balance decreasing by `19,158,433,044,140,030,441,150` units.  
     - Pool contract `0x1e16070a...` BTTToken balance increasing by the same amount.  
     - Pool contract’s BEP20USDT balance decreasing by `19,614,368,172,377,693,460,000` units.  
     - Attacker EOA `0xbda2a27c...` BEP20USDT balance increasing by `19,025,937,127,206,362,656,200` units.  
     - Secondary address `0xbd65ef47...` BEP20USDT balance increasing by `588,431,045,171,330,803,800` units.

   - **Evidence snippet – BEP20USDT state diff in tx 0x7978c002...**

   Source: prestateTracer `balance_diff.json` for profit‑taking transaction `0x7978c002...`.

   ```json
   {
     "0x55d398326f99059ff775485246999027b3197955": {
       "erc20": {
         "0x1e16070a8734B3d686E0CF035c05fBBC1ba21C98": {
           "delta": "-19614368172377693460000"
         },
         "0xbda2a27cdb2ffd4258f3b1ed664ed0f28f9e0fc3": {
           "delta": "19025937127206362656200"
         },
         "0xbd65ef472b7e158ff4757de18fb1f877be2b2213": {
           "delta": "588431045171330803800"
         }
       }
     }
   }
   ```

   *Caption: The BEP20USDT balance diff for tx `0x7978c002...` shows the pool losing `19,614,368,172,377,693,460,000` BEP20USDT, with `19,025,937,127,206,362,656,200` units going to the attacker EOA and `588,431,045,171,330,803,800` units going to `0xbd65ef47...`, confirming the profit‑taking stage of the exploit.*

---

## Impact & Losses

Impact quantification in this report is restricted to the two analyzed seed transactions only. Under this scope, the losses and flows are:

### Quantified token deltas (two‑transaction scope)

- **BTTToken (reward token)**  
  - **Total drained from BTNFT:** `19,158,433,044,140,030,441,194` BTTToken units.  
  - **Total received by helper contract in exploit‑setup tx:** `19,158,433,044,140,030,441,194` BTTToken units.  
  - These values are taken directly from the prestateTracer `balance_diff` for exploit‑setup transaction `0x1e90cbff...`.

- **BEP20USDT (stablecoin, reference asset)**  
  - **Total lost by pool `0x1e16070a...`:** `19,614,368,172,377,693,460,000` BEP20USDT units in profit‑taking transaction `0x7978c002...`.  
  - **Total received by attacker EOA `0xbda2a27c...`:** `19,025,937,127,206,362,656,200` BEP20USDT units.  
  - **Total received by secondary address `0xbd65ef47...`:** `588,431,045,171,330,803,800` BEP20USDT units.  
  - These amounts are taken directly from the prestateTracer `balance_diff` for `0x7978c002...`.

### Summary loss table (two‑transaction analysis scope)

From the perspective of the two analyzed seed transactions, the minimum on‑chain losses attributable to this exploit pattern are:

- `BTTToken`: `19,158,433,044,140,030,441,194` units transferred from BTNFT to the helper contract.  
- `BEP20USDT`: `19,614,368,172,377,693,460,000` units transferred out of pool `0x1e16070a...`, with `19,025,937,127,206,362,656,200` units going to the attacker EOA and `588,431,045,171,330,803,800` units to `0xbd65ef47...`.

These token deltas form a lower bound on the losses associated with this exploit pattern under the explicit two‑transaction scope of this analysis.

### Profit predicate and ACT opportunity

The exploit is profit‑driven, with BEP20USDT as the reference asset:

- **Reference asset:** BEP20USDT (`0x55d398326f99059ff775485246999027b3197955`).  
- **Adversary address (profit owner):** EOA `0xbda2a27cdb2ffd4258f3b1ed664ed0f28f9e0fc3`.  
- **Value delta in reference asset over the two seed transactions:** `19,025,937,127,206,362,656,200` BEP20USDT units credited to the attacker EOA in `0x7978c002...`, with no BEP20USDT deltas in the exploit‑setup transaction.  
- **Gas cost:** The attacker EOA spends `0.021693543` BNB + `0.002328133` BNB = `0.024021676` BNB in gas fees across the two transactions. Even under an extreme upper bound that prices `1` BNB at `1,000` BEP20USDT, the gas cost would be about `24,021.676` BEP20USDT, which is negligible relative to the `19,025,937,127,206,362,656,200` BEP20USDT inflow.

Measured over the two‑transaction sequence, the attacker’s BEP20USDT‑denominated portfolio value increases strictly after accounting for gas, confirming a profitable ACT opportunity.

---

## ACT Opportunity Summary

The exploit path described above constitutes a deterministic ACT opportunity on BSC:

- **Pre‑state (`σ_B`)** – Public BSC mainnet pre‑state immediately before block `48472356`, reconstructed from canonical chain data and the collected traces, balance diffs, and contract metadata for the two seed transactions.  
- **Transaction sequence (`b`)** – Two adversary‑crafted transactions:
  1. `0x1e90cbff...`: helper contract harvests BTTToken from BTNFT via flawed `_update(to == address(this))` logic.  
  2. `0x7978c002...`: helper contract routes harvested BTTToken into pool `0x1e16070a...` and swaps to BEP20USDT profit.
- **Feasibility:** Both transactions are standard EOA‑signed transactions from an unprivileged address to the helper contract, requiring only deployment of the helper contract and payment of BNB gas; they use BTNFT, BTTToken, BEP20USDT, and pool state determined entirely by prior on‑chain activity.

Given this pre‑state and transaction sequence, an unprivileged attacker can deterministically:

1. Harvest vested BTTToken from BTNFT for approved victim tokenIds via `BTNFT.transferFrom(victim, address(BTNFT), tokenId)`.  
2. Swap harvested BTTToken into BEP20USDT using public liquidity in pool `0x1e16070a...` and router `0x82C7c2F4...`.  
3. Realize net BEP20USDT profit at the attacker EOA after gas.

---

## References

This section lists the main on‑chain and code artifacts referenced in the analysis:

1. **BTNFT source Contract.sol (`0x0FC91B6Fea2E7A827a8C99C91101ed36c638521B`)**  
   - Collected verified source for the BTNFT vesting NFT contract, including the overridden `_update` hook and `claimReward` logic.

2. **BTTToken source Contract.sol (`0xDAd4df3eFdb945358a3eF77B939Ba83DAe401DA8`)**  
   - Collected verified source for the BTTToken ERC20 reward token.

3. **BEP20USDT source Contract.sol (`0x55d398326f99059ff775485246999027b3197955`)**  
   - Collected verified source for the BEP20USDT stablecoin used as the reference profit asset.

4. **Exploit‑setup transaction trace (`0x1e90cbff665c43f91d66a56b4aa9ba647486a5311bb0b4381de4d653a9d8237d`)**  
   - `cast run -vvvvv` trace showing helper contract `0x7A4D1443...` calling `BTNFT.transferFrom(victim, BTNFT, tokenId)` and triggering BTTToken transfers and `TokensClaimed` events for many tokenIds.

5. **Exploit‑setup transaction balance diff (`0x1e90cbff665c43f91d66a56b4aa9ba647486a5311bb0b4381de4d653a9d8237d`)**  
   - QuickNode prestateTracer `balance_diff` showing BTTToken deltas between BTNFT and helper contract for the harvesting transaction.

6. **Profit‑taking transaction trace (`0x7978c002d12be9b748770cc31cbaa1b9f3748e4083c9f419d7a99e2e07f4d75f`)**  
   - `cast run -vvvvv` trace showing the helper contract’s approvals, transfers, and swap path through pool `0x1e16070a...` and router `0x82C7c2F4...` to produce BEP20USDT payouts.

7. **Profit‑taking transaction balance diff (`0x7978c002d12be9b748770cc31cbaa1b9f3748e4083c9f419d7a99e2e07f4d75f`)**  
   - QuickNode prestateTracer `balance_diff` showing BEP20USDT deltas for the pool, attacker EOA, and secondary recipient address.

8. **Data collection summary**  
   - Aggregated view of fetched contract sources, bytecode, txlists, and state diffs used to support the analysis, including references for BTNFT, BTTToken, BEP20USDT, helper contract, pool, router, and relevant addresses.

