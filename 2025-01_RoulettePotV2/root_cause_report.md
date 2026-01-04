# RoulettePotV2 swapProfitFees flash-loan drain on BNB Chain

## 1. Incident Overview TL;DR

On BNB Chain (chainid 56), attacker EOA `0x0000000000004f3d8aaf9175fd824cb00ad4bf80` used an attacker-controlled router `0x000000000000bb1b11e5ac8099e92e366b64c133` to execute a flash-loan-driven exploit against `RoulettePotV2` (`0xf573748637e0576387289f1914627d716927f90f`).  
In a single transaction `0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490`, the router:
- Obtained a Pancake V3 WBNB flash loan,
- Called `RoulettePotV2.finishRound()`,
- Invoked the unguarded `RoulettePotV2.swapProfitFees()` function,
- Swapped RoulettePotV2’s BNBP, CAKE, and BUSD casino balances into BNB and LINK,  
- Repaid the flash loan and distributed the remaining BNB profit to attacker-controlled addresses.

The attacker cluster `{0x0000000000004f3d8aaf9175fd824cb00ad4bf80, 0x000000000000bb1b11e5ac8099e92e366b64c133, 0xdfac7733c205c3a2a5e202293ebb37e4633bc286}` gained `39.520332269709821513` BNB net of gas, while RoulettePotV2’s casino balances in BNBP, CAKE, BUSD and 4.171603472025223867 BNB of native balance were drained.

The root cause is a protocol bug: `swapProfitFees()` is an external, publicly callable treasury-management function with no access control. It allows any caller to convert accumulated casino profit and liquidity into BNB and LINK and route the resulting assets along the caller’s control path.

## 2. Key Background

**Protocol and contracts**
- **Protocol name:** RoulettePotV2.
- **Victim contract:** `RoulettePotV2` at `0xf573748637e0576387289f1914627d716927f90f` on BNB Chain, verified source.
- **Treasury pot:** `PotLottery` at `0xfb0232ecaf4f963af6874daa7d986e56fe0d0cc6`, referenced by RoulettePotV2 as `potAddress`.
- **Key tokens and pairs:**
  - BNBP token `0x4D9927a8Dc4432B93445dA94E4084D292438931F`, Pancake pair `0x4C736d24d72D874cc2465553500c1Ff3Fc7b3BDA`.
  - CAKE token `0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82`, Pancake pair `0x0Ed7e52944161450477ee417de9Cd3a859b14fD0`.
  - BUSD token with Pancake pair `0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16`.
  - LINK token `0xf8a0bf9cf54bb92f17374d9e9a321e6a111a51bd` and ERC677 LINK `0x404460C6A5EdE2D891e8297795264fDe62ADBB75`.
  - WBNB `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`.

**Pre-state \u03a3\_B at block 45,668,285**

The ACT opportunity is defined relative to the pre-state immediately before block `45668286` on BNB Chain (block height `B = 45668285`), reconstructed from public artifacts:
- Native balances and ERC-20 balances for the attacker cluster `{attacker EOA, router, profit-sink EOA}`.
- RoulettePotV2 casino state for BNBP, CAKE, BUSD.
- WBNB pool balances and Pancake AMM reserves for relevant pools.

The following collected artifacts specify this pre-state:
- Seed tx metadata and prestate diff for `0xd9e0…3490`:
  - `artifacts/root_cause/seed/56/0xd9e0014a32...3490/metadata.json`
  - `artifacts/root_cause/data_collector/iter_1/tx/56/0xd9e0014a32...3490/balance_diff.prestate.json`
  - `artifacts/root_cause/data_collector/iter_4/profit/seed_tx_balance_diff_prestate.json`
  - `artifacts/root_cause/seed/56/0xd9e0014a32...3490/balance_diff.json`
- RoulettePotV2 casino state pre/post exploit:
  - `artifacts/root_cause/data_collector/iter_4/contract/56/0xf5737486...f90f/casino_state/casino_state_pre_post.json`
- Victim contract source:
  - `artifacts/root_cause/data_collector/iter_1/contract/56/0xf5737486...f90f/source/src/Roulette/RouletteV2.sol`
- Router deployment and internal tx history:
  - `artifacts/root_cause/data_collector/iter_4/address/56/0x000000000000bb1b11e5ac8099e92e366b64c133/txlist_internal_full.json`
- Detailed on-chain trace:
  - `artifacts/root_cause/data_collector/iter_1/tx/56/0xd9e0014a32...3490/debug_trace_callTracer.json`
  - `artifacts/root_cause/seed/56/0xd9e0014a32...3490/trace.cast.log`

The casino pre/post state for BNBP and CAKE illustrates that significant token liquidity was present before the exploit and removed afterward:

```json
// RoulettePotV2 casino_state_pre_post.json (BNBP and CAKE casinos)
{
  "BNBP": {
    "pre": {
      "tokenName": "BNBP",
      "liquidity": 324850208759244500000000,
      "fee": 50,
      "profit": 18620276300000000000000,
      "tokenId": 4
    },
    "post": {
      "liquidity": 0,
      "fee": 50,
      "profit": 0,
      "tokenId": 4
    }
  },
  "CAKE": {
    "pre": {
      "tokenName": "CAKE",
      "liquidity": 585977361274789000000,
      "fee": 50,
      "profit": 22666000000000000000,
      "tokenId": 3
    },
    "post": {
      "liquidity": 260256024930936500000,
      "fee": 50,
      "profit": 0,
      "tokenId": 3
    }
  }
}
```

## 3. Vulnerability Analysis

### 3.1 Core vulnerability

The ACT opportunity arises because `RoulettePotV2.swapProfitFees()` is declared `external` and has no access control modifiers. It is designed as a treasury-management function to:
- Aggregate casino profits for BNBP, CAKE, BUSD,
- Swap tokens to BNB and LINK,
- Fund VRF in LINK and allocate residual BNBP to a PotLottery-based tokenomics pool.

However, since **any address** can call it, the function effectively allows unprivileged callers (including attacker-controlled routers) to liquidate the casino’s token liquidity and route the resulting BNB and LINK under their control.

### 3.2 Vulnerable components

- **RoulettePotV2.swapProfitFees()** (`RouletteV2.sol`, lines 753–894, address `0xf5737486...f90f`):
  - External function with no `onlyOwner` or similar access control.
  - Uses internal accounting (`Casino.profit`, `Casino.liquidity`, `linkSpent`) to compute token amounts to swap and LINK funding requirements.
  - Approves PancakeRouter to spend token balances from RoulettePotV2 and converts them to BNB and LINK.
- **Attacker-controlled router `0x000000000000bb1b11e5ac8099e92e366b64c133`**:
  - Orchestrates a Pancake V3 WBNB flash loan.
  - Calls `RoulettePotV2.finishRound()` and then `RoulettePotV2.swapProfitFees()` in the same transaction.
  - Routes the resulting BNB and LINK to attacker addresses and treasury-like sinks it controls.
- **AMM infrastructure (Pancake)**:
  - Deep liquidity in BNBP, CAKE, and BUSD pairs enables large swaps from RoulettePotV2’s balances to BNB.
  - PancakeRouter `0x10ED43C718714eb63d5aA57B78B54704E256024E` is the router used by `swapProfitFees()` to perform swaps.

### 3.3 Security principles violated

- **Missing access control on privileged treasury-management function**  
  `swapProfitFees()` exposes a powerful treasury operation to arbitrary callers. There is no restriction to a trusted operator or governance.

- **Failure to separate game accounting from treasury operations**  
  The same contract that holds user-facing casino liquidity also exposes a public function that can liquidate these holdings, instead of isolating treasury flows in a separate, controlled module.

- **Lack of flash-loan resistance**  
  The function assumes honest, operator-triggered execution and does not limit the timing, frequency, or context of calls. This allows a searcher to use flash loans to drain value in a single block while preserving apparent invariants.

- **Implicit caller trust instead of explicit authorization**  
  The system relies on expectations about who will call treasury-management functions, rather than enforcing these expectations in code.

The `swapProfitFees()` implementation, reproduced below, shows both the lack of access control and its ability to move large token amounts from RoulettePotV2 through PancakeRouter into BNB and LINK:

```solidity
// Snippet from RouletteV2.sol (swapProfitFees)
function swapProfitFees() external {
    IPancakeRouter02 router = IPancakeRouter02(pancakeRouterAddr);
    address[] memory path = new address[](2);
    uint256 totalBNBForGame;
    uint256 totalBNBForLink;
    uint256 length = casinoCount;
    uint256 BNBPPool = 0;

    // Swap each token to BNB
    for (uint256 i = 1; i <= length; ++i) {
        Casino memory casinoInfo = tokenIdToCasino[i];
        IERC20 token = IERC20(casinoInfo.tokenAddress);

        if (casinoInfo.liquidity == 0) continue;

        uint256 availableProfit = casinoInfo.profit < 0 ? 0 : uint256(casinoInfo.profit);
        if (casinoInfo.liquidity < availableProfit) {
            availableProfit = casinoInfo.liquidity;
        }

        uint256 gameFee = (availableProfit * casinoInfo.fee) / 100;
        uint256 amountForLinkFee = getTokenAmountForLink(casinoInfo.tokenAddress, linkSpent[i]);
        _updateProfitInfo(i, uint256(gameFee), availableProfit);
        casinoInfo.liquidity = tokenIdToCasino[i].liquidity;

        // If fee from the profit is not enought for link, then use liquidity
        if (gameFee < amountForLinkFee) {
            if (casinoInfo.liquidity < (amountForLinkFee - gameFee)) {
                amountForLinkFee = gameFee + casinoInfo.liquidity;
                tokenIdToCasino[i].liquidity = 0;
            } else {
                tokenIdToCasino[i].liquidity -= (amountForLinkFee - gameFee);
            }
            gameFee = 0;
        } else {
            gameFee -= amountForLinkFee;
        }

        _updateLinkConsumptionInfo(i, amountForLinkFee);

        if (casinoInfo.tokenAddress == address(0)) {
            totalBNBForGame += gameFee;
            totalBNBForLink += amountForLinkFee;
            continue;
        }
        if (casinoInfo.tokenAddress == BNBPAddress) {
            BNBPPool += gameFee;
            gameFee = 0;
        }

        path[0] = casinoInfo.tokenAddress;
        path[1] = wbnbAddr;

        if (gameFee + amountForLinkFee == 0) {
            continue;
        }
        token.approve(address(router), gameFee + amountForLinkFee);
        uint256[] memory swappedAmounts = router.swapExactTokensForETH(
            gameFee + amountForLinkFee,
            0,
            path,
            address(this),
            block.timestamp
        );
        totalBNBForGame += (swappedAmounts[1] * gameFee) / (gameFee + amountForLinkFee);
        totalBNBForLink += (swappedAmounts[1] * amountForLinkFee) / (gameFee + amountForLinkFee);
    }

    // ... subsequent LINK and BNBP distribution logic ...
}
```

## 4. Detailed Root Cause Analysis

### 4.1 ACT opportunity definition and success predicate

**Block height and pre-state:**  
- ACT opportunity block height `B = 45668285` (immediately before exploit block `45668286` on BNB Chain).
- Pre-state \u03a3\_B includes:
  - Native balances for attacker EOA `0x0000000000004f3d8aaf9175fd824cb00ad4bf80`, router `0x000000000000bb1b11e5ac8099e92e366b64c133`, and profit-sink EOA `0xdfac7733c205c3a2a5e202293ebb37e4633bc286`.
  - RoulettePotV2 casino state for BNBP, CAKE, BUSD.
  - WBNB pool balances and AMM reserves for involved Pancake pairs.

**Success predicate:**  
The exploit is successful if, in a single adversary-crafted transaction on chainid 56:
- The attacker cluster’s total BNB balance increases, net of gas, by `39.520332269709821513` BNB, and
- The increase is funded by draining RoulettePotV2’s BNBP, CAKE, BUSD casino balances and its native BNB, as opposed to other sources.

The profit view in `seed_tx_balance_diff_prestate.json` shows the native balance deltas for the key addresses:

```json
// seed_tx_balance_diff_prestate.json (native_balance_deltas excerpt)
[
  {
    "address": "0xf573748637e0576387289f1914627d716927f90f",
    "before_wei": "4171603472025223888",
    "after_wei": "21",
    "delta_wei": "-4171603472025223867"
  },
  {
    "address": "0x000000000000bb1b11e5ac8099e92e366b64c133",
    "before_wei": "9999810001",
    "after_wei": "1",
    "delta_wei": "-9999810000"
  },
  {
    "address": "0x0000000000004f3d8aaf9175fd824cb00ad4bf80",
    "before_wei": "1379794158320757963",
    "after_wei": "20900126438030389476",
    "delta_wei": "19520332279709631513"
  },
  {
    "address": "0xdfac7733c205c3a2a5e202293ebb37e4633bc286",
    "before_wei": "34418196782733558",
    "after_wei": "20034418196782733558",
    "delta_wei": "20000000000000000000"
  }
]
```

Summing `delta_wei` across `{attacker EOA, router, profit-sink}` yields `39,520,332,269,709,821,513` wei (`39.520332269709821513` BNB) net profit.

The success predicate is therefore:
- **Reference asset:** BNB.
- **Adversary main address:** `0x0000000000004f3d8aaf9175fd824cb00ad4bf80`.
- **Fees paid (gas):** `0.001261246` BNB (1,261,246,000,000,000 wei).
- **Cluster value before:** `1.414212365103301522` BNB.
- **Cluster value after:** `40.934544634813123035` BNB.
- **Cluster value delta:** `39.520332269709821513` BNB.

These values are derived deterministically from:
- `native_balance_deltas.before_wei` and `after_wei` in `seed_tx_balance_diff_prestate.json`.
- The router→attacker transfer amount and attacker gas spend as observed in `debug_trace_callTracer.json`.

### 4.2 Exploit conditions (ACT opportunity)

For an unprivileged adversary, the ACT exploit is realizable under the following fully on-chain conditions:
- RoulettePotV2 is deployed with nonzero `Casino.liquidity` and nonnegative `Casino.profit` for BNBP and CAKE casinos, plus nonzero BUSD liquidity, as recorded in `casino_state_pre_post.json` at pre_block `45668285`.
- `swapProfitFees()` remains external and callable by any address, with no access control gating.
- Pancake V3 pool `0x172fcD41E0913e95784454622d1c3724f546f849` can provide a sufficient WBNB flash loan via the router.
- BNBP, CAKE and BUSD tokens held by RoulettePotV2 have active Pancake pairs:
  - `0x4C736d24d72D874cc2465553500c1Ff3Fc7b3BDA` (BNBP),
  - `0x0Ed7e52944161450477ee417de9Cd3a859b14fD0` (CAKE),
  - `0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16` (BUSD),
  that accept large swaps at the exploit time.
- The router’s sequence (flash loan → `finishRound()` → `swapProfitFees()` → swaps → LINK funding → BNB distribution) fits within one transaction and satisfies standard inclusion rules on BNB Chain.

### 4.3 Concrete victim transaction and on-chain traces

The exploit transaction is:
- **Chain:** BNB Chain (56)
- **Tx hash:** `0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490`
- **Type:** Adversary-crafted.
- **Sender (EOA):** `0x0000000000004f3d8aaf9175fd824cb00ad4bf80`.
- **Recipient:** Router `0x000000000000bb1b11e5ac8099e92e366b64c133.morph()`.
- **Value:** 0 BNB.

Inclusion feasibility is evidenced by the seed metadata: an unprivileged EOA signs and broadcasts a 0-value transaction to the public router with gas `0x1a8fce`, gasPrice `0x3b9aca00`, nonce `0xa9` and chainId `56`. Any EOA with sufficient BNB to pay gas and valid parameters is able to submit the same `morph()` call and have it included under standard BNB Chain rules.

The `trace.cast.log` for this transaction shows the high-level control flow:

```bash
# Seed transaction trace (cast run -vvvvv) for 0xd9e0...3490 (excerpt)
Traces:
  [1537333] 0x000000000000Bb1B11e5Ac8099E92e366B64c133::...(morph payload)
    ├─ [1503900] PancakeV3Pool::flash(..., 0, 4203732130200000000000, ...)
    │   └─ ... (pair and price updates)
    ├─ [234772] RoulettePotV2::finishRound()
    │   └─ ... (VRF checks, game settlement, events)
    ├─ [1096763] RoulettePotV2::swapProfitFees()
    │   └─ ... (PancakeRouter calls to swap casino tokens for BNB and LINK)
    └─ ... (BNB and LINK routing, flash loan repayment)
```

`debug_trace_callTracer.json` provides the detailed call tree, confirming the sequence:
1. Router acquires a WBNB flash loan.
2. Router calls `RoulettePotV2.finishRound()` to settle a game round and adjust casino accounting.
3. Router calls `RoulettePotV2.swapProfitFees()`, which:
   - Draws from `Casino.profit` and `Casino.liquidity`,
   - Approves PancakeRouter to move BNBP, CAKE, BUSD from RoulettePotV2,
   - Swaps these tokens into BNB and LINK,
   - Sends LINK to the VRF coordinator via PegSwap and ERC677 LINK,
   - Leaves remaining BNB under the caller’s control flow.
4. Router repays the flash loan and forwards BNB profit to attacker EOAs.

### 4.4 How `swapProfitFees()` drains casino balances

Within `swapProfitFees()` for each casino:
- `availableProfit` is set to `max(Casino.profit, 0)` and capped at `Casino.liquidity`.
- `gameFee` is `availableProfit * fee / 100`.
- `amountForLinkFee` is `getTokenAmountForLink(tokenAddress, linkSpent[i])`.
- `_updateProfitInfo` and `_updateLinkConsumptionInfo` mutate internal accounting, and `Casino.liquidity` may be reduced further if `gameFee` is insufficient to cover `amountForLinkFee`.
- For non-`address(0)` casinos:
  - If `tokenAddress == BNBPAddress`, `gameFee` is added to `BNBPPool`.
  - Otherwise, `gameFee + amountForLinkFee` is approved to PancakeRouter and swapped to WBNB, which is then split into `totalBNBForGame` and `totalBNBForLink`.
- After the loop:
  - `totalBNBForLink` is swapped to LINK, converted via PegSwap, and transferred to VRF coordinator.
  - `totalBNBForGame` is swapped to BNBP and fed into PotLottery via `addAdminTokenValue`.

In the exploit pre-state, `casino_state_pre_post.json` shows:
- **BNBP casino:**
  - Pre: `liquidity = 324850208759244500000000`, `profit = 18620276300000000000000`, `fee = 50`.
  - Post: `liquidity = 0`, `profit = 0`.
- **CAKE casino:**
  - Pre: `liquidity = 585977361274789000000`, `profit = 22666000000000000000`, `fee = 50`.
  - Post: `liquidity = 260256024930936500000`, `profit = 0`.
- **BUSD casino:**
  - Pre: nonzero liquidity and negative profit.
  - Post: `liquidity = 0`, profit unchanged (still negative).

The ERC-20 balance diffs in `balance_diff.json` and `seed_tx_balance_diff_prestate.json` show:
- RoulettePotV2’s BNBP balance decreases by `324850208759244488266486` units, mirrored as a positive delta on Pancake pair `0x4C736d24d72D874cc2465553500c1Ff3Fc7b3BDA`.
- CAKE balance decreases by `325721336343852503289` units, mirrored on pair `0x0Ed7e52944161450477ee417de9Cd3a859b14fD0`.
- BUSD balance decreases by `9442741234770661142` units, mirrored on pair `0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16`.

These changes match the intended behavior of `swapProfitFees()` when invoked, but in this incident they are triggered by an attacker-controlled router instead of a trusted operator.

### 4.5 Excluding alternative sinks

The analysis verifies that drained value is not diverted via other contracts such as `PotLottery` in this block:
- `casino_state_pre_post.json` encodes BNBPPool-related changes inside RoulettePotV2’s casino accounting and `linkSpent`, with no conflicting PotLottery state transitions.
- Router internal-tx history around block `45668286` shows no unexpected treasury calls beyond the documented sequence.
- `debug_trace_callTracer.json` confirms that the major BNB outflows from RoulettePotV2 in the exploit transaction occur through the `swapProfitFees()`-driven swaps and VRF funding path.

Therefore, the **root cause** of the loss is:
- An **unguarded, external `swapProfitFees()` function** that allows arbitrary callers to liquidate RoulettePotV2 casino liquidity and profit.
- The attacker router’s use of a **flash loan** and carefully structured call sequence to invoke it at a time when casino liquidity was large and fully extractable.

## 5. Adversary Flow Analysis

### 5.1 Adversary-related accounts

The analysis identifies the following adversary-related accounts on BNB Chain (chainid 56), using on-chain evidence:

- **Attacker EOA (primary):** `0x0000000000004f3d8aaf9175fd824cb00ad4bf80`  
  - Tx sender of exploit transaction `0xd9e0…3490`.  
  - Receives `19.520332279709631513` BNB net of gas in the transaction, as shown in `seed_tx_balance_diff_prestate.json` and `debug_trace_callTracer.json`.

- **Attacker-controlled router contract:** `0x000000000000bb1b11e5ac8099e92e366b64c133`  
  - A CREATE2-deployed router whose internal-tx history shows deployment by EOA `0x2bab3d77f90532f097b500ec0c0cbd1591566b1a` in block `41505732`.  
  - Its call trace for `0xd9e0…3490` shows it executing the Pancake V3 flash loan and calling `RoulettePotV2.finishRound()` and `swapProfitFees()`, then forwarding BNB and other assets to attacker EOAs.

- **Profit-sink EOA:** `0xdfac7733c205c3a2a5e202293ebb37e4633bc286`  
  - Receives exactly `20` BNB (`20000000000000000000` wei) from the router in the exploit transaction.  
  - Has no balancing outflow in the same transaction, as shown in `seed_tx_balance_diff_prestate.json` and the router’s `txlist_internal_full.json`.

These three addresses form the adversary cluster used to evaluate profit and ACT feasibility.

### 5.2 Adversary strategy summary

At a high level, the attacker:
1. Deploys or uses router `0x000000000000bb1b11e5ac8099e92e366b64c133` with logic to execute Pancake V3 flash loans and downstream contract calls.
2. Identifies that RoulettePotV2’s `swapProfitFees()` is:
   - External,
   - Unrestricted by access control,
   - Capable of swapping casino token liquidity into BNB and LINK.
3. Waits until RoulettePotV2’s BNBP, CAKE, and BUSD casinos hold large amounts of liquidity and profit.
4. Crafts a single `morph()` transaction from attacker EOA `0x0000000000004f3d8aaf9175fd824cb00ad4bf80` that:
   - Borrows WBNB via Pancake V3 pool `0x172fcD41E0913e95784454622d1c3724f546f849` and pair `0x824eb9faDFb377394430d2744fa7C42916DE3eCe`,
   - Calls `RoulettePotV2.finishRound()` to perform game settlement,
   - Calls `RoulettePotV2.swapProfitFees()` to liquidate BNBP, CAKE, BUSD casino liquidity and fund LINK,
   - Repays the flash loan,
   - Sends the remaining BNB profit to the attacker EOA and profit-sink EOA.

### 5.3 Adversary lifecycle stages (per transaction)

For transaction `0xd9e0…3490`, the adversary lifecycle is:

1. **Reconnaissance and preparation**  
   - On-chain inspection of `RoulettePotV2` source reveals external `swapProfitFees()` with no access control.  
   - Historical data show casinos with substantial BNBP, CAKE, BUSD liquidity and profit.  
   - Router is deployed with flash-loan and routing logic.

2. **Execution (single-block flash-loan exploit)**  
   - Attacker EOA sends a 0-value transaction to router `morph()` with a data payload that encodes:
     - Flash loan parameters (WBNB amount, pool/pair addresses),
     - Calls to `finishRound()` and `swapProfitFees()` on `RoulettePotV2`,
     - Swap and distribution steps for the resulting BNB and LINK.
   - Router:
     - Calls Pancake V3 pool `0x172fcd41e0913e95784454622d1c3724f546f849` to obtain a WBNB flash loan.
     - Routes through pair `0x824eb9faDFb377394430d2744fa7C42916DE3eCe` as part of the flash loan path.
     - Invokes `RoulettePotV2.finishRound()` and then `RoulettePotV2.swapProfitFees()`.
     - Uses PancakeRouter `0x10ED43C718714eb63d5aA57B78B54704E256024E` to convert BNBP, CAKE, BUSD from RoulettePotV2 into BNB and LINK.
     - Repays the flash loan and forwards BNB to `0x0000000000004f3d8aaf9175fd824cb00ad4bf80` and `0xdfac7733c205c3a2a5e202293ebb37e4633bc286`.

3. **Post-exploit consolidation**  
   - Attacker EOA and profit-sink EOA hold the extracted BNB.  
   - No immediate on-chain behavior in the same transaction offsets these gains.

### 5.4 Transaction sequence B (ACT realization)

The ACT opportunity is realized with a single transaction in the sequence:

1. **Index 1**  
   - **Chainid:** 56 (BNB Chain)  
   - **Txhash:** `0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490`  
   - **Type:** adversary-crafted  
   - **Inclusion feasibility:**  
     - Unprivileged EOA `0x0000000000004f3d8aaf9175fd824cb00ad4bf80` signs and broadcasts a 0-value transaction to public router `0x000000000000bb1b11e5ac8099e92e366b64c133.morph()` with gas `0x1a8fce`, gasPrice `0x3b9aca00`, nonce `0xa9` and chainId `56`, as shown in the seed metadata.  
     - Under standard BNB Chain inclusion rules, any unprivileged EOA with sufficient BNB balance and valid gas parameters is able to submit the same `morph()` call and have the transaction included.
   - **Notes:**  
     - Within this transaction, router `0x000000000000bb1b11e5ac8099e92e366b64c133` executes a Pancake V3 flash loan via pool `0x172fcD41E0913e95784454622d1c3724f546f849` and pair `0x824eb9faDFb377394430d2744fa7C42916DE3eCe`, calls `RoulettePotV2.finishRound()` and the unguarded `RoulettePotV2.swapProfitFees()`, repays the flash loan, converts the victim’s BNBP/CAKE/BUSD casino balances into BNB and LINK, and distributes BNB profit to attacker-related addresses `0x0000000000004f3d8aaf9175fd824cb00ad4bf80` and `0xdfac7733c205c3a2a5e202293ebb37e4633bc286`.

The only other relevant transaction explicitly listed is:
- **Related tx:** `0x4c2a99c21877d7eddae97b0df04eac584c0631bb788eee5706c28a36d4b3ff0a` on chainid 56, categorized as “related” in the analysis but not the primary exploit.

## 6. Impact & Losses

### 6.1 Token-level losses from RoulettePotV2

Using `seed_tx_balance_diff_prestate.json` and `casino_state_pre_post.json`, the analysis quantifies the protocol’s losses:

- **BNBP**  
  - Loss: `324850208759244488266486` BNBP units.  
  - This matches the negative BNBP delta on RoulettePotV2 and the positive delta on Pancake pair `0x4C736d24d72D874cc2465553500c1Ff3Fc7b3BDA`.

- **CAKE**  
  - Loss: `325721336343852503289` CAKE units.  
  - Matches the negative CAKE delta on RoulettePotV2 and the positive delta on Pancake pair `0x0Ed7e52944161450477ee417de9Cd3a859b14fD0`.

- **BUSD**  
  - Loss: `9442741234770661142` BUSD units.  
  - Matches the negative BUSD delta on RoulettePotV2 and the positive delta on Pancake pair `0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16`.

- **BNB (native)**  
  - Loss: `4.171603472025223867` BNB (`4,171,603,472,025,223,867` wei) from RoulettePotV2’s native balance, as recorded in `native_balance_deltas` for `0xf573748637e0576387289f1914627d716927f90f` in `seed_tx_balance_diff_prestate.json`.

### 6.2 Attacker profit

From the attacker cluster’s pre/post BNB balances:
- **Fees paid (gas):**  
  - `0.001261246` BNB (`1,261,246,000,000,000` wei), computed from the router→attacker transfer in `debug_trace_callTracer.json` and the attacker’s native balance delta.

- **Cluster value before (BNB):**  
  - `1.414212365103301522` BNB, corresponding to:
    - Attacker EOA: `1.379794158320757963` BNB.
    - Router: `0.000009999810001` BNB.
    - Profit-sink EOA: `0.034418196782733558` BNB.

- **Cluster value after (BNB):**  
  - `40.934544634813123035` BNB, corresponding to:
    - Attacker EOA: `20.900126438030389476` BNB.
    - Router: `0.000000000000000001` BNB.
    - Profit-sink EOA: `20.034418196782733558` BNB.

- **Net profit (reference asset BNB):**  
  - `39.520332269709821513` BNB (`39,520,332,269,709,821,513` wei), equal to the sum of native balance deltas for the attacker EOA, router, and profit-sink EOA.

Thus, **RoulettePotV2 loses** its entire BNBP casino liquidity, its entire BUSD casino liquidity, a large portion of its CAKE casino liquidity, and `4.171603472025223867` BNB of native balance.  
The **attacker cluster gains** `39.520332269709821513` BNB net of gas, and the LINK spent to fund VRF is sourced from victim-held balances under the attacker-controlled call path rather than from a restricted treasury.

## 7. References

Key artifacts and references used in this analysis:

1. **Seed tx metadata for 0xd9e0…3490**  
   - `artifacts/root_cause/seed/56/0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490/metadata.json`

2. **Prestate and profit-view native and ERC-20 balance diffs**  
   - `artifacts/root_cause/data_collector/iter_4/profit/seed_tx_balance_diff_prestate.json`
   - `artifacts/root_cause/seed/56/0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490/balance_diff.json`
   - `artifacts/root_cause/data_collector/iter_1/tx/56/0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490/balance_diff.prestate.json`

3. **RoulettePotV2 source code (swapProfitFees and casino accounting)**  
   - `artifacts/root_cause/data_collector/iter_1/contract/56/0xf573748637e0576387289f1914627d716927f90f/source/src/Roulette/RouletteV2.sol`

4. **RoulettePotV2 casino state pre/post exploit**  
   - `artifacts/root_cause/data_collector/iter_4/contract/56/0xf573748637e0576387289f1914627d716927f90f/casino_state/casino_state_pre_post.json`

5. **Exploit call trace and flash-loan routing**  
   - `artifacts/root_cause/data_collector/iter_1/tx/56/0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490/debug_trace_callTracer.json`
   - `artifacts/root_cause/seed/56/0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490/trace.cast.log`

6. **Router internal tx history and deployment**  
   - `artifacts/root_cause/data_collector/iter_4/address/56/0x000000000000bb1b11e5ac8099e92e366b64c133/txlist_internal_full.json`

7. **Additional schema and planning artifacts**  
   - `artifacts/root_cause/plan_root_cause.json`  
   - `artifacts/root_cause/schema/root_cause.json`  
   - `artifacts/root_cause/schema/current_analysis_result.json`  
   - `artifacts/root_cause/schema/act_oppo_checklist.json`

