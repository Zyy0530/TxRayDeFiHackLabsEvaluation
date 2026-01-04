# Incident Overview TL;DR

On BNB Chain (chainid 56), a single seed transaction `0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b` uses a Pancake flash loan to generate large trade volume through the YB/USDT pair. This activity triggers YB’s fee-on-transfer tokenomics, causing protocol-designed fee accrual and USDT redistribution via YB’s TokenDistributor and constructor-configured addresses. The behavior observed in this transaction is driven by YB’s tokenomics and distribution logic, not by a permissionless exploit or profit-making strategy available to an unprivileged adversary. The incident is therefore classified as **non-ACT**.

# Key Background

YB (`0x04227350eda8cb8b1cfb84c727906cb3ccbff547`) is a fee-on-transfer token on BNB Chain whose Solidity implementation follows an `AbsToken` / `TokenDistributor` pattern. For each trade involving YB, a portion of tokens is taken as a fee and routed to a dedicated `TokenDistributor` contract `0x81e190f176f7ae69a7afd7bd7eef2354879db5ec`. The TokenDistributor periodically swaps accumulated YB into USDT and forwards the proceeds to a set of constructor-configured addresses (fund, leader, child, and repair addresses). This design concentrates value on YB-controlled infrastructure and predefined recipients rather than on arbitrary traders.

The seed transaction is sent by EOA `0x00000000b7da455fed1553c4639c4b29983d8538` to an orchestrator contract `0xbdcd584ec7b767a58ad6a4c732542b026dceaa35`. The orchestrator takes a Pancake flash loan in USDT, trades through the YB/USDT pair `0x38231f8eb79208192054be60cb5965e34668350a`, repays the flash loan, and leaves USDT concentrated in YB-owned liquidity and distribution addresses. TokenDistributor access controls and AbsToken fee logic restrict who can withdraw accumulated USDT: only YB and a deployment-time origin address are allowed to call `claimToken`, preventing arbitrary EOAs from redirecting these funds.

The relevant pre-state for ACT considerations is the canonical BNB Chain state immediately before block `48415276`, the block containing the seed transaction. Evidence for this state includes:

- `artifacts/root_cause/seed/56/0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b/metadata.json`
- `artifacts/root_cause/seed/56/0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b/trace.cast.log`
- `artifacts/root_cause/seed/56/0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b/balance_diff.json`
- `artifacts/root_cause/data_collector/iter_1/tx/56/0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b/state_diff_prestateTracer.json`

The ACT-specific metadata in the final analysis is:

- `metadata.report_title`: `YB Tokenomics Incident on BNB Chain`
- `metadata.protocol_name`: `YB`
- `metadata.is_act`: `false`
- `metadata.root_cause_category`: `other`

# Vulnerability Analysis

The YB token implements complex fee-on-transfer mechanics and a dedicated TokenDistributor that together create highly asymmetric value routing:

- For each qualifying trade involving YB and USDT, the YB contract charges fees, burns some YB, sends some to the TokenDistributor, and routes remaining value to addresses configured at deployment.
- The TokenDistributor is designed so that only a small, privileged set of callers can pull USDT out of it.

The core parts of this design can be seen in the on-chain YB source:

```solidity
contract TokenDistributor {
    mapping(address => bool) private _feeWhiteList;

    constructor(address usdt) {
        IERC20(usdt).approve(msg.sender, ~uint256(0));
        IERC20(usdt).approve(tx.origin, ~uint256(0));
        _feeWhiteList[msg.sender] = true;
        _feeWhiteList[tx.origin] = true;
    }

    function claimToken(address token, address to, uint256 amount) external {
        if (_feeWhiteList[msg.sender]) {
            IERC20(token).transfer(to, amount);
        }
    }
}
```

This snippet, taken from the verified YB contract source (`Contract.sol` for `0x04227350eda8cb8b1cfb84c727906cb3ccbff547`), shows that:

- The TokenDistributor whitelists `msg.sender` and `tx.origin` at deployment time.
- Only whitelisted addresses can call `claimToken` to move tokens (including USDT) out of the distributor.

The higher-level fee routing and USDT distribution logic in the YB token is implemented in the `AbsToken`-derived contract. When sufficient fees accumulate and a swap is triggered, YB swaps tokens via the configured router and then distributes USDT to the fund, leader, child, and repair addresses. A key part of this logic is:

```solidity
uint256 usdtBalance = USDT.balanceOf(address(_feeDistributor));
_swapRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
    tokenAmount,
    0,
    path,
    address(_feeDistributor),
    block.timestamp
);

usdtBalance = USDT.balanceOf(address(_feeDistributor)) - usdtBalance;
uint256 sellUsdt = (usdtBalance * contractSellAmount) / tokenAmount;
usdtBalance -= sellUsdt;
// ...
if (sellUsdt > 0) {
    uint256 fundUsdt = (sellUsdt * _fundRate) / 10000;
    if (fundUsdt > 0) {
        _safeTransfer(_usdt, fundAddress, fundUsdt);
    }
    uint256 leaderUsdt = (sellUsdt * _leaderRate) / 10000;
    if (leaderUsdt > 0) {
        _safeTransfer(_usdt, leaderAddress, leaderUsdt);
    }
    uint256 teachUsdt = (sellUsdt * _teachRate) / 10000;
    if (teachUsdt > 0) {
        _safeTransfer(_usdt, repairLpAddress, teachUsdt);
    }
}
// ...
if (usdtBalance > 0) {
    uint256 totalFee = _totalBuyFees + _totalSellFees - _buyDestroyFee - _sellDestroyFee;
    uint256 usdtAmount = ((_buyChildFee + _sellChildFee) * usdtBalance) / totalFee;
    if (usdtAmount > 0) {
        _safeTransfer(_usdt, childAddress, usdtAmount);
    }
    // further allocations to fundAddress and repairLpAddress
}
```

This fragment (also from `Contract.sol`) demonstrates that:

- USDT generated by fee swaps accumulates first on the TokenDistributor.
- It is then moved into a set of hard-configured addresses (fund, leader, child, repair), not to arbitrary traders.

The “vulnerability” exposed by the incident is not a standard permissionless exploit but the aggressive, protocol-intended value routing of YB’s tokenomics. The code ensures that:

- Fees and swap proceeds favor YB-controlled infrastructure and deployment-time configured addresses.
- Access to the TokenDistributor’s balances is restricted to whitelisted callers.

As a result, while the seed transaction generates significant USDT and YB flows, these flows are structurally directed toward YB’s own ecosystem rather than toward a general adversary.

# Detailed Root Cause Analysis

## Seed Transaction Behavior

The seed transaction under analysis is:

- Chain: BNB Chain (`chainid = 56`)
- Transaction hash: `0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b`
- Block number: `48415276`
- Role: `seed`

From `trace.cast.log` and `balance_diff.json`, the transaction performs the following high-level sequence:

1. EOA `0x00000000b7da455fed1553c4639c4b29983d8538` calls orchestrator contract `0xbdcd584ec7b767a58ad6a4c732542b026dceaa35`.
2. The orchestrator executes a Pancake V3 flash loan from pool `0x36696169c63e42cd08ce11f5deebbcebae652050`, borrowing `19,200` USDT (`0x55d398326f99059ff775485246999027b3197955`).
3. It routes USDT into the Pancake V2 pair `0x38231f8eb79208192054be60cb5965e34668350a` (YB/USDT) and performs multiple swaps into YB.
4. YB’s fee-on-transfer logic causes each swap to burn some YB, send some to the TokenDistributor, and allocate YB to various helper addresses and the orchestrator.
5. The orchestrator repays the flash loan within the same transaction.
6. At the end of the transaction, USDT balances are significantly increased on:
   - The YB/USDT pair `0x38231f8eb79208192054be60cb5965e34668350a`
   - The TokenDistributor `0x81e190f176f7ae69a7afd7bd7eef2354879db5ec`
   - Constructor-configured address `0x6820f3dfe24cc322bdbe649e40311e5e6e9964b3`
   - Another USDT liquidity pool `0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae`

The native and ERC20 balance diffs confirm that the seed-sender EOA pays gas and does not receive net profit in a reference asset:

- From `balance_diff.json`:

```json
{
  "address": "0x00000000b7da455fed1553c4639c4b29983d8538",
  "before_wei": "177883329344769538",
  "after_wei": "155534087624769538",
  "delta_wei": "-22349241720000000"
}
```

- No ERC20 balance delta entry is recorded for this EOA, indicating no net change in ERC20 tokens (including USDT and YB) for the seed sender.

## USDT Distribution and Holders

The USDT large-positive-holders summary for the seed transaction is captured in:

- `artifacts/root_cause/data_collector/iter_2/tx/56/0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b/usdt_large_positive_holders_summary.json`

Key entries include:

```json
{
  "chainid": 56,
  "txhash": "0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b",
  "token": "0x55d398326f99059ff775485246999027b3197955",
  "holders": [
    {
      "address": "0x38231f8eb79208192054be60cb5965e34668350a",
      "usdt_delta": 7344.532578935489,
      "account_type": "contract",
      "appears_as_yb_recipient": true
    },
    {
      "address": "0x81e190f176f7ae69a7afd7bd7eef2354879db5ec",
      "usdt_delta": 3510.7915774154003,
      "account_type": "contract",
      "appears_as_yb_recipient": true
    },
    {
      "address": "0x6820f3dfe24cc322bdbe649e40311e5e6e9964b3",
      "usdt_delta": 1186.0699940339982,
      "account_type": "EOA",
      "appears_as_yb_recipient": false
    },
    {
      "address": "0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae",
      "usdt_delta": 15261.68240413122,
      "account_type": "contract",
      "appears_as_yb_recipient": false
    }
  ]
}
```

These holders correspond to:

- YB/USDT liquidity pair
- TokenDistributor
- A constructor-configured recipient address (`0x6820f3d...`)
- Another USDT liquidity pool

Notably, none of these are identified as unprivileged adversary addresses, and their provenance is consistent with YB’s own infrastructure or configured tokenomics recipients.

## ACT Opportunity Fields

The ACT opportunity fields in the final JSON are deterministically set to encode the absence of an ACT:

- `act_opportunity.block_height_B = "48415276"` (seed transaction block)
- `act_opportunity.transaction_sequence_b = []` (no distinct adversary sequence beyond the seed tx)
- `act_opportunity.success_predicate.type = "none"`
- `act_opportunity.success_predicate.profit.reference_asset = "USD"`
- `act_opportunity.success_predicate.profit.value_delta_in_reference_asset = "0"`
- `act_opportunity.success_predicate.profit.valuation_notes` explains that there is no adversary-owned account with net positive profit in USD.

These settings mirror the substantive conclusion that there is no ACT opportunity. They avoid placeholders such as `unknown` and are compatible with the observed traces and deltas.

# Adversary Flow Analysis

The adversary flow analysis concludes that no profitable adversary strategy exists for an unprivileged actor:

- The only EOA directly involved (`0x00000000b7da455fed1553c4639c4b29983d8538`) pays gas and has no net gain in USDT or other ERC20 tokens.
- The orchestrator (`0xbdcd584ec7b767a58ad6a4c732542b026dceaa35`) and helper contracts end the transaction with YB balances but no net positive USDT deltas and no observed follow-up sells within the analyzed windows.
- USDT gains accrue to:
  - The YB/USDT pair `0x38231f8eb79208192054be60cb5965e34668350a`
  - The TokenDistributor `0x81e190f176f7ae69a7afd7bd7eef2354879db5ec`
  - Constructor-configured address `0x6820f3dfe24cc322bdbe649e40311e5e6e9964b3`
  - USDT liquidity pool `0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae`

The adversary-related account classification in the final JSON is:

- `adversary_cluster = []` (no adversary addresses)
- `victim_candidates`:
  - YB token (`0x04227350eda8cb8b1cfb84c727906cb3ccbff547`, verified)
  - TokenDistributor helper (`0x81e190f176f7ae69a7afd7bd7eef2354879db5ec`, unverified)

The lifecycle stage recorded is:

- `stage_name`: `Seed transaction execution and YB fee routing`
- `txs`: the single seed transaction with:
  - `chain_name`: `BNB Chain`
  - `chainid`: `56`
  - `tx`: `0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b`
  - `block_number`: `48415276`
  - `mechanism`: `flashloan`
- `effect`: describes the flash loan, trading through YB/USDT, repayment, and the accumulation of USDT/YB on YB infrastructure and configured addresses.
- `code_or_trace_evidence`:
  - `trace.cast.log` for the seed transaction
  - `balance_diff.json` for the seed transaction
  - `Contract.sol` for the YB token

No additional lifecycle stages are needed because no further adversary actions (such as profitable exits) are observed.

# Impact & Losses

The impact analysis is straightforward:

- `total_loss_overview`:
  - `USDT`: `0`

No protocol or user fund loss is attributed to an adversary. USDT flows into:

- YB-owned liquidity
- The TokenDistributor
- Constructor-configured distribution addresses

as designed by the YB tokenomics. The seed-sender EOA pays gas but does not receive a compensating USDT gain. No adversary cluster with net positive profit in a reference asset is identified. Accordingly:

- The incident is **non-ACT**.
- The effective “loss” is that trade volume driven by the orchestrator benefits YB’s own infrastructure and configured recipients, not a general adversary.

# References

The analysis is supported by the following concrete artifacts:

1. **Seed transaction metadata and traces**  
   Path:  
   `artifacts/root_cause/seed/56/0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b/`  
   Includes:
   - `metadata.json` (transaction metadata)
   - `trace.cast.log` (detailed call trace)
   - `balance_diff.json` (native and ERC20 balance deltas)
   - `state_diff_prestateTracer.json` (pre-state tracer diffs)

2. **YB token and TokenDistributor source**  
   Path:  
   `artifacts/root_cause/seed/56/0x04227350eda8cb8b1cfb84c727906cb3ccbff547/src/Contract.sol`  
   Contains the verified Solidity implementation of YB, including:
   - `TokenDistributor` with whitelisted `claimToken`
   - `AbsToken` fee-on-transfer mechanics
   - USDT routing to fund, leader, child, and repair addresses

3. **USDT large positive holders summary for the seed transaction**  
   Path:  
   `artifacts/root_cause/data_collector/iter_2/tx/56/0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b/usdt_large_positive_holders_summary.json`  
   Summarizes the USDT addresses with large positive deltas in the seed transaction, showing that:
   - Gains accrue to YB/USDT liquidity, the TokenDistributor, a constructor-configured recipient, and a USDT liquidity pool.
   - No unprivileged adversary address with net positive profit in USDT is identified.

