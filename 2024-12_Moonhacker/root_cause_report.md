## Incident Overview TL;DR

Moonwell’s Optimism USDC market was targeted by a searcher-controlled EOA that used a helper contract and an Aave USDC flash loan to unwind three large borrower positions and capture their economic value and incentive rewards. In a single transaction on Optimism (tx `0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe`, block `129697251`), the attacker:

- Borrowed USDC via an Aave flash loan.
- Repaid the USDC debt of three Moonwell borrower contracts on their behalf.
- Triggered reward accrual and transfers (OP and xWELL) for those borrowers.
- Redeemed the borrowers’ MErc20 collateral on the USDC market.
- Repaid the flash loan and kept the remaining USDC as profit.

The protocol’s accounting and access control behaved as designed; the root cause is an ACT-style, permissionless MEV opportunity created by the combination of repay-on-behalf and reward distribution mechanics, not a bug in the Moonwell contracts.

## Key Background

Moonwell on Optimism implements a compound-style lending market for USDC, with MErc20 tokens representing interest-bearing deposits and a Comptroller plus MultiRewardDistributor handling liquidity parameters and reward emissions. At block `129697250` (the pre-state for this incident), all relevant contract code and configuration were publicly visible and reconstructible from on-chain data and verified sources.

The ACT opportunity is defined relative to the publicly reconstructible pre-state:

- **Chain:** Optimism (`chainid = 10`).
- **Pre-state block:** `129697250` (state immediately before block `129697251`).
- **Key contracts and sources:**
  - Moonwell USDC market (`0x8e08617b0d66359d73aa11e11017834c29155525`, MErc20Delegate).
  - MultiRewardDistributor proxy (`0xF9524bfa18C19C3E605FbfE8DFd05C6e967574Aa`) with implementation source.
  - Comptroller (`0xCa889f40aae37FFf165BccF69aeF1E82b5C511B9`) with verified source.
  - USDC token (`0x0b2c639c533813f4aa9d7837caf62653d097ff85`), OP token, and xWELL token contracts.

These components and their configuration are backed by the following artifacts:

- Seed tx metadata and raw Etherscan payload for the incident transaction:
  - `artifacts/root_cause/seed/10/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe/metadata.json`
- Detailed state diff and balance changes for the seed tx:
  - `artifacts/root_cause/seed/10/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe/balance_diff.json`
  - `artifacts/root_cause/data_collector/iter_3/tx/10/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe/prestate_tracer_state_diff.json`
- Verified Moonwell contract sources:
  - `artifacts/root_cause/data_collector/iter_2/contract/10/0xff0731337f615ac5403cb243623283bc04cde121/source/src/rewards/MultiRewardDistributor.sol`
  - `artifacts/root_cause/data_collector/iter_2/contract/10/0xCa889f40aae37FFf165BccF69aeF1E82b5C511B9/source/src/Comptroller.sol`
  - `artifacts/root_cause/seed/10/0xa9ce0a4de55791c5792b50531b18befc30b09dcc/out/MToken.sol/MToken.json`

The key actors in this incident are:

- **Attacker EOA:** `0x36491840ebcf040413003df9fb65b6bc9a181f52`.
- **Helper contract (MoonHacker):** `0x4E258F1705822c2565D54ec8795d303fDf9F768e` (deployed within the incident tx).
- **Moonwell USDC market:** `0x8e08617b0d66359d73aa11e11017834c29155525` (MErc20Delegate via proxy).
- **MultiRewardDistributor:** `0xF9524bfa18C19C3E605FbfE8DFd05C6e967574Aa`.
- **Comptroller:** `0xCa889f40aae37FFf165BccF69aeF1E82b5C511B9`.
- **Borrower contracts whose positions are unwound:**
  - `0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847`
  - `0x24592eD1ccf9e5AE235e24A932b378891313FB75`
  - `0x80472c6848015146FDC3d15CDF6Dc11cA3cb3513`

All of these addresses and their roles are reconstructed strictly from on-chain traces, state diffs, and verified contract sources.

## Vulnerability Analysis

The incident does not rely on a storage corruption bug or broken invariant in the Moonwell protocol. Instead, it exploits a **design-level MEV opportunity** created by the combination of:

- **Repay-on-behalf semantics:** Moonwell exposes `repayBorrowBehalf`, which allows any address to repay another account’s borrow position.
- **Reward accrual on state change:** The Comptroller and MultiRewardDistributor update per-market and per-account reward indices when supply or borrow positions change, then credit OP and xWELL rewards to the affected accounts.
- **Permissionless reward claims and redemptions:** Any address can cause borrowers’ rewards to accrue and can then redeem their MErc20 balances once the debt is fully repaid, as long as normal liquidity checks pass.
- **Atomic composition with flash loans:** A searcher can use a flash loan to pre-fund the repay-on-behalf operations, then unwind the position and repay the loan within one transaction.

The relevant logic is encoded in the Moonwell reward distributor. For example, the `MultiRewardDistributor` implementation includes reward claim functionality that is callable without privileged access and that updates indices and transfers rewards based on usage:

```solidity
// Excerpt from MultiRewardDistributor (verified source for 0xF9524bfa18C19C3E605FbfE8DFd05C6e967574Aa)
function claimReward(uint8 rewardType, address[] memory holders, address[] memory mtokens) external {
    // For each holder and market, update indexes and transfer accrued rewards
    // according to the difference between global and per-account indices.
}
```

The MErc20 market, via the MToken/MErc20Delegate implementation, supports repay-on-behalf and redeem flows that can be driven by an external helper contract:

```json
// Excerpt from MToken ABI (0xa9ce0a4de55791c5792b50531b18befc30b09dcc)
{
  "name": "repayBorrowBehalf",
  "type": "function",
  "inputs": [
    { "name": "borrower", "type": "address" },
    { "name": "repayAmount", "type": "uint256" }
  ]
}
```

Together, these primitives allow an unprivileged searcher to:

1. Repay other accounts’ borrow positions.
2. Force the reward mechanism to finalize and credit their accumulated OP/xWELL.
3. Redeem the accounts’ MErc20 collateral.
4. Route the resulting USDC surplus to the attacker within a single atomic transaction.

The root cause is therefore that the incentive and repay-on-behalf design create a **permissionless, economically profitable rebalancing and reward-harvesting path** that can be exploited by searchers as a MEV opportunity when large, under-managed borrower positions exist.

## Detailed Root Cause Analysis

### ACT Opportunity Definition

The ACT (anyone-can-take) opportunity is defined with respect to pre-state σ\_B at block `129697250` on Optimism:

- **Block height B:** `129697251`.
- **Pre-state σ\_B:** Optimism state at block `129697250` plus verified contract code and configuration for:
  - Moonwell USDC market (`0x8e08617b0d66359d73aa11e11017834c29155525`).
  - MultiRewardDistributor (`0xF9524bfa18C19C3E605FbfE8DFd05C6e967574Aa`).
  - Comptroller (`0xCa889f40aae37FFf165BccF69aeF1E82b5C511B9`).
  - USDC, OP, and xWELL token contracts.

This pre-state is fully reconstructible from:

- Seed metadata and trace: `metadata.json`, `trace.cast.log`.
- Prestate tracer diff: `prestate_tracer_state_diff.json`.
- Verified contract sources listed above.

### Adversary Transaction Sequence

The ACT opportunity is realizable in a single transaction:

- **Tx 1 (adversary-crafted):**
  - Chain: Optimism (`chainid = 10`).
  - Hash: `0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe`.
  - Role: Attacker-profit transaction.
  - Inclusion feasibility: Any unprivileged Optimism address can deploy a helper contract and submit this transaction, which:
    - Obtains an Aave USDC flash loan.
    - Calls Moonwell `repayBorrowBehalf` and `Comptroller.claimReward` for the three borrower contracts.
    - Redeems their MErc20 balances.
    - Repays the flash loan and returns the remaining USDC to the attacker EOA.

The raw transaction payload for this tx is fully visible in the seed metadata:

```json
// Seed transaction metadata (excerpt for tx 0xd12016...54c4fe)
{
  "chainid": 10,
  "txhash": "0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe",
  "etherscan": {
    "tx": {
      "result": {
        "from": "0x36491840ebcf040413003df9fb65b6bc9a181f52",
        "to": null,
        "blockNumber": "0x7bb05e3",
        "input": "0x60806040... (helper deployment + call sequence)"
      }
    }
  }
}
```

### Success Predicate and Profit Quantification

The success predicate is purely profit-based, in reference asset USD, and is defined for the attacker EOA `0x36491840ebcf040413003df9fb65b6bc9a181f52`:

- **Reference asset:** USD.
- **Fees paid in reference asset:** `0.047029968513716235` USD (gas cost, priced from native ETH).
- **Value before (lower bound):** `>= 282.847978816493531997` USD.
  - Derived from the attacker’s ETH balance before the tx (`0.089997 ETH`) multiplied by the native USD price (`3,142.860082186001` USD/ETH) from `pnl_estimate_usd.json`.
  - Ignores any pre-existing holdings in non-ETH tokens to remain conservative.
- **Value after (lower bound):** `>= 319219.353152436519815762` USD.
  - Equal to the ETH-based lower bound before the tx plus the attacker’s net USDC and ETH PnL.
  - XWELL is treated as having zero USD value because it has no price in `pnl_estimate_usd.json`.
- **Value delta (net profit):** `318936.505173620026283765` USD.

These values are computed from the concrete balance changes and prices:

- From `balance_diff.json`, the attacker’s USDC balance delta is:

```json
// Balance diff snippet (seed tx balance_diff.json)
{
  "token": "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
  "holder": "0x36491840ebcf040413003df9fb65b6bc9a181f52",
  "before": "0",
  "after": "318987572368",
  "delta": "318987572368",
  "contract_name": "FiatTokenV2_2"
}
```

- From `pnl_estimate_usd.json`, token and native prices and PnL are:

```json
// PnL estimate (excerpt for tx 0xd12016...54c4fe)
{
  "token_price_data": {
    "tokens": {
      "USDC": {
        "usd_price": 0.999840055949413,
        "address": "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
        "decimals": 6
      },
      "OP": {
        "usd_price": 0.31362098864356375,
        "address": "0x4200000000000000000000000000000000000042",
        "decimals": 18
      },
      "XWELL": {
        "usd_price": null,
        "address": "0xa88594d404727625a9437c3f886c7643872296ae",
        "decimals": 18
      }
    },
    "native": {
      "usd_price": 3142.860082186001,
      "decimals": 18
    }
  },
  "pnl_components_usd": {
    "USDC": {
      "quantity": 318987.572368,
      "usd_price": 0.999840055949413,
      "usd_pnl": 318936.55220358854
    },
    "ETH": {
      "quantity": -1.4964066895719e-05,
      "usd_price": 3142.860082186001,
      "usd_pnl": -0.047029968513716235
    }
  }
}
```

Using only the attacker’s USDC and ETH movements:

- USDC profit: `318,936.55220358854` USD.
- Gas cost: `0.047029968513716235` USD.
- Net USD profit: `318,936.505173620026283765` USD.

This net profit is strictly positive and does not depend on any price for xWELL, which is assigned a null USD price in the data.

## Adversary Flow Analysis

The adversary flow for tx `0xd12016...54c4fe` is fully traceable from `trace.cast.log` and the prestate tracer diff. At a high level, it has three stages.

### 1. Helper Deployment and Flash Loan Acquisition

The attacker EOA deploys a helper contract and obtains an Aave USDC flash loan:

```bash
// Seed transaction trace excerpt (trace.cast.log)
[12297637] → new <unknown>@0x4E258F1705822c2565D54ec8795d303fDf9F768e(...)
...
// Later in executeOperation: flashLoanSimple and USDC transfer in from Aave's L2Pool
```

This step leaves the helper contract funded with a large USDC balance sourced from Aave, with the obligation to repay principal plus fee before the transaction ends.

### 2. Repay-on-Behalf and Reward Accrual

The helper uses the borrowed USDC to repay the debts of the three Moonwell borrower contracts on their behalf. The trace excerpt shows the repay and allowance flows for borrower `0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847`:

```bash
// trace.cast.log excerpt (repayment for 0xD9B45e2c...)
MErc20Delegator::getAccountSnapshot(MoonHacker: [0xD9B45e2c...]) [staticcall]
...
FiatTokenV2_2::transfer(MoonHacker: [0xD9B45e2c...], 485984781792) [delegatecall]
...
MErc20Delegator::repayBorrow(485984781792)
  MErc20Delegate::repayBorrow(485984781792) [delegatecall]
```

Across the three borrowers, USDC is moved from the helper to the Moonwell USDC market via `FiatTokenV2_2::transfer`, and `MErc20Delegate::repayBorrow` reduces their borrow balances to zero. This is reflected in `balance_diff.json`, where the MErc20 balances of the borrower contracts drop to zero while the USDC market’s internal state and the reward indices update.

As the borrowers’ positions change, the Comptroller and MultiRewardDistributor update their reward indices and credit OP and xWELL rewards to the borrower contracts. In `balance_diff.json`, this appears as:

- OP balances:
  - MultiRewardDistributor loses `191.284209780459277074` OP.
  - The three borrower contracts gain the corresponding OP amounts.
- xWELL balances:
  - xWELL distributor address loses `10,900.526042791664` xWELL.
  - The three borrower contracts gain the corresponding xWELL amounts.

### 3. Redemption, Flash-Loan Repayment, and Profit Realization

Once the borrowers’ borrow balances are fully repaid, the helper redeems their MErc20 balances back into USDC and routes the proceeds:

- The USDC market’s MErc20 balances for the three borrowers drop to zero.
- USDC flows back out of the market and through the helper.
- A portion of the USDC is used to repay the Aave flash loan plus fee.
- The remaining USDC, `318,987.572368` tokens, is sent to the attacker EOA.

The final USDC and native balance changes are captured in `balance_diff.json` and `pnl_estimate_usd.json` and summarized as:

- Attacker USDC balance: `0 → 318,987.572368` (token `0x0b2c639c...`).
- Attacker native ETH balance: decreases by `0.000014964066895719` ETH (gas).
- No other addresses in the attacker cluster receive USDC; borrowers retain only OP and xWELL balances.

This flow confirms that the attacker’s profit arises from atomically unwinding the borrowers’ positions, harvesting their equity and incentives, and paying back the flash loan.

## Impact & Losses

The impact is primarily economic and borne by the three borrower contracts and by Moonwell’s incentive emission budget. The protocol remains solvent, and there is no direct loss of funds from protocol reserves beyond the intended reward emissions.

### Quantified Token Movements

From `balance_diff.json` and `pnl_estimate_usd.json`:

- **USDC (0x0b2c639c533813f4aa9d7837caf62653d097ff85):**
  - Attacker EOA gains `318,987.572368` USDC.
  - This corresponds to a priced USDC PnL of `318,936.55220358854` USD for the attacker.
- **OP (0x4200000000000000000000000000000000000042):**
  - MultiRewardDistributor loses `191.284209780459277074` OP.
  - The three borrower contracts jointly gain `191.28420978045926` OP.
- **xWELL (0xa88594d404727625a9437c3f886c7643872296ae):**
  - xWELL distributor address loses `10,900.526042791664` xWELL.
  - The three borrower contracts jointly gain `10,900.526042791664` xWELL.

In total:

- Approximately `318,987.572368` USDC is converted into attacker profit after repaying the flash loan and covering gas.
- Approximately `191.284` OP and `10,900.526` xWELL are emitted from reward reserves to the borrower contracts as part of the unwinding.

### Economic Interpretation

The attacker’s profit corresponds to:

- The borrowers’ residual equity in the USDC market, plus
- The effect of realizing their accrued incentive rewards, less
- The cost of the flash loan fee and gas.

The protocol does not incur a shortfall; instead, the incident demonstrates that:

- Large, heavily leveraged positions with accrued rewards can be economically attractive targets.
- A searcher can use flash loans and repay-on-behalf plus reward hooks to convert those positions into immediate USDC profit.

## References

The analysis is grounded in the following on-chain artifacts and verified sources:

- **[1] Seed transaction metadata and trace for tx 0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe**
  - `artifacts/root_cause/seed/10/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe/metadata.json`
  - `artifacts/root_cause/seed/10/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe/trace.cast.log`

- **[2] Balance diffs for the seed transaction**
  - `artifacts/root_cause/seed/10/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe/balance_diff.json`

- **[3] USD PnL estimate for the attacker cluster**
  - `artifacts/root_cause/data_collector/iter_3/tx/10/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe/pnl_estimate_usd.json`

- **[4] Moonwell MultiRewardDistributor implementation source**
  - `artifacts/root_cause/data_collector/iter_2/contract/10/0xff0731337f615ac5403cb243623283bc04cde121/source/src/rewards/MultiRewardDistributor.sol`

- **[5] Moonwell Comptroller source**
  - `artifacts/root_cause/data_collector/iter_2/contract/10/0xCa889f40aae37FFf165BccF69aeF1E82b5C511B9/source/src/Comptroller.sol`

- **[6] Moonwell MToken / MErc20Delegate ABI and implementation**
  - `artifacts/root_cause/seed/10/0xa9ce0a4de55791c5792b50531b18befc30b09dcc/out/MToken.sol/MToken.json`

These references are sufficient for an independent reader to reconstruct the pre-state, reproduce the trace and balance changes, and verify the MEV opportunity and profit calculations without relying on any off-chain assumptions beyond standard token price data used in `pnl_estimate_usd.json`.

