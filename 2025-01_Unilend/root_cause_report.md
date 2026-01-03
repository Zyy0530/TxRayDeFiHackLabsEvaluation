## Incident Overview & TL;DR

This analysis covers a Unilend V2 / Lido stETH position opened around Ethereum mainnet block 21,608,070. An adversary-related externally owned account (EOA) `0x55f5f8058816d5376df310770ca3a2e294089c33` deploys and calls a router contract `0x3f814e5fae74cd73a70a0ea38d85971dfa6fda21` to take a large stETH-denominated borrow on Unilend. The sequence uses a USDC flashloan from `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb`, opens Unilend position 115 in the stETH pool `0x4e34dd25dbd367b1bf82e1b5527dbbe799fad0d0`, and leaves stETH on the EOA and router.

On-chain traces, ERC20 balance snapshots, UnilendV2Pool storage diffs, UnilendV2Core health-factor views, native balance deltas, and txlists show that every unit of stETH obtained by the adversary-related cluster is fully matched by a recorded Unilend token1 debt. The EOA also pays positive ETH gas and contributes to a USDC flashloan fee. No transaction in the analysed window repays or unwinds the Unilend liability while allowing the adversary-related cluster to retain the stETH. As a result, there is no ACT-qualifying exploit and no net profit for the adversary-related cluster.

## Key Background

- **Protocol context**: The activity involves Unilend V2 core `0x7f2e24d2394f2bdabb464b888cb02eba6d15b958` and its stETH pool `0x4e34dd25dbd367b1bf82e1b5527dbbe799fad0d0`, along with Lido stETH `0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84`, wstETH `0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0`, and a USDC flashloan provider `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb`.
- **State at block B**: The analysis defines `pre_state_sigma_B` as Ethereum mainnet state immediately before block 21,608,070 for the Unilend core and pool, stETH and wstETH tokens, flashloan provider, adversary EOA, and router.
- **Seed transaction**: The primary focus is the seed transaction
  `0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba`
  in block 21,608,070, where the EOA calls the router to orchestrate the flashloan and Unilend operations.
- **Related transaction**: A follow-up stETH `approve` transaction
  `0xf60da12f6f2c8212aeab69ecd91bb66b80dc4040df0eff026b30613136936d90`
  in block 21,608,096 aligns allowance with the stETH obtained in the seed transaction but does not change the Unilend debt.

The ACT opportunity is formally framed as a profit predicate with reference asset ETH, adversary address `0x55f5…9c33`, and block height `B = 21,608,070`. The question is whether a permissionless adversary can achieve positive net portfolio change, after liabilities and fees, using the observed transaction sequence.

## Vulnerability & Root Cause Analysis

### Evidence from the seed transaction

The seed transaction metadata from the explorer confirms basic parameters: the EOA sender, router callee, gas configuration, and zero ETH value transfer.

```json
{
  "chainid": 1,
  "txhash": "0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba",
  "from": "0x55f5f8058816d5376df310770ca3a2e294089c33",
  "to": "0x3f814e5fae74cd73a70a0ea38d85971dfa6fda21",
  "value": "0"
}
```

*Caption: Seed transaction metadata confirming the adversary EOA, router, and zero native ETH transfer (from seed metadata JSON).*

The detailed trace for the seed transaction shows the router obtaining a 60,000,000,000,000 USDC flashloan from the Morpho vault’s flashloan provider and then interacting with Unilend to open the stETH borrow position.

```text
0x3F814e5FaE74cd73A70a0ea38d85971dFA6fdA21::66f28d10(...)
  ...
  0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb::flashLoan(..., 60000000000000, ...)
    emit FlashLoan(..., 60000000000000)
    ...
    UnilendV2Pool::token1Data() [staticcall]
    ...
```

*Caption: Seed transaction trace excerpt showing the router’s USDC flashloan and calls into UnilendV2Pool and related contracts (from cast trace log).*

ERC20 balance snapshots across the seed transaction demonstrate the stETH movement from the pool to the adversary-related cluster:

```json
{
  "token": "0xae7ab96520de3a18e5e111b5eaab095312d7fe84",
  "snapshots": {
    "0x55f5...9c33": { "pre": "0", "post": "60672854887643676586", "delta": "60672854887643676586" },
    "0x3f814e5fae74cd73a70a0ea38d85971dfa6fda21": { "pre": "0", "post": "1", "delta": "1" },
    "0x4e34dd25dbd367b1bf82e1b5527dbbe799fad0d0": {
      "pre": "60672854905837671913",
      "post": "18193995324",
      "delta": "-60672854887643676589"
    }
  }
}
```

*Caption: ERC20 balance snapshots showing the stETH leaving the Unilend pool and landing on the EOA and router, with a 2 wei rounding difference (from ERC20 balance snapshots JSON).*

The UnilendV2Pool state diff for token1Data and positionData[115] shows that this stETH outflow is recorded as increased token1 borrow at both the pool and position levels:

```json
{
  "token1Data": {
    "totalBorrowShare": {
      "before_raw": "0x...0df4b15a01b65ac6",
      "after_raw": "0x...351f1941309684f7c"
    },
    "totalBorrow": {
      "before_raw": "0x...0e0e683ff2938cde",
      "after_raw": "0x...3580fb07a1dddeac4"
    }
  },
  "positionData[115]": {
    "token1borrowShare": {
      "before_raw": null,
      "after_raw": "0x00000000000000000000000000000000000000000000000343fce2b907b1f4b6"
    }
  }
}
```

*Caption: UnilendV2Pool storage diff showing total token1 borrow and position 115’s token1 borrow share increasing consistently with the stETH outflow (from pool state diff JSON).*

UnilendV2Core router view calls around the seed transaction show health-factor changes consistent with a new, highly leveraged token1 borrow. Before the transaction, the router has zero token1 borrow and no health-factor contribution; afterward, the router’s token1 borrow is roughly `60672854887643676588` stETH with a token1 health factor significantly below the 1e18 threshold, marking the position as over-leveraged but correctly accounted for.

### No protocol bug or accounting inconsistency

The vulnerability analysis in the JSON concludes that there is no lending, accounting, pricing, reentrancy, or access-control bug:

- Traces and storage diffs tie the stETH that leaves the pool directly to the router’s position 115 token1 borrow.
- The ERC20 snapshots match the pool’s stETH balance decrease with the EOA and router’s stETH increases, up to a negligible rounding difference.
- Health-factor views from UnilendV2Core show the router’s position acquiring token1 debt and a sub-threshold health factor exactly when the pool’s token1 borrow and the EOA/router stETH balances change.
- Native balance deltas show the EOA paying ETH gas to the block producer.

The combination of these artefacts demonstrates that Unilend’s core and pool record the router’s large stETH balance as an over-leveraged liability, not free profit. There is no inconsistency between UnilendV2Core, UnilendV2Pool, and ERC20 balances, and no evidence of any state where the adversary holds transferable value without a corresponding liability.

### ACT exploit conditions not met

The exploit predicate is a profit condition in ETH terms. For an ACT-qualifying exploit, an unprivileged adversary would need to obtain transferable value (such as stETH) from Unilend or related contracts without a matching liability, or with a liability that can later be removed while retaining the value.

The report’s “exploit_conditions” field states that no such condition is satisfied and explains why:

- The stETH obtained in the seed transaction is fully offset by a recorded token1 liability and associated health factor on Unilend.
- There is no transaction in the analysed sequence that eliminates or reduces the liability while letting the adversary-related cluster keep the stETH.
- The USDC flashloan fee is paid from the Morpho vault to the flashloan provider, and the EOA pays gas, so costs are non-zero.

Given the evidence, the root cause is that there is **no protocol exploit**: the system behaves in line with its lending and accounting design, and the observed behaviour is a highly leveraged position rather than an exploit.

## Adversary Flow Analysis

### Adversary strategy summary

The “Adversary Flow Analysis” section describes a concise lifecycle:

- The EOA `0x55f5…9c33` deploys and funds the router `0x3f81…da21`.
- The EOA calls the router with a crafted calldata payload that triggers a USDC flashloan, interacts with Lido/wstETH, and opens Unilend position 115 in the stETH pool.
- The transaction ends with stETH distributed between the EOA and router and a large token1 liability recorded for position 115.
- A follow-up stETH `approve` aligns allowance but leaves the Unilend debt unchanged.
- Within the EOA and router txlist windows, there is no transaction that repays, closes, or meaningfully reduces the Unilend liability while allowing the adversary-related cluster to retain the stETH.

### Identified adversary-related accounts

The report explicitly identifies and justifies the adversary-related cluster:

- **EOA 0x55f5…9c33**: Sender of the adversary-crafted seed transaction and the follow-up stETH `approve`, source of deployment and funding for the router, and recipient of most of the stETH in the seed transaction.
- **Router 0x3f81…da21**: Router contract deployed and exclusively used by the adversary EOA in the analysed window; it executes the sequence of Unilend and Lido calls that open position 115 and borrow stETH.

It also lists potential protocol-side victim candidates (UnilendV2Core, UnilendV2Pool, Lido stETH, wstETH, USDC flashloan provider) but concludes that none suffers protocol fund loss or negative net balance change attributable to an exploit.

### Lifecycle stages

The adversary lifecycle is broken into three stages:

1. **Seed transaction: flashloan-funded Unilend stETH borrow**
   - The router obtains the USDC flashloan, uses UnilendV2Core and UnilendV2Pool to open position 115, lends a small amount of token0, and borrows around `60672854887643676589` stETH from the pool to the EOA and router.
   - The Unilend pool’s token1Data and positionData[115] slots and UnilendV2Core view calls record the new borrow and low health factor.
2. **Follow-up approval**
   - Transaction `0xf60d…6d90` in block 21,608,096 sets the stETH allowance for spender `0xcf5540fffcdc3d510b18bfca6d2b9987b0772559` to `60672854887643676586`, aligning allowance with the stETH obtained.
   - This approval does not move stETH or change the Unilend token1 liability; it only updates allowance.
3. **Post-window behaviour**
   - Within the reviewed txlist windows for the EOA (`[21607950, 21608100]`) and router (`[21608043, 21612000]`), there is no transaction that repays or unwinds the Unilend token1 debt while allowing the adversary-related cluster to retain the stETH.
   - There is no further transaction that increases the adversary-related cluster’s net portfolio value.

The lifecycle analysis supports the conclusion that the position remains over-leveraged and open, with the stETH balance tied to a corresponding liability, not free profit.

## Impact & Loss Analysis

The impact and loss analysis concludes:

- **Adversary profit**: The adversary-related cluster does not achieve net profit in ETH terms. The stETH obtained is matched by Unilend token1 debt, the USDC flashloan fee is paid out of the Morpho vault to the flashloan provider, and the EOA pays ETH gas to the block producer `0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97`.
- **Protocol and user losses**: There is no protocol fund loss and no address with a negative net balance change attributable to an exploit. The act of opening an over-leveraged position does not cause a loss for Unilend or Lido; it simply creates risk borne by the position owner and subject to Unilend’s liquidation rules.
- **ACT opportunity**: The cross-token overview records zero net ACT-qualifying gains in stETH and USDC. Given the recorded liability and the absence of a subsequent “freeing” transaction, there is no ACT-qualifying profit opportunity.

In short, the on-chain sequence represents a risky leveraged position, not an exploit or profitable attack.

## References

The report’s conclusions are grounded in the following key artefacts (all collected under the incident’s root_cause artifacts directory):

1. **Seed transaction metadata and trace**  
   - Seed transaction metadata and detailed cast trace for `0x4403…b6ba` (block 21,608,070), showing the router’s flashloan and Unilend interactions.
2. **ERC20 balance snapshots for seed transaction**  
   - Pre/post stETH, wstETH, and USDC balances for the EOA, router, flashloan provider, Unilend core, and pool, confirming stETH and USDC movements.
3. **UnilendV2Pool token1Data and positionData[115] storage diff**  
   - Storage diff for the stETH pool at `0x4e34…d0d0`, showing consistent increases in total token1 borrow and position 115’s token1 borrow share.
4. **UnilendV2Core router health-factor views**  
   - Health-factor and balanceOfUserTokens view calls at blocks 21,608,069 (pre) and 21,608,070 (post), demonstrating the router’s new token1 debt and sub-threshold health factor.
5. **EOA txlist window [21607950, 21608100]**  
   - EOA transaction history covering the failed and successful router calls and the follow-up stETH approval, confirming the absence of any profitable unwind.
6. **Router txlist window [21608043, 21612000]**  
   - Router transaction history showing deployment and use solely by the adversary EOA.
7. **Native balance deltas for seed transaction**  
   - ETH balance changes for the EOA and block producer, confirming that the EOA pays gas and does not receive ETH subsidy.

## Challenger Conclusion

After independently reviewing the victim transaction, Unilend contract state, traces, and balance data, and verifying that the current `root_cause.json` contains no prohibited speculative or undetermined language, the challenger accepts the analyzer’s conclusion:

- The incident does **not** constitute an ACT-qualifying exploit.
- The adversary-related cluster opens an over-leveraged Unilend stETH borrow position with corresponding on-chain liability and non-zero fees.
- There is no net profit and no protocol or user loss attributable to an exploit.

The challenge result is **Pass**, and this report serves as the final human-readable root cause summary.

