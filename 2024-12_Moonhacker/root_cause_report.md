## Moonwell Optimism – MoonHacker Reward Claim Is Not an ACT Exploit

### Incident Overview & TL;DR

On Optimism, an address cluster centered on EOAs `0xba38bf7d3bc6785c52cf17e2691b852a6260d93a` and `0x36491840ebcf040413003df9fb65b6bc9a181f52` used a flash-loan-primed Moonwell USDC position and a helper contract to trigger reward index updates, claim a large amount of OP and xWELL for the `MoonHacker` contract at `0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847`, and partially unwind the position in seed transaction `0xd12016b2...` on Optimism (chain ID 10).

The large reward payment follows Moonwell’s configured reward speeds and index-based accrual logic in `MultiRewardDistributor` and does not involve any access-control, accounting, or invariant violation. The incident is a design-consistent incentive payout and not an ACT-style exploit.

### Key Background

Moonwell on Optimism implements Compound-style lending markets, including the USDC market `MErc20Delegator` at `0x8E08617b0d66359D73Aa11E11017834C29155525`, which exposes standard supply and borrow operations through a proxy that delegates to a market implementation.

Rewards on Moonwell are managed by `MultiRewardDistributor` (implementation `0xff0731337f615ac5403cb243623283bc04cde121` behind proxy `0xf9524bfa18c19c3e605fbfe8dfd05c6e967574aa`). This contract maintains global supply and borrow indices per reward token and market, as well as per-user indices, to compute accrued OP and xWELL rewards from configured emission speeds.

The `MultiRewardDistributor` implementation uses Compound-style index math in `calculateBorrowRewardsForUser` and related functions, scaling values with `1e18` and `1e36` constants and reading market configuration and user positions from the Moonwell Comptroller and markets. This logic underpins the reward amounts observed in the incident.

The `MoonHacker` contract at `0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847` is deployed by EOA `0xba38bf7d3bc6785c52cf17e2691b852a6260d93a`. It automates a flash-loan-primed supply and borrow strategy on the Moonwell USDC market and exposes helper functions such as `smartSupply` to open and manage a large borrow position.

A separate helper contract at `0x4E258F1705822c2565D54ec8795d303fDf9F768e`, deployed by EOA `0x36491840ebcf040413003df9fb65b6bc9a181f52` in the seed transaction, centralizes calls that read USDC balances, update market reward indices across multiple markets, trigger `disburseSupplierRewards` and `disburseBorrowerRewards` for `MoonHacker`, and orchestrate partial unwind steps.

#### Example: Reward Distributor Core Logic

The collected `MultiRewardDistributor` implementation shows standard index-based reward accounting and tight access control around configuration changes:

```solidity
// Collected MultiRewardDistributor implementation (core structure)
contract MultiRewardDistributor is
    Pausable,
    ReentrancyGuard,
    Initializable,
    MultiRewardDistributorCommon,
    ExponentialNoError
{
    using SafeERC20 for IERC20;

    mapping(address => MarketEmissionConfig[]) public marketConfigs;
    Comptroller public comptroller;
    address public pauseGuardian;
    uint224 public constant initialIndexConstant = 1e36;
    uint256 public emissionCap;
}
```

*Caption: Excerpt from the collected `MultiRewardDistributor` implementation, showing a standard, access-controlled reward distributor bound to the Moonwell Comptroller, with index-based reward configuration.*

### Vulnerability & Root Cause Analysis

The reviewed contracts and traces do not reveal a protocol vulnerability. Instead, the reward logic distributes OP and xWELL to `MoonHacker` exactly as defined by `MultiRewardDistributor`’s index-based calculations, applied to a large and long-lived USDC borrow position on Moonwell.

In `MultiRewardDistributor.sol`, `calculateBorrowRewardsForUser` reads the user’s `borrowBalanceStored` and the market’s `borrowIndex`, normalizes the borrow amount as:

```solidity
// Conceptual calculation path from collected source
normalizedBorrow = borrowBalanceStored * 1e18 / borrowIndex;
accrued = normalizedBorrow * (globalBorrowIndexDelta) / doubleScale; // doubleScale = 1e36
```

*Caption: Conceptual reward calculation logic derived from `calculateBorrowRewardsForUser`, using normalized borrows and index deltas to compute accrued rewards.*

During the priming transaction `0xc20f8c...` on Optimism, traces show that `MoonHacker` uses an Aave L2 `flashLoan` to borrow USDC, supplies USDC into the Moonwell USDC market, mints mTokens, and borrows USDC to repay the flash loan. The resulting state includes:

- A large USDC borrow for `MoonHacker` on the Moonwell USDC market.
- Increased market cash at the USDC market contract, consistent with the supplied USDC.

The balance diff for the priming transaction records a net increase in USDC at the market consistent with this behavior, establishing the base for substantial reward accrual under the configured reward speeds.

Between the priming block and the seed block `129697251`, traces and address histories show that the borrow position remains open, so rewards accrue in `MultiRewardDistributor` according to the configured emission speeds and elapsed time.

In the seed transaction `0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe`, helper contract `0x4E258F...` (deployed and called by `0x3649...`) invokes the Moonwell Comptroller, which calls `MultiRewardDistributor` to:

- Update market supply and borrow indices across several markets.
- Disburse accumulated OP and xWELL rewards to `MoonHacker` on the USDC market, and adjust balances via ERC20 transfers.

The seed trace includes multiple `DisbursedSupplierRewards` and `DisbursedBorrowerRewards` events targeting `MoonHacker`:

```text
// Seed transaction trace (cast run -vvvv) for tx 0xd12016b2...
emit DisbursedBorrowerRewards(mToken: MErc20Delegator: [0x8E08617b0d66359D73Aa11E11017834C29155525],
                              borrower: MoonHacker: [0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847],
                              emissionToken: 0x4200000000000000000000000000000000000042,
                              totalAccrued: 26959125608760496573 [2.695e19])
emit DisbursedBorrowerRewards(mToken: MErc20Delegator: [0x8E08617b0d66359D73Aa11E11017834C29155525],
                              borrower: MoonHacker: [0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847],
                              emissionToken: 0xA88594D404727625A9437C3f886C7643872296AE,
                              totalAccrued: 1537857362904502739239 [1.537e21])
emit DisbursedSupplierRewards(mToken: MErc20Delegator: [0x8E08617b0d66359D73Aa11E11017834C29155525],
                              supplier: MoonHacker: [0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847],
                              emissionToken: 0x4200000000000000000000000000000000000042,
                              totalAccrued: 30095264625691763690 [3.009e19])
```

*Caption: Seed transaction trace excerpt for tx `0xd12016b2...`, showing OP/xWELL borrower and supplier reward disbursements to `MoonHacker` from the USDC market.*

The corresponding balance diff for the seed transaction confirms the net reduction of OP and xWELL at the reward distributor proxy and matching increases at `MoonHacker`:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x4200000000000000000000000000000000000042",
      "holder": "0xf9524bfa18c19c3e605fbfe8dfd05c6e967574aa",
      "before": "27325636526022524887527",
      "after": "27134352316242065610453",
      "delta": "-191284209780459277074",
      "contract_name": "GovernanceToken"
    },
    {
      "token": "0xa88594d404727625a9437c3f886c7643872296ae",
      "holder": "0xf9524bfa18c19c3e605fbfe8dfd05c6e967574aa",
      "before": "2018119853462208478006309",
      "after": "2007219327419416814100756",
      "delta": "-10900526042791663905553",
      "contract_name": "xWELL"
    }
  ]
}
```

*Caption: Seed transaction state diff for tx `0xd12016b2...`, showing OP and xWELL leaving the `MultiRewardDistributor` proxy; the matching positive deltas at `MoonHacker` confirm the reward payout destination.*

Plugging the recorded `borrowBalanceStored`, `borrowIndex`, global indices, and emission configuration into `calculateBorrowRewardsForUser` reproduces the OP borrower reward value within rounding. The exercised code paths do not rely on reentrancy, unrestricted `delegatecall`, unchecked external calls, or unsafe arithmetic; reward disbursement is gated by the Comptroller and the configured reward speeds and indices.

As a result, the large OP and xWELL transfer is fully explained by intended reward accounting applied to a large and long-standing borrow position. There is no protocol bug or access-control failure; the root cause is design-consistent reward configuration and the adversary’s choice to concentrate rewards on a single position.

#### Components Involved

- `MultiRewardDistributor` implementation `0xff0731337f615ac5403cb243623283bc04cde121`, behind proxy `0xf9524bfa18c19c3e605fbfe8dfd05c6e967574aa`, which manages reward indices and disbursement.
- Moonwell USDC market `MErc20Delegator` at `0x8E08617b0d66359D73Aa11E11017834C29155525` and its underlying market implementation, which track USDC supply and borrow balances.
- USDC `FiatTokenProxy` at `0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85`, the underlying token for the Moonwell USDC market.

#### Exploit Conditions

There is no exploit-specific condition beyond the presence of a sufficiently large and long-lived USDC borrow position on Moonwell. To reproduce the observed reward payout:

- An address opens a large USDC borrow via the Moonwell USDC market.
- The position remains active across blocks while rewards accrue at the configured speeds.
- The address (or a coordinating helper contract) eventually invokes the standard reward-claim flow via the Comptroller and `MultiRewardDistributor`, triggering index updates and reward disbursements.

#### Security Principles

The traces and source-code review show no violation of access control, invariant preservation, or arithmetic safety in the exercised paths. Economic design and parameterization allow concentrated incentive payouts to a single position, but this behavior matches the configured reward scheme rather than a security failure.

### Adversary Flow Analysis

#### Strategy Summary

The adversary uses a single-chain, multi-transaction strategy on Optimism:

1. Deploy `MoonHacker` to act as the borrower-facing contract.
2. Use a flash loan to prime a large USDC position on the Moonwell USDC market via `MoonHacker::smartSupply`.
3. Maintain the borrow position during the reward accrual window.
4. Deploy and call a helper contract that batches reward index updates and reward disbursement calls, then partially unwinds the position.

#### Adversary-Related Accounts

- `0xba38bf7d3bc6785c52cf17e2691b852a6260d93a` (EOA, Optimism):
  - Sender of the `MoonHacker` deployment transaction `0xacc02ff...`.
  - Sender of the priming `smartSupply` transaction `0xc20f8c...`.
  - Repeated caller of `MoonHacker` and Moonwell borrower functions in the period between priming and the seed transaction, as indicated by gathered address-history traces.

- `0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847` (`MoonHacker` contract, Optimism):
  - Deployed by `0xba38...` in tx `0xacc02ff...`.
  - Acts as borrower in the Moonwell USDC market.
  - Immediate recipient of OP and xWELL rewards in the seed transaction `0xd12016...`, as shown by reward events and ERC20 `Transfer` logs.

- `0x36491840ebcf040413003df9fb65b6bc9a181f52` (EOA, Optimism):
  - Sender of the seed helper contract deployment and execution transaction `0xd12016...`, as recorded in the seed transaction metadata.
  - Address history shows coordination with `0xba38...`, including a zero-value message transaction containing a direct communication string.

- `0x4E258F1705822c2565D54ec8795d303fDf9F768e` (helper contract, Optimism):
  - Deployed by `0x3649...` in the seed transaction.
  - Orchestrates calls to the Moonwell Comptroller, `MultiRewardDistributor`, the USDC market, and USDC in order to update indices, disburse rewards, and partially unwind the position.

Candidate victim contracts (though no exploit is present) include:

- Moonwell `MultiRewardDistributor` proxy at `0xf9524bfa18c19c3e605fbfe8dfd05c6e967574aa`.
- Moonwell USDC market `MErc20Delegator` at `0x8E08617b0d66359D73Aa11E11017834C29155525`.
- USDC `FiatTokenProxy` at `0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85`.

#### Lifecycle Stages

1. **Adversary initialization and MoonHacker deployment**

   - Transaction: `0xacc02fff0540e69ed8cfa98575ccf16369ba71b6480dd5b902d14b648be5e54b` (Optimism, chain ID 10).
   - EOA `0xba38...` deploys `MoonHacker` at `0xD9B4...`, establishing the contract that will hold the Moonwell position and receive rewards.

   ```text
   // Deployment trace (cast run -vvvv) for tx 0xacc02ff...
   0xba38bf7d3bc6785c52cf17e2691b852a6260d93a -> MoonHacker (create)
   MoonHacker deployed at 0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847
   ```

   *Caption: Seeded deployment trace confirming that EOA `0xba38...` deploys `MoonHacker` on Optimism.*

2. **Flash-loan-primed Moonwell USDC position**

   - Transaction: `0xc20f8cd2285da230796286bc52318433945895dc8ef0750193ccd640b5d327da` (Optimism, chain ID 10).
   - EOA `0xba38...` calls `MoonHacker::smartSupply`, which:
     - Uses an Aave L2 `flashLoan` to borrow USDC.
     - Supplies USDC to the Moonwell USDC market contract.
     - Mints mTokens representing the supplied USDC.
     - Borrows USDC from Moonwell to repay the flash loan.
   - The resulting state reflects a large net USDC borrow by `MoonHacker` and increased USDC in the market.

   ```text
   // Priming transaction trace (cast run -vvvv) for tx 0xc20f8c...7da
   MoonHacker::smartSupply(FiatTokenProxy: [0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85],
                           MErc20Delegator: [0x8E08617b0d66359D73Aa11E11017834C29155525],
                           484594000000, 110000000000)
     ├─ L2PoolInstance::flashLoanSimple(MoonHacker, USDC, 484594000000, ...)
     ├─ FiatTokenV2_2::transfer(... -> MoonHacker, 484594000000)
     ├─ MErc20Delegator::mint(594594000000)
     ├─ AccrueInterest(...)
     └─ Further Comptroller and market calls to open the borrow position
   ```

   *Caption: Priming transaction trace showing `MoonHacker::smartSupply` using an Aave flash loan to supply and borrow USDC in the Moonwell USDC market.*

3. **Reward index updates, reward claim, and partial unwind**

   - Transaction: `0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe` (Optimism, block `129697251`).
   - EOA `0x3649...` deploys helper contract `0x4E258F...` and invokes it in the same transaction.
   - The helper contract:
     - Invokes the Moonwell Comptroller, which calls `MultiRewardDistributor` to update supply and borrow indices across multiple markets.
     - Triggers `disburseSupplierRewards` and `disburseBorrowerRewards` for `MoonHacker` in the USDC market and others.
     - Calls `MErc20Delegator::redeem` and related USDC transfer functions to partially unwind the position.
   - OP and xWELL balances move from the reward proxy `0xf9524bfa18c19c3e605fbfe8dfd05c6e967574aa` to `MoonHacker`, and the Moonwell USDC market’s balances change in line with a partial redemption.

The combination of traces and state diffs shows that the adversary’s flow is a sophisticated but standard use of existing reward and lending mechanisms, not an exploit of a vulnerability.

### Impact & Losses

The seed transaction’s balance diff and logs show that the `MultiRewardDistributor` proxy at `0xf9524bfa18c19c3e605fbfe8dfd05c6e967574aa` transfers:

- `191.284209780459277074` OP (contract `0x4200000000000000000000000000000000000042`).
- `10900.526042791666390553` xWELL (contract `0xa88594d404727625a9437c3f886c7643872296ae`).

These tokens move from the reward proxy to `MoonHacker` at `0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847`, as confirmed by the ERC20 `Transfer` events and the state diff.

The inspected traces do not show any insolvency event, reentrancy, or invariant-breaking state change. The impact is a large but configuration-consistent incentive payout driven by:

- The configured reward speeds in `MultiRewardDistributor`.
- The size and duration of `MoonHacker`’s USDC borrow position.
- The helper contract’s timing and batching of reward-claim calls.

No protocol funds are lost beyond the intended operation of the reward program.

### References

Key supporting artifacts and evidence:

- **[1] Seed transaction trace and balance diff (tx `0xd12016b2...`)**  
  - Seed transaction on Optimism that deploys and executes the helper contract, triggers reward index updates and reward disbursements, and partially unwinds the position.

- **[2] Priming transaction trace and balance diff (tx `0xc20f8c...7da`)**  
  - Priming transaction where `MoonHacker::smartSupply` uses an Aave flash loan to establish a large USDC borrow position on the Moonwell USDC market.

- **[3] MoonHacker deployment trace (tx `0xacc02ff...54b`)**  
  - Deployment of the `MoonHacker` contract by EOA `0xba38...`, which later acts as the borrower and reward recipient.

- **[4] MultiRewardDistributor implementation source**  
  - Verified implementation of the reward distributor contract at `0xff0731337f615ac5403cb243623283bc04cde121`, used to reproduce and validate the reward accounting logic.

- **[5] Moonwell USDC market source**  
  - Verified source code for the `MErc20Delegator` USDC market at `0x8E08617b0d66359D73Aa11E11017834C29155525`, including interest accrual and accounting paths.

- **[6] USDC FiatTokenProxy source**  
  - Verified USDC proxy implementation at `0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85`, showing standard ERC20 behavior underpinning the lending and reward flows.

- **[7] Address history for `0xba38bf7d3bc6785c52cf17e2691b852a6260d93a`**  
  - Transaction history confirming this EOA as the deployer of `MoonHacker` and participant in the priming and subsequent borrower interactions.

- **[8] Address history for `0x36491840ebcf040413003df9fb65b6bc9a181f52`**  
  - Transaction history linking this EOA to the helper contract deployment and execution in the seed transaction, and showing coordination with `0xba38...`.

