## Incident Overview TL;DR

On Optimism (chainid 10), a fresh EOA `0x36491840ebcf040413003df9fb65b6bc9a181f52` deploys a helper/router contract at `0x4E258F1705822c2565D54ec8795d303fDf9F768e` and, in the same transaction, orchestrates Aave v3 USDC flash loans into three user-owned MoonHacker helper contracts. These MoonHacker contracts hold leveraged positions in the Moonwell mUSDC market `0x8E08617b0d66359D73Aa11E11017834C29155525` and have accrued GovernanceToken and xWELL rewards via the MultiRewardDistributor proxy `0xF9524bfa18C19C3E605FbfE8DFd05C6e967574Aa`. The helper/router uses the flash-loaned USDC to drive each MoonHacker through its `executeOperation` callback, repay its borrows, redeem mUSDC, and claim rewards. After repaying Aave’s flash loan plus premium, the helper forwards a net `318987.572368` USDC to the adversary EOA.

The root cause is that the MoonHacker helper contracts implement Aave’s flash-loan receiver interface with an `executeOperation` callback that performs repay/redeem/claimReward for the position without restricting who can trigger this sequence. Any unprivileged router that can obtain an Aave flash loan can cause these user-owned MoonHacker contracts to unwind their positions and redirect a portion of the resulting USDC to an arbitrary EOA.

## Key Background

The incident involves several on-chain components:

- **Moonwell mUSDC market**: The mUSDC token at `0x8E08617b0d66359D73Aa11E11017834C29155525` is implemented by the `MErc20Delegate` contract (layout address `0xa9ce0a4de55791c5792b50531b18befc30b09dcc`) and represents an interest-bearing market over USDC on Optimism.
- **USDC token**: USDC is represented by `FiatTokenProxy` at `0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85`, with verified implementation `FiatTokenV2_2` at layout address `0xded3b9a8dbedc2f9cb725b55d0e686a81e6d06dc`.
- **Reward tokens and distributor**:
  - GovernanceToken: `0x4200000000000000000000000000000000000042`
  - xWELL: `0xA88594D404727625A9437C3f886C7643872296AE`
  - Rewards are paid from the MultiRewardDistributor proxy `0xF9524bfa18C19C3E605FbfE8DFd05C6e967574Aa`, whose implementation is the `MultiRewardDistributor` contract at `0xff0731337f615ac5403cb243623283bc04cde121` (source in `artifacts/root_cause/data_collector/iter_2/contract/10/0xff0731337f615ac5403cb243623283bc04cde121/source/src/rewards/MultiRewardDistributor.sol`).
- **MoonHacker helper contracts**: Three separate MoonHacker contracts on Optimism hold leveraged mUSDC positions and accrue rewards:
  - `0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847`
  - `0x24592ed1ccf9e5ae235e24a932b378891313fb75`
  - `0x80472c6848015146fdc3d15cdf6dc11ca3cb3513`

The source code for MoonHacker (for example, at `artifacts/root_cause/data_collector/iter_1/contract/10/0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847/source/src/MoonHacker.sol`) shows a helper that wraps Moonwell’s mUSDC market and Aave’s flash-loan interface, enabling “smart” supply and redeem flows.

The seed transaction under analysis is:

- Chain: Optimism (`chainid = 10`)
- Tx hash: `0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe`
- Block: `129697251`

Transaction metadata and traces are captured in:

```json
// Seed transaction metadata (Etherscan-style)
// artifacts/root_cause/seed/10/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe/metadata.json
{
  "chainid": 10,
  "txhash": "0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe",
  "etherscan": {
    "tx": {
      "result": {
        "from": "0x36491840ebcf040413003df9fb65b6bc9a181f52",
        "to": null,
        "blockNumber": "0x7bb05e3",
        "hash": "0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe"
      }
    }
  }
}
```

This transaction both deploys the helper/router contract and executes the flash-loan-driven unwind and reward extraction.

## Vulnerability Analysis

### MoonHacker’s flash-loan receiver design

The core vulnerability resides in the MoonHacker helper contracts. They implement Aave’s flash-loan receiver callback `executeOperation` and, when called with specific parameters, automatically:

- Repay the Moonwell mUSDC borrow,
- Redeem mUSDC into underlying USDC, and
- Call `Comptroller.claimReward(address(this))` to pull accumulated GovernanceToken and xWELL rewards to the MoonHacker contract.

Critically, the `executeOperation` function itself has no access control: it does not check that the caller is a specific trusted Aave pool or that the flash loan was initiated by the MoonHacker owner. As long as an external router can cause Aave v3 to call the MoonHacker contract as a `IFlashLoanSimpleReceiver`, the MoonHacker will happily unwind its position and claim rewards.

The relevant fragment of MoonHacker.sol is:

```solidity
// artifacts/root_cause/data_collector/iter_1/contract/10/0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847/source/src/MoonHacker.sol
function  executeOperation(
    address token,
    uint256 amountBorrowed,
    uint256 premium,
    address initiator,
    bytes calldata params
)  external returns (bool) {
    
    (SmartOperation operation, address mToken, uint256 amountToSupplyOrReedem) =
        abi.decode(params, (SmartOperation, address, uint256));
    uint256 totalAmountToRepay = amountBorrowed + premium;

    if (operation == SmartOperation.SUPPLY) {
        uint256 totalSupplyAmount = amountBorrowed + amountToSupplyOrReedem;
        IERC20(token).approve(mToken, totalSupplyAmount);
        require(IMToken(mToken).mint(totalSupplyAmount) == 0, "mint failed");
        require(IMToken(mToken).borrow(totalAmountToRepay) == 0, "borrow failed");
        IERC20(token).approve(address(POOL), totalAmountToRepay);

    } else if (operation == SmartOperation.REDEEM) {
        IERC20(token).approve(mToken, amountBorrowed);
        require(IMToken(mToken).repayBorrow(amountBorrowed) == 0, "repay borrow failed");
        require(IMToken(mToken).redeem(amountToSupplyOrReedem) == 0, "redeem failed");
        COMPTROLLER.claimReward(address(this));

    } else {
        revert("invalid op");
    }

    if (strcmp(IERC20Detailed(token).symbol(), "WETH")) {
        IWETH(token).deposit{value: totalAmountToRepay}();
    }

    IERC20(token).approve(address(POOL), totalAmountToRepay);
    return true;
}
```

All explicit user-facing entrypoints such as `smartSupply`, `smartRedeem`, and other management functions are protected by the `onlyOwner` modifier. However, `executeOperation`—the function that actually repays the borrow, redeems mUSDC, and claims rewards—is not restricted. Aave’s design assumes that only the borrower or a trusted party will arrange flash loans into a receiver; MoonHacker instead exposes the receiver to arbitrary flash-loan initiators.

### Victim ownership and separation from adversary

Storage and transaction history evidence shows that the MoonHacker contracts are owned by EOAs distinct from the adversary EOA:

- `0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847` is owned by `0xba38bf7d3bc6785c52cf17e2691b852a6260d93a` (decoded from storage slot 0).
- `0x80472c6848015146fdc3d15cdf6dc11ca3cb3513` is owned by `0x092f3356d8827eb95459d661c1113f9e7dcfbf19`.
- `0x24592ed1ccf9e5ae235e24a932b378891313fb75` is owned by `0x0a1e309abddb3aabf7eb7b74c5a2aa5c2b09d996`.

Their `txlist_normal.json` histories show normal “user helper” usage: deployment transactions and subsequent `smartSupply`-style calls from those EOAs. In contrast, the seed EOA `0x36491840ebcf040413003df9fb65b6bc9a181f52` has only the incident transaction in the observed window, and does not appear as the owner of any MoonHacker contract.

This separation establishes that:

- The MoonHacker contracts are victim-owned helper contracts.
- The adversary EOA is a distinct unprivileged account exploiting the open `executeOperation` surface, not the original owner of the leveraged positions.

### Reward distribution is correct but exploitable

The MultiRewardDistributor logic is standard and behaves as expected: it tracks market emission configs and pays out GovernanceToken and xWELL rewards to holders and borrowers of mTokens. The key design is that rewards flow to the address that holds the mTokens and accrues them—not directly to the underlying user.

The exploit does not depend on incorrect reward math; instead, it leverages the fact that the MoonHacker contracts, as mUSDC holders, are the rightful recipients of rewards. When the adversary routes flash loans through these contracts and forces them to claim their rewards, those rewards are legitimately transferred to the MoonHacker contract addresses, after which the helper/router aggregates the resulting USDC-equivalent value and redirects part of it to the adversary EOA.

## Detailed Root Cause Analysis

### Pre-state: leveraged MoonHacker positions and reward accrual

Immediately before block `129697251` on Optimism, the chain state includes:

- Three MoonHacker contracts with active leveraged mUSDC positions in the Moonwell mUSDC market `0x8E08617b0d66359d73aa11e11017834c29155525`.
- Accrued GovernanceToken and xWELL rewards associated with these positions via the MultiRewardDistributor.
- Aave v3 pool at `0x38d693ce1df5aadf7bc62595a37d667ad57922e5` with sufficient USDC liquidity to issue flash loans in token `0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85`.

This pre-state is summarized in `artifacts/root_cause/seed/index.json` and `metadata.json`, and quantified in the balance diff file described below.

### Seed transaction mechanics

The seed transaction `0xd12016b25d7a...54c4fe` from `0x36491840ebcf040413003df9fb65b6bc9a181f52` is a type-2 contract-creation tx with zero ETH value. It deploys the helper/router contract at `0x4E258F1705822c2565D54ec8795d303fDf9F768e` and immediately executes its entrypoint.

The trace (`trace.cast.log`) shows the following high-level flow:

```text
// Seed transaction trace (excerpt)
// artifacts/root_cause/seed/10/0xd12016b2...54c4fe/trace.cast.log
[12297637] → new <unknown>@0x4E258F1705822c2565D54ec8795d303fDf9F768e(...)
  ├─ AaveV3Pool::flashLoanSimple(MoonHacker: 0xD9B45e2c..., USDC, amount, params)
  │   ├─ 0xD9B45e2c...::executeOperation(USDC, amountBorrowed, premium, initiator, params)
  │   │   ├─ MErc20Delegator::repayBorrow(...)
  │   │   ├─ MErc20Delegator::redeem(...)
  │   │   ├─ Comptroller::claimReward(address(this))
  │   │   └─ FiatTokenProxy::transfer(...)
  ├─ AaveV3Pool::flashLoanSimple(MoonHacker: 0x24592ed1...)
  │   └─ 0x24592ed1...::executeOperation(...)
  ├─ AaveV3Pool::flashLoanSimple(MoonHacker: 0x80472c68...)
  │   └─ 0x80472c68...::executeOperation(...)
  └─ FiatTokenProxy::transfer(USDC, to: 0x36491840ebcf040413003df9fb65b6bc9a181f52, 318987572368)
```

This confirms that:

- The helper/router is the orchestrator calling `flashLoanSimple` on Aave.
- Each MoonHacker contract acts as a flash-loan receiver via `executeOperation`.
- Inside each `executeOperation`, the MoonHacker repays its borrow, redeems mUSDC, claims rewards, and arranges for USDC to be returned to Aave.
- After repayment plus premium, the remaining USDC is transferred to the adversary EOA.

### Balance diffs and profit computation

The ERC20 balance diffs for the seed transaction are captured in `artifacts/root_cause/seed/10/0xd12016b2...54c4fe/balance_diff.json`. For USDC (`0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85`), the relevant entries are:

```json
// artifacts/root_cause/seed/10/0xd12016b2...54c4fe/balance_diff.json (excerpt)
{
  "erc20_balance_deltas": [
    {
      "token": "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
      "holder": "0x38d693ce1df5aadf7bc62595a37d667ad57922e5",
      "delta": "441958984"
    },
    {
      "token": "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
      "holder": "0x8e08617b0d66359d73aa11e11017834c29155525",
      "delta": "-319429531352"
    },
    {
      "token": "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
      "holder": "0x36491840ebcf040413003df9fb65b6bc9a181f52",
      "before": "0",
      "after": "318987572368",
      "delta": "318987572368"
    }
  ]
}
```

Interpreting these with USDC’s 6 decimals:

- Aave pool `0x38d693ce...57922e5` gains `441.958984` USDC (flash-loan premium).
- mUSDC market `0x8e08617b0d66...C29155525` loses `319429.531352` USDC.
- Adversary EOA `0x36491840...9a181f52` gains `318987.572368` USDC.

These three deltas sum to zero, confirming conservation of USDC. The adversary’s profit from the incident is therefore exactly `318987.572368` USDC.

GovernanceToken and xWELL diffs show large negative deltas on the MultiRewardDistributor proxy and matching positive deltas for the three MoonHacker contracts, proving that accrued rewards are claimed to the MoonHacker addresses during this transaction.

### Root cause distilled

Putting the evidence together:

1. MoonHacker contracts are user-owned helpers that hold leveraged mUSDC positions and accrue rewards.
2. Their `executeOperation` callback, which repays borrows, redeems mUSDC, and claims rewards, is callable by any party that can get Aave to invoke the flash loan receiver interface; it has no access control or initiator verification.
3. An unprivileged EOA deploys a router that calls Aave’s `flashLoanSimple` targeting these MoonHacker contracts, causing them to execute `executeOperation` with parameters chosen by the adversary.
4. The MoonHacker contracts unwittingly repay their loans, redeem mUSDC, claim rewards, and make USDC available for repayment plus premium back to Aave.
5. The helper/router then consolidates the net USDC surplus and transfers `318987.572368` USDC to the adversary EOA.

The vulnerability is therefore a **missing access control on the flash-loan callback path** in MoonHacker’s design, which allows arbitrary third parties to forcibly close and harvest reward-bearing positions.

## Adversary Flow Analysis

This section walks through the adversary’s actions and on-chain effects in the seed transaction.

### Stage 1: Helper/router deployment and setup

- The adversary EOA `0x36491840ebcf040413003df9fb65b6bc9a181f52` sends a contract-creation tx deploying the helper/router at `0x4E258F1705822c2565D54ec8795d303fDf9F768e`.
- The helper’s bytecode and trace show that it is designed to:
  - Query balances and positions,
  - Call Aave v3’s `flashLoanSimple`,
  - Route flash loans to target MoonHacker contracts,
  - Repay Aave with premium, and
  - Transfer remaining USDC to the EOA.

The transaction metadata and input, shown in `metadata.json`, confirm the deploy-and-execute pattern.

### Stage 2: Flash loans into MoonHacker contracts

- The helper calls Aave v3 pool `0x38d693ce1df5aadf7bc62595a37d667ad57922e5` via `flashLoanSimple`, specifying USDC token `0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85` and each MoonHacker contract as the receiver.
- For each receiver, Aave:
  - Transfers USDC to the MoonHacker contract.
  - Invokes `executeOperation(token, amountBorrowed, premium, initiator, params)` on that contract.

The trace log shows multiple calls of the form:

```text
// trace excerpt: MoonHacker executeOperation callbacks
0xD9B45e2c...::executeOperation(FiatTokenProxy: [0x0b2C639c...], 485984781792, 0, ..., params)
0x24592ed1...::executeOperation(FiatTokenProxy: [0x0b2C639c...], ...)
0x80472c68...::executeOperation(FiatTokenProxy: [0x0b2C639c...], ...)
```

These calls confirm that the MoonHacker contracts are acting as Aave flash-loan receivers under the helper’s control.

### Stage 3: Forced repay, redeem, and reward claim

Inside each `executeOperation` with `SmartOperation.REDEEM`:

- The MoonHacker:
  - Approves the mUSDC market to pull USDC.
  - Calls `IMToken(mToken).repayBorrow(amountBorrowed)` on `0x8E08617b0d66359d73aa11e11017834c29155525`.
  - Calls `IMToken(mToken).redeem(amountToSupplyOrReedem)` to redeem mUSDC for USDC.
  - Calls `COMPTROLLER.claimReward(address(this))`, which triggers the MultiRewardDistributor to transfer accumulated GovernanceToken and xWELL rewards to the MoonHacker contract.

The trace and balance diffs show:

- Large negative mUSDC balances for each MoonHacker contract.
- Matching USDC flows from the mUSDC market to the MoonHacker contracts and then back to Aave plus premium.
- Reward token flows from `0xF9524bfa...7574Aa` to each MoonHacker.

### Stage 4: Profit consolidation to adversary EOA

After all MoonHacker positions are repaid and redeemed and the flash loans are repaid with premium, the helper/router transfers the remaining USDC to the adversary EOA:

- USDC delta for `0x36491840ebcf040413003df9fb65b6bc9a181f52` is `+318987572368` (i.e., `318987.572368` USDC).
- There is no prior USDC balance for this EOA in the balance diff file, so its final USDC balance equals the profit.

The final USDC distribution is:

- Adversary EOA: `+318987.572368` USDC (profit).
- Aave pool: `+441.958984` USDC (flash-loan premium).
- Moonwell mUSDC market: `-319429.531352` USDC (loss of underlying backing the redeemed positions).

This sequence is fully contained in the single seed transaction and requires no privileged actions or governance permissions.

## Impact & Losses

The quantitative impact, measured in USDC, is:

- **Adversary profit**: `318987.572368` USDC gained by the EOA `0x36491840ebcf040413003df9fb65b6bc9a181f52`.
- **mUSDC market loss**: `319429.531352` USDC removed from `0x8E08617b0d66359d73aa11E11017834C29155525`, corresponding to the unwind of three leveraged MoonHacker positions.
- **Aave flash-loan premium**: `441.958984` USDC gained by the pool `0x38d693ce1df5aadf7bc62595a37d667ad57922e5`.

In practical terms:

- The original MoonHacker users lose their leveraged exposure and the USDC collateral that was backing those positions is redirected to the adversary and Aave.
- GovernanceToken and xWELL rewards are legitimately paid to the MoonHacker contracts as per protocol rules; the exploit does not forge rewards but harvests value by forcibly closing positions and aggregating the resulting USDC to the adversary.

The profit calculation is deterministic and derived directly from `balance_diff.json` for USDC; no conversion of gas costs into USDC is performed, but the USDC profit magnitude dominates any realistic gas expenditure in this transaction.

## References

Key supporting artifacts:

- **[1] Seed transaction metadata and trace**  
  `artifacts/root_cause/seed/10/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe/metadata.json`  
  `artifacts/root_cause/seed/10/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe/trace.cast.log`

- **[2] Seed transaction USDC and reward token balance diffs**  
  `artifacts/root_cause/seed/10/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe/balance_diff.json`

- **[3] MoonHacker helper contract source code**  
  `artifacts/root_cause/data_collector/iter_1/contract/10/0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847/source/src/MoonHacker.sol`

- **[4] MultiRewardDistributor contract source code**  
  `artifacts/root_cause/data_collector/iter_2/contract/10/0xff0731337f615ac5403cb243623283bc04cde121/source/src/rewards/MultiRewardDistributor.sol`

- **[5] Seed index summary**  
  `artifacts/root_cause/seed/index.json`

- **[6] Ownership and history evidence for MoonHacker contracts**  
  `artifacts/root_cause/data_collector/iter_2/address/10/0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847/storage_slot_0.json`  
  `artifacts/root_cause/data_collector/iter_2/address/10/0x80472c6848015146fdc3d15cdf6dc11ca3cb3513/storage_slot_0.json`  
  `artifacts/root_cause/data_collector/iter_2/address/10/0x80472c6848015146fdc3d15cdf6dc11ca3cb3513/txlist_normal.json`  
  `artifacts/root_cause/data_collector/iter_2/address/10/0x24592ed1ccf9e5ae235e24a932b378891313fb75/txlist_normal.json`

