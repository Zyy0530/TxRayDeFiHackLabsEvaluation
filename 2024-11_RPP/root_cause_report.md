# RichPipToken Pancake V2 Pool Drain via Flash-Loan-Enabled Fee Mechanics

## Incident Overview TL;DR

On BSC block 43752882, an adversary-controlled helper contract at `0xfebfe8fbe1cbe2fbdcfb8d37331f2c8afd2a4b45` used a Pancake V3 BEP20USDT flash loan to execute a long sequence of swaps against the RichPipToken/BEP20USDT Pancake V2 pair at `0x7f42d51db070454251c2b0b6922128bb2cf768e9`. In a single transaction (`0x76c39537374e7fa7f206ed3c99aa6b14ccf1d2dadaabe6139164cc37966e40bd`), the attacker drained most of the pool’s BEP20USDT and RichPipToken reserves.

The adversary EOA `0x709b30b69176a3ccc8ef3bb37219267ee2f5b112` ends the transaction with approximately `14,085,416.858771742702566` BEP20USDT, while the LP position is effectively emptied of both BEP20USDT and RichPipToken. The core root cause is RichPipToken’s fee-on-transfer and LP-burning mechanics, which, when combined with a standard Pancake V2 pair and a flash-loan-capable helper contract, can be composed into a fully permissionless ACT opportunity that deterministically drains LP reserves.

## Key Background

RichPipToken (`0x7d1a69302d2a94620d5185f2d80e065454a35751`) is a BEP20 token deployed on BSC whose constructor hardcodes BEP20USDT (`0x55d398326f99059ff775485246999027b3197955`) as `mainAddress` and creates a Pancake V2 pair against BEP20USDT via the standard Pancake router at `0x10ed43c718714eb63d5aa57b78b54704e256024e`. This behavior is visible directly in the verified source code.

```solidity
contract RichPipToken is ERC20Burnable, Ownable {
    IUniswapV2Router02 public uniswapV2Router;
    address public uniswapV2Pair;

    address public mainAddress = address(0x55d398326f99059fF775485246999027B3197955);
    ...
    constructor() ERC20("RichPip Token", "RPP") {
        IUniswapV2Router02 _uniswapV2Router = IUniswapV2Router02(
            0x10ED43C718714eb63d5aA57B78B54704E256024E // bsc network
        );
        uniswapV2Pair = IUniswapV2Factory(_uniswapV2Router.factory()).createPair(mainAddress, address(this));
        _excludedFees[msg.sender] = true;
        _excludedFees[address(this)] = true;
        _setAutomatedMarketMakerPair(address(uniswapV2Pair), true);
        uniswapV2Router = _uniswapV2Router;
        feeReciever = msg.sender;
    }
}
```

RichPipToken’s `transfer` and `transferFrom` logic introduces configurable buy, sell, and transfer fees, LP token burning, and a special `_sell` path when tokens are sent to the token contract itself. These mechanics make changes to the Pancake V2 pair’s reserves deviate from what a simple constant-product model would predict.

```solidity
function _burnLpsToken(uint256 amount) internal {
    uint256 liquidityPairBalance = balanceOf(uniswapV2Pair);
    uint256 amountToBurn = amount * _lpBurnRate / _commonDiv;
    if (amountToBurn > 0 && liquidityPairBalance > amountToBurn) {
        if (!swapIng && !minting) {
            autoLiquidityPairTokens(amountToBurn);
        }
    }
}

function _sell(address from, uint256 amount) internal {
    require(!swapIng, "Swapping");
    require(amount > 0, "Sell amount must large than zero");
    require(msg.sender == tx.origin, "Only external calls allowed");
    require(amount < everyTimeSellLimitAmount, "Exchange Overflow");

    super._transfer(from, address(this), amount);
    if (enableSwitch && !_excludedFees[from]) {
        uint256 _txFee;
        uint256 _burnFee;
        // sell
        unchecked {
            _txFee = amount * sellFee / _commonDiv;
            _burnFee = amount * txBurnRate / _commonDiv;
        }
        _burnLpsToken(_burnFee);
        _transfer(address(this), feeReciever, _txFee);
    }
}
```

Before the exploit, the RichPipToken/BEP20USDT Pancake V2 pair at `0x7f42d51db070454251c2b0b6922128bb2cf768e9` accumulates substantial BEP20USDT and RichPipToken liquidity, as evidenced by historical Swap, Mint, and Burn events in the pair logs.

The Pancake V3 BEP20USDT pool at `0x36696169c63e42cd08ce11f5deebbcebae652050` offers standard flash loans. In the exploit trace, this pool lends `1,200,000` BEP20USDT and is repaid with a `600` BEP20USDT fee.

The helper contract `0xfebfe8fbe1cbe2fbdcfb8d37331f2c8afd2a4b45` is deployed by the adversary EOA shortly before the exploit (tx `0xf626eb38b3989d934b9159e70ad50edfa881e7dcbb6de2d9b0641209d3a76aa6`) and acts as an unprivileged strategy contract. Its disassembly shows public entrypoints for requesting a flash loan and routing swaps via Pancake infrastructure, but no reliance on privileged roles or owner-only functions of RichPipToken.

From the act-opportunity perspective, we consider the pre-state `sigma_B` at or immediately before block `43752882`, where:

- RichPipToken, BEP20USDT, and the RichPipToken/BEP20USDT Pancake V2 pair are fully deployed and liquid.
- The helper contract is already deployed by the adversary EOA.
- Pancake V2 and V3 infrastructure operate with standard semantics and no special permissioning relevant to the exploit.

## Vulnerability Analysis

The underlying vulnerability is not a single missing access control check but a compositional design flaw in how RichPipToken’s tokenomics interact with a standard AMM pair and a flash-loan provider.

Key aspects:

- RichPipToken hardcodes BEP20USDT as its `mainAddress` and sets up a Pancake V2 pair against it, inviting standard AMM liquidity provision despite non-standard transfer behavior.
- Its transfer hooks implement asymmetric fees, LP burning tied to trade flows, and special handling when tokens move through the token contract address. These mechanics can cause the LP’s reserves to change in ways that are not aligned with the apparent swap amounts.
- When a sophisticated searcher can route large flash-loan-powered trades through this pair, the non-linear fee and burning mechanics allow reserves to be collapsed while funneling value toward the adversary-controlled addresses.
- Because the exploit uses only public Pancake V3 flash-loan entrypoints, Pancake V2 router functions, and RichPipToken’s public transfer paths (including `_sell` triggered under specific routing), no owner-only configuration functions (such as `excludedFromFees` or `setMintWhitelist`) are invoked during the exploit.

The vulnerable components are:

- RichPipToken (`0x7d1a69302d2a94620d5185f2d80e065454a35751`), specifically its `transfer`, `transferFrom`, `_sell`, `_burnLpsToken`, and related LP-burning and fee logic.
- The RichPipToken/BEP20USDT Pancake V2 pair (`0x7f42d51db070454251c2b0b6922128bb2cf768e9`), whose reserves can be drained via repeated fee-bearing trades orchestrated by an external helper contract.
- The Pancake V3 BEP20USDT pool (`0x36696169c63e42cd08ce11f5deebbcebae652050`), which provides the `1,200,000` BEP20USDT flash loan that amplifies the exploit.

Security assumptions violated by this design include:

- Assuming that complex fee-on-transfer and LP-burning tokenomics cannot be combined with standard AMM pools to create a deterministic, permissionless drain of LP reserves.
- Assuming LP reserves change in a relatively invariant manner with respect to swap inputs, when in fact RichPipToken’s hooks skew the reserves and extract value to fee receivers and attacker-controlled accounts.
- Assuming that only protocol operators or token issuers can materially reshape pool reserves, while here a searcher using only public contracts and a flash loan drives catastrophic losses for LPs.

## Detailed Root Cause Analysis

### Exploit Preconditions (sigma_B)

At pre-state `sigma_B` (block height `43752882`):

- RichPipToken has been deployed and configured via owner transactions (fee rates, LP burn rates, whitelists), and its Pancake V2 pair with BEP20USDT holds substantial liquidity.
- The helper contract `0xfebfe8fbe1cbe2fbdcfb8d37331f2c8afd2a4b45` is deployed by the adversary EOA `0x709b30b69176a3ccc8ef3bb37219267ee2f5b112`.
- Pair logs and prior traces show the token operating with its documented fee and LP-burning configuration, and no protections preventing large flash-loan-driven trades from interacting with the pair.

From this state, any unprivileged searcher with access to the same on-chain state and standard BSC infrastructure can submit the exploit transaction sequence using only public interfaces.

### Flash Loan and Core Execution Path

In the exploit transaction `0x76c39537374e7fa7f206ed3c99aa6b14ccf1d2dadaabe6139164cc37966e40bd`, the trace shows the following high-level structure:

```text
PancakeV3Pool::flash(
  recipient = 0xfebfe8fbe1cbe2fbdcfb8d37331f2c8afd2a4b45,
  amount0 = 1200000000000000000000000, // 1,200,000 BEP20USDT
  amount1 = 0
)
  -> BEP20USDT::transfer(pool -> helper, 1,200,000e18)
  -> helper::pancakeV3FlashCallback(fee0 = 600000000000000000000, fee1 = 0)
       -> series of PancakeRouter swaps against RichPipToken/BEP20USDT pair
       -> repeated RichPipToken::transfer/transferFrom calls
       -> LP burn and fee logic trigger on each relevant transfer
  -> BEP20USDT transfers returning principal + 600e18 fee to the V3 pool
```

This is directly visible in `trace.cast.log` for the exploit transaction, where a `flash` call of `1.2e24` BEP20USDT is followed by a callback with a `6e20` BEP20USDT fee and multiple `swapTokensForExactTokens` calls routed through the RichPipToken/BEP20USDT pair.

### Reserve Collapse and Value Flow

The combination of RichPipToken’s fee and LP-burning behavior with the orchestrated swaps leads to a large, non-linear change in reserves. The `balance_diff.json` for the exploit transaction quantifies these changes:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x36696169c63e42cd08ce11f5deebbcebae652050",
      "delta": "600000000000000000000",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x7f42d51db070454251c2b0b6922128bb2cf768e9",
      "delta": "-14685416858771742702566",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x709b30b69176a3ccc8ef3bb37219267ee2f5b112",
      "delta": "14085416858771742702566",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x7d1a69302d2a94620d5185f2d80e065454a35751",
      "holder": "0x7f42d51db070454251c2b0b6922128bb2cf768e9",
      "delta": "-146842367999999999999998550",
      "contract_name": "RichPipToken"
    }
  ]
}
```

Interpreting these deltas:

- The Pancake V3 BEP20USDT pool gains `600` BEP20USDT (the flash-loan fee).
- The RichPipToken/BEP20USDT V2 pair loses `14,685,416.858771742771566` BEP20USDT and `146,842,367.999999999999998550` RichPipToken.
- The adversary EOA `0x709b30b69176a3ccc8ef3bb37219267ee2f5b112` ends the transaction with `14,085,416.858771742702566` BEP20USDT.

These values match the narrative in `root_cause.json` and confirm that the adversary’s profit is realized directly from the LP’s BEP20USDT reserves, with additional RichPipToken balances distributed to other addresses (including the helper and fee receiver) via the token’s custom mechanics.

### Deterministic ACT Opportunity

No owner-only configuration functions of RichPipToken (such as `excludedFromFees`, `setMintWhitelist`, or other administrative setters) are invoked in the exploit transaction. All interaction routes through:

- `PancakeV3Pool::flash` and its callback,
- Pancake V2 router swap functions such as `swapTokensForExactTokens` and `swapTokensForExactTokensSupportingFeeOnTransferTokens`, and
- RichPipToken’s public `transfer` and `transferFrom` handlers.

As a result, given `sigma_B`, any unprivileged actor who observes this state can:

- Deploy an equivalent helper/strategy contract capable of calling the same flash-loan and router functions.
- Submit the exploit transaction to the public mempool (or other public relays) with sufficient gas.

The success predicate is purely profit-based:

- Reference asset: BEP20USDT.
- Adversary address: `0x709b30b69176a3ccc8ef3bb37219267ee2f5b112`.
- Fees paid in BEP20USDT: `600` (flash-loan fee to the V3 pool).
- Value before: `0` BEP20USDT.
- Value after: `14,085,416.858771742702566` BEP20USDT.
- Delta: `14,085,416.858771742702566` BEP20USDT.

Gas is paid in BNB and not converted into BEP20USDT units in this analysis, so the BEP20USDT delta already incorporates all BEP20USDT inflows and outflows from the flash loan and swaps.

## Adversary Flow Analysis

### Adversary Strategy Summary

The adversary executes a single-transaction, flash-loan-powered pool drain using a custom unprivileged helper contract. The helper borrows BEP20USDT from Pancake V3, trades aggressively against the RichPipToken/BEP20USDT Pancake V2 pair using paths that trigger RichPipToken’s fee and LP-burning behavior, and then repays the flash loan while leaving a large BEP20USDT surplus with the adversary EOA.

### Adversary-Related Accounts

- `0x709b30b69176a3ccc8ef3bb37219267ee2f5b112` (BSC EOA):
  - Sender of the exploit transaction `0x76c39537374e7fa7f206ed3c99aa6b14ccf1d2dadaabe6139164cc37966e40bd`.
  - Deployer of the helper contract in tx `0xf626eb38b3989d934b9159e70ad50edfa881e7dcbb6de2d9b0641209d3a76aa6`.
  - Direct recipient of `14,085,416.858771742702566` BEP20USDT profit, as shown in `balance_diff.json`.

- `0xfebfe8fbe1cbe2fbdcfb8d37331f2c8afd2a4b45` (BSC contract):
  - Helper/strategy contract deployed by the adversary EOA.
  - Orchestrates the Pancake V3 flash loan and all relevant swaps in the exploit transaction, as confirmed by the call tree in `trace.cast.log` and the helper’s disassembly.

Victim-side contracts and tokens:

- RichPipToken/BEP20USDT Pancake V2 LP (`0x7f42d51db070454251c2b0b6922128bb2cf768e9`), whose reserves are drained.
- RichPipToken (`0x7d1a69302d2a94620d5185f2d80e065454a35751`), whose tokenomics create the exploitable mechanics.
- BEP20USDT (`0x55d398326f99059ff775485246999027b3197955`), used as the reference asset and flash-loan currency.

### Adversary Lifecycle Stages

1. **Helper Contract Deployment**
   - Transaction: `0xf626eb38b3989d934b9159e70ad50edfa881e7dcbb6de2d9b0641209d3a76aa6` (block `43752698`, BSC).
   - Actor: EOA `0x709b30b69176a3ccc8ef3bb37219267ee2f5b112`.
   - Effect: Deploys the helper contract `0xfebfe8fbe1cbe2fbdcfb8d37331f2c8afd2a4b45`, which contains logic to request Pancake V3 flash loans and route swaps through the RichPipToken/BEP20USDT Pancake V2 pair.
   - Evidence: `artifacts/root_cause/data_collector/iter_1/address/56/0xfebfe8fbe1cbe2fbdcfb8d37331f2c8afd2a4b45/txlist.json` and `disassembly_from_bytecode.txt` under the corresponding `contract` directory.

2. **Flash-Loan Exploit Execution**
   - Transaction: `0x76c39537374e7fa7f206ed3c99aa6b14ccf1d2dadaabe6139164cc37966e40bd` (block `43752882`, BSC).
   - Mechanism: `flashloan`.
   - Effect:
     - The helper borrows `1,200,000` BEP20USDT from Pancake V3 pool `0x36696169c63e42cd08ce11f5deebbcebae652050`.
     - It performs a long sequence of swaps and RichPipToken transfers against Pancake V2 pair `0x7f42d51db070454251c2b0b6922128bb2cf768e9`, repeatedly triggering RichPipToken’s fee and LP-burning logic in ways that disproportionately reduce the pair’s reserves.
     - It repays the flash loan with a `600` BEP20USDT fee.
     - It leaves the adversary EOA holding `14,085,416.858771742702566` BEP20USDT, while the LP’s BEP20USDT and RichPipToken balances are largely drained.
   - Evidence: `trace.cast.log` and `balance_diff.json` in `artifacts/root_cause/seed/56/0x76c39537374e7fa7f206ed3c99aa6b14ccf1d2dadaabe6139164cc37966e40bd/`, plus RichPipToken source at `artifacts/root_cause/seed/56/0x7d1a69302d2a94620d5185f2d80e065454a35751/src/RichPipToken.sol`.

## Impact & Losses

Total losses and redistributions are quantified in BEP20USDT and RichPipToken.

- BEP20USDT:
  - The RichPipToken/BEP20USDT Pancake V2 pair loses `14,685,416.858771742771566` BEP20USDT.
  - The adversary EOA gains `14,085,416.858771742702566` BEP20USDT.
  - The Pancake V3 BEP20USDT pool gains `600` BEP20USDT as a flash-loan fee.

- RichPipToken:
  - The RichPipToken/BEP20USDT pair loses `146,842,367.999999999999998550` RichPipToken.
  - A large portion of these tokens moves to other addresses (including the helper and fee receiver), consistent with the token’s burning and fee mechanisms.

Effectively, liquidity providers in the RichPipToken/BEP20USDT Pancake V2 pair lose almost their entire BEP20USDT and RichPipToken exposure in a single block, while the adversary realizes a profit of approximately `14.085M` BEP20USDT. Beyond direct financial loss, the incident undermines confidence in providing liquidity to complex fee-on-transfer tokens on BSC and highlights that exotic tokenomics can create large, permissionless ACT-style MEV opportunities.

## References

- [1] Exploit transaction metadata and trace for `0x76c39537374e7fa7f206ed3c99aa6b14ccf1d2dadaabe6139164cc37966e40bd`:
  - `artifacts/root_cause/seed/56/0x76c39537374e7fa7f206ed3c99aa6b14ccf1d2dadaabe6139164cc37966e40bd/`
- [2] RichPipToken source code (`RichPipToken.sol`):
  - `artifacts/root_cause/seed/56/0x7d1a69302d2a94620d5185f2d80e065454a35751/src/RichPipToken.sol`
- [3] Helper contract disassembly (strategy contract at `0xfebfe8fbe1cbe2fbdcfb8d37331f2c8afd2a4b45`):
  - `artifacts/root_cause/data_collector/iter_1/contract/56/0xfebfe8fbe1cbe2fbdcfb8d37331f2c8afd2a4b45/disassembly_from_bytecode.txt`
- [4] Pair logs and liquidity history for the RichPipToken/BEP20USDT Pancake V2 pair:
  - `artifacts/root_cause/data_collector/iter_2/pair/56/0x7f42d51db070454251c2b0b6922128bb2cf768e9/logs_by_topic.json`

