# Morpho PAXG Cross-Chain Leverage Sequence – Root Cause Report

## Incident Overview & TL;DR

This analysis focuses on Ethereum EOA `0x02dbe46169fdf6555f2a125eee3dce49703b13f5` executing a sequence of DEX aggregation, lending on Morpho Blue, and cross-chain bridging via RangoDiamond from Ethereum mainnet (chainid 1) to Base (chainid 8453). The user first swaps DAI for PAXG using Uniswap’s Universal Router, then supplies that PAXG as collateral in a Morpho Blue PAXG market to borrow USDC, and finally bridges a small amount of WETH to Base, where it is used in downstream DEX and margin-like interactions.

All observed traces, pre-/post-state balance diffs, and contract code show standard, over‑collateralized use of public protocols with no abnormal minting, no under‑collateralized borrow, and no third‑party profit beyond configured protocol and bridge fees.

**Conclusion:** There is **no ACT exploit** in this sequence. The alert corresponds to a benign user‑initiated leverage and cross‑chain repositioning flow. The ACT profit predicate is not satisfied, and the analyzer records `value_delta_in_reference_asset = 0` under the profit exploit predicate, meaning no net adversary profit (after fees) is realized within the analyzed window.

Key points:

- The Morpho Blue PAXG market remains over‑collateralized for the user’s position.
- Universal Router and RangoDiamond behave exactly as designed, routing and bridging assets without hidden minting or privileged shortcuts.
- Base‑side trades and liquidity operations consume the bridged ETH and generate expected fees, but do not create value from nowhere.
- The ACT opportunity object has an empty transaction sequence and a profit delta of zero in USD terms, confirming that no ACT exploit path exists for this scenario.

## Key Background

### Protocols and Components

- **Morpho Blue PAXG market (Ethereum mainnet):**  
  - Collateral token: PAXG at `0x45804880De22913dAFE09f4980848ECE6ecbAf78`.  
  - Debt token: USDC at `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`.  
  - Market configuration (oracle and LLTV) is taken from the cloned Morpho deployment at `0x4095f064b8d3c3548a3bebfd0bbfd04750e30077` (see Reference [2]). The parameters imply an over‑collateralized market where the user’s borrow size is safely within the allowed loan‑to‑value bounds.

- **Uniswap Universal Router (Ethereum mainnet):**  
  - Router address: `0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad`.  
  - Used to perform a pre‑seed swap from DAI to PAXG before opening the Morpho position.  
  - The router is a generic, permissionless command dispatcher with no owner‑only mint path; it sequences encoded commands and reverts if required commands fail.

- **RangoDiamond (Ethereum mainnet):**  
  - Proxy address: `0x69460570c93f9de5e2edbc3052bf10125f0ca22d`.  
  - Implements an EIP‑2535‑style diamond proxy that delegates calls to facet contracts registered in its diamond storage.  
  - Used as the Ethereum‑side bridge entry point for WETH, which is later filled on Base as canonical WETH‑equivalent and forwarded to the same EOA.

- **Base L2 (chainid 8453) contracts used post‑bridge:**  
  - Canonical WETH‑equivalent wrapper: `0x4200000000000000000000000000000000000006`.  
  - DEX and derivatives contracts: `0xca4e...`, `0x19ceea...`, `0x382c...`, `0x8335...`, and `0xd9aa...`, which receive and redistribute the user’s bridged ETH through swaps, liquidity additions, and margin‑like adjustments.

### ACT Opportunity Pre‑State

The ACT opportunity object in `root_cause.json` defines the pre‑incident state `σ_B` as *Ethereum mainnet state immediately before block 20,956,052 plus the relevant Base L2 state*:

- Includes EOA `0x02dbe4...`, Morpho Bundler `0x4095f0...`, Morpho Blue market `0xBBBBBbb...`, oracle `0xDd1778...`, Universal Router `0x3fc9...`, and RangoDiamond `0x6946...` on chainid 1.
- Includes Base state immediately before the first bridge fill transaction `0x460a6c32...` on chainid 8453.

Pre‑state evidence is drawn from the seed transaction `0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b` and associated artifacts:

- Seed transaction metadata and balance diffs, including the Morpho borrow and PAXG collateral flows (Reference [1]):  
  - `metadata.json`  
  - `trace.cast.log`  
  - `balance_diff.json`
- Detailed seed traces:  
  - `debug_traceTransaction_callTracer.json`  
  - `debug_traceTransaction_prestateTracer_diff.json`
- Contract source and configuration:  
  - Morpho Bundler and Morpho Blue market source in the cloned repo at `0x4095f0...` (Reference [2]).  
  - Universal Router source at `0x3fc9...` (Reference [3]).  
  - RangoDiamond source at `0x6946...22d` (Reference [4]).
- Bridge‑related traces:  
  - Ethereum‑side bridge tx `0xf28a7d82...` summary and logs (Reference [5]).  
  - Base bridge fill tx `0x460a6c32...` transaction object and debug traces (Reference [6]).

All of these artifacts are present under the configured `artifacts/root_cause/...` tree; no referenced evidence is missing.

## Vulnerability & Root Cause Analysis

### Summary

The analyzer explicitly concludes that **no vulnerability or broken invariant** is present in Morpho Blue, the Uniswap Universal Router, or the RangoDiamond bridging flow for the studied transactions. The system behaves as designed:

- The user opens an over‑collateralized PAXG‑backed USDC debt position on Morpho Blue.
- Universal Router executes a standard DAI→PAXG swap.
- RangoDiamond and associated bridge helpers move a small WETH amount from Ethereum to Base.
- Base‑side contracts then perform ordinary swaps and liquidity/margin operations with the bridged ETH.

No contract‑level bug, oracle misconfiguration, or cross‑chain accounting discrepancy is required to explain any observed value movement.

### Universal Router Behavior

The Universal Router’s `execute` functions are central to the pre‑seed DAI→PAXG trade. The collected source code (Reference [3]) shows a straightforward command loop with no owner‑only minting or hidden privileged logic:

```solidity
// Uniswap Universal Router execute loop (from UniversalRouter.sol for 0x3fc9...fad)
contract UniversalRouter is RouterImmutables, IUniversalRouter, Dispatcher, RewardsCollector {
    modifier checkDeadline(uint256 deadline) {
        if (block.timestamp > deadline) revert TransactionDeadlinePassed();
        _;
    }

    function execute(bytes calldata commands, bytes[] calldata inputs, uint256 deadline)
        external
        payable
        checkDeadline(deadline)
    {
        execute(commands, inputs);
    }

    function execute(bytes calldata commands, bytes[] calldata inputs) public payable override isNotLocked {
        bool success;
        bytes memory output;
        uint256 numCommands = commands.length;
        if (inputs.length != numCommands) revert LengthMismatch();

        for (uint256 commandIndex = 0; commandIndex < numCommands;) {
            bytes1 command = commands[commandIndex];
            bytes calldata input = inputs[commandIndex];
            (success, output) = dispatch(command, input);
            if (!success && successRequired(command)) {
                revert ExecutionFailed({commandIndex: commandIndex, message: output});
            }
            unchecked { commandIndex++; }
        }
    }
}
```

*Caption: Seed DAI→PAXG trade routed via a generic loop over commands, with no privileged backdoor; failures simply revert the transaction.*

This implementation matches the analyzer’s description: the router is a stateless dispatcher that takes encoded commands and executes them sequentially, enforcing deadlines and optional revert‑on‑failure semantics. There is no hidden path that would mint assets or bypass slippage and risk checks.

### Morpho Blue Market Health

The seed Morpho Bundler multicall `0x256979ae...` is the core lending transaction. It is preceded by a DAI→PAXG swap `0x0dcd4003...` and followed by a bridge transaction `0xf28a7d82...`. The analyzer uses `balance_diff.json` and the seed traces to reconstruct the collateral and debt flows.

From `balance_diff.json` for seed tx `0x256979ae...` (Reference [1]):

```json
// Seed Morpho Bundler tx balance diff excerpt (0x256979ae..., chainid 1)
[
  { "key": "chainid", "value": 1 },
  { "key": "txhash", "value": "0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b" },
  {
    "key": "native_balance_deltas",
    "value": [
      {
        "address": "0x02dbe46169fdf6555f2a125eee3dce49703b13f5",
        "before_wei": "10607571130228010",
        "after_wei": "7057309733174882",
        "delta_wei": "-3550261397053128"
      }
    ]
  },
  {
    "key": "erc20_transfers",
    "value": [
      {
        "token": "0x45804880de22913dafe09f4980848ece6ecbaf78",
        "from": "0x02dbe46169fdf6555f2a125eee3dce49703b13f5",
        "to": "0x4095f064b8d3c3548a3bebfd0bbfd04750e30077",
        "value": "132577813003136114"
      },
      {
        "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "from": "0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb",
        "to": "0x02dbe46169fdf6555f2a125eee3dce49703b13f5",
        "value": "230002486670"
      }
    ]
  }
]
```

*Caption: Seed Morpho Bundler tx: PAXG collateral of ~132.58 PAXG moves from the EOA to the Morpho Bundler/market, while ~230,002.49 USDC is borrowed back to the EOA; the EOA also pays gas in ETH.*

The analyzer compares:

- The **actual DAI→PAXG trade price** from pre‑seed swap `0x0dcd4003...` (~2,696.50 DAI per PAXG).
- The **Morpho oracle price** (~2,664.83 DAI per PAXG), taken from the PAXG market configuration in the cloned Morpho repo.

Because the user paid *more* for PAXG than the oracle recognizes (i.e., the oracle is slightly conservative), the resulting PAXG collateral is **valued lower** in risk checks than the user’s acquisition cost. The borrowed USDC amount (230,002.48667) is still within the LLTV bounds for this market, so:

- The position is over‑collateralized according to Morpho’s risk model.
- There is no under‑collateralized or “free‑money” borrow.

### RangoDiamond and Bridging Behavior

The Ethereum‑side bridge transaction `0xf28a7d82...` sends a very small WETH amount from the EOA to RangoDiamond, which then interacts with a bridge helper contract to move value to Base. The RangoDiamond contract is a simple proxy that delegates logic to facets registered in diamond storage:

```solidity
// RangoDiamond diamond proxy fallback (from RangoDiamond.sol for 0x6946...22d)
contract RangoDiamond {
    constructor(address _contractOwner, address _diamondCutFacet) payable {
        LibDiamond.setContractOwner(_contractOwner);
        IDiamondCut.FacetCut[] memory cut = new IDiamondCut.FacetCut[](1);
        bytes4[] memory functionSelectors = new bytes4[](1);
        functionSelectors[0] = IDiamondCut.diamondCut.selector;
        cut[0] = IDiamondCut.FacetCut({
            facetAddress: _diamondCutFacet,
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: functionSelectors
        });
        LibDiamond.diamondCut(cut, address(0), "");
    }

    fallback() external payable {
        LibDiamond.DiamondStorage storage ds;
        bytes32 position = LibDiamond.DIAMOND_STORAGE_POSITION;
        assembly { ds.slot := position }
        address facet = ds.selectorToFacetAndPosition[msg.sig].facetAddress;
        if (facet == address(0)) {
            revert LibDiamond.FunctionDoesNotExist();
        }
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

*Caption: RangoDiamond proxy: a standard EIP‑2535‑style diamond that only delegates to configured facets; it has no embedded bridge logic of its own.*

The actual bridge behavior is confirmed by:

- `bridge_log_hints.json` for Ethereum tx `0xf28a7d82...` (Reference [5]), which shows a WETH deposit to a Base bridge with fields:  
  - `amount = 0x94cf98f758756` WETH,  
  - `minAmount = 0x94a2b0b94af14`,  
  - destination chainid `8453`,  
  - destination address equal to the same EOA `0x02dbe4...`.
- `tx.json` and debug traces for Base tx `0x460a6c32...` (Reference [6]).

From the Base prestateTracer diff for `0x460a6c32...`:

```json
// Base bridge fill tx pre/post balances (0x460a6c32..., chainid 8453)
{
  "result": {
    "pre": {
      "0x02dbe46169fdf6555f2a125eee3dce49703b13f5": { "balance": "0x611de7c72c87e", "nonce": 3243 },
      "0x4200000000000000000000000000000000000006": { "balance": "0x2b51027df2e1e23b5916" }
    },
    "post": {
      "0x02dbe46169fdf6555f2a125eee3dce49703b13f5": { "balance": "0xf5c0988077792" },
      "0x4200000000000000000000000000000000000006": { "balance": "0x2b51027df2e1e2d0ec4c" }
    }
  }
}
```

*Caption: Base bridge fill: canonical WETH‑equivalent balance at `0x4200...06` decreases while the EOA ETH balance increases by the bridged amount minus fees; no external mint occurs.*

These traces show:

- A helper relayer calls the Base bridge contract, which mints the canonical WETH‑equivalent token at `0x4200...06` and then immediately transfers exactly `minAmount` worth of ETH‑equivalent to the EOA.
- The difference between `amount` (on Ethereum) and `minAmount` (on Base) is captured as a bridge fee; this fee is accounted for in contract balances and does not constitute adversary profit in ACT terms.

### Base‑Side DEX and Margin Interactions

After the bridge fill, the EOA performs several transactions on Base:

- `0x23a34710de86a2b3f2915288cd1fcb23c1de95d0debec437076c9ca2017e6abb` (add liquidity).
- `0x8058eaeb9d91996016fa7a501f7edab6aef9aa2ce87160f77798eb90d44be42f` (add liquidity).
- `0x6e8b032392a39d53c41e3d08b845d4dbbbeb8542d42a548a57262e1ecf35ca9a` (complex DEX/margin trade).

The analyzer uses `debug_traceTransaction_prestateTracer_diff.json` for each of these (Reference [6]) to confirm that:

- In `0x23a34710...` and `0x8058eaeb...`, the EOA calls a DEX contract (e.g., `0xca4e...`) with method selector `0xf305d719` (addLiquidity‑style), sending ETH value. The diff shows ETH balances decreasing at the EOA and increasing in the pool contracts, consistent with liquidity provision.
- In `0x6e8b0323...`, the EOA interacts with `0x19ceea...` and helper contracts `0x382c...`, `0x8335...`, and `0xd9aa...` via a complex encoded payload. The diff shows standard ERC‑20 and ETH balance updates between these contracts and the EOA, with no “mint from nowhere”.

Across all Base‑side transactions, balance diffs sum to zero across the system except for gas and protocol fees, satisfying normal conservation of value.

### ACT Exploit Predicate and Profit Delta

The ACT opportunity section in `root_cause.json` describes the exploit predicate as a profit‑seeking strategy:

- `type = "profit"`.
- `reference_asset = "USD"`.
- `adversary_address = "0x0000000000000000000000000000000000000000"` (placeholder indicating that no specific adversary is identified).
- `fees_paid_in_reference_asset = "unknown"`, `value_before_in_reference_asset = "unknown"`, `value_after_in_reference_asset = "unknown"` (reflecting incomplete absolute pricing, but sufficient relative information).
- **Crucially, `value_delta_in_reference_asset = "0"`**, with valuation notes explaining that no transaction sequence produces net positive adversary portfolio value after fees.

The valuation notes synthesize the evidence:

- The DAI→PAXG trade and Morpho borrow combine into a standard over‑collateralized leverage position, with oracle pricing slightly *less* favorable than the user’s entry price.
- The bridge from `0xf28a7d82...` to `0x460a6c32...` yields exactly the configured `minAmount` on Base, with a well‑accounted fee for the bridge.
- Base‑side DEX and margin operations rearrange the user’s risk profile and fee exposure but do not create new value outside what the user supplies.

The ACT transaction sequence `transaction_sequence_b` is empty in the JSON, and the exploit predicate is not satisfied anywhere in the observed flows. The root cause is therefore recorded as **“other”**: a benign user leverage and cross‑chain migration pattern that happens to touch multiple protocols but does not exploit them.

## Adversary Flow Analysis

Although no adversary or exploit is identified, the analyzer reconstructs the lifecycle of the user’s activity to verify that no hidden ACT opportunity exists.

### Seed and Pre‑Seed (Ethereum mainnet)

1. **Pre‑seed DAI→PAXG swap – Universal Router, tx `0x0dcd4003...` (chainid 1)**  
   - The user spends approximately 357,496.64 DAI to purchase 132.577813 PAXG through Universal Router at `0x3fc9...fad`.  
   - Traces and balance diffs show DAI leaving the EOA and PAXG arriving, with pool balances adjusting as expected. There is no indication of a privileged price or mint.

2. **Seed Morpho Bundler multicall – tx `0x256979ae...` (chainid 1, role = seed)**  
   - The EOA interacts with the Morpho Bundler `0x4095f0...`, which orchestrates:  
     - PAXG approval and transfer from the EOA to the Morpho market.  
     - A call to `supplyCollateral` on the PAXG market at `0xBBBBBbb...` with approximately 132.58 PAXG.  
     - A borrow of ~230,002.48667 USDC back to the EOA.  
   - Cast trace output from `trace.cast.log` highlights the PAXG transfer and subsequent Morpho calls:

```text
// Seed Morpho Bundler tx cast trace excerpt (0x256979ae..., chainid 1)
Traces:
  0x4095F064B8d3c3548A3bebfd0Bbfd04750E30077::ac9650d8(...)
    0x4095F064B8d3c3548A3bebfd0Bbfd04750E30077::approve2(...)
      0x000000000022D473030F116dDEE9F6B43aC78BA3::permit(...)
    0x4095F064B8d3c3548A3bebfd0Bbfd04750E30077::transferFrom2(...)
      0x45804880De22913dAFE09f4980848ECE6EcbAf78::transferFrom(...)
        emit Transfer(from: 0x02DBE4..., to: 0x4095F0..., value: 132577813003136114)
    0x4095F064B8d3c3548A3bebfd0Bbfd04750E30077::morphoSupplyCollateral(...)
      0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb::supplyCollateral(...)
```

*Caption: Morpho Bundler seed call path: PAXG collateral moves from the EOA into the Morpho PAXG market and is registered as collateral; no unexpected token mints or under‑priced collateral are observed.*

This phase establishes the user’s leveraged position on Ethereum without any anomalous behavior.

### Bridge Initiation (Ethereum mainnet)

3. **Bridge transaction – tx `0xf28a7d8213f4...` (chainid 1, role = related)**  
   - The EOA sends `0.000104701298966133` WETH to RangoDiamond at `0x6946...22d`.  
   - `bridge_log_hints.json` describes the corresponding cross‑chain bridge event, capturing the `amount`, `minAmount`, destination chainid (`8453`), and destination EOA (`0x02dbe4...`).  
   - debug traces show WETH moving from the EOA to a bridge helper address and a deposit event enqueued for Base.

This step prepares the cross‑chain movement of value; no profit can be realized here beyond normal bridge semantics.

### Bridge Fill and Post‑Bridge Activity (Base)

4. **Bridge fill – tx `0x460a6c3244348d61...` (chainid 8453, role = related)**  
   - A relayer account `0x1b59...` calls a Base bridge contract at `0x09aea4...`, which:  
     - Mints canonical WETH‑equivalent at `0x4200...06`.  
     - Transfers exactly `0x94a2b0b94af14` units (corresponding to `0.000104439136919922` ETH) to the EOA.  
   - PrestateTracer diffs show the EOA’s ETH balance increasing by this amount and the bridge/relayer and canonical token balances adjusting accordingly, with no unexplained gain.

5. **Base DEX add‑liquidity calls – txs `0x23a34710...` and `0x8058eaeb...` (chainid 8453, role = related)**  
   - The EOA sends ETH into a DEX contract (e.g., `0xca4e...`) with selector `0xf305d719`.  
   - Prestate diffs show ETH moving from the EOA into pool contracts, with LP positions recorded internally by the DEX; there is no net creation of ETH.

6. **Base DEX/margin operations – tx `0x6e8b0323...` (chainid 8453, role = related)**  
   - The EOA interacts with `0x19ceea...` and helper contracts: `0x382c...`, `0x8335...`, and `0xd9aa...`.  
   - The diff shows ERC‑20 and ETH balances moving between the EOA and these contracts in a pattern consistent with swaps or margin adjustments; there is no external inflow of value beyond what the EOA already bridged or acquired in previous steps.

Across steps 4–6, the adversary‑style perspective finds no point where:

- The EOA receives value without supplying assets or risk in return, or
- Balances at the protocol level violate conservation of value, or
- Bridge invariants (e.g., 1:1 mapping between L1 deposit and L2 mint minus fees) are broken.

### Overall Flow Verdict

Viewed as a whole, the flow is:

1. Acquire PAXG with DAI via Universal Router.  
2. Use PAXG as collateral on Morpho Blue to borrow USDC.  
3. Bridge a small WETH amount from Ethereum to Base.  
4. Use bridged ETH in DEX and margin‑like operations on Base.

Each stage is consistent with expected protocol behavior and fee structures. The root cause of the alert is simply that this multi‑protocol, cross‑chain leverage pattern superficially resembles an exploit chain, but the deeper analysis shows no ACT exploit opportunity and no net profit in USD terms (`value_delta_in_reference_asset = 0`).

## Impact & Losses

The `Impact & Losses` section of `root_cause.json` reports:

- **Total losses:**  
  - `token_symbol = ""`, `amount = "0"`.  
  - No protocol, user, or third‑party losses attributable to a bug or adversarial strategy.

- **Observed effects:**  
  - The EOA assumes an over‑collateralized USDC debt position on Morpho Blue, backed by PAXG collateral acquired on Ethereum.  
  - The EOA pays:
    - Gas fees on Ethereum and Base.  
    - Bridge fees inherent in the difference between `amount` and `minAmount` on the bridge.  
    - DEX and potential margin fees on Base.  
  - Value is relocated from Ethereum to Base as intended, but conservation of value holds across chains once fees are accounted for.

There is no safety or liveness violation for Morpho, Uniswap, or Rango, and no users or third‑party protocols incur losses due to an exploit. All changes in balances and state are explainable as normal operation.

## References

The following references correspond directly to the `refs` array in `root_cause.json` and were used to support the conclusions above:

1. **[1] Seed Morpho Bundler tx trace and balance diff**  
   - Seed transaction `0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b` (Ethereum mainnet).  
   - Includes `metadata.json`, `trace.cast.log`, and `balance_diff.json` under:  
   - `artifacts/root_cause/seed/1/0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b/`

2. **[2] Morpho Blue cloned repo for 0x4095f0...**  
   - Full cloned source tree and configuration for Morpho Bundler and PAXG market at:  
   - `artifacts/root_cause/data_collector/iter_1/artifacts/contract/1/0x4095f064b8d3c3548a3bebfd0bbfd04750e30077/`

3. **[3] Universal Router source for 0x3fc9...fad**  
   - Universal Router contract source, including the `execute` loop and dispatcher logic, at:  
   - `artifacts/root_cause/data_collector/iter_3/artifacts/contract/1/0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad/src/UniversalRouter.sol`

4. **[4] RangoDiamond source for 0x6946...22d**  
   - Diamond proxy shell and associated libraries at:  
   - `artifacts/root_cause/data_collector/iter_3/artifacts/contract/1/0x69460570c93f9de5e2edbc3052bf10125f0ca22d/src/rango/RangoDiamond.sol`

5. **[5] Ethereum bridge tx 0xf28a7d82... logs and traces**  
   - Ethereum mainnet bridge initiation transaction, including `tx_and_logs_summary.json`, call traces, prestate diffs, and `bridge_log_hints.json`, at:  
   - `artifacts/root_cause/data_collector/iter_3/artifacts/tx/1/0xf28a7d8213f4113364dc1c5b97be3ae0bc08681f13ba15dfda4c28568957a436/`

6. **[6] Base bridge fill tx 0x460a6c32... logs and traces**  
   - Base chain bridge fill transaction, including `tx.json`, call traces, and prestate diffs, at:  
   - `artifacts/root_cause/data_collector/iter_3/artifacts/tx/8453/0x460a6c3244348d616d69e164a9bdbc5993ff29f4c416e3c4852fd73a54bd2baa/`

7. **[7] Base EOA 0x02dbe4... txlist around incident window**  
   - Full transaction list for the EOA on Base around the incident period, at:  
   - `artifacts/root_cause/data_collector/iter_3/artifacts/address/8453/0x02dbe46169fdf6555f2a125eee3dce49703b13f5/txlist.json`

These references collectively support the core conclusion of the report: **no ACT exploit occurred, and the ACT profit predicate’s `value_delta_in_reference_asset` is 0**, indicating that the monitored activity is benign cross‑protocol usage rather than an adversarial strategy.

