# AggregationRouter FiatTokenV2_2 Allowance Abuse (chainid 1329)

## Incident Overview TL;DR

An unprivileged EOA `0xd43d0660601E613F9097d5C75cd04ee0C19E6f65` exploits the executor pattern of `AggregationRouter` at `0x14bb98581Ac1F1a43fD148db7d7D793308Dc4d80` on chainid 1329 to drain a victim’s FiatTokenV2_2 balance using a pre-existing allowance. The attacker sends a crafted `swap(SwapParams)` call with `srcToken = dstToken = syUSD` (`0x059A6b0bA116c63191182a0956cF697d0d2213eC`), `amount = 0`, and `executor = FiatTokenProxy` (`0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392`), embedding calldata for `FiatTokenV2_2::transferFrom` that moves `17,999,880,000` FiatTokenV2_2 units from victim EOA `0x9A9F47F38276f7F7618Aa50Ba94B49693293Ab50` to the attacker.

Because AggregationRouter blindly forwards `executeParams` to the executor and FiatTokenV2_2’s allowance model treats AggregationRouter as an authorized spender, this transfer succeeds without any victim-originated transaction. A follow-on settlement transaction uses `Permit2Proxy` at `0x89c6340B1a1f4b25d36cd8B063D49045caf3f818` and the LiFi diamond at `0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE` to route the stolen tokens to downstream addresses `0x8b7bc59c92f77980d1120406a173d7c611060da3` and `0xdc39167b80874765a334be78a378417bb42aae26`.

This is a protocol bug (root_cause_category `protocol_bug`) and an ACT opportunity: any EOA can repeat the strategy by finding a victim with a large FiatTokenV2_2 allowance to AggregationRouter and submitting a single EIP-1559 transaction with appropriate calldata.

## Key Background

**Report metadata and scope**

- Report title: `AggregationRouter FiatTokenV2_2 Allowance Abuse on chainid 1329`.
- Protocol name: `AggregationRouter / FiatTokenV2_2`.
- Chain: `chain_1329` (chainid 1329).
- ACT flag: `is_act = true`; the exploit requires only public on-chain state, verified contract code, and standard transactions.

**Core contracts and roles**

- `FiatTokenV2_2` implementation (see [3]) is a Circle-issued ERC20-style token. Its `transferFrom` enforces `value <= allowed[from][msg.sender]` and sufficient balance, and it supports permit-style helpers (EIP-2612 and EIP-3009).
- `FiatTokenProxy` at `0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392` is an upgradeable proxy that delegates to the FiatTokenV2_2 implementation at layout address `0xcafdc392214661c8c6c7165e491890ad84bed171`, so external `transferFrom` calls execute with `msg.sender` equal to the immediate caller (for example, AggregationRouter).
- `AggregationRouter` at `0x14bb98581Ac1F1a43fD148db7d7D793308Dc4d80` provides a `swap(SwapParams)` function that for ERC20 `srcToken` calls `SafeERC20.safeTransferFrom(msg.sender, params.executor, params.amount)` and then unconditionally calls `params.executor` with `params.executeParams`. There is no binding between `params.amount` and any internal `transferFrom`, and no restriction that the executor operate only on `msg.sender`’s balances.
- `syUSD` at `0x059A6b0bA116c63191182a0956cF697d0d2213eC` is an ERC20 token used as both `srcToken` and `dstToken` in the exploit; in the incident transaction the `amount` parameter is zero, so `syUSD::transferFrom(msg.sender, executor, 0)` is a no-op on balances.
- `Permit2Proxy` at `0x89c6340B1a1f4b25d36cd8B063D49045caf3f818` exposes `callDiamondWithEIP2612Signature` and related functions that pull ERC20 tokens from `msg.sender` based on an EIP-2612 permit or an existing allowance, then forward them to the LiFi diamond.
- The LiFi diamond at `0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE` is the downstream router that receives approved FiatTokenV2_2 from Permit2Proxy and forwards them according to attacker-specified calldata.

**Participants and addresses**

- Victim EOA: `0x9A9F47F38276f7F7618Aa50Ba94B49693293Ab50`.
- Attacker EOA: `0xd43d0660601E613F9097d5C75cd04ee0C19E6f65`.
- Funder EOA: `0x8c826f795466e39acbff1bb4eeeb759609377ba1` (funds attacker with native gas).
- Downstream profit addresses:
  - `0x8b7bc59c92f77980d1120406a173d7c611060da3` (receives 9,719,935,200 FiatTokenV2_2 units).
  - `0xdc39167b80874765a334be78a378417bb42aae26` (receives 8,279,944,800 FiatTokenV2_2 units).
- Stakeholder contracts and their verification status in the artifacts:
  - FiatTokenV2_2 via FiatTokenProxy (`0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392`), verified.
  - AggregationRouter (`0x14bb98581Ac1F1a43fD148db7d7D793308Dc4d80`), verified.
  - syUSD (`0x059A6b0bA116c63191182a0956cF697d0d2213eC`), verified.
  - LiFi Permit2Proxy (`0x89c6340B1a1f4b25d36cd8B063D49045caf3f818`), verified.
  - LiFi Diamond (`0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE`), not marked verified in the collected metadata.
  - Victim EOA, not a contract and not verified.

**Pre-incident state (sigma_B) and ACT opportunity**

- Block height `B`: `167791782` (immediately before exploit block `167791783` on chainid 1329).
- Pre-state definition:
  - The victim EOA holds a positive FiatTokenV2_2 balance.
  - The victim has granted AggregationRouter a FiatTokenV2_2 allowance of at least `17,999,880,000` units.
  - AggregationRouter, FiatTokenProxy/FiatTokenV2_2, syUSD, and Permit2Proxy are deployed with the verified code present in the artifacts.
- Evidence for this state includes:
  - Seed index and metadata for tx `0x6150ec6b2b1b46d1bcba0cab9c3a77b5bca218fd1cdaad1ddc7a916e4ce792ec` (see [1]).
  - Seed trace and balance diff for the same tx (see [1]).
  - Verified contract source trees for AggregationRouter, FiatTokenV2_2, FiatTokenProxy, syUSD, and Permit2Proxy (see [2], [3], [4]).
  - Pre-incident victim routing traces (see [5]) that show FiatTokenV2_2 `transferFrom` operations using allowances.

**Success predicate and outcome**

- Success type: `profit`.
- Reference asset: raw FiatTokenV2_2 units.
- Adversary address: attacker EOA `0xd43d0660601E613F9097d5C75cd04ee0C19E6f65`.
- Value before (in FiatTokenV2_2 units): `0`.
- Value after: `17,999,880,000`.
- Value delta: `17,999,880,000`.
- Fees in reference asset: `0` (gas is paid in the native token).
- This is validated by the seed tx balance diff, which shows the attacker EOA going from 0 to `17,999,880,000` FiatTokenV2_2 units and the victim losing the same amount.

## Vulnerability Analysis

### AggregationRouter executor design

The core bug lies in the design of `AggregationRouter::swap`, which performs a zero-amount ERC20 transfer from `msg.sender` and then executes an arbitrary external call on a caller-chosen executor under the router’s identity.

Relevant excerpt from `AggregationRouter.sol` at `0x14bb98581Ac1F1a43fD148db7d7D793308Dc4d80` (see [2]):

```solidity
function swap(SwapParams calldata params) external payable returns (uint256 returnAmount) {
    IERC20 srcToken = params.srcToken;
    if (srcToken.isETH() && msg.value != params.amount) revert InvalidMsgValue();

    if (!srcToken.isETH()) srcToken.safeTransferFrom(msg.sender, params.executor, params.amount);

    (bool success, bytes memory returnData) = params.executor.call{value: msg.value}(params.executeParams);
    if (!success) revert ExecuteFailed();

    returnAmount = abi.decode(returnData, (uint256));

    emit Swapped(address(params.srcToken), address(params.dstToken), params.amount, returnAmount, params.extraData);
}
```

Key properties:

- For ERC20 `srcToken`, the router calls `safeTransferFrom(msg.sender, params.executor, params.amount)` and then performs `params.executor.call(params.executeParams)` with `msg.sender = AggregationRouter`.
- The router does not:
  - Restrict `params.executor` to a specific allowlist.
  - Ensure that `params.executeParams` operates only on `msg.sender`’s balances.
  - Bind the internal token flows to the `srcToken`/`dstToken` or `amount` fields.
- It is therefore possible for an unprivileged EOA to:
  - Set `amount = 0`, so the pre-executor transferFrom is a no-op.
  - Choose an executor that can perform arbitrary actions, including calling FiatTokenV2_2 via proxy.
  - Encode calldata that uses third-party allowances granted to AggregationRouter.

### Interaction with FiatTokenV2_2 allowances and FiatTokenProxy

From the FiatTokenV2_2 implementation (see [3]) and the proxy architecture:

- FiatTokenV2_2 enforces the standard ERC20 invariant:
  - `transferFrom(from, to, value)` succeeds only if `value <= allowed[from][msg.sender]` and `from` has sufficient balance.
- FiatTokenProxy delegates to FiatTokenV2_2, preserving `msg.sender` as the external caller (here, AggregationRouter).
- The victim has configured a large allowance from their address to AggregationRouter:
  - `allowed[victim][AggregationRouter] >= 17,999,880,000`.

When AggregationRouter calls FiatTokenProxy as executor and the proxy delegatecalls `transferFrom(victim, attacker, 17,999,880,000)`, the allowance check is evaluated against `allowed[victim][AggregationRouter]`. Because this allowance is sufficient, the transfer succeeds and moves the victim’s balance directly to the attacker.

### Zero-amount syUSD transfer

In the exploit transaction:

- `srcToken = dstToken = syUSD` (`0x059A6b0bA116c63191182a0956cF697d0d2213eC`).
- `amount = 0`.

The trace shows:

- A `syUSD::transferFrom(attacker, FiatTokenProxy, 0)` call that emits events but does not change balances.
- The entire economic effect occurs within the executor payload: a FiatTokenV2_2 `transferFrom` executed via FiatTokenProxy.

This design allows the router to appear to process a swap while in reality performing an arbitrary balance transfer based solely on third-party allowances.

### Security principles violated

The incident violates several key security principles:

- Least privilege for token allowances and router spenders: AggregationRouter is granted a broad FiatTokenV2_2 allowance that it can apply to any `transferFrom` call in its executor payload, not just those that correspond to user-initiated swaps.
- Separation between user-input token flows and internal executor logic: the executor payload can perform token transfers unrelated to `msg.sender`’s balances or the `srcToken` amount, enabling third-party drains.
- Assumption that routers only move funds belonging to `msg.sender`: the router’s design allows arbitrary EOAs to instruct it to use allowances granted by other users, without those users participating in the exploit transaction.

## Detailed Root Cause Analysis

### Seed exploit transaction: 0x6150ec6b2b1b46d1bcba0cab9c3a77b5bca218fd1cdaad1ddc7a916e4ce792ec

Seed metadata (see [1]) shows:

- Chainid: 1329.
- From: `0xd43d0660601E613F9097d5C75cd04ee0C19E6f65` (attacker).
- To: `0x14bb98581Ac1F1a43fD148db7d7D793308Dc4d80` (AggregationRouter).
- Value: 0.
- Input data: ABI-encoded `swap(SwapParams)` with the parameters described above.

Seed trace excerpt (cast trace, see [1]) – executor abuse of FiatTokenV2_2:

```bash
Traces:
  AggregationRouter::swap(SwapParams({ srcToken: syUSD, dstToken: syUSD, amount: 0,
    executor: FiatTokenProxy, executeParams: FiatTokenV2_2::transferFrom(victim, attacker, 17999880000) }))
    syUSD::transferFrom(attacker, FiatTokenProxy, 0)
    FiatTokenProxy::fallback(victim, attacker, 17999880000)
      FiatTokenV2_2::transferFrom(victim, attacker, 17999880000) [delegatecall]
        emit Transfer(from: victim, to: attacker, value: 17999880000)
```

Seed balance diff (see [1]) – FiatTokenV2_2 balances:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0xe15fc38f6d8c56af07bbcbe3baf5708a2bf42392",
      "holder": "0x9a9f47f38276f7f7618aa50ba94b49693293ab50",
      "before": "18167880000",
      "after": "168000000",
      "delta": "-17999880000"
    },
    {
      "token": "0xe15fc38f6d8c56af07bbcbe3baf5708a2bf42392",
      "holder": "0xd43d0660601e613f9097d5c75cd04ee0c19e6f65",
      "before": "0",
      "after": "17999880000",
      "delta": "17999880000"
    }
  ]
}
```

These artifacts jointly show that:

- The only non-zero FiatTokenV2_2 movement in the seed transaction is a direct transfer from the victim to the attacker.
- The transaction is fully realizable by any EOA that can construct the `swap` calldata; no privileged roles are required.

### Post-drain settlement transaction: 0xde33765939b8aae87d42a7415b9215a3d86f05023a63c1fc81b631f4ad093165

After the drain, the attacker EOA holds `17,999,880,000` FiatTokenV2_2 units. The settlement transaction (see [6]) moves these tokens into the LiFi stack and then to the final recipients.

Key steps from the settlement trace:

- Attacker calls `Permit2Proxy.callDiamondWithEIP2612Signature` on `0x89c6340B1a1f4b25d36cd8B063D49045caf3f818`.
- Permit2Proxy pulls `17,999,880,000` FiatTokenV2_2 units from the attacker (using a permit or allowance).
- Permit2Proxy approves the LiFi diamond at `0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE` for at least this amount.
- The diamond executes routing calldata that sends:
  - `9,719,935,200` units to `0x8b7bc59c92f77980d1120406a173d7c611060da3`.
  - `8,279,944,800` units to `0xdc39167b80874765a334be78a378417bb42aae26`.

Settlement balance diff excerpt (see [6]):

```json
{
  "erc20_balance_deltas": [
    {
      "holder": "0xd43d0660601e613f9097d5c75cd04ee0c19e6f65",
      "delta": "-17999880000"
    },
    {
      "holder": "0x8b7bc59c92f77980d1120406a173d7c611060da3",
      "delta": "9719935200"
    },
    {
      "holder": "0xdc39167b80874765a334be78a378417bb42aae26",
      "delta": "8279944800"
    }
  ]
}
```

This confirms that the attacker’s FiatTokenV2_2 balance returns to 0 and the profit is realized by the downstream addresses.

### ACT exploit conditions

The ACT opportunity is realizable whenever the following conditions hold (as summarized in the analysis):

- Victim holds at least `17,999,880,000` FiatTokenV2_2 units at pre-state.
- Victim has granted AggregationRouter a FiatTokenV2_2 allowance of at least `17,999,880,000` units (via `approve` or permit).
- AggregationRouter is deployed with the executor pattern described above.
- FiatTokenProxy delegates to FiatTokenV2_2 and preserves `msg.sender = AggregationRouter` during `transferFrom`.
- The attacker EOA has sufficient native token to pay gas for one `swap` transaction and one settlement transaction.

Under these deterministic conditions, any unprivileged EOA can reproduce the exploit using on-chain information and public contract code.

## Adversary Flow Analysis

### Strategy summary

The adversary executes a single-chain ACT as follows:

1. Ensure the victim has previously configured a large FiatTokenV2_2 allowance to AggregationRouter through legitimate routing activity.
2. Fund an attacker EOA with native gas from a separate EOA.
3. Use the attacker EOA to submit one crafted `AggregationRouter::swap` transaction that drains the victim’s FiatTokenV2_2 balance into the attacker account using the existing allowance.
4. Use the attacker EOA to call Permit2Proxy and LiFi to move the drained tokens to downstream addresses, completing the profit realization.

### Adversary-related accounts and roles

- Attacker EOA `0xd43d0660601E613F9097d5C75cd04ee0C19E6f65`:
  - Sends the exploit swap transaction `0x6150ec6b2b1b46d1bcba0cab9c3a77b5bca218fd1cdaad1ddc7a916e4ce792ec`.
  - Sends the settlement transaction `0xde33765939b8aae87d42a7415b9215a3d86f05023a63c1fc81b631f4ad093165`.
  - Receives `17,999,880,000` FiatTokenV2_2 units in the seed transaction and then passes them to Permit2Proxy for routing.
- Funder EOA `0x8c826f795466e39acbff1bb4eeeb759609377ba1`:
  - Sends `614.020281943191535616` units of the native asset to the attacker EOA in tx `0x4d113f8b9db29bfe97a1b00653ef12cf45407775cce84a52717eec676e2b226f`, funding gas for the exploit and settlement.
- Downstream recipients:
  - `0x8b7bc59c92f77980d1120406a173d7c611060da3` receives `9,719,935,200` FiatTokenV2_2 units.
  - `0xdc39167b80874765a334be78a378417bb42aae26` receives `8,279,944,800` FiatTokenV2_2 units.
- Victim EOA `0x9A9F47F38276f7F7618Aa50Ba94B49693293Ab50`:
  - Holds the initial FiatTokenV2_2 balance.
  - Grants the allowance that makes the exploit possible.
  - Does not send the exploit or settlement transactions.
- Protocol-infrastructure contracts (victim candidates in the analysis):
  - FiatTokenV2_2 via `FiatTokenProxy` (`0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392`).
  - AggregationRouter (`0x14bb98581Ac1F1a43fD148db7d7D793308Dc4d80`).
  - syUSD token (`0x059A6b0bA116c63191182a0956cF697d0d2213eC`).
  - LiFi Permit2Proxy (`0x89c6340B1a1f4b25d36cd8B063D49045caf3f818`).
  - LiFi Diamond (`0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE`).

### Lifecycle stages and transactions

1. Victim routing and allowance configuration (see [5])  
   - Txs:  
     - `0x3f290eed6df0093df6aec359bdb25bf8a4af8b018942fe57c3b76a021211c02d` (block `167702492`, mechanism `swap`).  
     - `0xc295b5493f953ccdc595a955627ef4702e930992464c436370e0fc6af95eab2e` (block `167703849`, mechanism `swap`).  
     - `0x4983c13280d6623aa4aa48094efa976e5044839f158eb4cc739fdc77e6b22f32` (block `167791215`, mechanism `swap`).  
   - Effect: the victim uses DeFi routers and aggregators, and in the process AggregationRouter and related contracts successfully execute FiatTokenV2_2 `transferFrom` calls drawing from the victim’s balance via allowances. One pre-incident AggregationRouter swap moves `19,999,880,000` FiatTokenV2_2 units from the victim to `0x5e14b180f3055b7e18a8c4f3edcff3a26126fc24`, demonstrating that large allowances are already in use.

2. Adversary funding  
   - Tx: `0x4d113f8b9db29bfe97a1b00653ef12cf45407775cce84a52717eec676e2b226f` (block `167784200`, mechanism `transfer`).  
   - Effect: funder EOA sends `614.020281943191535616` native units to the attacker EOA, providing sufficient gas for the exploit and settlement.

3. Allowance abuse and FiatTokenV2_2 drain  
   - Tx: `0x6150ec6b2b1b46d1bcba0cab9c3a77b5bca218fd1cdaad1ddc7a916e4ce792ec` (block `167791783`, mechanism `router_swap`).  
   - Effect: attacker calls `AggregationRouter::swap` with the zero-amount syUSD transfer and FiatTokenProxy executor, supplying `executeParams` that encode `FiatTokenV2_2::transferFrom(victim, attacker, 17,999,880,000)`. FiatTokenProxy delegatecalls FiatTokenV2_2 with `msg.sender = AggregationRouter`, and the call uses the victim’s allowance to move `17,999,880,000` FiatTokenV2_2 units from the victim to the attacker.

4. Post-drain settlement via Permit2Proxy and LiFi  
   - Tx: `0xde33765939b8aae87d42a7415b9215a3d86f05023a63c1fc81b631f4ad093165` (block `167792185`, mechanism `router_settlement`).  
   - Effect: attacker calls `Permit2Proxy.callDiamondWithEIP2612Signature`, transferring `17,999,880,000` FiatTokenV2_2 units from the attacker to Permit2Proxy, approving the LiFi diamond, and executing diamond calldata that routes `9,719,935,200` units to `0x8b7bc59c92f77980d1120406a173d7c611060da3` and `8,279,944,800` units to `0xdc39167b80874765a334be78a378417bb42aae26`. The attacker EOA’s FiatTokenV2_2 balance returns to 0.

## Impact & Losses

**Total quantified loss**

- Token: `FiatTokenV2_2` (via `0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392`).
- Amount: `17,999,880,000` units.

**Incident impact**

- The exploit transaction `0x6150ec6b2b1b46d1bcba0cab9c3a77b5bca218fd1cdaad1ddc7a916e4ce792ec` transfers `17,999,880,000` FiatTokenV2_2 units from victim EOA `0x9A9F47F38276f7F7618Aa50Ba94B49693293Ab50` to attacker EOA `0xd43d0660601E613F9097d5C75cd04ee0C19E6f65`.
- The settlement transaction `0xde33765939b8aae87d42a7415b9215a3d86f05023a63c1fc81b631f4ad093165` moves the same amount from the attacker EOA to downstream addresses `0x8b7bc59c92f77980d1120406a173d7c611060da3` and `0xdc39167b80874765a334be78a378417bb42aae26` via Permit2Proxy and LiFi.
- Net effect: the attacker-controlled cluster (attacker and downstream addresses) gains `17,999,880,000` FiatTokenV2_2 units; the victim EOA loses the same amount on chainid 1329.

## References

- [1] Seed tx metadata, trace, and balance diff for `0x6150ec6b2b1b46d1bcba0cab9c3a77b5bca218fd1cdaad1ddc7a916e4ce792ec` – `artifacts/root_cause/seed/1329/0x6150ec6b2b1b46d1bcba0cab9c3a77b5bca218fd1cdaad1ddc7a916e4ce792ec`.
- [2] `AggregationRouter.sol` source at `0x14bb98581Ac1F1a43fD148db7d7D793308Dc4d80` – `artifacts/root_cause/data_collector/iter_1/contract/1329/0x14bb98581Ac1F1a43fD148db7d7D793308Dc4d80/source/src/AggregationRouter.sol`.
- [3] `FiatTokenV2_2.sol` implementation source – `artifacts/root_cause/seed/1329/0xcafdc392214661c8c6c7165e491890ad84bed171/src/v2/FiatTokenV2_2.sol`.
- [4] `Permit2Proxy.sol` source at `0x89c6340B1a1f4b25d36cd8B063D49045caf3f818` – `artifacts/root_cause/data_collector/iter_3/contract/1329/0x89c6340b1a1f4b25d36cd8b063d49045caf3f818/source/src/Periphery/Permit2Proxy.sol`.
- [5] Pre-incident victim routing transaction traces `0x3f290eed6df0093df6aec359bdb25bf8a4af8b018942fe57c3b76a021211c02d`, `0xc295b5493f953ccdc595a955627ef4702e930992464c436370e0fc6af95eab2e`, `0x4983c13280d6623aa4aa48094efa976e5044839f158eb4cc739fdc77e6b22f32` – `artifacts/root_cause/data_collector/iter_3/tx/1329`.
- [6] Settlement transaction trace and balance diff for `0xde33765939b8aae87d42a7415b9215a3d86f05023a63c1fc81b631f4ad093165` – `artifacts/root_cause/data_collector/iter_3/tx/1329/0xde33765939b8aae87d42a7415b9215a3d86f05023a63c1fc81b631f4ad093165`.
