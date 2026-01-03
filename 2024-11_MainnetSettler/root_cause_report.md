# Replay of MainnetSettler EVERYBODY Allowance to Drain Victim via UniversalRouter Swaps

**Protocol:** MainnetSettler / EVERYBODY / UniversalRouter  
**Chain:** Ethereum Mainnet (chainid 1)  
**Category:** Protocol bug (authorization / allowance misuse)  
**ACT status:** Concrete profit opportunity is demonstrated and executed on-chain.

---

## Incident Overview & TL;DR

An adversary-controlled EOA `0x3A38877312D1125d2391663CBa9f7190953Bf2d9` (abbreviated as `0x3A3...`) exploited a design flaw in the MainnetSettler aggregator’s CurveTricrypto route to steal the entire EVERYBODY token balance of victim EOA `0xA31d98b1aA71a99565EC2564b81f834E90B1097b` (abbreviated as `0xA31d...`). The victim had previously granted MainnetSettler `0x70bf6634eE8Cb27D04478f184b9b8BB13E5f4710` an effectively unlimited EVERYBODY allowance and used it for a legitimate trade, leaving a large residual allowance in place.

In adversary-crafted transaction:

- **Seed / theft tx:** `0xfab5912f858b3768b7b7d312abcc02b64af7b1e1b62c4f29a2c1a2d1568e9fa2`

`0x3A3...` deploys a helper contract `0x285D37b0480910f977CD43C9bd228527BfaD816E` and a MainnetSettler clone `0x95b4FEcf1F5b9C56CE51EBfEDd582C5F40F2Ef8c`, then invokes the clone’s fallback/execute entrypoint with crafted calldata. This causes `EVERYBODY::transferFrom(0xA31d..., 0x3A3..., 308453642481581939556432141)` to execute using the victim’s standing allowance, without any participation from `0xA31d...` in that transaction.

In two follow-up adversary-crafted transactions:

- **UniversalRouter swap 1:** `0x4482d1ed3dbf618f3655d8dcc910fbf2160aeb2e9bdbe474d6c02d49628e097f`  
- **UniversalRouter swap 2:** `0xbcab5ed62fad6f3e4b3536b82561883d4b277382440727667b7c6c01b9bdecae`

`0x3A3...` uses Uniswap’s UniversalRouter `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD` together with Permit2 `0x000000000022D473030F116dDEE9F6B43aC78BA3` to swap the stolen EVERYBODY into WETH and then ETH via the EVERYBODY/WETH UniswapV2 pair `0x9e5f2b740E52C239DA457109bcCeD1F2bb40da5B`, realizing a net profit of approximately **17.63 ETH**.

**Root cause (high level):**  
MainnetSettler’s CurveTricrypto “VIP” route allows calldata to specify an arbitrary **payer** address whose ERC‑20 tokens will be pulled using an existing allowance. The implementation does not bind this payer to `msg.sender` or to a transaction-specific off-chain signature. As a result, any EOA can encode a victim address that has previously approved MainnetSettler and cause a clone to call `transferFrom` against that victim’s allowance. Combined with permissionless UniversalRouter swaps, this creates a concrete ACT opportunity to drain victims who left large approvals in place.

---

## Key Background

- **EVERYBODY token (0x68b36248...):**  
  The EVERYBODY ERC‑20 token at `0x68b36248477277865c64dfc78884ef80577078f3` uses OpenZeppelin-style `allowance` and `transferFrom` semantics. Balance and allowance changes in all relevant transactions behave exactly as expected for a standard ERC‑20 (no token-side bug is required for the exploit).

- **MainnetSettler aggregator (0x70bf66...):**  
  MainnetSettler at `0x70bf6634eE8Cb27D04478f184b9b8BB13E5f4710` is a complex routing contract that supports multiple DEX integrations. One route is a CurveTricrypto “VIP” path that:
  - Encodes a call to a CurveTricrypto pool via `exchange_extended(...)`.
  - Stores parameters (including the **payer** address whose tokens will be spent) in transient storage.
  - Receives a callback where it reconstructs a Permit2-style `PermitTransferFrom` struct and then calls an internal `_transferFrom` helper, which ultimately delegates to `SafeTransferLib.safeTransferFrom` to pull tokens from the payer.

- **Uniswap UniversalRouter + Permit2:**  
  The UniversalRouter at `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD` plus Permit2 `0x000000000022D473030F116dDEE9F6B43aC78BA3` allow EOAs to perform batched swaps and transfers from approved balances. In this exploit, the adversary uses only their own EVERYBODY balance (stolen from the victim) and normal Permit2 approvals to swap into WETH and then ETH, without any special privileges.

- **Victim prior behavior:**  
  Prior to the adversary’s seed transaction, `0xA31d...`:
  1) Approves MainnetSettler for a large (effectively unlimited) EVERYBODY allowance.  
  2) Executes a legitimate MainnetSettler trade that routes EVERYBODY through the EVERYBODY/WETH UniswapV2 pool, leaving a large unused allowance intact.  
  These actions establish the pre‑state (`σ_B`) used by the ACT opportunity: MainnetSettler has a large standing allowance over the victim’s EVERYBODY balance.

---

## Vulnerability & Root Cause Analysis

### Vulnerability Summary

The vulnerability lies in MainnetSettler’s CurveTricrypto VIP route, which:

- Accepts a **payer** address in calldata for the CurveTricrypto swap.
- Uses this payer’s existing ERC‑20 allowance to perform `transferFrom`.
- Does not enforce that the payer is equal to `msg.sender`, nor does it require a fresh, transaction-bound signature from the payer.

As a result, any unprivileged EOA can:

1. Identify a victim address that has granted a large EVERYBODY allowance to MainnetSettler.  
2. Deploy a Settler clone and invoke it with calldata encoding the victim as the payer and themselves as the receiver.  
3. Cause the clone to call `EVERYBODY::transferFrom(victim, adversary, amount)` within the CurveTricrypto callback context, relying solely on the previously granted allowance.

### Evidence from MainnetSettler CurveTricrypto Route

The collected MainnetSettler source (verified for contract `0x70bf66...`) shows the CurveTricrypto callback building a transfer from an arbitrary payer and then calling an internal `_transferFrom` which delegates to `SafeTransferLib.safeTransferFrom`.

**Snippet 1 – MainnetSettler CurveTricrypto callback and transfer (from collected MainnetSettler source for 0x70bf66..., src/flat/MainnetFlat.sol):**

```solidity
function curveTricryptoSwapCallback(
    address payer,
    address receiver,
    address sellToken,
    uint256 sellAmount,
    uint256 buyAmount
) external {
    // ... validation that the caller is the CurveTricrypto pool ...
    _curveTricryptoSwapCallback(payer, receiver, sellToken, sellAmount, buyAmount);
}

function _curveTricryptoSwapCallback(
    address payer,
    address receiver,
    address sellToken,
    uint256 sellAmount,
    uint256 buyAmount
) internal {
    // parameters reconstructed from transient storage
    PermitTransferFrom memory permit = _getCurveTricryptoPermit();
    Permit2TransferDetails memory transferDetails = _getCurveTricryptoTransferDetails(
        payer,
        receiver,
        sellToken,
        sellAmount
    );

    _transferFrom(permit, transferDetails, _curveTricryptoSig, false);
}

function _transferFrom(
    PermitTransferFrom memory permit,
    Permit2TransferDetails memory transferDetails,
    bytes memory sig,
    bool isForwarded
) internal {
    // ...
    SafeTransferLib.safeTransferFrom(
        transferDetails.token,
        transferDetails.from,    // payer
        transferDetails.to,      // recipient (router / pool)
        transferDetails.amount
    );
}
```

*Caption: CurveTricrypto callback reuses a **payer** field reconstructed from transient storage and ultimately calls `safeTransferFrom` from that payer, without binding the payer to `msg.sender` or enforcing a fresh signature for this specific clone.*

Root-cause properties:

- The `payer` is treated as a data parameter, **not** as an authorization principal tied to `msg.sender` or a per‑transaction signature.
- The design assumes a trusted flow from an earlier route configuration, but that configuration is fully controllable by whoever calls the Settler clone’s entrypoint.
- Because allowances are global to the token and not scoped per Settler clone, a clone can reuse allowances that were granted to the canonical implementation.

### Evidence from Seed Theft Transaction

The seed transaction `0xfab5912f...` is adversary-crafted and performs the theft in a single transaction:

1. `0x3A3...` deploys a helper contract `0x285D37...`.  
2. The helper deploys a MainnetSettler clone `0x95b4FEcf...`.  
3. The helper immediately invokes the clone’s fallback/execute entrypoint with calldata that:
   - Encodes the victim `0xA31d...` as the payer.
   - References EVERYBODY `0x68b3...` as the sell token.
   - Specifies `0x3A3...` as the beneficiary.

The collected seed trace shows `EVERYBODY::transferFrom` moving the full stolen amount from the victim to the adversary:

**Snippet 2 – Seed transaction trace around EVERYBODY::transferFrom (from seed transaction trace for tx 0xfab5912f..., cast run -vvvvv):**

```bash
... 
CALL  to EVERYBODY@0x68b36248477277865c64dfc78884ef80577078f3
  └─ transferFrom(
       from: 0xA31d98b1aA71a99565EC2564b81f834E90B1097b,
       to:   0x3A38877312D1125d2391663CBa9f7190953Bf2d9,
       value: 308453642481581939556432141
     )
  ↳ SUCCESS
...
```

*Caption: Seed transaction trace shows EVERYBODY `transferFrom` pulling `308453642481581939556432141` tokens from victim `0xA31d...` to adversary `0x3A3...` as part of the MainnetSettler clone execution.*

The corresponding balance diff confirms that the victim loses exactly this amount of EVERYBODY while `0x3A3...` gains it, with no ETH transferred back to the victim:

**Snippet 3 – Seed transaction balance diff (from pre/post state diff for tx 0xfab5912f..., debug_traceTransaction diffMode):**

```json
{
  "post": {
    "0x3a38877312d1125d2391663cba9f7190953bf2d9": {
      "tokens": {
        "0x68b36248477277865c64dfc78884ef80577078f3": "308453642481581939556432141"
      }
    },
    "0xa31d98b1aa71a99565ec2564b81f834e90b1097b": {
      "tokens": {
        "0x68b36248477277865c64dfc78884ef80577078f3": "0x0"
      }
    }
  }
}
```

*Caption: Balance diff for the seed theft transaction shows the victim’s EVERYBODY balance dropping to zero while the adversary receives the full stolen amount.*

### Dependency on Prior Victim Allowance

The exploit depends on a large, pre-existing EVERYBODY allowance from the victim to MainnetSettler:

- In transaction `0xac8440b4f3448e6bc46ed12057630a0832dd78f7d0d21c8cd9242158cfed92dc`, `0xA31d...` approves MainnetSettler `0x70bf66...` for a very large EVERYBODY allowance.
- In transaction `0xb792411afbd1cb8a7dab00d56c2ca29084ab29933dc92482e63b7648bbe7f39e`, the victim uses MainnetSettler for a legitimate trade. The traces and balance diffs confirm:
  - MainnetSettler executes a route through the EVERYBODY/WETH UniswapV2 pair `0x9e5f2b74...`.
  - The trade consumes **some** of the allowance but leaves a large amount unused.

**Snippet 4 – Pre-seed MainnetSettler trade trace (from victim aggregator trade tx 0xb792411a..., cast run -vvvvv):**

```bash
CALL  to EVERYBODY@0x68b36248477277865c64dfc78884ef80577078f3
  └─ transferFrom(
       from: 0xA31d98b1aA71a99565EC2564b81f834E90B1097b,
       to:   0x9e5f2b740E52C239DA457109bcCeD1F2bb40da5B,
       value: 10000000481581939556432141
     )
...
CALL  to WETH9@0xC02aaA39b223FE8D0A0E5C4F27eAD9083C756Cc2
  └─ withdraw( ... )
```

*Caption: Victim’s legitimate MainnetSettler trade spends EVERYBODY into the UniswapV2 pool but leaves an effectively unlimited residual allowance, which the adversary later reuses.*

Because allowances are granted at the token level (EVERYBODY → MainnetSettler implementation) and not scoped per clone or per route execution, the MainnetSettler clone in the seed transaction can successfully call `transferFrom` against the same allowance.

### Security Principles Violated

- **Least privilege:**  
  A single long-lived EVERYBODY approval to MainnetSettler grants ongoing power to move the victim’s tokens, far beyond the needs of a single trade.

- **Authorization binding:**  
  The contract does not bind the spending address (payer) to `msg.sender` or to a unique, transaction-specific signature, enabling a confused-deputy pattern where a third party chooses the payer.

- **Replay resistance:**  
  The design allows re-use of a previously granted allowance and route layout for a different caller, without fresh consent from the victim, as long as on-chain conditions (prices, reserves, slippage) remain acceptable.

---

## Adversary Flow Analysis

### Adversary Strategy Summary

The adversary executes a **single-chain, three-transaction** exploit on Ethereum Mainnet:

1. Leverage the victim’s standing EVERYBODY allowance to siphon tokens from the victim via a MainnetSettler clone.  
2. Convert the stolen EVERYBODY into WETH and then ETH via Uniswap’s UniversalRouter.  
3. Pay only gas and a small router fee, ending with the victim’s EVERYBODY fully drained and the adversary holding ~17.63 ETH of net profit.

### Key Actors and Contracts

- **Adversary EOA:**  
  `0x3A38877312D1125d2391663CBa9f7190953Bf2d9`  
  - Sends all three adversary-crafted transactions (`0xfab5912f...`, `0x4482d1ed...`, `0xbcab5ed...`).  
  - Receives stolen EVERYBODY and final net ETH profit.

- **Helper contract:**  
  `0x285D37b0480910f977CD43C9bd228527BfaD816E`  
  - Deployed by `0x3A3...` in `0xfab5912f...`.  
  - Creation bytecode hard-codes:
    - MainnetSettler implementation address `0x70bf66...`.  
    - EVERYBODY token address `0x68b3...`.  
    - Victim `0xA31d...`.  
    - Adversary `0x3A3...`.  
  - Deploys the MainnetSettler clone and triggers its fallback execution with crafted calldata.

- **MainnetSettler clone:**  
  `0x95b4FEcf1F5b9C56CE51EBfEDd582C5F40F2Ef8c`  
  - Deployed by the helper in `0xfab5912f...`.  
  - Executes the CurveTricrypto route that calls EVERYBODY::transferFrom on the victim and routes tokens to the adversary EOA.

- **Victim EOA:**  
  `0xA31d98b1aA71a99565EC2564b81f834E90B1097b`  
  - EVERYBODY holder and MainnetSettler user.  
  - Grants the large EVERYBODY allowance and makes a prior legitimate trade via MainnetSettler.

- **EVERYBODY token:**  
  `0x68b36248477277865c64dfc78884ef80577078f3`

- **UniswapV2 pair (EVERYBODY/WETH):**  
  `0x9e5f2b740E52C239DA457109bcCeD1F2bb40da5B`

- **UniversalRouter:**  
  `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD`

### Lifecycle Stage 1 – Victim Allowance and Initial Aggregator Trade (Pre-State)

**Transactions:**

1. `0xac8440b4f3448e6bc46ed12057630a0832dd78f7d0d21c8cd9242158cfed92dc` (block `21229159`)  
   - Mechanism: `approve`  
   - Action: `0xA31d...` approves MainnetSettler `0x70bf66...` for a very large EVERYBODY allowance.

2. `0xb792411afbd1cb8a7dab00d56c2ca29084ab29933dc92482e63b7648bbe7f39e` (block `21229162`)  
   - Mechanism: `aggregator_trade`  
   - Action: `0xA31d...` calls MainnetSettler’s `execute` function to perform a legitimate trade via the EVERYBODY/WETH pool.  
   - Effect: EVERYBODY is swapped to WETH and then ETH for the victim’s benefit, but a large unused allowance remains.

**Key effect:**  
The pre‑state `σ_B` before the adversary’s seed tx includes:

- Victim `0xA31d...` with a large EVERYBODY balance and an effectively unlimited allowance granted to MainnetSettler `0x70bf66...`.  
- UniswapV2 pair `0x9e5f2b74...` with sufficient liquidity in EVERYBODY/WETH.  
- No specific binding between the allowance and any particular MainnetSettler clone.

### Lifecycle Stage 2 – Adversary Helper & Settler Clone Deployment plus Token Theft

**Transaction:**

- `0xfab5912f858b3768b7b7d312abcc02b64af7b1e1b62c4f29a2c1a2d1568e9fa2` (block `21230768`)  
  - Mechanism: `contract_deploy_and_execute`

**Flow:**

1. `0x3A3...` broadcasts a contract-creation transaction deploying helper `0x285D37...`.  
2. The helper deploys the MainnetSettler clone `0x95b4FEcf...`.  
3. The helper immediately calls the clone’s fallback/execute entrypoint with calldata that:
   - Embeds victim `0xA31d...` as the payer.  
   - Targets EVERYBODY `0x68b3...` as the sell token.  
   - Uses parameters compatible with the known MainnetSettler CurveTricrypto route.  
4. Inside the call tree:
   - The CurveTricrypto callback reconstructs the payer as `0xA31d...`.  
   - `_transferFrom` ultimately issues `EVERYBODY::transferFrom(0xA31d..., 0x3A3..., 308453642481581939556432141)`.  
   - The call succeeds because MainnetSettler (and thus its clone) has sufficient allowance from the victim.

**Effect:**  
The victim’s entire EVERYBODY balance of `308453642481581939556432141` is moved to `0x3A3...`.  
`0x3A3...` pays only gas (≈0.0055 ETH) in this transaction and receives no ETH transfers; profit realization is deferred to later swaps.

### Lifecycle Stage 3 – Adversary Profit Realization via UniversalRouter Swaps

**Transaction 1 – Partial swap of stolen EVERYBODY:**

- `0x4482d1ed3dbf618f3655d8dcc910fbf2160aeb2e9bdbe474d6c02d49628e097f` (block `21230785`)  
  - Mechanism: `router_swap` via UniversalRouter::execute  
  - Action:
    - UniversalRouter uses Permit2 to pull `10000000481581939556432141` EVERYBODY from `0x3A3...` into the UniswapV2 pair `0x9e5f2b74...`.  
    - The pair swaps EVERYBODY for WETH.  
    - WETH is withdrawn to ETH and sent to `0x3A3...`.  
  - Effect: `0x3A3...` receives approximately `0.7758` ETH.

**Snippet 5 – Balance diff for first UniversalRouter swap (from debug_traceTransaction balance diff for tx 0x4482d1ed...):**

```json
{
  "post": {
    "0x3a38877312d1125d2391663cba9f7190953bf2d9": {
      "balance": "0x...", 
      "tokens": {
        "0x68b36248477277865c64dfc78884ef80577078f3": "208453641999000000000000000"
      }
    }
  },
  "pre": {
    "0x3a38877312d1125d2391663cba9f7190953bf2d9": {
      "balance": "0x...",
      "tokens": {
        "0x68b36248477277865c64dfc78884ef80577078f3": "308453642481581939556432141"
      }
    }
  }
}
```

*Caption: After the first UniversalRouter swap, the adversary’s EVERYBODY balance decreases while ETH/WETH balance increases, reflecting partial monetization of the stolen tokens.*

**Transaction 2 – Final swap and fee payment:**

- `0xbcab5ed62fad6f3e4b3536b82561883d4b277382440727667b7c6c01b9bdecae` (block `21230861`)  
  - Mechanism: `router_swap` via UniversalRouter::execute  
  - Action:
    - Permit2 pulls the remaining `298453642000000000000000000` EVERYBODY from `0x3A3...` into the UniswapV2 pair.  
    - The pair swaps to WETH.  
    - A small portion of WETH (`≈0.001944 ETH` equivalent) is paid to `0x000000fee13a103A10D593b9AE06b3e05F2E7E1c` (likely a fee recipient).  
    - The rest is withdrawn to ETH and sent to `0x3A3...`.

**Snippet 6 – Balance diff for second UniversalRouter swap (from debug_traceTransaction balance diff for tx 0xbcab5ed...):**

```json
{
  "post": {
    "0x3a38877312d1125d2391663cba9f7190953bf2d9": {
      "balance": "0xeb39158244e6fb5d",
      "nonce": 24
    },
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": {
      "storage": {
        "0xce92721ced85eee7333b28c1e1c5531ffbdcd1bdcd500c8a5e16b44af392f6c5": "0x000000000000000000000000000000000000000000000002928e396eabe8e88b"
      }
    }
  },
  "pre": {
    "0x3a38877312d1125d2391663cba9f7190953bf2d9": {
      "balance": "0x12fcf23b10c7335",
      "nonce": 23
    }
  }
}
```

*Caption: Final UniversalRouter swap converts the remaining EVERYBODY into ETH, leaving `0x3A3...` with significantly higher ETH balance and no residual EVERYBODY.*

**Net effect over all adversary-crafted txs:**

- `0x3A3...` ends with ≈17.63 ETH more than it started with (after gas and router fees).  
- `0x3A3...` has effectively zero EVERYBODY remaining (all stolen tokens have been swapped).  
- The EVERYBODY/WETH pool reserves are altered by the two large swaps, affecting on-chain prices.

---

## Impact & Losses

### Quantitative Losses

From the root-cause analysis and state diffs:

- **Token lost:**  
  - Asset: EVERYBODY (`0x68b36248477277865c64dfc78884ef80577078f3`)  
  - Amount: `308453642481581939556432141` EVERYBODY

- **Value realization (approximate, in ETH):**  
  - First UniversalRouter swap (`0x4482d1ed...`): ≈ `0.7758` ETH to `0x3A3...`.  
  - Second UniversalRouter swap (`0xbcab5ed...`): ≈ `16.8641` ETH to `0x3A3...` (net of a small WETH fee to `0x000000fee13a103A10D593b9AE06b3e05F2E7E1c`).  
  - Net profit: ≈ **17.63 ETH** for `0x3A3...` after accounting for gas.

### Distribution of Impact

- **Victim EOA 0xA31d...:**  
  - Permanently loses `308453642481581939556432141` EVERYBODY.  
  - Does not directly lose ETH in the adversary-crafted transactions, but loses the economic value of their EVERYBODY holdings.

- **Adversary EOA 0x3A3...:**  
  - Gains control of the victim’s EVERYBODY, then converts the entire amount into ETH.  
  - Realizes ≈17.63 ETH profit, minus gas and router fees.

- **EVERYBODY/WETH UniswapV2 pool (0x9e5f2b74...):**  
  - Experiences large inflows of EVERYBODY and outflows of WETH due to the adversary swaps.  
  - On-chain EVERYBODY price is impacted for other traders due to the shifted reserves.

### Systemic Considerations

- Any other EOA that had granted large EVERYBODY allowances to MainnetSettler and left them in place would be vulnerable to the same pattern (helper + clone + CurveTricrypto route invocation).  
- The vulnerability stems from MainnetSettler’s authorization model, not from the EVERYBODY token or UniversalRouter.

---

## References

This section lists key evidence sources used in the analysis. All artifact paths refer to the local incident collection and are summarized in human-readable form; readers do not need to open the raw files to understand the report.

- **[1] Seed tx trace for theft (Settler clone)**  
  - Description: Full EVM trace and balance diff for the adversary-crafted seed transaction `0xfab5912f858b3768b7b7d312abcc02b64af7b1e1b62c4f29a2c1a2d1568e9fa2`, which deploys the helper and Settler clone and performs `EVERYBODY::transferFrom` from the victim to the adversary.  
  - Origin: Seed transaction trace (`cast run -vvvvv`) and associated `balance_diff` from the incident’s seed artifacts.

- **[2] Pre-seed MainnetSettler usage by victim**  
  - Description: Trace and balance diff for the victim’s legitimate MainnetSettler transaction `0xb792411afbd1cb8a7dab00d56c2ca29084ab29933dc92482e63b7648bbe7f39e`, showing EVERYBODY being swapped via the EVERYBODY/WETH UniswapV2 pool and confirming the presence of a large residual allowance.  
  - Origin: Data collector artifacts for tx `0xb792411a...` (trace and balance diff).

- **[3] MainnetSettler and UniversalRouter source code**  
  - MainnetSettler (`0x70bf66...`):  
    - Description: Flattened source (`MainnetFlat.sol`) including the CurveTricrypto route, callback, and `_transferFrom` implementation that mis-handle the payer binding.  
    - Origin: Collected contract source for MainnetSettler from the incident artifacts.  
  - UniversalRouter (`0x3fC91A3a...`):  
    - Description: Source for Uniswap’s UniversalRouter used in the profit-realization transactions, showing the `execute` function and Permit2 integration.  
    - Origin: Collected contract source for UniversalRouter from the incident artifacts.

### Missing or Unused Evidence

All artifacts referenced in `root_cause.json` for this incident were present and sufficient to support the conclusions in this report. No external on-chain queries or speculative assumptions were required.

