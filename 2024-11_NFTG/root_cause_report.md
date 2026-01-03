# BSC PresaleWithUSDT Flash-Loan Drain via Mispriced Presale Payout

## Incident Overview & TL;DR

On BSC block `44348367`, an unprivileged EOA `0x5af00b07a55f55775e4d99249dc7d81f5bc14c22` deployed a helper contract `0x6deF9e4a6bb9C3bfE0648A11D3FfF14447079e78`, used it to take a large USDT flash loan from a DODO pool, and repeatedly called a USDT-based presale function `Unresolved_85d07203(uint256,address)` (referred to here as `PresaleWithUSDT`) on presale contract `0x5fbbb391d54f4fb1d1cf18310c93d400bc80042e`.  
In each loop, the helper transferred tens of USDT into the presale while the presale immediately paid back nearly an order of magnitude more USDT, resulting in a single-block net drain of approximately **10,044.49 USDT** from the presale to the attacker.

The core root cause is a **mispriced USDT payout path** in the presale’s `PresaleWithUSDT` logic, where Chainlink BNB/USD prices, a presale `salePrice`, and commission settings are combined such that callers can deterministically receive more USDT than they supply.  
No privilege checks or effective caps prevent an arbitrary contract from looping this favorable trade inside a flash-loan transaction.

From a protocol perspective, this is an **ACT opportunity**: a publicly exposed, mispriced presale purchase function that any contract can repeatedly invoke using flash-loaned USDT to extract reserves from the presale with no directional market risk.

## Key Background

- **Presale contract and modes**
  - The victim contract `0x5fbbb3…` on BSC (chainid `56`) is a presale contract that supports:
    - A BNB-based path `Presale(address)` that accepts native BNB.
    - A USDT-based path exposed as `Unresolved_85d07203(uint256,address)` in the ABI, which is treated as `PresaleWithUSDT`.
  - The presale stores a `salePrice`, minimum and maximum buy limits, and commission percentages, and it integrates with a main token contract (via `store_c`) for delivering presale tokens.

- **Oracle and pricing configuration**
  - The presale relies on a Chainlink-style **BNB/USD oracle**:
    - Proxy at `0x0567f2…`
    - Implementation at `0xa6e8f2…`
  - For USDT-related quantities, functions such as `minBuyUSDT()`, `maxBuyUSDT()`, and `Unresolved_85d07203`:
    - Call `latestAnswer()` on the BNB/USD oracle.
    - Multiply the returned 8-decimal price by `0x02540be400` (`10^10`) to lift it to 18-decimal precision for arithmetic with `salePrice` and other 18-decimal values.

- **BNB-based presale path (for context)**
  - The `Presale()` function:
    - Computes the purchased amount as roughly `(msg.value * salePrice) / 1e18`.
    - Applies commissions derived from an internal commission configuration (`unresolved_3a2a034c`).
    - Transfers presale tokens from a main contract to the purchaser, enforcing `minBuy` and `maxBuy` bounds on the BNB sent.
  - This path appears to respect straightforward min/max checks on `msg.value`, and is not directly involved in the exploit.

- **USDT-based min/max and purchase path**
  - The presale tracks a USDT-denominated buying window with `minBuyUSDT()` and `maxBuyUSDT()`, both of which:
    - Read the Chainlink BNB/USD `latestAnswer()`.
    - Multiply the oracle output by `0x02540be400` (`10^10`) and propagate that value into downstream arithmetic.
  - The `Unresolved_85d07203(uint256,address)` (`PresaleWithUSDT`) entrypoint:
    - Begins by reading the same BNB/USD oracle price and applying the same scaling factor.
    - Enforces a Pausable `paused` check, which is **off** during the exploit.
    - Then performs further arithmetic involving the caller-supplied `usdtAmount` and the presale configuration to compute how much USDT to accept and return.

- **Flash-loan liquidity source**
  - The adversary sources USDT from a DODO pool `0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476` via a `flashLoan` call.
  - In the exploit transaction, this provides **825,555.5 USDT** of temporary liquidity, sufficient to execute many iterations of the mispriced presale purchase without the attacker pre-funding USDT.

## Vulnerability & Root Cause Analysis

### High-level vulnerability

The `PresaleWithUSDT` entrypoint on `0x5fbbb3…` allows a caller to provide a USDT amount and receive **more USDT back from the presale than it supplied**.  
The overpayment is deterministic, arising from how Chainlink BNB/USD prices are combined with the presale’s `salePrice` and commission configuration.  
Because the function is permissionless and callable by contracts, an attacker can loop this favorable trade inside a flash loan, draining USDT from the presale’s reserves.

### Misuse of Chainlink BNB/USD price and scaling

Decompiled presale code shows that both `Unresolved_85d07203` and the associated USDT limit functions call `latestAnswer()` on a Chainlink BNB/USD oracle and then multiply the returned value by `0x02540be400` (`10^10`), aligning the 8-decimal oracle to 18 decimals for further arithmetic with presale parameters.

```solidity
/// @custom:selector    0x85d07203
/// @custom:signature   Unresolved_85d07203(uint256 arg0, address arg1) public
function Unresolved_85d07203(uint256 arg0, address arg1) public {
    require(arg0 == arg0);
    require(arg1 == (address(arg1)));
    require(!(bytes1(isPaused / 0x0100...)), "Pausable: paused");
    var_a = 0x50d25bcd00000000000000000000000000000000000000000000000000000000;
    (bool success, bytes memory ret0) = address(store_f / 0x01).latestAnswer(); // Chainlink BNB/USD
    uint256 var_c = var_c + (uint248(ret0.length + 0x1f));
    require(!((var_c + ret0.length) - var_c) < 0x20);
    require(var_f == (var_f));
    require((!var_f) | (0x02540be400 == ((var_f * 0x02540be400) / (var_f))));
    ...
}
```

*Caption: Decompiled `Unresolved_85d07203` (`PresaleWithUSDT`) showing the Chainlink `latestAnswer()` call and the `0x02540be400` scaling, taken from the collected contract source for `0x5fbbb3…` (verified decompilation).*

In the exploit transaction, call traces show `latestAnswer()` consistently returning **`61840939882`**.  
That value, after scaling by `0x02540be400` and combined with `salePrice` and commission parameters, results in a payout formula where each presale iteration sends the caller significantly more USDT than it receives.

### Evidence of mispriced USDT flows per call

The seed transaction trace for the exploit (`tx 0xbd330f…`) clearly demonstrates the per-call imbalance between USDT sent to and paid out from the presale:

```text
Traces:
  ... DPPFlashLoanCall(...)
    ├─ BEP20USDT::transfer(0x5fbBb391d54f4FB1d1CF18310c93d400BC80042E, 110000000000000 [1.1e14])
    ├─ 0x5fbBb391d54f4FB1d1CF18310c93d400BC80042E::85d07203(..., 0x6deF9e4a6bb9C3bfE0648A11D3FfF14447079e78)
    │   ├─ EACAggregatorProxy::latestAnswer()  → 61840939882
    │   ├─ BEP20USDT::transferFrom(0x6deF9e4a6bb9C3bfE0648A11D3FfF14447079e78,
    │   │                          0x5fbBb391d54f4FB1d1CF18310c93d400BC80042E,
    │   │                          76500000000000000000 [7.65e19])
    │   ├─ BEP20USDT::transfer(0x5fbBb391d54f4FB1d1CF18310c93d400BC80042E,
    │   │                      0x6deF9e4a6bb9C3bfE0648A11D3FfF14447079e78,
    │   │                      989635670427665056608 [9.896e20])
    │   ...
```

*Caption: Seed transaction trace (`cast run -vvvv` style) for exploit tx `0xbd330f…`, showing each `PresaleWithUSDT` call pulling **76.5 USDT** from the helper and returning approximately **989.635670427665056608 USDT** back, while reading a Chainlink BNB/USD price of `61840939882`.*

This trace evidences:

- A **flash loan** of `825555500000000000000` (825,555.5 USDT) from the DODO pool to the helper.
- Multiple calls into `0x5fbbb3…::85d07203`, each:
  - `transferFrom` of `76.5` USDT-equivalent from the helper to the presale.
  - `transfer` of about `989.635670427665056608` USDT from the presale to the helper.
- Chainlink `latestAnswer()` returning `61840939882` before each mispriced payout.

### Aggregate USDT flow and presale drain

The state-diff analysis of the exploit transaction aggregates all ERC-20 USDT transfers and shows the cumulative effect on the key actors:

```json
[
  { "token": "0x55d398326f99059ff775485246999027b3197955",
    "from": "0x6098a5638d8d7e9ed2f952d35b2b67c34ec6b476",
    "to":   "0x6def9e4a6bb9c3bfe0648a11d3fff14447079e78",
    "value": "825555500000000000000"
  },
  { "token": "0x55d398326f99059ff775485246999027b3197955",
    "from": "0x6def9e4a6bb9c3bfe0648a11d3fff14447079e78",
    "to":   "0x5fbbb391d54f4fb1d1cf18310c93d400bc80042e",
    "value": "76500000000000000000"
  },
  { "token": "0x55d398326f99059ff775485246999027b3197955",
    "from": "0x5fbbb391d54f4fb1d1cf18310c93d400bc80042e",
    "to":   "0x6def9e4a6bb9c3bfe0648a11d3fff14447079e78",
    "value": "989635670427665056608"
  },
  ...
]
```

*Caption: Extract from the ERC-20 transfer diff for tx `0xbd330f…`, highlighting the DODO → helper flash loan, helper → presale USDT inputs, and presale → helper USDT outputs, from the collected balance-diff artifact for the seed transaction.*

Summing over all USDT transfers in this transaction (including the flash loan repayment) yields:

- **Presale contract `0x5fbbb3…`**: net **−10,044.490614704315622688 USDT**.
- **Attacker EOA `0x5af0…`**: net **+10,044.490614704315622688 USDT**.
- **Helper contract `0x6deF…` + DODO pool `0x6098a5…`**: net approximately **0** USDT (borrowed funds are repaid).

These numbers match the `exploit_predicate` profit calculation and confirm that the mispricing is realized entirely as a **drain from the presale’s USDT reserves to the attacker**, not from the flash-loan provider.

### Vulnerable components

The key vulnerable components identified in the analysis are:

- **Presale contract `0x5fbbb391d54f4fb1d1cf18310c93d400bc80042e` (BSC, chainid 56)**  
  - Specifically the `Unresolved_85d07203(uint256,address)` function (`PresaleWithUSDT`), which accepts a USDT amount and address, and directs the USDT-based purchase path.

- **`minBuyUSDT()` and `maxBuyUSDT()` helper view functions on the same contract**  
  - These functions share the same Chainlink BNB/USD price reading and scaling pattern as `PresaleWithUSDT`, and thus participate in the mispriced USDT-denominated bounds.

- **Interaction with Chainlink BNB/USD oracle (proxy `0x0567f2…`, implementation `0xa6e8f2…`)**  
  - The oracle itself behaves as expected, but its output is **misused** in the presale arithmetic, creating an exploitable payout ratio.

### Exploit conditions

For the exploit to succeed as observed, the following conditions must hold (all are evidenced in the collected traces and state diffs):

- **Presale unpaused**:  
  - The Pausable `paused` check in `Unresolved_85d07203` must pass. Traces show the function executes without reverting, so the contract is not paused during the exploit.

- **Presale funded with USDT**:  
  - The presale must hold sufficient USDT to pay out the inflated returns. The exploit transaction does not mint USDT; all net gain comes from existing presale reserves.

- **Oracle returns a price that overpays given configuration**:  
  - Chainlink BNB/USD `latestAnswer()` returns `61840939882` in the exploit transaction. Combined with the configured `salePrice` and commission parameters, the presale arithmetic produces a payout where each USDT input yields significantly more USDT output.

- **Attacker can source large temporary USDT and loop calls**:  
  - The DODO flash loan provides **825,555.5 USDT** within a single transaction, allowing multiple `PresaleWithUSDT` iterations without pre-funding.

- **No effective buy caps or reentrancy-style guards**:  
  - There are no strict per-transaction or per-address bounds that prevent repeatedly invoking `PresaleWithUSDT` in a single transaction. The traces show many such calls executed back-to-back via the helper contract.

### Security principles violated

- **Conservation of value in presale accounting**  
  - The presale sends more USDT to buyers than it receives, violating the intended invariant that presale reserves should not be a net source of USDT.

- **Correct use of price oracles**  
  - A BNB/USD price feed is used with misaligned scaling and internal configuration, such that the resulting USDT payouts are systematically mispriced in favor of the caller.

- **Defense in depth via limits and caps**  
  - The contract lacks effective per-tx and per-user limits to guard against looping a mispriced payout inside one transaction.

- **Least privilege and exposure minimization**  
  - A highly sensitive pricing path is exposed through a public function callable by any contract, enabling a fully permissionless ACT opportunity.

## Adversary Flow Analysis

### Strategy summary

The adversary follows a standard **flash-loan MEV drain pattern**:

1. Deploy a helper contract that orchestrates the flash loan and presale interactions.
2. Take a large USDT flash loan from DODO.
3. Loop the mispriced `PresaleWithUSDT` function, repeatedly extracting USDT from the presale.
4. Repay the flash loan.
5. Forward the net USDT profit to the attacker EOA.
6. Optionally lock or self-destruct the helper contract.

All of this occurs in block `44348367`, using only publicly callable functions and standard gas, with no special permissions.

### Lifecycle stage 1: Adversary contract deployment

- **Transaction**: `0xe2ad1a84ef3dad3bd1d0ba234d30b99a7961384a4a03284507ab5e8ee626c9e7` (BSC, block `44348367`).  
- **Action**: EOA `0x5af0…` deploys helper contract `0x6deF…`, which:
  - Encodes references to USDT token `0x55d3…`, DODO USDT pool `0x6098a5…`, and presale `0x5fbbb3…`.
  - Implements `flashLoan` callback logic that invokes `PresaleWithUSDT` multiple times and then repays the flash loan.

The transaction-trace log shows the helper’s constructor wiring in these addresses and storing the flash-loan parameters:

```text
Traces:
  [486588] 0x6deF9e4a6bb9C3bfE0648A11D3FfF14447079e78::transfer(0x5fbBb3..., ...)
    ├─ BEP20USDT::approve(0x5fbBb3..., 11579208923731619542357... [~2^256-1])
    ├─ 0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476::flashLoan(..., 825555500000000000000, 0x6deF9e4..., 0x3078)
    ...
```

*Caption: Deployment-related trace showing the helper contract configuring USDT approvals and referencing the DODO pool and presale, from the collected `trace.cast.log` for the deployment transaction.*

The helper’s transaction history around the exploit block corroborates the three key lifecycle transactions:

```json
[
  {
    "hash": "0xe2ad1a84ef3dad3bd1d0ba234d30b99a7961384a4a03284507ab5e8ee626c9e7",
    "blockNumber": "44348367",
    "from": "0x5af00b07a55f55775e4d99249dc7d81f5bc14c22",
    "to": "",
    "value": "0"
  },
  {
    "hash": "0xbd330fd17d0f825042474843a223547132a49abb0746a7e762a0b15cf4bd28f6",
    "blockNumber": "44348367",
    "from": "0x5af00b07a55f55775e4d99249dc7d81f5bc14c22",
    "to": "0x6def9e4a6bb9c3bfe0648a11d3fff14447079e78",
    "value": "0",
    "input": "0x1a6952300000000000000000000000005fbbb3..."
  },
  {
    "hash": "0x1b351d5b197300672d33e79f8cfa7780248900fffa558d0c537195677ae12755",
    "blockNumber": "44348367",
    "from": "0x5af00b07a55f55775e4d99249dc7d81f5bc14c22",
    "to": "0x6def9e4a6bb9c3bfe0648a11d3fff14447079e78",
    "value": "0",
    "input": "0xffffffff000000000000000000000000ca11bde0..."
  }
]
```

*Caption: Helper contract `0x6deF…` transaction list around block `44348367`, showing deployment, the main exploit call into `PresaleWithUSDT`, and the subsequent cleanup transaction (from the collected helper-address txlist artifact).*

### Lifecycle stage 2: Flash-loan setup and presale exploitation

- **Transaction**: `0xbd330fd17d0f825042474843a223547132a49abb0746a7e762a0b15cf4bd28f6` (BSC, block `44348367`).  
- **Action**:
  - The attacker calls the helper, which:
    1. Requests a USDT flash loan of **825,555.5 USDT** from DODO.
    2. Inside the flash-loan callback, repeatedly calls `0x5fbbb3…::PresaleWithUSDT` with a fixed USDT amount per iteration.
    3. After all iterations, repays the flash loan plus fees.
    4. Sends the remaining USDT profit to the attacker EOA `0x5af0…`.

The detailed call trace (see the earlier snippet) shows:

- The DODO pool transferring `825555500000000000000` USDT to the helper.
- Each presale iteration:
  - `transferFrom` of `76500000000000000000` (76.5 USDT) from the helper to the presale.
  - A presale contract call to `85d07203` that pulls the Chainlink BNB/USD price.
  - A `transfer` of `989635670427665056608` USDT from the presale back to the helper.

The balance-diff artifact confirms that when all iterations and the flash-loan repayment are aggregated, the presale loses **10,044.49 USDT**, which ends up at the attacker EOA.

### Lifecycle stage 3: Post-exploit cleanup

- **Transaction**: `0x1b351d5b197300672d33e79f8cfa7780248900fffa558d0c537195677ae12755` (BSC, block `44348367`).  
- **Action**:
  - EOA `0x5af0…` sends a follow-up transaction to the helper with a `0xffffffff` function selector and an argument `0xca11bde0…`, invoking a function labeled `LOCK8605463013()` in the trace.

The trace for this transaction is minimal:

```text
Traces:
  [22191] 0x6deF9e4a6bb9C3bfE0648A11D3FfF14447079e78::LOCK8605463013()
    ├─ storage changes:
    │   @ 0xdeafbeefdeafbeef...: 0 → 0x000000000000000000000000ca11bde0...
    └─ ← [Stop]
Transaction successfully executed.
Gas used: 43623
```

*Caption: Cleanup transaction trace for tx `0x1b351…`, showing a `LOCK…`-style function writing a sentinel value at a `0xdeafbeef…` storage slot, from the collected `trace.cast.log` for the cleanup transaction.*

No further USDT transfers or presale interactions from `0x6deF…` appear in the subsequent blocks in the collected txlist, consistent with the helper being locked or deactivated after the exploit.

## Impact & Losses

### Quantified loss

Based on the ERC-20 transfer diffs for the seed transaction `0xbd330f…`:

- **Token impacted**: `USDT` (`0x55d398326f99059ff775485246999027b3197955` on BSC).  
- **Total net loss from presale**:  
  - `10044490614704315622688` units, i.e., **10,044.490614704315622688 USDT** (assuming 18-decimal representation aligned with the artifact).
- **Total net gain for attacker EOA `0x5af0…`**:  
  - Matching **+10,044.490614704315622688 USDT**.
- **Flash-loan provider and helper**:  
  - DODO pool `0x6098a5…` and helper `0x6deF…` end with net ~0 USDT (borrowed principal plus fees repaid).

### Qualitative impact

- The presale contract’s **USDT reserves are directly depleted**, reducing backing for existing and future presale participants.
- Because the exploit is a purely local arithmetic mispricing (not a one-off mistake in configuration), **any entity able to obtain similar flash-loan liquidity could repeat the exploit** until presale reserves are exhausted or the contract is paused/updated.
- The incident undermines trust in both:
  - The presale’s internal accounting and pricing logic.
  - The protocol’s handling of oracle-based pricing and commission parameters.

## References

Key supporting artifacts used in this analysis (all from the provided root-cause dataset):

- **[1] Seed transaction metadata and balance diffs**  
  - Seed transaction `0xbd330f…` metadata and ERC-20 balance-diff analysis, used to quantify the net USDT movement between the presale, attacker, helper, and DODO pool.

- **[2] Seed transaction trace and call tracer**  
  - `trace.cast`-style transaction trace and `debug_traceTransaction` call-tracer output for tx `0xbd330f…`, used to reconstruct the flash-loan sequence, repeated `PresaleWithUSDT` calls, and precise USDT flows per iteration.

- **[3] Heimdall decompiled presale contract and ABI**  
  - Decompiled Solidity and ABI for presale contract `0x5fbbb391d54f4fb1d1cf18310c93d400bc80042e`, used to identify `Unresolved_85d07203`, `minBuyUSDT`, `maxBuyUSDT`, and the Chainlink `latestAnswer()` usage and scaling.

- **[4] Historical `PresaleWithUSDT` USDT deltas sample**  
  - Historical USDT delta samples for `PresaleWithUSDT`, used to confirm that the observed mispricing is consistent with how the function behaves across transactions, not unique to the exploit.

- **[5] Executor (helper) contract txlist around exploit block**  
  - Historical transaction list for helper contract `0x6deF9e4a6bb9C3bfE0648A11D3FfF14447079e78` around block `44348367`, used to corroborate the deployment, exploitation, and cleanup lifecycle and to verify the absence of post-exploit presale interactions.

All conclusions in this report are directly supported by these artifacts plus the final root-cause JSON analysis; no external on-chain queries beyond the provided dataset were used.

