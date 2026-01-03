# ORAAI & BUBAI LP Drain via Hard‑Wired Drain Contracts

## Metadata

- **Protocol / system:** ORAAI & BUBAI WETH pools on Uniswap V2–style AMMs (Ethereum mainnet)
- **Incident type:** Malicious protocol design / backdoored ERC20 tokens (`protocol_bug` in metadata)
- **Primary assets affected:** WETH reserves in:
  - ORAAI/WETH pair `0x6dabcbd75b29bf19c98a33ecac2ef7d6e949d75d`
  - BUBAI/WETH pair `0x6fade19a644e0ea75539758a7c9dae3dcae119b1`
- **Adversary EOAs:** `0xa60fae100d9c3d015c9cd7107f95cbacf58a1cbd`, `0x420bbc0c936d9811e47e305f56bb9659f063b9ba`
- **Adversary drain contracts:** `0xd15ef15ec38a0dc4da8948ae51051cc40a41959b` (ORAAI), `0xc6eb2dca90db7401f917b852ac9818a15bb9d567` (BUBAI)
- **Key pools / router:** UniswapV2Pair clones for ORAAI/WETH and BUBAI/WETH; router `0x7a250d5630b4cf539739df2c5dacb4c659f2488d` (canonical UniswapV2Router02)

All evidence referenced below comes from the provided `root_cause.json`, seed transaction artifacts, and collected contract source code within the root cause artifact directory; no external on-chain queries were performed.

## ACT Opportunity & Exploitability

### Pre‑state \u03c3\_B (Opportunity Conditions)

The ACT opportunity `pre_state_sigma_B` describes a mainnet state before the profit‑taking drain transactions:

- The ORAAI token (`0xb0f34ba1617bb7c2528e570070b8770e544b003e`) and BUBAI token (`0x88a5705156d73f26e552d591c087b5fa901873d0`) are already deployed with compiled logic that hard‑codes:
  - `_oracex = 0xd15ef15ec38a0dc4da8948ae51051cc40a41959b` inside ORAAI, and
  - `_bubblefund = 0xc6eb2dca90db7401f917b852ac9818a15bb9d567` inside BUBAI.
- UniswapV2‑style pairs hold significant liquidity:
  - ORAAI/WETH: `0x6dabcbd75b29bf19c98a33ecac2ef7d6e949d75d`
  - BUBAI/WETH: `0x6fade19a644e0ea75539758a7c9dae3dcae119b1`
- The special external allowance functions:
  - `ORAAI.stuckToken(address _stuck)`
  - `BUBAI.releaseLimit(address _rel)`
  can be (and in practice are) invoked with `_stuck` / `_rel` set to the LP pair addresses, granting the drain contracts effectively unlimited allowances over the LPs’ token balances.

This pre‑state is evidenced by:

- Seed transaction metadata for the two drain transactions:
  - `seed/1/0x1b4730e7.../metadata.json`
  - `seed/1/0x872fcfcf.../metadata.json`
- Collected token/LP sources:
  - ORAAI `Contract.sol` (token): `data_collector/iter_1/artifacts/contract/1/0xb0f34b.../project/src/Contract.sol`
  - BUBAI `Contract.sol` (token): `data_collector/iter_1/artifacts/contract/1/0x88a570.../project/src/Contract.sol`
  - ORAAI/WETH pair `Contract.sol` (pair clone): `data_collector/iter_1/artifacts/contract/1/0x6dabcbd7.../project/src/Contract.sol`
  - BUBAI/WETH pair `Contract.sol` (pair clone): `data_collector/iter_1/artifacts/contract/1/0x6fade1.../project/src/Contract.sol`

No referenced artifact for this pre‑state was missing; all were present in the provided directories.

### Transaction Sequence b (Exploit Transactions)

The exploit transaction sequence `transaction_sequence_b` contains two adversary‑crafted transactions on Ethereum mainnet:

1. **BUBAI pool drain**
   - Tx: `0x872fcfcfd2e61ab5ec848f5e1a75b75f471bdb8c808c06388434e7179a9e40db`
   - Block: `21073455`
   - From EOA: `0x420bbc0c936d9811e47e305f56bb9659f063b9ba`
   - To drain contract: `0xc6eb2dca90db7401f917b852ac9818a15bb9d567`
   - Call data: selector `0x8c4d1486` with arguments (BUBAI token address, BUBAI/WETH pair address, amount parameter `0x64`)
   - Inclusion feasibility: a standard EOA → contract call with sufficient gas; no special privileges or censorship assumptions.

2. **ORAAI pool drain**
   - Tx: `0x1b4730e715286862042def956d5aaa6a53203ee02b97ea913de73fa462e48f90`
   - Block: `21074246`
   - From EOA: `0xa60fae100d9c3d015c9cd7107f95cbacf58a1cbd`
   - To drain contract: `0xd15ef15ec38a0dc4da8948ae51051cc40a41959b`
   - Call data: selector `0x8c4d1486` with arguments (ORAAI token address, ORAAI/WETH pair address, amount parameter `0x64`)
   - Inclusion feasibility: also a normal EOA → contract call; again, no special privileges needed beyond private‑key control and gas.

Both transactions are easily realizable within ACT’s adversary model: they are single‑transaction calls from unprivileged EOAs to public functions of already‑deployed contracts, paying market gas prices and interacting only with standard ERC20 and UniswapV2 components.

### Exploit Predicate (Profit in ETH)

The `exploit_predicate` is a profit predicate over reference asset **ETH**, evaluated at \u03c3\_B and the post‑transaction states:

- **Reference asset:** ETH
- **Adversary addresses:** EOAs `0x420b...` and `0xa60f...`
- **Values and deltas (from `balance_diff.json`):**
  - For tx `0x872fcfcf...` (BUBAI drain, EOA `0x420b...`):
    - ETH before: `0.67216000758068319`
    - ETH after:  `50.877766494630894545`
    - Delta:      `≈ 50.205606487050211355` ETH
    - Gas fee:    `≈ 0.013037833399143102` ETH
  - For tx `0x1b4730e7...` (ORAAI drain, EOA `0xa60f...`):
    - ETH before: `0.138290092398146532`
    - ETH after:  `68.793428035821014853`
    - Delta:      `≈ 68.655137943422868321` ETH
    - Gas fee:    `≈ 0.005994913076288604` ETH

In both cases, the adversary’s ETH balance increase vastly exceeds gas costs, so the portfolio value in ETH strictly increases over \u03c3\_B → \u03c3′. No off‑chain PnL assumptions are made; the predicate uses only on‑chain ETH balances and gas data from the seed artifacts.

Non‑monetary oracle fields are left empty in `root_cause.json`, so no non‑monetary success condition is asserted for this incident.

## Incident Overview & TL;DR

### High‑Level Summary

- Two ERC20 tokens, **ORAAI** and **BUBAI**, were deployed with **built‑in backdoor allowance functions** that can grant a hard‑wired drain contract unlimited allowance over any holder, including the Uniswap LP contracts for the tokens’ WETH pools.
- The adversary controlled both the EOAs and the drain contracts referenced in these backdoors. After LPs had deposited substantial WETH liquidity, the adversary:
  - Primed the backdoor allowances from the LP contracts to the drain contracts.
  - Called a single drain function per pool from each EOA, causing the drain contract to:
    1. Pull almost all token reserves out of the LP via `transferFrom`.
    2. Call `sync()` on the Uniswap pair so reserves record near‑zero tokens but large WETH.
    3. Swap a fraction of the seized tokens back into the pool via `UniswapV2Router02.swapExactTokensForETHSupportingFeeOnTransferTokens`, extracting a large amount of WETH.
    4. Withdraw WETH to ETH and forward it to the controlling EOA.
- Across the two transactions, the adversary realizes **≈ 118.86 ETH gross**, or **≈ 118.86 ETH – 0.019 ETH ≈ 118.84 ETH net** profit, while leaving LPs with near‑zero WETH and essentially worthless tokens.

### Root Cause (One Sentence)

The root cause is **malicious, hard‑coded allowance backdoors** in the ORAAI and BUBAI ERC20 contracts (`stuckToken` and `releaseLimit`) that let an adversary‑controlled drain contract obtain unbounded spending power over arbitrary addresses, including the LP pair contracts, enabling off‑curve draining of AMM liquidity.

## Key Background

- **Token design:** ORAAI and BUBAI are tax‑style ERC20 tokens on Ethereum mainnet, with familiar patterns (tax wallet, swap‑back to ETH, UniswapV2 router/pair integration) plus additional backdoor allowance functions.
- **Liquidity pools:** ORAAI/WETH and BUBAI/WETH use standard UniswapV2Pair clones; their source and interfaces match the canonical Uniswap V2 design, with `getReserves`, `swap`, and `sync` functions mirroring expected semantics.
- **Router:** The router `0x7a250d56...` is the canonical UniswapV2Router02 instance; traces for both exploit transactions show standard swap and WETH withdraw flows through this router.
- **Trust assumptions violated:** Uniswap LPs typically assume the ERC20 token side of the pair obeys standard allowance semantics, where only the token holder can grant allowances. Here, the token code itself embeds a privileged drain address that can be granted allowance from arbitrary holders, including the LP contract.

## Vulnerability & Root Cause Analysis

### Malicious Allowance Backdoor in ORAAI (`stuckToken`)

In the ORAAI token source, a private address `_oracex` is hard‑coded to the drain contract `0xd15ef15e...`. The public function `stuckToken` unconditionally sets the allowance for `_oracex` from any `_stuck` address to `_maxTxAmount`:

```solidity
// Collected ORAAI token source (Contract.sol)
function stuckToken(address _stuck) external {
    _allowances[_stuck][_oracex] = _maxTxAmount;
}
```

*Caption: ORAAI’s `stuckToken` function gives the hard‑coded drain contract `_oracex` an effectively unlimited allowance from any `_stuck` address, with no access control, enabling it to spend tokens from arbitrary holders, including the ORAAI/WETH LP.*

Key properties:

- Any caller can invoke `stuckToken(_stuck)`.
- `_stuck` can be any address, including the UniswapV2Pair contract `0x6dabcbd7...`.
- `_maxTxAmount` is effectively a large global limit used elsewhere in the token; setting the allowance to this value gives the drain contract near‑unbounded `transferFrom` rights.
- There is no owner check, no restriction to rescue scenarios, and no limitation to EOAs or non‑contract addresses.

Thus, once `stuckToken(0x6dabcbd7...)` is called, the drain contract `0xd15ef15e...` can arbitrarily move ORAAI out of the LP contract using `transferFrom`, completely bypassing normal AMM swap constraints.

### Malicious Allowance Backdoor in BUBAI (`releaseLimit`)

The BUBAI token contains an analogous backdoor via `_bubblefund` and `releaseLimit`:

```solidity
// Collected BUBAI token source (Contract.sol)
function releaseLimit(address _rel) external {
    _allowances[_rel][_bubblefund] = _maxTxAmount;
}
```

*Caption: BUBAI’s `releaseLimit` function mirrors ORAAI’s `stuckToken`, granting the hard‑coded `_bubblefund` drain contract unrestricted allowance from any `_rel` address, including the BUBAI/WETH LP.*

Again:

- Any caller can invoke `releaseLimit(_rel)`.
- `_rel` can be the BUBAI/WETH LP `0x6fade1...`.
- `_bubblefund` is the adversary’s drain contract `0xc6eb2dc...`.

Together, these functions embed a **universal allowance backdoor** into both tokens.

### How the Backdoor Enables Off‑Curve Drains

The UniswapV2Pair clones for ORAAI/WETH and BUBAI/WETH behave as standard AMM contracts and are not themselves vulnerable. The exploit arises because:

1. The LP contracts hold large balances of ORAAI/BUBAI and WETH from user‑provided liquidity.
2. The token backdoor functions grant the adversary drain contracts full `transferFrom` rights over the LP’s token balances.
3. The adversary can use `transferFrom` from the drain contract to:
   - Pull almost all tokens out of the LP contract into the drain contract, while leaving WETH untouched.
   - Call `sync()` so the pair’s stored reserves record near‑zero tokens but high WETH.
4. The adversary then performs a token→WETH swap via the canonical router:
   - Supplying a large token amount into a pool whose recorded token reserve is tiny and WETH reserve is large.
   - Receiving an outsized amount of WETH due to the skewed reserves.

This is **not** a flaw in the AMM math, but a violation of the assumption that the token side cannot independently break conservation via arbitrary `transferFrom` operations from the LP contract.

### Vulnerable Components

From `root_cause.json`:

- ORAAI token `0xb0f34b...`, function `stuckToken(address _stuck)`
- BUBAI token `0x88a570...`, function `releaseLimit(address _rel)`
- Drain contracts `0xd15ef15e...` and `0xc6eb2dc...` as hard‑coded allowance beneficiaries
- UniswapV2Pair LPs:
  - ORAAI/WETH: `0x6dabcbd7...`
  - BUBAI/WETH: `0x6fade1...`

### Exploit Preconditions

The `exploit_conditions` list highlights the concrete conditions required:

- ORAAI and BUBAI must be deployed with `_oracex` and `_bubblefund` set to adversary‑controlled contracts (`0xd15ef15e...`, `0xc6eb2dc...`).
- `stuckToken(lpAddress)` and `releaseLimit(lpAddress)` must be called with the LP pair addresses so that the drain contracts acquire unlimited allowances from the LPs.
- The UniswapV2 LPs must hold substantial WETH so that a manipulated swap still returns significant WETH.
- The adversary must be able to send ordinary EOA transactions to the drain contracts—trivially satisfied on Ethereum.

### Security Principles Violated

- **ERC20 allowance safety:** Allowances are expected to be granted only by the token holder; here, a public function can write allowances on behalf of arbitrary holders to a privileged contract.
- **LP asset isolation:** Liquidity reserves should only move according to AMM swap semantics; enabling an external contract to `transferFrom` LP balances breaks isolation and allows off‑curve drains.
- **Least privilege:** Hard‑coding a single, globally privileged drain contract into the token and giving it universal spend rights violates least‑privilege principles and introduces a catastrophic single point of failure.

## Adversary Flow Analysis

### Adversary Accounts and Contracts

From `adversary_related_accounts`:

- **0xa60fae100d9c3d015c9cd7107f95cbacf58a1cbd (EOA):**
  - Sender of the ORAAI drain tx `0x1b4730e7...`
  - Deployer of drain contract `0xd15ef15e...` (as shown in its address txlist).
- **0x420bbc0c936d9811e47e305f56bb9659f063b9ba (EOA):**
  - Sender of the BUBAI drain tx `0x872fcfcf...`
  - Deployer/user of drain contract `0xc6eb2dc...`.
- **0xd15ef15ec38a0dc4da8948ae51051cc40a41959b (contract):**
  - Drain/executor referenced as `_oracex` in ORAAI’s source.
  - Target of profit‑taking call `0x1b4730e7...`.
- **0xc6eb2dca90db7401f917b852ac9818a15bb9d567 (contract):**
  - Drain/executor referenced as `_bubblefund` in BUBAI’s source.
  - Target of profit‑taking call `0x872fcfcf...`.

Candidate victims are the two LP contracts:

- ORAAI/WETH UniswapV2Pair `0x6dabcbd7...`
- BUBAI/WETH UniswapV2Pair `0x6fade1...`

### Lifecycle Stage 1: Deployment and Liquidity Setup

At this stage:

- EOAs `0xa60f...` and `0x420b...` deploy their respective drain contracts (`0xd15e...`, `0xc6eb...`).
- ORAAI and BUBAI tokens, embedding the backdoor allowance logic, are deployed and integrated with UniswapV2 via the canonical router.
- Liquidity is added to ORAAI/WETH and BUBAI/WETH pools, building up WETH reserves from external LPs.

Evidence for this phase comes from:

- Address‑level transaction lists under `data_collector/iter_1/artifacts/address/1/.../transactions_by_address.json`, which show the deployment and subsequent usage of the drain contracts and tokens.

### Lifecycle Stage 2: Backdoor Allowance Priming

Before the visible drain transactions, `stuckToken` and `releaseLimit` must be called with the LP pair addresses. While those exact calls are not singled out in the seed traces, their effect is implicit and required by the later `transferFrom` flows.

- For ORAAI:
  - A call `stuckToken(0x6dabcbd7...)` must occur, giving `_oracex` (`0xd15e...`) an essentially unlimited allowance from the ORAAI/WETH LP.
- For BUBAI:
  - A call `releaseLimit(0x6fade1...)` must occur, giving `_bubblefund` (`0xc6eb...`) unlimited allowance from the BUBAI/WETH LP.

This is directly supported by the token source snippets above; once these functions are called, the drain contracts can perform the later `transferFrom` operations observed in the seed traces.

### Lifecycle Stage 3: Drain Execution and WETH Extraction

#### BUBAI Drain (Tx `0x872fcfcf...`)

The BUBAI drain transaction starts from EOA `0x420b...` to drain contract `0xc6eb...`, which then drives a sequence of calls that drain the BUBAI/WETH pool:

```text
// Seed transaction trace (cast run -vvvvv) for 0x872fcfcf...
├─ [20968] BUBAI::transferFrom(0x6faDe19a644e0EA75539758A7C9DAe3Dcae119B1, 0xC6EB2dca90db7401f917B852AC9818a15BB9d567, 90306446498140933 [9.03e16])
│   ├─ emit Transfer(from: 0x6faDe19a644e0EA75539758A7C9DAe3Dcae119B1, to: 0xC6EB2dca90db7401f917B852AC9818a15BB9d567, value: 90306446498140933 [9.03e16])
├─ 0x6faDe19a644e0EA75539758A7C9DAe3Dcae119B1::sync()
│   ├─ BUBAI::balanceOf(pair) → 100
│   ├─ WETH9::balanceOf(pair) → 50210823996967103956 [5.021e19]
│   ├─ emit Sync(: 100, : 50210823996967103956)
├─ UniswapV2Router02::swapExactTokensForETHSupportingFeeOnTransferTokens(...)
│   ├─ BUBAI::transferFrom(0xC6EB2dca..., pair, 90306446498140933 [9.03e16])
│   ├─ pair::swap(0, 50210823996967048188 [5.021e19], router, 0x)
│   │   ├─ WETH9::transfer(pair → router, 5.021e19)
│   │   ├─ emit Sync(: 90306446498141033 [9.03e16], : 55768)
│   │   ├─ emit Swap(... amount1Out: 50210823996967048188 [5.021e19], to: router)
```

*Caption: BUBAI drain trace shows the drain contract using its allowance to pull BUBAI from the LP, calling `sync()` to set reserves to `(100 BUBAI, 5.021e19 WETH)`, then swapping BUBAI back into the pool and extracting ≈ 50.21 WETH to the router.*

The associated `balance_diff.json` confirms the WETH and ETH movements:

```json
{
  "chainid": 1,
  "txhash": "0x872fcfcfd2e61ab5ec848f5e1a75b75f471bdb8c808c06388434e7179a9e40db",
  "native_balance_deltas": [
    {
      "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "before_wei": "3036880777568881847838308",
      "after_wei":  "3036830566744884880790120",
      "delta_wei":  "-50210823996967048188"
    },
    {
      "address": "0x420bbc0c936d9811e47e305f56bb9659f063b9ba",
      "before_wei": "672160007580683190",
      "after_wei":  "50877766494630894545",
      "delta_wei":  "50205606487050211355"
    }
  ]
}
```

*Caption: BUBAI drain `balance_diff.json` shows ≈ 50.21 WETH leaving the WETH contract and ≈ 50.21 ETH arriving at EOA `0x420b...` (minus minor builder/MEV fees).*

#### ORAAI Drain (Tx `0x1b4730e7...`)

The ORAAI drain transaction is structurally identical, with EOA `0xa60f...` calling drain contract `0xd15e...`:

```text
// Seed transaction trace (cast run -vvvvv) for 0x1b4730e7...
[238813] 0xD15Ef15e...::8c4d1486(ORAAI, ORAAI/WETH pair, 0x64)
  ├─ ORAAI::approve(UniswapV2Router02, 1.157e77)
  ├─ ORAAI::balanceOf(pair) → 9.469e16
  ├─ ORAAI::transferFrom(pair, 0xD15Ef15e..., 9.469e16)
  │   ├─ emit Transfer(from: pair, to: ORAAI, value: 9.469e14)
  │   ├─ emit Transfer(from: pair, to: 0xD15Ef15e..., value: 9.375e16)
  │   ├─ emit Approval(owner: pair, spender: 0xD15Ef15e..., value: 9.053e17)
  ├─ pair::sync()
  │   ├─ ORAAI::balanceOf(pair) → 100
  │   ├─ WETH9::balanceOf(pair) → 4.593e19
  │   ├─ emit Sync(reserve0: 100, reserve1: 4.593e19)
  ├─ UniswapV2Router02::swapExactTokensForETHSupportingFeeOnTransferTokens(...)
  │   ├─ ORAAI::transferFrom(0xD15Ef15e..., pair, 9.375e16)
  │   ├─ pair::swap(0, 4.593e19, router, 0x)
  │   │   ├─ WETH9::transfer(pair → router, 4.593e19)
  │   │   ├─ emit Sync(reserve0: 9.281e16, reserve1: 49639)
  │   │   ├─ emit Swap(... amount1Out: 4.593e19, to: router)
  │   ├─ WETH9::withdraw(4.593e19) → ETH to 0xD15Ef15e...
```

*Caption: ORAAI drain trace shows the drain contract using its LP allowance to pull ORAAI from the ORAAI/WETH pair, sync reserves to `(100 ORAAI, 4.593e19 WETH)`, then swapping ORAAI for ≈ 45.93–68.66 WETH and withdrawing it to ETH.*

The ORAAI `balance_diff.json` quantifies the ETH profit:

```json
{
  "chainid": 1,
  "txhash": "0x1b4730e715286862042def956d5aaa6a53203ee02b97ea913de73fa462e48f90",
  "native_balance_deltas": [
    {
      "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "before_wei": "3040510854464540238794428",
      "after_wei":  "3040464921843070114390464",
      "delta_wei":  "-45932621470124403964"
    },
    {
      "address": "0xa60fae100d9c3d015c9cd7107f95cbacf58a1cbd",
      "before_wei": "138290092398146532",
      "after_wei":  "68793428035821014853",
      "delta_wei":  "68655137943422868321"
    }
  ]
}
```

*Caption: ORAAI drain `balance_diff.json` shows ≈ 45.93 WETH leaving the WETH contract and ≈ 68.66 ETH arriving at EOA `0xa60f...`, reflecting both swap proceeds and intermediate balances routed via the drain contract.*

Together, these traces and diffs demonstrate:

- The drain contracts rely on pre‑existing LP allowances (granted via the malicious token functions).
- The LP pairs’ token reserves are collapsed to a minimal value (`100` units) while WETH reserves remain large, then suddenly emptied via a swap.
- WETH is withdrawn to ETH and credited to the adversary’s EOA, consistent with the profit predicate.

## Impact & Losses

### Quantified On‑Chain Losses

From `total_loss_overview` and the seed `balance_diff.json` files:

- **WETH via ORAAI/WETH LP (`0x6dabcbd7...`):**
  - Approx. `45.932621470124403964` WETH flows from the LP through the router and into the adversary path in tx `0x1b4730e7...` (as shown by `delta_wei` for WETH in the ORAAI `balance_diff.json`).
- **WETH via BUBAI/WETH LP (`0x6fade1...`):**
  - Approx. `50.210823996967048188` WETH flows from the LP through the router and into the adversary path in tx `0x872fcfcf...`.

Net, the two highlighted drain transactions remove roughly **96.14 WETH** from the ORAAI/WETH and BUBAI/WETH pools and route it, via drain contracts and the UniswapV2 router, into the adversary EOAs.

### Qualitative Impact on Victims and Markets

- **Liquidity providers (LPs):**
  - LPs in the ORAAI/WETH and BUBAI/WETH pools are left holding LP tokens corresponding to pools with **near‑zero WETH** and large balances of tokens whose market value collapses after the drain.
  - The incident functions as a **rug pull**, where the adversary leverages a token‑level backdoor to siphon out the real value (WETH), leaving victims with illiquid or valueless tokens.
- **Token holders:**
  - Non‑LP holders of ORAAI and BUBAI experience a sharp loss of liquidity and likely steep price declines as WETH is removed and AMM pricing breaks.
- **Broader ecosystem:**
  - The incident illustrates how malicious token designs can weaponize standard AMM infrastructure, harming LPs and traders even when the AMM contracts themselves are correct.

No additional losses beyond what is visible in the provided transactions and `balance_diff.json` files are assumed; the report focuses solely on the on‑chain deltas evidenced in the artifacts.

## Remediation Recommendations

### For Token and Protocol Developers

- **Disallow arbitrary third‑party allowance writes:**
  - Avoid any function that writes to `_allowances[holder][spender]` for arbitrary `holder` and `spender`. Only the holder (or a formally authorized entity) should be able to grant allowances.
- **Eliminate hard‑coded privileged addresses:**
  - Do not hard‑code drain or admin addresses into ERC20 contracts, especially where they can bypass normal permission checks. If privileged roles are needed, implement them with transparent, revocable access control and clear published semantics.
- **Restrict “rescue” or “stuck funds” functions:**
  - Functions that move tokens from arbitrary addresses (e.g., “stuck token” helpers) should:
    - Be limited to rescuing from the token contract itself, not arbitrary external addresses.
    - Be gated by multi‑sig or timelocked governance, not public entrypoints.
    - Be clearly documented and audited with explicit threat modeling of LP and AMM interactions.
- **Formalize interactions with AMMs:**
  - When deploying tokens intended for AMM use, explicitly analyze and test for misuse of `transferFrom` from AMM pair addresses, including scenarios where approvals are manipulated or granted by non‑holders.

### For AMM / DEX and Listing Pipelines

- **Strengthen token listing checks:**
  - Implement automated and manual checks on new tokens added to official frontends or recommended liquidity pools to detect:
    - Functions that can grant allowances on behalf of arbitrary holders.
    - Hard‑coded privileged addresses (`_oracex`, `_bubblefund`, etc.) with unclear semantics.
    - Unusual write patterns to `_allowances` or other critical mappings.
- **Flag LP‑drain risk patterns:**
  - Maintain a pattern library for LP‑drain backdoors (like `stuckToken`, `releaseLimit`) and prevent or flag creation of official pools for tokens matching these patterns.

### For Users and LPs

- **Scrutinize token source code before providing liquidity:**
  - Before adding liquidity to a token/WETH pool, review (or rely on audited reviews of) the token’s source for:
    - Any external function that can modify allowances or balances for arbitrary addresses.
    - Hard‑coded “fund”, “drain”, or “rescue” addresses.
- **Prefer audited, well‑known tokens and pools:**
  - Avoid providing significant liquidity to newly deployed, unaudited tokens, especially when they contain non‑standard logic beyond basic tax mechanics.

## References

The following local artifacts underpin the analysis:

- **[1] ORAAI drain seed transaction artifacts**  
  Seed metadata, trace, and balance diffs for tx `0x1b4730e7...` under `seed/1/0x1b4730e7.../`.

- **[2] BUBAI drain seed transaction artifacts**  
  Seed metadata, trace, and balance diffs for tx `0x872fcfcf...` under `seed/1/0x872fcfcf.../`.

- **[3] ORAAI token source and compiled artifacts**  
  Full source and build outputs under `data_collector/iter_1/artifacts/contract/1/0xb0f34b.../project/`.

- **[4] BUBAI token source and compiled artifacts**  
  Full source and build outputs under `data_collector/iter_1/artifacts/contract/1/0x88a570.../project/`.

- **[5] UniswapV2Pair clones for ORAAI/WETH and BUBAI/WETH**  
  Pair sources and artifacts under the respective `project/` directories for `0x6dabcbd7...` and `0x6fade1...`.

- **[6] Address‑level transaction histories**  
  `transactions_by_address.json` under `data_collector/iter_1/artifacts/address/1/` for the adversary EOAs and drain contracts, establishing deployment relationships and repeated usage patterns.

All of the above artifacts were present and readable in the supplied root cause directory; no referenced evidence was missing.

