## Incident Overview TL;DR

On BNB Chain (chainid 56), an unprivileged attacker EOA `0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c` used three helper contracts to call unsafe public functions in unverified Venus‑integrated strategy contracts `0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c` and `0xb5cb0555c0c51e603ead62c6437da65372e4e1b0`.  
These functions transferred the strategies’ entire vToken and underlying‑token balances into attacker‑controlled positions. The attacker then redeemed the vTokens on Venus to obtain underlying assets and BNB, leaving the strategies effectively empty while Venus core components behaved according to their documented semantics.  
The root cause is a protocol‑level bug in the `0xb5cb0555…` strategy contracts: they expose publicly callable draining logic that moves strategy‑held vTokens and underlying tokens to arbitrary recipients without enforcing any access control.

## Key Background

- Venus on BNB Chain uses a proxy pattern where `Unitroller` holds storage and delegates calls to a Comptroller implementation (a Diamond‑style controller at `0x347ba9559ffc65a94af0f6a513037cd4982b7b18`). The Comptroller facets enforce market, collateral, and reward accounting and gate vToken transfers and redeems via `transferAllowed` and `redeemAllowed` hooks.  
- The unverified `0xb5cb0555…` strategy contracts act as aggregator‑like strategies: they deposit user funds into Venus markets via vTokens (vUSDT, vUSDC, vBTC, vETH, VBNB) and periodically rebalance token exposure using DEXes such as PancakeSwap v2/v3 and Algebra/Thena pools.  
- Helper contracts created by EOAs can freely call public functions on these strategies. If those functions lack access control, any unprivileged searcher can run them as part of a permissionless ACT (anyone‑can‑take) opportunity.

At ACT pre‑state `σ_B`, defined as BNB Chain state at block `52052493` immediately before helper transaction `0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44`, the strategy contracts `0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c` and `0xb5cb0555c0c51e603ead62c6437da65372e4e1b0` hold large balances of vTokens and corresponding underlying tokens for their users. This is evidenced by the seed transaction metadata and balance diffs:

```json
// Seed helper tx metadata and balance diff (excerpt)
{
  "txhash": "0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44",
  "blockNumber": "52052493",
  "from": "0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c",
  "to": null,
  "contractAddress": "0xC269cd69CcCB1BBEDB44f93c612905219F424c11",
  "decoded_roles": ["attacker-helper-deploy"],
  "balance_diff_summary": "strategy vToken balances drop to zero; attacker receives those vTokens"
}
```

Pre‑incident management calls such as `getRich()` and `printMoney()` into the `0xb5cb0555a1…` strategy show complex but permissionless DEX routing that rebalances positions without breaking Venus invariants:

```bash
# Seed trace for pre-incident getRich/printMoney call (excerpt)
Traces:
  [518133] 0xB5CB0555A1D28C9DfdbC14017dae131d5c1cc19c::40e5c1ee(...)
    ├─ PancakePair::getReserves()
    ├─ PancakeV3Pool::slot0()
    ├─ AlgebraPool::globalState()
    ├─ WBNB::balanceOf(0xB5CB0555A1D28C9DfdbC14017dae131d5c1cc19c)
    ├─ WBNB::transfer(PancakePair: [...])
    ├─ PancakePair::swap(...)
    ├─ AlgebraPool::swap(...)
    └─ WBNB::transfer(0xB5CB0555A1D28C9DfdbC14017dae131d5c1cc19c, ...)
```

These traces confirm that the management functions are permissionless and perform DEX swaps but do not themselves manipulate Venus controller storage outside documented transfer/redeem flows.

## Vulnerability Analysis

The vulnerability lies entirely in the design of the unverified Venus‑integrated strategy contracts `0xb5cb0555a1…` and `0xb5cb0555c0…`, and in the associated management contract `0xB5CB0555c4A333543DbE0b219923C7B3e9D84a87` on BNB Chain.

Disassembly and runtime bytecode for `0xb5cb0555c0c51e603ead62c6437da65372e4e1b0` show a dispatcher that exposes multiple public functions, including a selector `0x0243f5a2` that is reachable via the management contract’s `printMoney()` entrypoint:

```bash
// Strategy 0xb5cb0555c0… disassembly (excerpt)
00000000: PUSH1 0x80
00000002: PUSH1 0x40
00000004: MSTORE
...
000000fc: JUMPDEST
000000fd: DUP1
000000fe: PUSH4 0x0243f5a2
00000103: EQ
00000104: PUSH2 0x02df
00000107: JUMPI
...
```

Analysis of this function and surrounding logic (from the runtime bytecode and disassembly under  
`artifacts/root_cause/data_collector/iter_3/contract/56/0xb5cb0555c0c51e603ead62c6437da65372e4e1b0/`) shows that:

- The strategy holds user positions in vTokens such as vUSDT, vUSDC, vBTC, vETH, and VBNB.  
- It exposes functions that, when called, can transfer the contract’s entire vToken or underlying‑token balances to an arbitrary recipient specified by the caller.  
- There is no owner‑only or role‑based access control gating these draining paths; they are publicly callable.

The companion strategy `0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c` exposes analogous logic for directly transferring underlying BEP20 tokens (e.g., BEP20Ethereum, BEP20USDT, BscTrueUSD, BTCB, USDC‑like, StablecoinV2) to a caller‑chosen recipient.

The management contract `0xB5CB0555c4A333543DbE0b219923C7B3e9D84a87` provides a user‑facing entrypoint `printMoney()` that forwards to the vulnerable draining functions on the strategy contracts. Because `printMoney()` itself is also publicly callable, any unprivileged EOA can route through it into the draining paths.

By contrast, the Venus controller stack operates as intended. The `Unitroller` proxy delegates to the Diamond‑based Comptroller implementation at `0x347ba9559ffc65a94af0f6a513037cd4982b7b18`, which exposes standard vToken interfaces and hooks:

```json
// Comptroller/Unitroller compiled interfaces (excerpt)
{
  "contracts": {
    "Unitroller.sol:Unitroller": { "...": "..." },
    "VToken.sol:VToken": { "abi": [ { "name": "transferAllowed", "...": "..." }, { "name": "redeemAllowed", "...": "..." } ] }
  }
}
```

Observed traces show `PolicyFacet::transferAllowed` and `redeemAllowed` being called and returning successfully when the strategies transfer vTokens or the attacker redeems them. There is no evidence of incorrect Venus accounting or unauthorized underlying transfers originating from the controller itself. Venus simply enforces its usual rules for suppliers and borrowers; the bug is that the strategy contracts voluntarily assign their vTokens and underlying tokens to the attacker.

In summary, the vulnerability is:

- **Component**: Venus‑integrated strategy contracts `0xb5cb0555a1…` and `0xb5cb0555c0…` plus management contract `0xB5CB0555c4A333543DbE0b219923C7B3e9D84a87`.  
- **Bug**: Publicly callable draining functions that can move all strategy‑held vTokens and underlying tokens to an arbitrary recipient.  
- **Missing control**: No access control or authorization check to restrict who can invoke these draining paths.

## Detailed Root Cause Analysis

### ACT Pre‑State and Opportunity

At pre‑state `σ_B` (BNB Chain, block `52052493`), the strategy contracts hold large balances of:

- vTokens: vUSDT, vUSDC, vBTC, vETH, VBNB.  
- Underlying tokens: BEP20Ethereum, BEP20USDT, BscTrueUSD, BTCB, USDC‑like stablecoins, StablecoinV2, KogeToken, CakeToken, BUSD, and others.

This is captured by the seed transaction metadata and balance diff for `0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44` and corroborated by pre‑incident management traces into `0xb5cb0555a1…`:

```bash
# Representative pre-incident strategy trace (excerpt)
Traces:
  [518133] 0xB5CB0555A1D28C9DfdbC14017dae131d5c1cc19c::40e5c1ee(...)
    ├─ PancakePair::getReserves() [staticcall]
    ├─ PancakeV3Pool::liquidity() [staticcall]
    ├─ AlgebraPool::globalState() [staticcall]
    ├─ WBNB::transfer(PancakePair: [...], 4704636884108740)
    ├─ PancakePair::swap(...)
    ├─ AlgebraPool::swap(...)
    └─ WBNB::transfer(0xB5CB0555A1D28C9DfdbC14017dae131d5c1cc19c, 4792230690500639)
```

These traces show permissionless strategy‑level rebalancing logic that relies on external DEX liquidity but does not directly alter Venus controller invariants.

### Exploit Transaction Sequence `b`

From `σ_B`, the adversary executes a deterministic ACT transaction sequence `b` composed of three helper deployments and a set of vToken redeem transactions:

1. **Helper deployment and vToken drain – `0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44` (block `52052493`)**  
   - Attacker EOA `0xd5c6…` deploys helper contract `0xC269cd69CcCB1BBEDB44f93c612905219F424c11`.  
   - The helper calls management contract `0xB5CB0555c4A333543DbE0b219923C7B3e9D84a87::printMoney()`, which routes into selector `0x0243f5a2` on strategy `0xb5cb0555c0c51e603ead62c6437da65372e4e1b0`.  
   - Inside this call, the strategy invokes `VBep20Delegator.transfer` on vTokens:
     - `0xfd5840cd36d94d7229439859c0112a4185bc0255` (vUSDT)  
     - `0xeca88125a5adbe82614ffc12d0db554e2e2867c8` (vUSDC‑like)  
     - `0xf508fcd89b8bd15579dc79a6827cb4686a3592c8` (vBTCB)  
     - `0x882c173bc7ff3b7786ca16dfed3dfffb9ee7847b` (vETH‑like)  
   - For each vToken, `from` is the strategy `0xb5cb0555c0…` and `to` is the attacker EOA `0xd5c6…`.  
   - The Venus controller (Unitroller delegating to `0x347ba9…`) processes `PolicyFacet::transferAllowed` calls, emitting `DistributedSupplierVenus` events and allowing the transfers because both addresses are treated as ordinary suppliers.  
   - The balance diff `artifacts/root_cause/seed/56/0x7708aa…/balance_diff.json` shows the strategy’s vToken balances dropping to zero and the attacker gaining the same vToken amounts.

2. **Helper deployment and underlying‑token drain – `0x8c026c3939f7e2d0376d13e30859fa918a5a567348ca1329836df88bef30c73e` (block `52052680`)**  
   - The same attacker EOA deploys helper `0x7C2565b563E057D482be2Bf77796047E5340C57a`.  
   - The helper interacts with strategy `0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c`, querying its underlying balances and then causing direct ERC20 transfers from the strategy to the attacker.  
   - Tokens drained include:
     - `0x2170ed0880ac9a755fd29b2688956bd959f933f8` (BEP20Ethereum / wrapped ETH)  
     - `0x55d398326f99059ff775485246999027b3197955` (BEP20USDT)  
     - `0x40af3827f39d0eacbf4a168f8d4ee67c121d11c9` (BscTrueUSD)  
     - `0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c` (BTCB)  
     - `0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d` (USDC‑like stablecoin)  
     - `0xc5f0f7b66764f6ec8c8dff7ba683102295e16409` (StablecoinV2).  
   - The corresponding balance diff shows each of these token balances for `0xb5cb0555a1…` dropping from non‑zero to zero, while the attacker’s balances increase by exactly the same amounts.

3. **Third helper and additional drains – `0xf9025e317ce71bc8c055a511fccf0eb4eafd0b8c613da4d5a8e05e139966d6ff` (block `52053062`)**  
   - A third helper contract created by `0xd5c6…` interacts with vTokens including:
     - `0xa07c5b74c9b40447a954e1466938b865b6bbea36` (VBNB)  
     - `0xeca88125a5adbe82614ffc12d0db554e2e2867c8` (VBep20Delegator, USDC‑like)  
     - `0x882c173bc7ff3b7786ca16dfed3dfffb9ee7847b` (vETH‑like)  
   - It also drains underlying tokens such as:
     - `0xe6df05ce8c8301223373cf5b969afcb1498c5528` (KogeToken)  
     - `0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82` (CakeToken)  
     - `0xe9e7cea3dedca5984780bafc599bd69add087d56` (BUSD).  
   - Balance diffs for this transaction confirm strategy balances falling toward zero and attacker balances rising correspondingly, including BNB obtained via VBNB.

4. **Redeem transactions and profit realization – `0x2213e78f…`, `0x6bcaf243…`, `0x90cf871e…`, `0x70b2eb1a…`, `0x9526a215…`**  
   - After consolidating vTokens from the strategies, the attacker executes a series of vToken redeem transactions using standard Venus interfaces.  
   - These transactions convert the vTokens into underlying assets and additional BNB, further increasing the attacker’s token and native balances while leaving the strategies’ positions empty.  
   - The traces in `artifacts/root_cause/data_collector/iter_2/tx/56/*/trace.cast.log` and corresponding `balance_diff.prestate_tracer.json` files show vToken balances on `0xd5c6…` decreasing to zero and underlying token balances increasing by matching amounts.

The consolidated attacker profit is captured by the balance‑change aggregation:

```json
// Attacker profit estimate (excerpt)
{
  "chainid": 56,
  "attacker": "0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c",
  "native_delta_wei": "1225082628931509965365",
  "erc20_deltas_raw": {
    "0x2170ed0880ac9a755fd29b2688956bd959f933f8": "70167761779861972034",
    "0x55d398326f99059ff775485246999027b3197955": "422559719328979182049334",
    "0x40af3827f39d0eacbf4a168f8d4ee67c121d11c9": "4253611958524052045623",
    "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c": "3008595449505912147",
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": "207614516941641936060441",
    "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409": "1523817415577564055735",
    "0xe6df05ce8c8301223373cf5b969afcb1498c5528": "363924239113942121542",
    "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82": "4439768743215238075224",
    "0xe9e7cea3dedca5984780bafc599bd69add087d56": "3688064818698799499583"
  },
  "native_delta_bnb": "1225.082628931509965365"
}
```

Even ignoring any approximate USD valuation fields, the raw token and BNB deltas are strictly positive across multiple assets, establishing a deterministic profit for the attacker under the standard ACT adversary model.

### Root Cause Summary

Putting these elements together:

- At `σ_B`, the strategies hold large user‑funded positions in Venus vTokens and underlying tokens.  
- The strategies and their management contract expose public functions that can transfer these positions to any recipient specified by the caller.  
- An unprivileged EOA deploys helper contracts that call these public draining functions, substituting the attacker’s address as the recipient.  
- Venus correctly processes the resulting vToken transfers and redeem operations, as the attacker is a valid supplier in the protocol.  
- No access control or authorization checks prevent this behavior.  

The deterministic ACT opportunity is therefore: from `σ_B` (block `52052493`), apply transaction sequence `b` consisting of:

- The three helper deployments (`0x7708aa…`, `0x8c026c…`, `0xf9025e…`) that drain vTokens and underlying tokens from the strategies to the attacker.  
- The subsequent vToken redeem transactions (`0x2213e7…`, `0x6bcaf2…`, `0x90cf87…`, `0x70b2eb…`, `0x9526a2…`).  

This sequence leads deterministically to post‑state `σ_B'`, where the strategies’ relevant balances are near‑zero and the attacker holds those assets plus extra BNB, having paid only gas.

## Adversary Flow Analysis

### Adversary Strategy Summary

The adversary executes a two‑phase, single‑chain strategy:

1. **Draining phase** – Deploy helper contracts that call public draining functions on the `0xb5cb0555…` strategies, transferring their vToken and underlying‑token balances into attacker‑controlled positions.  
2. **Realization phase** – Redeem the acquired vTokens on Venus, converting them into underlying tokens and BNB and consolidating profit in the attacker EOA.

### Adversary-Related Accounts

- **Attacker EOA**  
  - Chain: BNB Chain (`56`)  
  - Address: `0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c`  
  - Role: Origin of all three helper deployments and the subsequent redeem transactions; receives drained vTokens and underlying tokens per balance diffs.

- **Helper Contracts**  
  - `0xC269cd69CcCB1BBEDB44f93c612905219F424c11` – Deployed in `0x7708aa…`; calls `printMoney()` and routes into selector `0x0243f5a2` on `0xb5cb0555c0…`, causing vToken transfers to the attacker.  
  - `0x7C2565b563E057D482be2Bf77796047E5340C57a` – Deployed in `0x8c026c…`; invokes strategy logic on `0xb5cb0555a1…` to transfer underlying‑token balances to the attacker.  
  - A third helper (address from `0xf9025e…`) – Further drains vTokens and underlying tokens, including via VBNB and tokens KogeToken, CakeToken, and BUSD.

- **Victim Strategy Contracts**  
  - `0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c` – Unverified Venus‑integrated strategy holding user funds and exposing public functions that transfer underlying‑token balances to arbitrary recipients.  
  - `0xb5cb0555c0c51e603ead62c6437da65372e4e1b0` – Unverified Venus‑integrated strategy holding user funds and exposing public functions that transfer its vToken and underlying‑token balances to arbitrary recipients.

### Adversary Lifecycle Stages

1. **Helper Deployment and Initial Drains**  
   - Transactions:
     - `0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44` (block `52052493`)  
     - `0x8c026c3939f7e2d0376d13e30859fa918a5a567348ca1329836df88bef30c73e` (block `52052680`)  
     - `0xf9025e317ce71bc8c055a511fccf0eb4eafd0b8c613da4d5a8e05e139966d6ff` (block `52053062`)  
   - Mechanism: `contract_deploy_and_strategy_call`.  
   - Effect: Helper contracts deployed by `0xd5c6…` invoke public draining functions in the `0xb5cb0555…` strategy cluster, transferring the strategies’ vToken and underlying‑token balances into attacker‑controlled addresses.  
   - Evidence: `artifacts/root_cause/seed/56/*/trace.cast.log`, `artifacts/root_cause/seed/56/*/balance_diff.json`, and strategy runtime bytecode/disassembly under `artifacts/root_cause/data_collector/iter_3/contract/56/0xb5cb0555a1…` and `…/0xb5cb0555c0…`.

2. **vToken Redeems and Profit Realization**  
   - Transactions:
     - `0x2213e78f56da2b4188b14701623459fa5e4cb0ab00b11ac2ea2359c9488eca9b` (block `52052493`)  
     - `0x6bcaf243d9b44433613841dc7d129c6aaed7172a7fe14549eab087afe688ef9f` (block `52052680`)  
     - `0x90cf871e3a84457192c575e2386cfa9d9ba240f1de9219824a1c253e3fced61e` (block `52053062`)  
     - `0x70b2eb1a1e910180f2b8e934e525e4230331b83f0dc1d91395adea642f3d0daa` (block `52053062`)  
     - `0x9526a2157e361066f3f2a36746925777ad32338f30ac68ce4b1605e495a8f01a` (block `52053062`)  
   - Mechanism: `redeem` via public Venus vToken interfaces.  
   - Effect: The attacker redeems the vTokens obtained from the drained strategies into underlying tokens and BNB, consolidating profit on EOA `0xd5c6…` while the victim strategies’ balances fall to near‑zero.  
   - Evidence: `artifacts/root_cause/data_collector/iter_2/tx/56/*/trace.cast.log` and `artifacts/root_cause/data_collector/iter_3/tx/56/*/balance_diff.prestate_tracer.json`, plus Venus controller artifacts under `artifacts/root_cause/data_collector/iter_3/contract/56/0x347ba9559ffc65a94af0f6a513037cd4982b7b18/source`.

## Impact & Losses

The incident results in a large, multi‑token loss for users of the `0xb5cb0555…` Venus‑integrated strategies on BNB Chain:

- The strategies’ balances in key vTokens and underlying tokens (USDT, USDC‑like, BscTrueUSD, BTCB, KogeToken, CakeToken, BUSD, wrapped ETH, and related assets) drop from large non‑zero values to near‑zero, as recorded in the victim strategy balance diffs referenced in the seed and data collector artifacts.  
- The attacker EOA `0xd5c6…` accumulates those assets along with a strictly positive amount of BNB after gas, as shown by the consolidated profit estimate `profit_estimate_cluster_eoa_only.json`.  
- Venus itself remains solvent and continues to enforce its standard rules; losses are borne entirely by users who deposited into the misdesigned strategies.

Aggregated impact in reference‑asset terms is intentionally not encoded as a single scalar field in `root_cause.json`. Instead, the on‑disk artifacts provide reproducible per‑token and BNB deltas that quantify the loss and the attacker’s profit at the token level.

## References

Key supporting artifacts for this analysis are:

1. **Seed helper transaction metadata, traces, and balance diffs**  
   - `artifacts/root_cause/seed/56/0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44/metadata.json`  
   - `artifacts/root_cause/seed/56/0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44/balance_diff.json`  
   - `artifacts/root_cause/seed/56/0x7708aaedf3d408c47b04d62dac6edd2496637be9cb48852000662d22d2131f44/trace.cast.log`  
   - Analogous artifacts for `0x8c026c3939f7e2d0376d13e30859fa918a5a567348ca1329836df88bef30c73e` and `0xf9025e317ce71bc8c055a511fccf0eb4eafd0b8c613da4d5a8e05e139966d6ff`.

2. **Attacker redeem transaction traces and balance diffs**  
   - `artifacts/root_cause/data_collector/iter_2/tx/56/*/trace.cast.log`  
   - `artifacts/root_cause/data_collector/iter_3/tx/56/*/balance_diff.prestate_tracer.json`.

3. **Venus Unitroller/Comptroller implementation source and compiled artifacts**  
   - `artifacts/root_cause/data_collector/iter_3/contract/56/0x347ba9559ffc65a94af0f6a513037cd4982b7b18/source`.

4. **Strategy runtime bytecode, disassembly, and ABI analysis**  
   - `artifacts/root_cause/data_collector/iter_3/contract/56/0xb5cb0555a1d28c9dfdbc14017dae131d5c1cc19c`  
   - `artifacts/root_cause/data_collector/iter_3/contract/56/0xb5cb0555c0c51e603ead62c6437da65372e4e1b0`.

5. **Attacker profit estimate (token and BNB deltas)**  
   - `artifacts/root_cause/data_collector/iter_3/address/56/0xd5c6f3b71bcceb2ef8332bd8225f5f39e56a122c/profit_estimate_cluster_eoa_only.json`.

Together, these artifacts provide a fully reconstructible, evidence‑backed explanation of the incident’s root cause, exploit flow, and impact under the ACT adversary model.

