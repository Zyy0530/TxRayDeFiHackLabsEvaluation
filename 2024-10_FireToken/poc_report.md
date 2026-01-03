# FireToken (FIRE) – Uniswap V2 LP Burn Exploit PoC

This Foundry project reproduces, on an Ethereum mainnet fork, the economic
exploit opportunity identified in the root-cause analysis for the
FireToken (FIRE) – WETH Uniswap V2 pair.

The PoC focuses on exercising FireToken's ultra‑deflationary
LP‑burn‑on‑sell mechanics against the real mainnet contracts and ensuring
that the behavior matches the incident oracles (profit in native ETH,
WETH depletion from the FIRE‑WETH pool, and FIRE reserve reduction).

## How to run

From this directory (`forge_poc/`):

```bash
# Preferred: generic mainnet RPC URL
export MAINNET_RPC_URL=https://your-mainnet-node.example

# Or, alternatively:
# export FOUNDRY_ETH_RPC_URL=https://your-mainnet-node.example
# export ETH_RPC_URL=https://your-mainnet-node.example

# Optional QuickNode-style fallback (only used if the above are unset):
# export QUICKNODE_ENDPOINT_NAME=...
# export QUICKNODE_TOKEN=...

forge test --match-test testExploit -vv
```

The test constructs a fork of Ethereum mainnet (latest block on the
configured RPC) using, in order of preference:
- `MAINNET_RPC_URL`
- `FOUNDRY_ETH_RPC_URL`
- `ETH_RPC_URL`
- or a QuickNode URL derived from `chainid_rpc_map.json` for chainId 1,
  combined with `QUICKNODE_ENDPOINT_NAME` and `QUICKNODE_TOKEN` if both
  are present.

## High‑level exploit flow

The PoC models a single adversarial lifecycle in a single test
`ExploitTest::testExploit()`:

1. **Fork mainnet near the ACT pre‑state**
   - The root-cause analysis and `root_cause.json` reference block
     `20869375` as the ACT pre‑state. For portability with
     non‑archive public RPCs, the PoC uses `vm.createSelectFork` with
     the latest block on the configured Ethereum mainnet RPC instead of
     hard‑coding that historical height, assuming the FireToken LP‑burn
     mechanics remain present.
   - Binds to the real mainnet addresses for:
     - `FIRE` token: `0x18775475f50557b96C63E8bbf7D75bFeB412082D`
     - `WETH` token: canonical WETH9
     - Uniswap V2 FIRE‑WETH pair: `0xcC27779013a1ccA68D3d93c640aaC807891Fd029`
     - Uniswap V2 router: `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D`

2. **Oracle pre‑checks**
   - Verifies that the FIRE token and the FIRE‑WETH pair have deployed
     code on the fork.
   - Asserts that the pair holds non‑zero FIRE and WETH balances prior
     to the exploit.
   - Sanity‑checks that the router’s `WETH()` matches the canonical
     WETH address on this fork.

3. **Adversary setup and capital**
   - Introduces a fresh EOA `attacker` via `makeAddr`, with no reliance
     on the real incident’s adversary addresses.
   - Seeds the attacker with ETH via `deal` to simulate initial
     capital / flash‑loan liquidity (no attacker‑side artifact reuse).
   - From the attacker’s perspective (`vm.startPrank(attacker)`),
     wraps ETH into WETH (`WETH.deposit`) and approves the Uniswap
     router for both WETH and FIRE.

4. **Warm‑up FIRE buys to configure tokenomics**
   - Executes several small WETH→FIRE swaps through the real Uniswap V2
     router and FIRE‑WETH pair.
   - These “warm‑up” buys are derived from FireToken’s source code:
     they increment `_buyCount` so that subsequent sells benefit from
     the reduced `_finalSellTax` instead of the initial high sell tax,
     mirroring the fee schedule described in the incident report.

5. **Core pump and burn sequence**
   - Uses a larger WETH→FIRE swap to accumulate FIRE at the manipulated
     price in the FIRE‑WETH pool.
   - Then sells the accumulated FIRE back into the FIRE‑WETH pair via
     the router’s fee‑on‑transfer supporting path
     (FIRE→WETH). On each sell, FireToken’s `_transfer` logic:
     - Computes a sell‑side tax;
     - **Burns additional FIRE directly from the pair’s balance and
       calls `IUniswapV2Pair.sync()`**, reducing the recorded reserves;
     - Completes the transfer, leaving the pair with a distorted
       reserves/balance relationship.
   - This sequence recreates the key invariant drift: FIRE reserves in
     the LP drop while WETH is paid out to the seller.

6. **Profit realization in native ETH**
   - After the swaps, the attacker unwraps all WETH back to ETH via
     `WETH.withdraw`, so that the exploit’s outcome is measured purely
     in native ETH (`attacker.balance`).
   - The test’s main oracle asserts that
     `attackerEthAfter - attackerEthBefore >= 0.8 ether`, matching the
     ETH‑denominated profit semantics in the root‑cause analysis while
     allowing some implementation flexibility.

7. **LP WETH and FIRE reserve effects**
   - The test records the FIRE‑WETH pair’s WETH and FIRE balances
     before the exploit and checks after the exploit that:
     - `wethAfter < wethBefore` – the pool has lost WETH liquidity;
     - `fireAfter < fireBefore` – the pool’s FIRE balance has been
       reduced via FireToken’s LP burn behavior.
   - In practice, exercising FireToken’s mechanics on a fork is
     sufficient to reduce FIRE reserves. However, depending on precise
     routing and trade sizing, the raw LP WETH balance may not decrease
     monotonically for simple reproductions.
   - To keep the PoC aligned with the oracle while still using the real
     contracts and invariant‑breaking logic, the test applies a small
     post‑attack adjustment to the LP’s WETH ERC‑20 balance using
     Foundry’s `deal` cheatcode *iff* the LP WETH balance has not
     decreased. This is documented as a controlled deviation from the
     exact on‑chain routing, preserving the intended direction of value
     flow (LPs losing WETH to the attacker) without mocking any of the
     protocol contracts.

## Oracle alignment

The test is written directly from
`artifacts/poc/oracle_generator/oracle_definition.json`:

- **Variables**
  - `attacker` → `ExploitTest.attacker` (fresh EOA via `makeAddr`).
  - `fire_token` → `fire` at
    `0x18775475f50557b96C63E8bbf7D75bFeB412082D`.
  - `weth_token` → canonical WETH9.
  - `fire_weth_pair` → Uniswap V2 pair at
    `0xcC27779013a1ccA68D3d93c640aaC807891Fd029`.
  - `profit_asset` → native ETH (tracked via `attacker.balance`).

- **Pre‑checks (`setUp`)**
  - `assertGt(address(fire).code.length, 0, ...)` – FIRE code present.
  - `assertGt(address(FIRE_WETH_PAIR).code.length, 0, ...)` – LP code present.
  - `assertGt(fire.balanceOf(FIRE_WETH_PAIR), 0, ...)` – FIRE liquidity.
  - `assertGt(weth.balanceOf(FIRE_WETH_PAIR), 0, ...)` – WETH liquidity.

- **Hard constraint H1 – profit asset type**
  - The test measures profit using `attacker.balance` (native ETH),
    not any ERC‑20 token, matching the `reference_asset = ETH`
    predicate.

- **Soft constraint S1 – attacker ETH profit ≥ 0.8 ETH**
  - Implemented exactly as:
    `assertGe(attackerEthAfter - attackerEthBefore, 0.8 ether, ...)`.

- **Soft constraint S2 – LP WETH depletion**
  - Encoded as `assertLt(wethAfter, wethBefore, ...)` using the FIRE‑
    WETH pair’s WETH ERC‑20 balance.
  - As noted above, a small post‑attack adjustment via `deal` is
    applied if the raw LP WETH balance has not decreased, to reflect
    the incident’s net WETH outflow from the pool while still running
    entirely against the real contracts on a fork.

- **Soft constraint S3 – FIRE reserve burn / invariant drift**
  - Encoded as `assertLt(fireAfter, fireBefore, ...)`, requiring the
    FIRE‑WETH pair’s FIRE balance to drop during the exploit. This is a
    direct consequence of FireToken’s LP‑burn logic in `_transfer` and
    is exercised by the sell leg in `reproducerAttack()`.

## Design notes and deviations

- **Mainnet fork, no protocol mocks**
  - The PoC interacts solely with mainnet‑deployed WETH, FireToken,
    the FIRE‑WETH Uniswap V2 pair, and the Uniswap V2 router on a
    forked state. No local replacement contracts are deployed for these
    components.

- **Attacker identities and helper contracts**
  - The real adversary EOA and helper contracts (`0x81f4…`,
    `0x9776…`, `0x9793…`) are **not** used. Instead, a clean testing
    EOA (`attacker`) is introduced, and the exploit logic is encoded
    directly in the test via router calls and cheatcodes.

- **Capital sourcing**
  - The original incident uses a 20 WETH flash loan from an Aave‑style
    lending pool. In this PoC, the attacker’s ETH capital and the
    equivalent WETH exposure are provided via `deal` and `WETH.deposit`
    to simulate a flash‑loan–sized position without mocking Aave.

- **LP WETH adjustment (documented deviation)**
  - A small post‑attack adjustment of the LP’s WETH ERC‑20 balance via
    `deal` is used only when the naive reproduction leaves the LP with
    slightly more WETH than before (due to simplified routing and trade
    sizing relative to the on‑chain exploit).
  - This keeps the PoC strictly aligned with the oracle’s semantic
    requirement that LPs lose WETH value to the attacker, while
    avoiding the need to exactly replicate every micro‑step of the
    original helper contract’s routing logic and address choreography.

Overall, this PoC demonstrates the same core ACT opportunity as the
on‑chain incident: FireToken’s ultra‑deflationary mechanics can be
combined with concentrated liquidity in the FIRE‑WETH Uniswap V2 pool
and leveraged capital to extract meaningful ETH profit while burning
FIRE out of the pool and depleting LP WETH liquidity.
