# BNB Chain Mispriced Deposit Mint via Hard-Coded BNB Price

## ACT Classification

- **is_act:** false (not proven ACT)
- **Rationale:** The incident clearly involves an adversarial EOA exploiting a severe pricing and minting bug to extract ~2.16M USDT from a PancakeSwap WBNB/USDT pool using only ~1 BNB. However, based on available evidence we cannot show that the deposit entrypoint into the helper/aggregator stack is fully permissionless for arbitrary unprivileged EOAs. The safest conclusion is that this is a serious protocol bug and economic exploit, but **not a proven ACT opportunity** in the strict sense of an unprivileged adversary opportunity defined over public pre-state.

## High-Level Summary

On BNB Chain, EOA `0xb32a53af...` deployed router contract `0x631adff0...` and then executed a single transaction that:

1. Sent **1 BNB** to the router.
2. Wrapped **0.001 BNB** into WBNB and called helper `0x95e92b0...::deposit(WBNB, 10^15)`.
3. Routed the deposit through aggregator `0x637d8c...`, pricing helper `0x4cbbb1...`, pricing implementation `0xb9d3bb...`, and ERC1967 proxy `0x0dfb6a...` (implementation `0xB1C4605f...`).
4. Minted roughly **9.73e33 share tokens** to the router.
5. Swapped **3e25 share tokens** against PancakeSwap pool `0xb5252fce...` to receive about **2.16M BEP20USDT** at the expense of pool liquidity providers.
6. Forwarded the remaining **0.999 BNB** to a secondary address `0x1266c6...`.

The EOA thus turned ~1 BNB into ~2.16M USDT in a single block.

## Root Cause

The core technical root cause is a **misdesigned pricing and minting stack**:

- Pricing implementation `0xb9d3bb...::getBNBPriceInUSDT` reads a WBNB/USDT PancakePair but, per decompilation, returns a **hard-coded constant `500e18`** as the BNB price in USDT, independent of pool reserves or token decimals.
- The deposit path `0x95e92b0... -> 0x637d8c... -> 0xb9d3bb... -> 0x0dfb6a...` treats this constant price as authoritative when computing how many share tokens to mint for a given WBNB deposit.
- For the exploit tx, a **0.001 BNB** deposit is valued as though it were worth an enormous amount of USDT, causing the system to mint **astronomically more share tokens** than is economically justified.
- There appear to be **no effective caps or sanity checks** on share issuance relative to real collateral or external market prices.
- The minted share token is freely tradable and is dumped into a real PancakeSwap USDT pool, converting the over-minted internal accounting token into real USDT.

In short, the system hard-codes an unrealistic BNB price and fails to bound share-token issuance, enabling an attacker with access to the deposit entrypoint to manufacture overvalued shares and sell them into external liquidity.

## Why This Is Not Proven ACT

Under the ACT framework, an incident is an ACT only if an unprivileged adversary, using public information and standard inclusion rules, could construct a transaction sequence `b` over a public pre-state `σ_B` that satisfies a profit or safety predicate.

From the collected evidence and the analyzer’s latest iteration:

- We **do** have:
  - A clear economic exploit in a single profit tx.
  - Decompilation of the key pricing implementation `0xb9d3bb...` showing the hard-coded price.
  - Traces and balance diffs confirming the size of the share mint and USDT payout.
  - Identification of the adversary cluster (EOA `0xb32a53af...` and router `0x631adff0...`).
- We **do not yet have**:
  - A complete, verified view of the **access control / role gating** on helper `0x95e92b0...`, aggregator `0x637d8c...`, proxy `0x0dfb6a...`, and share implementation `0xB1C4605f...` to show that any arbitrary EOA could invoke the same deposit path.
  - A rigorous proof, from verified source rather than decompilation alone, of the exact share-mint formula and its invariants.

Because these gaps remain, we cannot certify that an **unprivileged** adversary starting from a public pre-state could necessarily reproduce the exploit; the deposit path might rely on special roles or operator misconfiguration. Therefore the report conservatively classifies the incident as a **protocol bug with adversarial exploitation, but not a proven ACT opportunity**.

## Key Evidence

- Seed tx trace and balance diffs: `artifacts/root_cause/seed/56/0x2a65...a150/`.
- Decompilation of pricing contract `0xb9d3bb...`: `artifacts/root_cause/data_collector/iter_2/contract/56/0xb9d3bb.../decompile/...-decompiled.sol`.
- EOA and router tx histories around the incident block from Etherscan v2 API.

