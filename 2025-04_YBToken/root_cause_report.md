# Root Cause Report: YB Treasury Drain via Whitelist-Gated Router on BSC

## Classification

- **Incident type:** Treasury routing / value reallocation within YB ecosystem on BSC
- **ACT status:** **NON-ACT** under the ACT adversary model

## High-Level Summary

On BSC (chainid 56), seed transaction
`0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b`
invokes router `0xbdcd584ec7b767a58ad6a4c732542b026dceaa35`. The router:

1. Takes a Pancake V3 USDT flash loan from pool
   `0x36696169c63e42cd08ce11f5deebbcebae652050`.
2. Repeatedly calls a whitelist-gated function `f3db5490(uint256)` on
   auxiliary / treasury-style contract
   `0x113f16a3341d32c4a38ca207ec6ab109cf63e434`.
3. Routes USDT into YB/USDT AMM pair `0x38231f8eb79208192054be60cb5965e34668350a`,
   triggering YB's fee-on-transfer logic and redistributing value to
   YB-related addresses including `0x81e190f176f7ae69a7afd7bd7eef2354879db5ec`
   and `0x6820f3dfe24cc322bdbe649e40311e5e6e9964b3`.

The Pancake V3 pool is fully repaid principal plus fee, and the seed EOA
`0x00000000b7da455fed1553c4639c4b29983d8538` gains no ERC-20 tokens and pays
only gas. Deterministic net gains accrue to a YB project–controlled address
cluster, not to an independent, unprivileged adversary.

## Impact and Losses

- Contract `0x113f16a3341d32c4a38ca207ec6ab109cf63e434` loses exactly
  **27,647,627.078968518455567 USDT** in the seed transaction, as shown by the
  prestate tracer balance diff.
- USDT balances for the YB/USDT pair `0x38231f8eb79208192054be60cb5965e34668350a`,
  treasury/fee-style addresses including `0x81e190f176f7ae69a7afd7bd7eef2354879db5ec`
  and `0x6820f3dfe24cc322bdbe649e40311e5e6e9964b3`, and a long tail of smaller
  recipients increase by corresponding amounts.
- Pancake V3 pool `0x36696169c63e42cd08ce11f5deebbcebae652050` ends with a
  net **+9.6 USDT** consistent with flash-loan fees and suffers no loss of
  principal.
- The seed sender EOA pays approximately **0.02234924172 BNB** in gas and has
  no positive ERC-20 balance delta.

Downstream price movements and secondary trading behavior outside this address
set are not evaluated; the above impacts are taken directly from on-chain
balance and trace data.

## Reason This Is NON-ACT

Under the ACT adversary model, an ACT opportunity exists only if an
unprivileged adversary can, from a publicly reconstructible pre-state,
construct a permissionless transaction sequence **b** that deterministically
increases the adversary's net portfolio value after fees.

In this incident:

- Calls into `0x113f16a3...::f3db5490` are gated by an internal whitelist.
  Router `0xbdcd584e...` can invoke this function only because it has been
  explicitly whitelisted by the YB project.
- The only addresses with clear net gains (`0x6820...`, `0x81e1...` and the
  YB/USDT pair) are tightly coupled to YB configuration and treasury flows and
  behave as project-controlled infrastructure, not as an independent searcher
  or attacker cluster.
- No sequence of permissionless transactions was identified that allows a
  generic, unprivileged adversary to route value from publicly held liquidity
  or third-party accounts into their own addresses using this mechanism.

Therefore, while the design concentrates a large amount of USDT in a
whitelist-controlled treasury path and allows project-controlled reallocation
through a single call, it **does not** constitute an adversarial contract
threat opportunity under the ACT definition.
