# Andy token approval-drain via malicious swap helper

## TL;DR

A victim EOA `0x382f…2ba1` granted an unlimited approval for the Andy (ANDY) token to an executor contract `0xDf31…cfd0f`. An adversary EOA `0xc31a…c649` later routed a transaction through a swap-helper stack to use that allowance, pulling roughly `8.84e22` ANDY out of the victim, swapping it to WETH on a Uniswap V2 pool, and unwrapping to about `0.0011` ETH that was paid to the attacker. There is no bug in the Andy ERC‑20 implementation or Uniswap; the loss is an approval‑drain attack that exploits a malicious / misleading off‑chain flow combined with standard ERC‑20 allowances.

## Evidence that this is a complete ACT opportunity

- **Pre‑state**: Before block `23133706`, the victim holds a large ANDY balance and has not approved the executor contract.
- **Step 1 – Victim approval (victim‑observed)**: Tx `0x8df5…269f2` calls `Andy.approve(0xDf31…cfd0f, type(uint256).max)` from the victim, establishing an unlimited allowance. This is a standard ERC‑20 approve, confirmed by the seed trace and metadata.
- **Step 2 – Adversary drain & swap (adversary‑crafted)**: Tx `0x33b2…5773b` from attacker `0xc31a…c649` routes through contracts `0xF0D5…c6971`, `0xDf31…cfd0f`, `0x2E1Dee…8764` and `0x40Aa95…cd7f` to:
  - call `Andy.transferFrom(victim, router, 88438777696239504000000)` using the prior approval;
  - send those ANDY into Uniswap V2 pair `0xa1bF0e9…c1C2c0` against WETH `0xC02a…6Cc2`;
  - execute `UniswapV2Pair.swap` and then `WETH9.withdraw`, paying ETH out to the attacker.
- **Profit measurement**: `balance_diff.json` for `0x33b2…5773b` shows attacker `0xc31a…c649` gaining `1094648119380540` wei ≈ `0.0010946` ETH, while the victim’s ANDY balance drops by the same notional amount that is sold through the pool.
- **Unprivileged and reproducible**: The draining tx uses only standard ERC‑20 allowance semantics and Uniswap V2 mechanics. Given the approval and sufficient gas/fee payment, any unprivileged adversary could have submitted an equivalent drain‑and‑swap transaction under normal inclusion rules.

Together, these facts satisfy the ACT opportunity checklist: a publicly reconstructible pre‑state, a concrete sequence of (victim‑observed + adversary‑crafted) transactions, and a measurable profit in ETH for the adversary.

## Root cause

- The **core root cause** is the victim’s unlimited ANDY approval to an untrusted executor contract that is part of a malicious swap‑helper stack.
- Andy’s ERC‑20 code and the Uniswap V2/WETH9 contracts behave as designed; there is no protocol bug or MEV‑style manipulation.
- The incident is best categorized as **"other"** in the root_cause schema: an approval‑drain / phishing‑style attack that leverages standard DeFi components rather than a flaw in the token or DEX.
