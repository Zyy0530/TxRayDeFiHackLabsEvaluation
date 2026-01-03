# Paribus Camelot PNFT Over-Borrow via AlgebraSingleAssetOracle on Arbitrum

## Incident Overview & TL;DR

On Arbitrum (chainid 42161), an unprivileged attacker EOA `0x5af00b07007cc1349794df5b2c15528237648035` executed a single flash-loan-powered transaction (`0xf5e753d3da60db214f2261343c1e1bc46e674d2fa4b7a953eaf3c52123aeebd2`) that drained essentially all ETH liquidity from the Paribus pEther market.

The adversary used a helper contract (`AtInverseBrah` at `0xbd4786f93ceef3dd73600ebe0b0bdccca2f7d37c`) to:
- Flash-borrow a large amount of USDT from an Aave-style pool.
- Mint a Camelot StandardArbERC20/USDT LP NFT (tokenId `224023`).
- Wrap and deposit that LP NFT as PNFT collateral into Paribus via `PNFTTokenDelegator` and `Comptroller`.
- Borrow almost all ETH from the Paribus pEther market against this NFT.
- Repay the flash loan and exit with ~12.6 ETH net profit.

The core root cause is a protocol-level oracle integration and risk configuration bug: Paribus’s NFT collateralization pipeline wires an `AlgebraSingleAssetOracle`-based Camelot NFP oracle into `ArbitrumPriceOracle` and then into `PNFTTokenDelegator`/`Comptroller` without enforcing a coherent loan-to-value limit for LP NFTs. In the observed pre-state, the system’s own oracle assigns the StandardArbERC20/USDT LP NFT (tokenId 224023) a value of only ~13.76k USD, yet allows the pEther market to lend ~41.75k USD worth of ETH against it in a single transaction, yielding an effective borrow-to-collateral ratio of ~303% and enabling a deterministic drain by any unprivileged actor who reproduces the calldata.

**Key exploit facts (from on-chain evidence):
- Block: `296699667` on Arbitrum.
- Profit tx: `0xf5e753d3da60db214f2261343c1e1bc46e674d2fa4b7a953eaf3c52123aeebd2`.
- Attacker EOA: `0x5af00b07007cc1349794df5b2c15528237648035`.
- Helper contract (AtInverseBrah): `0xbd4786f93ceef3dd73600ebe0b0bdccca2f7d37c`.
- PNFTTokenDelegator: `0xa26B6Df27F520017a2F0A5b0C0aA9C97D05f1f26`.
- Comptroller proxy: `0x712E2B12D75fe092838A3D2ad14B6fF73d3fdbc9`.
- Paribus pEther market: `0xAffd437801434643B734D0B2853654876F66f7D7`.
- ArbitrumPriceOracle: `0xa185a8c0929D473f2d0d2A132c4464fc01380bCe`.
- AlgebraSingleAssetOracle TWAP module: `0x03Ae45A78Fb44cdA83746FAa0314741C88A63306`.
- Profit: ~`12.5997` ETH net to the attacker (~41.7k USD at the oracle ETH price).

**Snippet 1 – Profit transaction trace (flash loan, LP mint, PNFT collateral, borrow)**

```txt
Traces (seed transaction trace.cast log excerpt for 0xf5e7…ebd2):
  0xbD4786F93CEEf3DD73600eBE0b0BdccCA2f7d37c::8c0d14e8(...)
    ├─ 0x794a61358D6845594F94dc1DB02A252b5b4814aD::flashLoan(... [3.093e12] USDT ...)
    │   ├─ L2PoolInstance::flashLoan(...)
    │   ├─ NonfungiblePositionManager::mint(... StandardArbERC20/USDT LP ...)
    │   │   ├─ AlgebraPool::mint(... liquidity 261501642958000974 ...)
    │   │   ├─ NonfungiblePositionManager::algebraMintCallback(... amount0 = 136766218539458444869127, amount1 = 500000000000 ...)
    │   ├─ Comptroller::enterNFTMarkets([PNFTTokenDelegator 0xa26B6Df27F520017a2F0A5b0C0aA9C97D05f1f26])
    │   ├─ pEther::borrow(12599960598441767978)
    │   ├─ flashLoan repayment and unwind
```

*Caption: Seed transaction trace clearly shows the Aave-style USDT flash loan, Camelot LP NFT minting over the StandardArbERC20/USDT pool, PNFT collateralization via Comptroller, and the subsequent pEther borrow of `12.599960598441767978` ETH within a single atomic transaction.*


## Key Background

### Protocol Architecture on Arbitrum

Paribus on Arbitrum uses a Compound-style architecture with:
- pTokens, including a pEther-like market at `0xAffd437801434643B734D0B2853654876F66f7D7`.
- A `Comptroller` proxy at `0x712E2B12D75fe092838A3D2ad14B6fF73d3fdbc9` governing collateral factors and borrow permissions.
- A `PNFTTokenDelegator` at `0xa26B6Df27F520017a2F0A5b0C0aA9C97D05f1f26` that wraps NFT collateral types, including Uniswap V3 and Camelot/Algebra LP positions.

Collected sources and decompilations for these components (PNFTToken/PNFTTokenDelegator, Comptroller, and pEther) confirm that PNFT tokens can be enabled as collateral markets and that the pEther market relies on oracle-derived prices for borrow limits.

### Oracle Stack for NFT and LP Pricing

`ArbitrumPriceOracle` at `0xa185a8c0929D473f2d0d2A132c4464fc01380bCe` is implemented as an `AggregatorOracle` that composes several price sources:
- A Chainlink-based `ArbitrumChainlink` module for core tokens (ETH, USDT, WBTC, ARB, USDC, etc.).
- A UniV2 and UniV3-based price oracle stack for standard ERC-20 pairs.
- An `AlgebraSingleAssetOracle` TWAP module (`0x03Ae45A78Fb44cdA83746FAa0314741C88A63306`) for Algebra/Camelot pools.
- Non-fungible position oracles (`NFPOracle` / `AlgebraV1PriceOracle`) for Uniswap V3 and Camelot V2 LP NFTs.

For NFTs, `AggregatorOracle.getUnderlyingNFTPrice` first tries the dex-specific NFP oracle based on the PNFTToken’s underlying non-fungible position manager and only falls back to a general `OracleNFT` for non-LP NFTs. For Camelot StandardArbERC20/USDT positions, the Camelot NFPOracle path is selected.

**Snippet 2 – ArbitrumPriceOracle construction and dependencies**

```solidity
// From collected ArbitrumPriceOracle source (contract 0xa185…0bCe)
contract ArbitrumPriceOracle is AggregatorOracle {
    constructor(address _algebraTwapSourceOracle) public {
        chainlinkSourceOracle = new ArbitrumChainlink();
        uniV2SourceOracle = new UniV2PriceOracle(this);
        uniV3PriceOracle = new UniV3PriceOracle(this, 0xC36442b4a4522E871399CD717aBDD847Ab11FE88);
        camelotV2Oracle = new AlgebraV1PriceOracle(this, 0x00c7f3082833e796A5b3e4Bd59f6642FF44DCD15);
        pEtherAddress = 0xAffd437801434643B734D0B2853654876F66f7D7;
        paribusOracle = 0xc8Be723395F6B1f51886947cCaE731a36Df615ba;
        algebraTwapSourceOracle = IAlgebraSingleAssetOracle(_algebraTwapSourceOracle);
    }
}
```

*Caption: The collected ArbitrumPriceOracle deployment matches the on-chain address and explicitly wires in the Camelot NFP oracle (`camelotV2Oracle`) and the AlgebraSingleAssetOracle TWAP module used in this incident.*

### AlgebraSingleAssetOracle and Chainlink Integration

The `AlgebraSingleAssetOracle` contract (deployed at `0x03Ae45A78Fb44cdA83746FAa0314741C88A63306`) is responsible for deriving token prices from Algebra pools and optional Chainlink feeds. Its core behavior:
- Maintains an `assetConfig` mapping from asset addresses to a price path (one or two Algebra pools) and a quote token.
- Optionally connects the quote token to a Chainlink price feed to express the final price in USD.
- Uses a TWAP interval (`twapInterval`) per asset to compute average prices from pool observations.

**Snippet 3 – AlgebraSingleAssetOracle asset configuration structure**

```solidity
// From AlgebraSingleAssetOracle source (0x03ae…3306)
contract AlgebraSingleAssetOracle {
    struct AlgebraPricePath {
        IAlgebraPool pool;
        // if target/interim token is token0, then TRUE
        bool token0IsInterim;
    }

    struct PricePathWithChainlink {
        AlgebraPricePath[] algebraPricePath;
        // quote Token address for algebra path
        address quoteToken;
        // if price feed available then it will return price in quote token
        address underlyingPriceFeed;
        // Twap interval for observations
        uint32 twapInterval;
    }

    mapping(address => PricePathWithChainlink) internal assetConfig;

    function isTokenSupported(address _asset) external view returns (bool) {
        return
            assetConfig[_asset].algebraPricePath.length != 0 ||
            _asset == assetConfig[_asset].quoteToken;
    }
}
```

*Caption: This snippet shows how AlgebraSingleAssetOracle keeps per-asset pool and Chainlink configuration, matching the report’s description that StandardArbERC20 is priced through an Algebra pool against USDT plus a USDT/USD Chainlink feed.*

In the collected configuration, the StandardArbERC20 token is mapped to the Camelot Algebra pool `0x25874cC60cBF7495b7Cd1FA724178d251CfAD5a8`, with USDT as the quote token and a live USDT/USD Chainlink feed. USDT itself is priced directly via Chainlink.

### ParibusOracleDelegator and PNFT Integration

`ParibusOracleDelegator` (`0xc8Be723395F6B1f51886947cCaE731a36Df615ba`) is a proxy for a patched oracle delegate implementation (`ParibusOracleDelegatePatched` at `0xb8d6b7e2b1e6c84aeddd56909636107ea122d589`). The patched implementation introduces `getPositionPriceWei`, which:
- Queries the same `AggregatorOracle.camelotV2Oracle` for Camelot LP NFTs.
- Divides by the ETH/USD price so that Paribus’s internal `priceWei` (in ETH) is consistent with the aggregator’s USD valuations.

However, for the PNFTTokenDelegator used in this exploit, `ArbitrumPriceOracle.getUnderlyingNFTPrice(PNFTTokenDelegator, tokenId)` takes the direct Camelot NFPOracle path based on `pNFTToken.underlying()` and does **not** rely on Paribus’s own NFT oracle for the initial LP valuation. Thus, the effective price the lending protocol uses for the NFT collateral is precisely the Camelot NFPOracle output.

### Oracle and Price Semantics for pEther and PNFT

- `Oracle.getUnderlyingPrice(pToken)` delegates to `getPriceOfUnderlying(underlyingAddress, 36 - underlyingDecimals)`, which ultimately calls `AggregatorOracle.getTokenPrice` to obtain prices with 18 decimals.
- For `pEther`, this results in an ETH/USD price scaled by `1e18`.
- `OracleNFT.getUnderlyingNFTPrice(PNFTToken, tokenId)` (and corresponding AggregatorOracle methods) compute NFT prices in USD by combining the LP amounts and token prices from the NFPOracle.

In the collected artifacts at block `296699667`:
- `ArbitrumPriceOracle.getUnderlyingPrice(pEther)` returns an ETH/USD price of `3,313.1894` (scaled by `1e18`).
- `ArbitrumPriceOracle.getUnderlyingNFTPrice(PNFTTokenDelegator(0xa26B6Df27F520017a2F0A5b0C0aA9C97D05f1f26), tokenId 224023)` returns an NFT USD price of `13,762.960161379621412354` (scaled by `1e18`).

These values are derived from the following view-call snapshot.

**Snippet 4 – Oracle view calls at the incident block**

```json
// From oracle_view_calls_block_296699667.json
{
  "chainid": 42161,
  "block_number": 296699667,
  "notes": "eth_call-style evaluation of AlgebraSingleAssetOracle and ArbitrumPriceOracle views at incident block",
  "calls": {
    "ArbitrumPriceOracle.getUnderlyingNFTPrice": {
      "result": "0x0000000000000000000000000000000000000000000002ea1770d37c952a1e02"
    },
    "ArbitrumPriceOracle.getUnderlyingPrice.pEther": {
      "result": "0x0000000000000000000000000000000000000000000000b39bbd4d452d998000"
    }
  }
}
```

*Caption: The view-call snapshot shows the on-chain outputs used in the report: an NFT price of ~13.76k USD and an ETH/USD price of ~3,313.19, both scaled by 1e18, matching the valuation calculations in the root-cause analysis.*


## Vulnerability & Root Cause Analysis

### High-Level Vulnerability Summary

The vulnerability is an over-borrow condition caused by misaligned oracle integration and risk parameters for Camelot LP NFTs used as PNFT collateral. Specifically:
- The Camelot NFPOracle pipeline (via `AlgebraSingleAssetOracle` and Chainlink) assigns the attacker’s StandardArbERC20/USDT LP NFT (tokenId 224023) a value of ~13.76k USD.
- The Paribus pEther market, using `ArbitrumPriceOracle`, allows a borrow of ~41.75k USD worth of ETH against this NFT in the same pre-state.
- There are no additional per-market caps, conservative collateral factors, or circuit breakers applied to this PNFT market to prevent such a high effective loan-to-value.

As a result, the attacker can create a specially crafted LP NFT and, in a single atomic transaction, drain the pEther market while remaining “over-collateralized” according to the protocol’s own misconfigured oracle.

### Detailed Exploit Conditions

The exploit predicate is of type **profit**, with the following economic parameters (all in USD reference terms, based solely on on-chain oracle outputs and balance diffs at block `296699667`):
- Reference asset: USD.
- Adversary address: `0x5af00b07007cc1349794df5b2c15528237648035`.
- Fees paid: `0.711413369127499846` USD equivalent.
- Total portfolio value before tx: `1321.3076449869314445628424` USD.
- Total portfolio value after tx: `43066.6521267927261266858756` USD.
- Value delta: `41745.3444818057946821230332` USD.

Key conditions that must hold (and do hold in the collected artifacts):
1. **Oracle configuration**: `ArbitrumPriceOracle` is configured to use `AlgebraSingleAssetOracle` and the Camelot NFPOracle for StandardArbERC20/USDT LP NFTs.
   - The asset config for StandardArbERC20 points to Algebra pool `0x25874cC60cBF7495b7Cd1FA724178d251CfAD5a8` and a USDT/USD Chainlink feed.
   - USDT is priced directly via Chainlink.
2. **Collateral whitelisting**: The PNFTTokenDelegator for StandardArbERC20/USDT Camelot positions is whitelisted as a valid NFT collateral market in the Comptroller.
   - Its collateral factor and risk parameters are such that the pEther market will lend against the oracle NFT value without additional per-market caps that would limit this borrow.
3. **Liquidity availability**: The pEther market holds at least ~12.6 ETH of liquidity at the incident block.
   - Balance diffs show its native balance dropping from `12.599960598441767978` ETH to `0` in the profit tx.
4. **Oracle numeric misalignment**: In the observed state, the StandardArbERC20/USDT LP NFT tokenId 224023 is assigned a nonzero USD value (`13,762.96` USD) that is **materially below** the amount that pEther will lend against it (`41,746.06` USD in ETH equivalent), enabling an effective borrow-to-collateral ratio of ~3.03x.
5. **Attack execution feasibility**: The attacker is able to obtain a sufficiently large USDT flash loan (`3,093,209,807,085` USDT units) to mint the desired LP NFT and immediately use it as collateral within the same transaction.

### Concrete Evidence: Over-Borrow from Balance Diffs

The prestate balance diffs for the profit transaction show the pEther market being fully drained while the attacker EOA receives an almost equal amount of ETH.

**Snippet 5 – Native balance diff (pEther market and attacker EOA)**

```json
// From balance_diff_prestate.json for tx 0xf5e7…ebd2
{
  "native_balance_deltas": [
    {
      "address": "0xaffd437801434643b734d0b2853654876f66f7d7",
      "before_wei": "12599960598441767978",
      "after_wei": "0",
      "delta_wei": "-12599960598441767978"
    },
    {
      "address": "0x5af00b07007cc1349794df5b2c15528237648035",
      "before_wei": "398802327747073996",
      "after_wei": "12998548204576751974",
      "delta_wei": "12599745876829677978"
    }
  ]
}
```

*Caption: The Paribus pEther market’s balance drops from `12.599960598441767978` ETH to `0`, while the attacker EOA’s balance increases by `12.599745876829677978` ETH, confirming the drain and profit reported in the analysis.*

### How the Oracle Stack Enables Over-Borrow

The Camelot NFPOracle (AlgebraV1PriceOracle) prices LP NFTs by:
1. Reconstructing token0/token1 amounts for the position using Algebra pool state and the LP’s liquidity and tick range.
2. Calling `aggregateOracle.getTokenPrice(token0, 18)` and `getTokenPrice(token1, 18)` to derive USD prices for each side.
3. Summing both sides (including uncollected fees) to obtain a USD valuation for the LP NFT (18-decimal fixed-point).

For the StandardArbERC20/USDT pool:
- The StandardArb token’s price comes from `AlgebraSingleAssetOracle.getTokenPrice(StandardArbERC20, 18)` using the Algebra pool `0x25874cC60cBF7495b7Cd1FA724178d251CfAD5a8` and a USDT/USD Chainlink feed.
- USDT is directly priced via Chainlink.

At the incident block, the specific LP parameters for tokenId 224023 are observable in the transaction trace (liquidity, amounts, tick range). Combined with the TWAP-derived prices, this yields a relatively modest USD valuation of ~13.76k for the NFT. However, the Comptroller’s risk settings for the PNFT market and the pEther market’s reliance on this oracle effectively permit a borrow of ~3.03x that value.

This misalignment between NFT valuation and borrowable ETH is purely on the protocol side; no re-entrancy, admin compromise, or low-level arithmetic bug is required. The attacker simply constructs an LP NFT that the oracle over-trusts for collateralization relative to its economic value to the protocol.

### Security Principles Violated

1. **Over-collateralization and risk management**
   - The protocol allows an NFT collateral asset valued at ~13.76k USD to back a borrow of ~41.75k USD worth of ETH, resulting in an effective loan-to-value of ~303% on a single position.
   - This directly violates conservative over-collateralization principles expected in lending markets, especially for complex LP NFT collateral.

2. **Sound oracle integration**
   - The system relies on a complex `AlgebraSingleAssetOracle` + Camelot NFPOracle pipeline without robust sanity checks or fallback behavior when TWAP-based LP valuations diverge from safe collateralization bounds.
   - Attackers can craft LP positions that fit within oracle assumptions but violate risk boundaries at the lending layer.

3. **Defense-in-depth for new collateral types**
   - LP NFTs backed by volatile or thinly traded assets (such as StandardArbERC20 on Algebra/Camelot) are integrated as collateral without additional circuit breakers, per-asset caps, or more conservative collateral factors.
   - A misconfiguration or extreme TWAP outcome directly translates into over-borrow opportunities that can drain markets like pEther in one transaction.


## Adversary Flow Analysis

### Adversary-Related Accounts

The analysis identifies a small, well-justified adversary cluster:

- **Attacker EOA**: `0x5af00b07007cc1349794df5b2c15528237648035`
  - Sender of the profit transaction `0xf5e7…ebd2`.
  - Receives the net ETH profit (native balance increase of ~`12.5997` ETH) in the balance diffs.
  - Transaction history is consistent with a searcher/attacker address.

- **Helper contract (AtInverseBrah)**: `0xbd4786f93ceef3dd73600ebe0b0bdccca2f7d37c`
  - Deployed and exclusively used by the attacker EOA.
  - Orchestrates the flash-loan, Camelot LP minting, PNFT collateralization, and pEther borrow sequence within a single transaction.
  - Decompiled source shows no privileged roles or direct access to Paribus admin paths; its power comes purely from interacting with public protocol entrypoints.

The primary protocol-side victims are identified as:
- Paribus pEther market (`0xAffd437801434643B734D0B2853654876F66f7D7`).
- Paribus Comptroller (`0x712E2B12D75fe092838A3D2ad14B6fF73d3fdbc9`).
- Paribus PNFTTokenDelegator (`0xa26B6Df27F520017a2F0A5b0C0aA9C97D05f1f26`).
- ArbitrumPriceOracle (`0xa185a8c0929D473f2d0d2A132c4464fc01380bCe`).

These contracts collectively implement the misconfigured collateralization pipeline that the attacker exploits.

### Adversary Lifecycle Stages

#### 1. Adversary Contract Deployment and Setup

- **Transaction**: `0x93345781abd125aadafe3edc557f64c6363816d305da0ebda7f87ae6c5779c00` (block `296565764`).
- **Mechanism**: Contract deployment on Arbitrum.
- **Effect**: The attacker’s EOA deploys the `AtInverseBrah` controller contract, preparing a reusable entrypoint that encodes the full flash-loan and collateralization strategy.
  - At this stage, the contract does not modify Paribus configuration or oracle settings; it only sets up infrastructure.

**Snippet 6 – AtInverseBrah deployment trace excerpt**

```txt
// From AtInverseBrah deployment trace (0x9334…9c00)
[deploy] from 0x5af0…8035 -> 0xbd4786f93ceef3dd73600ebe0b0bdccca2f7d37c
  code: 0x60806040...
```

*Caption: The deployment trace confirms that the attacker EOA deploys AtInverseBrah, establishing a dedicated contract to run the exploit logic.*

#### 2. Dry-Run / Configuration Calls into AtInverseBrah

- **Transactions**:
  - `0xf4a88dc25bf60cd6edbf6007897248bf0a2cd99627923ffb51c8ccdb837d4ed0` (block `296698792`).
  - `0x4b6fb4e2fedd4fa7fb6ada6eb53db525db815d434d352f16619340133446b115` (block `296699382`).
- **Mechanism**: Calls into AtInverseBrah helper functions (e.g., `aggregate()`, `LOCK8605463013()`).
- **Effect**: These transactions set up approvals and validate that:
  - The Aave-style flash lender is callable.
  - The Camelot NonfungiblePositionManager and Algebra pool are reachable.
  - PNFTTokenDelegator and Paribus/Arbitrum oracles can be interacted with as expected.

These dry-runs do not themselves drain value or change oracle configuration, but they confirm wiring and ensure the final profit transaction will execute successfully.

#### 3. Single-Transaction Flash-Loan LP Mint, PNFT Collateralization, and pEther Drain

- **Transaction**: `0xf5e753d3da60db214f2261343c1e1bc46e674d2fa4b7a953eaf3c52123aeebd2` (block `296699667`).
- **Mechanism**: Combined flash-loan, LP mint, PNFT collateralization, and borrow.
- **Detailed Flow**:
  1. **USDT Flash Loan**
     - AtInverseBrah calls the Aave L2 pool to flashLoan `3,093,209,807,085` USDT units to itself.
  2. **Camelot StandardArbERC20/USDT LP NFT Mint**
     - Using the flash-loaned USDT and StandardArbERC20, AtInverseBrah invokes Camelot’s NonfungiblePositionManager and Algebra pool (`0x25874cC60cBF7495b7Cd1FA724178d251CfAD5a8`) to mint an LP position:
       - Liquidity: `261501642958000974`.
       - `amount0` (StandardArbERC20): `136,766,218,539,458,444,869,127` units.
       - `amount1` (USDT): `500,000,000,000` units.
       - TokenId: `224023`.
  3. **PNFT Collateralization**
     - The freshly minted LP NFT is transferred to `PNFTTokenDelegator` (`0xa26B6Df27F520017a2F0A5b0C0aA9C97D05f1f26`).
     - The attacker calls `Comptroller.enterNFTMarkets([PNFTTokenDelegator])` to mark the PNFT market as collateral-enabled for their account.
  4. **pEther Borrow via Misconfigured Oracle**
     - With the PNFT collateral in place, AtInverseBrah calls `borrow(12599960598441767978)` on the pEther market (`0xAffd437801434643B734D0B2853654876F66f7D7`).
     - `ArbitrumPriceOracle` consults the Camelot NFPOracle (and underpinning AlgebraSingleAssetOracle TWAP path) to value the NFT collateral.
     - Despite the NFT being worth only ~13.76k USD per the oracle, the pEther market transfers `12.599960598441767978` ETH to the attacker EOA, corresponding to ~41.75k USD at the ETH/USD oracle price.
  5. **Flash-Loan Repayment and Profit Realization**
     - The attacker repays the USDT flash loan within the same transaction.
     - The remaining ETH (minus gas) constitutes the net profit.

This lifecycle fully matches the collected traces and balance diffs, and no privileged operations or admin interventions are involved.


## Impact & Losses

The direct on-chain impact observed in the collected artifacts is:

- A complete drain of the Paribus pEther market’s native balance in the profit transaction block.
  - pEther balance: `12.599960598441767978` ETH before the tx, `0` after.
- An increase in the attacker’s EOA balance from `0.398802327747073996` ETH to `12.998548204576751974` ETH, for a net gain of `12.599745876829677978` ETH after gas.
- At the ETH/USD oracle price of `3,313.1894` USD/ETH, this corresponds to a net profit of approximately `41.7k` USD.
- The protocol’s solvency for positions involving the StandardArbERC20/USDT PNFT collateral is compromised, because the NFT’s recorded oracle value (~13.76k USD) is far below the borrowed amount (~41.75k USD) that has been transferred to an adversary-controlled EOA.

No evidence in the collected artifacts suggests additional, larger multi-block drains beyond this single pEther market incident, but the root cause indicates that similar over-borrow opportunities could exist for other LP NFT configurations if the same oracle and risk settings apply.


## References

Below are the primary evidence sources used in this root cause report, summarized in human-readable form:

1. **Seed profit transaction metadata and trace for `0xf5e7…ebd2`**
   - Contains raw transaction metadata (from Etherscan-like RPC), `trace.cast.log` execution trace, and `balance_diff.json` / `balance_diff_prestate.json` showing ETH and ERC-20 balance changes.
   - Demonstrates the flash-loan, LP minting, PNFT collateralization, and pEther borrow sequence and quantifies the attacker’s profit.

2. **ArbitrumPriceOracle, AggregatorOracle, SourceOracle, and NFPOracle Solidity sources**
   - Provide the implementation details for how token and NFT prices are computed, including the use of `camelotV2Oracle` and the `algebraTwapSourceOracle` (`AlgebraSingleAssetOracle`).
   - Confirm that pEther uses `getUnderlyingPrice` with an ETH/USD price and that PNFT NFTs use the Camelot NFPOracle path for LP valuation.

3. **AlgebraSingleAssetOracle Solidity source**
   - Documents the `assetConfig` mapping, TWAP interval handling, and integration with Chainlink price feeds.
   - Confirms that StandardArbERC20 pricing can be routed via an Algebra pool and a USDT/USD Chainlink feed to produce USD prices.

4. **ParibusOracleDelegator and ParibusOracleDelegatePatched sources**
   - Show how Paribus’s internal oracle stack relates to the AggregatorOracle and confirm that the patched delegate uses the same Camelot NFPOracle outputs when computing `priceWei` for LP NFTs.

5. **Camelot Algebra pool and oracle view outputs at block `296699667`**
   - `pricing_state_snapshot.json` and `oracle_view_calls_block_296699667.json` capture Algebra pool state, TWAP observations, and oracle view outputs for the incident block.
   - These files provide the numerical evidence for the ETH/USD price, the NFT’s USD valuation, and the underlying pool configuration that led to the over-borrow.

Collectively, these artifacts are sufficient to reconstruct the exploit path and confirm that the root cause is a protocol-level oracle and risk-parameter misconfiguration that enables over-borrowing via Camelot StandardArbERC20/USDT LP NFTs on Arbitrum.
