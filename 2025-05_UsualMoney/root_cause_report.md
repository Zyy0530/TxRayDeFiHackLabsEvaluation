# Usd0PP/VaultRouter unwrap cap MEV on Ethereum mainnet

## Incident Overview & TL;DR

An unprivileged searcher EOA 0x2ae2… on Ethereum mainnet deploys a router and helper contract, then
uses a single constructor transaction to route deeply discounted Usd0PP liquidity from a
CurveStableSwapNG pool through VaultRouter’s large configured unwrap cap into USD0, and finally
through ParaSwap and Uniswap V3 into WETH and native ETH. The resulting ETH is immediately forwarded
to profit-recipient EOA 0xac5…, yielding a net cluster gain of 15.88695667374731498 ETH after gas
with no residual ERC20 or vault positions. All calls execute through permissionless interfaces of
VaultRouter, Usd0PP, DEX pools, and WETH9, satisfying the ACT adversary model.

The root cause is an economic configuration and cross-protocol routing opportunity: VaultRouter
holds a very large Usd0PP unwrap cap, and the Usd0PP/Usd0/Curve/Uniswap stack allows a
permissionless actor to convert discounted Usd0PP liquidity into fully backed USD0 and then into
ETH, capturing value intended for the system’s backing and LPs. No invariant-breaking bug or access-
control failure is observed in VaultRouter, Usd0PP, or the DEXes; the event is an MEV-style ACT
opportunity driven by unwrap cap size and market pricing.

## Key Background

- Usd0PP is a capped wrapper over USD0 that tracks USD0 holdings inside the Usd0PP contract and exposes unwrapWithCap(user,amount) guarded by per-caller unwrapCaps[user] and the USD0PP_CAPPED_UNWRAP_ROLE; when invoked by an authorized caller, unwrapWithCap burns Usd0PP from the caller and transfers an equal amount of USD0 from the contract’s internal balance.
- VaultRouter is a permissionless router that accepts deposits in USD0PP or SUsds, converts them to target assets, and optionally deposits them into WrappedDollarVault; for USD0PP, the deposit path calls _convertUSD0ppToTokens, which transfers Usd0PP from the caller to VaultRouter and then calls MINTER_USD0PP.unwrapWithCap, consuming the router’s unwrap cap and receiving USD0.
- The CurveStableSwapNG pool at 0x1d08…ec52 holds large Usd0PP and Usd0 balances and can be traded against permissionlessly, while Uniswap V3 pools (including the USDC/WETH pool at 0x88e6…f5640) provide deep liquidity to route USD0 exposure into USDC and then into WETH/ETH.
- Within the incident window, router 0xf195… holds exactly 10 SUsds that it uses to seed a new Uniswap V3 Usd0/SUsds pool and later recovers as adjusted liquidity; adversary EOA 0x2ae2… starts with 0.15 ETH and no other material balances, and profit-recipient EOA 0xac5… is a fresh wallet that first receives 16.03695667374731498 ETH from 0x2ae2… directly after the seed tx.

## Vulnerability & Root Cause Analysis

### High-Level Vulnerability

The vulnerable condition is an economically generous unwrap cap on Usd0PP for VaultRouter:
unwrapCaps[VaultRouter] is configured to approximately 1.8998e24 Usd0PP, enabling a single
permissionless call to redeem the entire amount of discounted Usd0PP from CurveStableSwapNG into
fully backed USD0 via VaultRouter.deposit(Usd0PP) and Usd0PP.unwrapWithCap.

### Detailed Root Cause

Verified Usd0PP and VaultRouter sources show a deliberate design where VaultRouter, endowed with
USD0PP_CAPPED_UNWRAP_ROLE, can call unwrapWithCap to convert Usd0PP to USD0 up to a per-address cap
unwrapCaps[VaultRouter]. Before the incident, unwrapCaps[VaultRouter] equals
1.899838465685386939269479e24, matching the amount of Usd0PP sitting in the Curve Usd0PP/USD0 pool
at 0x1d08…ec52. In the seed transaction, helper 0xfb45… uses the permissionless VaultRouter.deposit
entrypoint with tokenIn = Usd0PP to transfer that entire Usd0PP position from CurveStableSwapNG into
VaultRouter and immediately invoke unwrapWithCap for the full cap. The Usd0PP contract burns
1.8998e24 Usd0PP from VaultRouter, reduces unwrapCaps[VaultRouter] from 1.8998e24 to 0, and
transfers the same amount of USD0 from its internal holdings to VaultRouter, as confirmed by
CappedUnwrap events, ERC20 balance diffs, and storage diffs. VaultRouter then routes the USD0
through ParaSwap and Uniswap V3, ultimately converting it into WETH and then ETH for the adversary
cluster. Throughout this flow, contract logic behaves exactly as specified: balances, caps, and
totalSupply change in lockstep, and there is no evidence of reentrancy, access-control bypass,
integer error, or misconfigured proxy. The economic vulnerability is that unwrapCaps[VaultRouter]
was set large enough that a single MEV-style transaction could drain practically all Usd0PP from the
Curve pool at a discount to its backing value and convert it into ETH, with VaultRouter acting as a
public conduit rather than a tightly controlled redemption path.

### Vulnerable Components

- Usd0PP 0x35d8949372d46b7a3d5a56006ae77b215fc69bc0 :: unwrapWithCap(address user, uint256 amount)
- VaultRouter 0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09 :: deposit(address tokenIn, uint256 amountIn, …)
- System configuration of unwrapCaps[VaultRouter] for Usd0PP prior to block 22575930

### Exploit Preconditions

- unwrapCaps[VaultRouter] for Usd0PP must be configured to a very large value (here approximately 1.8998e24) that matches or exceeds the discounted Usd0PP liquidity in CurveStableSwapNG.
- Usd0PP, VaultRouter, CurveStableSwapNG, and downstream DEXes must expose fully permissionless interfaces so that an arbitrary EOA can call VaultRouter.deposit(Usd0PP) and route the resulting USD0 through liquid markets into ETH.
- The Curve Usd0PP/USD0 pool and Uniswap V3 / ParaSwap routing must provide sufficient liquidity and pricing such that swapping the redeemed USD0 into WETH/ETH yields a positive net ETH gain after gas.

### Security Principles Impacted

- Economic design and configuration: granting a large unwrap cap to a permissionless router created a public arbitrage path that allowed external searchers to extract significant value from protocol liquidity while leaving protocol-level invariants intact.
- Assumption that role-and-cap based wrappers (Usd0PP + unwrapCaps[VaultRouter]) would prevent large-scale redemptions by untrusted parties, which does not hold when the router entrypoint remains fully permissionless and cap values are configured near available liquidity.

### Evidence: Usd0PP State and Unwrap Cap Consumption

The following snippet comes from the focused Usd0PP/USD0 state diff around the seed transaction, showing totalSupply, backing, and unwrapCaps[VaultRouter] being reduced to zero:

```json
{
  "snapshots": {
    "usd0pp_totalSupply_before": {
      "blockNumber": 22575929,
      "blockTag": "0x1587b39",
      "raw": "0x000000000000000000000000000000000000000001e2b30a5c8d7124e6eb5fc7",
      "value": "583547739791236692309663687"
    },
    "usd0pp_totalSupply_after": {
      "blockNumber": 22575930,
      "blockTag": "0x1587b3a",
      "raw": "0x000000000000000000000000000000000000000001e120bbe974e3e027185e60",
      "value": "581647901325551305370394208"
    },
    "unwrapCap_vaultrouter_before": {
      "blockNumber": 22575929,
      "blockTag": "0x1587b39",
      "raw": "0x00000000000000000000000000000000000000000001924e73188d44bfd30167",
      "value": "1899838465685386939269479"
    },
    "unwrapCap_vaultrouter_after": {
      "blockNumber": 22575930,
      "blockTag": "0x1587b3a",
      "raw": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "value": "0"
    },
    "usd0_balance_usd0pp_before": {
      "blockNumber": 22575929,
      "blockTag": "0x1587b39",
      "raw": "0x000000000000000000000000000000000000000001e2b30a5c8d7124e6eb5fc7",
      "value": "583547739791236692309663687"
    },
    "usd0_balance_usd0pp_after": {
      "blockNumber": 22575930,
      "blockTag": "0x1587b3a",
      "raw": "0x000000000000000000000000000000000000000001e120bbe974e3e027185e60",
      "value": "581647901325551305370394208"
    },
    "usd0_balance_vaultrouter_before": {
      "blockNumber": 22575929,
      "blockTag": "0x1587b39",
      "raw": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "value": "0"
    },
    "usd0_balance_vaultrouter_after": {
      "blockNumber": 22575930,
      "blockTag": "0x1587b3a",
      "raw": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "value": "0"
    }
  },
  "prestate_storage_usd0pp": {
    "0x8845959cb364d70f227a27f287ec0115963c1ce81c6b0cc368f2518cfff8e12d": {
      "from": "0x00000000000000000000000000000000000000000001924e73188d44bfd30167",
      "to": "0x0"
    },
    "0xb61f539cb3f4c1172e4b5518df8696f4586781e469690deb55784ce526fdd1ec": {
      "from": "0x0000000000000000000000000000000000000000000000008e9dde233b7c3a91",
      "to": "0x00000000000000000000000000000000000000000001924f01b66b67fb4f3bf8"
    },
    "0xa3e6b8ea496189f5a4dac613ac4e16804f990c0a2c98b3f517f34baf911482ac": {
      "from": "0x00000000000000000000000000000000000000000036d709fe3cdc07ec9ff39d",
      "to": "0x0000000000000000000000000000000000000000003544bb8b244ec32cccf236"
    },
    "0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace02": {
      "from": "0x000000000000000000000000000000000000000001e2b30a5c8d7124e6eb5fc7",
      "to": "0x000000000000000000000000000000000000000001e120bbe974e3e027185e60"
    }
  }
}
```

_Caption: Seed transaction Usd0PP/USD0 snapshots and storage changes, highlighting unwrapCaps[VaultRouter] dropping from 1.8998e24 to 0 and matching movements in Usd0PP.totalSupply and USD0 balances._

### Evidence: VaultRouter Deposit and USD0PP Handling

The next snippet shows the relevant portion of the verified VaultRouter implementation, demonstrating the permissionless deposit path and conversion of USD0PP via the minter's unwrapWithCap logic:

```solidity
     * ########################
     * # CONSTRUCTOR #
     * ########################
     */

    /// @notice constructor for the VaultRouter
    /// @param _registryContract The address of the registry contract
    /// @param _augustusRegistry The address of the paraswap augustus registry
    /// @param _vault The address of the vault
    constructor(
        address _registryContract,
        address _augustusRegistry,
        address _vault
    )
        ReentrancyGuard()
        Pausable()
    {
        if (
            _registryContract == address(0) || _augustusRegistry == address(0)
                || _vault == address(0)
        ) {
            revert NullAddress();
        }
        REGISTRY_CONTRACT = IRegistryContract(_registryContract);
        REGISTRY_ACCESS = IRegistryAccess(
            REGISTRY_CONTRACT.getContract(CONTRACT_REGISTRY_ACCESS)
        );
        USD0 = IERC20(REGISTRY_CONTRACT.getContract(CONTRACT_USD0));
        USD0PP = IERC20(REGISTRY_CONTRACT.getContract(CONTRACT_USD0PP));
        SUSDS = IERC20(ADDRESS_SUSDS);
        MINTER_USD0PP = IUSD0ppMinter(address(USD0PP));
        VAULT = WrappedDollarVault(_vault);
        AUGUSTUS_REGISTRY = IParaSwapAugustusRegistry(_augustusRegistry);
        SUSDS.approve(address(VAULT), type(uint256).max);
        USD0.approve(address(MINTER_USD0PP), type(uint256).max);
    }

    /// @inheritdoc IVaultRouter
    function rescueToken(IERC20 token) external whenNotPaused nonReentrant {
        if (!REGISTRY_ACCESS.hasRole(ROUTER_RESCUER_ROLE, _msgSender())) {
            revert NotAuthorized();
        }
        uint256 balance = token.balanceOf(address(this));
        token.safeTransfer(_msgSender(), balance);
        emit TokenRescued(token, balance);
    }

    /// @inheritdoc IVaultRouter
    function rescueEther() external whenNotPaused nonReentrant {
        if (!REGISTRY_ACCESS.hasRole(ROUTER_RESCUER_ROLE, _msgSender())) {
            revert NotAuthorized();
        }
        uint256 balance = address(this).balance;
        payable(_msgSender()).sendValue(balance);
        emit EtherRescued(balance);
    }

    /// @inheritdoc IVaultRouter
    function pause() external nonReentrant {
        if (!REGISTRY_ACCESS.hasRole(ROUTER_PAUSER_ROLE, _msgSender())) {
            revert NotAuthorized();
        }
        _pause();
    }

    /// @inheritdoc IVaultRouter
    function unpause() external nonReentrant {
        if (!REGISTRY_ACCESS.hasRole(ROUTER_UNPAUSER_ROLE, _msgSender())) {
            revert NotAuthorized();
        }
        _unpause();
    }

    /*
     * ########################
     * # PUBLIC #
     * ########################
     */

    /// @inheritdoc IVaultRouter
    function deposit(
        IParaSwapAugustus augustus,
        IERC20 tokenIn,
        uint256 amountIn,
        uint256 minTokensToReceive,
        uint256 minSharesToReceive,
        address receiver,
        bytes calldata swapData
    )
        public
        payable
        whenNotPaused
        nonReentrant
        returns (uint256 sharesReceived)
    {
        if (tokenIn != USD0PP && tokenIn != SUSDS) {
            revert InvalidInputToken(address(tokenIn));
        }
        if (receiver == address(0)) {
            revert NullAddress();
```

_Caption: Extract from verified VaultRouter source showing the public `deposit` entrypoint and the internal conversion of input tokens (including USD0PP) into vault shares using ParaSwap and the USD0PP minter._

## Adversary Flow Analysis

The adversary executes a two-transaction, single-chain strategy: a complex constructor transaction
that deploys helper contracts, consumes VaultRouter’s entire Usd0PP unwrap cap against discounted
Curve liquidity, and routes USD0 through ParaSwap/Uniswap into ETH, followed by a simple ETH
transfer consolidating proceeds into a separate profit-recipient EOA.

### Adversary-Related Accounts

#### Adversary Cluster

- `0x2ae2f691642bb18cd8deb13a378a0f95a9fee933` (EOA=True, contract=False): Sender of the seed contract-creation transaction 0x585d8b…f271f8 and payer of gas for both b transactions; orchestrates the entire exploit path and transfers ETH proceeds to 0xac5….
- `0xf195b8800B729aEe5E57851dD4330fCBB69F07EA` (EOA=False, contract=True): Router contract deployed by 0x2ae2… in the seed tx; holds 10 SUsds pre-incident and orchestrates calls into VaultRouter, CurveStableSwapNG, ParaSwap, Morpho, and Uniswap as part of the exploit path.
- `0xfb45BcD7239774cdBC5018fD47faF1a2fc219D1F` (EOA=False, contract=True): Helper contract deployed by 0xf195… in the seed tx; calls VaultRouter.deposit with tokenIn = Usd0PP, receives WETH from Uniswap V3, and unwraps it to native ETH for 0x2ae2….
- `0xac5d14d7d1159009fb8b2901fe9ea2d51ee9def6` (EOA=True, contract=False): Immediate ETH profit recipient in tx 0x0934c1…d89f4, receiving 16.03695667374731498 ETH from 0x2ae2… shortly after the seed tx and acting as the adversary’s consolidation wallet.

#### Protocol / Victim Candidates

- Usd0PP `0x35d8949372d46b7a3d5a56006ae77b215fc69bc0` (verified=True)
- Usd0 `0x73a15fed60bf67631dc6cd7bc5b6e8da8190acf5` (verified=True)
- VaultRouter `0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09` (verified=True)
- SUsds `0xa3931d71877c0e7a3148cb7eb4463524fec27fbd` (verified=True)

### Lifecycle Stages and Key Transactions

#### Adversary setup and SUsds funding

**Transactions:**
- Ethereum (chainid 1), tx 0x4388b5ec68d7ca9cb756a26b7d66b0d6d1f5c4da (log context), block 22575505, mechanism transfer

**Effect:**

Router address 0xf195… is funded with 10 SUsds via a SUsds Transfer event from
0x4388b5ec68d7ca9cb756a26b7d66b0d6d1f5c4da prior to the seed tx, providing the only non-ETH asset
that the adversary sacrifices during the exploit.

**Evidence reference:**

- artifacts/root_cause/data_collector/iter_3/other/1/susds_funding_0xf195_logs_iter3.json

#### Router deployment and unwrap cap consumption

**Transactions:**
- Ethereum (chainid 1), tx 0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8, block 22575930, mechanism other

**Effect:**

EOA 0x2ae2… sends a constructor transaction that deploys router 0xf195… and helper 0xfb45…,
initializes a Uniswap V3 Usd0/SUsds pool with the 10 SUsds, transfers 1.8998e24 Usd0PP from
CurveStableSwapNG to VaultRouter via VaultRouter.deposit(Usd0PP), and calls Usd0PP.unwrapWithCap
through VaultRouter to burn the same amount of Usd0PP and transfer an equal quantity of USD0 from
Usd0PP to VaultRouter while reducing unwrapCaps[VaultRouter] to zero.

**Evidence reference:**

- artifacts/root_cause/seed/1/0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8/trace.cast.log; artifacts/root_cause/data_collector/iter_3/tx/1/0x585d8b…/usd0pp_state_diff.json

#### DEX routing and profit realization

**Transactions:**
- Ethereum (chainid 1), tx 0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8, block 22575930, mechanism other
- Ethereum (chainid 1), tx 0x0934c11bd6ca220fc3be20099dd50923b7a2e32e066e829bdcf1e2cc617d89f4, block 22575942, mechanism transfer

**Effect:**

Within the seed tx, VaultRouter routes the USD0 obtained from unwrapWithCap through ParaSwap and
Uniswap V3 (including the USDC/WETH pool 0x88e6…f5640), resulting in WETH9 transferring
15.925452345403740016 WETH to 0xfb45… and then unwrapping it to 15.925452345403740016 ETH for
0x2ae2…. After the block, 0x2ae2… sends 16.03695667374731498 ETH to 0xac5… via a simple transfer,
paying 0.0001491 ETH in gas; the cluster’s net ETH value moves from 0.15 ETH pre-seed to
16.03695667374731498 ETH after this consolidation.

**Evidence reference:**

- artifacts/root_cause/seed/1/0x585d8b…/trace.cast.log; artifacts/root_cause/data_collector/iter_2/tx/1/0x585d8b…/balance_diff_full.json; artifacts/root_cause/data_collector/iter_3/address/1/0xac5d14…/txlist_0x1587800-0x1587e00.json

### Evidence: Seed Transaction Trace Excerpt

The following excerpt from the seed transaction debug trace shows VaultRouter and Usd0PP interactions that consume the unwrap cap and move USD0 into the routing path:

```text
    │   │   ├─ [1194607] 0xfb45BcD7239774cdBC5018fD47faF1a2fc219D1F::onMorphoFlashLoan(1899838465685386939269479 [1.899e24], 0x000000000000000000000000def171fe48cf0115b1d80b88dc8eab59176fee5700000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2)
    │   │   │   ├─ [25263] TransparentUpgradeableProxy::fallback(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09], 1899838465685386939269479 [1.899e24])
    │   │   │   │   ├─ [24818] Usd0PP::approve(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09], 1899838465685386939269479 [1.899e24]) [delegatecall]
    │   │   │   │   │   ├─ emit Approval(owner: 0xfb45BcD7239774cdBC5018fD47faF1a2fc219D1F, spender: VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09], value: 1899838465685386939269479 [1.899e24])
    │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   @ 0x1177897fc58318790dd99468f809799d62977e50c025562062179f8d9fc6ccbd: 0 → 0x00000000000000000000000000000000000000000001924e73188d44bfd30167
    │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [488300] VaultRouter::deposit(AugustusSwapper: [0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57], TransparentUpgradeableProxy: [0x35D8949372D46B7a3D5A56006AE77B215fc69bC0], 1899838465685386939269479 [1.899e24], 1, 0, 0xfb45BcD7239774cdBC5018fD47faF1a2fc219D1F, 0xa6886da9000000000000000000000000000000000000000000000000000000000000002000000000000000000000000073a15fed60bf67631dc6cd7bc5b6e8da8190acf5000000000000000000000000a3931d71877c0e7a3148cb7eb4463524fec27fbd000000000000000000000000e592427a0aece92de3edee1f18e0157c0586156400000000000000000000000000000000000000000001924e73188d44bfd301670000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000068360529000000000000000000000000e033cb1bb400c0983fa60ce62f8ecdf6a16fce090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e033cb1bb400c0983fa60ce62f8ecdf6a16fce0900000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000220d3ba174c721349ff915ec624c071422a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b73a15fed60bf67631dc6cd7bc5b6e8da8190acf50001f4a3931d71877c0e7a3148cb7eb4463524fec27fbd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)
    │   │   │   │   ├─ [3084] TransparentUpgradeableProxy::fallback(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09]) [staticcall]
    │   │   │   │   │   ├─ [2642] Usd0::balanceOf(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 0
    │   │   │   │   │   └─ ← [Return] 0
    │   │   │   │   ├─ [32131] TransparentUpgradeableProxy::fallback(0xfb45BcD7239774cdBC5018fD47faF1a2fc219D1F, VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09], 1899838465685386939269479 [1.899e24])
    │   │   │   │   │   ├─ [31680] Usd0PP::transferFrom(0xfb45BcD7239774cdBC5018fD47faF1a2fc219D1F, VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09], 1899838465685386939269479 [1.899e24]) [delegatecall]
    │   │   │   │   │   │   ├─ [1114] TransparentUpgradeableProxy::fallback(0xfb45BcD7239774cdBC5018fD47faF1a2fc219D1F) [staticcall]
    │   │   │   │   │   │   │   ├─ [672] Usd0::isBlacklisted(0xfb45BcD7239774cdBC5018fD47faF1a2fc219D1F) [delegatecall]
    │   │   │   │   │   │   │   │   └─ ← [Return] false
    │   │   │   │   │   │   │   └─ ← [Return] false
    │   │   │   │   │   │   ├─ [3114] TransparentUpgradeableProxy::fallback(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09]) [staticcall]
    │   │   │   │   │   │   │   ├─ [2672] Usd0::isBlacklisted(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09]) [delegatecall]
    │   │   │   │   │   │   │   │   └─ ← [Return] false
    │   │   │   │   │   │   │   └─ ← [Return] false
    │   │   │   │   │   │   ├─ emit Transfer(sender: 0xfb45BcD7239774cdBC5018fD47faF1a2fc219D1F, receiver: VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09], value: 1899838465685386939269479 [1.899e24])
    │   │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   │   @ 0xbea7af3a40cde1183e71265909987606f3035945301ee159df093c77e7727a4f: 0x00000000000000000000000000000000000000000001924e73188d44bfd30167 → 0
    │   │   │   │   │   │   │   @ 0x3aac32d6e2672b37ae67d1e742435fe38b0632c25d6e1faa7e6f772924440eb7: 0 → 0x00000000000000000000000000000000000000000001924e73188d44bfd30167
    │   │   │   │   │   │   │   @ 0x1177897fc58318790dd99468f809799d62977e50c025562062179f8d9fc6ccbd: 0x00000000000000000000000000000000000000000001924e73188d44bfd30167 → 0
    │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   ├─ [78921] TransparentUpgradeableProxy::fallback(1899838465685386939269479 [1.899e24])
    │   │   │   │   │   ├─ [78482] Usd0PP::unwrapWithCap(1899838465685386939269479 [1.899e24]) [delegatecall]
    │   │   │   │   │   │   ├─ [7673] TransparentUpgradeableProxy::fallback(0x91ecad9c58e10e45ad5091669dee80adb4c63f7f67b654cf8e4eab2d35f6b320, VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09]) [staticcall]
    │   │   │   │   │   │   │   ├─ [2728] RegistryAccess::hasRole(0x91ecad9c58e10e45ad5091669dee80adb4c63f7f67b654cf8e4eab2d35f6b320, VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09]) [delegatecall]
    │   │   │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   │   ├─ [1114] TransparentUpgradeableProxy::fallback(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09]) [staticcall]
    │   │   │   │   │   │   │   ├─ [672] Usd0::isBlacklisted(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09]) [delegatecall]
    │   │   │   │   │   │   │   │   └─ ← [Return] false
    │   │   │   │   │   │   │   └─ ← [Return] false
    │   │   │   │   │   │   ├─ [3114] TransparentUpgradeableProxy::fallback(0x0000000000000000000000000000000000000000) [staticcall]
    │   │   │   │   │   │   │   ├─ [2672] Usd0::isBlacklisted(0x0000000000000000000000000000000000000000) [delegatecall]
    │   │   │   │   │   │   │   │   └─ ← [Return] false
    │   │   │   │   │   │   │   └─ ← [Return] false
    │   │   │   │   │   │   ├─ emit Transfer(sender: VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09], receiver: 0x0000000000000000000000000000000000000000, value: 1899838465685386939269479 [1.899e24])
    │   │   │   │   │   │   ├─ emit DailyUsd0ppOutflowUpdated(dayIndex: 20235 [2.023e4], amount: 1899838465685386939269479 [1.899e24])
    │   │   │   │   │   │   ├─ [33168] TransparentUpgradeableProxy::fallback(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09], 1899838465685386939269479 [1.899e24])
    │   │   │   │   │   │   │   ├─ [32723] Usd0::transfer(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09], 1899838465685386939269479 [1.899e24]) [delegatecall]
    │   │   │   │   │   │   │   │   ├─ emit Transfer(sender: TransparentUpgradeableProxy: [0x35D8949372D46B7a3D5A56006AE77B215fc69bC0], receiver: VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09], value: 1899838465685386939269479 [1.899e24])
    │   │   │   │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   │   │   │   @ 0x6aacc0c22ff51c459752b32304cb0b918c0ffd2ddd95a1ba1648d5e23bb6591b: 0x000000000000000000000000000000000000000001e2b30a5c8d7124e6eb5fc7 → 0x000000000000000000000000000000000000000001e120bbe974e3e027185e60
    │   │   │   │   │   │   │   │   │   @ 0x3aac32d6e2672b37ae67d1e742435fe38b0632c25d6e1faa7e6f772924440eb7: 0 → 0x00000000000000000000000000000000000000000001924e73188d44bfd30167
    │   │   │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   │   ├─ emit CappedUnwrap(user: VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09], amount: 1899838465685386939269479 [1.899e24], remainingAllowance: 0)
    │   │   │   │   │   │   ├─  storage changes:
    │   │   │   │   │   │   │   @ 0x8845959cb364d70f227a27f287ec0115963c1ce81c6b0cc368f2518cfff8e12d: 0x00000000000000000000000000000000000000000001924e73188d44bfd30167 → 0
    │   │   │   │   │   │   │   @ 0x3aac32d6e2672b37ae67d1e742435fe38b0632c25d6e1faa7e6f772924440eb7: 0x00000000000000000000000000000000000000000001924e73188d44bfd30167 → 0
    │   │   │   │   │   │   │   @ 0xb61f539cb3f4c1172e4b5518df8696f4586781e469690deb55784ce526fdd1ec: 0x0000000000000000000000000000000000000000000000008e9dde233b7c3a91 → 0x00000000000000000000000000000000000000000001924f01b66b67fb4f3bf8
    │   │   │   │   │   │   │   @ 0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace02: 0x000000000000000000000000000000000000000001e2b30a5c8d7124e6eb5fc7 → 0x000000000000000000000000000000000000000001e120bbe974e3e027185e60
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   └─ ← [Return]
    │   │   │   │   ├─ [1084] TransparentUpgradeableProxy::fallback(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09]) [staticcall]
    │   │   │   │   │   ├─ [642] Usd0::balanceOf(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 1899838465685386939269479 [1.899e24]
    │   │   │   │   │   └─ ← [Return] 1899838465685386939269479 [1.899e24]
    │   │   │   │   ├─ [4715] AugustusRegistry::isValidAugustus(AugustusSwapper: [0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57]) [staticcall]
    │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   ├─ [1084] TransparentUpgradeableProxy::fallback(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09]) [staticcall]
    │   │   │   │   │   ├─ [642] Usd0::balanceOf(VaultRouter: [0xE033cb1bB400C0983fA60ce62f8eCDF6A16fcE09]) [delegatecall]
```

_Caption: Seed transaction trace excerpt showing VaultRouter.deposit(Usd0PP), Usd0PP.unwrapWithCap, CappedUnwrap events, and USD0 transfers into VaultRouter before routing through ParaSwap/Uniswap._

## Impact & Losses

### Quantitative Impact

- Token: ETH, amount: 15.88695667374731498

### Impact Narrative

From the perspective of the adversary-related cluster, the incident yields a deterministic net
profit of 15.88695667374731498 ETH after gas costs, funded by a combination of CurveStableSwapNG LPs
and counterparties along the ParaSwap/Uniswap routing path who sell Usd0PP/Usd0/USDC at prices that
allow this bundle to be profitable. No protocol-owned vaults, caps, or accounting invariants are
broken: Usd0PP supply and USD0 backing move in lockstep, unwrapCaps[VaultRouter] is correctly
decremented to zero, and VaultRouter behaves exactly as configured. The economic impact is therefore
best described as an MEV/arbitrage extraction of value from public liquidity, not a protocol
insolvency or direct theft from a privileged treasury.

### Evidence: ETH Profit and Balance Diffs

The ETH profit calculation is supported by pre/post balance diffs for the adversary cluster and WETH9:

```json
{
  "native_balance_deltas": [
    {
      "address": "0x2ae2f691642bb18cd8deb13a378a0f95a9fee933",
      "before_wei": "150000000000000000",
      "after_wei": "16037105773747314980",
      "delta_wei": "15887105773747314980"
    },
    {
      "address": "0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97",
      "before_wei": "5830940823354723826",
      "after_wei": "5838345859354723826",
      "delta_wei": "7405036000000000"
    },
    {
      "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "before_wei": "2799376188098007370170763",
      "after_wei": "2799360262645661966430747",
      "delta_wei": "-15925452345403740016"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0xa3931d71877c0e7a3148cb7eb4463524fec27fbd",
      "holder": "0xf195b8800b729aee5e57851dd4330fcbb69f07ea",
      "before": "10",
      "after": "0",
      "delta": "-10",
      "balances_slot": "2",
      "slot_key": "0x0e54b025604338dfca561efe3c1ed0f2c2a0c69b8c3b4e31f9ccce6b577f6183",
      "layout_address": "0x4e7991e5c547ce825bdeb665ee14a3274f9f61e0",
      "contract_name": "SUsds"
    },
    {
      "token": "0xa3931d71877c0e7a3148cb7eb4463524fec27fbd",
      "holder": "0xb4f2210c6641f7d018bd314fecc96f7758be3d68",
      "before": "0",
      "after": "1",
      "delta": "1",
      "balances_slot": "2",
      "slot_key": "0xb76352772fe31247e5f56acb1c106b88a31b9de9f8aa68d288690b7b2de55d4a",
      "layout_address": "0x4e7991e5c547ce825bdeb665ee14a3274f9f61e0",
      "contract_name": "SUsds"
    },
    {
      "token": "0xa3931d71877c0e7a3148cb7eb4463524fec27fbd",
      "holder": "0xef13101c5bbd737cfb2bf00bbd38c626ad6952f7",
      "before": "182235002328603076",
      "after": "182235002328603080",
      "delta": "4",
      "balances_slot": "2",
      "slot_key": "0xfd85dfc1b8704f237a6fcedafd7808f0e4f66bf32dc1f96318dfeb6481913b0a",
      "layout_address": "0x4e7991e5c547ce825bdeb665ee14a3274f9f61e0",
      "contract_name": "SUsds"
    },
    {
      "token": "0xa3931d71877c0e7a3148cb7eb4463524fec27fbd",
      "holder": "0x67ec31a47a4126a66c7bb2fe017308cf5832a4db",
      "before": "294954199841440345580623",
      "after": "294954199841440345580628",
      "delta": "5",
      "balances_slot": "2",
      "slot_key": "0xd995e7c97a171d2ee93a294db9beb5034dec75da6b40ceea96ca1fc7db44c936",
      "layout_address": "0x4e7991e5c547ce825bdeb665ee14a3274f9f61e0",
      "contract_name": "SUsds"
    }
  ]
}
```

_Caption: Seed transaction balance deltas showing 0x2ae2…'s native balance increase, WETH9's matching decrease, and key ERC20 balance shifts along the routing path._

## References

- [1] Seed transaction metadata and trace: artifacts/root_cause/seed/1/0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8
- [2] Usd0PP and Usd0 verified sources: artifacts/root_cause/seed/1/0x9f2bd21bf8012fce0d5845537c1deff3a89bc85b/src; artifacts/root_cause/seed/1/0xae12f6f805842e6dafe71a6d2b41b28ba5fc821e/src
- [3] VaultRouter verified source: artifacts/root_cause/data_collector/iter_1/contract/1/0xe033cb1bb400c0983fa60ce62f8ecdf6a16fce09/source/src/VaultRouter.sol
- [4] Balance and state diffs for seed tx: artifacts/root_cause/data_collector/iter_1/tx/1/0x585d8b…/erc20_balance_diff_usd0pp_usd0.json; artifacts/root_cause/data_collector/iter_2/tx/1/0x585d8b…/balance_diff_full.json; artifacts/root_cause/data_collector/iter_3/tx/1/0x585d8b…/usd0pp_state_diff.json
- [5] Adversary txlists and unwrap caps history: artifacts/root_cause/data_collector/iter_1/address/1/0x2ae2…/txlist_0x1587b00-0x1587b80.json; artifacts/root_cause/data_collector/iter_3/address/1/0xac5d14…/txlist_0x1587800-0x1587e00.json; artifacts/root_cause/data_collector/iter_3/other/1/unwrap_caps_vaultrouter.json
