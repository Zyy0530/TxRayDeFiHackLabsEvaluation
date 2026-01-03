# Incident Overview & TL;DR

On BSC (chainid 56), an adversary-controlled helper contract executed a single flash‑loan transaction (tx `0x84c385aab658d86b64e132e8db0c092756d5a9331a1131bf05f8214d08efba56`) that:

- Borrowed 2,000 WBNB from a Pancake V3 pool.
- Swapped WBNB to BUSD and bought VISTA tokens cheaply via the VistaFinance ICO contract.
- Flash‑minted a large amount of VISTA via the token’s ERC20FlashMint extension to bypass staking constraints.
- Sold 1,594 VISTA into a separate VistaFinance sell/buy contract that valued VISTA at ~22.86 USDT per token based on a misconfigured oracle.
- Converted the resulting USDT back to WBNB, repaid the loan (~2,001 WBNB), and left ~48.23 WBNB profit for the adversary EOA.

The **root cause** is a **mispriced, owner-controlled oracle** (`vistaForcePlan` at `0xb9c3401c846f3ac4ccd2bdb1901e41c1da463e10`) whose `price` variable was set to approximately 22.86 while the ICO continued to sell VISTA at 1 BUSD per token. The VistaFinance sell/buy contract (`0xf738de9913bc1e21b1a985bb0E39Db75091263b7`) trusted this oracle price without any sanity checks or linkage to the ICO rate, creating a deterministic, permissionless on‑chain arbitrage: **buy VISTA at 1 BUSD and immediately redeem at ~22.86 USDT**.

This price inconsistency between the ICO and the sell contract is entirely on‑chain and does not require any special privileges. The adversary simply automated the arbitrage using a flash loan and helper contract, extracting protocol‑owned USDT and WBNB reserves.


# Key Background

## Protocol Components

- **VISTA Token (VistaFinance)**  
  - Address: `0x493361D6164093936c86Dcb35Ad03b4C0D032076`  
  - ERC‑20 token with staking and OpenZeppelin’s `ERC20FlashMint` extension, which allows uncollateralized flash‑minting of arbitrary amounts of VISTA within a single transaction.

  Minimal excerpt showing the VISTA token contract and staking hook:

  ```solidity
  // Collected VistaFinance token source (verified on explorer)
  // Contract: VistaFinance (VISTA) - snippet
  contract VistaFinance is ERC20, ERC20Burnable, ERC20Permit, ERC20Votes, ERC20FlashMint, AccessControl {
      struct Stake {
          uint256 amount;
          uint256 releaseTime;
      }

      mapping(address => Stake[]) private stakedTokens;

      event TokensStaked(address indexed wallet, uint256 amount, uint256 releaseTime);
      event TokensUnstaked(address indexed wallet, uint256 amount);

      constructor() ERC20("Vista Finance", "VISTA") ERC20Permit("Vista Finance") {
          _mint(msg.sender, 21000000 * 10 ** decimals());
          _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
      }
      ...
      function getFreeBalance(address _userAddress) public returns (uint256) {
          Stake[] storage userStakings = stakedTokens[_userAddress];
          uint256 stakedAmount = 0;
          uint256 balance = balanceOf(_userAddress);
          ...
          uint256 freeBalance = balance - stakedAmount;
          return freeBalance;
      }
  }
  ```

  *Caption: VistaFinance token contract with staking and ERC20FlashMint, used both for ICO distribution and flash‑minting during the exploit.*

- **VistaFinanceICO (ICO contract)**  
  - Address: `0x7C98b0cEEaFCf5b5B30871362035f728955b328c`  
  - Sells VISTA tokens for BUSD at a fixed 1:1 rate (1 BUSD per 1 VISTA), and stakes part of the purchased amount.

  ```solidity
  // Collected VistaFinanceICO contract source
  contract VistaFinanceICO {
      IBUSD private busdToken;
      IVista private vistaToken;
      uint256 private day = 86400;
      uint256 private month = day * 30;
      address admin = 0x3a923ae336112bcADA95d1A44393f16C51A68C33;
      ...
      function stake(uint256 amount, address sponsor) external {
          amount = amount * 10 ** 18;
          require(amount > 0, "Amount must be greater than 0");
          require(busdToken.balanceOf(msg.sender) >= amount, "Insufficient BUSD balance");
          require(busdToken.allowance(msg.sender, address(this)) >= amount, "Insufficient allowance");

          busdToken.transferFrom(msg.sender, address(this), amount);
          busdToken.transfer(admin, amount * 95 / 100);
          busdToken.transfer(sponsor, amount * 5 / 100);
          vistaToken.transfer(msg.sender, amount);
          ...
      }
  }
  ```

  *Caption: VistaFinanceICO sells VISTA at a fixed 1:1 rate versus BUSD (1 BUSD → 1 VISTA).*

- **vistaForcePlan Oracle (price source)**  
  - Address: `0xb9c3401c846f3ac4ccd2bdb1901e41c1da463e10`  
  - Upgradeable contract that defines an owner‑controlled price used as the VISTA/USDT conversion rate, and exposes it via a public `price` variable (Solidity auto‑generated getter `price()`).

  ```solidity
  // Collected vistaForcePlan oracle source
  contract vistaForcePlan is Initializable, OwnableUpgradeable, UUPSUpgradeable {
      uint256 private day = 86400;
      uint256 private month = day * 30;
      uint256 private startmonth = 18 * (day * 30);
      uint256 public price = 8100000000000000000;
      // uint public price;
      address public usdt = 0x55d398326f99059fF775485246999027B3197955;
      address public vista = 0x493361D6164093936c86Dcb35Ad03b4C0D032076;
      ...
      function initialize() initializer public {
          __Ownable_init();
          __UUPSUpgradeable_init();
          _transferOwnership(msg.sender);
          ...
          // Initialize the Token contract
          tokenPriceInBusd = 490;
          ...
      }
      ...
      function updatePrice(uint256 _newPrice) public onlyOwner {
          require(_newPrice != price, "New price must be different.");

          uint256 oldPrice = price;
          price = _newPrice;

          emit PriceUpdated(oldPrice, _newPrice);
      }

      // Function to stake ERC-20 tokens into the contract
      function stake(uint256 USDTAmount, address refer, address user) public {
          IERC20 vistaToken = IERC20(vista);
          IERC20 usdToken = IERC20(usdt);
          uint256 amount = (USDTAmount * 1 ether) / price;
          require(usdToken.transferFrom(user, address(this), USDTAmount), "USDT transferFrom failed");
          ...
          require(vistaToken.transfer(user, amount), "VISTA transfer to sender failed");
          ...
      }
  }
  ```

  *Caption: vistaForcePlan exposes a mutable `price` used directly in a linear formula to convert USDT deposits into VISTA amounts; the same getter is later used by the sell contract.*

- **VistaFinance sell/buy contract**  
  - Address: `0xf738de9913bc1e21b1a985bb0E39Db75091263b7`  
  - Deployed as an upgradeable contract that uses `vistaForcePlan.price()` to convert between USDT and VISTA in both `buy` and `sell` directions. The implementation is only available as a decompiled EVM artifact.

  ```solidity
  // Decompiled VistaFinance sell/buy contract - buy() snippet
  function buy(uint256 arg0, address arg1) public {
      ...
      // Transfer USDT from buyer into this contract
      (bool success, bytes memory ret0) =
          address(0x55d398326f99059ff775485246999027b3197955).Unresolved_23b872dd(var_b); // transferFrom
      ...
      // Read vistaForcePlan oracle price
      (bool success, bytes memory ret0) =
          address(0xb9c3401c846f3ac4ccd2bdb1901e41c1da463e10).price(); // staticcall
      ...
      // Compute VISTA amount ~ arg0 * 1e18 / price
      require(((arg0 * 0x0de0b6b3a7640000) / var_e.length) > 0);
      uint256 var_g = (arg0 * 0x0de0b6b3a7640000) / var_e.length;
      // Transfer VISTA to buyer
      (bool success, bytes memory ret0) =
          address(0x493361d6164093936c86dcb35ad03b4c0d032076).Unresolved_a9059cbb(var_d); // transfer
      ...
  }
  ```

  ```solidity
  // Decompiled VistaFinance sell/buy contract - sell() snippet
  function sell(uint256 arg0, address arg1) public {
      require(arg1 == (address(arg1)));
      // Read vistaForcePlan oracle price
      (bool success, bytes memory ret0) =
          address(0xb9c3401c846f3ac4ccd2bdb1901e41c1da463e10).price(); // staticcall
      ...
      // Compute required VISTA from arg0 and oracle price
      require(((arg0 * 0x0de0b6b3a7640000) / var_b.length) > 0);
      ...
      // Check allowance and transfer VISTA from seller into this contract
      (bool success, bytes memory ret0) =
          address(0x493361d6164093936c86dcb35ad03b4c0d032076).Unresolved_dd62ed3e(var_f); // allowance
      ...
      (bool success, bytes memory ret0) =
          address(0x493361d6164093936c86dcb35ad03b4c0d032076).Unresolved_23b872dd(var_g); // transferFrom
      ...
      // Pay USDT to seller
      (bool success, bytes memory ret0) =
          address(0x55d398326f99059ff775485246999027b3197955).Unresolved_a9059cbb(var_i); // transfer
      ...
  }
  ```

  *Caption: Decompiled sell/buy contract uses `vistaForcePlan.price()` directly to compute VISTA amounts for given USDT values and vice versa, with no checks against the ICO price or external markets.*

## Adversary Accounts and Helper Contract

- **Adversary EOA**: `0x3D71366228EBD5196D45eE72f82405da601190ad`  
  - Sends the seed transaction and ultimately receives the BNB profit.

- **Helper contract**: `0x10036dAD92fd0459daAb57C506eA656d46BF5727`  
  - Deployed and used by the adversary EOA to orchestrate:
    - WBNB flash loan from Pancake V3.
    - Swaps across Pancake liquidity pools (WBNB ↔ BUSD ↔ USDT).
    - ICO purchase via `VistaFinanceICO::stake`.
    - VISTA flash‑mint via `VistaFinance::flashLoan`.
    - Overpriced sale via `sell()` on the VistaFinance sell/buy contract.

The existence and usage of these actors is visible in the seed transaction trace and in the balance diff summary.


# Vulnerability & Root Cause Analysis

## High-Level Vulnerability

The core vulnerability is the **inconsistent pricing of VISTA across two protocol components**:

- The **ICO contract** sells VISTA for BUSD at a fixed **1:1 rate**.
- The **sell/buy contract** prices VISTA using `vistaForcePlan.price()` and, during the incident, treats VISTA as worth approximately **22.86 USDT per token**.

Because:

- The oracle price is centrally controlled by the `vistaForcePlan` owner via `updatePrice(uint256 _newPrice)`.
- The sell/buy contract does not enforce any relationship between this price and the ICO rate or on‑chain liquidity.

Any user who can buy VISTA from the ICO can immediately redeem it into the sell contract at ~22.86x its purchase cost, limited only by the sell contract’s USDT reserves. This creates a **deterministic, permissionless arbitrage** between two contracts of the same protocol.

## Evidence of Mispriced Oracle

The seed transaction’s execution trace shows the sell contract calling the oracle’s `price()` getter and receiving a value corresponding to 22.86:

```bash
# Seed transaction trace (cast run -vvvvv) for tx 0x84c3...
│   │   │   ├─ [130937] VistaFinance::flashLoan(..., 1000000000000000000000000 [1e24], ...)
│   │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000,
│   │   │   │   │             to: 0x10036dAD92fd0459daAb57C506eA656d46BF5727,
│   │   │   │   │             value: 1000000000000000000000000 [1e24])
│   │   │   │   ├─ [83727] 0x10036dAD92fd0459daAb57C506eA656d46BF5727::onFlashLoan(...)
│   │   │   │   │   ├─ [78648] 0xf738de9913bc1e21b1a985bb0E39Db75091263b7::sell(
│   │   │   │   │   │       36438840000000000000000 [3.643e22], 0x10036dAD92fd0459daAb57C506eA656d46BF5727)
│   │   │   │   │   │   ├─ [2362] vistaForcePlan::price() [staticcall]
│   │   │   │   │   │   │   └─ ← [Return] 22860000000000000000 [2.286e19]
```

*Caption: Seed transaction trace showing the sell contract calling `vistaForcePlan::price()` and receiving 22.86 × 10¹⁸ as the oracle price.*

This `price` (2.286e19) corresponds to **22.86** when interpreted as a standard 18‑decimal fixed‑point value. The decompiled sell/buy contract uses this value in a formula of the form:

- `VISTA_amount ≈ USDT_amount * 1e18 / price`.

At the same time, the ICO contract continues to offer VISTA at 1 BUSD per token:

```solidity
// VistaFinanceICO::stake
function stake(uint256 amount, address sponsor) external {
    amount = amount * 10 ** 18;
    ...
    busdToken.transferFrom(msg.sender, address(this), amount);
    ...
    vistaToken.transfer(msg.sender, amount);
    ...
}
```

*Caption: ICO stake function minting exactly `amount` VISTA for `amount` BUSD (1:1 pricing).*

Taken together:

- **ICO price**: 1 VISTA = 1 BUSD.  
- **Sell contract price** (via oracle): 1 VISTA ≈ 22.86 USDT.

Ignoring minor BUSD/USDT differences, this yields an exploitable **~22.86× profit factor** between buying from the ICO and selling into the sell contract.

## Exploit Path and Use of Flash Minting

The adversary leverages both the ICO and the VISTA flash‑mint feature to source enough VISTA to meaningfully exploit the mispricing:

1. **Buy VISTA from ICO at 1 BUSD each**  
   From the trace:

   ```bash
   # Seed transaction trace – ICO purchase segment
   │   │   │   ├─ [69604] PancakeRouter::swapExactTokensForTokensSupportingFeeOnTransferTokens(
   │   │   │   │       2000000000000000000000 [2e21], ..., [WBNB, BUSD], 0x10036d..., ...)
   ...
   │   │   │   ├─ [1081385] VistaFinanceICO::stake(1594, 0x10036dAD92fd0459daAb57C506eA656d46BF5727)
   │   │   │   │   ├─ emit PurchasedICO(user: 0x10036d..., amount: 1594000000000000000000 [1.594e21])
   ```

   *Caption: Trace shows the helper contract swapping WBNB to BUSD and then calling `VistaFinanceICO::stake(1594, ...)`, buying 1,594 VISTA‑denominated units (scaled by 1e18).*

2. **Flash‑mint additional VISTA**  
   The VISTA token supports ERC‑3156 flash loans via `ERC20FlashMint`. The trace shows a flash loan of 1,000,000 VISTA (1e24 units):

   ```bash
   # Seed transaction trace – VISTA flash-mint segment
   │   │   ├─ [130937] VistaFinance::flashLoan(
   │   │   │       0x10036dAD92fd0459daAb57C506eA656d46BF5727,
   │   │   │       VistaFinance: [0x493361D6...2076],
   │   │   │       1000000000000000000000000 [1e24], ...)
   │   │   │   ├─ emit Transfer(
   │   │   │   │       from: 0x0000000000000000000000000000000000000000,
   │   │   │   │       to:   0x10036dAD92fd0459daAb57C506eA656d46BF5727,
   │   │   │   │       value: 1000000000000000000000000 [1e24])
   ```

   *Caption: Trace evidence that VistaFinance flash‑mints 1,000,000 VISTA to the helper contract for use within the same transaction.*

   These flash‑minted tokens, together with the ICO‑purchased VISTA, allow the helper contract to work around staking or balance constraints while still repaying the flash loan within the transaction.

3. **Sell 1,594 VISTA into the mispriced sell contract**  
   The trace shows the helper contract calling `sell()` on the sell/buy contract with a USDT amount of 36,438.84 (3.643884e22 with 18 decimals), and the contract internally pulling 1,594 VISTA from the helper:

   ```bash
   # Seed transaction trace – sell() segment
   │   │   │   │   ├─ [78648] 0xf738de9913bc1e21b1a985bb0E39Db75091263b7::sell(
   │   │   │   │   │       36438840000000000000000 [3.643e22],
   │   │   │   │   │       0x10036dAD92fd0459daAb57C506eA656d46BF5727)
   │   │   │   │   │   ├─ [2362] vistaForcePlan::price() [staticcall]
   │   │   │   │   │   │   └─ ← [Return] 22860000000000000000 [2.286e19]
   ...
   │   │   │   │   │   ├─ [40653] VistaFinance::transferFrom(
   │   │   │   │   │   │       0x10036dAD92fd0459daAb57C506eA656d46BF5727,
   │   │   │   │   │   │       0xf738de9913bc1e21b1a985bb0E39Db75091263b7,
   │   │   │   │   │   │       1594000000000000000000 [1.594e21])
   │   │   │   │   │   ├─ [29971] BEP20USDT::transfer(
   │   │   │   │   │   │       0x10036dAD92fd0459daAb57C506eA656d46BF5727,
   │   │   │   │   │   │       36438840000000000000000 [3.643e22])
   ```

   *Caption: sell() call uses oracle price 22.86 to accept 1,594 VISTA and pay out 36,438.84 USDT from the sell contract to the helper contract.*

4. **Unwind to WBNB and repay flash loan**  
   After receiving 36,438.84 USDT, the helper contract swaps USDT back to WBNB and repays the 2,001 WBNB (principal + fee), leaving surplus WBNB that is then withdrawn to the adversary EOA.

## Quantification of Mispricing and Profit

The seed `balance_diff.json` (pre‑state vs post‑state) confirms the net movement of native BNB (via WBNB) and tokens:

```json
// Seed transaction balance diff summary
{
  "chainid": 56,
  "txhash": "0x84c385aab658d86b64e132e8db0c092756d5a9331a1131bf05f8214d08efba56",
  "native_balance_deltas": [
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "before_wei": "1332205739154792335149888",
      "after_wei":  "1332157504159917891237446",
      "delta_wei":  "-48234994874443912442"
    },
    {
      "address": "0x3d71366228ebd5196d45ee72f82405da601190ad",
      "before_wei": "2798071956935597970",
      "after_wei":  "51031144695127510412",
      "delta_wei":  "48233072738191912442"
    }
  ],
  "erc20_transfers": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "from":  "0xf738de9913bc1e21b1a985bb0e39db75091263b7",
      "to":    "0x10036dad92fd0459daab57c506ea656d46bf5727",
      "value": "36438840000000000000000"
    },
    ...
  ]
}
```

*Caption: Balance diff shows ~48.23 WBNB net loss from the WBNB pool and 36,438.84 USDT moving from the sell contract to the adversary helper, matching the exploit description.*

The native balance deltas show:

- WBNB contract (`0xbb4c...095c`): `delta_wei = -48.234994874443912442` BNB equivalent.
- Adversary EOA: `delta_wei = +48.233072738191912442` BNB equivalent.

This is consistent with:

- 2,000 WBNB borrowed and repaid with ~1 WBNB fee, plus
- ~48.23 WBNB profit extracted from protocol liquidity.

The ERC‑20 transfer section corroborates:

- 36,438.84 USDT (`0x55d3...7955`) transferred from the sell contract to the helper contract during `sell()`.
- 1,594 VISTA transferred from the helper contract to the sell contract.

Combining these, the effective sell‑side price realized is:

- `36,438.84 USDT / 1,594 VISTA ≈ 22.86 USDT per VISTA`, matching the oracle‑reported `price`.

## Root Cause Summary

1. **Centralized price oracle without safeguards**  
   - `vistaForcePlan` exposes `price` as a mutable, owner‑set variable and provides `updatePrice(uint256 _newPrice)` without any invariants, bounds, or checks against on‑chain markets.

2. **Inconsistent pricing across protocol components**  
   - The ICO contract continues to sell VISTA at 1 BUSD per token, even as `price` is set to ~22.86. There is no mechanism tying the ICO price to the oracle or vice versa.

3. **Sell/buy contract over‑trusts oracle**  
   - The sell/buy contract uses `vistaForcePlan.price()` as its authoritative price for both `buy` and `sell`, directly converting USDT ↔ VISTA based on the provided value, without any sanity checks or caps relative to its USDT reserves.

4. **Flash‑mint amplifies exploitability but is not the root bug**  
   - `ERC20FlashMint` on VISTA allows the adversary to temporarily borrow a large amount of VISTA, making it easier to hit meaningful volumes. However, the core issue remains the **price inconsistency** between the ICO and sell contract; even without flash‑mint, the arbitrage would exist.

5. **Permissionless, reproducible arbitrage**  
   - The exploit does not change `price`. It only exploits the already‑mispriced oracle by routing publicly available liquidity and contracts in one transaction. Any unprivileged actor could replicate the same sequence from the publicly observable pre‑state.

Security principles violated:

- Failure to maintain consistency between oracle price and primary token sale price.
- Over‑reliance on a centralized, mutable oracle without bound checks or validation against DEX markets.
- Lack of sell‑side limits or reserve‑aware checks in the sell contract when honoring redemptions at oracle‑derived prices.


# Adversary Flow Analysis

## Adversary Strategy Summary

The adversary conducts a **single, carefully constructed flash‑loan transaction** that:

1. Uses a Pancake V3 flash loan to temporarily obtain 2,000 WBNB.
2. Swaps WBNB to BUSD.
3. Uses BUSD to purchase VISTA via the ICO at 1 BUSD per VISTA.
4. Flash‑mints additional VISTA via `VistaFinance::flashLoan` (ERC20FlashMint) to work around staking constraints.
5. Approves and calls the VistaFinance sell/buy contract to sell 1,594 VISTA into its USDT pool at ~22.86 USDT per VISTA.
6. Swaps the resulting USDT back into WBNB.
7. Repays the WBNB loan plus fee and keeps the remaining WBNB as profit, which is finally withdrawn to the adversary EOA.

## Adversary-Related Accounts

- **EOA (adversary)**: `0x3D71366228EBD5196D45eE72f82405da601190ad`  
  - Initiates the exploit transaction.  
  - Receives the net BNB profit, as confirmed by `native_balance_deltas` in `balance_diff.json`.

- **Helper contract**: `0x10036dAD92fd0459daAb57C506eA656d46BF5727`  
  - Acts as the orchestrator of the exploit:
    - Calls Pancake V3 for a flash loan.
    - Interacts with PancakeRouter pairs for swaps.
    - Calls `VistaFinanceICO::stake`.
    - Calls `VistaFinance::flashLoan`.
    - Calls `VistaFinance` approve / transfer / transferFrom.
    - Calls the sell/buy contract’s `sell()` function.

- **Victim protocol components**:
  - `VistaFinanceICO` (`0x7C98b0cEEaFCf5b5B30871362035f728955b328c`) – sells underpriced VISTA.
  - `VistaFinance` token (`0x493361D6164093936c86Dcb35Ad03b4C0D032076`) – provides flash‑minted VISTA.
  - `VistaFinance sell/buy` (`0xf738de9913bc1e21b1a985bb0E39Db75091263b7`) – holds mispriced USDT liquidity and honors overpriced redemptions.
  - `vistaForcePlan` (`0xb9c3401c846f3ac4ccd2bdb1901e41c1da463e10`) – mispriced oracle used by the sell/buy contract.

## Lifecycle Stages

### 1. Initial Funding and Helper Setup

- **Mechanism**: Prior transfers and contract deployments (not in the seed transaction).
- **Effect**:
  - EOA `0x3D7136...` accumulates initial BNB to pay gas and deploys the helper contract `0x10036d...`.
  - Evidence for this stage comes from historical transaction lists (not re‑printed here), but is not critical to understanding the exploit mechanics.

No privileged operations or protocol configuration changes are required at this stage; the attacker simply sets up standard infrastructure.

### 2. Adversary-Crafted Exploit Transaction (Seed Tx)

- **Transaction**: `0x84c385aab658d86b64e132e8db0c092756d5a9331a1131bf05f8214d08efba56`  
- **Block**: `43791254` on BSC.  
- **Mechanism**: A single atomic transaction using a flash loan and multi‑hop DeFi interactions.

#### Step 2.1 – Flash Loan and WBNB → BUSD Swap

- Helper contract takes a 2,000 WBNB flash loan from a Pancake V3 pool (address `0x36696169C63e42cd08ce11f5deeBbCeBae652050`).
- Swaps the borrowed WBNB to BUSD via a Pancake pair (`0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16`).
- Evidence from trace (simplified):

```bash
│   ├─ PancakeV3Pool::flash(0x10036d..., 0, 2000000000000000000000 [2e21], ...)
│   │   ├─ WBNB::transfer(0x10036d..., 2000000000000000000000 [2e21])
...
│   │   ├─ PancakeRouter::swapExactTokensForTokensSupportingFeeOnTransferTokens(
│   │   │       2000000000000000000000 [2e21], ..., [WBNB, BUSD], 0x10036d..., ...)
│   │   │   ├─ BEP20Token::transfer(0x10036d..., 955431835233099194383151 [9.554e23])  // BUSD out
```

*Caption: Flash loan of 2,000 WBNB and subsequent swap to ~9.55e23 BUSD received by the helper contract.*

#### Step 2.2 – Underpriced ICO Purchase

- The helper contract then calls `VistaFinanceICO::stake(1594, helper)`:
  - Sends 1,594 BUSD (scaled by 1e18) to the ICO contract.
  - Receives 1,594 VISTA (scaled by 1e18) and additional staked/bonus VISTA.

Evidence from trace:

```bash
│   │   │   ├─ VistaFinanceICO::stake(1594, 0x10036d...)
│   │   │   │   ├─ BEP20Token::transfer(admin, 1514300000000000000000 [1.514e21])     // 95% BUSD
│   │   │   │   ├─ BEP20Token::transfer(0x10036d..., 79700000000000000000 [7.97e19])  // 5% BUSD
│   │   │   │   ├─ VistaFinance::transfer(0x10036d..., 1594000000000000000000 [1.594e21]) // VISTA
│   │   │   │   ├─ VistaFinance::stakeTokens(... multiple calls ...)
│   │   │   │   ├─ emit PurchasedICO(user: 0x10036d..., amount: 1594000000000000000000 [1.594e21])
```

*Caption: ICO stake sequence where 1,594 BUSD is converted into 1,594 VISTA (plus related staking), confirming the 1:1 ICO price.*

#### Step 2.3 – VISTA Flash-Mint

- The helper contract requests and receives a flash loan of 1,000,000 VISTA tokens:

```bash
│   │   ├─ VistaFinance::flashLoan(
│   │   │       0x10036d..., VistaFinance: [0x493361D6...2076],
│   │   │       1000000000000000000000000 [1e24], ...)
│   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000,
│   │   │   │               to:   0x10036d..., value: 1000000000000000000000000 [1e24])
```

*Caption: Flash‑mint of 1,000,000 VISTA tokens to the helper contract.*

These tokens are used transiently during the exploit and are burned back at the end of the flash loan, but they provide temporary balance to satisfy staking and allowance flows.

#### Step 2.4 – Overpriced Sale into the Sell Contract

- Within the flash loan callback, the helper contract:
  - Approves the sell contract to spend VISTA.
  - Calls `sell(36438840000000000000000, helper)` on the sell/buy contract.
  - The sell contract:
    - Calls `vistaForcePlan::price()` and receives 22.86 × 10¹⁸.
    - Pulls 1,594 VISTA from the helper via `VistaFinance::transferFrom`.
    - Sends 36,438.84 USDT from its balance to the helper via `BEP20USDT::transfer`.

Evidence (combined trace snippet):

```bash
│   │   │   │   ├─ 0xf738de...::sell(36438840000000000000000 [3.643e22], 0x10036d...)
│   │   │   │   │   ├─ vistaForcePlan::price() [staticcall]
│   │   │   │   │   │   └─ ← [Return] 22860000000000000000 [2.286e19]
│   │   │   │   │   ├─ VistaFinance::transferFrom(
│   │   │   │   │   │       0x10036d..., 0xf738de..., 1594000000000000000000 [1.594e21])
│   │   │   │   │   ├─ BEP20USDT::transfer(
│   │   │   │   │   │       0xf738de..., 0x10036d..., 36438840000000000000000 [3.643e22])
```

*Caption: sell() call exchanging 1,594 VISTA for 36,438.84 USDT at the mispriced oracle rate of 22.86.*

#### Step 2.5 – USDT → WBNB Swap and Flash-Loan Repayment

- The helper contract swaps 36,438.84 USDT back to WBNB using PancakeRouter, then returns 2,001 WBNB (principal + fee) to the flash‑loan pool.
- The remaining WBNB (~48.23 BNB equivalent) remains with the helper and is ultimately withdrawn to the EOA, as reflected in the balance diff.

At the end of the transaction:

- All flash‑loaned WBNB and VISTA are repaid/burned.
- The mispriced USDT reserves in the sell contract and WBNB liquidity suffer a net loss.
- The adversary EOA’s BNB balance increases by approximately 48.23 BNB.


# Impact & Losses

## Quantitative Impact (Per Seed Transaction)

- **USDT reserves in the sell contract**  
  - 36,438.84 USDT transferred from the sell contract (`0xf738de...`) to the adversary helper (`0x10036d...`) during `sell()`.

- **WBNB / BNB reserves**  
  - Net loss of ~48.23 WBNB/BNB value from the WBNB liquidity pool, corresponding to the adversary’s profit after repaying the flash loan.

These figures are directly supported by `balance_diff.json` for the seed transaction.

## Qualitative / Protocol-Level Impact

- **Immediate economic loss**  
  - The VistaFinance ecosystem loses protocol‑owned liquidity in both USDT (held in the sell contract) and WBNB (via the Pancake pool) as a result of honoring the mispriced VISTA redemptions.

- **Structural risk**  
  - As long as:
    - The ICO continues to sell VISTA at 1 BUSD per token, and  
    - The oracle `price` remains higher (e.g., 22.86), and  
    - The sell contract maintains significant USDT reserves,
  - The same arbitrage can be repeated by any unprivileged actor, potentially draining USDT reserves entirely.

- **User‑facing effects (not fully covered by artifacts)**  
  - The artifact set does not include subsequent blocks or additional attacks, so follow‑on impacts (such as price collapse of VISTA, further drains, or user withdrawal failures) are not directly evidenced here.
  - However, the presence of such a large, deterministic arbitrage opportunity is consistent with a severe economic exploit on protocol‑owned liquidity and can materially undermine user trust and token value.


# References

The following references correspond to the on‑disk artifacts used in this report (paths relative to the incident session root). They are listed for provenance; all essential information has been summarized in this document so that readers do not need to inspect the raw files.

- **[1] Seed transaction metadata and trace**  
  - Source: Seed artifacts for tx `0x84c385aab658d86b64e132e8db0c092756d5a9331a1131bf05f8214d08efba56`  
  - Contains:
    - `metadata.json` (basic tx info, block, gas).  
    - `trace.cast.log` (full `cast run -vvvvv` trace).  
    - `balance_diff.json` (pre‑/post‑state balance changes).

- **[2] VistaFinance token and ICO source code**  
  - Source: Collected contract bundle for VISTA token `0x493361D6164093936c86Dcb35Ad03b4C0D032076`.  
  - Contains:
    - VISTA ERC‑20 + `ERC20FlashMint` implementation.  
    - Related project files and tests.

- **[3] VistaFinanceICO contract source**  
  - Source: Collected source for ICO contract `0x7C98b0cEEaFCf5b5B30871362035f728955b328c`.  
  - Shows fixed‑rate 1:1 BUSD → VISTA `stake()` logic.

- **[4] VistaFinance sell/buy decompiled contract**  
  - Source: Decompiled EVM for sell/buy contract `0xf738de9913bc1e21b1a985bb0E39Db75091263b7`.  
  - Shows `buy()` and `sell()` implementations calling `vistaForcePlan.price()` and converting between USDT and VISTA.

- **[5] vistaForcePlan oracle source**  
  - Source: Collected source for oracle contract `0xb9c3401c846f3ac4ccd2bdb1901e41c1da463e10`.  
  - Shows the owner‑settable `price` variable and its use in `stake()` and the auto‑generated `price()` getter.

- **[6] Iter_2 Root Cause Analyzer intermediate analysis**  
  - Source: `current_analysis_result.json` from root cause analyzer iteration 2.  
  - Provides intermediate reasoning and cross‑checks that guided the final root cause synthesis in this report.


# Limitations

- The analysis is based solely on the provided on‑disk artifacts under the incident’s root cause directory.  
- Historical transactions for initial funding and helper deployment are referenced conceptually but not re‑fetched from external chain data.  
- The report focuses on the **documented seed exploit transaction** and does not assert whether additional attacks occurred before or after the observed block.

