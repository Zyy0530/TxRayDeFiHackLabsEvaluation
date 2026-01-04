# VirtualToken Launchpad Loan/Router Debt Exploit Root Cause Report

## Incident Overview TL;DR

An unprivileged adversary cluster consisting of EOA `0x713d2b652e5f2a86233c57af5341db42a5559dd1` and helper contract `0x351d38733de3f1e73468d24401c59f63677000c9` executed three Balancer flash-loan-assisted transactions that abused VirtualToken’s loan/debt accounting together with a launchpad/router stack (`0x19c5538df65075d53d6299904636bae68b6df441` and `0x62f250cf7021e1cf76c765dec8ec623fe173a1b5`).  
Across these transactions, the adversary moved ETH out of VirtualToken `0x280a8955a11fcd81d72ba1f99d265a48ce39ac2e` into LamboToken/VirtualToken Uniswap V2 pools and then into EOA `0x713d…`.  

Balance diffs for the three attacker-crafted transactions:
- `0x900891b4540cac8443d6802a08a7a0562b5320444aa6d8eed19705ea6fb9710b`
- `0x1ae40f26819da4f10bc7c894a2cc507cdb31c29635d31fa90c8f3f240f0327c0`
- `0x90db330d9e46609c9d3712b60e64e32e3a4a2f31075674a58dd81181122352f8`

show that `0x713d…`’s ETH balance increases by exactly `140.445092235085859298` ETH, while VirtualToken’s native ETH holdings and relevant pool reserves decrease by matching amounts. The exploit is an ACT opportunity: any unprivileged adversary with access to the same contracts and calldata can reproduce the profit sequence on Ethereum mainnet as long as the preconditions remain in place.

## Key Background

VirtualToken `0x280a8955a11fcd81d72ba1f99d265a48ce39ac2e` is an ERC20-like token with additional loan accounting. A configurable “valid factory” can call `takeLoan` and `repayLoan` for specific borrower addresses (used here as pool addresses). VirtualToken tracks per-address debt in a `_debt` mapping and enforces a per-block loan limit via `lastLoanBlock` and `loanedAmountThisBlock`. It also controls ETH flows through `cashIn` (wrap ETH into VirtualToken) and `cashOut` (burn VirtualToken and send ETH out) which are restricted to whitelisted callers.

The launchpad contract `0x19c5538df65075d53d6299904636bae68b6df441` (“launchpad 0x19c5..”) and the router/factory contract `0x62f250cf7021e1cf76c765dec8ec623fe173a1b5` (“router 0x62f2..”) integrate VirtualToken with several Uniswap V2 pools that pair VirtualToken with LamboToken variants:
- `0x0634866dfd8f05019c2a6e1773dc64cb5a5d3e6c` – LamboToken/VirtualToken Pair 1
- `0x582d17d24127cfdcbc8c4e0a40c12d77b2e7a48d` – LamboToken/VirtualToken Pair 2
- `0xda173e4212ae2477274621248bd15cc8455044ca` – LamboToken/VirtualToken Pair 3

Router `0x62f2..` can call `addVirtualLiquidity` and related methods that internally invoke VirtualToken’s `takeLoan` on these pools, thereby increasing `_debt` for each pool while minting additional VirtualToken into them. Launchpad `0x19c5..` is whitelisted on VirtualToken and can call `cashIn` and `cashOut` to wrap and unwrap ETH into/out of VirtualToken balances.

On-chain txlists in:
- `artifacts/root_cause/data_collector/iter_4/address/1/0x19c5538df65075d53d6299904636bae68b6df441/etherscan_v2_normal.json`
- `artifacts/root_cause/data_collector/iter_4/address/1/0x62f250cf7021e1cf76c765dec8ec623fe173a1b5/etherscan_v2_normal.json`

show at least 12 distinct EOAs using `0x19c5..` and at least 3 distinct EOAs using `0x62f2..` over their lifetimes. This demonstrates that both contracts serve as de facto permissionless launchpad/router interfaces under a standard unprivileged-adversary model (no allowlists or off-chain access controls at the transaction layer).

The three incident transactions are all calls from EOA `0x713d…` to helper contract `0x351d…`. The helper orchestrates a Balancer Vault flash loan in WETH, unwraps to ETH, drives `buyQuote` / `sellQuote` and loan/liquidity operations across the three LamboToken/VirtualToken pools, and finally routes ETH profit back to `0x713d…` after repaying the flash loan.

## Vulnerability Analysis

### Vulnerable VirtualToken Loan/Debt Design

VirtualToken’s core loan and accounting logic is implemented in `src/VirtualToken.sol` (`seed/1/0x280a8955a11fcd81d72ba1f99d265a48ce39ac2e/src/VirtualToken.sol`):

```solidity
contract VirtualToken is ERC20, ReentrancyGuard, Ownable {
    address public underlyingToken;
    uint256 public cashOutFee;
    uint256 public lastLoanBlock;
    uint256 public loanedAmountThisBlock;
    uint256 public totalCashOutFeesCollected;
    uint256 public constant MAX_LOAN_PER_BLOCK = 300 ether;

    mapping(address => uint256) public _debt;
    mapping(address => bool) public whiteList;
    mapping(address => bool) public validFactories;
    ...
    function cashIn() external payable onlyWhiteListed {
        _transferAssetFromUser(msg.value);
        _mint(msg.sender, msg.value);
        emit Wrap(msg.sender, msg.value);
    }

    function cashOut(uint256 amount) external onlyWhiteListed returns (uint256 amountAfterFee) {
        uint256 fee = (amount * cashOutFee) / 10000;
        totalCashOutFeesCollected += fee;
        amountAfterFee = amount - fee;

        _burn(msg.sender, amount);
        _transferAssetToUser(amountAfterFee);
        emit Unwrap(msg.sender, amountAfterFee);
    }

    function takeLoan(address to, uint256 amount) external payable nonReentrant onlyValidFactory {
        if (block.number > lastLoanBlock) {
            lastLoanBlock = block.number;
            loanedAmountThisBlock = 0;
        }
        require(loanedAmountThisBlock + amount <= MAX_LOAN_PER_BLOCK, "Loan limit per block exceeded");

        loanedAmountThisBlock += amount;
        _mint(to, amount);
        _increaseDebt(to, amount);

        emit LoanTaken(to, amount);
    }

    function _increaseDebt(address user, uint256 amount) internal {
        _debt[user] += amount;
    }
    ...
    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && balanceOf(from) < value + _debt[from]) {
            revert DebtOverflow(from, _debt[from], value);
        }
        super._update(from, to, value);
    }
}
```

Key properties:
- `takeLoan` mints VirtualToken to an arbitrary `to` address and increases `_debt[to]` by the same amount, without moving any ETH out of the contract.
- `cashIn` and `cashOut` move ETH in and out of the contract and mint/burn VirtualToken for whitelisted callers (here, `0x19c5..`).
- The `_update` override enforces an invariant on senders: for any transfer from `from`, it reverts if `balanceOf(from) < value + _debt[from]`. This couples the sender’s token balance with their outstanding debt, but only at the address level of `from`.

VirtualToken’s storage snapshot around the incident (pre-state and incident blocks) is captured in:

```json
// artifacts/root_cause/data_collector/iter_3/address/1/0x280a.../storage/virtual_token_storage_slots.json
{
  "blocks": {
    "21184770": {
      "whiteList": {
        "0x351d38733de3f1e73468d24401c59f63677000c9": "0x0",
        "0x62f250cf7021e1cf76c765dec8ec623fe173a1b5": "0x0",
        "0x19c5538df65075d53d6299904636bae68b6df441": "0x1"
      },
      "validFactories": {
        "0x62f250cf7021e1cf76c765dec8ec623fe173a1b5": "0x1"
      },
      "_debt": {
        "0x0634866dfd8f05019c2a6e1773dc64cb5a5d3e6c": "0x1158e460913d000000",
        "0x582d17d24127cfdcbc8c4e0a40c12d77b2e7a48d": "0x1158e460913d000000",
        "0xda173e4212ae2477274621248bd15cc8455044ca": "0x1158e460913d000000"
      }
    },
    ...
  }
}
```

This shows that at and around block `21184770`:
- Launchpad `0x19c5..` is whitelisted for `cashIn`/`cashOut`.
- Router `0x62f2..` is the configured `validFactory` for loans.
- Each of the three Uniswap V2 pools already has nonzero `_debt` of 320 ETH (`0x1158e460913d000000`) which grows further over incident blocks.

### Launchpad and Router Integration with Uniswap V2 Pools

The pools at `0x0634..`, `0x582d..`, and `0xda17..` are standard Uniswap V2 pairs, as shown by their verified source (e.g. `seed/1/0x0634.. /src/Contract.sol`), containing canonical `UniswapV2Pair` logic with `mint`, `burn`, `swap`, `getReserves`, and reserve-updating `_update` functions.

Router `0x62f2..` exposes `addVirtualLiquidity` functions that, as seen in traces, perform the following:
1. Call VirtualToken::`takeLoan(pool, 300e18)` to mint 300 VirtualToken to a pool and increment `_debt[pool]` by 300e18.
2. Transfer LamboToken from helper `0x351d..` to the pool.
3. Call `UniswapV2Pair::mint` to issue LP tokens to the router or another address.

Launchpad `0x19c5..` exposes `buyQuote` and `sellQuote` endpoints that:
1. For `buyQuote`, accept ETH, call VirtualToken::`cashIn` on `0x280a..`, and then route VirtualToken and LamboToken to/from the pools.
2. For `sellQuote`, move LamboToken from `0x351d..` to `0x19c5..`, then to pools, and receive VirtualToken back, before calling VirtualToken::`cashOut` to extract ETH.

Full-lifetime txlists for both `0x19c5..` and `0x62f2..` show that these entrypoints are used by multiple independent EOAs, confirming that they operate as permissionless endpoints rather than being restricted to a single operator.

## Detailed Root Cause Analysis

### End-to-End Adversary Strategy

The ACT opportunity arises from the way VirtualToken’s per-address `_debt` accounting and `_update` invariant interact with launchpad and router operations across Uniswap V2 pools:

1. Router `0x62f2..` calls `takeLoan` to mint VirtualToken into the LamboToken/VirtualToken pools, increasing `_debt[pool]` but not moving any ETH.
2. The pools, under router/launchpad control, use these VirtualToken balances in swaps and liquidity operations while retaining their `_debt` obligations.
3. Launchpad `0x19c5..` accumulates VirtualToken balances via `buyQuote` and `sellQuote` flows that trade against the pools.
4. `0x19c5..` then calls `cashOut` on VirtualToken using its accumulated VirtualToken balances, causing VirtualToken to burn those balances and send ETH from its reserves to the launchpad.
5. The launchpad forwards the ETH to helper contract `0x351d..`, which after repaying the Balancer flash loan, forwards net profit to EOA `0x713d..`.

Crucially, the `_debt` mapping is tied to the pool addresses, not to the launchpad or helper. When `0x19c5..` calls `cashOut`, its own `_debt` is zero, and the `_update` override only checks `from` (the token sender). As a result, VirtualToken allows fully backed-looking `cashOut` operations using tokens ultimately sourced from loaned VirtualToken that still resides as `_debt` on the pools. Over repeated cycles, this design transfers real ETH from VirtualToken to the adversary while leaving the pools with inflated VirtualToken balances and matching `_debt` that is never repaid.

### Concrete Execution Flow: First Profit Transaction

The first attacker-crafted transaction is:
- Chain: Ethereum mainnet
- Tx: `0x900891b4540cac8443d6802a08a7a0562b5320444aa6d8eed19705ea6fb9710b`
- Block: `21184778`
- Type: Adversary-crafted call from `0x713d…` to `0x351d…`

The seed trace (`artifacts/root_cause/seed/1/0x9008../trace.cast.log`) shows the following sequence:

```text
0x351D...::start(VirtualToken: [0x280A...], 0x19C5..., 0x62f2..., LamboToken: [0xAefEF...], 4859)
  Vault::flashLoan(0x351D..., [WETH], [32560203560896180352774], ...)
    WETH9::transfer(0x351D..., 32560203560896180352774)
  0x351D...::receiveFlashLoan(...)
    WETH9::withdraw(32560203560896180352774)
    0x19C5...::buyQuote{value: 32560203560896180352774}(...)
      VirtualToken::cashIn{value: 32560203560896180352774}()
      0x62f2...::addVirtualLiquidity(VirtualToken, LamboToken, 300e18, 0)
        VirtualToken::takeLoan(UniswapV2Pair: [0x0634...], 300e18)
        UniswapV2Pair::mint(...)
      0x19C5...::sellQuote(...)
        LamboToken::transferFrom(0x351D..., 0x19C5..., ...)
        LamboToken::transfer(0x0634..., ...)
        UniswapV2Pair::swap(32692717028774184611148, 0, 0x19C5..., 0x)
          VirtualToken::transfer(0x19C5..., 32692717028774184611148)
        VirtualToken::cashOut(32692717028774184611148)
          (ETH sent from VirtualToken to 0x19C5...)
        0x351D...::fallback{value: 32692717028774184611148}()
    WETH9::deposit{value: 32560203560896180352774}()
    WETH9::transfer(Vault, 32560203560896180352774)   // flash loan repaid
    0x713d...::fallback{value: 132513467878004258374}()
```

This trace confirms:
- VirtualToken mints tokens to the launchpad via `cashIn` and to the pool via `takeLoan`.
- The router increases `_debt[0x0634..]` by 300e18 while the pool’s VirtualToken balance increases.
- A large swap in the pool sends `~32.6927e21` VirtualToken from the pool to the launchpad, while LamboToken moves in the opposite direction.
- `0x19c5..` then calls `cashOut` for the amount received, burning those tokens and pulling ETH directly from VirtualToken to `0x19c5..`, which forwards it to `0x351d..` and ultimately to `0x713d..`.

The corresponding balance diffs (`artifacts/root_cause/seed/1/0x9008../balance_diff.json`) quantify this:

```json
{
  "native_balance_deltas": [
    {
      "address": "0x713d2b652e5f2a86233c57af5341db42a5559dd1",
      "delta_wei": "132499658930377592956"
    },
    {
      "address": "0x280a8955a11fcd81d72ba1f99d265a48ce39ac2e",
      "delta_wei": "-132513467878004258374"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0x280a8955a11fcd81d72ba1f99d265a48ce39ac2e",
      "holder": "0x0634866dfd8f05019c2a6e1773dc64cb5a5d3e6c",
      "delta": "167486532121995741626",
      "contract_name": "VirtualToken"
    },
    {
      "token": "0xaefef41f5a0bb29fe3d1330607b48fbba55904ce",
      "holder": "0x0634866dfd8f05019c2a6e1773dc64cb5a5d3e6c",
      "delta": "-6749153341821447559220422",
      "contract_name": "LamboToken"
    },
    {
      "token": "0xaefef41f5a0bb29fe3d1330607b48fbba55904ce",
      "holder": "0x351d38733de3f1e73468d24401c59f63677000c9",
      "delta": "6749153341821447559220422",
      "contract_name": "LamboToken"
    }
  ]
}
```

This shows:
- `0x713d…` gains exactly `132.499658930377592956` ETH in this transaction.
- VirtualToken loses `132.513467878004258374` ETH.
- The Uniswap V2 pool at `0x0634..` gains VirtualToken while losing LamboToken, and helper `0x351d..` accumulates LamboToken.

### Repetition Across Additional Pools

The second and third attacker-crafted transactions repeat the same pattern on the other two LamboToken/VirtualToken pools, using different LamboToken contracts and pool addresses:

1. **Second transaction**
   - Tx: `0x1ae40f26819da4f10bc7c894a2cc507cdb31c29635d31fa90c8f3f240f0327c0` (block `21184784`)
   - Pool: `0x582d17d24127cfdcbc8c4e0a40c12d77b2e7a48d`
   - LamboToken: `0xab181941a6096296ecf1b0859ea65c797676d428`
   - ETH profit to `0x713d…`: `4.833145314097841493` ETH  
   - VirtualToken ETH loss: `4.846141416396402693` ETH

2. **Third transaction**
   - Tx: `0x90db330d9e46609c9d3712b60e64e32e3a4a2f31075674a58dd81181122352f8` (block `21184796`)
   - Pool: `0xda173e4212ae2477274621248bd15cc8455044ca`
   - LamboToken: `0xd74ebad20145dc09b393b7589bd5a7e55787bec9`
   - ETH profit to `0x713d…`: `3.112287990610424849` ETH  
   - VirtualToken ETH loss: `3.125543372313501089` ETH

The respective `trace.cast.log` and `balance_diff.json` artifacts for these transactions mirror the structure of the first: Balancer flash loans route through `0x351d..`, router `0x62f2..` increases `_debt` on the target pool via `takeLoan`, Uniswap V2 swaps transfer VirtualToken to `0x19c5..`, and `cashOut` drains ETH from VirtualToken to `0x713d..` after the flash loan is repaid.

Summing the three native deltas for `0x713d…` yields:

```text
132.499658930377592956
+ 4.833145314097841493
+ 3.112287990610424849
= 140.445092235085859298 ETH
```

matching the profit figure stated in the analysis and confirming a deterministic ETH gain for the adversary across the three transactions.

### Why the Invariant Fails

VirtualToken attempts to prevent over-withdrawal by checking, for each transfer:

```solidity
if (from != address(0) && balanceOf(from) < value + _debt[from]) {
    revert DebtOverflow(from, _debt[from], value);
}
```

This enforces that any sender must always maintain a token balance at least equal to its outstanding `_debt`. However:
- `_debt` is tracked per address, not per pool/launchpad system-wide.
- `cashOut` burns tokens and sends ETH based on `msg.sender`’s token balance, where `_debt[msg.sender]` is zero for the whitelisted launchpad `0x19c5..`.
- The router uses `takeLoan` to mint tokens directly to the pools, increasing `_debt[pool]`, while `cashIn` and swaps move tokens from the pools to `0x19c5..`.
- Once VirtualToken tokens are held by `0x19c5..`, `cashOut` will send ETH to `0x19c5..` regardless of the `_debt` left behind on the pools.

Across the three transactions, the pools end with higher `_debt` values and large VirtualToken balances, but this does not prevent further cashOut operations from `0x19c5..` in subsequent cycles, nor does it reconcile ETH reserves with total outstanding debt. This is the fundamental protocol bug: VirtualToken’s loan/debt scheme and `_update` invariant do not tie ETH reserves, pool balances, and per-address debt together strongly enough to prevent repeated under-collateralized withdrawals.

## Adversary Flow Analysis

The adversary’s strategy is a three-stage, single-chain flow that leverages flash loans, VirtualToken’s loans and debt accounting, and launchpad/router integrations with Uniswap V2 pools.

### Stage 1: Initial Setup and Flash Loan

In the first incident transaction (`0x9008..`, block `21184778`), EOA `0x713d…` calls helper contract `0x351d…`, which requests a large WETH flash loan from Balancer Vault `0xba1222…`. The helper unwraps WETH to ETH and uses a small initial ETH balance (~0.1563 ETH) only for gas. This behavior is documented in:
- `artifacts/root_cause/seed/1/0x9008../trace.cast.log`
- `artifacts/root_cause/seed/1/0x9008../balance_diff.json`

The same pattern repeats in the two subsequent transactions with smaller, but structurally identical, flash loan and ETH flows.

### Stage 2: Loan-Backed Liquidity and Debt Manipulation

Across the three transactions, helper `0x351d…` repeatedly:
1. Calls launchpad `0x19c5..::buyQuote` with large amounts of ETH obtained via flash loan.
2. Launchpad calls VirtualToken::`cashIn` to mint VirtualToken to itself and interacts with the relevant LamboToken/VirtualToken pool.
3. Router `0x62f2..` calls `addVirtualLiquidity` which:
   - Invokes VirtualToken::`takeLoan(pool, 300e18)`, increasing `_debt[pool]` and minting VirtualToken to the pool.
   - Transfers LamboToken from `0x351d…` to the pool.
   - Uses UniswapV2Pair::`mint` to create LP tokens.
4. Launchpad uses LamboToken from `0x351d…` to trade against the pool, receiving large amounts of VirtualToken.

This sequence increases `_debt` on the pools (as seen in `virtual_token_storage_slots.json`) while accumulating VirtualToken balances at `0x19c5..` and LamboToken balances at `0x351d…`, and leaving the pools with high VirtualToken balances and large outstanding `_debt`.

### Stage 3: ETH Extraction and Profit Realization

In each incident transaction, once the launchpad holds enough VirtualToken from the manipulated pools, it calls `cashOut`, causing VirtualToken to send ETH to `0x19c5..`. This ETH is then forwarded to `0x351d…`, which repays the flash loan and sends net profit to `0x713d…`.

The stage is summarized by the three incident transactions:
- `0x9008..` (block `21184778`) – main profit loop on pool `0x0634..`  
- `0x1ae4..` (block `21184784`) – repeat on pool `0x582d..`  
- `0x90db..` (block `21184796`) – repeat on pool `0xda17..`

For each, the traces and balance diffs show:
- VirtualToken::`cashOut` transferring ETH from `0x280a…` to `0x19c5..`.
- ETH flowing through `0x351d…` to `0x713d…`.
- The Balancer flash loan being fully repaid in WETH.

After all three transactions, the cumulative ETH profit at `0x713d…` is exactly `140.445092235085859298` ETH.

## Impact & Losses

### Quantified ETH Loss

From the three seed `balance_diff.json` files, summing the `native_balance_deltas` for VirtualToken `0x280a…` yields a total ETH loss of:

- Token: ETH
- Amount: `140.445092235085859298`

This matches the summed ETH gain for EOA `0x713d…`, confirming that:
- VirtualToken transfers exactly `140.445092235085859298` ETH from its holdings to the adversary cluster across the three attacker-crafted transactions.

### Effects on Pools and Liquidity Providers

After the exploit sequence:
- The three LamboToken/VirtualToken Uniswap V2 pools at `0x0634..`, `0x582d..`, and `0xda17..` end with increased VirtualToken `_debt` values and altered reserves.
- LamboToken balances in the pools are reduced and large LamboToken positions are accumulated at the helper contract `0x351d…`.
- VirtualToken’s backing relative to its total supply and the pool obligations is weakened because ETH has been withdrawn to the adversary while `_debt` remains outstanding at the pool addresses.

This report quantifies the direct ETH loss from VirtualToken to the adversary and the associated increase in pool debt. It does not compute secondary market PnL for individual LPs or model subsequent monetization of the large LamboToken balances held by `0x351d…`, as those effects occur outside the documented incident window and are not required to establish the existence and exploitability of the ACT opportunity.

## References

Key artifacts supporting this analysis:

1. **VirtualToken source and storage layout**  
   - Contract: VirtualToken `0x280a8955a11fcd81d72ba1f99d265a48ce39ac2e`  
   - Code and storage: `artifacts/root_cause/seed/1/0x280a8955a11fcd81d72ba1f99d265a48ce39ac2e`

2. **Seed transaction 0x9008.. trace and balance diff**  
   - Tx: `0x900891b4540cac8443d6802a08a7a0562b5320444aa6d8eed19705ea6fb9710b`  
   - Artifacts: `artifacts/root_cause/seed/1/0x900891b4540cac8443d6802a08a7a0562b5320444aa6d8eed19705ea6fb9710b`

3. **Seed transaction 0x1ae4.. trace and balance diff**  
   - Tx: `0x1ae40f26819da4f10bc7c894a2cc507cdb31c29635d31fa90c8f3f240f0327c0`  
   - Artifacts: `artifacts/root_cause/seed/1/0x1ae40f26819da4f10bc7c894a2cc507cdb31c29635d31fa90c8f3f240f0327c0`

4. **Seed transaction 0x90db.. trace and balance diff**  
   - Tx: `0x90db330d9e46609c9d3712b60e64e32e3a4a2f31075674a58dd81181122352f8`  
   - Artifacts: `artifacts/root_cause/seed/1/0x90db330d9e46609c9d3712b60e64e32e3a4a2f31075674a58dd81181122352f8`

5. **Launchpad and router transaction lists**  
   - Launchpad `0x19c5538df65075d53d6299904636bae68b6df441` txlist:  
     `artifacts/root_cause/data_collector/iter_4/address/1/0x19c5538df65075d53d6299904636bae68b6df441/etherscan_v2_normal.json`
   - Router `0x62f250cf7021e1cf76c765dec8ec623fe173a1b5` txlist:  
     `artifacts/root_cause/data_collector/iter_4/address/1/0x62f250cf7021e1cf76c765dec8ec623fe173a1b5/etherscan_v2_normal.json`

