# BBXToken BBX–USDT Auto-Burn Exploit on BSC

## Incident Overview & TL;DR

On BSC (chainid 56), EOA `0x8aea7516b3b6aabf474f8872c5e71c1a7907e69e` deployed a helper contract `0x0489e8433e4e74fb1ba938df712c954ddea93898` and used it to repeatedly trigger BBXToken `0x67ca347e7b9387af4e81c36cca4eaf080dcb33e9`’s auto-burn hook against the BBX–USDT PancakeSwap pair `0x6051428b580f561b627247119eed4d0483b8d28e`. By driving many consecutive burn-and-sync operations on this pool and then executing a final swap in transaction `0x0dd486368444598610239b934dd9e8c6474a06d11380d1cfec4d91568b5ac581`, the adversary drained approximately `11,905.927933743202788913` USDT (18 decimals) from the pool to the same EOA.

This incident qualifies as an ACT opportunity: the exploit uses only public contracts (PancakeRouter `0x10ed43c718714eb63d5aa57b78b54704e256024e` and standard BEP20 tokens), no privileged roles, and can be reproduced by any EOA that submits the same sequence of transactions with sufficient gas. The root cause category is a **protocol_bug** in the BBXToken contract’s transfer logic, not an infrastructure or off-chain failure.

At a high level, the root cause is that BBXToken’s `_transfer` implementation burns a fraction of BBX from a globally configured `liquidityPool` and calls `sync()` on the underlying PancakeSwap pair whenever `block.timestamp >= lastBurnTime + lastBurnGapTime`, but never updates `lastBurnTime` and does not restrict who can trigger this logic. Once the burn window opens, any account can cause an arbitrary number of burn-and-sync operations on the BBX–USDT pool and then drain USDT at a manipulated price.

## Key Background

### Protocol and Token Setup

- **Protocol / Pool**: BBXToken / BBX–USDT PancakeSwap pool on BSC.
- **BBXToken**: `0x67ca347e7b9387af4e81c36cca4eaf080dcb33e9`  
  - ERC20 token with total supply `10,000,000 * 10^decimals`.  
  - Implements tax logic on buys and sells against a designated `liquidityPool`.  
  - Includes an auto-burn mechanism that interacts directly with a PancakeSwap pair via `IPancakePari(liquidityPool).sync()`.  
  - Source collected from chain: `/artifacts/root_cause/seed/_contracts/56/0x67ca347e7b9387af4e81c36cca4eaf080dcb33e9/source/src/Contract.sol`.
- **USDT (BEP20USDT)**: `0x55d398326f99059ff775485246999027b3197955`  
  - Uses 18 decimals (`_decimals = 18`), so all USDT values in traces and balance diffs are expressed in 18-decimal units.  
  - Source collected from chain: `/artifacts/root_cause/seed/_contracts/56/0x55d398326f99059ff775485246999027b3197955/source/src/Contract.sol`.
- **WBNB**: `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c` (standard wrapped BNB token; source also collected under `seed/_contracts/56/...`).
- **BBX–USDT PancakeSwap pair (victim pool)**: `0x6051428b580f561b627247119eed4d0483b8d28e`, stored in `BBXToken.liquidityPool`.
- **Upstream WBNB–USDT PancakeSwap pair**: `0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae`, used to source USDT for seeding the BBX–USDT pool via PancakeRouter.

In the BBXToken constructor:

- `usdtToken` is set to BEP20USDT `0x55d398326f99059fF775485246999027B3197955`.
- A PancakeSwap liquidity pool is created via `IUniswapFactory(_factouy).createPair(usdtToken, address(this))`.
- The newly created pair address is stored in `liquidityPool`.
- `lastBurnTime` is initialized to `block.timestamp`.
- `lastBurnGapTime` is initialized to `1 days`.

In a constant-product AMM such as PancakeSwap, burning BBX from a BBX–USDT pair while keeping USDT constant reduces the BBX reserve, increases the implied BBX price, and allows a subsequent swap to withdraw more USDT for a given BBX change than would be possible under the original reserves, directly harming LPs.

### Act Opportunity State (Pre-Exploit)

The analysis fixes a pre-exploit state `σ_B` at BSC block `47626457`, immediately before the first adversary transaction `0xf7019e1232704c3ede4ecf00b79ccf647b2cb3718b9f6972e70dc7c5170e3f91` executes. In this state:

- BBXToken, BEP20USDT, WBNB, the BBX–USDT PancakePair, and the upstream WBNB–USDT PancakePair exist with their on-chain balances and configurations.
- The BBX–USDT pair is already configured as `BBXToken.liquidityPool`.
- The WBNB–USDT pair holds USDT that can be routed via PancakeRouter into the BBX–USDT pool.

**Seed / pre-state evidence (as collected):**

- Seed tx metadata and traces for both adversary transactions:  
  - `/artifacts/root_cause/seed/56/0xf7019e1232704c3ede4ecf00b79ccf647b2cb3718b9f6972e70dc7c5170e3f91/metadata.json`  
  - `/artifacts/root_cause/seed/56/0xf7019e1232704c3ede4ecf00b79ccf647b2cb3718b9f6972e70dc7c5170e3f91/trace.cast.log`  
  - `/artifacts/root_cause/seed/56/0x0dd486368444598610239b934dd9e8c6474a06d11380d1cfec4d91568b5ac581/metadata.json`  
  - `/artifacts/root_cause/seed/56/0x0dd486368444598610239b934dd9e8c6474a06d11380d1cfec4d91568b5ac581/trace.cast.log`
- Verified or reconstructed contract sources:  
  - BBXToken, BEP20USDT, and WBNB sources under `seed/_contracts/56/...`.
- Decompiled helper contract:  
  - `/artifacts/root_cause/data_collector/iter_1/contract/56/0x0489e8433e4e74fb1ba938df712c954ddea93898/decompile/0x0489e8433e4e74fb1ba938df712c954ddea93898-decompiled.sol`.
- PrestateTracer balance diffs:  
  - `/artifacts/root_cause/data_collector/iter_1/tx/56/0xf7019e1232704c3ede4ecf00b79ccf647b2cb3718b9f6972e70dc7c5170e3f91/balance_diff.json`  
  - `/artifacts/root_cause/data_collector/iter_1/tx/56/0x0dd486368444598610239b934dd9e8c6474a06d11380d1cfec4d91568b5ac581/balance_diff.json`.
- EOA-normal txlist around the incident:  
  - `/artifacts/root_cause/data_collector/iter_1/address/56/0x8aea7516b3b6aabf474f8872c5e71c1a7907e69e/normal_txlist.json`.

## Vulnerability & Root Cause Analysis

### Auto-Burn Hook in BBXToken::_transfer

BBXToken implements a time-gated auto-burn hook that operates directly on its AMM liquidity pool. The relevant fragment of the BBXToken source (Contract.sol for `0x67ca347e7b9387af4e81c36cca4eaf080dcb33e9`) is:

```solidity
// BBXToken auto-burn block (from Contract.sol)
if (block.timestamp >= lastBurnTime + lastBurnGapTime) {
    uint256 totalNum = this.balanceOf(liquidityPool);
    uint256 burnNum = totalNum * burnRate / 10000;
    super._transfer(liquidityPool, address(0xdead), burnNum);
    IPancakePari(liquidityPool).sync();
}
```

**Snippet origin:** Collected BBXToken source (Contract.sol) for contract `0x67ca347e7b9387af4e81c36cca4eaf080dcb33e9`.

Key properties of this code as implemented on-chain:

- `liquidityPool` is a global variable pointing to the BBX–USDT PancakeSwap pair `0x6051428b580f561b627247119eed4d0483b8d28e`.
- `burnRate` is a configurable fraction (initially `300`, i.e., 3% when divided by `10000`).
- `lastBurnTime` is set in the constructor and is **never updated again**, including inside `_transfer`.
- `lastBurnGapTime` is set to `1 days`.

Within `_transfer`, this block executes whenever `block.timestamp >= lastBurnTime + lastBurnGapTime`. Once the inequality first becomes true, it stays true for all later blocks because `lastBurnTime` is never updated. There is no additional guard on `msg.sender`, `from`, `recipient`, or `amount` for entering the burn path: any transfer that reaches this block (including transfers of `0` tokens between arbitrary addresses) will:

1. Compute `burnNum = balanceOf(liquidityPool) * burnRate / 10000`.
2. Transfer `burnNum` BBX from the liquidity pool to the burn address `0x000000000000000000000000000000000000dEaD`.
3. Call `sync()` on the PancakeSwap pair so that the reserves reflect the reduced BBX balance.

This design hands a permanent, unbounded burn-and-reserve-skew capability over the BBX–USDT pool to any account that can cause `BBXToken::_transfer` to run, without distinguishing protocol-owned actions from external actors.

### Helper Contract Design

The helper contract `0x0489e8433e4e74fb1ba938df712c954ddea93898` is specifically designed to drive this auto-burn logic. The decompiled helper (Heimdall-rs v0.9.2) contains a function with selector `0x5f83db9b` that:

```solidity
// Helper contract core logic (decompiled)
contract DecompiledContract {
    bytes32 store_a;

    /// @custom:selector 0x5f83db9b
    function Unresolved_5f83db9b(address arg0, uint256 arg1) public {
        require(arg0 == (address(arg0)));
        require(msg.sender == (address(store_a)));
        (bool success, bytes memory ret0) = address(arg0).lastBurnTime();      // staticcall
        (bool success, bytes memory ret0) = address(arg0).lastBurnGapTime();   // staticcall
        (bool success, bytes memory ret0) = address(arg0).liquidityPool();     // staticcall
        (bool success, bytes memory ret0) = address(arg0).burnRate();          // staticcall
        // ... subsequent logic drives BBXToken::transfer and related calls ...
    }
}
```

**Snippet origin:** Decompiled helper contract source for `0x0489e8433e4e74fb1ba938df712c954ddea93898`.

Important observations:

- The helper requires `msg.sender == address(store_a)`, binding usage to a specific controlling address.
- It reads `lastBurnTime`, `lastBurnGapTime`, `liquidityPool`, and `burnRate` from the target token contract, confirming that it is explicitly tailored to interact with tokens implementing this pattern (here, BBXToken).
- In the actual exploit trace, the helper then issues repeated `BBXToken::transfer` calls that trigger the burn-and-sync logic on the BBX–USDT pair.

### On-Chain Evidence of the Burn-and-Sync Exploit

The seed trace for the second adversary transaction (`0x0dd486368444598610239b934dd9e8c6474a06d11380d1cfec4d91568b5ac581`) shows the helper contract repeatedly calling `BBXToken::transfer` with zero amount, each time burning BBX from the liquidity pool and syncing reserves:

```text
// Seed transaction trace for 0x0dd48636... (excerpt)
0x0489E8433e4E74fB1ba938dF712c954DDEA93898::5f83db9b( ... target = BBXToken ...)
  ├─ BBXToken::lastBurnTime()         → 1742375453
  ├─ BBXToken::lastBurnGapTime()      → 86400
  ├─ BBXToken::liquidityPool()        → PancakePair 0x6051428B580f561B627247119EEd4D0483B8D28e
  ├─ BBXToken::burnRate()             → 300
  ├─ BBXToken::transfer(0x0489..., 0)
  │   ├─ BBXToken::balanceOf(PancakePair 0x6051...) → 9911575883587736770542
  │   ├─ emit Transfer(from: PancakePair 0x6051..., to: 0x0000...dEaD, value: 297347276507632103116)
  │   ├─ PancakePair::sync()
  │   └─ ...
  ├─ BBXToken::transfer(0x0489..., 0)
  │   ├─ emit Transfer(from: PancakePair 0x6051..., to: 0x0000...dEaD, value: 288426858212403140022)
  │   ├─ PancakePair::sync()
  │   └─ ...
  ├─ (additional repeated BBXToken::transfer(0x0489..., 0) + sync() calls)
```

**Snippet origin:** Seed transaction trace (`trace.cast.log`) for tx `0x0dd486368444598610239b934dd9e8c6474a06d11380d1cfec4d91568b5ac581`.

Each iteration:

- Reads the current BBX balance at the liquidity pool.
- Burns a fraction of that BBX balance (according to `burnRate`) to `0x000000000000000000000000000000000000dEaD`.
- Calls `sync()` so PancakeSwap’s reserves incorporate the reduced BBX balance while the USDT balance remains unchanged.

PrestateTracer balance diffs for the same transaction show the net effect on BBX and USDT balances:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x67ca347e7b9387af4e81c36cca4eaf080dcb33e9",
      "holder": "0x6051428b580f561b627247119eed4d0483b8d28e",
      "before": "9911575883587736770542",
      "after": "12938879334679926716",
      "delta": "-9898637004253056843826",
      "contract_name": "BBXToken"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x6051428b580f561b627247119eed4d0483b8d28e",
      "before": "11908084752893273069840",
      "after": "2156819150070280927",
      "delta": "-11905927933743202788913",
      "contract_name": "BEP20USDT"
    }
  ]
}
```

**Snippet origin:** PrestateTracer `balance_diff.json` for tx `0x0dd486368444598610239b934dd9e8c6474a06d11380d1cfec4d91568b5ac581`.

These diffs show:

- The BBX–USDT pair loses approximately `9,898.637004253056843826` BBX (18 decimals) from its BBX balance, overwhelmingly burned to `0x000000000000000000000000000000000000dEaD` and partially redirected to tax and dividend wallets `0x849d09e4dbd4ec5449ec7d807dd137be6db002c6` and `0xe6acc53b8f9327ddf029ffed36186471d92b6837`.
- The same pair loses `11,905.927933743202788913` USDT from its USDT balance, which is sent to the adversary’s EOA in the final swap.

### Root Cause Summary

The root cause is a **broken time-gated auto-burn invariance** in BBXToken’s transfer logic:

- `lastBurnTime` is used as a gating variable for periodic burns, but it is never updated after deployment.
- As soon as `block.timestamp >= lastBurnTime + lastBurnGapTime` becomes true, it remains true forever.
- Any transfer that executes `_transfer` (including zero-amount transfers orchestrated through the helper contract) can trigger a burn-and-sync on the global `liquidityPool`, regardless of who initiates the transfer or whether they own any LP tokens.
- This gives arbitrary external actors ongoing, unbounded ability to manipulate the BBX–USDT pool’s reserves and price, which the adversary exploits to drain USDT after compressing the BBX reserve.

## Adversary Flow Analysis

### Transaction Sequence (σ_B → Exploit)

The core adversary sequence in block `47626457` is:

1. **Tx 1 (adversary-crafted)**  
   - **Chain**: BSC (`chainid = 56`)  
   - **Tx hash**: `0xf7019e1232704c3ede4ecf00b79ccf647b2cb3718b9f6972e70dc7c5170e3f91`  
   - **Role**: Deploy and seed.  
   - **Inclusion feasibility**:  
     - Standard contract-creation transaction from EOA `0x8aea7516b3b6aabf474f8872c5e71c1a7907e69e`, funded with `0.05` BNB.  
     - Uses public PancakeRouter `0x10ed43c718714eb63d5aa57b78b54704e256024e`.  
     - Uses public tokens BEP20USDT `0x55d398326f99059ff775485246999027b3197955` and BBXToken `0x67ca347e7b9387af4e81c36cca4eaf080dcb33e9`.  
     - No privileged checks appear in the trace; any EOA with the same inputs and gas can deploy the helper contract and perform the same swaps.  
   - **Notes / effect**:  
     - Deploys helper contract `0x0489e8433e4e74fb1ba938df712c954ddea93898` with `0.05` BNB.  
     - In the constructor, routes `WBNB → USDT → BBX` via PancakeRouter so that USDT from the WBNB–USDT pair `0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae` flows into the BBX–USDT pair `0x6051428b580f561b627247119eed4d0483b8d28e`.  
     - BBX flows from the BBX–USDT pair to tax and dividend wallets `0x849d09e4dbd4ec5449ec7d807dd137be6db002c6` and `0xe6acc53b8f9327ddf029ffed36186471d92b6837`, adjusting the initial pool composition in a way that sets up later burns.

2. **Tx 2 (adversary-crafted)**  
   - **Chain**: BSC (`chainid = 56`)  
   - **Tx hash**: `0x0dd486368444598610239b934dd9e8c6474a06d11380d1cfec4d91568b5ac581`  
   - **Role**: Main exploit.  
   - **Inclusion feasibility**:  
     - Regular call from the same EOA `0x8aea7516b3b6aabf474f8872c5e71c1a7907e69e` to helper contract `0x0489e8433e4e74fb1ba938df712c954ddea93898`.  
     - Uses function selector `0x5f83db9b` with parameters `(target = BBXToken 0x67ca347e7b9387af4e81c36cca4eaf080dcb33e9, arg1 = 0x1f4)`.  
     - The helper enforces only `msg.sender == address(store_a)` and otherwise uses public view functions (`lastBurnTime`, `lastBurnGapTime`, `liquidityPool`, `burnRate`) and public `BBXToken::transfer` plus PancakePair `sync`/`swap` calls.  
     - Any EOA that previously deployed the same helper with identical configuration can send this call without special permissions.  
   - **Notes / effect**:  
     - Executes a loop of `BBXToken::transfer` calls that trigger `_transfer`’s burn-from-liquidityPool path on the BBX–USDT pair.  
     - Each iteration burns BBX from the pair to `0x000000000000000000000000000000000000dEaD` and tax wallets and then calls `PancakePair::sync()`, progressively reducing the BBX reserve while keeping USDT constant.  
     - After enough iterations, the helper calls `PancakePair::swap(11905927933743202788913, 0, 0x8aea7516b3b6aabf474f8872c5e71c1a7907e69e, 0x)` on the BBX–USDT pair, sending `11,905.927933743202788913` USDT to the EOA at an over-favorable price given the compressed BBX reserve.

### Post-Exploit Routing and Deposits

After the main exploit, the adversary performs additional transactions to move and partially obfuscate funds:

- **Stage:** Post-exploit routing and deposits  
- **Transactions (all on BSC, `chainid = 56`)**:
  - `0xdb8c1c552f51a234529d9370153f5b0b9ed4adfacd47dc435fbdcbc9e06cc806` (transfer / approve)  
  - `0x8052e56b6578b158692633b75f3119ff74b9ec9aae7772cd8d4c94138276739f` (transfer / aggregator execute)  
  - `0xd581fe8774a0e1174304ffc6b7cc44e33ad6eae93988945a46ca5985ce53f782` (deposit)  
  - `0x4df242ec81c12998adfcbefd926b4e4868733569b544a6543c3a3ecd12bd70d5` (deposit)

**Effect:**

- After receiving USDT from the BBX–USDT pool in the exploit tx, the EOA:
  - Calls `BEP20USDT::approve` on `0x55d398326f99059ff775485246999027b3197955` to grant spender `0x31c2f6fcff4f8759b3bd5bf0e1084a055615c768` full allowance over its USDT.
  - Invokes contract `0x1a0a18ac4becddbd6389559687d1a73d8927e416` via `execute(bytes,bytes[],uint256)` with parameters referencing USDT, WBNB, and the EOA, likely routing funds through an aggregator-style contract.
  - Performs two `deposit(address,bytes32,bytes)` calls to `0x0d5550d52428e7e3175bfc9550207e4ad3859b17`, each sending `10` BNB, moving a portion of the adversary’s BNB out of the EOA.

**Evidence source:** EOA-normal txlist for `0x8aea7516b3b6aabf474f8872c5e71c1a7907e69e` under `/artifacts/root_cause/data_collector/iter_1/address/56/.../normal_txlist.json`.

### Adversary-Related Accounts

The analysis identifies the following adversary-related addresses and their roles:

- **EOA (attacker)**: `0x8aea7516b3b6aabf474f8872c5e71c1a7907e69e`  
  - Deploys the helper contract.  
  - Initiates the main exploit transaction.  
  - Receives drained USDT from the BBX–USDT pool.  
  - Orchestrates downstream approvals, aggregator calls, and deposits.
- **Helper contract**: `0x0489e8433e4e74fb1ba938df712c954ddea93898`  
  - Implements the `0x5f83db9b` function that reads BBXToken’s `lastBurnTime`, `lastBurnGapTime`, `liquidityPool`, and `burnRate` and then drives repeated `BBXToken::transfer` calls to exploit the auto-burn hook.
- **BBX–USDT PancakeSwap pair (victim pool)**: `0x6051428b580f561b627247119eed4d0483b8d28e`  
  - Serves as `BBXToken.liquidityPool`.  
  - Loses BBX through repeated burns and USDT through the final draining swap.
- **Tax and dividend wallets**:  
  - `0x849d09e4dbd4ec5449ec7d807dd137be6db002c6`  
  - `0xe6acc53b8f9327ddf029ffed36186471d92b6837`  
  - Receive portions of burned BBX as part of the tokenomics, as evidenced in balance diffs.
- **USDT spender / aggregator-related contracts**:  
  - Spender `0x31c2f6fcff4f8759b3bd5bf0e1084a055615c768` (receives USDT allowance).  
  - Aggregator/executor `0x1a0a18ac4becddbd6389559687d1a73d8927e416` (called via `execute`).  
  - Deposit contract `0x0d5550d52428e7e3175bfc9550207e4ad3859b17` (receives `10` BNB deposits twice post-exploit).

These identifications are backed by the helper contract decompilation, seed traces for the exploit transactions, and the EOA-normal txlist.

## Impact & Losses

### Quantitative Loss Summary

Total losses attributed to the exploit, expressed in 18-decimal units, are:

- **USDT**: `11,905.927933743202788913`  
- **BBX**: `9,898.637004253056843826`

### Pool-Level Impact

The BBX–USDT PancakeSwap pair `0x6051428b580f561b627247119eed4d0483b8d28e` experiences:

- A USDT reserve reduction of `11,905.927933743202788913` (18 decimals) in the main exploit transaction `0x0dd486368444598610239b934dd9e8c6474a06d11380d1cfec4d91568b5ac581`, corresponding to `11905927933743202788913` raw units in `balance_diff.json`.
- A BBX reserve reduction of approximately `9,898.637004253056843826` tokens, largely burned to `0x000000000000000000000000000000000000dEaD` and partially redirected to the tax and dividend wallets.

These changes:

- Reduce the value of LP positions that supplied USDT and BBX to this pool.  
- Cause a sharp, manipulation-driven change in the BBX/USDT price because the BBX reserve is compressed by repeated burns while USDT is left intact until the final draining swap.

## Relevant Transactions

For completeness, the set of all transactions identified as relevant in the analysis is:

- **Adversary-crafted**:
  - `0xf7019e1232704c3ede4ecf00b79ccf647b2cb3718b9f6972e70dc7c5170e3f91` (helper deploy and initial routing)
  - `0x0dd486368444598610239b934dd9e8c6474a06d11380d1cfec4d91568b5ac581` (main burn-and-drain exploit)
- **Related / post-exploit routing**:
  - `0xdb8c1c552f51a234529d9370153f5b0b9ed4adfacd47dc435fbdcbc9e06cc806`
  - `0x8052e56b6578b158692633b75f3119ff74b9ec9aae7772cd8d4c94138276739f`
  - `0xd581fe8774a0e1174304ffc6b7cc44e33ad6eae93988945a46ca5985ce53f782`
  - `0x4df242ec81c12998adfcbefd926b4e4868733569b544a6543c3a3ecd12bd70d5`

All of these are on BSC (`chainid = 56`) and are reproduced in the seed and data-collector artifacts under `/artifacts/root_cause/seed/56/...` and `/artifacts/root_cause/data_collector/iter_1/...`.

## References

The following on-chain artifacts and local collections underpin this analysis:

1. **BBXToken source (Contract.sol)**  
   - Collected contract source for BBXToken `0x67ca347e7b9387af4e81c36cca4eaf080dcb33e9`.  
   - Path: `/artifacts/root_cause/seed/_contracts/56/0x67ca347e7b9387af4e81c36cca4eaf080dcb33e9/source/src/Contract.sol`.

2. **Helper contract `0x0489e8...` decompiled source**  
   - Heimdall-rs decompiled contract for helper `0x0489e8433e4e74fb1ba938df712c954ddea93898`.  
   - Path: `/artifacts/root_cause/data_collector/iter_1/contract/56/0x0489e8433e4e74fb1ba938df712c954ddea93898/decompile/0x0489e8433e4e74fb1ba938df712c954ddea93898-decompiled.sol`.

3. **Seed tx `0xf7019e12...` metadata and trace**  
   - Includes tx metadata and `cast run` trace for the helper-deploy / initial routing transaction.  
   - Path prefix: `/artifacts/root_cause/seed/56/0xf7019e1232704c3ede4ecf00b79ccf647b2cb3718b9f6972e70dc7c5170e3f91`.

4. **Seed tx `0x0dd48636...` metadata and trace**  
   - Includes tx metadata and `cast run` trace for the main exploit transaction.  
   - Path prefix: `/artifacts/root_cause/seed/56/0x0dd486368444598610239b934dd9e8c6474a06d11380d1cfec4d91568b5ac581`.

5. **PrestateTracer balance diffs for `0xf7019e12...` and `0x0dd48636...`**  
   - Balance delta JSON files showing native and ERC20 balance changes, used to quantify drained amounts and burned tokens.  
   - Path: `/artifacts/root_cause/data_collector/iter_1/tx/56`.

6. **EOA `0x8aea...` normal txlist around the incident window**  
   - Normal transaction list for the adversary EOA, used to reconstruct post-exploit routing and deposits.  
   - Path: `/artifacts/root_cause/data_collector/iter_1/address/56/0x8aea7516b3b6aabf474f8872c5e71c1a7907e69e/normal_txlist.json`.

Together, these artifacts show deterministically that a broken auto-burn hook in BBXToken’s `_transfer` function allowed an external EOA to repeatedly burn BBX from the BBX–USDT pool, skew reserves, and drain `≈11.9k` USDT, with no reliance on speculative assumptions or unresolved hypotheses.

