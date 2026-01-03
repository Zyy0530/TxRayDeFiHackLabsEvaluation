# Incident Root Cause Report: WETC/PancakeSwap USDT Drain on BSC

## 1. Incident Overview TL;DR
- **Chain / Block**: BNB Smart Chain (chainid 56), seed tx `0x2b6b411adf6c452825e48b97857375ff82b9487064b2f3d5bc2ca7a5ed08d615`.
- **Primary actor**: EOA `0x7e7c1f0d567c0483f85e1d016718e44414cdbafe` operating via orchestrator contract `0xAf68EFB3c1e81AAD5cDb3D4962C8815FB754c688`.
- **Core issue**: A malicious ERC20 token **WETC** (`0xe7f12b72bfd6e83c237318b89512b418e7f6d7a7`) with custom fee/redistribution logic is paired with USDT (`0x55d398326f99059ff775485246999027b3197955`) on PancakeSwap. The token’s sell path (`transferSell`) drains large amounts of WETC from the WETC/USDT pool to fee-recipient addresses. The orchestrator then routes USDT into secondary pools, which are later unwound via two UniversalRouter transactions to realize profit in USDT.
- **Classification**: `is_act = true`, type `malicious-token-fee-drain-and-cross-pool-price-manipulation`.
- **Profit**: At least `101411.453369913807317074` USDT (wei `101411453369913807317074`) to the adversary, computed from precise USDT balance changes across aggregator txs `0xed96ad63...7329` and `0x42953d77...4604`, ignoring gas costs.
- **Analysis iteration**: 2 (`metadata.analysis_iteration = 2`), artifacts under `artifacts/root_cause/root_cause_analyzer/final`.

## 2. Key Background

### 2.1 Seed transaction and evidence
- **Seed tx role**: `seed_role_hypothesis = "attacker-profit"`. The seed tx is the attacker’s orchestrated flash-loan transaction that sets up the exploit by draining WETC and USDT from the WETC/USDT pool and routing USDT into a USDT/0x9692... pool.
- **Seed tx**: `0x2b6b411adf6c452825e48b97857375ff82b9487064b2f3d5bc2ca7a5ed08d615` on BSC.
- **Key evidence files for the seed target**:
  - `artifacts/root_cause/seed/56/0x2b6b4...615/metadata.json`
  - `artifacts/root_cause/seed/56/0x2b6b4...615/trace.cast.log`
  - `artifacts/root_cause/seed/56/0x2b6b4...615/balance_diff.json`
  - `artifacts/root_cause/data_collector/iter_1/tx/56/0x2b6b4...615/balance_diff_prestate_tracer.json`
  - `artifacts/root_cause/seed/56/0x55d3...955/src/Contract.sol` (BEP20USDT)
  - `artifacts/root_cause/seed/56/0xe7f1...7a7/src/WETC.sol` (WETC)
  - `artifacts/root_cause/data_collector/iter_2/tx/56/0xed96...329/trace.cast.log`
  - `artifacts/root_cause/data_collector/iter_2/tx/56/0x4295...604/trace.cast.log`

From `metadata.json` for the seed tx:
```json
{
  "chainid": 56,
  "txhash": "0x2b6b411adf6c452825e48b97857375ff82b9487064b2f3d5bc2ca7a5ed08d615",
  "etherscan": {
    "tx": {
      "result": {
        "from": "0x7e7c1f0d567c0483f85e1d016718e44414cdbafe",
        "to": "0xaf68efb3c1e81aad5cdb3d4962c8815fb754c688",
        "input": "0xe3b872d3..."
      }
    }
  }
}
```
This confirms the seed tx is a call from the adversary EOA to the orchestrator `0xAf68...` with selector `0xe3b872d3`.

### 2.2 Victim and adversary-related contracts
- **Victim-stable asset**: BEP20 USDT contract `0x55d398326f99059ff775485246999027b3197955`.
- **Malicious token**: WETC token `0xe7f12b72bfd6e83c237318b89512b418e7f6d7a7`.
- **Secondary adversarial tokens**:
  - `0x96928300ed3b68b8ED25C293e225c8d9C1a79E18`
  - `0xc0ba10e4fce96534f76d93c5c47ab13cb91719a9`
- **AMM infrastructure contracts** (used but not owned by adversary):
  - PancakeV3Pool `0x92b7807bf19b7dddf89b706143896d05228f3121`
  - WETC/USDT PancakePair `0x8e2cc521b12deba9a20edea829c6493410dad0e3`
  - USDT/0x9692... PancakePair `0x119d1777d617fc70f6b063990eedc2b9c87a7475`
  - USDT/0xc0ba... PancakePair `0xA635000b4731b6F654151E197432C90444C6fe2c`
  - PancakeRouter `0x10ED43C718714eb63d5aA57B78B54704E256024E`
  - UniversalRouter `0xd9c500dff816a1da21a48a732d3498bf09dc9aeb`

### 2.3 WETC token mechanics
WETC is an ERC20 token with custom transfer logic that distinguishes among buys, sells, LP adds/removes, and ordinary transfers. The relevant excerpts from `WETC.sol`:

```solidity
contract WETC is ERC20,AccessControlEnumerable {
    address public routerAddress;
    address public pairAddress;
    address public usdtBnbAddress;
    uint256[] public buyPercent;
    address[] public buyAddress;
    uint256[] public sellPercent;
    address[] public sellAddress;
    uint256[] public burnPercent;
    address[] public burnAddress;
    uint256 public delinePercent;
    uint256 public hdPercent;
    mapping(address=>uint256) public whiteAddress;

    mapping(uint256=>uint256) public dayPrice;
    mapping(uint256=>uint256) public dayPercent;

    function _transfer(address from, address to, uint256 amount) internal override {
        require(from != address(0), "transfer from the zero address");
        require(to != address(0), "transfer to the zero address");
        require(amount > 0, "transfer amount to small");
        if(whiteAddress[from] == 1 || whiteAddress[to] == 1){
            super._transfer(from,to,amount);
        }
        (uint256 addLP, uint256 removeLP) = _isLiquidity(from, to);
        if (addLP>0 || removeLP>0) {
            if(addLP>0){ addPairLp(from,to,amount); }
            if(removeLP>0){ removePairLp(from,to,amount); }
            return;
        }
        if(from == pairAddress){
            //买入
            transferBuy(from,to,amount);
        }else if(to == pairAddress){
            //卖出
            transferSell(from,to,amount);
        }else{
            //转账
            super._transfer(from,to,amount);
        }
        if(pairAddress == address(0)){
            pairAddress = IUniswapV2Factory(IUniswapV2Router02(routerAddress).factory()).getPair(address(this),usdtBnbAddress);
        }
    }

    function transferSell(address from,address to,uint256 amount) internal {
        uint256 dfhdPercent = checkDayDf();
        uint256 price1 = 0;
        if(dfhdPercent>0){
            price1 = amount * (dfhdPercent - sellPercent[1]) / 10000;
        }else{
            price1 = amount * sellPercent[0] / 10000;
        }
        if(price1>0){
            super._transfer(from, sellAddress[0], price1);
        }
        uint256 price2 = amount * sellPercent[1] / 10000;
        if(price2>0){
            super._transfer(from, sellAddress[1], price2);
            emit NodeInfo(from,2,price2);
        }
        amount = amount - price1 - price2;
        super._transfer(from, to, amount);
    }
}
```

This design allows the token to siphon a configurable fraction of each sell (LP-out) from the WETC/USDT pair to specific fee-recipient addresses (`sellAddress[0]`, `sellAddress[1]`), with dynamic parameters driven by `dayPrice`/`dayPercent` and `checkDayDf()`. When combined with large, orchestrated sells from the pool, this mechanism can move a huge volume of WETC from the pool to adversary-controlled accounts while leaving USDT in the pool vulnerable to subsequent price manipulation.

## 3. Vulnerability Analysis

### 3.1 Vulnerable design
- The **core vulnerability** is **not** a bug in PancakeSwap or USDT, but the adversarial design of WETC’s transfer and fee logic:
  - On sells (`to == pairAddress`), `transferSell` splits the amount between fee recipients (`sellAddress[0]`, `sellAddress[1]`) and the actual recipient, based on `sellPercent` and dynamic `dayPercent` derived from price movements.
  - The contract can set `sellAddress` values such that fee-recipient addresses are under adversary control.
  - The token uses on-chain price observations (`getLinePrice`, `dayPrice`, `dayPercent`) to modulate fee percentages, enabling large extractions once certain thresholds are met.
- This fee logic means that when the WETC/USDT pair is used as a counterparty in swaps, **WETC can be drained from the pair directly to fee recipients**, without any explicit swap to USDT for those addresses. The adversary then exploits the resulting reserve imbalance via carefully orchestrated swaps.

### 3.2 Victim exposures
- **Primary victim pool**: WETC/USDT PancakePair `0x8e2cc521b12deba9a20edea829c6493410dad0e3`.
- **Secondary victim pools**:
  - USDT/0x9692... pair `0x119d1777d617fc70f6b063990eedc2b9c87a7475`.
  - USDT/0xc0ba... pair `0xA635000b4731b6F654151E197432C90444C6fe2c`.
- These pools are standard Pancake V2/V3 AMM contracts and do not have privileged roles exploited here. They are used as liquidity sources/sinks that become mispriced because of WETC’s custom fee logic and the orchestrated trade sequence.

### 3.3 Evidence of pool-level impact
From `balance_diff.json` for the seed transaction:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x92b7807bf19b7dddf89b706143896d05228f3121",
      "delta": "100000000000000000000",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x8e2cc521b12deba9a20edea829c6493410dad0e3",
      "delta": "-101495403570120114925199",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x119d1777d617fc70f6b063990eedc2b9c87a7475",
      "delta": "101395403570120114925199",
      "contract_name": "BEP20USDT"
    },
    {
      "token": "0xe7f12b72bfd6e83c237318b89512b418e7f6d7a7",
      "holder": "0x8e2cc521b12deba9a20edea829c6493410dad0e3",
      "delta": "-6409151513542464192544376",
      "contract_name": "WETC"
    }
  ]
}
```

This shows:
- PancakeV3Pool `0x92b7...` **gains** `100` USDT as flash-loan fee.
- WETC/USDT pair `0x8e2c...` **loses** `~1.014954e23` USDT and `~6.409e24` WETC.
- USDT/0x9692... pair `0x119d...` **gains** `~1.013954e23` USDT.
This confirms the seed transaction drains large amounts of WETC and USDT from the WETC/USDT pool and routes USDT into the USDT/0x9692... pool.

## 4. Detailed Root Cause Analysis

### 4.1 Adversary cluster
- **Core operator EOA**: `0x7e7c1f0d567c0483f85e1d016718e44414cdbafe`.
- **Core operator contracts**: orchestrator `0xAf68EFB3c1e81AAD5cDb3D4962C8815FB754c688`.
- **Malicious or adversarial tokens**:
  - WETC `0xe7f12b72bfd6e83c237318b89512b418e7f6d7a7`.
  - `0x96928300ed3b68b8ED25C293e225c8d9C1a79E18`.
  - `0xc0ba10e4fce96534f76d93c5c47ab13cb91719a9`.
- **Beneficiary addresses** (WETC fee recipients):
  - `0x78bb09f285fa0b4005e131124175f50627347a5a`.
  - `0x419d7e35caa34487a575dec6c7ab74699b6bde49`.
  - `0xb213171c9a803997b44842d0361e742e1e6691fc`.
- **Rationale**:
  - EOA `0x7e7c...` deploys and drives orchestrator `0xAf68...` and sends both the seed flash-loan transaction and the two UniversalRouter aggregator transactions.
  - WETC at `0xe7f1...` and secondary tokens 0x9692... and 0xc0ba... participate in fee- and price-manipulation flows that ultimately increase this EOA’s USDT balance.
  - WETC fee-recipient addresses receive WETC directly from the WETC/USDT pair during the seed tx via WETC’s custom `transferSell` logic.
  - Pancake pools, PancakeRouter, and UniversalRouter function as standard infrastructure and are not adversary-owned, but are intentionally used to extract value.

### 4.2 ACT classification
- `is_act = true` (this is an Adversarial Contract Threat).
- `act_type = "malicious-token-fee-drain-and-cross-pool-price-manipulation"`.
- Summary: a malicious WETC token with custom fee logic is combined with a dedicated orchestrator contract and cross-pool routing to drain liquidity and USDT value from PancakeSwap pools into adversary-controlled accounts, using only public entry points on existing infrastructure.

### 4.3 End-to-end exploit opportunity sequence (sequence_b)
The exploit is captured as `sequence_b`, with `is_identified = true`, `k = 3` transactions:

#### Tx 1 (index 1): Seed flash-loan and WETC/USDT drain
- **Tx**: `0x2b6b411adf6c452825e48b97857375ff82b9487064b2f3d5bc2ca7a5ed08d615`.
- **Role**: `seed-flash-loan-and-WETC/USDT-drain`.
- **High-level behavior**:
  - Orchestrator `0xAf68...` calls PancakeV3Pool `0x92b7...` to flash-loan `1,000,000` USDT.
  - It swaps USDT into WETC via WETC/USDT pair `0x8e2c...`, triggering WETC’s `transferSell` fee logic multiple times.
  - Large amounts of WETC are transferred from `0x8e2c...` to fee-recipient addresses `0x78bb...`, `0x419d...`, and `0xb213...`.
  - WETC is then swapped back to USDT, moving `101395403570120114925199` USDT into USDT/0x9692... pair `0x119d...`.
  - The flash loan principal plus a `100` USDT fee are repaid to PancakeV3Pool `0x92b7...`.
- **Portfolio deltas (reference asset: USDT)**:
  - `pancake_v3_pool_0x92b7`: `usdt_change_wei = +100000000000000000000` (100 USDT fee gain).
  - `wetc_usdt_pair_0x8e2c`:
    - `usdt_change_wei = -101495403570120114925199`.
    - `wetc_change_wei = -6409151513542464192544376`.
  - `usdt_9692_pair_0x119d`: `usdt_change_wei = +101395403570120114925199`.
  - `wetc_fee_recipients`:
    - `0x78bb09f2...7a5a`: `wetc_change_wei = 3204575756771232096272186`.
    - `0x419d7e35...e49`: `wetc_change_wei = 356063972974581344030242`.
    - `0xb213171c...91fc`: `wetc_change_wei = 2848511783796650752241948`.
  - `adversary_eoa_0x7e7c`: `usdt_change_wei = 0` during the seed tx (flash loan handled inside the orchestrator).

The seed `trace.cast.log` confirms this flow:
```text
PancakeV3Pool::flash(..., 1000000000000000000000000, ...)
  BEP20USDT::transfer(0xAf68..., 1000000000000000000000000)
  0xAf68...::pancakeV3FlashCallback(...)
    PancakePair::swap(..., 6994607918395778704138079, 0xAf68..., ...)
      WETC::transfer(0xAf68..., 6994607918395778704138079)
      ...
    WETC::transfer(0xB213..., 2826628210553654715733044)
    WETC::transfer(0x78bb..., 2543965389498289244159739)
    WETC::transfer(0x419D..., 282662821055365471573304)
```
This shows WETC being pulled from the pool and redistributed to fee recipients during the orchestrator’s flash-loan callback.

#### Tx 2 (index 2): Unwind 0x9692 position via USDT/0x9692 pair
- **Tx**: `0xed96ad630c33e8da2a801697a9e1d4c3cf8e3ebe4d68c5c532b23ad4fa07a329`.
- **Role**: `unwind-0x9692-position-via-USDT-0x9692-pair`.
- **High-level behavior**:
  - EOA `0x7e7c...` calls UniversalRouter `0xd9c5...::execute`.
  - UniversalRouter uses Permit2 to obtain spending rights over 0x9692... tokens held by the EOA.
  - It transfers `61367499975000000000000000000` units of 0x9692... into the USDT/0x9692 pair `0x119d...`.
  - A PancakePair::swap sends `101396403570118477219918` USDT from `0x119d...` to the EOA.
- **Portfolio deltas (reference asset: USDT)**:
  - `adversary_eoa_0x7e7c`:
    - `usdt_before_wei = 45787109395335770274555`.
    - `usdt_after_wei  = 147183512965454247494473`.
    - `usdt_change_wei = 101396403570118477219918`.
  - `usdt_9692_pair_0x119d`: `usdt_change_wei = -101396403570118477219918`.

This is directly visible in the trace for tx `0xed96...`:
```text
BEP20USDT::balanceOf(0x7e7C...) [staticcall]
  ← [Return] 45787109395335770274555
...
PancakePair::swap(101396403570118477219918, 0, 0x7e7C..., 0x)
  BEP20USDT::transfer(0x7e7C..., 101396403570118477219918)
...
BEP20USDT::balanceOf(0x7e7C...) [staticcall]
  ← [Return] 147183512965454247494473
```

#### Tx 3 (index 3): Unwind 0xc0ba position via USDT/0xc0ba pair
- **Tx**: `0x42953d7756aed612975d9ae7e0b029ed4ec2b4092959948341be6f9387d84604`.
- **Role**: `unwind-0xc0ba-position-via-USDT-c0ba-pair`.
- **High-level behavior**:
  - EOA `0x7e7c...` again calls UniversalRouter `0xd9c5...::execute`.
  - UniversalRouter uses Permit2 to obtain spending rights over token `0xc0ba10e4fce96534f76d93c5c47ab13cb91719a9`.
  - It transfers `245469999900002665033118713663` units into USDT/0xc0ba pair `0xA635...`.
  - A PancakePair::swap sends `15049799795330097156` USDT from `0xA635...` to the EOA, leaving only `66` wei of USDT in the pool.
- **Portfolio deltas (reference asset: USDT)**:
  - `adversary_eoa_0x7e7c`:
    - `usdt_before_wei = 147183512965454247494473`.
    - `usdt_after_wei  = 147198562765249577591629`.
    - `usdt_change_wei = 15049799795330097156`.
  - `usdt_c0ba_pair_0xA635`: `usdt_change_wei = -15049799795330097156`.

Confirmed by tx `0x4295...` trace:
```text
PancakePair::swap(15049799795330097156, 0, 0x7e7C..., 0x)
  BEP20USDT::transfer(0x7e7C..., 15049799795330097156)
...
BEP20USDT::balanceOf(PancakePair: [0xA635...]) → 66
BEP20USDT::balanceOf(0x7e7C...) → 147198562765249577591629
```

### 4.4 Adversary model feasibility
- `adversary_model_feasibility.unprivileged = true`.
- The adversary uses only public entry points on:
  - PancakeV3Pool, PancakeV2 pairs, PancakeRouter.
  - UniversalRouter and Permit2.
  - ERC20 tokens (WETC, USDT, 0x9692..., 0xc0ba...).
- The adversary must have:
  - Deployed and configured the WETC token, including its fee recipients and dynamic fee parameters.
  - Acquired large balances of tokens 0x9692... and 0xc0ba....
- **No privileged roles or admin controls** are required on the AMM contracts or third-party infrastructure. The exploit is achieved entirely through public calls and adversarial token logic.

### 4.5 Analysis quality gates (meta)
The analysis explicitly passes the following quality gates, each backed by evidence:
- **Analyzed victim tx or source/bytecode**: Seed tx `0x2b6b41...` is examined via metadata, QuickNode prestateTracer, and balance diffs, and correlated with verified BEP20USDT and WETC source, including WETC’s `_transfer`, `transferBuy`, `transferSell`, and `burnDay` logic.
- **Analyzed stakeholder code**: WETC.sol and BEP20USDT Contract.sol are reviewed in detail; orchestrator `0xAf68...` and token `0x9692...` are examined via bytecode/disassembly and call traces to determine their roles in routing and price manipulation.
- **Analyzed on-chain traces**: Foundry cast traces for `0x2b6b41...`, `0xed96...`, and `0x4295...` are used to reconstruct internal calls, Permit2 operations, swaps, and exact before/after USDT balances for the EOA and pools.
- **Identified adversary-related accounts**: EOA `0x7e7c...`, orchestrator `0xAf68...`, WETC fee recipients `0x78bb...`, `0x419d...`, and `0xb213...`, along with the involved AMM pools, are identified and their roles justified.
- **No speculative/unknown content**: The gap analysis notes that all required ACT and root cause elements are fully specified. There are no remaining “likely”, “unknown”, or “TBD” statements.

## 5. Adversary Flow Analysis

### 5.1 High-level flow
1. **Setup**: Adversary deploys WETC with adversarial fee logic and configures fee-recipient addresses that they control or benefit from.
2. **Seed flash-loan tx (0x2b6b41...)**:
   - Borrow 1,000,000 USDT from PancakeV3Pool `0x92b7...`.
   - Swap USDT to WETC via WETC/USDT `0x8e2c...`, triggering WETC’s `transferSell` logic to send large WETC amounts to `0x78bb...`, `0x419d...`, and `0xb213...`.
   - Swap WETC back to USDT; route `101395403570120114925199` USDT into USDT/0x9692... pool `0x119d...`.
   - Repay flash loan plus `100` USDT fee.
3. **Aggregator tx 0xed96...**: Unwind 0x9692 position from `0x119d...` into USDT, increasing the EOA’s USDT balance by `101396403570118477219918` and draining `0x119d...` of USDT.
4. **Aggregator tx 0x4295...**: Unwind 0xc0ba position from `0xA635...` into USDT, increasing the EOA’s USDT balance by `15049799795330097156` and draining `0xA635...` to only `66` wei of USDT.

### 5.2 Profit path
- **Seed tx**: No net USDT profit at the EOA; this tx redistributes WETC and repositions USDT into the USDT/0x9692 pool while paying the flash-loan fee.
- **Aggregator tx 0xed96...**:
  - EOA USDT balance: `45787109395335770274555 → 147183512965454247494473` (delta `101396403570118477219918`).
- **Aggregator tx 0x4295...**:
  - EOA USDT balance: `147183512965454247494473 → 147198562765249577591629` (delta `15049799795330097156`).
- **Total profit**:
  - `101396403570118477219918 + 15049799795330097156 = 101411453369913807317074` wei.
  - This equals `101411.453369913807317074` USDT.
- **Funding source of profit**:
  - USDT losses from WETC/USDT pool `0x8e2c...`, USDT/0x9692 pool `0x119d...`, and USDT/0xc0ba pool `0xA635...`, as shown in balance diffs and swap traces.

### 5.3 Adversary-related accounts and roles
- **EOA 0x7e7c...**: Core operator and final USDT beneficiary.
- **Orchestrator 0xAf68...**: Conducts the flash-loan and complex sequence of swaps that exploits WETC’s fee logic and repositions USDT into secondary pools.
- **WETC fee recipients**:
  - `0x78bb...`, `0x419d...`, `0xb213...` receive large WETC inflows during the seed tx directly from the WETC/USDT pair via WETC’s `transferSell`, as confirmed by balance and trace data.
- **AMM infrastructure**: PancakeV3Pool, PancakeV2 pairs, PancakeRouter, and UniversalRouter provide liquidity and routing and are not compromised by privilege misuse; they are misused only via contract semantics of the malicious token.

## 6. Impact & Losses

### 6.1 Monetary impact
- **Reference asset**: USDT (`exploit_predicate.monetary.reference_asset = "USDT"`).
- **Minimum profit (ignoring gas)**:
  - `min_profit_wei = 101411453369913807317074`.
  - `min_profit_units = 101411.453369913807317074` USDT.
- **Computation (exact as in analysis)**:
  - From tx `0xed96...`:
    - EOA USDT balance: `45787109395335770274555 → 147183512965454247494473`.
    - Delta: `101396403570118477219918` wei.
  - From tx `0x4295...`:
    - EOA USDT balance: `147183512965454247494473 → 147198562765249577591629`.
    - Delta: `15049799795330097156` wei.
  - Sum: `101396403570118477219918 + 15049799795330097156 = 101411453369913807317074` wei.
- **Gas costs**: Explicitly ignored (`ignores_gas_costs = true`).

### 6.2 Distribution of losses
- **WETC/USDT pair 0x8e2c...**:
  - Loses `101495403570120114925199` USDT and `6409151513542464192544376` WETC in the seed tx, while WETC is redistributed to fee recipients.
- **USDT/0x9692 pair 0x119d...**:
  - Gains `101395403570120114925199` USDT in the seed tx.
  - Then loses `101396403570118477219918` USDT in tx `0xed96...` to the EOA.
- **USDT/0xc0ba pair 0xA635...**:
  - Holds USDT liquidity that is almost entirely drained in tx `0x4295...`, leaving `66` wei in the pool after the swap.

### 6.3 Non-monetary impact
- `has_non_monetary_harm = false`.
- The incident affects token-holder and liquidity-provider balances but does not change governance outcomes, price-oracle feeds, or protocol liveness beyond the immediate financial loss.

### 6.4 Gap analysis
- `act_gap_analysis.missing_or_uncertain_items = []` (no missing or uncertain items).
- Notes: All required ACT and root cause elements are established from collected source code, balance diffs, and call traces. The end-to-end adversary sequence, profit amount in USDT, adversary-related accounts, and vulnerability mechanism are fully specified without speculative or unknown content.

## 7. References

- **Raw analysis metadata**:
  - `metadata.analysis_iteration = 2`.
  - `metadata.analysis_output_dir = "artifacts/root_cause/root_cause_analyzer/final"`.
- **Seed target and evidence**:
  - Seed tx `0x2b6b41...615` (chainid 56), role `attacker-profit`.
  - Evidence files listed in Section 2.1.
- **Data collection summary**:
  - `artifacts/root_cause/data_collector/data_collection_summary.json` (describes partial/complete status for contract source, tx traces, and txlists used here).
- **Seed index**:
  - `artifacts/root_cause/seed/index.json` (maps the seed tx and associated artifacts, including WETC and BEP20USDT source code). 
- **Contract source code**:
  - WETC: `artifacts/root_cause/seed/56/0xe7f12b72bfd6e83c237318b89512b418e7f6d7a7/src/WETC.sol`.
  - BEP20USDT: `artifacts/root_cause/seed/56/0x55d398326f99059ff775485246999027b3197955/src/Contract.sol`.
- **On-chain traces**:
  - Seed tx cast trace: `artifacts/root_cause/seed/56/0x2b6b4...615/trace.cast.log`.
  - Aggregator tx 0xed96... cast trace: `artifacts/root_cause/data_collector/iter_2/tx/56/0xed96...329/trace.cast.log`.
  - Aggregator tx 0x4295... cast trace: `artifacts/root_cause/data_collector/iter_2/tx/56/0x4295...604/trace.cast.log`.
- **Balance diffs and prestate tracer**:
  - Seed tx balance diffs: `artifacts/root_cause/seed/56/0x2b6b4...615/balance_diff.json`.
  - Seed tx prestate tracer: `artifacts/root_cause/data_collector/iter_1/tx/56/0x2b6b4...615/balance_diff_prestate_tracer.json`.
- **Adversary txlists** (supporting role attribution):
  - `artifacts/root_cause/data_collector/iter_1/address/56/0x7e7c1f0d567c0483f85e1d016718e44414cdbafe/txlist.json`.
  - `artifacts/root_cause/data_collector/iter_1/address/56/0xAf68EFB3c1e81AAD5cDb3D4962C8815FB754c688/txlist.json`.
  - `artifacts/root_cause/data_collector/iter_1/address/56/0xb213171c9a803997b44842d0361e742e1e6691fc/txlist.json`.
  - `artifacts/root_cause/data_collector/iter_2/address/56/0x78bb09f285fa0b4005e131124175f50627347a5a/txlist.json`.
  - `artifacts/root_cause/data_collector/iter_2/address/56/0x419d7e35caa34487a575dec6c7ab74699b6bde49/txlist.json`.
  - `artifacts/root_cause/data_collector/iter_2/address/56/0x119d1777d617fc70f6b063990eedc2b9c87a7475/txlist.json`.

The above references, together with the detailed traces and source snippets, fully support the described root cause: WETC’s adversarial fee/redistribution mechanics plus orchestrated cross-pool routing enable an unprivileged, purely on-chain extraction of at least 101,411.453369913807317074 USDT from PancakeSwap liquidity pools into the adversary’s EOA.
