# Incident Overview & TL;DR

An attacker-controlled helper contract exploited a design flaw in the Unilend V2 stETH/USDC pool to execute an under-collateralized borrow of stETH using flash loans. Within a single Ethereum mainnet transaction (0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba in block 21608070), the helper orchestrated flash loans from Morpho, unwrapped wstETH to stETH, manipulated Unilend V2 pool accounting via lend/borrow/redeemUnderlying, and extracted approximately 60.672854887643676587 stETH from the pool. The UnilendV2Pool contract recorded a large increase in token1Data.totalBorrow and totalBorrowShare without sufficient collateral, leaving the pool undercollateralized, while the attacker’s EOA ended the transaction with a net profit of 60672854887643676587 stETH.

# Key Background

The incident occurred on Ethereum mainnet at block 21608070 against the Unilend V2 stETH/USDC pool:
- Pool: `UnilendV2Pool` at `0x4E34DD25Dbd367B1bF82E1B5527DBbE799fAD0d0` configured for stETH/USDC.
- Core orchestrator: `UnilendV2Core` at `0x7f2E24D2394f2bdabb464B888cb02EbA6d15B958`.
- Flash loan provider: Morpho at `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb`.
- LST assets: Lido stETH at `0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84` and wstETH at `0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0`.
- Adversary EOA: `0x55F5f8058816d5376DF310770Ca3A2e294089C33`.
- Helper contract: `0x3F814e5FaE74cd73A70a0ea38d85971dFA6fdA21`, deployed and funded by the attacker EOA.

Prior to the exploit, the relevant contracts and tokens were already deployed and active, and the helper contract had been deployed by the attacker:
- Pre-state and deployment context are documented in:
  - `artifacts/root_cause/seed/index.json`
  - `artifacts/root_cause/seed/1/0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba/metadata.json`
  - Address txlists for attacker EOA and helper under `artifacts/root_cause/data_collector/iter_1/address/1/…`.
- Verified or reconstructed sources for Unilend and Lido/wstETH are available under:
  - `artifacts/root_cause/data_collector/iter_1/contract/1/0x4E34DD25Dbd367B1bF82E1B5527DBbE799fAD0d0/source`
  - `artifacts/root_cause/seed/1/0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0/out/Contract.sol/WstETH.json`
  - `artifacts/root_cause/seed/1/0x6ca84080381e43938476814be61b779a8bb6a600/src/contracts/0.4.24/Lido.sol`
  - `artifacts/root_cause/seed/1/0x6ca84080381e43938476814be61b779a8bb6a600/src/contracts/0.4.24/StETH.sol`

The ACT opportunity is fully permissionless: the attacker EOA submits standard Ethereum L1 transactions to deploy the helper and call it. All contracts involved (Morpho, Unilend V2 pool/core, Lido, wstETH) are public and permissionless. No privileged roles, governance actions, or off-chain coordination are needed beyond observing on-chain data and crafting standard transactions.

# Vulnerability Analysis

The root cause lies in UnilendV2Pool’s accounting and health-factor logic, specifically how it handles lend/borrow and redeemUnderlying for token1 (stETH) when combined with flash loans. The pool tracks per-token totals using the `tM` struct:

```solidity
struct tM {
    uint totalLendShare;
    uint totalBorrowShare;
    uint totalBorrow;
}
```

and position-level exposures via `pM`:

```solidity
struct pM {
    uint token0lendShare;
    uint token1lendShare;
    uint token0borrowShare;
    uint token1borrowShare;
}
```

Key functions:
- `lend`: mints lending shares based on `totalLendShare`, on-chain token balances, and `totalBorrow`.
- `borrow`: mints borrow shares and increases `totalBorrow` for the chosen token.
- `redeem` and `redeemUnderlying`: burn lending shares and transfer underlying tokens, subject to health-factor checks.
- `userHealthFactorLtv` and `userHealthFactor`: compute health factors from oracle-valued collateral and outstanding borrows.

The critical property exploited is that the combination of:
- share-based accounting (`totalLendShare`, `totalBorrowShare`, `totalBorrow`),
- the ordering of operations in lend/borrow/redeemUnderlying, and
- the health-factor checks using oracle-derived values

allows the attacker’s helper to:
1. Establish a position with stETH liquidity in the pool.
2. Borrow a large amount of stETH (token1) using that position.
3. Call `redeemUnderlying` in a way that increases `token1Data.totalBorrow` and `token1Data.totalBorrowShare` while transferring more stETH out of the pool than is covered by durable collateral.
4. End with a large net stETH transfer from the pool to the attacker, recorded as an outstanding borrow rather than an immediately failing health-factor condition.

This is a protocol-level design flaw: all behavior follows the contract’s logic; no reentrancy, external bug, or privileged misconfiguration is required.

# Detailed Root Cause Analysis

## UnilendV2Pool accounting behavior

For token1 (stETH), UnilendV2Pool maintains:
- `token1Data.totalBorrow` and `token1Data.totalBorrowShare` as aggregate borrow state.
- `positionData[_nftID].token1lendShare` and `token1borrowShare` as per-position state.

The relevant functions are defined in `artifacts/root_cause/data_collector/iter_1/contract/1/0x4E34DD25Dbd367B1bF82E1B5527DBbE799fAD0d0/source/src/pool.sol`. For example, the redeemUnderlying logic for token1 is:

```solidity
function redeemUnderlying(uint _nftID, int _amount, address _receiver) external onlyCore returns(int rtAmount) {
    accrueInterest();
        
    pM storage _positionMt = positionData[_nftID];
        
    if(_amount > 0){
        tM storage _tm1 = token1Data;
            
        uint tokenBalance1 = IERC20(token1).balanceOf(address(this));
        uint _totTokenBalance1 = tokenBalance1.add(_tm1.totalBorrow);
        uint tok_amount1 = getShareByValue(_totTokenBalance1, _tm1.totalLendShare, uint(_amount));
            
        require(tok_amount1 > 0, 'Insufficient Liquidity Burned');
        require(_positionMt.token1lendShare >= tok_amount1, "Balance Exceeds Requested");
        require(tokenBalance1 >= uint(_amount), "Not enough Liquidity");
            
        _burnLPposition(_nftID, 0, tok_amount1);

        // check if _healthFactorLtv > 1
        checkHealthFactorLtv0(_nftID);
            
        transferToUser(token1, payable(_receiver), uint(_amount));
            
        rtAmount = int(tok_amount1);

        emit Redeem(token1, _nftID, tok_amount1, uint(_amount));
    }
}
```

and borrow for token1:

```solidity
function borrow(uint _nftID, int amount, address payable _recipient) external onlyCore {
    accrueInterest();

    if(amount > 0){
        tM storage _tm1 = token1Data;
            
        uint ntokens1 = calculateShare(_tm1.totalBorrowShare, _tm1.totalBorrow, uint(amount));
        if(_tm1.totalBorrowShare == 0){
            _mintBposition(0, 0, 10**3);
        }
        require(ntokens1 > 0, 'Insufficient Borrow1 Liquidity Minted');
            
        _mintBposition(_nftID, 0, ntokens1);
            
        _tm1.totalBorrow = _tm1.totalBorrow.add(uint(amount));

        // check if _healthFactorLtv > 1
        checkHealthFactorLtv1(_nftID);
            
        transferToUser(token1, payable(_recipient), uint(amount));

        emit Borrow(token1, _nftID, uint(amount), _tm1.totalBorrow, _recipient);
    }
}
```

The helper’s sequence aligns these operations such that:
- The pool’s view of available liquidity and borrow shares is manipulated using flash-loaned stETH and temporary positions.
- The health-factor checks are satisfied at the time of each call, but the overall effect is that `token1Data.totalBorrow` and `totalBorrowShare` end up much larger, while a corresponding amount of real stETH has been permanently transferred out of the pool to the attacker.

The annotated state diff for the incident transaction shows the critical changes:

```json
{
  "contract": "0x4e34dd25dbd367b1bf82e1b5527dbbe799fad0d0",
  "solidity_variable": "token1Data.totalBorrow",
  "from_dec": "1012861590066924766",
  "to_dec": "61685716659650554564",
  "interpretation": "Total borrowed principal for this token in the pool."
}
```

and:

```json
{
  "contract": "0x4e34dd25dbd367b1bf82e1b5527dbbe799fad0d0",
  "solidity_variable": "token1Data.totalBorrowShare",
  "from_dec": "1005623616944364230",
  "to_dec": "61244895617071206268",
  "interpretation": "Total borrow shares outstanding for this token in the pool."
}
```

These large jumps in totalBorrow and totalBorrowShare reflect a substantial new stETH borrowing position, while on-chain balances and ERC20 transfers show that a nearly equal amount of stETH has left the pool to the attacker’s benefit.

## Deterministic profit in stETH

The success predicate is defined purely in stETH terms:
- Reference asset: stETH.
- Adversary address: `0x55F5f8058816d5376DF310770Ca3A2e294089C33`.
- Value delta: `60672854887643676587` (stETH units, 18 decimals).

This is computed using only ERC20 stETH Transfer events and the state diff in the exploit tx. The decoded ERC20 logs for 0x4403…74e0 show:

```json
{
  "event": "Transfer",
  "address": "0xae7ab96520de3a18e5e111b5eaab095312d7fe84",
  "from": "0x3f814e5fae74cd73a70a0ea38d85971dfa6fda21",
  "to_or_spender": "0x55f5f8058816d5376df310770ca3a2e294089c33",
  "value": "60672854887643676587"
}
```

and the pool’s stETH transfers:

```json
{
  "event": "Transfer",
  "address": "0xae7ab96520de3a18e5e111b5eaab095312d7fe84",
  "from": "0x4e34dd25dbd367b1bf82e1b5527dbbe799fad0d0",
  "to_or_spender": "0x3f814e5fae74cd73a70a0ea38d85971dfa6fda21",
  "value": "60672854887643676589"
}
```

Intermediate flows between the helper and wstETH/Lido net to effectively one-wei rounding residues, so the attacker’s EOA balance increases by exactly 60672854887643676587 stETH, while the pool loses essentially the same amount. This computation uses only on-chain logs and state diffs, not any off-chain oracle.

# Adversary Flow Analysis

The adversary lifecycle consists of three main transactions, all on Ethereum mainnet:

1. **Helper contract deployment**
   - Tx: `0xdff3f578284507a25d162df3f8a7fdfbd0d2078de80efaafd9b930750d2174e0` (block 21608043).
   - Actor: EOA `0x55F5f8058816d5376DF310770Ca3A2e294089C33`.
   - Action: Deploys helper contract `0x3F814e5FaE74cd73A70a0ea38d85971dFA6fdA21` with sufficient gas and fees; no privileged roles required.

2. **Failed calibration helper call**
   - Tx: `0xb8ea8725dcdfd91006558bf846d636baa2365de52a8b293ca62f4a1b111072df` (block 21608056).
   - Actor: Same EOA calling the helper with the same calldata as the later exploit.
   - Behavior: The transaction executes the helper logic, including flash loans and Unilend interactions, but reverts before any persistent state changes in Unilend, Lido, wstETH, Morpho, or the helper. State and balance diffs show no net change for the pool or attacker accounts.
   - Evidence: 
     - `artifacts/root_cause/data_collector/iter_2/tx/1/0xb8ea8725…72df/trace.cast.log`
     - `artifacts/root_cause/data_collector/iter_2/state_diff/1/0xb8ea8725…72df.json`
     - `artifacts/root_cause/data_collector/iter_2/balance_diff/1/0xb8ea8725…72df.json`

3. **Successful flashloan-assisted exploit**
   - Tx: `0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba` (block 21608070).
   - Actor: Attacker EOA calling the helper contract.
   - High-level flow (from cast trace and decoded logs):
     - The helper obtains a USDC flash loan from Morpho.
     - The helper (or associated logic) obtains wstETH and unwraps it to stETH using Lido/wstETH contracts, increasing its stETH balance.
     - The helper supplies USDC and stETH liquidity to Unilend V2, establishing position(s) in the stETH/USDC pool.
     - Through coordinated `lend`, `borrow`, and `redeemUnderlying` calls on `UnilendV2Pool`, the helper creates a large stETH borrowing position while still satisfying health-factor checks at call time.
     - `token1Data.totalBorrow` and `totalBorrowShare` increase sharply, as shown in the state diff, while ERC20 logs show large stETH transfers from the pool to the helper.
     - The helper repays all flash loans to Morpho in USDC and wstETH, then sends 60672854887643676587 stETH from the helper to the attacker EOA.
   - Representative trace snippet:

```text
0x3F814e5FaE74cd73A70a0ea38d85971dFA6fdA21::onMorphoFlashLoan(...)
  ├─ WstETH::unwrap(5757882098882308991)
  │   ├─ Lido::transfer(..., 6853968499544955185)
  ├─ UnilendV2Core::lend(...)
  ├─ UnilendV2Core::borrow(...)
  ├─ UnilendV2Core::redeemUnderlying(...)
```

   - Evidence:
     - `artifacts/root_cause/seed/1/0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba/trace.cast.log`
     - `artifacts/root_cause/data_collector/iter_2/state_diff/1/0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba.json`
     - `artifacts/root_cause/data_collector/iter_3/state_diff_annotations/1/0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba.state_diff_annotated.json`
     - `artifacts/root_cause/data_collector/iter_3/tx/1/0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba.receipt.decoded_erc20.json`

The net effect of the adversary flow is that the helper uses public contracts and flash loans to maneuver UnilendV2Pool’s accounting into a state where a large amount of stETH is legally “borrowed” and withdrawn, but the system ends with an undercollateralized pool and a stETH profit for the attacker EOA.

# Impact & Losses

The impact is a direct loss of stETH from the Unilend V2 stETH/USDC pool:
- Total loss overview:
  - Token: stETH.
  - Amount: `60.672854887643676587` stETH.

On-chain evidence:
- ERC20 stETH transfer from pool to helper:

```json
{
  "event": "Transfer",
  "address": "0xae7ab96520de3a18e5e111b5eaab095312d7fe84",
  "from": "0x4e34dd25dbd367b1bf82e1b5527dbbe799fad0d0",
  "to_or_spender": "0x3f814e5fae74cd73a70a0ea38d85971dfa6fda21",
  "value": "60672854887643676589"
}
```

- Final ERC20 stETH transfer from helper to attacker EOA:

```json
{
  "event": "Transfer",
  "address": "0xae7ab96520de3a18e5e111b5eaab095312d7fe84",
  "from": "0x3f814e5fae74cd73a70a0ea38d85971dfa6fda21",
  "to_or_spender": "0x55f5f8058816d5376df310770ca3a2e294089c33",
  "value": "60672854887643676587"
}
```

These transfers align with the state diff showing the pool’s stETH balance decreasing by essentially the same amount. The remaining two wei correspond to rounding residues through intermediate Lido/wstETH conversions and do not change the economic conclusion.

At the accounting level:
- `UnilendV2Pool.token1Data.totalBorrow` and `totalBorrowShare` record large outstanding stETH borrows.
- The pool’s actual stETH holdings are reduced by ~60.67 stETH.
- The attacker’s EOA realizes a net gain of `60672854887643676587` stETH by the end of the exploit transaction, with all flash loans fully repaid.

# References

- [1] Incident transaction trace 0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba  
  `artifacts/root_cause/seed/1/0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba/trace.cast.log`

- [2] Annotated state diff for incident tx 0x4403…74e0  
  `artifacts/root_cause/data_collector/iter_3/state_diff_annotations/1/0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba.state_diff_annotated.json`

- [3] Decoded ERC20 receipt for incident tx 0x4403…74e0  
  `artifacts/root_cause/data_collector/iter_3/tx/1/0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba.receipt.decoded_erc20.json`

- [4] UnilendV2Pool source and storage layout  
  `artifacts/root_cause/data_collector/iter_1/contract/1/0x4E34DD25Dbd367B1bF82E1B5527DBbE799fAD0d0/source/out/pool.sol/UnilendV2Pool.json` and `source/src/pool.sol`

- [5] Lido stETH and wstETH sources  
  `artifacts/root_cause/seed/1/0x6ca84080381e43938476814be61b779a8bb6a600/src/contracts/0.4.24/StETH.sol`  
  `artifacts/root_cause/seed/1/0x6ca84080381e43938476814be61b779a8bb6a600/src/contracts/0.4.24/Lido.sol`  
  `artifacts/root_cause/seed/1/0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0/out/Contract.sol/WstETH.json`

