# MFT Tax Router Honeypot on BSC

## Incident Overview & TL;DR

This incident involves a deliberately constructed honeypot and fee-siphoning scheme on BNB Smart Chain (BSC, chainid 56) built around the MFT tax token, an automation contract, and a honeypot token.

In the observed victim transaction, EOA `0x2bee9915ddefdc987a42275fbcc39ed178a70aaa` calls `transfer2(address,uint256)` on automation contract `0x6e088c3dd1055f5dd1660c1c64de2af8110b85a8` with MFT token `0x29ee4526e3a4078ce37762dc864424a089ebba11` and an amount of `14,000,000` units. The call routes MFT through a PancakeSwap-style pair and MFT’s internal tax logic.

On-chain balance deltas show that the victim loses a large amount of MFT and pays gas, while:
- MFT’s hard-coded tax recipients `0x86ABD8be0eC670A06cC0B8a77b63084176182Ac0` and `0xc69502eE6441805174E64Ac2a9139446e3D48d76` receive USDT profits; and
- the automation contract ends up holding honeypot token `0xbbe5bea9e8d9886776beb21f0749804d18ab7fb9`.

No ERC20 assets flow back to the victim. This behavior is consistent across the seed transaction and is the intended design of the system, not an accidental bug.

### Seed Transaction Summary

**Seed tx:**

```json
{
  "chainid": 56,
  "txhash": "0xe24ee2af7ceee6d6fad1cacda26004adfe0f44d397a17d2aca56c9a01d759142",
  "etherscan": {
    "tx": {
      "result": {
        "from": "0x2bee9915ddefdc987a42275fbcc39ed178a70aaa",
        "to": "0x6e088c3dd1055f5dd1660c1c64de2af8110b85a8",
        "input": "0x7ce7c990...",
        "gas": "0x5f5e100",
        "gasPrice": "0x3b9aca00",
        "value": "0x0"
      }
    }
  }
}
```

*Snippet 1 – Seed victim transaction metadata showing `from` = victim EOA, `to` = automation contract, 0-value call with selector `0x7ce7c990` (decoded as `transfer2(address,uint256)`).*

## Key Background

### Tokens and Contracts

The scheme relies on three main contracts on BSC:

- **MFT tax token** – ERC20-like contract at `0x29ee4526e3a4078ce37762dc864424a089ebba11`.
- **Automation contract** – decompiled contract at `0x6e088c3dd1055f5dd1660c1c64de2af8110b85a8` that exposes `transfer2`, `withdrawErc20`, `withdrawETH`, `withdrawAll`, and `destroy` functions.
- **Honeypot token** – token at `0xbbe5bea9e8d9886776beb21f0749804d18ab7fb9`, owned by EOA `0xb07be4cfcc614fed528e07677b3a7d58af5a7330`.

These contracts are wired together using a PancakeSwap-style router and a dedicated pair for MFT/USDT.

### MFT Token Tax Logic

The verified MFT source code shows that MFT is a fee-on-transfer token with hard-coded USDT tax recipients and a function that automatically swaps collected MFT into USDT and forwards the proceeds to these addresses.

```solidity
// Collected from verified MFT source (Contract.sol)
string public override name = "MFT";
string public override symbol = "MFT";
address deadAddress = 0xc69502eE6441805174E64Ac2a9139446e3D48d76;
address superAddress = 0x86ABD8be0eC670A06cC0B8a77b63084176182Ac0;
...
function _transfer(address from, address to, uint256 amount) private {
    ...
    if (_swapPairList[to]) {
        if (!inSwap) {
            uint256 contractTokenBalance = _balances[address(this)];
            if (contractTokenBalance > 0) {
                uint256 swapFee = _buyFundFee + _sellFundFee;
                uint256 numTokensSellToFund = amount;
                if (numTokensSellToFund > contractTokenBalance) {
                    numTokensSellToFund = contractTokenBalance;
                }
                swapTokenForFund(numTokensSellToFund / 2, swapFee, deadAddress);
                swapTokenForFund(numTokensSellToFund / 2, swapFee, superAddress);
            }
        }
    }
}
```

*Snippet 2 – MFT contract showing hard-coded tax recipients and call into `swapTokenForFund` on sells via the DEX pair.*

`swapTokenForFund` swaps MFT held by the contract into USDT and transfers all resulting USDT from a `TokenDistributor` helper directly to the configured `_target` address (either `deadAddress` or `superAddress`).

```solidity
function swapTokenForFund(
    uint256 tokenAmount,
    uint256 swapFee,
    address _target
) private lockTheSwap {
    if (swapFee == 0) return;
    swapFee += swapFee;

    address[] memory path = new address[](2);
    path[0] = address(this);
    path[1] = currency; // USDT
    ...
    _swapRouter
        .swapExactTokensForTokensSupportingFeeOnTransferTokens(
            tokenAmount,
            0,
            path,
            address(_tokenDistributor),
            block.timestamp
        );
    IERC20 token = IERC20(currency);
    uint256 blance = token.balanceOf(address(_tokenDistributor));
    token.transferFrom(address(_tokenDistributor), _target, blance);
}
```

*Snippet 3 – MFT `swapTokenForFund` logic swapping MFT to USDT and forwarding the full USDT balance to `_target` (tax recipient address).* 

### Automation Contract Behavior

The decompiled automation contract at `0x6e088…` exposes a `transfer2(address,uint256)` function with selector `0x7ce7c990`. Although the decompiled code is low-level and not meant to be recompiled, its structure shows that:

- It requires the caller and arguments to be simple address/uint256 types.
- It uses stored addresses (`store_c`, `store_d`, `store_e`, `store_f`) corresponding to router/pair/token contracts.
- It queries token balances, sets a short deadline, and performs swaps through external contracts.
- It exposes `withdrawErc20`, `withdrawETH`, `withdrawAll`, and `destroy` functions that route value back to a stored owner address derived from `store_a`.

```solidity
// Decompiled transfer2 from 0x6e088…
function transfer2(address arg0, uint256 arg1) public {
    require(arg0 == (address(arg0)));
    require(arg1 == arg1);
    require(address(msg.sender) - (address(store_a / 0x01)));
    store_b = (address(arg0) * 0x01) | (uint96(store_b));
    ...
    require(address(store_c / 0x01).code.length);
    (bool success, bytes memory ret0) = address(store_c / 0x01).Unresolved_490e6cbc(var_f); // router/pair call
    ...
    address var_l = address(store_d / 0x01);
    address var_m = address(store_e / 0x01);
    ...
    (bool success, bytes memory ret0) = address(store_d / 0x01).Unresolved_70a08231(var_i); // balanceOf
    ...
    require(address(store_f / 0x01).code.length);
    (bool success, bytes memory ret0) = address(store_f / 0x01).Unresolved_5c11d795(var_j); // router/pair call
    ...
}
```

*Snippet 4 – Key structure of `transfer2` in the automation contract, showing orchestration of external swaps and balance queries via stored router/pair/token addresses.*

Additional functions like `withdrawErc20`, `withdrawETH`, `withdrawAll`, and `destroy` are present and redirect funds to an owner address derived from storage, reinforcing that the contract’s economics are designed for the owner’s benefit rather than for callers.

### Honeypot Token and Adversary Ownership

For the honeypot token `0xbbe5bea9e8d9886776beb21f0749804d18ab7fb9`, the collected artifacts show that its `owner()` is EOA `0xb07be4cfcc614fed528e07677b3a7d58af5a7330`.

```json
{
  "result": "0x000000000000000000000000b07be4cfcc614fed528e07677b3a7d58af5a7330"
}
```

*Snippet 5 – Owner call response for honeypot token `0xbbe5…`, identifying EOA `0xb07…` as contract owner.*

Long-range ERC20 balance deltas for `0xb07…` show that, across its lifetime, it accumulates USDT and ends with a very large balance of the honeypot token while its MFT balance ends at zero.

```json
{
  "address": "0xb07be4cfcc614fed528e07677b3a7d58af5a7330",
  "tokens": {
    "0x55d398326f99059ff775485246999027b3197955": {
      "label": "USDT",
      "end_balance": "24433564757695475",
      "net_delta": "24433564757695475"
    },
    "0x29ee4526e3a4078ce37762dc864424a089ebba11": {
      "label": "MFT",
      "end_balance": "0"
    },
    "0xbbe5bea9e8d9886776beb21f0749804d18ab7fb9": {
      "label": "HONEYPOT",
      "end_balance": "24999995000002134172948489"
    }
  }
}
```

*Snippet 6 – Lifetime ERC20 deltas for adversary EOA `0xb07…`, showing accumulation of USDT and a very large honeypot balance.*

Combining these observations, EOA `0xb07…` is the owner/deployer of both the automation contract and the honeypot token and the ultimate beneficiary of the scheme (via ownership and withdrawal functions).

## Vulnerability & Root Cause Analysis

### High-Level Root Cause

The root cause is a malicious contract composition rather than a typical protocol bug:

- MFT is configured as a fee-on-transfer tax token whose tax proceeds are always paid in USDT to two hard-coded EOAs (`0x86ABD8…` and `0xc69502…`).
- The automation contract `0x6e088…` exposes a seemingly generic `transfer2(token, amount)` entrypoint but internally routes flows through a DEX pair and MFT’s tax logic.
- The honeypot token `0xbbe5…` is used as the sink token that the automation contract accumulates during victim interactions.

When a victim calls `transfer2(MFT, amount)` on `0x6e088…`, no checks enforce any reward to the caller. Instead, the system guarantees that:

- the victim’s MFT is drawn into swap paths involving the MFT/USDT pair;
- MFT taxes are realized and swapped into USDT inside the MFT contract; and
- the resulting USDT proceeds are sent to `deadAddress` and `superAddress`, i.e., `0xc69502…` and `0x86ABD8…`.

### Concrete On-Chain Effects in the Seed Transaction

The seed transaction’s ERC20 net deltas concisely summarize per-address outcomes.

```json
{
  "txhash": "0xe24ee2af7ceee6d6fad1cacda26004adfe0f44d397a17d2aca56c9a01d759142",
  "tokens": {
    "0x55d398326f99059ff775485246999027b3197955": {
      "0x2bee…": "0",
      "0x6e088…": "0",
      "0x67c88…": "-42082049076742253922410",
      "0x86abd8…": "536706198879928083",
      "0xc69502…": "1593671642304587883"
    },
    "0xbbe5bea9e8d9886776beb21f0749804d18ab7fb9": {
      "0x6e088…": "1000000000000075900"
    },
    "0x29ee4526e3a4078ce37762dc864424a089ebba11": {
      "0x2bee…": "-1832701300100941151931",
      "0x6e088…": "0",
      "0x67c88…": "-1189614578340678529330143"
    }
  }
}
```

*Snippet 7 – ERC20 net deltas for the seed transaction, showing MFT outflow from `0x2bee…`, USDT profits to `0x86ABD8…` and `0xc69502…`, and honeypot 0xbbe5… accumulation at `0x6e088…`.*

Key observations:

- The victim `0x2bee…` has a large negative MFT delta (`-1.832701300100941151931e21` units) with **no ERC20 inflows**.
- `0x86ABD8…` and `0xc69502…` gain USDT (`+0.5367…` and `+1.5937…` USDT respectively).
- The automation contract `0x6e088…` ends the transaction with `+1.0000000000000759e18` units of honeypot token `0xbbe5…` and zero net USDT and MFT.
- Helper address `0x67c88…` is strongly negative in both USDT and MFT, consistent with being an intermediary that routes flows toward the tax recipients and the honeypot.

The native balance deltas confirm that the victim also pays gas:

```json
{
  "native_balance_deltas": [
    {
      "address": "0x2bee9915ddefdc987a42275fbcc39ed178a70aaa",
      "before_wei": "1144166755240541632",
      "after_wei": "1142664322240541632",
      "delta_wei": "-1502433000000000"
    }
  ]
}
```

*Snippet 8 – Native balance delta for the victim EOA showing gas paid in the seed transaction.*

Combining ERC20 and native deltas, the seed transaction strictly harms the victim and strictly benefits the adversary cluster.

### Why This Is a Designed Honeypot/Router Attack

Several properties show that this is an intentional design rather than an incidental bug:

- MFT’s tax recipients are hard-coded EOAs controlled by the adversary, not governance-controlled addresses.
- The automation contract is deployed and owned by the same EOA (`0xb07…`) that owns the honeypot token, and its withdrawal functions favor the owner.
- The ERC20 net deltas in the seed transaction match exactly what MFT’s `swapTokenForFund` and the automation routing would produce.
- Long-range deltas for `0xb07…` show accumulation of USDT and honeypot tokens, indicating repeated profit extraction over time.

## Adversary Flow Analysis

### Adversary Cluster

The adversary cluster consists of:

1. **EOA `0xb07be4cfcc614fed528e07677b3a7d58af5a7330`** – deployer and owner of the automation contract and the honeypot token; accrues long-term USDT and honeypot balances.
2. **Automation contract `0x6e088c3dd1055f5dd1660c1c64de2af8110b85a8`** – orchestrates swaps and accumulates honeypot tokens; exposes privileged withdraw/destroy functions for the owner.
3. **Honeypot token `0xbbe5bea9e8d9886776beb21f0749804d18ab7fb9`** – illiquid or adversary-controlled asset accumulated by `0x6e088…` and ultimately by the owner `0xb07…`.
4. **MFT tax recipients `0x86ABD8be0eC670A06cC0B8a77b63084176182Ac0` and `0xc69502eE6441805174E64Ac2a9139446e3D48d76`** – EOAs receiving deterministic USDT inflows from MFT’s tax logic whenever the configured path is used.

### Lifecycle Stages

1. **Infrastructure deployment** – EOA `0xb07…` deploys the automation contract and honeypot token, assigning ownership to itself and configuring stored addresses for router, pair, MFT, and other helpers.
2. **Liquidity and tax configuration** – MFT is deployed as a fee-on-transfer token paired against USDT on PancakeSwap; liquidity for MFT/USDT is established, and MFT’s `deadAddress` and `superAddress` are set to `0xc69502…` and `0x86ABD8…` respectively.
3. **Victim interaction and fee siphoning** – victims call `transfer2(MFT, amount)` on `0x6e088…`. The automation contract routes tokens through the MFT/USDT pair and MFT’s tax logic, resulting in:
   - victim MFT outflows and gas costs;
   - USDT gains at `0x86ABD8…` and `0xc69502…`;
   - honeypot token accumulation at `0x6e088…`, which can eventually be pulled by `0xb07…` via withdraw functions.

The all-relevant-txs set in the analysis (including two adversary-crafted transactions and one related configuration transaction) is consistent with this lifecycle.

## Impact & Losses

### Seed Transaction Impact

From the ERC20 net deltas for the seed transaction:

- **Victim loss:**
  - `0x2bee…` loses `1.832701300100941151931e21` units of MFT.
  - Pays `1,502,433,000,000,000` wei in gas.
  - Receives no ERC20 tokens.

- **Adversary gains:**
  - `0x86ABD8…` gains `0.536706198879928083` USDT.
  - `0xc69502…` gains `1.593671642304587883` USDT.
  - Automation contract `0x6e088…` gains `1.0000000000000759e18` units of honeypot `0xbbe5…` and ends the tx with zero net USDT and MFT.

### Systemic Risk

Because the attack is implemented as a permissionless honeypot/automation design, any additional victim calling `transfer2(MFT, amount)` can be exploited in the same way. The scheme is repeatable and deterministic, and the adversary cluster can accumulate further USDT and honeypot tokens over time.

## References

- **Seed tx metadata and balance diff for 0xe24ee2af7c…** – victim transaction details, native and ERC20 balance changes.
- **MFT token source and ABI** – verified source code and compiled artifacts for `0x29ee4526e3a4078ce37762dc864424a089ebba11`.
- **Automation contract 0x6e088… decompiled code** – decompiler output for `0x6e088c3dd1055f5dd1660c1c64de2af8110b85a8`.
- **Honeypot token 0xbbe5… owner evidence** – owner call logs and artifacts showing `0xb07…` as owner.
- **Adversary EOA 0xb07… ERC20 net deltas** – lifetime ERC20 balance deltas for the owner EOA, showing accumulated USDT and honeypot balances.

