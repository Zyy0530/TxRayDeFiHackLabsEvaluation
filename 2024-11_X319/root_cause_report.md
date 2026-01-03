# BNB Chain: 0xedd6...b2c0 `claimEther` Uncontrolled Ether Withdrawal

## Incident Overview & TL;DR

On BNB Chain (chainid 56), an unprivileged externally owned account (EOA) `0xe60329a82c5add1898ba273fc53835ac7e6fd5ca` deployed a small helper contract whose constructor immediately called `claimEther(address,uint256)` on contract `0xedd632eaf3b57e100ae9142e8ed1641e5fd6b2c0`, withdrawing the contract’s entire 20.85 BNB native balance to the attacker. The helper contract performs no post-construction logic, so the sole purpose of the transaction was to trigger this withdrawal. Shortly afterwards, the attacker fragmented the received BNB into many deposits to contract `0x0d5550d52428e7e3175bfc9550207e4ad3859b17` via a `deposit(address,bytes32,bytes)` function.

The core root cause is that contract `0xedd6...b2c0` exposes a *public* `claimEther(address,uint256)` function that unconditionally transfers arbitrary native BNB to the supplied address. The function performs only a trivial address-type check and does **not** enforce any access control or entitlement checks based on `msg.sender`, an operator role, or recorded balances. This creates a direct ACT opportunity for any account to drain the contract’s BNB balance in a single call.

This incident is categorized as an ACT realization with:
- `protocol_name`: Contract `0xedd632eaf3b57e100ae9142e8ed1641e5fd6b2c0` on BNB Chain.
- `is_act`: `true`.
- `root_cause_category`: `protocol_bug`.

## Key Background

### Contract 0xedd6...b2c0 design and code provenance

- Contract `0xedd632eaf3b57e100ae9142e8ed1641e5fd6b2c0` on BNB Chain has **no verified source code** on the block explorer. Data collection attempted an Etherscan `getsourcecode` fetch, which confirmed the lack of verification.
- Runtime bytecode for the contract was fetched from QuickNode RPC and decompiled using Heimdall. The resulting Solidity-like code and ABI show an ERC20-style token with an `operator` address, `mint` and `burn` functions, and standard `balanceOf`/`transfer`/`approve` interfaces, plus an extra function `claimEther(address,uint256)` that pays out native BNB.
- Heimdall decompilation and bytecode disassembly show that `claimEther(address,uint256)` takes an arbitrary destination address and amount, performs only a trivial address-type check on the first parameter, and then executes a native transfer without referencing `msg.sender` or any stored authorization.

**Heimdall-decompiled `claimEther` for 0xedd6...b2c0**  
Origin: Decompiled contract source for `0xedd6...b2c0` (Heimdall decompiler output).
```solidity
function claimEther(address arg0, uint256 arg1) public {
    require(arg0 == (address(arg0)));
    (bool success, bytes memory ret0) = address(arg0).transfer(arg1);
}
```
*Caption: Decompiled `claimEther` shows a public function that transfers an arbitrary amount of native BNB to any address, with no access control or entitlement checks.*

In contrast, other functions in the same contract (such as `burn`) explicitly gate behavior on `msg.sender == operator` or perform balance checks, reinforcing that the lack of checks in `claimEther` is a genuine design bug rather than a decompilation artifact.

### ACT opportunity and pre-state σ
t
The ACT opportunity is evaluated at block height `B = 43860720` on BNB Chain (chainid 56). Immediately before inclusion of the adversary-crafted transaction `0x679028cb0a5af35f57cbea120ec668a5caf72d74fcc6972adc7c75ef6c9a9092` in this block, the pre-state σ
t is:

- Victim contract `0xedd6...b2c0` holds **20.85 BNB** in its native balance.
- EOA `0xe60329a8...d5ca` (the attacker) holds **0.0983219987 BNB**, which is sufficient to pay gas for one contract-creation transaction at a gas price of 3 gwei.

These facts are derived from the prestate tracer balance diff for the seed transaction and internal transactions around the victim contract.

**Prestate balance diff for the seed transaction**  
Origin: `prestateTracer` balance diff for tx `0x6790...9092`.
```json
{
  "native_balance_deltas": [
    {
      "address": "0xe60329a82c5add1898ba273fc53835ac7e6fd5ca",
      "before_wei": "98321998700000000",
      "after_wei": "20948078293700000000",
      "delta_wei": "20849756295000000000"
    },
    {
      "address": "0xedd632eaf3b57e100ae9142e8ed1641e5fd6b2c0",
      "before_wei": "20850000000000000000",
      "after_wei": "0",
      "delta_wei": "-20850000000000000000"
    }
  ]
}
```
*Caption: Prestate tracer shows the victim contract starting with 20.85 BNB and ending with 0 BNB, while the attacker’s EOA increases from approximately 0.0983 BNB to ~20.9481 BNB during the exploit transaction.*

### Exploit predicate and profit characterization

The event is a straightforward profit-motivated ACT realization:

- `exploit_predicate.type`: `profit` (no non-monetary oracle is involved).
- `reference_asset`: BNB (native token on BNB Chain).
- `adversary_address`: EOA `0xe60329a82c5add1898ba273fc53835ac7e6fd5ca`.
- **Value before** (BNB): `0.0983219987`.
- **Value after** (BNB): `20.9480782937`.
- **Value delta** (BNB): `20.849756295`.

Gas fees are computed from the seed transaction as:
- `gasUsed = 81235`, `gasPrice = 3 gwei`.
- Fee = `81235 * 3e9 wei = 243705000000000 wei = 0.000243705 BNB`.

Combining these, the adversary’s net portfolio change in BNB is approximately **+20.849756295 BNB after fees**, entirely funded by draining the victim contract’s native balance via a single `claimEther` call.

### Inclusion feasibility and adversary capabilities

The adversary-crafted transaction `0x6790...9092` is a standard contract creation transaction from `0xe60329a8...d5ca` on BNB Chain. With an initial balance of ~0.0983 BNB and a gas price of 3 gwei, the EOA can:

- Pay for contract deployment gas.
- Embed in the constructor a single external call to `0xedd6...b2c0::claimEther(attacker_address, 20850000000000000000)`.
- Execute fully under normal gas and consensus rules, as confirmed by successful execution and gas usage in the cast trace.

## Adversary Flow Analysis

The adversary lifecycle is well-captured by three stages: pre-funding, exploit execution via a helper contract, and post-exploit outbound transfers.

### Stage 1 – Adversary pre-tx funding state

- Immediately before the seed transaction, the prestate tracer shows EOA `0xe60329a8...d5ca` holding **0.0983219987 BNB**, enough to fund a single contract-creation transaction with 3 gwei gas price.
- At the same time, victim contract `0xedd6...b2c0` holds **20.85 BNB**, making a full balance withdrawal possible in a single call.
- This stage is evidenced by the same `balance_diff_prestate.json` snippet shown above and by the internal transaction list for `0xedd6...b2c0` around blocks `43860000–43861000`, which does not show other drains in the window.

### Stage 2 – Helper contract deployment and `claimEther` call

The core exploit occurs in the adversary-crafted transaction `0x679028cb0a5af35f57cbea120ec668a5caf72d74fcc6972adc7c75ef6c9a9092` in block `43860720`:

- From: EOA `0xe60329a8...d5ca`.
- To: contract creation (no `to` address in the tx; resulting contract is `0x54588267066ddbc6f8dcd724d88c25e2838b6374`).
- Mechanism: `contract_deploy_and_call` – the constructor of the new contract immediately calls the victim’s `claimEther` function.

**Seed transaction call trace**  
Origin: `cast run -vvvvv` trace for tx `0x6790...9092` (evm-version `cancun`).
```text
[23807] → new <unknown>@0x5458...B6374(...)
  ├─ [7303] 0xedD632eAf3b57e100aE9142e8eD1641e5Fd6b2c0::claimEther(
  │       0xE60329A82C5aDD1898bA273FC53835Ac7e6fD5cA,
  │       20850000000000000000 [2.085e19]
  │   )
  │   ├─ [0] 0xE60329A82C5aDD1898bA273FC53835Ac7e6fD5cA::fallback{value: 20850000000000000000}()
  │   │   └─ ← [Stop]
  │   └─ ← [Stop]
  └─ ← [Return] 0x6080...
```
*Caption: Seed transaction constructor deploys helper contract `0x5458...b6374`, whose constructor calls `claimEther(attacker, 20850000000000000000)` on `0xedd6...b2c0`, sending 20.85 BNB to the attacker EOA.*

This trace, combined with the decompiled `claimEther` code, shows that:

- The helper contract’s constructor is a thin wrapper that forwards a `claimEther` call to the victim contract.
- The value field in the internal call matches the victim’s full 20.85 BNB balance (`20850000000000000000` wei).
- The only EOA receiving native BNB is `0xe60329a8...d5ca`.

Because `claimEther` is publicly callable and unguarded, any EOA can deploy such a helper contract (or call directly) to drain whatever native BNB balance the contract holds at the time of call.

### Stage 3 – Post-exploit outbound transfers from attacker EOA

After successfully draining 20.85 BNB, the attacker EOA `0xe60329a8...d5ca` initiates a series of outbound transfers to contract `0x0d5550d52428e7e3175bfc9550207e4ad3859b17`, primarily via a `deposit(address _tornado, bytes32 _commitment, bytes _encryptedNote)` function. These transactions fragment the stolen funds into multiple deposits of varying sizes (most commonly 1 BNB, with some 0.1 BNB and 10 BNB deposits), dispersing the drained BNB into that contract.

**Sample post-exploit deposits from the attacker**  
Origin: normal transaction list for address `0xe60329a8...d5ca` (blocks up to `43861020`).
```json
[
  {
    "hash": "0xf0be182a54a60c6c977630c8debf2bef5f3c3fe8f549df3e5be7988655e2c2da",
    "from": "0xe60329a82c5add1898ba273fc53835ac7e6fd5ca",
    "to": "0x0d5550d52428e7e3175bfc9550207e4ad3859b17",
    "value": "1000000000000000000",
    "functionName": "deposit(address _tornado, bytes32 _commitment, bytes _encryptedNote)"
  },
  {
    "hash": "0x557ee6e1303d257f8aad3d1bcf633cd843c64f0098df7c0d1a59ab8d58825b63",
    "from": "0xe60329a82c5add1898ba273fc53835ac7e6fd5ca",
    "to": "0x0d5550d52428e7e3175bfc9550207e4ad3859b17",
    "value": "10000000000000000000",
    "functionName": "deposit(address _tornado, bytes32 _commitment, bytes _encryptedNote)"
  }
]
```
*Caption: Example post-exploit deposits by the attacker EOA into contract `0x0d55...b17`, illustrating fragmentation of the drained BNB into multiple `deposit` calls.*

Within the analyzed window, there are no observed compensating inflows back to the victim contract `0xedd6...b2c0`. As a result, at least 20.85 BNB remain removed from the victim.

## Impact & Losses

The impact is concentrated in a single exploit transaction with subsequent fund obfuscation:

- The victim contract `0xedd6...b2c0` loses its entire native BNB balance of **20.85 BNB** in one `claimEther` call.
- The adversary EOA `0xe60329a8...d5ca` receives 20.85 BNB (before gas) and then disperses the funds into `0x0d55...b17` through multiple `deposit` transactions.
- No compensating inflows back to `0xedd6...b2c0` are seen in the analyzed time window, so the **realized loss is at least 20.85 BNB**.

**Total loss overview**
- Asset: `BNB` (native token).
- Amount lost: `20.85` BNB.

## Root Cause Summary

The root cause is a **protocol-level bug** in contract `0xedd6...b2c0`:

- `claimEther(address,uint256)` is a public function that any caller can invoke.
- The function takes an arbitrary destination address and amount and then transfers native BNB to that address.
- It does **not** enforce any authorization checks (e.g., `onlyOwner`, `onlyOperator`, or `msg.sender` balance/role checks) nor does it validate the caller against stored entitlements.
- Given a positive native balance in the contract, any EOA can call `claimEther` (directly or via a helper contract) to withdraw arbitrary BNB amounts up to the full contract balance.

This design directly enables the ACT: at pre-state σ
t, the contract holds 20.85 BNB; the adversary can and does trigger `claimEther(attacker, 20.85 BNB)` in a single transaction, fully draining the contract.

## References

The analysis is grounded in the following collected artifacts:

- **[1] Seed transaction metadata and balance diff for `0x6790...9092`**  
  Origin: seed metadata and prestate tracer output for the adversary-crafted transaction.  
  Captures tx parameters, block inclusion (`43860720`), and detailed balance diffs for `0xe603...d5ca` and `0xedd6...b2c0`.

- **[2] Victim contract `0xedd6...b2c0` decompiled source and ABI**  
  Origin: Heimdall decompilation and ABI generated from on-chain runtime bytecode.  
  Provides function signatures and semantics for `claimEther`, `mint`, `burn`, `transfer`, and related ERC20-like functions, confirming the lack of access control on `claimEther`.

- **[3] Cast run trace and prestate balance diff for seed tx `0x6790...9092`**  
  Origin: `cast run -vvvvv` trace and JSON state diff from QuickNode prestate tracer.  
  Shows the helper contract deployment, internal call to `0xedd6...b2c0::claimEther(attacker, 20.85 BNB)`, the value flow to the attacker’s EOA, and the gas usage underpinning the exploit.

- **Additional data collector outputs**  
  - Normal and internal txlists for `0xedd6...b2c0` around blocks `43860000–43861000`, confirming no other competing drains in the window.  
  - Normal txlist for `0xe603...d5ca` up to block `43861020`, documenting the sequence of `deposit` calls into `0x0d55...b17` used to move the stolen funds.
