# BNB Chain WBNB PrivilegedLoan Drain via BorrowerOperationsV6::sell

## 1. Incident Overview TL;DR

On BNB Chain (chainid 56), an unprivileged adversary-controlled EOA `0x3fee6d8aaea76d06cf1ebeaf6b186af215f14088` used a custom helper contract `0xe82fc275b0e3573115eadca465f85c4f96a6c631` to invoke `BorrowerOperationsV6::sell` through collateral-holder proxy `0x2eed3dc9c5134c056825b12388ee9be04e522173`. Due to a design flaw in how `BorrowerOperationsV6` integrates with `TokenHolder::privilegedLoan` behind token-holder proxy `0x616b36265759517af14300ba1dd20762241a3828`, the call transferred 20 WBNB of protocol collateral from `0x2eed...` to arbitrary recipients even though the referenced loan (`loanId = 0`) was not active. In the core exploit transaction `0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6` at block `63856735`, 0.8 WBNB was sent to external EOA `0x8432cd30c4d72ee793399e274c482223dca2bf9e` and 19.2 WBNB to attacker-controlled contract `0xe82f...`, with no WBNB returned to the collateral-holder. Including deployment, configuration, exploit, and withdrawal transactions, the attacker paid 0.1247948 BNB in gas, yielding at least 19.0752052 WBNB of net profit from a permissionless ACT opportunity.

## 2. Key Background

The affected system is a BorrowerOperationsV6-based protocol that manages collateralized positions and integrates with a separate TokenHolder component for collateral handling. On BNB Chain:

- The collateral-holder is deployed as proxy `0x2eed3dc9c5134c056825b12388ee9be04e522173` and delegates to a `BorrowerOperationsV6` implementation.
- A token-holder proxy `0x616b36265759517af14300ba1dd20762241a3828` delegates to a TokenHolder implementation (implementation address `0x8c7f34436c0037742aecf047e06fd4b27ad01117`) that exposes `privilegedLoan` and related WBNB transfer logic.
- The collateral token is WBNB at address `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`, implemented as a standard wrapping contract where each 1 WBNB represents 1 BNB deposited on-chain.

Immediately before block `63856735` (pre-state `σ_B`), the protocol state relevant to the incident is reconstructed from:

- Seed metadata for the exploit transaction at `artifacts/root_cause/seed/56/0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6/metadata.json`.
- A prestate tracer for the exploit transaction at `artifacts/root_cause/data_collector/iter_2/tx/56/0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6/trace.prestate_tracer.json`.
- WBNB contract storage and code at `artifacts/root_cause/seed/56/0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c/src/Contract.sol`.

The root cause category for this incident is a protocol bug: a flawed interaction between BorrowerOperationsV6 and TokenHolder that allows misuse of `TokenHolder::privilegedLoan` to drain collateral-holder WBNB without any active loan or enforced repayment.

## 3. Vulnerability Analysis

### 3.1 Vulnerable Components

The core vulnerability resides in how BorrowerOperationsV6 and TokenHolder are wired:

- **Collateral-holder proxy (`0x2eed3dc9c5134c056825b12388ee9be04e522173`) and BorrowerOperationsV6 implementation**  
  This proxy delegates calls to a BorrowerOperationsV6 implementation that includes a `sell` function. For `loanId = 0`, the implementation reads the loan record via `loans(0)` and obtains a struct where `active` is `false` and exposure-related fields are zero. Despite this, the implementation continues into the TokenHolder flow and triggers `TokenHolder::privilegedLoan`.

- **TokenHolder proxy (`0x616b36265759517af14300ba1dd20762241a3828`) and implementation (`0x8c7f34436c0037742aecf047e06fd4b27ad01117`)**  
  The TokenHolder implementation exposes `privilegedLoan` and WBNB transfer logic. When invoked in this context, it:
  - Reads WBNB balance for the collateral-holder at `0x2eed...`.
  - Transfers 20 WBNB from `0x2eed...` to the token-holder proxy `0x616b...`.
  - Permits additional WBNB transfers from `0x616b...` to arbitrary recipients, including external EOAs and attacker-controlled contracts, without enforcing that the loan is active or that a repayment to `0x2eed...` occurs.

The combination of these components creates a privileged collateral-transfer path that can be invoked under conditions where no legitimate loan-based collateral movement should be allowed.

### 3.2 Security Principles Violated

The incident violates several key security properties:

- **Access control:** The `TokenHolder::privilegedLoan` path, which is capable of moving collateral-holder WBNB, is reachable from an unprivileged external contract via BorrowerOperationsV6::sell. There is no restriction that limits calls to protocol-owned components or enforces that only legitimate protocol flows can invoke this function.
- **Collateral accounting and invariants:** Collateral-holder `0x2eed...` loses 20 WBNB of collateral associated with `loans(0)` even though the loan is not active and without any corresponding reduction in user liabilities or protocol exposure records. This breaks expected collateralization and accounting invariants.
- **Separation of concerns:** Profit-calculation and collateral-transfer logic are routed through a shared `TokenHolder::privilegedLoan` entry point without strict preconditions on loan state. This allows external contracts to repurpose internal flows—intended for controlled protocol operations—into direct value-extraction paths.

### 3.3 Exploit Preconditions

The ACT opportunity is permissionless and relies only on public chain state and standard transactions. The necessary conditions are:

- An unprivileged EOA can deploy an arbitrary helper contract (here `0xe82f...`) and configure it with token-holder proxy `0x616b...` via a public function (selector `0x57964aaf`).
- BorrowerOperationsV6::sell accepts parameters supplied via the helper contract such that:
  - The function routes into TokenHolder::privilegedLoan for the WBNB collateral associated with `loanId = 0`, where the loan record is not active.
  - The function uses the collateral-holder’s WBNB balance at `0x2eed...` as the source of funds for the privileged loan.
- TokenHolder::privilegedLoan lacks a guard that enforces repayment of the 20 WBNB back to the collateral-holder proxy `0x2eed...` and permits arbitrary WBNB recipients, including the attacker-controlled contract `0xe82f...` and the external EOA `0x8432...`.

Under these conditions, any unprivileged adversary can reproduce the exploit using only standard EOA transactions.

## 4. Detailed Root Cause Analysis

### 4.1 Seed Transaction and Pre-State

The seed transaction for the incident is:

- **Chain:** BNB Chain (chainid 56)  
- **Tx hash:** `0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6`  
- **From:** EOA `0x3fee6d8aaea76d06cf1ebeaf6b186af215f14088`  
- **To:** Attacker helper contract `0xe82fc275b0e3573115eadca465f85c4f96a6c631`  
- **Value:** 0 BNB  

Seed metadata confirms the calldata and sender:

```json
{
  "chainid": 56,
  "txhash": "0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6",
  "etherscan": {
    "tx": {
      "result": {
        "from": "0x3fee6d8aaea76d06cf1ebeaf6b186af215f14088",
        "to": "0xe82fc275b0e3573115eadca465f85c4f96a6c631",
        "input": "0xe4c61b84...00000000000000002eed3dc9c5134c056825b12388ee9be04e522173...bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c..."
      }
    }
  }
}
```

This shows the attacker calling selector `0xe4c61b84` on `0xe82f...` with parameters that include:

- Collateral-holder proxy `0x2eed3dc9c5134c056825b12388ee9be04e522173`.
- WBNB token `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`.
- A 20 WBNB amount (encoded as `20000000000000000000`).

The prestate and balance diff artifacts confirm the attacker pays only gas in this transaction. The balance diff is:

```json
{
  "chainid": 56,
  "txhash": "0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6",
  "native_balance_deltas": [
    {
      "address": "0x3fee6d8aaea76d06cf1ebeaf6b186af215f14088",
      "before_wei": "38540774100000000",
      "after_wei": "38522785300000000",
      "delta_wei": "-17988800000000"
    }
  ]
}
```

This shows a native BNB loss of `0.0179888` BNB for the attacker in the seed exploit transaction.

### 4.2 On-Chain Call Trace: BorrowerOperationsV6 and TokenHolder Flow

The iter_2 call tracer and cast trace for the seed transaction show the exact call flow from the attacker into the protocol. A key excerpt from the cast trace:

```bash
BorrowerOperationsV6::sell(..., 0x2EeD3DC9c5134C056825b12388Ee9Be04E522173, ...)
  ├─ TokenHolder::privilegedLoan(WBNB: [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c], 20000000000000000000 [2e19]) [delegatecall]
  │   ├─ WBNB::balanceOf(TransparentUpgradeableProxy: [0x2EeD3DC9c5134C056825b12388Ee9Be04E522173]) [staticcall]
  │   │   └─ ← [Return] 20028629095890410925 [2.002e19]
  │   ├─ WBNB::transfer(TransparentUpgradeableProxy: [0x616B36265759517AF14300Ba1dD20762241a3828], 20000000000000000000 [2e19])
  │   │   ├─ emit Transfer(src: 0x2EeD3DC9..., dst: 0x616B3626..., wad: 20000000000000000000 [2e19])
  │   └─ emit PrivilegedLoan(borrower: 0x616B3626..., amount: 20000000000000000000 [2e19])
  ├─ WBNB::transfer(0x8432CD30C4d72Ee793399E274C482223DCA2bF9e, 800000000000000000 [8e17])
  ├─ WBNB::transfer(0xe82Fc275B0e3573115eaDCa465f85c4F96A6c631, 800000000000000000 [8e17])
  ├─ WBNB::transfer(0xe82Fc275B0e3573115eaDCa465f85c4F96A6c631, 18400000000000000000 [1.84e19])
  ├─ emit Sell(..., profit: 20000000000000000000 [2e19])
WBNB::balanceOf(0xe82Fc275B0e3573115eaDCa465f85c4F96A6c631) [staticcall]
  └─ ← [Return] 19200000000000000000 [1.92e19]
```

This trace establishes:

- BorrowerOperationsV6::sell is invoked via the collateral-holder proxy `0x2eed...` and delegates into the BorrowerOperationsV6 implementation.
- That implementation calls `TokenHolder::privilegedLoan(WBNB, 20 WBNB)` through the token-holder proxy `0x616b...`.
- TokenHolder::privilegedLoan:
  - Checks `WBNB.balanceOf(0x2eed...)`, which returns approximately `20.028629095890410925` WBNB.
  - Transfers exactly `20` WBNB from `0x2eed...` to `0x616b...`.
  - Emits a `PrivilegedLoan` event for the 20 WBNB loan.
- Subsequent WBNB transfers from `0x616b...`:
  - 0.8 WBNB (`800000000000000000`) to `0x8432cd30c4d72ee793399e274c482223dca2bf9e`.
  - 0.8 WBNB and then 18.4 WBNB to `0xe82f...`, for a total of 19.2 WBNB.
- A final `WBNB.balanceOf(0xe82f...)` returns `19.2` WBNB, confirming that the attacker-controlled contract holds the entire 19.2 WBNB portion of the drained collateral, and there is no WBNB transfer back to `0x2eed...`.

### 4.3 Contract Semantics: WBNB, BorrowerOperationsV6, and TokenHolder

The WBNB contract source (verified on BscScan and collected in the artifacts) is:

```solidity
pragma solidity ^0.4.18;

contract WBNB {
    string public name     = "Wrapped BNB";
    string public symbol   = "WBNB";
    uint8  public decimals = 18;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;

    function() public payable {
        deposit();
    }
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        Deposit(msg.sender, msg.value);
    }
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        msg.sender.transfer(wad);
        Withdrawal(msg.sender, wad);
    }

    function totalSupply() public view returns (uint) {
        return this.balance;
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint wad)
        public
        returns (bool)
    {
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != uint(-1)) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        Transfer(src, dst, wad);

        return true;
    }
}
```

This confirms:

- 1 WBNB corresponds to 1 BNB deposited via `deposit()`, and withdrawals redeem BNB via `withdraw()`.
- The standard ERC-20 transfer semantics ensure that the WBNB movements observed in the trace correspond directly to economic value transfers of BNB.

From the collected BorrowerOperationsV6 and TokenHolder sources (and the disassembly for `0xe82f...`), the analyzer and this challenge agree that:

- `BorrowerOperationsV6::sell` reads `loans(0)` from its storage and finds an inactive loan but still proceeds to invoke `TokenHolder::privilegedLoan`.
- `TokenHolder::privilegedLoan` uses the collateral-holder’s WBNB balance as the lending pool without ensuring that:
  - The loan is active.
  - The borrowed WBNB is repaid to the collateral-holder.
  - Recipients are restricted to protocol-owned addresses.

Together, these semantics explain how 20 WBNB can be moved from `0x2eed...` to attacker-controlled destinations via a single `sell` call.

### 4.4 Profit Calculation and ACT Opportunity

The adversary-crafted transaction sequence `b` is:

1. `0xba473228bd61e8ba4bd8c8c9f411d863a24091fb301d6f25c63b693a2d325bf6` (deploy helper contract `0xe82f...`).
2. `0x6598c2c962e5a019abedb40f1480c3e7bf0e09a8aaa7bdc549c36239dd7ee406` (configure helper contract with token-holder proxy `0x616b...`, selector `0x57964aaf`).
3. `0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6` (core exploit via BorrowerOperationsV6::sell and TokenHolder::privilegedLoan).
4. `0xa9f735df65cc26f2bda9a51ac46824fdb09dd5092d869c9690d7b273a51c164e` (withdrawERC20(WBNB) from `0xe82f...` back to the attacker EOA).

Tx history and metadata for `0xe82f...` show:

```json
[
  { "hash": "0xba4732...", "gasUsed": "967711" },
  { "hash": "0x6598c2...", "gasUsed": "46248"  },
  { "hash": "0xc291d7...", "gasUsed": "179888" },
  { "hash": "0xa9f735...", "gasUsed": "54101"  }
]
```

All four transactions use `gasPrice = 100000000` wei (100 gwei). Summing gas used:

- Total gasUsed = `967711 + 46248 + 179888 + 54101 = 1247948`.
- Total gas cost = `1247948 × 100 gwei = 1247948 × 1e-7 BNB = 0.1247948` BNB.

Given the 1:1 WBNB↔BNB wrapping, the reference asset cost is `0.1247948` WBNB.

From the exploit call trace:

- 20 WBNB is transferred from `0x2eed...` to `0x616b...`.
- 0.8 WBNB is sent from `0x616b...` to external EOA `0x8432...`.
- 19.2 WBNB ends up at attacker-controlled contract `0xe82f...`, confirmed by `WBNB.balanceOf(0xe82f...) = 19.2 WBNB` at the end of the exploit transaction.

Thus, in WBNB terms:

- Value gained by the attacker cluster: at least 19.2 WBNB.
- Fees paid in reference asset: 0.1247948 WBNB-equivalent.
- Net value delta: `>= 19.0752052` WBNB.

This satisfies the ACT success predicate: a permissionless, reproducible strategy that yields positive profit in a reference asset (WBNB) using only standard EOA transactions and publicly available contract code and traces.

## 5. Adversary Flow Analysis

### 5.1 Adversary Cluster and Roles

The incident centers on the following addresses:

- **Attacker EOA:** `0x3fee6d8aaea76d06cf1ebeaf6b186af215f14088`  
  Sends all four attacker-crafted transactions (deployment, configuration, exploit, withdrawal) and pays all gas costs.

- **Attacker helper contract:** `0xe82fc275b0e3573115eadca465f85c4f96a6c631`  
  Deployed by the attacker EOA and used as the entry contract for the exploit. It exposes a function with selector `0x57964aaf` to configure the token-holder proxy and a function with selector `0xe4c61b84` that drives the BorrowerOperationsV6::sell / TokenHolder::privilegedLoan call path. It later holds 19.2 WBNB before the attacker calls `withdrawERC20(WBNB)` to pull the funds back to the EOA.

- **Collateral-holder proxy (victim):** `0x2eed3dc9c5134c056825b12388ee9be04e522173`  
  Delegates to BorrowerOperationsV6 and holds collateral in WBNB; loses 20 WBNB during the exploit.

- **Token-holder proxy (victim-side component):** `0x616b36265759517af14300ba1dd20762241a3828`  
  Delegates to the TokenHolder implementation and executes `privilegedLoan` and subsequent WBNB transfers.

- **External EOA recipient (non-adversary):** `0x8432cd30c4d72ee793399e274c482223dca2bf9e`  
  Receives 0.8 WBNB during the exploit. Its tx history shows long-term activity and governance-style interactions with protocol contracts, but no transactions to or from the attacker EOA or helper contract across the collected history; it is treated as an external, non-adversary recipient.

### 5.2 Stage-by-Stage Flow

The `act_opportunity.transaction_sequence_b` and detailed traces correspond to the following stages:

1. **Helper contract deployment (tx 0xba4732...)**  
   - The attacker EOA sends a 0-value contract-creation transaction with gasPrice 100 gwei.
   - The payload deploys `0xe82f...`, which includes logic to configure the token-holder proxy and to forward structured calls into BorrowerOperationsV6::sell.

2. **Configuration of helper contract (tx 0x6598c2...)**  
   - The attacker calls selector `0x57964aaf` on `0xe82f...` with the token-holder proxy address `0x616b...`.
   - This sets internal state in `0xe82f...` so that later exploit calls route to the correct TokenHolder proxy and collateral-holder.

3. **PrivilegedLoan-based WBNB drain (tx 0xc291d7...)**  
   - The attacker calls selector `0xe4c61b84` on `0xe82f...`, passing parameters that include:
     - Collateral-holder proxy `0x2eed...`.
     - WBNB token `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`.
     - A 20 WBNB amount.
   - The helper contract routes the call to `BorrowerOperationsV6::sell` on `0x2eed...`. Internally:
     - `BorrowerOperationsV6::sell` reads `loans(0)` for the caller, finds an inactive loan struct, but still calls token-holder proxy `0x616b...` to execute `TokenHolder::privilegedLoan(WBNB, 20 WBNB)`.
     - TokenHolder::privilegedLoan reads `WBNB.balanceOf(0x2eed...) ≈ 20.0286 WBNB` and transfers exactly 20 WBNB from `0x2eed...` to `0x616b...`.
     - From `0x616b...`, 0.8 WBNB is transferred to `0x8432...`, and 19.2 WBNB is transferred in two steps to `0xe82f...`, which ends the transaction with a WBNB balance of 19.2 WBNB.
     - No WBNB is transferred back to `0x2eed...`; the collateral-holder’s WBNB balance decreases by 20 WBNB and remains so after the transaction.

4. **WBNB withdrawal to adversary EOA (tx 0xa9f735...)**  
   - The attacker calls `withdrawERC20(WBNB)` on `0xe82f...`.
   - This causes the 19.2 WBNB held by the helper contract to be transferred under direct control of the attacker EOA, completing the profit realization.

Throughout this sequence, the attacker relies solely on public contract interfaces and standard EOA transactions, making this an anyone-can-take (ACT) opportunity.

## 6. Impact & Losses

The incident results in a net collateral loss and adversary profit quantified as follows:

- **Total WBNB drained from collateral-holder:** 20 WBNB  
  - Source: Collateral-holder proxy `0x2eed3dc9c5134c056825b12388ee9be04e522173`.
  - Destination: Token-holder proxy `0x616b36265759517af14300ba1dd20762241a3828`, then redistributed.

- **Distribution of drained WBNB:**
  - 0.8 WBNB to external EOA `0x8432cd30c4d72ee793399e274c482223dca2bf9e`.
  - 19.2 WBNB to attacker-controlled contract `0xe82fc275b0e3573115eadca465f85c4f96a6c631`, later withdrawn to the attacker EOA via `withdrawERC20(WBNB)` in tx `0xa9f735...`.

- **Adversary profit in reference asset (WBNB):**
  - Gross gain: at least 19.2 WBNB controlled by the attacker’s contract.
  - Gas fees across the four attacker-crafted transactions: `0.1247948` BNB (equivalently 0.1247948 WBNB).
  - Net profit: `>= 19.0752052` WBNB.

From the protocol’s perspective, collateral-holder `0x2eed...` permanently loses 20 WBNB of collateral, with no matching adjustment in protocol accounting for loans(0) and no compensation for the victim.

## 7. References

Key supporting artifacts used in this analysis:

1. **Seed tx metadata for exploit transaction**  
   - Tx: `0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6`  
   - File: `artifacts/root_cause/seed/56/0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6/metadata.json`

2. **Call tracer and cast trace for exploit transaction**  
   - Files:  
     - `artifacts/root_cause/data_collector/iter_2/tx/56/0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6/trace.call_tracer.json`  
     - `artifacts/root_cause/seed/56/0xc291d70f281dbb6976820fbc4dbb3cfcf56be7bf360f2e823f339af4161f64c6/trace.cast.log`

3. **WBNB token contract source**  
   - Contract: `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`  
   - File: `artifacts/root_cause/seed/56/0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c/src/Contract.sol`

4. **Tx history for adversary helper contract `0xe82f...`**  
   - File: `artifacts/root_cause/data_collector/iter_3/address/56/0xe82fc275b0e3573115eadca465f85c4f96a6c631/txlist_normal.json`

5. **Tx history for external WBNB recipient EOA `0x8432...`**  
   - File: `artifacts/root_cause/data_collector/iter_3/address/56/0x8432cd30c4d72ee793399e274c482223dca2bf9e/txlist_normal.json`

These artifacts, together with the collected BorrowerOperationsV6 and TokenHolder sources and the analyzer’s balance diffs and prestate traces, fully substantiate the root cause and adversary flow described above.

