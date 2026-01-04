# Incident Overview TL;DR

This report covers a SmartLoans WETH Pool interaction on Arbitrum in which SmartLoan borrower `0xf81b4381b70EF520Ae635AFD4B0E8aeb994131fb`, owned in the BorrowersRegistry by router `0x0B2Bcf06F740C322BC7276b6b90dE08812cE9bfE`, executes a Balancer-assisted transaction that borrows `66.619545304650988218` aeWETH from `WethPoolTUP` at `0x2E2fE9Bc7904649b65B6373bAF40F9e2E0b883c5` and routes the tokens to downstream router `0x52EE5c0eA2E7b38D4B24c09D4D18cba6C293200E` while fully repaying the Balancer flash loan within the same transaction (Arbitrum tx `0x6a2f989b5493b52ffc078d0a59a3bf9727d134b403aa6e0bf309fd513a728f7f`).  
From an ACT (anyone-can-take) perspective, this behaviour is not an exploit: the borrower is a registered SmartLoan in the BorrowersRegistry, the pool’s utilisation and registry checks succeed, and the available on-chain evidence does not exhibit a deterministic, unprivileged strategy that realizes adversary profit or protocol-level harm.

# Key Background

The WethPool is a pooled-lending contract whose `borrow(uint256 _amount)` function uses a borrowers registry and a utilisation cap to constrain borrowing. Borrowing is permitted only for accounts that pass `borrowersRegistry.canBorrow(msg.sender)` and only while pool utilisation remains at or below `92.5%`, enforced as:

- `borrowersRegistry.canBorrow(msg.sender)` must return `true`, which ties borrowing rights to a registry of approved SmartLoan contracts.
- Post-borrow utilisation must satisfy `totalBorrowed * 1e18 / totalSupply <= 0.925e18`; otherwise, the transaction reverts with `MaxPoolUtilisationBreached`.

The BorrowersRegistry is implemented by a SmartLoansFactory contract (behind a proxy) that maintains two core mappings:

- `ownersToLoans`: owner EOA → SmartLoan (loan) address.  
- `loansToOwners`: SmartLoan (loan) address → owner EOA.

The registry acts as a BorrowersRegistry for pools via `IBorrowersRegistry.canBorrow(address _account)`, which returns `true` exactly when `loansToOwners[_account] != address(0)`. As a result, only SmartLoan contracts that appear as keys in `loansToOwners` are authorized to borrow.

At the incident block, the registry view shows that SmartLoan `0xf81b4381b70EF520Ae635AFD4B0E8aeb994131fb` is a registered borrower, and its recorded owner is router `0x0B2Bcf06F740C322BC7276b6b90dE08812cE9bfE`. Calls made via this router on behalf of the SmartLoan are therefore treated as coming from an authorized borrower by WethPool.

# Vulnerability Analysis

The verified `Pool.sol` implementation for the WethPool enforces three key conditions around borrowing:

```solidity
function borrow(uint256 _amount) public virtual canBorrow nonReentrant {
    if (_amount > IERC20(tokenAddress).balanceOf(address(this))) revert InsufficientPoolFunds();

    _accumulateBorrowingInterest(msg.sender);

    borrowed[msg.sender] += _amount;
    borrowed[address(this)] += _amount;

    _transferFromPool(msg.sender, _amount);

    _updateRates();

    emit Borrowing(msg.sender, _amount, block.timestamp);
}

modifier canBorrow() {
    if(address(borrowersRegistry) == address(0)) revert BorrowersRegistryNotConfigured();
    if(!borrowersRegistry.canBorrow(msg.sender)) revert NotAuthorizedToBorrow();
    if(totalSupply() == 0) revert InsufficientPoolFunds();
    _;
    if((totalBorrowed() * 1e18) / totalSupply() > getMaxPoolUtilisationForBorrowing()) revert MaxPoolUtilisationBreached();
}

function getMaxPoolUtilisationForBorrowing() public view returns (uint256) {
    return 0.925e18;
}
```

These semantics ensure that:

- Only accounts recognized by the BorrowersRegistry as loans can borrow.  
- The pool must hold sufficient aeWETH for the requested borrow amount.  
- The pool cannot exceed a 92.5% utilisation ratio after the borrow.

The SmartLoansFactory, acting as the BorrowersRegistry, implements `canBorrow` based on registry mappings:

```json
{
  "core_contract": "SmartLoansFactory",
  "acts_as_borrowers_registry": true,
  "key_semantics": {
    "mappings": {
      "ownersToLoans": "owner EOA -> SmartLoan (loan) address",
      "loansToOwners": "SmartLoan (loan) address -> owner EOA"
    },
    "canBorrow_logic": {
      "description": "IBorrowersRegistry.canBorrow(address _account) returns true iff loansToOwners[_account] != address(0).",
      "implication": "Any address with a loan registered as key in loansToOwners is authorized to borrow in pools that reference this registry."
    }
  }
}
```

Given these mechanics, the seed transaction’s borrow succeeds because the SmartLoan address is explicitly registered in `loansToOwners`, and the utilisation ratio after borrowing remains below the configured `92.5%` cap. No victim contract, address, or function is demonstrated to be vulnerable under the ACT definition based on the reviewed pool, registry, and router semantics.

From an ACT perspective:

- No attacker-crafted multi-transaction sequence `b` is identified that begins from a canonical pre-state and deterministically produces adversary profit or protocol-level harm.  
- No profit or non-monetary exploit predicate is established; the on-chain evidence does not show a net positive P/L for an unprivileged adversary cluster in a fixed reference asset, nor a breached protocol safety invariant.  
- No missing access control, broken invariant, or misconfigured parameter is shown that an arbitrary unprivileged adversary could reproduce to their advantage.

Accordingly, no ACT-style vulnerability is identified in the WethPool or BorrowersRegistry based on the available evidence.

# Detailed Root Cause Analysis

The core on-chain behaviour in the analyzed transaction is a standard SmartLoans borrow sequence rather than an exploit.

The trace for Arbitrum tx `0x6a2f989b5493b52ffc078d0a59a3bf9727d134b403aa6e0bf309fd513a728f7f` shows:

```text
Seed transaction trace (cast run -vvvvv)
...
│   │   │   │   │   │   ├─ [279950] WethPoolTUP::fallback(66619545304650988218 [6.661e19])
│   │   │   │   │   │   │   ├─ [272748] WethPool::borrow(66619545304650988218 [6.661e19]) [delegatecall]
│   │   │   │   │   │   │   ├─ [9896] SmartLoansFactoryTUP::fallback(0xf81b4381b70EF520Ae635AFD4B0E8aeb994131fb) [staticcall]
│   │   │   │   │   │   │   │   ├─ [2598] SmartLoansFactory::canBorrow(0xf81b4381b70EF520Ae635AFD4B0E8aeb994131fb) [delegatecall]
│   │   │   │   │   │   │   │   │   └─ ← [Return] true
...
│   │   │   │   │   │   ├─ emit Borrowing(user: 0xf81b4381b70EF520Ae635AFD4B0E8aeb994131fb, value: 66619545304650988218 [6.661e19], timestamp: 1731310565 [1.731e9])
...
```

This trace demonstrates that:

- Router `0x0B2Bcf06F740C322BC7276b6b90dE08812cE9bfE` invokes the WethPool through a proxy.  
- WethPool’s `borrow` function delegates to SmartLoansFactory via the BorrowersRegistry proxy to evaluate `canBorrow` on SmartLoan `0xf81b...`.  
- `SmartLoansFactory.canBorrow(0xf81b...)` returns `true`, confirming that the SmartLoan is a registered borrower.  
- The WethPool emits a `Borrowing` event for borrower `0xf81b...` and value `66.619545304650988218` aeWETH.

The accompanying balance diff for the same transaction shows the token movement:

```json
{
  "erc20_balance_deltas": [
    {
      "token": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
      "holder": "0x2e2fe9bc7904649b65b6373baf40f9e2e0b883c5",
      "before": "99587041744590818507",
      "after": "32967496439939830289",
      "delta": "-66619545304650988218",
      "contract_name": "aeWETH"
    },
    {
      "token": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
      "holder": "0x52ee5c0ea2e7b38d4b24c09d4d18cba6c293200e",
      "before": "0",
      "after": "66619545304650988218",
      "delta": "66619545304650988218",
      "contract_name": "aeWETH"
    }
  ]
}
```

This confirms that:

- `WethPoolTUP` at `0x2E2fE9Bc7904649b65B6373bAF40F9e2E0b883c5` sends exactly `66.619545304650988218` aeWETH out of the pool.  
- Router `0x52EE5c0eA2E7b38D4B24c09D4D18cba6C293200E` receives the same amount.  
- Total aeWETH supply is conserved; there is no mint, burn, or unexplained loss at the token level.

Combined with the registry semantics, these traces and diffs show a single SmartLoans borrower invoking `WethPool.borrow` in a manner consistent with configured access control and utilisation limits. The Balancer flash loan is repaid within the same transaction, and no protocol invariant breach or ACT-style exploit path is demonstrated.

# Adversary Flow Analysis

The adversary-related flow can be summarized as follows:

- An unprivileged EOA initiates a transaction that calls a router controlling a SmartLoan.  
- The router orchestrates a Balancer flash loan of aeWETH, uses the SmartLoan to borrow additional aeWETH from WethPool, and routes the borrowed aeWETH to a downstream router.  
- The Balancer flash-loan principal is repaid within the same transaction, and downstream contracts handle swaps and settlements of the moved aeWETH.

The analysis identifies an adversary-related cluster with the following roles:

- `0xb87881637b5c8e6885c51ab7d895e53fa7d7c567` (EOA, Arbitrum): sender of the seed transaction that initiates the Balancer flash loan and SmartLoans borrow.  
- `0x0B2Bcf06F740C322BC7276b6b90dE08812cE9bfE` (contract, Arbitrum): router contract that owns SmartLoan `0xf81b...` in the BorrowersRegistry and orchestrates the borrow and routing of aeWETH.  
- `0xf81b4381b70EF520Ae635AFD4B0E8aeb994131fb` (contract, Arbitrum): SmartLoans borrower contract registered in the BorrowersRegistry and authorized to borrow from WethPool.  
- `0x52EE5c0eA2E7b38D4B24c09D4D18cba6C293200E` (contract, Arbitrum): downstream router that receives the `66.619545304650988218` aeWETH transferred out of WethPoolTUP in the seed transaction.  
- `0x56e7f67211683857ee31a1220827cac5cdaa634c` (EOA, Arbitrum): address that receives tokens from `0x52EE...` in the same block range and interacts with DEXes and bridges to move or swap these assets.

The primary lifecycle stage relevant to the ACT assessment is:

- **Borrow execution and aeWETH routing**  
  - **Transaction**: Arbitrum `0x6a2f989b5493b52ffc078d0a59a3bf9727d134b403aa6e0bf309fd513a728f7f`, block `273278742`.  
  - **Mechanism**: `flashloan + borrow + transfer`.  
  - **Effect**:  
    - EOA `0xb8788163...` calls router `0x0B2B...`, which takes a Balancer flash loan of aeWETH.  
    - Router `0x0B2B...` triggers SmartLoan `0xf81b...` to call `WethPool.borrow` and borrow `66.619545304650988218` aeWETH from `WethPoolTUP`.  
    - The borrowed aeWETH is transferred from `WethPoolTUP` to router `0x52EE...`.  
    - The Balancer flash-loan principal is repaid within the same transaction.  

This flow relies on standard SmartLoans and WethPool semantics, with no demonstrated deviation that would constitute an ACT exploit path.

The victim-candidate identified for context is:

- **SmartLoans WethPoolTUP**  
  - Chain: Arbitrum (`42161`)  
  - Address: `0x2E2fE9Bc7904649b65B6373bAF40F9e2E0b883c5`  
  - Verified: `true`

# Impact & Losses

Within the analyzed on-chain evidence, there is no demonstrated protocol or user loss attributable to an ACT opportunity. The transaction increases SmartLoan borrower debt and moves aeWETH into the adversary-related cluster, but:

- There is no observed protocol insolvency event.  
- There is no liquidation cascade or systemic liquidity shortfall tied to the borrow.  
- There are no stuck funds or unaccounted token movements linked to a protocol vulnerability.  

No quantitative loss figure is therefore reported as ACT-driven loss.

# References

- [1] Seed transaction metadata, trace, and balance diffs for Arbitrum tx `0x6a2f989b5493b52ffc078d0a59a3bf9727d134b403aa6e0bf309fd513a728f7f` (metadata, `trace.cast.log`, and `balance_diff.json`).  
- [2] WethPool `Pool.sol` source for contract `0x0b4c71fc70b6b65c04fd62b10191ee7999761a5a`, including `borrow`, `canBorrow`, utilisation enforcement, and interest index logic.  
- [3] SmartLoansFactory / BorrowersRegistry semantics and decoded borrower registry view, including `ownersToLoans`, `loansToOwners`, and `canBorrow` logic for Arbitrum implementation address `0x8b5c0352dd98be579285da94e51ea9dc749eb22d`.

