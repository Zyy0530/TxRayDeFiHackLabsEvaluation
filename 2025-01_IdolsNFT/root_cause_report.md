## IdolMain stETH Reward Drain via Self-Transfer Accounting Bug

**Protocol:** Idol / VIRTUE stETH Rewards  
**Category:** protocol_bug  
**Chain:** Ethereum mainnet  
**ACT Opportunity:** Yes (reproducible pattern if unpatched)

---

## Incident Overview & TL;DR

On Ethereum mainnet, an adversary-controlled helper contract `0x22d22134612C0741EBDb3B74a58842D6E74E3b16` deployed by EOA `0xe546480138d50bb841b204691c39cc514858d101` repeatedly called `IdolMain.safeTransferFrom` with `from = to = 0x22d2...` for Idol NFT tokenId `940` within a single transaction. This abused IdolMain’s stETH reward accounting to drain `12.950523927926154327` stETH from the protocol’s reward pool into the adversary cluster and then forward it to EOA `0x8152970a81f558d171a22390E298B34Be8d40CF4`. The exploit was surrounded by funding and post-exploit swap transactions executed by `0x8152...`, which transferred ETH to `0xe546...` and later traded stETH/ETH via aggregator and Curve-style routes.

Root cause: a logic bug in `IdolMain._beforeTokenTransfer` and `_claimEthRewards` treats self-transfers (`from == to`) of an Idol NFT as though the sender will have zero balance. It deletes `claimedSnapshots[_from]` based on the pre-transfer balance and then calls `_claimEthRewards` again for `_to` while `balanceOf(_to) > 0`. This allows any holder (or contract) that can call `safeTransferFrom(from, from, tokenId)` to repeatedly reset its snapshot and reclaim the full stETH reward allocation multiple times, draining the shared stETH pool.

---

## Key Background

### IdolMain reward design

- `IdolMain` (`0x439cac149B935AE1D726569800972E1669d17094`) is an `ERC721Enumerable`-based contract that tracks “gods” (Idol NFTs) and distributes stETH-denominated rewards to NFT holders.
- It maintains:
  - `stethPrincipalBalance`: the intended principal stETH balance.
  - `allocatedStethRewards`: stETH allocated to Idol holders via `rewardPerGod`.
  - `rewardPerGod`: cumulative stETH-per-Idol rewards.
  - `claimedSnapshots[address]`: the last `rewardPerGod` level settled for each holder.
- Rewards are computed as:

```solidity
function getPendingStethReward(address _user)
  public
  view
  returns (uint256)
{
  return (balanceOf(_user) * (rewardPerGod - claimedSnapshots[_user]));
}
```

*Snippet 1 – IdolMain pending reward calculation (from verified IdolMain.sol).*

- `_claimEthRewards(_user)` transfers any pending rewards, subtracts from `allocatedStethRewards`, and sets `claimedSnapshots[_user] = rewardPerGod`.
- `updateRewardPerGod` compares the contract’s stETH balance to `stethPrincipalBalance + allocatedStethRewards` and, when there is surplus stETH, increases `rewardPerGod` and `allocatedStethRewards`.

### stETH as reward asset

- IdolMain uses Lido’s stETH token (`0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84`) as the rewards asset.
- IdolMain holds stETH and periodically calls `updateRewardPerGod` to distribute surplus stETH to Idol holders via `rewardPerGod`.

### Transfer hook and contract access

- IdolMain overrides ERC721’s `_beforeTokenTransfer` hook to settle rewards for both sender and recipient on each transfer and to reset snapshots for addresses that drop to zero NFTs.
- The key hook is:

```solidity
function _beforeTokenTransfer(
  address _from,
  address _to,
  uint256 _tokenId
)
  internal
  virtual
  override
  onlyAllowedContracts(_to)
{
  super._beforeTokenTransfer(_from, _to, _tokenId);
  if(_from != address(0x0)){
    if (lockedGods[_tokenId]) {
      require(deployTime + 365 days < block.timestamp,'Token can only be transferred when lock has expired');
    }
    _claimEthRewards(_from);

    if(balanceOf(_from) == 1){
      delete claimedSnapshots[_from];
    }
  }

  if(balanceOf(_to) > 0){
    _claimEthRewards(_to);
  } else {
    claimedSnapshots[_to] = rewardPerGod;
  }
}
```

*Snippet 2 – IdolMain `_beforeTokenTransfer` reward hook (from verified IdolMain.sol).*

- `safeTransferFrom` is overridden but ultimately calls `_safeTransfer`, which triggers this hook before token balances are updated.
- `allowAllContracts` is `true` by default and, when true, contract addresses may call transfer functions unless explicitly blacklisted. This allows arbitrary helper contracts to call `safeTransferFrom`.

---

## Vulnerability & Root Cause Analysis

### Vulnerability summary

IdolMain mis-handles self-transfers of Idol NFTs. During `safeTransferFrom(from, from, tokenId)` the `_beforeTokenTransfer` hook:

1. Calls `_claimEthRewards(_from)` and, if `balanceOf(_from) == 1`, deletes `claimedSnapshots[_from]`.
2. Then, for `_to` (same address), sees `balanceOf(_to) > 0` in the pre-transfer state and calls `_claimEthRewards(_to)` again.

Because the hook runs before ERC721 updates balances and because the deletion check uses the pre-transfer balance, an address that holds exactly one Idol and self-transfers it will:

- Claim its pending rewards once, then
- Reset its snapshot to zero via `delete claimedSnapshots[_from]`, then
- Claim again as if it had never claimed, based on the full `rewardPerGod` value.

Repeated self-transfers allow the same holder (including contracts) to double-claim on each transfer and drain the protocol’s shared stETH reward pool.

### Detailed root cause mechanics

Before the exploit:

- `rewardPerGod` reflects accumulated stETH rewards.
- For a holder `H` with one Idol, `claimedSnapshots[H] = S` and `rewardPerGod > S`.
- `getPendingStethReward(H) = rewardPerGod - S` (since `balanceOf(H) = 1`).

During a self-transfer `safeTransferFrom(H, H, tokenId)`:

1. `_beforeTokenTransfer` is called once with `_from = _to = H` before balances change.
2. `_claimEthRewards(_from)` pays:
   - `currentRewards1 = balanceOf(H) * (rewardPerGod - claimedSnapshots[H])`
   - Sets `claimedSnapshots[H] = rewardPerGod`.
3. Because `balanceOf(_from) == 1` in the pre-transfer state, it executes `delete claimedSnapshots[_from]`, resetting the snapshot for `H` to 0.
4. For `_to = H`, `balanceOf(_to) > 0` still holds (pre-transfer), so `_claimEthRewards(_to)` runs again, now with `claimedSnapshots[H] == 0`, paying:
   - `currentRewards2 = balanceOf(H) * (rewardPerGod - 0)`.

This double-claim pattern allows the account to withdraw more than its fair share of rewards. Each self-transfer:

- Decreases `allocatedStethRewards` twice.
- Transfers stETH from IdolMain to the attacker-controlled address twice.
- Does not correctly keep `claimedSnapshots` in sync with the reward pool’s intended invariant.

The key design assumptions violated are:

- `claimedSnapshots[_user]` should represent the last `rewardPerGod` used when paying `_user`, and should not be reset while the user still owns an Idol.
- The per-transfer hook must not double-settle rewards for the same address within a single transfer.
- Self-transfers (`from == to`) must not be treated as exits followed by re-joins in a way that allows reward re-claiming.

### On-chain evidence of the bug in action

In the seed exploit transaction `0x5e989304b1fb61ea0652db4d0f9476b8882f27191c1f1d2841f8977cb8c5284c` (block `21624240`):

- EOA `0xe546...` creates helper contract `0x22d2...`.
- Constructor arguments include:
  - stETH `0xae7a...` (Lido).
  - IdolMain `0x439c...`.
  - EOA `0x8152...` as the ultimate beneficiary.
- Immediately after deployment, `0x22d2...` repeatedly calls:

```json
{
  "from": "0x22d22134612c0741ebdb3b74a58842d6e74e3b16",
  "to": "0x439cac149b935ae1d726569800972e1669d17094",
  "input": "0x42842e0e00000000000000000000000022d22134612c0741ebdb3b74a58842d6e74e3b1600000000000000000000000022d22134612c0741ebdb3b74a58842d6e74e3b1600000000000000000000000000000000000000000000000000000000000003ac"
}
```

*Snippet 3 – callTracer excerpt: `0x22d2...` calls `safeTransferFrom(0x22d2..., 0x22d2..., 940)` on IdolMain in the seed exploit tx.*

Each such call triggers the `_beforeTokenTransfer` logic above. The trace shows, per iteration:

```json
{
  "from": "0x439cac149b935ae1d726569800972e1669d17094",
  "to": "0xae7ab96520de3a18e5e111b5eaab095312d7fe84",
  "input": "0xa9059cbb...00000000000000000000000022d22134612c0741ebdb3b74a58842d6e74e3b16...000000000000000000000000000000000000000000000000006e55a476f8c6ff",
  "type": "CALL"
}
```

*Snippet 4 – callTracer excerpt: Lido `transfer` delegatecall moving stETH from IdolMain to `0x22d2...` per self-transfer loop.*

The seed `trace.cast.log` confirms that:

- Each iteration invokes Lido’s `transfer` (via proxy `0x1714...17eb`) from IdolMain to `0x22d2...`, emitting standard ERC20 `Transfer` and Lido `TransferShares` events.
- After many iterations, `Lido::balanceOf(0x22d2...)` returns `12950523927926154327` stETH units.
- A final `Lido::transfer(0x8152..., 12950523927926154327)` moves all accumulated stETH from `0x22d2...` to `0x8152...`.

```text
Lido::balanceOf(0x22d2...) -> 12950523927926154327
Lido::transfer(0x8152..., 12950523927926154327)
  emit Transfer(from: 0x22d2..., to: 0x8152..., value: 12950523927926154327)
```

*Snippet 5 – seed `trace.cast.log` excerpt showing final stETH balance and transfer from helper contract to `0x8152...`.*

This behaviour is consistent with repeated double-claiming of stETH rewards via the self-transfer bug and draining the stETH pool held by IdolMain.

### Exploit conditions

The exploit requires:

1. Control of an Idol NFT (here tokenId `940`) through an address or contract that can call `safeTransferFrom(from, from, tokenId)`.
2. IdolMain holding a positive amount of stETH with `rewardPerGod > 0` such that `getPendingStethReward(user)` is non-zero.
3. `allowAllContracts` being `true` (default) or attacker contracts being whitelisted so contract addresses can trigger `safeTransferFrom` and `_beforeTokenTransfer`.
4. No patch that blocks self-transfers or special-cases `from == to` in `_beforeTokenTransfer` to avoid deleting `claimedSnapshots[_from]` while the user still owns an Idol.

Security principles violated:

- **Conservation of reward pool:** `allocatedStethRewards + stethPrincipalBalance` should match the stETH available to cover rewards, but double-claims break this invariant.
- **Correctness of per-holder accounting:** `claimedSnapshots[_user]` should monotonically track settlement; deleting it on a pre-transfer `balanceOf(_from) == 1` when `from == to` violates this.
- **Safe ERC721 hook usage:** `_beforeTokenTransfer` fails to account for self-transfers and allows the hook to double-apply settlement for the same address in one transfer.

---

## Adversary Flow Analysis

### Adversary-related accounts

**Adversary cluster:**

- `0xe546480138d50bb841b204691c39cc514858d101` – exploit deployer EOA.
  - Sends the core contract-creation tx `0x5e98...5284c` that deploys `0x22d2...`.
  - Receives ETH funding from `0x8152...` immediately beforehand.
- `0x22d22134612C0741EBDb3B74a58842D6E74E3b16` – helper contract.
  - Created in tx `0x5e98...5284c`.
  - Repeatedly calls `IdolMain.safeTransferFrom(0x22d2..., 0x22d2..., 940)` and receives stETH via Lido delegatecalls.
  - Ultimately transfers `12950523927926154327` stETH to `0x8152...`.
- `0x8152970a81f558d171a22390E298B34Be8d40CF4` – funding and profit-taking EOA.
  - Pre-positions stETH/ETH via aggregator `0x3fc9...` in tx `0xdc74...`.
  - Sends multiple 2 ETH transfers (txs `0xc468...`, `0x178e...`) to fund `0xe546...`.
  - Receives `12950523927926154327` stETH from `0x22d2...` in the exploit tx.
  - Later trades stETH/ETH via router `0x4531...` in tx `0xcc49...`, realising profit.

**Victim contracts:**

- Idol stETH rewards treasury: `IdolMain` at `0x439cac149B935AE1D726569800972E1669d17094` (verified source).
- Lido stETH token: `0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84` (verified source).

### Lifecycle stages

#### 1. Funding and pre-positioning

- **Transactions:**
  - `0x56e14baf3336367cde96e1b54d99f384fd4a76b90912e8e09a5bafbf1309b2b6` – ETH inflow to `0x8152...`.
  - `0xdc74e81df45fb4e9fc510713540b5fffa9b3fd213309bc9074612cf9bc87829f` – aggregator `execute(...)` from `0x8152...`.
  - `0xc468bf728153dfffa724ea81adfc8f657e0423c41eaab38bbdc3d0fda1d7dd9b` – 2 ETH transfer from `0x8152...` to `0xe546...`.
  - `0x178e1973701d69283d18e23edd5715120eca5c8a77f6981b331e7e77ea3f4be4` – another 2 ETH transfer from `0x8152...` to `0xe546...`.

- **Effect:**  
  `0x8152...` receives ETH, trades stETH via an aggregator to adjust its position, and sends multiple 2 ETH funding transfers to `0xe546...`, ensuring the exploit-deployer has enough ETH for the high-gas contract creation in block `21624240`. `0x8152...` retains stETH and ETH balances for later profit-taking.

Relevant evidence:

```json
[
  {
    "hash": "0xc468bf728153dfffa724ea81adfc8f657e0423c41eaab38bbdc3d0fda1d7dd9b",
    "from": "0x8152970a81f558d171a22390e298b34be8d40cf4",
    "to": "0xe546480138d50bb841b204691c39cc514858d101",
    "value": "2000000000000000000"
  }
]
```

*Snippet 6 – Etherscan-style txlist excerpt showing 2 ETH funding from `0x8152...` to `0xe546...` (from collected address txlist).*

#### 2. Exploit contract deployment and stETH drain

- **Transaction:** `0x5e989304b1fb61ea0652db4d0f9476b8882f27191c1f1d2841f8977cb8c5284c` (block `21624240`).
  - From `0xe546...`, `to` empty (contract creation).
  - Deploys helper contract `0x22d2...` with constructor parameters:
    - stETH `0xae7a...`.
    - IdolMain `0x439c...`.
    - Beneficiary `0x8152...`.
    - TokenId `940`.
  - Within the same transaction:
    - `0x22d2...` repeatedly invokes `safeTransferFrom(0x22d2..., 0x22d2..., 940)` on IdolMain.
    - Each invocation triggers `_beforeTokenTransfer`, double-claims rewards, and in turn calls Lido’s `transfer` to move stETH from IdolMain to `0x22d2...`.
    - After many loops, `Lido::balanceOf(0x22d2...)` returns `12950523927926154327` stETH units.
    - A final `Lido::transfer(0x8152..., 12950523927926154327)` forwards all stETH to `0x8152...`.
    - `safeTransferFrom(0x22d2..., 0xe546..., 940)` returns Idol NFT 940 to `0xe546...`.

Relevant creation call:

```json
{
  "to": "0x22d22134612c0741ebdb3b74a58842d6e74e3b16",
  "type": "CREATE",
  "input": "0x60806040...ae7a...439c...8152...000003ac..."
}
```

*Snippet 7 – callTracer excerpt showing helper contract creation with stETH, IdolMain, and 0x8152 parameters (from seed callTracer trace).*

#### 3. Post-exploit consolidation and off-ramp

- **Transaction:** `0xcc49a82ec89808a4ebe9556f780e065a242cc629e56c5141e538e9799cd46f95` (block `21626007`).
  - From `0x8152...` to router `0x45312ea0eff7e09c83cbe249fa1d7598c4c8cd4e`.
  - Sends 5 ETH and calls `exchange(address[11], uint256[5][5], uint256, uint256, address[5])` with a route involving:
    - stETH `0xae7a...`.
    - Curve pool `0xdc24316b9ae028f1497c275eb9192a3ea0f67022`.
    - ETH.
  - Traces show:
    - stETH transferred from pool `0xdc24...` to router `0x4531...`.
    - ETH minted/withdrawn to `0x8152...`.

```json
{
  "from": "0x45312ea0eff7e09c83cbe249fa1d7598c4c8cd4e",
  "to": "0xae7ab96520de3a18e5e111b5eaab095312d7fe84",
  "input": "0xa9059cbb...00000000000000000000000045312ea0...000000000000000000000000000000000000000000000000457119618d735d37"
}
```

*Snippet 8 – callTracer excerpt showing stETH transfer in the post-exploit Curve/aggregator swap route (from iter_2 callTracer for tx 0xcc49...).*

This converts part of the adversary’s stETH position (including the 12.95 stETH drained from IdolMain) into ETH, realising profit in the reference asset.

### Repeatability and follow-on attempts

The IdolMain txlist around the incident window shows later `safeTransferFrom` calls from `0xe546...` to itself using tokenId 940 (e.g., txs `0x5cc6...`, `0xc44b...`, `0xb81b...`, `0x2b6d...`). Some succeed and some fail, indicating repeated attempts to exercise the same self-transfer pattern post-incident. This supports the conclusion that the pattern is repeatable and constitutes an ongoing ACT exposure while the bug remains unpatched.

---

## Impact & Losses

### Quantitative impact

- **Token:** stETH (`0xae7a...`).
- **Amount drained:** `12.950523927926154327` stETH (on-chain units: `12950523927926154327`).

Within the seed exploit tx `0x5e98...5284c`:

- Lido stETH transfers move a total of `12950523927926154327` units of stETH:
  - From IdolMain `0x439c...` to helper `0x22d2...` across many loops.
  - Then from `0x22d2...` to EOA `0x8152...` in a single final `transfer`.
- Idol NFT tokenId 940 ends the exploit transaction owned by `0xe546...`, so the Idol holder remains in place while IdolMain’s stETH reward pool is reduced.

Subsequent self-`safeTransferFrom` transactions from `0xe546...` to itself (e.g., `0xec82...`, `0x3d66...`, `0x5a06...`, `0x5cc6...`, `0xc44b...`, `0xb81b...`, `0x2b6d...`) confirm the self-transfer pattern is reusable and can continue to drain rewards if the contract is not patched.

### Profit predicate

- **Reference asset:** ETH.
- **Adversary address:** `0x8152...`.
- **Value gained (lower bound):** at least `12.950523927926154327` ETH-equivalent via the 12.95 stETH transfer.
- **Fees, pre/post balances, and net P&L:** 
  - `fees_paid_in_reference_asset`: unknown (gas is observable but not converted to ETH P&L here).
  - `value_before_in_reference_asset`: unknown (full historical balance diffs not computed).
  - `value_after_in_reference_asset`: unknown.
  - The analysis intentionally records these as unknown because deriving exact fee-adjusted ETH P&L across txs `0xdc74...`, `0x5e98...`, and `0xcc49...` would require additional ERC20 balance diffs and off-chain price data.

Nevertheless, the direct stETH inflow of 12.95 stETH from IdolMain’s treasury to the adversary cluster is clearly evidenced in traces and provides a conservative lower bound on adversary profit.

---

## ACT Opportunity and Pre-State

### Pre-state at block 21624240 (σ_B)

Immediately before block `21624240`:

- IdolMain `0x439c...` held stETH balances representing principal (`stethPrincipalBalance`) and accumulated rewards (`allocatedStethRewards`) for Idol NFT holders.
- `rewardPerGod` and `allocatedStethRewards` had been configured by previous `updateRewardPerGod` calls.
- EOA `0x8152...` already owned Idol tokenId 940 and had previously interacted with stETH (approvals and transfers).
- This state is supported by:
  - Seed tx metadata for `0x5e98...5284c`.
  - Verified `IdolMain.sol` and Lido source.
  - Address txlists for `0x8152...`.
  - IdolMain txlist for the incident window.
  - Storage snapshots for IdolMain around the incident (`stethPrincipalBalance`, `allocatedStethRewards` slots).

Given these conditions, any holder of tokenId 940 (or similar) could reproduce the exploit pattern by deploying an equivalent helper contract and repeatedly self-transferring their Idol NFT.

### Transaction sequence leading to and following the exploit

The key adversary-crafted transactions are:

1. **Precursor aggregator trade – `0xdc74e81df45fb4e9fc510713540b5fffa9b3fd213309bc9074612cf9bc87829f`**
   - From `0x8152...` to aggregator `0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad`.
   - Executes a multi-call route that sells stETH for ETH and returns ETH to `0x8152...`.
   - Positions the adversary with ETH liquidity for funding the exploit.

2. **Funding transfers – `0xc468bf72...` and `0x178e1973...`**
   - Both from `0x8152...` to `0xe546...`, each sending 2 ETH.
   - Provide execution gas for the exploit deployment.

3. **Core exploit – `0x5e989304...5284c`**
   - From `0xe546...`, deploying `0x22d2...`.
   - Performs the self-`safeTransferFrom` loop and stETH drain described above.

4. **Post-exploit swap – `0xcc49a82e...`**
   - From `0x8152...` to `0x4531...` router.
   - Trades stETH via Curve pool `0xdc2431...` for ETH, consolidating profit.

These transactions together satisfy the exploit predicate: a sequence that moves value from IdolMain’s stETH treasury to the adversary cluster with no special privileges required beyond NFT ownership, stETH holdings, and standard approvals.

---

## All Relevant Transactions

The analysis considers the following Ethereum mainnet transactions as relevant to the incident and its context:

- **Adversary-crafted:**
  - `0x5e989304b1fb61ea0652db4d0f9476b8882f27191c1f1d2841f8977cb8c5284c` – exploit contract creation + stETH drain.
  - `0xdc74e81df45fb4e9fc510713540b5fffa9b3fd213309bc9074612cf9bc87829f` – precursor stETH/ETH aggregator trade by `0x8152...`.
  - `0xcc49a82ec89808a4ebe9556f780e065a242cc629e56c5141e538e9799cd46f95` – post-exploit stETH/ETH swap by `0x8152...`.
  - `0xc468bf728153dfffa724ea81adfc8f657e0423c41eaab38bbdc3d0fda1d7dd9b` – 2 ETH funding from `0x8152...` to `0xe546...`.
  - `0x178e1973701d69283d18e23edd5715120eca5c8a77f6981b331e7e77ea3f4be4` – second 2 ETH funding transfer from `0x8152...` to `0xe546...`.

- **Related (context and follow-on activity):**
  - `0x26aba26511874128b2bf075c4d5f801b27a42082c1ce7aa25327f61fa0185981`
  - `0x56e14baf3336367cde96e1b54d99f384fd4a76b90912e8e09a5bafbf1309b2b6`
  - `0xec8219a0ab3188338f91b95816c3f99487ab53efb27b35f0a9a8890eb36d8e4b`
  - `0x3d66d46fbe0530c6c4ccbfad723c4beedef19f2649cb79e559fe88817ee14a94`
  - `0x5a06f77e4210794fe436f1e545ee55e8cf88e821ec08176eeaf01ddb2fdf2873`
  - `0xc3b58d27882d994179eec848538310169c6300f0412088702a317f8366e1b769`
  - `0x017237ed8eb0c2d3695b20706aa5781460fdb216ad7e57d1f3689719bf909e1b`
  - `0xc44b242ac385633bcbe40461a0316b7628fc2fcf8302af1826956449405d1247`
  - `0x5cc6d66f8c8ec8d2eadb2918c3382350189cb9e8f57b6087c823fb37831ecf5f`
  - `0xb81b4e4ee7f656a5777fadb2a3d05561494ccdaa3a126a78154e98f930a2901f`
  - `0x2b6d7ee6c4179c17663fe7d874e40834699b14b3dc9812eefcf5b09669f7a629`

These cover funding, exploit execution, repeated self-transfer attempts, and post-exploit consolidation.

---

## References

- Seed transaction trace for exploit `0x5e98...5284c` (IdolMain/Lido call flow) – high-verbosity cast trace of the exploit showing the self-transfer loop, Lido delegatecalls, and final stETH transfer to `0x8152...`.
- CallTracer trace for tx `0x5e98...5284c` – structured call tree confirming helper contract creation, repeated `safeTransferFrom` calls, and Lido interactions.
- Verified `IdolMain.sol` source for `0x439c...` – contract code implementing `safeTransferFrom`, `_beforeTokenTransfer`, `_claimEthRewards`, and reward accounting.
- Lido stETH contract source for `0xae7a...` – implementation of stETH transfers and shares used by IdolMain.
- CallTracer trace for tx `0xdc74...` – precursor aggregator route for stETH/ETH adjustments by `0x8152...`.
- CallTracer trace for tx `0xcc49...` – post-exploit stETH/ETH swap via Curve pool `0xdc2431...` and router `0x4531...`.
- Address txlists for `0xe546...`, `0x8152...`, and `0x439c...` – contextual funding, repeated self-transfer attempts, and general activity around the incident window.

