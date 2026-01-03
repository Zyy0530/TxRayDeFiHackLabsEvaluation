# SBR/UniswapV2 WETH Reserve Desynchronization Exploit

**Protocol:** SBR token / UniswapV2Pair(SBR-WETH)
**Root Cause Category:** protocol_bug
**ACT-Structured:** True

## Incident Overview & TL;DR

On Ethereum mainnet at block 21991722, an unprivileged EOA 0x7A6488348a7626C10e35DF9aE0A2AD916a56A952 sends a single type-2 contract-creation transaction (0xe4c1aeac...) that deploys exploit contract 0x9926796371E0107abe406128fa801FDa0E436F44 and, during its constructor, executes a sequence of swap, skim, transfer, sync, and swap calls on the SBR/WETH UniswapV2Pair 0x3431c535dDFB6dD5376E5Ded276f91DEaA864FF2 and the SBR helper contract 0xaCa4263fFddA9E60C7260AAbA08c2b8F80D63cB1 which desynchronizes the pair's SBR reserves from its WETH reserves and then swaps nearly the entire WETH backing out to the EOA as ETH, yielding a net profit of roughly 8.494 ETH after gas.

### Root Cause TL;DR
The root cause is a malicious SBR token and helper design that uses msgSend/msgReceive-based transfer guards and a stateful helper callback to allow a single external contract to (a) transfer a large amount of SBR from the pair while WETH stays in place, (b) force the pair to sync against the reduced SBR balance and full WETH balance, and (c) immediately swap the resulting mispriced SBR back for WETH, draining the pool; UniswapV2Pair and WETH9 behave as designed, and the exploit is fully enabled by the SBR/helper logic deployed on mainnet.

## ACT Opportunity Characterization

- **Block height B:** 21991722
- **Pre-state (σ_B) definition:**

Ethereum mainnet public state immediately before block 21991722, including deployed contracts WETH9 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2, SBR token 0x460B1AE257118Ed6F63Ed8489657588a326a206D, helper 0xaCa4263fFddA9E60C7260AAbA08c2b8F80D63cB1, UniswapV2Pair(SBR-WETH) 0x3431c535dDFB6dD5376E5Ded276f91DEaA864FF2, UniswapV2Router02 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D, and the liquidity / state set up by prior transactions including SBR deployment tx 0x4f24ab769f43549839925e31d48c6e1691765a7371ae8ad235994a5f7a8684da and openTrade/liquidity tx 0x669a8393c58b7df99f11a06a3885d944144de8c35b7bc25790b8d669466070c8.

- **Key evidence for σ_B:**
  - artifacts/root_cause/seed/1/0xe4c1aeacf8c93f8e39fe78420ce7a114ecf59dea90047cd2af390b30af54e7b9/metadata.json
  - artifacts/root_cause/seed/1/0xe4c1aeacf8c93f8e39fe78420ce7a114ecf59dea90047cd2af390b30af54e7b9/trace.cast.log
  - artifacts/root_cause/seed/1/0xe4c1aeacf8c93f8e39fe78420ce7a114ecf59dea90047cd2af390b30af54e7b9/balance_diff.json
  - artifacts/root_cause/data_collector/data_collection_summary.json
  - artifacts/root_cause/data_collector/iter_2/tx/1/0x4f24ab769f43549839925e31d48c6e1691765a7371ae8ad235994a5f7a8684da/trace.cast.log
  - artifacts/root_cause/data_collector/iter_2/tx/1/0x669a8393c58b7df99f11a06a3885d944144de8c35b7bc25790b8d669466070c8/trace.cast.log
  - artifacts/root_cause/data_collector/iter_2/address/1/0x3431c535dDFB6dD5376E5Ded276f91DEaA864FF2/txlist_21991300-21991750.json
  - artifacts/root_cause/data_collector/iter_2/address/1/0xaCa4263fFddA9E60C7260AAbA08c2b8F80D63cB1/txlist_21991300-21991750.json

### Transaction Sequence b

- **Index:** 1
  - **Chain:** 1
  - **Txhash:** 0xe4c1aeacf8c93f8e39fe78420ce7a114ecf59dea90047cd2af390b30af54e7b9
  - **Type:** adversary-crafted
  - **Inclusion feasibility:** At sigma_B (Ethereum mainnet block 21991722 pre-state), the exploit transaction is a type-2 contract-creation transaction from unprivileged EOA 0x7A6488348a7626C10e35DF9aE0A2AD916a56A952 with 4000 wei of ETH value, calldata that deploys exploit contract 0x9926796371E0107abe406128fa801FDa0E436F44 and immediately invokes UniswapV2Router02::swapExactETHForTokensSupportingFeeOnTransferTokens, and gas / fee parameters (maxFeePerGas, maxPriorityFeePerGas, gasLimit, nonce) fully determined by public chain state and EOA-local nonce/fee choices; the transaction is signed with the EOA's private key and broadcast via standard Ethereum infrastructure, and the included trace / receipt show that it is accepted and executed under normal inclusion rules without relying on any private mempool, privileged contract permissions, or non-public state.
  - **Notes:** This single transaction both deploys the exploit contract and executes the full skim/sync/swap exploit flow that drains WETH-backed value from the SBR/WETH UniswapV2Pair into the adversary EOA, as evidenced by the trace, events, and native balance diff.

### Exploit Predicate
- **Type:** Profit (monetary)
- **Reference asset:** ETH
- **Adversary address:** 0x7A6488348a7626C10e35DF9aE0A2AD916a56A952
- **Value before:** 0.107241074354027967 ETH
- **Value after:** 8.601293644488706837 ETH
- **Net profit:** 8.494052570134678870 ETH

**Valuation notes:**

Native balance_diff.json for tx 0xe4c1aeac... shows the adversary EOA's ETH balance increasing from 0.107241074354027967 ETH to 8.601293644488706837 ETH (delta +8.494052570134678870 ETH), WETH9's native ETH backing decreasing by 8.495031867920840930 ETH, and a minor amount (0.000167476321539080 ETH) sent to 0xdadb0d80178819f2319190d340ce9a924f783711. Using gasUsed = 484,970 and effectiveGasPrice = 2,019,295,582 wei from the receipt, the transaction gas fee is 979,297,786,162,060 wei (0.00097929778616206 ETH). Including the 4000 wei attached as msg.value, the adversary's net ETH profit remains approximately 8.494 ETH after all protocol-visible fees, establishing a strictly positive profit predicate.

## Vulnerability & Root Cause Analysis

### Vulnerability Overview
The SBR token and helper together introduce a stateful, address- and call-pattern-sensitive transfer hook that allows a specially crafted external contract to manipulate which addresses the helper treats as contr/router/pair and to route SBR transfers through UniswapV2Pair in a way that leaves WETH in the pool while removing almost all SBR, then forces the pair to sync to this manipulated SBR balance before swapping tokens back for WETH at an artificially high price.

### Detailed Root Cause
The decompiled SBR token contract 0x460B1AE257118Ed6F63Ed8489657588a326a206D maintains msgSend and msgReceive variables that track the last observed transfer sender and recipient, and its transfer() function calls helper 0xaCa4263fFddA9E60C7260AAbA08c2b8F80D63cB1::Unresolved_569937dd(uint256) before updating balances. The helper's decompiled code shows that Unresolved_569937dd(uint256) reads msgReceive() and msgSend() from the token, compares them against stored router, pair, creator, and contr addresses, and updates internal state that records which address is treated as contr and which is recognized as the router and pair. In the exploit, the deployed contract 0x9926796371E0107abe406128fa801FDa0E436F44 uses a sequence of swap, skim, transfer, and sync calls so that, during early transfers, helper::Unresolved_569937dd() sees msgSend/msgReceive combinations that classify the exploit contract and the UniswapV2Pair as allowed participants. The exploit then performs UniswapV2Router02::swapExactETHForTokensSupportingFeeOnTransferTokens to move a large amount of SBR from the pair to the exploit contract while leaving WETH in the pair, followed by UniswapV2Pair::skim() and a token::transfer(pair, 1) that leave token.balanceOf(pair) equal to 1 and token.balanceOf(exploit_contract) equal to 54,804,369,678. A subsequent UniswapV2Pair::sync() call updates the pair's stored reserves to (1 SBR, ~8.495e18 WETH), desynchronizing reserves from the pool's economic value. Finally, the exploit contract approves the router and calls swapExactTokensForETHSupportingFeeOnTransferTokens(54,804,369,677, 0, [SBR, WETH9], 0x7A6488..., deadline), which transfers SBR back to the pair and invokes swap() against the manipulated reserves (1, 8,495,031,868,076,317,819), causing the pair to send 8.495031867920844930 WETH to the router and then to the adversary EOA as ETH. Throughout this flow, UniswapV2Pair and WETH9 execute their standard logic; the vulnerability lies in the SBR/helper design that enables reserve desynchronization via stateful transfer hooks and selective address whitelisting.

### Vulnerable Components
- SBR token 0x460B1AE257118Ed6F63Ed8489657588a326a206D: transfer(address,uint256)
- Helper contract 0xaCa4263fFddA9E60C7260AAbA08c2b8F80D63cB1: Unresolved_569937dd(uint256)
- SBR token 0x460B1AE257118Ed6F63Ed8489657588a326a206D: msgSend/msgReceive state variables and constructor wiring to helper/router/pair

### Exploit Preconditions
- SBR token and helper deployed and wired together with UniswapV2Router02 and the specific SBR/WETH UniswapV2Pair via constructor and configuration transactions before sigma_B.
- Sufficient SBR/WETH liquidity present in the UniswapV2Pair at sigma_B, established via openTrade/liquidity provisioning transactions such as 0x669a8393c58b7df99f11a06a3885d944144de8c35b7bc25790b8d669466070c8.
- An unprivileged EOA with enough ETH balance to pay gas and the 4000 wei input required to seed the swap, and the ability to deploy and call the exploit contract with the specific sequence of router/pair/helper interactions observed in tx 0xe4c1aeac....

### Violated Security Assumptions
- Assumption that ERC-20 tokens used in AMM pools implement straightforward, stateless transfer logic without stateful external callbacks that can selectively privilege certain senders/recipients.
- Assumption that Uniswap V2 reserve updates via sync() reflect economically meaningful balances and cannot be manipulated by contracts that move one side of the pool's assets out while leaving the other side in place.
- Assumption that fee-on-transfer or rebasing tokens used in AMMs do not introduce exploitable paths that allow reserve desynchronization and value extraction by a single unprivileged adversary.

## Adversary Flow Analysis

### Strategy Overview
The adversary uses a single adversary-crafted transaction that both deploys an exploit contract and executes a multi-step interaction with SBR, the helper, UniswapV2Router02, and the SBR/WETH UniswapV2Pair to first obtain a large SBR position with negligible ETH, then manipulate the pair's stored reserves via skim/transfer/sync while WETH remains in the pool, and finally swap the mispriced SBR back for WETH to extract approximately 8.495 ETH of profit.

### Adversary-Related Accounts
- **Address:** 0x7A6488348a7626C10e35DF9aE0A2AD916a56A952 (chainid 1)
  - **EOA:** True, **Contract:** False
  - **Reason:** Sender of exploit tx 0xe4c1aeac..., direct recipient of the final ETH proceeds after WETH9::withdraw, and deployer of exploit contract 0x9926796371E0107abe406128fa801FDa0E436F44 as shown in the seed metadata and trace.
- **Address:** 0x9926796371E0107abe406128fa801FDa0E436F44 (chainid 1)
  - **EOA:** False, **Contract:** True
  - **Reason:** Contract created by the exploit transaction from 0x7A6488..., orchestrating all UniswapV2Router02, UniswapV2Pair, SBR token, and helper calls that perform the reserve manipulation and profit-taking steps, as shown in the exploit trace.

### Victim / Infrastructure Contracts
- **SBR token** (0x460B1AE257118Ed6F63Ed8489657588a326a206D on Ethereum, chainid 1), verified=false
- **SBR/WETH UniswapV2Pair** (0x3431c535dDFB6dD5376E5Ded276f91DEaA864FF2 on Ethereum, chainid 1), verified=true
- **WETH9** (0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 on Ethereum, chainid 1), verified=true
- **UniswapV2Router02** (0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D on Ethereum, chainid 1), verified=true

### Lifecycle Stages

#### Adversary Initial Funding and Setup
- **Transactions:**
  - Chain 1 tx 0xe4c1aeacf8c93f8e39fe78420ce7a114ecf59dea90047cd2af390b30af54e7b9 at block 21991722
- **Effect:**
EOA 0x7A6488... uses its existing ETH balance to fund a type-2 contract-creation transaction with 4000 wei of msg.value and sufficient gas budget to deploy the exploit contract and execute the entire exploit sequence in a single transaction.
- **Evidence summary:**
Seed metadata, receipt.json, and balance_diff.json for tx 0xe4c1aeac... show the EOA sender, msg.value = 4000, gasUsed, and the resulting ETH balance changes.

#### Adversary Contract Deployment and Reserve Manipulation
- **Transactions:**
  - Chain 1 tx 0xe4c1aeacf8c93f8e39fe78420ce7a114ecf59dea90047cd2af390b30af54e7b9 at block 21991722
- **Effect:**
The exploit transaction deploys contract 0x992679... which, in its constructor, invokes UniswapV2Router02::swapExactETHForTokensSupportingFeeOnTransferTokens(WETH9 -> SBR) with 4000 wei, causing WETH9::deposit and WETH9::transfer(pair, 4000) followed by UniswapV2Pair::swap() and SBR's fee-on-transfer logic, resulting in 54,804,369,678 SBR being transferred from the pair to the exploit contract while WETH remains in the pair. The contract then calls UniswapV2Pair::skim() and SBR::transfer(pair, 1), both of which trigger helper::Unresolved_569937dd() with msgSend/msgReceive combinations that maintain the exploit contract and pair as privileged participants, leaving token.balanceOf(pair) = 1 and token.balanceOf(exploit_contract) = 54,804,369,678 while WETH9.balanceOf(pair) is approximately 8.495e18.
- **Evidence summary:**
Mid-section of artifacts/root_cause/seed/1/0xe4c1aeac.../trace.cast.log shows swapExactETHForTokensSupportingFeeOnTransferTokens, WETH9 deposit/transfer, SBR Transfer events, helper callbacks, skim(), and transfer(pair, 1), along with balanceOf(pair) / balanceOf(exploit_contract) calls; decompiled SBR and helper sources in artifacts/root_cause/data_collector/iter_1/contract/1/... show the msgSend/msgReceive and Unresolved_569937dd() logic.

#### Adversary Profit-Taking Swap
- **Transactions:**
  - Chain 1 tx 0xe4c1aeacf8c93f8e39fe78420ce7a114ecf59dea90047cd2af390b30af54e7b9 at block 21991722
- **Effect:**
After reserves are manipulated, the exploit contract calls UniswapV2Pair::sync() which reads token.balanceOf(pair) = 1 and WETH9.balanceOf(pair) = 8,495,031,868,076,317,819 and stores these as the new reserves; then the contract approves UniswapV2Router02 and calls swapExactTokensForETHSupportingFeeOnTransferTokens(54,804,369,677, 0, [SBR, WETH9], 0x7A6488..., deadline). This transfers SBR back to the pair, calls UniswapV2Pair::getReserves() which returns (1, 8,495,031,868,076,317,819), and executes swap() that sends 8.495031867920844930 WETH to the router, followed by WETH9::withdraw and a fallback that delivers 8.495031867920844930 ETH to the adversary EOA. Accounting for the 4000 wei input and gas fees, the adversary's net ETH profit is positive and matches the native balance diff.
- **Evidence summary:**
Later sections of artifacts/root_cause/seed/1/0xe4c1aeac.../trace.cast.log show sync(), getReserves() returning (1, 8,495,031,868,076,317,819), the swapExactTokensForETHSupportingFeeOnTransferTokens call, UniswapV2Pair::swap(), WETH9::withdraw, and the final ETH transfer to 0x7A6488...; balance_diff.json and balance_diff_erc20.json confirm the ETH and SBR/WETH flows.

## Impact & Losses

### Quantitative Summary
- 8.494052570134678870 ETH

### Detailed Impact
The exploit removes approximately 8.495 WETH worth of ETH backing from the SBR/WETH UniswapV2 pool and transfers it to the adversary EOA, reducing the pool's WETH reserves while leaving a minimal SBR reserve. The exploit sequence depends only on public contracts and state at sigma_B and does not use any privileged permissions, private orderflow, or secret configuration; an unprivileged actor who submits the same transaction from the same pre-state follows the same execution path and obtains the same reserve manipulation and WETH drain, subject only to normal network-level competition for ordering.

## References

- [1] Seed exploit trace and metadata for tx 0xe4c1aeac... — artifacts/root_cause/seed/1/0xe4c1aeacf8c93f8e39fe78420ce7a114ecf59dea90047cd2af390b30af54e7b9
- [2] SBR token decompiled source — artifacts/root_cause/data_collector/iter_1/contract/1/0x460B1AE257118Ed6F63Ed8489657588a326a206D/decompile/0x460B1AE257118Ed6F63Ed8489657588a326a206D-decompiled.sol
- [3] Helper contract decompiled source — artifacts/root_cause/data_collector/iter_1/contract/1/0xaCa4263fFddA9E60C7260AAbA08c2b8F80D63cB1/decompile/0xaCa4263fFddA9E60C7260AAbA08c2b8F80D63cB1-decompiled.sol
- [4] UniswapV2Pair verified source for 0x3431c535dDFB6dD5376E5Ded276f91DEaA864FF2 — artifacts/root_cause/data_collector/iter_1/contract/1/0x3431c535dDFB6dD5376E5Ded276f91DEaA864FF2/source
- [5] Data collection summary — artifacts/root_cause/data_collector/data_collection_summary.json

## All Relevant Transactions

- Chain 1 tx 0xe4c1aeacf8c93f8e39fe78420ce7a114ecf59dea90047cd2af390b30af54e7b9 — role: attacker-crafted
- Chain 1 tx 0x4f24ab769f43549839925e31d48c6e1691765a7371ae8ad235994a5f7a8684da — role: related
- Chain 1 tx 0x669a8393c58b7df99f11a06a3885d944144de8c35b7bc25790b8d669466070c8 — role: related
- Chain 1 tx 0xfb38e71983dc694822c75b958c6bd534c280aef658cbeefb93e63450f8fb4c93 — role: related
- Chain 1 tx 0x0ef06c2f88e052fa43d4779fe7ae9e6fd530bd97d74a1d26b383e703d7c2c72e — role: related

## Key Code and Trace Snippets

**SBR token transfer() with msgSend/msgReceive and helper callback** (decompiled SBR token source for 0x460B1AE257118Ed6F63Ed8489657588a326a206D).

```solidity
function transfer(address arg0, uint256 arg1) public returns (bool) {
    require(arg0 == (address(arg0)));
    msgSend = (uint96(msgSend)) | (address(msg.sender));
    msgReceive = (uint96(msgReceive)) | (address(arg0));
    require(0x01 == (bytes1(trade)), "ERC20: transfer to the zero address");
    require(address(msgSend), "ERC20: transfer to the zero address");
    require(address(arg0), "ERC20: transfer to the zero address");
    (bool success, bytes memory ret0) = address(store_g).Unresolved_569937dd(arg1); // call
    storage_map_h[msg.sender] = storage_map_h[msg.sender] - arg1;
    storage_map_h[arg0] = storage_map_h[arg0] + arg1;
    emit Transfer(msg.sender, arg0, arg1);
    return true;
}
```

**Helper Unresolved_569937dd(uint256) reading msgReceive/msgSend and tagging participants** (decompiled helper contract 0xaCa4263fFddA9E60C7260AAbA08c2b8F80D63cB1).

```solidity
function Unresolved_569937dd(uint256 arg0) public payable {
    require(!counter < 1);
    (bool success1, bytes memory ret0) = address(unresolved_9ea90ccc).msgReceive();
    address recv = address(uint160(uint256(bytes32(ret0))));
    require(address(router) == recv);
    require(address(pair) == recv);
    require(address(creator) == recv);
    require(address(contr) == recv);
    require(bytes1(storage_map_k[recv]) == 0x01);
    (bool success2, bytes memory ret1) = address(unresolved_9ea90ccc).msgSend();
    contr = msg.sender | uint96(contr);
    unresolved_9ea90ccc = msg.sender | uint96(unresolved_9ea90ccc);
}
```

**Seed transaction trace (cast run -vvvvv) for exploit tx 0xe4c1aeac... showing reserve manipulation and profit-taking swap**.

```text
UniswapV2Router02::swapExactTokensForETHSupportingFeeOnTransferTokens(54804369677, 0, [SBR, WETH9], 0x7A6488..., deadline)
  0x460B1AE2::transferFrom(0x992679..., UniswapV2Pair, 54804369677)
    0xaCa4263fFdd...::569937dd(...)
      0x460B1AE2::msgReceive() -> pair
      0x460B1AE2::msgSend() -> 0x992679...
      ...
    emit Transfer(from: 0x992679..., to: UniswapV2Pair, value: 54804369677)
  UniswapV2Pair::getReserves() -> (1, 8495031868076317819, ...)
  UniswapV2Pair::swap(0, 8495031867920844930, UniswapV2Router02, 0x)
    WETH9::transfer(UniswapV2Router02, 8495031867920844930)
    emit Sync(reserve0: 54804369678, reserve1: 155472889)
    emit Swap(amount0In: 54804369677, amount1Out: 8495031867920844930, to: UniswapV2Router02)
  WETH9::withdraw(8495031867920844930)
  0x7A6488...::fallback{value: 8495031867920844930}()
```
