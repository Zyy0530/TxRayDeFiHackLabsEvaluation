# Incident Overview TL;DR

On Ethereum mainnet, EOA 0xda97a086fc74b20c88bd71e12e365027e9ec2d24 deploys helper contract 0xD76C5305D0672CE5A2Cdd1e8419B900410ea1D36 and, in the same transaction, reconfigures proxy 0xF340bd3eB3E82994CfF5B8C3493245EDbcE63436 via initVRF to use this helper as VRF coordinator and LINK 0x514910771af9ca656af840dff83e8264ecf986ca as the randomness token.

Because initVRF on proxy 0xF340… is callable by an unprivileged EOA and the implementation’s VRF request logic streams LINK to the configured coordinator address without adequate restrictions, an attacker-controlled helper contract can be configured as coordinator and then used to drain 162 LINK from the proxy and convert it to ETH for the attacker.

## Key Background

- Proxy 0xF340bd3eB3E82994CfF5B8C3493245EDbcE63436 is a contract deployed by EOA 0x0c94ced619ac3f6fa1404fb485b6e17238d00f92 and used over a long period; its observed transactions include admin calls to addToken, setMinimum, setDevs and initVRF, and user calls to playGame and withdrawPlayerBalance with nonzero ETH. Evidence: artifacts/root_cause/data_collector/iter_3/tx/1/0xF340bd3eB3E82994CfF5B8C3493245EDbcE63436_txlist_0-latest.json.
- Implementation contract 0xd92A9110Beaf09115bc9628D8a296c2778041FE0, which proxy 0xF340… delegatecalls into, contains function 0x607d60e6. Pseudocode for 0x607d60e6 shows a loop that calls LinkToken.transferAndCall from the proxy to the configured VRF coordinator address, sending 2 LINK per iteration, tracking LINK-funded randomness requests, and then interacting with UniswapV2Router02 0x7a250d5630b4cf539739df2c5dacb4c659f2488d and WETH9 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 to convert LINK proceeds to ETH. Evidence: artifacts/root_cause/data_collector/iter_3/contract/1/0xd92A9110Beaf09115bc9628D8a296c2778041FE0/decompile/pseudocode_0x607d60e6.txt and artifacts/root_cause/seed/1/0x514910771af9ca656af840dff83e8264ecf986ca/src/Contract.sol.
- Helper contract 0xD76C5305D0672CE5A2Cdd1e8419B900410ea1D36 is created in the exploit transaction; its disassembly shows hardcoded addresses for LINK, WETH9, proxy 0xF340…, UniswapV2Router02, the LINK/WETH pair 0xa2107FA5B38d9bbd2C461D6EDf11B11A50F6b974 and EOA 0xda97a0…. The runtime code receives LINK via transferAndCall, approves UniswapV2Router02 to spend LINK, swaps LINK for ETH through the LINK/WETH pair and WETH9, forwards ETH to 0xda97a0… and 0xdadb0d80178819f2319190d340ce9a924f783711, and then selfdestructs. Evidence: artifacts/root_cause/data_collector/iter_2/contract/1/0xD76C5305D0672CE5A2Cdd1e8419B900410ea1D36/decompile/disassembly.txt.
- Balance and ERC20 state diffs for the exploit transaction show that proxy 0xF340… loses exactly 162 LINK, the LINK/WETH pair at 0xa2107FA5B38d9bbd2C461D6EDf11B11A50F6b974 gains 162 LINK and loses 0.848179619158684245 WETH, WETH9’s native ETH balance drops by 0.848179619158684245, EOA 0xda97a0… gains 0.845005252434861026 ETH, and address 0xdadb0d… gains 0.133049662894298 ETH. Evidence: artifacts/root_cause/data_collector/iter_2/tx/1/0x103b4550a1a2bdb73e3cb5ea484880cd8bed7e4842ecdd18ed81bf67ed19e03c/erc20_state_diff_link_weth.json and artifacts/root_cause/seed/1/0x103b4550a1a2bdb73e3cb5ea484880cd8bed7e4842ecdd18ed81bf67ed19e03c/balance_diff.json.

## Vulnerability Analysis

initVRF on proxy 0xF340… accepts a VRF coordinator address from any caller, and implementation function 0x607d60e6 sends LINK from the proxy to that coordinator address and allows it to route and convert funds without sufficient restrictions, so an adversary can register a custom coordinator helper that immediately swaps LINK to ETH and pays out to attacker-controlled addresses.

### Vulnerable Components
- Proxy 0xF340bd3eB3E82994CfF5B8C3493245EDbcE63436 initVRF(address _vrfCoordinator, address _link) configuration function.
- Implementation contract 0xd92A9110Beaf09115bc9628D8a296c2778041FE0 function 0x607d60e6 that loops over LINK.transferAndCall to the configured VRF coordinator and then routes LINK proceeds through UniswapV2Router02 and WETH9.

### Exploit Preconditions
- Proxy 0xF340… holds at least 162 LINK at pre-state σ_B and is configured to use implementation 0xd92A9… with function 0x607d60e6 available for execution.
- initVRF is callable by an unprivileged EOA and accepts arbitrary coordinator and LINK token addresses without verifying that the caller is an authorized operator.
- Implementation function 0x607d60e6 sends LINK from the proxy to the configured coordinator address via LinkToken.transferAndCall and allows repeated execution while LINK remains on the proxy.
- The configured coordinator address can execute arbitrary logic on receipt of LINK.transferAndCall, including approving UniswapV2Router02, swapping LINK to WETH through the LINK/WETH pair, unwrapping WETH to ETH via WETH9, and sending ETH to arbitrary addresses.
- The UniswapV2 LINK/WETH pool at 0xa2107FA5B38d9bbd2C461D6EDf11B11A50F6b974 and WETH9 0xc02a… provide sufficient liquidity to execute the observed 162 LINK → WETH → ETH swap.

### Security Principles Violated
- Missing or insufficient access control on critical configuration function initVRF for proxy 0xF340…, which allows any EOA to change the VRF coordinator and LINK token addresses.
- Design that routes LINK from the proxy directly to an externally configurable coordinator address without limiting that address to a trusted VRF coordinator implementation.
- Lack of invariant checks to constrain the volume or recipients of LINK streaming from the proxy, enabling complete depletion of the proxy’s LINK balance in a single transaction.

## Detailed Root Cause Analysis

In transaction 0x103b45…e03c, EOA 0xda97a0… deploys helper 0xD76C5… whose bytecode hardcodes the LINK, WETH9, router, pair, proxy and attacker EOA addresses. During the same transaction, the helper calls proxy function initVRF(address _vrfCoordinator, address _link) with its own address as _vrfCoordinator and LINK 0x5149… as _link. This call succeeds and updates the VRF configuration used by implementation contract 0xd92A9…. The proxy then executes function 0x607d60e6 via delegatecall into 0xd92A9…, which repeatedly calls LinkToken.transferAndCall from the proxy to helper 0xD76C5…, transferring 2 LINK per iteration until the proxy’s LINK balance has decreased by 162 LINK. The helper contract receives these LINK transfers, approves UniswapV2Router02 to spend 162 LINK, swaps 162 LINK for WETH through the LINK/WETH pair, unwraps WETH to ETH via WETH9, and sends ETH to 0xda97a0… and 0xdadb0d…. At the end of the transaction, helper 0xD76C5… selfdestructs. The net effect is that proxy 0xF340… loses 162 LINK, which are converted to 0.848179619158684245 ETH, of which 0.845005252434861026 ETH remains with EOA 0xda97a0… after gas, and 0.133049662894298 ETH is credited to 0xdadb0d…. The attack succeeds because initVRF lacks caller restrictions and because the implementation’s VRF request flow treats the configured coordinator address as an unrestricted LINK recipient that can redirect funds to arbitrary destinations.

```solidity
// LinkToken and WETH9 are standard contracts; exploit logic hinges on proxy VRF configuration and helper contract behavior.
```

```text
Seed transaction trace (cast run -vvvvv) for tx 0x103b4550a1a2bdb73e3cb5ea484880cd8bed7e4842ecdd18ed81bf67ed19e03c shows:
- Deployment of helper 0xD76C5305D0672CE5A2Cdd1e8419B900410ea1D36;
- initVRF(proxy=0xF340..., coordinator=0xD76C5..., link=0x5149...);
- Repeated LinkToken.transferAndCall calls from proxy 0xF340... to helper 0xD76C5...;
- Swaps through the LINK/WETH pair and WETH9, followed by ETH transfers to 0xda97a0... and 0xdadb0d....
```

## Adversary Flow Analysis

The adversary uses a single Ethereum mainnet transaction that deploys a custom helper contract, reconfigures proxy 0xF340… to use this helper as VRF coordinator, triggers the LINK-streaming function 0x607d60e6 to move 162 LINK from the proxy to the helper, swaps LINK to ETH through UniswapV2 and WETH9, and distributes ETH to an attacker EOA and a separate fee-recipient address.

### Adversary-Related Accounts
- 0xda97a086fc74b20c88bd71e12e365027e9ec2d24 (EOA: true, contract: false): Sender of the exploit transaction 0x103b45…e03c, recipient of 0.845005252434861026 ETH in that transaction, and sender of a subsequent 1 ETH Tornado Cash deposit; evidence from tx metadata, balance diffs and address txlist confirms this address originates the exploit and captures the majority of ETH profit.
- 0xD76C5305D0672CE5A2Cdd1e8419B900410ea1D36 (EOA: false, contract: true): Helper contract deployed by 0xda97a0… in the exploit transaction, configured as VRF coordinator for proxy 0xF340… via initVRF, recipient of 162 LINK from the proxy via LinkToken.transferAndCall during 0x607d60e6 execution, and intermediate contract that swaps LINK to ETH and forwards ETH to 0xda97a0… and 0xdadb0d… before selfdestruct.
- Victim: 0xF340bd3eB3E82994CfF5B8C3493245EDbcE63436 (0xF340bd3eB3E82994CfF5B8C3493245EDbcE63436 Proxy)

### Lifecycle Stages
#### Adversary Contract Deployment and VRF Reconfiguration

EOA 0xda97a0… deploys helper 0xD76C5… and uses it to call initVRF on proxy 0xF340…, setting 0xD76C5… as VRF coordinator and LINK 0x5149… as the randomness token for implementation 0xd92A9….

Key transactions:
- Ethereum Mainnet tx 0x103b4550a1a2bdb73e3cb5ea484880cd8bed7e4842ecdd18ed81bf67ed19e03c in block 23232613 (contract_deploy)

#### LINK Streaming and Swap to ETH

Proxy 0xF340… executes implementation function 0x607d60e6, which repeatedly calls LinkToken.transferAndCall from the proxy to helper 0xD76C5… until 162 LINK have been sent; helper 0xD76C5… approves UniswapV2Router02, swaps 162 LINK to WETH via the LINK/WETH pair at 0xa2107F…, unwraps WETH to ETH via WETH9, and prepares to forward ETH to designated recipients.

Key transactions:
- Ethereum Mainnet tx 0x103b4550a1a2bdb73e3cb5ea484880cd8bed7e4842ecdd18ed81bf67ed19e03c in block 23232613 (token_swap)

#### ETH Distribution and Post-Exploit Mixing

In the exploit transaction, helper 0xD76C5… sends 0.845005252434861026 ETH to 0xda97a0… and 0.133049662894298 ETH to 0xdadb0d… and then selfdestructs; four blocks later, EOA 0xda97a0… deposits 1 ETH into Tornado Cash contract 0xd90e2f925da726b50c4ed8d0fb90ad053324f31b via a standard deposit call.

Key transactions:
- Ethereum Mainnet tx 0x103b4550a1a2bdb73e3cb5ea484880cd8bed7e4842ecdd18ed81bf67ed19e03c in block 23232613 (transfer)
- Ethereum Mainnet tx 0xa06f2026d78845a4a818c0c187ee6c46d3474746480db35bffdc8a080591c87f in block 23232617 (transfer)

## Impact & Losses

### Total Loss Overview
- 162 LINK lost from proxy 0xF340bd3eB3E82994CfF5B8C3493245EDbcE63436.

### Impact Details
Proxy 0xF340bd3eB3E82994CfF5B8C3493245EDbcE63436 loses 162 LINK in a single exploit transaction; these tokens are transferred to helper 0xD76C5…, swapped through the LINK/WETH pool at 0xa2107F… and WETH9 0xc02a… into 0.848179619158684245 ETH, of which 0.845005252434861026 ETH remains with attacker EOA 0xda97a0… after gas and 0.133049662894298 ETH is credited to 0xdadb0d80178819f2319190d340ce9a924f783711. WETH9’s native ETH balance decreases by 0.848179619158684245 during the exploit transaction, matching the ETH amount routed out of WETH9.

## References

- [1] Exploit transaction metadata: artifacts/root_cause/seed/1/0x103b4550a1a2bdb73e3cb5ea484880cd8bed7e4842ecdd18ed81bf67ed19e03c/metadata.json
- [2] Exploit transaction cast trace: artifacts/root_cause/seed/1/0x103b4550a1a2bdb73e3cb5ea484880cd8bed7e4842ecdd18ed81bf67ed19e03c/trace.cast.log
- [3] Exploit transaction native balance diffs: artifacts/root_cause/seed/1/0x103b4550a1a2bdb73e3cb5ea484880cd8bed7e4842ecdd18ed81bf67ed19e03c/balance_diff.json
- [4] Exploit transaction LINK/WETH ERC20 diffs: artifacts/root_cause/data_collector/iter_2/tx/1/0x103b4550a1a2bdb73e3cb5ea484880cd8bed7e4842ecdd18ed81bf67ed19e03c/erc20_state_diff_link_weth.json
- [5] Helper contract 0xD76C5… disassembly: artifacts/root_cause/data_collector/iter_2/contract/1/0xD76C5305D0672CE5A2Cdd1e8419B900410ea1D36/decompile/disassembly.txt
- [6] Implementation 0xd92A9… pseudocode for 0x607d60e6: artifacts/root_cause/data_collector/iter_3/contract/1/0xd92A9110Beaf09115bc9628D8a296c2778041FE0/decompile/pseudocode_0x607d60e6.txt
- [7] Proxy 0xF340… address txlist: artifacts/root_cause/data_collector/iter_3/tx/1/0xF340bd3eB3E82994CfF5B8C3493245EDbcE63436_txlist_0-latest.json
- [8] Attacker EOA 0xda97a0… txlist and Tornado trace: artifacts/root_cause/data_collector/iter_3/tx/1/0xda97a086fc74b20c88bd71e12e365027e9ec2d24_txlist_0-23233000_page1.json
- [9] Tornado Cash deposit trace: artifacts/root_cause/data_collector/iter_2/tx/1/0xa06f2026d78845a4a818c0c187ee6c46d3474746480db35bffdc8a080591c87f/trace.cast.log