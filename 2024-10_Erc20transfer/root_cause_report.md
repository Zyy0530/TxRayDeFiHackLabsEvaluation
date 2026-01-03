## Unauthorized USDC drain via unprotected helper and router

### Metadata

- analysis_iteration: 4
- analysis_output_dir: `/home/ziyue/TxRayExperiment/slack-incident-C0A267R7RH8-1766394094_354389/artifacts/root_cause/root_cause_analyzer/iter_4/`
- report_title: Unauthorized USDC drain via unprotected helper and router
- protocol_name: Helper `0x43dc865e...` and router `0x6980a47b...` around USDC/WETH Uniswap V3 path
- root_cause_category: protocol_bug

---

## ACT Opportunity

### Block Height (B)

- block_height_B: `21019772`

### Pre-state (σ_B)

**Definition**

Ethereum mainnet state before block 21019772 with USDC allowance from `0x3dadf003afcc96d404041d8ae711b94f8c68c6a5` to helper `0x43dc865e916914fd93540461fde124484fbf8faa` and deployed code of helper `0x43dc865e916914fd93540461fde124484fbf8faa` and router `0x6980a47bee930a4584b09ee79ebe46484fbdbdd0`.

**Evidence**

- `seed/1/0x7f2540af4a1f7b0172a46f5539ebf943dd5418422e4faa8150d3ae5337e92172/metadata.json`
- `seed/1/0x7f2540af4a1f7b0172a46f5539ebf943dd5418422e4faa8150d3ae5337e92172/trace.cast.log`
- `seed/1/0x7f2540af4a1f7b0172a46f5539ebf943dd5418422e4faa8150d3ae5337e92172/balance_diff.json`
- `data_collector/iter_1/artifacts/contract/1/0x43dc865e916914fd93540461fde124484fbf8faa/disassembly.asm`
- `data_collector/iter_1/artifacts/contract/1/0x6980a47bee930a4584b09ee79ebe46484fbdbdd0/disassembly.asm`

### Transaction Sequence (b)

#### Transaction 1

- index: `1`
- chainid: `1`
- txhash: `0x7f2540af4a1f7b0172a46f5539ebf943dd5418422e4faa8150d3ae5337e92172`
- type: adversary-crafted
- inclusion_feasibility: Standard EIP-1559 transaction from unprivileged EOA `0xfde0d1575ed8e06fbf36256bcdfa1f359281455a` to router `0x6980a47bee930a4584b09ee79ebe46484fbdbdd0` with valid gas parameters.
- notes: EOA `0xfde0d1575ed8e06fbf36256bcdfa1f359281455a` calls router `0x6980a47bee930a4584b09ee79ebe46484fbdbdd0` which uses helper `0x43dc865e916914fd93540461fde124484fbf8faa` to transfer `14,773,350,000` USDC from victim `0x3dadf003afcc96d404041d8ae711b94f8c68c6a5`, swap it on Uniswap V3, unwrap WETH, and send ETH to `0x229b8325bb9ac04602898b7e8989998710235d5f`.

### Exploit Predicate

- type: profit

#### Profit

- reference_asset: ETH
- adversary_address: `cluster:{0xfde0d1575ed8e06fbf36256bcdfa1f359281455a,0x6980a47bee930a4584b09ee79ebe46484fbdbdd0,0x43dc865e916914fd93540461fde124484fbf8faa,0x229b8325bb9ac04602898b7e8989998710235d5f,0x388c818ca8b9251b393131c08a736a67ccb19297}`
- fees_paid_in_reference_asset: `0.001582793558332768`
- value_before_in_reference_asset: unknown
- value_after_in_reference_asset: value_before + `5.463274389444944942`
- value_delta_in_reference_asset: `5.463274389444944942`
- valuation_notes: Computed from `balance_diff.json` for tx `0x7f2540af4a1f7b0172a46f5539ebf943dd5418422e4faa8150d3ae5337e92172` and consolidation transfers within block `21019772`.

#### Non-monetary

- oracle_name: ""
- oracle_definition: ""
- oracle_evidence: ""

---

## Sections

### 1) Incident Overview & TL;DR

- incident_brief: An adversary-controlled EOA uses a custom router and helper to invoke an unprotected erc20TransferFrom that drains `14,773,350,000` USDC from victim `0x3dadf003afcc96d404041d8ae711b94f8c68c6a5`, swaps to WETH and ETH, and consolidates ETH profit to `0x388c818ca8b9251b393131c08a736a67ccb19297`.
- root_cause_brief: Helper contract `0x43dc865e916914fd93540461fde124484fbf8faa` exposes an erc20TransferFrom function that spends arbitrary approved USDC allowances without restricting caller identity, and router `0x6980a47bee930a4584b09ee79ebe46484fbdbdd0` allows adversary control over transfer parameters.

### 2) Vulnerability & Root Cause Analysis

- vulnerability_brief: The helper erc20TransferFrom function lacks any access control or binding between the approval granter and the entity that configures transfer parameters.
- root_cause_detail: In helper `0x43dc865e916914fd93540461fde124484fbf8faa`, erc20TransferFrom forwards arbitrary token, from, to, and amount parameters directly into token.transferFrom without checking msg.sender, ownership, or a per-user configuration mapping. Router `0x6980a47bee930a4584b09ee79ebe46484fbdbdd0` exposes a function that lets an external caller specify those parameters and route the received USDC through a Uniswap V3 swap and WETH unwrapping to ETH. Because victim `0x3dadf003afcc96d404041d8ae711b94f8c68c6a5` granted a large USDC allowance to the helper, the adversary can call the router once and deterministically drain `14,773,350,000` USDC and receive ETH.

#### Vulnerable Components

- `0x43dc865e916914fd93540461fde124484fbf8faa::erc20TransferFrom`
- `0x6980a47bee930a4584b09ee79ebe46484fbdbdd0::yoink`

#### Exploit Conditions

- Victim grants USDC allowance to helper `0x43dc865e916914fd93540461fde124484fbf8faa` that covers `14,773,350,000` units.
- Adversary controls an EOA that can call router `0x6980a47bee930a4584b09ee79ebe46484fbdbdd0` with chosen parameters.

#### Security Principles Violated

- Missing access control on token spending helper.
- Failure to bind token approvals to specific, user-controlled execution paths.

---

## All Relevant Transactions

- chainid: `1`, txhash: `0x7f2540af4a1f7b0172a46f5539ebf943dd5418422e4faa8150d3ae5337e92172`, role: adversary-crafted

```
