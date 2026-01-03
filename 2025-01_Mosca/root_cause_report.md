# Mosca withdrawAll/exitProgram drain via public orchestrator on BNB Chain

## Incident Overview & TL;DR

On BNB Chain, an unprivileged EOA 0xb7d7... triggered a public orchestrator contract 0x8512... to repeatedly call Mosca.exitProgram() and related functions in a single transaction, exploiting Mosca’s withdrawAll() accounting bug. This drained ~11.37M units of 0x8ac7... and ~8.88T units of 0x55d3... stablecoins from Mosca 0x1962... into PancakeSwap pools and a small direct transfer to Mosca’s owner 0x2fe7....

Mosca’s withdrawAll(address) and exitProgram() logic allow the same user entry to be withdrawn multiple times without debiting user balances or admin balances, enabling a public orchestrator to loop exitProgram() and over-withdraw stablecoins from the contract relative to its recorded liabilities.

## Key Background

- Mosca 0x1962b3...5037d is a referral-based investment contract holding USDT/USDC-like stablecoins (tokens 0x55d3... and 0x8ac7...) on BNB Chain and tracking per-user earnings in a User struct (balance, balanceUSDT, balanceUSDC) plus global adminBalance/adminBalanceUSDT/adminBalanceUSDC.
- The withdrawAll(address) function computes a per-user withdrawal amount as user.balance + user.balanceUSDT + user.balanceUSDC, transfers that amount in stablecoins to user.walletAddress, but does not decrement any of those balances or the admin balance counters; exitProgram() can call withdrawAll(msg.sender) when msg.sender is found in rewardQueue.
- Orchestrator contract 0x8512... exposes a public start(address,uint256) entry point that chains Mosca.join(...), Mosca.buy(...), and many Mosca.exitProgram() calls, while routing withdrawn stablecoins through PancakeSwap pools and helper addresses as reconstructed from the decompilation and callTracer trace.
- Mosca owner is the only account allowed to call emergencyWithdraw(), which sends the contract’s remaining usdt/usdc balances to owner without changing internal user/admin accounting; this is later invoked by 0x2fe7....

## ACT Opportunity and Pre-State

- **Block height B:** 45519931
- **Seed transaction (b[1]):** 0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff on chainid 56

### Pre-state ccde 

BNB Chain (chainid 56) state immediately before inclusion of seed tx 0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff in block 45519931, with Mosca 0x1962b3...5037d already deployed and configured (users mapping, rewardQueue, admin balances, owner set to 0x2fe7..., orchestrator 0x8512... and relevant Pancake pairs/WBNB contracts existing as in the prestateTracer snapshot).


### Non-monetary ACT predicate

- **Type:** non-monetary
- **Oracle name:** Mosca stablecoin reserve integrity

Oracle definition:

> O(sigma_B, sigma') = 1 if, starting from sigma_B, the execution of b causes Mosca contract 0x1962b3...5037d to experience (a) a large net decrease in its on-chain ERC20 stablecoin holdings (tokens 0x8ac7... and 0x55d3...) without corresponding reductions in user/admin accounting fields, and (b) a corresponding increase in user[0x8512...].balanceUSDC and adminBalance so that recorded liabilities/fees are no longer backed by actual contract balances.

Evidence used for this oracle:

> artifacts/root_cause/data_collector/iter_3/tx/56/0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff/balance_diff.json; artifacts/root_cause/data_collector/iter_1/tx/56/0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff/state_diff_prestateTracer.json; artifacts/root_cause/data_collector/iter_1/contract/56/0x1962b3356122d6a56f978e112d14f5e23a25037d/source/src/Contract.sol; artifacts/root_cause/data_collector/iter_2/contract/56/0x1962b3356122d6a56f978e112d14f5e23a25037d/user_prestate.json; artifacts/root_cause/data_collector/iter_4/contract/56/0x1962b3356122d6a56f978e112d14f5e23a25037d/mosca_user_admin_summary_seed_and_emergency.json; artifacts/root_cause/data_collector/iter_3/tx/56/0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff/mosca_state_diff_focus.json

## Vulnerability & Root Cause Analysis

**Vulnerability summary.** Mosca does not reduce user or admin accounting variables when paying out withdrawAll(addr), and exitProgram() can trigger withdrawAll(msg.sender) multiple times for the same user entry via a public orchestrator loop.

From the verified Mosca Contract.sol, withdrawAll(address addr) loads User storage for addr, requires msg.sender == user.walletAddress, computes uint balance = user.balance + user.balanceUSDT + user.balanceUSDC, and then transfers that amount of stablecoins (preferring usdc.balanceOf(this), otherwise usdt) to user.walletAddress, emitting a WithdrawAll event. Crucially, it never reduces user.balance, user.balanceUSDT, user.balanceUSDC, nor adminBalance/adminBalanceUSDT/adminBalanceUSDC. exitProgram() iterates rewardQueue and when it finds msg.sender, it calls withdrawAll(msg.sender), then later resets users[msg.sender].balance and enterprise status and removes the user from rewardQueue. The orchestrator 0x8512... start(...) function, as summarized in start_control_flow_summary.txt, repeatedly calls Mosca.join(...) and then Mosca.exitProgram() many times in a single transaction. Pre-state user records show users[0x8512...] had zero balance/balanceUSDT/balanceUSDC before the seed tx, while post-seed snapshots show users[0x8512...].balanceUSDC becomes ~9.85e20 units and adminBalance increases, despite Mosca’s ERC20 holdings in tokens 0x8ac7... and 0x55d3... dropping sharply. Call traces and balance diffs confirm that withdrawAll(msg.sender) is invoked repeatedly for 0x8512..., draining Mosca’s stablecoin balances to external recipients without correspondingly reducing internal accounting, thereby violating the intended one-to-one relationship between recorded earnings and available reserves.

### Vulnerable Components

- Mosca 0x1962b3356122d6a56f978e112d14f5e23a25037d, function withdrawAll(address)
- Mosca 0x1962b3356122d6a56f978e112d14f5e23a25037d, function exitProgram()
- Orchestrator 0x851288dcfb39330291015c82a5a93721cc92507a, function start(address,uint256) driving repeated exitProgram() loops

### Exploit Preconditions

- A user entry in Mosca.users[addr] must exist in rewardQueue with non-zero balance, balanceUSDT, or balanceUSDC while user.walletAddress is set to a controllable address.
- An unprivileged EOA must be able to trigger exitProgram() repeatedly for that addr (directly or via a helper like 0x8512...) in a single or multiple transactions.
- Mosca must hold sufficient usdt/usdc token balances (0x55d3..., 0x8ac7...) on-chain at sigma_B so that repeated withdrawAll(msg.sender) calls can transfer large amounts out before balances are exhausted.

### Security Principles Violated

- Conservation of value between contract accounting (user balances, admin balances) and actual ERC20 token holdings.
- Single-spend assumptions for user earnings (lack of idempotence and missing debits in withdrawAll).
- Least privilege and separation of concerns between user withdrawal logic and administrative fee accounting.

### Key Code Snippets

Withdraw-all logic in Mosca (showing missing debits):

```solidity
// Collected from verified Mosca Contract.sol
function withdrawAll(address addr) private {
         User storage user = users[addr];
        require(msg.sender == user.walletAddress, "Wallet addresses do not match");
        uint balance = user.balance + user.balanceUSDT + user.balanceUSDC;

        if(usdc.balanceOf(address(this)) >= balance){
            usdc.transfer(user.walletAddress, balance);
            emit WithdrawAll(user.walletAddress, block.timestamp, balance, 2);
        } else {
            usdt.transfer(user.walletAddress, balance);
            emit WithdrawAll(user.walletAddress, block.timestamp, balance, 1);
        }
        

       

    }
```

Exit-program logic calling withdrawAll(msg.sender):

```solidity
// Collected from verified Mosca Contract.sol
function exitProgram() external nonReentrant {
    require(!isBlacklisted[msg.sender], "Blacklisted user");
    User storage user = users[msg.sender];

    address referrer = referrers[user.collectiveCode];
    if (referrer != address(0) && users[referrer].inviteCount > 0) {
        users[referrer].inviteCount--;
    }

    for (uint256 i = 0; i < rewardQueue.length; i++) {
        address userAddr = rewardQueue[i];
        if (userAddr == msg.sender) {
            // Perform withdrawal before modifying user state
            withdrawAll(msg.sender);

            // Remove user from reward queue and reset state
            refByAddr[userAddr] = 0;
            referrers[user.refCode] = 0x000000000000000000000000000000000000dEaD;
            user.balance = 0;
            user.enterprise = false;

            rewardQueue[i] = rewardQueue[rewardQueue.length - 1];
            rewardQueue.pop();

            emit ExitProgram(msg.sender, block.timestamp);
        }
    }
}
```

## Adversary Flow Analysis

A single, adversary-crafted transaction from EOA 0xb7d7... calls a public orchestrator start(...) function that loops Mosca.exitProgram() and related calls to invoke withdrawAll(msg.sender) multiple times, draining Mosca’s stablecoin reserves into DEX liquidity pools and a small direct payout to the Mosca owner, without the adversary needing privileged access to Mosca.

### Adversary-Related Accounts and Victims

**Adversary cluster** (behaviorally-linked accounts):
- 0xb7d7240c207e094a9be802c0f370528a9c39fed5 on BNB Chain (chainid 56): Seed transaction sender that calls orchestrator 0x8512... start(...), pays gas, and initiates the repeated exitProgram()/withdrawAll loop; fully unprivileged with respect to Mosca (not owner, no special role).
- 0x851288dcfb39330291015c82a5a93721cc92507a on BNB Chain (chainid 56): Non-verified orchestrator contract whose start(address,uint256) function is called by 0xb7d7... in the seed tx; decompilation and start_control_flow_summary.txt show it repeatedly calls Mosca.exitProgram() and Mosca.join(...) to realize the over-withdrawal pattern.

**Victim candidates:**
- Mosca at 0x1962b3356122d6a56f978e112d14f5e23a25037d on BNB Chain (chainid 56)
- Mosca owner/treasury at 0x2fe70ef3db7ea49b5f14b5edf6208116458fa74a on BNB Chain (chainid 56)

### Lifecycle Stages

#### Adversary initial funding and setup

Involved transactions:
- 0x742f0580be25108a5d8342c4e075566b71d9d595b7713acb725d7dc0f9418322 on BNB Chain (block 45480690, mechanism transfer)

EOA 0x2fe7... receives BNB funding from 0x1d46..., and EOA 0xb7d7... accumulates sufficient BNB to pay gas for later orchestrator activity, as seen in their txlists.

Evidence artifacts:

> artifacts/root_cause/data_collector/iter_3/address/56/0x2fe70ef3db7ea49b5f14b5edf6208116458fa74a/txlist.json; artifacts/root_cause/data_collector/iter_1/address/56/0xb7d7240c207e094a9be802c0f370528a9c39fed5/txlist_45518000_45521000.json

#### Adversary transaction execution against Mosca

Involved transactions:
- 0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff on BNB Chain (block 45519931, mechanism other)

0xb7d7... calls 0x8512... start(...), which loops Mosca.exitProgram() and Mosca.join(...) many times, causing repeated withdrawAll(msg.sender) calls for 0x8512.... Mosca’s holdings of 0x8ac7... and 0x55d3... drop by ~11.37M and ~8.88T units respectively, while Pancake pairs 0xd99c... and 0x16b9... gain corresponding amounts and 0x2fe7... and 0x92b7... receive smaller 0x8ac7... allocations. Mosca.user[0x8512...] and adminBalance values increase without being debited by these withdrawals.

Evidence artifacts:

> artifacts/root_cause/data_collector/iter_3/tx/56/0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff/trace_callTracer.json; artifacts/root_cause/data_collector/iter_3/tx/56/0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff/mosca_state_diff_focus.json; artifacts/root_cause/data_collector/iter_3/tx/56/0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff/balance_diff.json; artifacts/root_cause/data_collector/iter_2/contract/56/0x1962b3356122d6a56f978e112d14f5e23a25037d/user_prestate.json; artifacts/root_cause/data_collector/iter_4/contract/56/0x1962b3356122d6a56f978e112d14f5e23a25037d/mosca_user_admin_summary_seed_and_emergency.json

#### Owner mitigation via emergencyWithdraw

Involved transactions:
- 0xad3b9013331601b8d721671fdb59f2e9e8d30e923a05bc2d2bbcbb8038dde16a on BNB Chain (block 45522214, mechanism mint)

Later, Mosca owner 0x2fe7... calls Mosca.emergencyWithdraw(), which is restricted by onlyOwner, and transfers the remaining on-contract stablecoin balance (notably ~2.82e19 units of 0x8ac7...) to owner. Mosca.getUser() and getAdminBalances() snapshots before and after this tx show no changes for users[0x8512...], users[0xb7d7...], users[0x2fe7...], or adminBalance/adminBalanceUSDT/adminBalanceUSDC, confirming this is an owner-only treasury withdrawal rather than part of the orchestrator exploit loop.

Evidence artifacts:

> artifacts/root_cause/data_collector/iter_1/contract/56/0x1962b3356122d6a56f978e112d14f5e23a25037d/source/src/Contract.sol; artifacts/root_cause/data_collector/iter_4/tx/56/0xad3b9013331601b8d721671fdb59f2e9e8d30e923a05bc2d2bbcbb8038dde16a/trace_callTracer.json; artifacts/root_cause/data_collector/iter_4/tx/56/0xad3b9013331601b8d721671fdb59f2e9e8d30e923a05bc2d2bbcbb8038dde16a/state_diff_prestateTracer.json; artifacts/root_cause/data_collector/iter_4/tx/56/0xad3b9013331601b8d721671fdb59f2e9e8d30e923a05bc2d2bbcbb8038dde16a/balance_diff.json; artifacts/root_cause/data_collector/iter_4/contract/56/0x1962b3356122d6a56f978e112d14f5e23a25037d/mosca_user_admin_summary_seed_and_emergency.json; artifacts/root_cause/data_collector/iter_4/contract/56/0x1962b3356122d6a56f978e112d14f5e23a25037d/mosca_user_admin_delta_emergency.json

### Representative Trace and Balance Snippets

Seed transaction ERC20 balance diffs for Mosca and key recipients:

```json
{
  "usdc_mosca": {
    "token": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
    "holder": "0x1962b3356122d6a56f978e112d14f5e23a25037d",
    "before": "11921680000000000000000",
    "after": "555561773399014778333",
    "delta": "-11366118226600985221667",
    "balances_slot": "1",
    "slot_key": "0x5e79873f2a6a59fee9298b5620ed70728685d01f06321c37ace2cfb7b69360db",
    "layout_address": "0xba5fe23f8a3a24bed3236f05f2fcf35fd0bf0b5c",
    "contract_name": "BEP20TokenImplementation"
  },
  "usdt_mosca": {
    "token": "0x55d398326f99059ff775485246999027b3197955",
    "holder": "0x1962b3356122d6a56f978e112d14f5e23a25037d",
    "before": "8997429999999999980296",
    "after": "116425073891625596065",
    "delta": "-8881004926108374384231",
    "balances_slot": "1",
    "slot_key": "0x5e79873f2a6a59fee9298b5620ed70728685d01f06321c37ace2cfb7b69360db",
    "contract_name": "BEP20USDT"
  }
}
```

Caption: Extract from extended balance_diff for the seed transaction, showing large USDC and USDT outflows from Mosca.

Mosca internal accounting around the seed transaction:

```json
{
  "seed_pre_adminBalances": {
    "adminBalance": "297214403940886699662 [2.972e20]",
    "adminBalanceUSDT": "0",
    "adminBalanceUSDC": "0"
  },
  "seed_post_adminBalances": {
    "adminBalance": "313569083743842364682 [3.135e20]",
    "adminBalanceUSDT": "0",
    "adminBalanceUSDC": "0"
  },
  "seed_post_user_8512": {
    "balance": "0",
    "balanceUSDT": "0",
    "balanceUSDC": "985221674876847290640 [9.852e20]",
    "nextDeadline": "1738560169 [1.738e9]",
    "bonusDeadline": "1736745769 [1.736e9]",
    "runningCount": "0",
    "inviteCount": "0",
    "refCode": "5226517170 [5.226e9]",
    "collectiveCode": "0",
    "walletAddress": "0x851288dcFb39330291015C82A5a93721CC92507A",
    "enterprise": "false"
  }
}
```

Caption: Snapshot of Mosca adminBalance and users[0x8512...] before and after the seed tx, showing adminBalance increasing and users[0x8512...].balanceUSDC becoming large while the ERC20 balance diffs show reserves dropping.

EmergencyWithdraw ERC20 balance diffs (owner consolidation):

```json
[
  {
    "token": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
    "holder": "0x2fe70ef3db7ea49b5f14b5edf6208116458fa74a",
    "before": "1987590482956630929198",
    "after": "2015807231725103835607",
    "delta": "28216748768472906409",
    "balances_slot": "1",
    "slot_key": "0xd4165037871536f0289211ec6e804b1849c956537a88dbc6dc46780d25530c71",
    "layout_address": "0xba5fe23f8a3a24bed3236f05f2fcf35fd0bf0b5c",
    "contract_name": "BEP20TokenImplementation"
  }
]
```

Caption: Extract from balance_diff for the emergencyWithdraw transaction by 0x2fe7..., showing remaining USDC moved from Mosca to the owner.

## Impact & Losses

Total stablecoin losses from Mosca in the seed transaction:

- 11366118.226600985221667 units of 0x8ac7... (USDC-like)
- 8881004.926108374384231 units of 0x55d3... (USDT)

Within the seed transaction, Mosca contract 0x1962... loses approximately 11,366,118.2266 units of token 0x8ac7... and 8,881,004.9261 units of token 0x55d3..., which are moved primarily into PancakeSwap pair contracts while Mosca's internal adminBalance and users[0x8512...].balanceUSDC increase rather than decrease. This breaks the implicit invariant that user/admin accounting is backed by on-chain token reserves and effectively renders previously recorded earnings and fee balances unbacked from the protocol's perspective. Subsequent owner emergencyWithdraw consolidates the remaining stablecoins to 0x2fe7... but does not repair the earlier accounting mismatch or the drained liquidity.

## References

- [1] Seed tx metadata and trace: `artifacts/root_cause/seed/56/0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff/metadata.json`
- [2] Mosca verified source (Contract.sol): `artifacts/root_cause/data_collector/iter_1/contract/56/0x1962b3356122d6a56f978e112d14f5e23a25037d/source/src/Contract.sol`
- [3] Mosca user prestate and post-seed snapshots: `artifacts/root_cause/data_collector/iter_2/contract/56/0x1962b3356122d6a56f978e112d14f5e23a25037d/user_prestate.json`
- [4] Mosca user/admin summary around seed & emergencyWithdraw: `artifacts/root_cause/data_collector/iter_4/contract/56/0x1962b3356122d6a56f978e112d14f5e23a25037d/mosca_user_admin_summary_seed_and_emergency.json`
- [5] Extended balance diffs for seed tx: `artifacts/root_cause/data_collector/iter_3/tx/56/0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff/balance_diff.json`
- [6] EmergencyWithdraw trace and balance diffs: `artifacts/root_cause/data_collector/iter_4/tx/56/0xad3b9013331601b8d721671fdb59f2e9e8d30e923a05bc2d2bbcbb8038dde16a/trace_callTracer.json`
- [7] Orchestrator start(...) decompile summary: `artifacts/root_cause/data_collector/iter_3/contract/56/0x851288dcfb39330291015c82a5a93721cc92507a/start_control_flow_summary.txt`