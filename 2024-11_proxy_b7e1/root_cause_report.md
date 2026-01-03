# BSC USDT marketplace drain via unprotected 0x9b3e9b92 call

**Protocol:** BNB Chain marketplace proxy `0xb7e1d1372f2880373d7c5a931cdbaa73c38663c6` with reward token proxy `0x7570fdad10010a06712cae03d2fc2b3a53640aa4`  
**Category:** Protocol logic / access-control bug (`root_cause_category = protocol_bug`)  
**ACT opportunity:** Yes (`is_act = true`)

## Incident Overview & TL;DR

On BNB Chain (chainid 56), a fresh externally owned account (EOA) `0x9f2ecec0145242c094b17807f299ce552a625ac5` deployed a constructor-only helper contract and, within the same transaction, invoked an unprotected function with selector `0x9b3e9b92` on marketplace proxy `0xb7e1...`. This call drained the proxy’s entire on-chain USDT balance of 8,484.92 units and minted 33,939.68 units of the associated reward token `0x7570...` to the helper contract.

The helper immediately swapped the stolen USDT through a public PancakeSwap USDT/WBNB pair into approximately `13.041098705767818172` WBNB, which was unwrapped to BNB and delivered back to the EOA. After accounting for gas and AMM slippage, the attacker realized a net profit of about `13.039081184767818172` BNB. In subsequent blocks, the attacker deposited most of this BNB into a Tornado-like mixer contract to obfuscate the proceeds.

**Root cause (brief):** The implementation behind proxy `0xb7e1...` exposes a function at selector `0x9b3e9b92` that any address can call. Instead of operating on per-user order balances, this function uses the proxy’s global `USDT.balanceOf` and reward-token minting to move all pooled USDT and newly minted reward tokens to an arbitrary recipient, with no access control and no requirement that the caller has any prior deposit or order in the system.

## Key Background

- **Proxy architecture and roles**
  - Marketplace proxy `0xb7e1...` and reward-token proxy `0x7570...` were both deployed on BNB Chain by creator EOA `0xbeb28a030fec8009157d112550e7e2f0b7683c40` as `TransparentUpgradeableProxy` instances.
  - `0xb7e1...` points to implementation `0x0df9d225ccfaa21ceb0b2ab6855b13dffa78d253`, while `0x7570...` points to implementation `0x28221c875bd823b73de945ac590411bc87aa89b2`.
  - Initialization calldata configures USDT `0x55d398326f99059ff775485246999027b3197955` as the settlement token, `0x7570...` as a trading or reward token, and sets owner/admin roles via a ProxyAdmin.

- **Marketplace implementation (0x0df9d2...)**
  - Decompiled code shows an order-management style contract that stores per-order parameters in mappings.
  - Functions like `cancelOrder(uint256)` and `editOrder(uint256,uint256)`:
    - Index into storage by order ID.
    - Require `msg.sender` to equal the stored order owner.
    - Check that the order is not already filled.
    - Perform USDT `transfer` / `transferFrom` for amounts derived from per-order storage.
    - Call the reward token’s `mint(address,uint256)` with selector `0x40c10f19` to mint rewards to the order owner.
  - These paths respect per-order ownership and do not operate on the proxy’s entire token balance.

- **Reward token implementation (0x28221c8...)**
  - Decompiled implementation `0x28221c8...` is an ERC20-like token with 9 decimals and events such as `Transfer`, `Approval`, `RewardMint`, `AuthorizedMinterSet`, `MarketplaceSet`, and `OwnershipTransferred`.
  - Its `mint(address,uint256)` function is gated so that only `marketplace` may mint, and `setMarketplace(address)` is owner-only. The deployment and configuration transactions set `marketplace = 0xb7e1...`, meaning only the marketplace proxy can mint reward tokens.

```solidity
/// From collected reward-token decompiled source (implementation 0x28221c8...)
/// @custom:selector    0x40c10f19
/// @custom:signature   mint(address arg0, uint256 arg1) public
function mint(address arg0, uint256 arg1) public {
    require(arg0 == (address(arg0)));
    require(msg.sender == (address(marketplace)), CustomError_e450d38c());
    // ...
}
```

*Snippet 1 – Reward token `mint` gate: only the configured `marketplace` (here proxy `0xb7e1...`) can mint 0x7570... tokens.*

- **Use of PancakeSwap**
  - The exploit uses public PancakeSwap contracts:
    - Pair `0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae` (USDT/WBNB).
    - Router `0x10ed43c718714eb63d5aa57b78b54704e256024e`.
  - These contracts are standard, verified components and are only used to swap stolen USDT for WBNB/BNB; no AMM bug is involved.

## Vulnerability & Root Cause Analysis

### Intended order-handling behavior

The marketplace implementation `0x0df9d2...` is designed to manage per-user orders. Functions such as `cancelOrder` and `editOrder`:

- Look up structured order data by ID in storage mappings.
- Require that `msg.sender` matches the recorded order owner.
- Enforce status checks (e.g., not already filled or canceled).
- Use per-order amounts stored on-chain to:
  - Move USDT between users and the contract using `transfer` / `transferFrom`.
  - Mint reward tokens to the specific order owner using the reward token’s `mint` function.

These functions therefore maintain a clear relationship between user actions, order state, and token balances.

### Exposed function at selector 0x9b3e9b92

By contrast, the implementation exposes another entry point at selector `0x9b3e9b92`, surfaced via the proxy `0xb7e1...`. Decompiled metadata confirms its presence:

```solidity
/// From collected marketplace decompiled source (implementation 0x0df9d2...)
/// @custom:selector    0x9b3e9b92
/// @custom:signature   Unresolved_9b3e9b92(address arg0, uint256 arg1, uint256 arg2, uint256 arg3, uint256 arg4, uint256 arg5) public pure
function Unresolved_9b3e9b92(address arg0, uint256 arg1, uint256 arg2, uint256 arg3, uint256 arg4, uint256 arg5) public pure {
    require(arg0 == (address(arg0)));
    require(arg3 == arg3);
    require(!arg4 > 0xffffffffffffffff);
    require(!(arg4) > 0xffffffffffffffff);
    require(!arg5 > 0xffffffffffffffff);
}
```

*Snippet 2 – Marketplace decompiled metadata showing a public function at selector `0x9b3e9b92`. The decompiler does not recover its real effects, so we rely on the on-chain trace to understand its behavior.*

The decompiler’s “pure” stub is clearly inconsistent with the observed side effects in the exploit transaction. To accurately characterize the function, we must rely on the concrete trace of the seed transaction, which calls `0x9b3e9b92` through the proxy.

### Behavior observed in the seed transaction trace

The seed transaction `0x864d33d0...` is a contract-creation transaction from EOA `0x9f2e...`. The constructor of the created helper contract `0x9b78...` performs the exploit by:

1. Calling the marketplace proxy `0xb7e1...` with selector `0x9b3e9b92`.
2. Causing the implementation `0x0df9d2...` to:
   - Interact with USDT `0x55d3...` and reward token `0x7570...`.
   - Read the full USDT balance of the proxy via `balanceOf(0xb7e1...)`.
   - Transfer that balance to the helper contract.
   - Mint reward tokens to the helper via the reward-token proxy.
3. Routing the stolen USDT from the helper into the Pancake USDT/WBNB pair, producing WBNB that is ultimately unwrapped into BNB for the attacker EOA.

This behavior is visible in the seed transaction’s balance diff and ERC20 transfers:

```json
{
  "chainid": 56,
  "txhash": "0x864d33d006e5c39c9ee8b35be5ae05a2013e556be3e078e2881b0cc6281bb265",
  "native_balance_deltas": [
    {
      "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "delta_wei": "-13041098705767818172"
    },
    {
      "address": "0x9f2ecec0145242c094b17807f299ce552a625ac5",
      "before_wei": "98371945900000000",
      "after_wei": "13137453130667818172",
      "delta_wei": "13039081184767818172"
    }
  ],
  "erc20_transfers": [
    {
      "token": "0x55d398326f99059ff775485246999027b3197955",
      "from": "0xb7e1d1372f2880373d7c5a931cdbaa73c38663c6",
      "to": "0x9b78b5d9febce2b8868ea6ee2822cb482a85ad74",
      "value": "8484920000000000000000"
    },
    {
      "token": "0x7570fdad10010a06712cae03d2fc2b3a53640aa4",
      "from": "0x0000000000000000000000000000000000000000",
      "to": "0x9b78b5d9febce2b8868ea6ee2822cb482a85ad74",
      "value": "16969840000000000000000"
    }
  ]
}
```

*Snippet 3 – Seed transaction balance diff (`balance_diff.json`): the marketplace proxy `0xb7e1...` sends 8,484.92 USDT (1e18 units) to helper `0x9b78...`, and the reward token mints 16,969.84 × 2 = 33,939.68 units to the same helper. The attacker EOA’s BNB balance increases by ~13.039 BNB, while the WBNB contract balance decreases by ~13.041 WBNB.*

Key points from the trace and balance diff:

- USDT `0x55d3...` flows:
  - From `0xb7e1...` to helper `0x9b78...` for 8,484.92 USDT.
  - From helper `0x9b78...` to Pancake pair `0x16b9...` for the same 8,484.92 USDT.
- Reward token `0x7570...` mints:
  - From the zero address to helper `0x9b78...`, twice, totaling 33,939.68 units.
- Native BNB flows:
  - WBNB contract `0xbb4c...` loses ~13.041 BNB-equivalent.
  - Attacker EOA `0x9f2e...` gains ~13.039 BNB net after gas.

The call trace (callTracer) confirms that this sequence is triggered by a single call through `0xb7e1...` with selector `0x9b3e9b92` originating from the helper’s constructor.

### Missing access control and improper accounting

From the combination of:

- The presence of a public function at selector `0x9b3e9b92` exposed via proxy `0xb7e1...`.
- The reward token gating `mint` to only the `marketplace` address.
- The observed behavior that any address (here, the helper contract) can call `0x9b3e9b92` to:
  - Transfer **all** USDT held by the proxy to an arbitrary recipient.
  - Mint reward tokens to that same recipient.

we conclude:

- **Missing access control:** The function behind `0x9b3e9b92` is not restricted to an owner, operator, or authenticated actor; any unprivileged caller can trigger it via the proxy.
- **Improper accounting:** Rather than referencing a specific order or user balance, the function operates on the proxy’s **global** USDT balance via `balanceOf(proxy)` and mints rewards based solely on that balance, ignoring per-user deposits and order state.
- **Proxy-level exposure:** Because `0xb7e1...` is a `TransparentUpgradeableProxy` with no additional gating, this implementation bug directly exposes user funds held by the proxy.

This combination creates a straightforward exploit predicate: whenever the proxy holds USDT, any address capable of sending a transaction can drain the entire balance and mint associated rewards, then liquidate for profit.

## Adversary Flow Analysis

### Adversary-related accounts

- **EOA `0x9f2ecec0145242c094b17807f299ce552a625ac5` (attacker origin)**
  - Originates the seed transaction `0x864d33d0...`.
  - Receives the final BNB profit after WBNB is unwrapped.
  - Later sends multiple deposits to a Tornado-like mixer contract `0x0d5550d52428e7e3175bfc9550207e4ad3859b17`.

- **Helper contract `0x9b78b5d9febce2b8868ea6ee2822cb482a85ad74`**
  - Created in the seed transaction as a constructor-only helper.
  - In its constructor, calls `0xb7e1...` with selector `0x9b3e9b92` to:
    - Receive 8,484.92 USDT and 33,939.68 reward tokens.
    - Forward the USDT into the Pancake USDT/WBNB pair to generate WBNB.
  - Does not initiate further transactions after construction.

- **Victim contracts**
  - Marketplace proxy `0xb7e1d1372f2880373d7c5a931cdbaa73c38663c6`:
    - Holds pooled USDT on behalf of users.
    - Exposes the vulnerable `0x9b3e9b92` function.
  - Reward token proxy `0x7570fdad10010a06712cae03d2fc2b3a53640aa4`:
    - Mints reward tokens to the helper when called by `0xb7e1...`.

### Exploit transaction: deployment and drain

The exploit is executed entirely within a single transaction:

```json
{
  "hash": "0x864d33d006e5c39c9ee8b35be5ae05a2013e556be3e078e2881b0cc6281bb265",
  "from": "0x9f2ecec0145242c094b17807f299ce552a625ac5",
  "to": "",
  "value": "0",
  "functionName": "atInversebrah(int248 a, uint48[] b, uint32 c, bytes20[] d, bytes30[] e)"
}
```

*Snippet 4 – Seed transaction summary from the attacker’s txlist: an EOA contract-creation transaction whose constructor performs the exploit logic.*

Lifecycle within this transaction:

1. **Helper deployment**
   - EOA `0x9f2e...` sends a contract-creation transaction with zero BNB value.
   - The deployed helper contract is assigned address `0x9b78...` (nonce 0 from the attacker EOA).

2. **Exploit call from constructor**
   - The helper’s constructor calls marketplace proxy `0xb7e1...` with selector `0x9b3e9b92`.
   - The proxy delegates to implementation `0x0df9d2...`, triggering the vulnerable logic described above.
   - As a result:
     - 8,484.92 USDT moves from `0xb7e1...` to `0x9b78...`.
     - 33,939.68 reward tokens are minted to `0x9b78...` via proxy `0x7570...`.

3. **Swap to BNB**
   - Helper `0x9b78...` swaps the stolen USDT into WBNB via Pancake pair `0x16b9...`.
   - WBNB is then unwrapped/forwarded as BNB to the attacker EOA `0x9f2e...`.
   - The net effect (as seen in `native_balance_deltas`) is:
     - WBNB contract `0xbb4c...` loses ~13.041 BNB-equivalent.
     - Attacker EOA `0x9f2e...` gains ~13.039 BNB after gas.

### Profit obfuscation via mixer deposits

After realizing the profit, the attacker EOA disperses the BNB into a Tornado-like mixer:

```json
[
  {
    "hash": "0x3a34200e5db502a2593d3cfcf595e477ea2f351c467626f8d2b7be7a717be35e",
    "from": "0x9f2ecec0145242c094b17807f299ce552a625ac5",
    "to": "0x0d5550d52428e7e3175bfc9550207e4ad3859b17",
    "value": "10000000000000000000",
    "functionName": "deposit(address _tornado, bytes32 _commitment, bytes _encryptedNote)"
  },
  {
    "hash": "0x15395547c4ccf60829b54c9ac323380ad5e55e762a84b360d987fff986c61c44",
    "from": "0x9f2ecec0145242c094b17807f299ce552a625ac5",
    "to": "0x0d5550d52428e7e3175bfc9550207e4ad3859b17",
    "value": "1000000000000000000",
    "functionName": "deposit(address _tornado, bytes32 _commitment, bytes _encryptedNote)"
  }
]
```

*Snippet 5 – Example mixer deposits from the attacker’s txlist: 10 BNB and 1 BNB transfers to a Tornado-like mixer contract via `deposit(...)`. Additional 1 BNB and 0.1 BNB deposits follow in later transactions.*

These transactions confirm that:

- The same EOA that initiated the exploit (`0x9f2e...`) controls the profits.
- The funds are deliberately routed into a privacy-preserving contract, hindering further attribution.

### Protocol deployment and configuration

Prior to the exploit:

- EOA `0xbeb28a0...` deploys the reward-token and marketplace proxies (`0x7570...` and `0xb7e1...`).
- Configuration transactions:
  - Set `marketplace = 0xb7e1...` on the reward token, allowing it to mint tokens.
  - Set `opWallet` on `0xb7e1...`, used in a zero-value USDT transfer observed in the exploit trace.
- No interactions between the creator EOA and the attacker EOA are observed in the artifact set.

This setup confirms that the vulnerable marketplace and its reward token were configured as intended before an unrelated EOA exploited the exposed function.

## Impact & Losses

### On-chain token movements

- **USDT loss**
  - The proxy `0xb7e1...` loses its entire on-chain USDT balance of 8,484.92 units to the helper contract `0x9b78...` in the exploit transaction.
  - No compensating inflows to the proxy are observed in the same transaction.

- **Reward token minting**
  - A total of 33,939.68 units of the reward token `0x7570...` are minted from the zero address to helper `0x9b78...`.
  - This mint is authorized because `0xb7e1...` is configured as `marketplace` on the reward token contract.

- **BNB profit**
  - Using the seed transaction balance diff:
    - Attacker EOA `0x9f2e...` increases its BNB balance from `0.0983719459` BNB to `13.137453130667818172` BNB.
    - The net delta is `13.039081184767818172` BNB after gas.
  - WBNB contract `0xbb4c...` loses `13.041098705767818172` WBNB-equivalent, consistent with AMM swap outputs and gas costs.

### Economic interpretation

- The protocol’s marketplace proxy loses at least 8,484.92 USDT of pooled liquidity and issues 33,939.68 reward tokens to the attacker-controlled helper.
- The attacker realizes a net profit of approximately 13.039 BNB after gas, which is then partially obfuscated via mixer deposits.
- The exact off-chain distribution of losses (i.e., which users funded the drained USDT) cannot be derived from the available on-chain artifacts, but the value transfer from the marketplace proxy to the adversary cluster is unambiguous.

## References

- **[1] Seed transaction call trace (callTracer)**
  - `debug_traceTransaction` with callTracer for `0x864d33d0...`, showing the helper’s constructor call into `0xb7e1...::0x9b3e9b92`, USDT and reward-token calls, and the AMM swap path.

- **[2] Seed transaction pre-state (prestateTracer)**
  - Prestate tracer output for the same transaction, capturing balances and storage before execution, used to reason about sigma_B and initial holdings.

- **[3] Marketplace implementation decompiled source**
  - Decompiled Solidity for implementation `0x0df9d2...`, including the protected order functions and the unresolved `0x9b3e9b92` entry point.

- **[4] Reward token implementation decompiled source**
  - Decompiled Solidity for implementation `0x28221c8...`, including `mint(address,uint256)` and `setMarketplace(address)` which demonstrate the marketplace’s authority to mint tokens.

- **[5] Seed transaction balance diff**
  - `balance_diff.json` for the seed transaction, used to quantify USDT drain and BNB profit.

- **[6] Creator EOA deployment and configuration txlist**
  - Transaction list for creator EOA `0xbeb28a0...`, showing deployment of the marketplace and reward-token proxies and subsequent configuration calls.

- **[7] Attacker EOA txlist**
  - Transaction list for attacker EOA `0x9f2e...`, including the exploit transaction and subsequent mixer deposits used to obfuscate stolen funds.

