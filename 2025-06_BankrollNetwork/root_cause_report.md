# BankrollNetworkStack WBNB Flashswap Dividend Drain on BNB Chain

## Incident Overview & TL;DR
On BNB Chain, an unprivileged adversary EOA 0x2dea406bb3bea68d6be8d9ef0071fdf63082fb52 deployed a small helper contract 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2 and, in a single flashswap-assisted transaction, used it to call BankrollNetworkStack::donatePool, ::buy, ::sell, and ::withdraw in a carefully ordered sequence that drained almost all WBNB held by BankrollNetworkStack 0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e into the helper and then into the EOA.

### Root Cause Summary
BankrollNetworkStack’s dividend and sell/withdraw accounting allows any address to (a) inject a large amount into dividendBalance_ via donatePool and buy fees, (b) immediately force a time-weighted release of the entire accumulated dividendBalance_ into profitPerShare_ via distribute() while holding a temporary token position, and then (c) sell and withdraw to capture a large WBNB payout backed by long-term user deposits and fees; this protocol bug, combined with a Pancake flashborrow, yields a deterministic, permissionless profit opportunity.

## Key Background
- BankrollNetworkStack is a dividend-paying token scheme deployed on BNB Chain that accepts WBNB deposits via buy/buyFor, mints internal accounting tokens 1:1 minus a 10% entry fee, charges a 10% exit fee on sells, and tracks accumulated fees and donations in dividendBalance_; a time-based distribute() function periodically moves a fraction of dividendBalance_ into profitPerShare_, from which holders can withdraw dividends as WBNB via withdraw().
- The contract exposes a public donatePool(uint amount) function that transfers WBNB from msg.sender into the contract and adds the same amount to dividendBalance_ without minting tokens for the donor, and a buy/buyFor path that both mints new tokens and, through allocateFees(), adds 80% of the 10% entry fee to dividendBalance_ while directing 20% to an elephantReserve_ buyback mechanism.
- The distribute() function is called from buyFor, sell, withdraw, and reinvest, and when invoked with SafeMath.safeSub(now, lastPayout) > distributionInterval (2 seconds) and tokenSupply_ > 0, it treats dividendBalance_ as a pool of unallocated dividends: it computes a per-second share at 2% of dividendBalance_ per day and, multiplied by the elapsed time since lastPayout, moves profit from dividendBalance_ into profitPerShare_ scaled by tokenSupply_.
- Because distribute() only considers the current dividendBalance_ and time since lastPayout and is callable from public entry points, any address that can control the timing and ordering of donatePool/buy/sell/withdraw calls, including within a single transaction using flashborrowed WBNB, can influence when a large accumulated dividendBalance_ is released and which token holders are in place to receive the resulting dividends.

## ACT Opportunity & Classification
- **Protocol name**: BankrollNetworkStack
- **Is ACT**: true
- **Root cause category**: protocol_bug
- **Pre-state block height B**: 51715417 on BNB Chain (chainid 56)

### Pre-state σ_B (before exploit)
BNB Chain (chainid 56) state immediately before block 51715418, in which BankrollNetworkStack 0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e holds approximately 29.7865 WBNB, tokenSupply_ is about 20.4011e18 units, profitPerShare_ and payoutsTo_ reflect historical fee and donation accruals, and dividendBalance_ is zero, with no special privileges granted to the eventual adversary EOA 0x2dea406bb3bea68d6be8d9ef0071fdf63082fb52 or helper 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2.

**Evidence supporting σ_B:**
- artifacts/root_cause/data_collector/iter_2/contract/56/0xadefb902cab716b8043c5231ae9a50b8b4ee7c4e/state/state_block_51715417.json
- artifacts/root_cause/data_collector/iter_1/tx/56/0x7226b3947c7e8651982e5bd777bca52d03ea31d19b515dec123595a4435ae22c/erc20_balance_diff_manual.json
- artifacts/root_cause/data_collector/iter_1/contract/56/0xadefb902cab716b8043c5231ae9a50b8b4ee7c4e/source/src/Contract.sol

### Transaction sequence b
- **Tx 1** (adversary-crafted on chainid 56): 0xedb33f085dbb70a9bd0c1d04154a18113cbe9464be882d8a990f1a0e579f502a
  - Inclusion feasibility: An unprivileged EOA 0x2dea406bb3bea68d6be8d9ef0071fdf63082fb52 deploys helper contract 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2 in a standard contract-creation transaction paying its own gas; contract deployment is permissionless on BNB Chain and uses no special privileges.
  - Notes: Helper deployment transaction for 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2 by the eventual adversary EOA; see artifacts/root_cause/data_collector/iter_2/address/56/0x2dea406bb3bea68d6be8d9ef0071fdf63082fb52/txlist_eoa_lifetime.json.
- **Tx 2** (adversary-crafted on chainid 56): 0x7226b3947c7e8651982e5bd777bca52d03ea31d19b515dec123595a4435ae22c
  - Inclusion feasibility: From the same unprivileged EOA 0x2dea406bb3bea68d6be8d9ef0071fdf63082fb52, the helper is called with a 0-value transaction that opens a PancakePair::swap flashborrow of 2,000 WBNB, interacts only with public functions donatePool, buy, sell, and withdraw on BankrollNetworkStack, and repays the flashborrow with 2,005.2 WBNB; all calls are standard contract interactions using public ABIs and a public Pancake pair, requiring no special roles, so any searcher/attacker with sufficient gas and the same calldata can have the transaction included.
  - Notes: Flashswap-assisted exploit transaction that donates WBNB to BankrollNetworkStack, forces distribution of accumulated dividendBalance_ via distribute(), then sells and withdraws to extract WBNB; see artifacts/root_cause/seed/56/0x7226b3...ae22c/* and artifacts/root_cause/data_collector/iter_1/tx/56/0x7226b3...ae22c/*.

### Success Predicate (Profit)
- **Reference asset**: WBNB
- **Adversary address**: 0x2dea406bb3bea68d6be8d9ef0071fdf63082fb52
- **Value before**: 0 WBNB
- **Value after**: 24.586528993752124174 WBNB
- **Value delta after gas**: 24.585658761752124174 WBNB

Profit is derived directly from the following concrete balance diffs:

```json
// Manual ERC20 balance diffs for key addresses across the seed tx 0x7226b3...ae22c
{
  "chainid": 56,
  "txhash": "0x7226b3947c7e8651982e5bd777bca52d03ea31d19b515dec123595a4435ae22c",
  "entries": [
    {
      "token_label": "WBNB",
      "token_address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "holder": "0x2dea406bb3bea68d6be8d9ef0071fdf63082fb52",
      "block_before": 51715417,
      "block_after": 51715418,
      "before": "0",
      "after": "24586528993752124174",
      "delta": "24586528993752124174"
    },
    {
      "token_label": "WBNB",
      "token_address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "holder": "0xe63a5c681cacb8484c8a989cfdd41b8e3b7a2be2",
      "block_before": 51715417,
      "block_after": 51715418,
      "before": "0",
      "after": "0",
      "delta": "0"
    },
    {
      "token_label": "WBNB",
      "token_address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "holder": "0xadefb902cab716b8043c5231ae9a50b8b4ee7c4e",
      "block_before": 51715417,
      "block_after": 51715418,
      "before": "29786528993752134174",
      "after": "10000",
      "delta": "-29786528993752124174"
    },
    {
      "token_label": "WBNB",
      "token_address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
      "holder": "0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae",
      "block_before": 51715417,
      "block_after": 51715418,
      "before": "26789857549452404185697",
      "after": "26795144831577047400224",
      "delta": "5287282124643214527"
    },
    {
      "token_label": "USDT",
      "token_address": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x2dea406bb3bea68d6be8d9ef0071fdf63082fb52",
      "block_before": 51715417,
      "block_after": 51715418,
      "before": "2178712759435751194221",
      "after": "2178712759435751194221",
      "delta": "0"
    },
    {
      "token_label": "USDT",
      "token_address": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xe63a5c681cacb8484c8a989cfdd41b8e3b7a2be2",
      "block_before": 51715417,
      "block_after": 51715418,
      "before": "0",
      "after": "0",
      "delta": "0"
    },
    {
      "token_label": "USDT",
      "token_address": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0xadefb902cab716b8043c5231ae9a50b8b4ee7c4e",
      "block_before": 51715417,
      "block_after": 51715418,
      "before": "0",
      "after": "0",
      "delta": "0"
    },
    {
      "token_label": "USDT",
      "token_address": "0x55d398326f99059ff775485246999027b3197955",
      "holder": "0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae",
      "block_before": 51715417,
      "block_after": 51715418,
      "before": "17263089746768279872932435",
      "after": "17263033646776441261312534",
      "delta": "-56099991838611619901"
    }
  ]
}
```

_Caption: WBNB/USDT before/after balances for the adversary EOA, helper, BankrollNetworkStack, and PancakePair over blocks 51715417 → 51715418._

```json
// Native BNB balance diff for the adversary EOA across the same tx
{
  "chainid": 56,
  "txhash": "0x7226b3947c7e8651982e5bd777bca52d03ea31d19b515dec123595a4435ae22c",
  "native_balance_deltas": [
    {
      "address": "0x2dea406bb3bea68d6be8d9ef0071fdf63082fb52",
      "before_wei": "994011827100000001",
      "after_wei": "993141595100000001",
      "delta_wei": "-870232000000000"
    }
  ],
  "erc20_balance_deltas": [],
  "erc20_balance_delta_errors": [],
  "errors": []
}
```

_Caption: BNB gas cost for the adversary EOA, used to net out WBNB-equivalent profit._

## Vulnerability & Root Cause Analysis
### Vulnerability Brief
BankrollNetworkStack allows any address to inject WBNB into dividendBalance_ via donatePool and buy/sell fees, then immediately trigger distribute() and subsequently sell and withdraw to capture a large share of both historical and newly injected dividends, all within a single transaction using temporary flashborrowed capital, draining contract-held WBNB from long-term depositors.

### Root Cause Detail
In BankrollNetworkStack (artifacts/root_cause/data_collector/iter_1/contract/56/0xadef...7c4e/source/src/Contract.sol), dividendBalance_ is increased whenever someone calls donatePool(amount) or when buy/sell fees are allocated via allocateFees(fee). The time-based distribute() function, called from public functions buyFor, sell, withdraw, and reinvest, computes profit = dividendBalance_ * payoutRate_ / 100 * (now - lastPayout) / 24h (with payoutRate_ = 2) and moves this profit from dividendBalance_ into profitPerShare_ in a single step, updating lastPayout to now. Critically, there is no restriction on who can call donatePool or trigger distribute(), and distribute() uses the current dividendBalance_ and now - lastPayout, not per-user state, to determine the amount of profit allocated. In the incident, immediately before block 51715418, BankrollNetworkStack has tokenSupply_ ≈ 20.4011e18, dividendBalance_ = 0, and a large effective (now - lastPayout) accumulated since the last distribution (inferred from the delta in profitPerShare_). During the flashswap-assisted seed transaction, the helper (i) donates 1,000 WBNB via donatePool, (ii) buys 240 WBNB of tokens (minting 216 WBNB-worth of tokens and adding 19.2 WBNB to dividendBalance_ via fees), and then (iii) triggers distribute() at the end of buyFor. At this moment, dividendBalance_ includes both the newly donated/fee amounts and previously undistributed dividends, so distribute() moves approximately 110.4544 WBNB (computed from the change in profitPerShare_) from dividendBalance_ into profitPerShare_, leaving dividendBalance_ at zero (as seen in the state changes inside the buy trace). The helper now holds 216 WBNB-worth of tokens whose payoutsTo_ have been updated relative to the increased profitPerShare_. Immediately after, the helper calls sell(216e18), burning its tokens, paying a 10% exit fee (21.6 WBNB) of which 17.28 WBNB is added back to dividendBalance_, and then calls withdraw(), which transfers myDividends() = 1,363.851513770135689714 WBNB from BankrollNetworkStack to the helper. The combination of (a) public donatePool, (b) public distribute() triggered via buyFor with a large pre-existing dividendBalance_ and long time since lastPayout, and (c) sell/withdraw that allow the same address to monetize the newly increased profitPerShare_ in the same transaction, creates a deterministic way for an attacker to convert accumulated dividends and their own temporary donation/fees into an immediate WBNB payout funded by BankrollNetworkStack’s reserves. Since the attacker uses a flashborrow from PancakePair to source the initial 2,000 WBNB and repays it at the end of the transaction, their only net cost is gas; the profit is realized as additional WBNB at their EOA. This behavior is not gated by any privileged role or off-chain coordination and constitutes a protocol accounting bug: the dividend release mechanism can be forced by any participant at a time and in a state that maximally benefits their temporary position.

### Vulnerable Components
- BankrollNetworkStack 0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e on BNB Chain; functions donatePool(uint256), buy(uint256)/buyFor(address,uint256), distribute(), sell(uint256), and withdraw().

### Exploit Preconditions
- BankrollNetworkStack has accumulated a non-trivial dividendBalance_ and a significant (now - lastPayout) time interval since the last distribution, so that a call to distribute() will move a large amount of dividends into profitPerShare_.
- The adversary can access sufficient WBNB, for example via a PancakePair::swap flashborrow, to call donatePool and buyFor with substantial amounts, amplifying dividendBalance_ just before triggering distribute().
- The adversary can call buyFor, sell, and withdraw in succession from the same address, within a single transaction, so that they temporarily hold a token position when distribute() is executed and then immediately realize the resulting dividends and exit their position.
- No protocol-level restrictions exist on who can call donatePool, buy, sell, or withdraw, and there are no safeguards in distribute() to prevent a single actor from forcing a large release of dividendBalance_ into profitPerShare_ at a chosen time.

### Violated Security Principles
- Dividends and fee distributions should not be fully controllable by individual actors in a way that allows them to front-run or force the emission of long-accumulated rewards to benefit a temporary position.
- The contract fails to ensure that the timing and amount of dividend distribution is independent of an attacker’s ability to inject capital and trigger distribution within a single transaction, breaking assumptions about fair, time-smoothed reward accrual.
- Economic invariants intended to protect pooled liquidity (that withdrawals should roughly track long-term deposits and fees) are violated by allowing a flashborrower to convert accumulated dividendBalance_ plus fees into an immediate, self-directed payout.

```solidity
// Excerpts from BankrollNetworkStack Contract.sol showing dividend accounting

    /// @dev This is how you pump pure "drip" dividends into the system
    function donatePool(uint amount) public returns (uint256) {
        require(token.transferFrom(msg.sender, address(this),amount));

        dividendBalance_ += amount;

        emit onDonation(msg.sender, amount,now);
    }

    /// @dev Converts all incoming eth to tokens for the caller, and passes down the referral addy (if any)
    function buy(uint buy_amount) public returns (uint256)  {
        return buyFor(msg.sender, buy_amount);
    }


    /// @dev Converts all incoming eth to tokens for the caller, and passes down the referral addy (if any)
    function buyFor(address _customerAddress, uint buy_amount) public returns (uint256)  {
        require(token.transferFrom(msg.sender, address(this), buy_amount));
        totalDeposits += buy_amount;
        uint amount = purchaseTokens(_customerAddress, buy_amount);

        emit onLeaderBoard(_customerAddress,
            stats[_customerAddress].invested,
            tokenBalanceLedger_[_customerAddress],
            stats[_customerAddress].withdrawn,
            now
        );

        //distribute
        distribute();

        return amount;
    }

    /**
     * @dev Fallback function to return any TRX/ETH accidentally sent to the contract
     */
    //to recieve ETH from uniswapV2Router when swaping
    receive() external payable {}

    /// @dev Converts all of caller's dividends to tokens.
    function reinvest() onlyStronghands public {
        // fetch dividends
        uint256 _dividends = myDividends();
        // retrieve ref. bonus later in the code

        // pay out the dividends virtually
        address _customerAddress = msg.sender;
        payoutsTo_[_customerAddress] += (int256) (_dividends * magnitude);

        // dispatch a buy order with the virtualized "withdrawn dividends"
        uint256 _tokens = purchaseTokens(msg.sender, _dividends);

        // fire event
        emit onReinvestment(_customerAddress, _dividends, _tokens, now);

        //Stats
        stats[_customerAddress].reinvested = SafeMath.add(stats[_customerAddress].reinvested, _dividends);
        stats[_customerAddress].xReinvested += 1;

        emit onLeaderBoard(_customerAddress,
            stats[_customerAddress].invested,
            tokenBalanceLedger_[_customerAddress],
            stats[_customerAddress].withdrawn,
            now
        );

        //distribute
        distribute();
    }

    /// @dev Withdraws all of the callers earnings.
    function withdraw() onlyStronghands public {
        // setup data
        address _customerAddress = msg.sender;
        uint256 _dividends = myDividends();

        // update dividend tracker
        payoutsTo_[_customerAddress] += (int256) (_dividends * magnitude);


        // lambo delivery service
        token.transfer(_customerAddress,_dividends);

        //stats
        stats[_customerAddress].withdrawn = SafeMath.add(stats[_customerAddress].withdrawn, _dividends);
        stats[_customerAddress].xWithdrawn += 1;
        totalTxs += 1;
        totalClaims += _dividends;

        // fire event
        emit onWithdraw(_customerAddress, _dividends, now);

        emit onLeaderBoard(_customerAddress,
            stats[_customerAddress].invested,
            tokenBalanceLedger_[_customerAddress],
            stats[_customerAddress].withdrawn,
            now
        );

        //distribute
        distribute();
    }


    /// @dev Liquifies tokens to eth.
    function sell(uint256 _amountOfTokens) onlyBagholders public {
        // setup data
        address _customerAddress = msg.sender;

        require(_amountOfTokens <= tokenBalanceLedger_[_customerAddress]);


        // data setup
        uint256 _undividedDividends = SafeMath.mul(_amountOfTokens, exitFee_) / 100;
        uint256 _taxedeth = SafeMath.sub(_amountOfTokens, _undividedDividends);

        // burn the sold tokens
        tokenSupply_ = SafeMath.sub(tokenSupply_, _amountOfTokens);
        tokenBalanceLedger_[_customerAddress] = SafeMath.sub(tokenBalanceLedger_[_customerAddress], _amountOfTokens);

        // update dividends tracker
        int256 _updatedPayouts = (int256) (profitPerShare_ * _amountOfTokens + (_taxedeth * magnitude));
        payoutsTo_[_customerAddress] -= _updatedPayouts;


        //drip and buybacks
        allocateFees(_undividedDividends);

        // fire event
        emit onTokenSell(_customerAddress, _amountOfTokens, _taxedeth, now);

        //distribute
        distribute();
    }

    /**
    * @dev Transfer tokens from the caller to a new holder.
    *  Zero fees
    */
    function transfer(address _toAddress, uint256 _amountOfTokens) onlyBagholders external returns (bool) {
        // setup
        address _customerAddress = msg.sender;

        // make sure we have the requested tokens
        require(_amountOfTokens <= tokenBalanceLedger_[_customerAddress]);

        // withdraw all outstanding dividends first
        if (myDividends() > 0) {
            withdraw();
        }


        // exchange tokens
        tokenBalanceLedger_[_customerAddress] = SafeMath.sub(tokenBalanceLedger_[_customerAddress], _amountOfTokens);
        tokenBalanceLedger_[_toAddress] = SafeMath.add(tokenBalanceLedger_[_toAddress], _amountOfTokens);

        // update dividend trackers
        payoutsTo_[_customerAddress] -= (int256) (profitPerShare_ * _amountOfTokens);
        payoutsTo_[_toAddress] += (int256) (profitPerShare_ * _amountOfTokens);



        /* Members
            A player can be initialized by buying or receiving and we want to add the user ASAP
         */
        if (stats[_toAddress].invested == 0 && stats[_toAddress].receivedTokens == 0) {
            players += 1;
        }

        //Stats
        stats[_customerAddress].xTransferredTokens += 1;
        stats[_customerAddress].transferredTokens += _amountOfTokens;
        stats[_toAddress].receivedTokens += _amountOfTokens;
        stats[_toAddress].xReceivedTokens += 1;
        totalTxs += 1;

        // fire event
        emit onTransfer(_customerAddress, _toAddress, _amountOfTokens,now);

        emit onLeaderBoard(_customerAddress,
            stats[_customerAddress].invested,
            tokenBalanceLedger_[_customerAddress],
            stats[_customerAddress].withdrawn,
            now
        );

        emit onLeaderBoard(_toAddress,
            stats[_toAddress].invested,
            tokenBalanceLedger_[_toAddress],
            stats[_toAddress].withdrawn,
            now
        );

        // ERC20
        return true;
    }


    /*=====================================
    =      HELPERS AND CALCULATORS        =
    =====================================*/

    /**
     * @dev Method to view the current eth stored in the contract
     */
    function totalTokenBalance() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    /// @dev Retrieve the total token supply.
    function totalSupply() public view returns (uint256) {
        return tokenSupply_;
    }

    /// @dev Retrieve the tokens owned by the caller.
    function myTokens() public view returns (uint256) {
        address _customerAddress = msg.sender;
        return balanceOf(_customerAddress);
    }

    /**
     * @dev Retrieve the dividends owned by the caller.
     */
    function myDividends() public view returns (uint256) {
        address _customerAddress = msg.sender;
        return dividendsOf(_customerAddress);
    }

    /// @dev Retrieve the token balance of any single address.
    function balanceOf(address _customerAddress) public view returns (uint256) {
        return tokenBalanceLedger_[_customerAddress];
    }

    /// @dev Retrieve the token balance of any single address.
    function tokenBalance(address _customerAddress) public view returns (uint256) {
        return _customerAddress.balance;
    }

    /// @dev Retrieve the dividend balance of any single address.
    function dividendsOf(address _customerAddress) public view returns (uint256) {
        return (uint256) ((int256) (profitPerShare_ * tokenBalanceLedger_[_customerAddress]) - payoutsTo_[_customerAddress]) / magnitude;
    }


    /// @dev Return the sell price of 1 individual token.
    function sellPrice() public pure returns (uint256) {
        uint256 _eth = 1e18;
        uint256 _dividends = SafeMath.div(SafeMath.mul(_eth, exitFee_), 100);
        uint256 _taxedeth = SafeMath.sub(_eth, _dividends);

        return _taxedeth;

    }

    /// @dev Return the buy price of 1 individual token.
    function buyPrice() public pure returns (uint256) {
        uint256 _eth = 1e18;
        uint256 _dividends = SafeMath.div(SafeMath.mul(_eth, entryFee_), 100);
        uint256 _taxedeth = SafeMath.add(_eth, _dividends);

        return _taxedeth;

    }

    /// @dev Function for the frontend to dynamically retrieve the price scaling of buy orders.
    function calculateTokensReceived(uint256 _ethToSpend) public pure returns (uint256) {
        uint256 _dividends = SafeMath.div(SafeMath.mul(_ethToSpend, entryFee_), 100);
        uint256 _taxedeth = SafeMath.sub(_ethToSpend, _dividends);
        uint256 _amountOfTokens = _taxedeth;

        return _amountOfTokens;
    }

    /// @dev Function for the frontend to dynamically retrieve the price scaling of sell orders.
    function calculateethReceived(uint256 _tokensToSell) public view returns (uint256) {
        require(_tokensToSell <= tokenSupply_);
        uint256 _eth = _tokensToSell;
        uint256 _dividends = SafeMath.div(SafeMath.mul(_eth, exitFee_), 100);
        uint256 _taxedeth = SafeMath.sub(_eth, _dividends);
        return _taxedeth;
    }


    /// @dev Stats of any single address
    function statsOf(address _customerAddress) public view returns (uint256[14] memory){
        Stats memory s = stats[_customerAddress];
        uint256[14] memory statArray = [s.invested, s.withdrawn, s.rewarded, s.contributed, s.transferredTokens, s.receivedTokens, s.xInvested, s.xRewarded, s.xContributed, s.xWithdrawn, s.xTransferredTokens, s.xReceivedTokens, s.reinvested, s.xReinvested];
        return statArray;
    }


    function dailyEstimate(address _customerAddress) public view returns (uint256){
        uint256 share = dividendBalance_.mul(payoutRate_).div(100);

        return (tokenSupply_ > 0) ? share.mul(tokenBalanceLedger_[_customerAddress]).div(tokenSupply_) : 0;
    }


    function allocateFees(uint fee) private {

        // 1/5 paid out instantly to Elephant holders
        uint256 instant = fee.div(5); 

       
        //If buy backs are enabled split the fee
        if (buybackEnabled) {
             
             //add the instant fee to the reserve
            elephantReserve_ = elephantReserve_.add(instant);
            dividendBalance_ = dividendBalance_.add(fee).sub(instant);
        } else {
            //add the entire fee to the dividend balance
            //this only happens when there is an issue with the buy back process.
            //If Pancake upgrades liquidity pools
            dividendBalance_ = dividendBalance_.add(fee); 
        }
        
    }

    function distribute() private {

        if (now.safeSub(lastBalance_) > balanceInterval) {
            emit onBalance(totalTokenBalance(), now);
            lastBalance_ = now;
        }


        if (SafeMath.safeSub(now, lastPayout) > distributionInterval && tokenSupply_ > 0) {

            //A portion of the dividend is paid out according to the rate
            uint256 share = dividendBalance_.mul(payoutRate_).div(100).div(24 hours);
            //divide the profit by seconds in the day
            uint256 profit = share * now.safeSub(lastPayout);
            //share times the amount of time elapsed
            dividendBalance_ = dividendBalance_.safeSub(profit);

            //Apply divs
            profitPerShare_ = SafeMath.add(profitPerShare_, (profit * magnitude) / tokenSupply_);

            lastPayout = now;
        }

    }



    /*==========================================
    =            INTERNAL FUNCTIONS            =
    ==========================================*/

    /// @dev Internal function to actually purchase the tokens.
    function purchaseTokens(address _customerAddress, uint256 _incomingeth) internal returns (uint256) {

        /* Members */
        if (stats[_customerAddress].invested == 0 && stats[_customerAddress].receivedTokens == 0) {
            players += 1;
        }

        totalTxs += 1;
```

_Caption: BankrollNetworkStack donatePool, buyFor, sell/withdraw, and distribute logic that enables forced release of dividendBalance_ into profitPerShare_ for a temporary holder._

## Adversary Flow Analysis
### Strategy Overview
The adversary deploys a helper contract, then in a single flashswap-assisted transaction borrows WBNB from a Pancake pair, donates and buys into BankrollNetworkStack to pump and immediately release dividendBalance_ into profitPerShare_, sells and withdraws to extract WBNB, repays the flashborrow, and leaves the profit at the EOA.

### Adversary-Related Accounts
- 0x2dea406bb3bea68d6be8d9ef0071fdf63082fb52 (chainid 56): EOA=True, contract=False – EOA is the sender of both the helper deployment transaction 0xedb33f0... and the exploit transaction 0x7226b3..., and it is the final recipient of 24.586528993752124174 WBNB according to artifacts/root_cause/data_collector/iter_1/tx/56/0x7226b3...ae22c/erc20_balance_diff_manual.json.
- 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2 (chainid 56): EOA=False, contract=True – Helper contract deployed by the adversary EOA in tx 0xedb33f0..., serves as the intermediate caller of PancakePair::swap and BankrollNetworkStack::donatePool/buy/sell/withdraw in the exploit tx 0x7226b3..., and temporarily holds and routes WBNB balances during the attack before forwarding the net profit to the EOA.

### Victim Candidates
- BankrollNetworkStack at 0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e on BNB Chain (chainid 56)
- PancakePair WBNB/USDT at 0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE on BNB Chain (chainid 56)

### Adversary contract deployment
EOA 0x2dea406bb3bea68d6be8d9ef0071fdf63082fb52 deploys helper contract 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2 in the same block as the exploit, setting up a reusable entry point that can open Pancake flashswaps and interact with BankrollNetworkStack.

Evidence: artifacts/root_cause/data_collector/iter_2/address/56/0x2dea406bb3bea68d6be8d9ef0071fdf63082fb52/txlist_eoa_lifetime.json

### Flashborrow and dividend manipulation
Helper contract 0xE63a... opens a PancakePair::swap to flashborrow 2,000 WBNB, donates 1,000 WBNB to BankrollNetworkStack via donatePool, buys 240 WBNB worth of tokens (minting 216 WBNB of internal tokens and adding 19.2 WBNB in fees to dividendBalance_), triggers distribute() at the end of buyFor to move about 110.4544 WBNB from dividendBalance_ to profitPerShare_, and then sells the 216 WBNB of tokens and withdraws 1,363.8515 WBNB in dividends.

Evidence: artifacts/root_cause/seed/56/0x7226b3...ae22c/trace.cast.log; artifacts/root_cause/data_collector/iter_1/tx/56/0x7226b3...ae22c/trace.cast.log; artifacts/root_cause/data_collector/iter_2/contract/56/0xadef...7c4e/state/state_block_51715417.json and state_block_51715418.json; artifacts/root_cause/data_collector/iter_1/contract/56/0xadef...7c4e/source/src/Contract.sol

### Flashloan repayment and profit realization
Using the 1,363.8515 WBNB withdrawn from BankrollNetworkStack plus remaining WBNB from the flashborrowed pool, the helper repays 2,005.2 WBNB to the Pancake pair and transfers 24.586528993752124174 WBNB to the adversary EOA, leaving helper balances at zero and increasing the EOA’s WBNB balance by 24.5865 while its BNB balance decreases by only 0.000870232 for gas.

Evidence: artifacts/root_cause/data_collector/iter_1/tx/56/0x7226b3...ae22c/erc20_balance_diff_manual.json; artifacts/root_cause/data_collector/iter_1/tx/56/0x7226b3...ae22c/balance_diff.json; artifacts/root_cause/seed/56/0x7226b3...ae22c/trace.cast.log

```bash
# Seed transaction trace snippet (cast run -vvvvv) for 0x7226b3...ae22c
Executing previous transactions from the block.
Traces:
  [478036] 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2::227636c0(000000000000000000000000adefb902cab716b8043c5231ae9a50b8b4ee7c4e000000000000000000000000bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c00000000000000000000000016b9a82891338f9ba80e2d6970fdda79d1eb0dae00000000000000000000000000000000000000000000006c6b935b8bbd400000)
    ├─ [24420] WBNB::approve(BankrollNetworkStack: [0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e], 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77])
    │   ├─ emit Approval(owner: 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, spender: BankrollNetworkStack: [0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e], value: 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77])
    │   ├─  storage changes:
    │   │   @ 0x33ddba21d2eb0d9a07c67771d788031bba5f29c356ce6acb68e92bc6da073155: 0 → 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    │   └─ ← [Return] true
    ├─ [2465] PancakePair::token0() [staticcall]
    │   └─ ← [Return] BEP20USDT: [0x55d398326f99059fF775485246999027B3197955]
    ├─ [350852] PancakePair::swap(0, 2000000000000000000000 [2e21], 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, 0x3030)
    │   ├─ [29962] WBNB::transfer(0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, 2000000000000000000000 [2e21])
    │   │   ├─ emit Transfer(from: PancakePair: [0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE], to: 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, value: 2000000000000000000000 [2e21])
    │   │   ├─  storage changes:
    │   │   │   @ 0x245489554ac5c53fe4ed737348254408ac6a86f05c55694d61c7c561015aa31e: 0 → 0x00000000000000000000000000000000000000000000006c6b935b8bbd400000
    │   │   │   @ 0x65a91b743eebb93754974b0d76ae6fbcc9c7843adbbd90f71368692e5c22fe4d: 0x0000000000000000000000000000000000000000000005ac48da0c1b8a82eff8 → 0x00000000000000000000000000000000000000000000053fdd46b08fcd42eff8
    │   │   └─ ← [Return] true
    │   ├─ [291932] 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2::pancakeCall(0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, 0, 2000000000000000000000 [2e21], 0x3030)
    │   │   ├─ [35096] BankrollNetworkStack::donatePool(1000000000000000000000 [1e21])
    │   │   │   ├─ [8225] WBNB::transferFrom(0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, BankrollNetworkStack: [0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e], 1000000000000000000000 [1e21])
    │   │   │   │   ├─ emit Transfer(from: 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, to: BankrollNetworkStack: [0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e], value: 1000000000000000000000 [1e21])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0x245489554ac5c53fe4ed737348254408ac6a86f05c55694d61c7c561015aa31e: 0x00000000000000000000000000000000000000000000006c6b935b8bbd400000 → 0x00000000000000000000000000000000000000000000003635c9adc5dea00000
    │   │   │   │   │   @ 0x990106cc395ebe4d2a0ffaeb97cadaa1647f0b174ada46ddfb1b2471e99ff3d4: 0x0000000000000000000000000000000000000000000000019d5f024dd478321e → 0x000000000000000000000000000000000000000000000037d328b013b318321e
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ emit onDonation(from: 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, amount: 1000000000000000000000 [1e21], timestamp: 1750317290 [1.75e9])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 10: 0 → 0x00000000000000000000000000000000000000000000003635c9adc5dea00000
    │   │   │   └─ ← [Return] 0
    │   │   ├─ [155203] BankrollNetworkStack::buy(240000000000000000000 [2.4e20])
    │   │   │   ├─ [3425] WBNB::transferFrom(0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, BankrollNetworkStack: [0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e], 240000000000000000000 [2.4e20])
    │   │   │   │   ├─ emit Transfer(from: 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, to: BankrollNetworkStack: [0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e], value: 240000000000000000000 [2.4e20])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0x245489554ac5c53fe4ed737348254408ac6a86f05c55694d61c7c561015aa31e: 0x00000000000000000000000000000000000000000000003635c9adc5dea00000 → 0x000000000000000000000000000000000000000000000029331e6558f0e00000
    │   │   │   │   │   @ 0x990106cc395ebe4d2a0ffaeb97cadaa1647f0b174ada46ddfb1b2471e99ff3d4: 0x000000000000000000000000000000000000000000000037d328b013b318321e → 0x000000000000000000000000000000000000000000000044d5d3f880a0d8321e
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ emit onTokenPurchase(customerAddress: 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, incomingeth: 240000000000000000000 [2.4e20], tokensMinted: 216000000000000000000 [2.16e20], timestamp: 1750317290 [1.75e9])
    │   │   │   ├─ emit onLeaderBoard(customerAddress: 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, invested: 240000000000000000000 [2.4e20], tokens: 216000000000000000000 [2.16e20], soldTokens: 0, timestamp: 1750317290 [1.75e9])
    │   │   │   ├─ [534] WBNB::balanceOf(BankrollNetworkStack: [0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e]) [staticcall]
    │   │   │   │   └─ ← [Return] 1269786528993752134174 [1.269e21]
    │   │   │   ├─ emit onBalance(balance: 1269786528993752134174 [1.269e21], timestamp: 1750317290 [1.75e9])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 11: 0x0000000000000000000000000000000000000000000000000001a56267bdf333 → 0x000000000000000000000000000000000000000000000000429eabf3f19df333
    │   │   │   │   @ 9: 2467 → 2468
    │   │   │   │   @ 0x245489554ac5c53fe4ed737348254408ac6a86f05c55694d61c7c561015aa325: 0 → 1
    │   │   │   │   @ 8: 158 → 159
    │   │   │   │   @ 0x9707ac5925852bdb2b1878cd68d15903b37996595f6164d9aee7e94982b0ccfc: 0 → 0x0000000000000000000000000000000799146d00aff62da465b9c340c9000000
    │   │   │   │   @ 7: 0x000000000000000000000000000000000000000000000000000000006800f161 → 0x000000000000000000000000000000000000000000000000000000006853b8ea
    │   │   │   │   @ 4: 0x0000000000000000000000000000000000000000000000011b1f7105d33f33cf → 0x00000000000000000000000000000000000000000000000cd0b9989b0f9f33cf
    │   │   │   │   @ 6: 0x000000000000000000000000000000000000000000000027887497aea09d7a85 → 0x0000000000000000000000000000000000000000000000348b1fe01b8e5d7a85
    │   │   │   │   @ 0x245489554ac5c53fe4ed737348254408ac6a86f05c55694d61c7c561015aa31e: 0 → 0x00000000000000000000000000000000000000000000000d02ab486cedc00000
    │   │   │   │   @ 10: 0x00000000000000000000000000000000000000000000003635c9adc5dea00000 → 0
    │   │   │   │   @ 0x92dd2f27a5527500ca7a321b9ceb5d6b894bc9eb6202a880ef4c9e92171cf112: 0 → 0x00000000000000000000000000000000000000000000000bb59a27953c600000
    │   │   │   │   @ 12: 0x000000000000000000000000000000000000000000000000000000006800f161 → 0x000000000000000000000000000000000000000000000000000000006853b8ea
    │   │   │   │   @ 5: 0x000000000000000000000000000000000000000000000000a61ce7d20b4cd318 → 0x0000000000000000000000000000000000000000000000061021284d5c65ea80
    │   │   │   └─ ← [Return] 216000000000000000000 [2.16e20]
    │   │   ├─ [526] BankrollNetworkStack::myTokens() [staticcall]
    │   │   │   └─ ← [Return] 216000000000000000000 [2.16e20]
    │   │   ├─ [26005] BankrollNetworkStack::sell(216000000000000000000 [2.16e20])
    │   │   │   ├─ emit onTokenSell(customerAddress: 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, tokensBurned: 216000000000000000000 [2.16e20], ethEarned: 194400000000000000000 [1.944e20], timestamp: 1750317290 [1.75e9])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 0x9707ac5925852bdb2b1878cd68d15903b37996595f6164d9aee7e94982b0ccfc: 0x0000000000000000000000000000000799146d00aff62da465b9c340c9000000 → 0xffffffffffffffffffffffffffffffb610c212389849660d48043d92d9000000
    │   │   │   │   @ 4: 0x00000000000000000000000000000000000000000000000cd0b9989b0f9f33cf → 0x0000000000000000000000000000000000000000000000011b1f7105d33f33cf
    │   │   │   │   @ 0x92dd2f27a5527500ca7a321b9ceb5d6b894bc9eb6202a880ef4c9e92171cf112: 0x00000000000000000000000000000000000000000000000bb59a27953c600000 → 0
    │   │   │   │   @ 11: 0x000000000000000000000000000000000000000000000000429eabf3f19df333 → 0x0000000000000000000000000000000000000000000000007e926510874df333
    │   │   │   │   @ 10: 0 → 0x000000000000000000000000000000000000000000000000efcee47256c00000
    │   │   │   └─ ← [Stop]
    │   │   ├─ [921] BankrollNetworkStack::myDividends() [staticcall]
    │   │   │   └─ ← [Return] 1363851513770135689714 [1.363e21]
    │   │   ├─ [534] WBNB::balanceOf(BankrollNetworkStack: [0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e]) [staticcall]
    │   │   │   └─ ← [Return] 1269786528993752134174 [1.269e21]
    │   │   ├─ [3262] WBNB::transfer(BankrollNetworkStack: [0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e], 94064984776383565540 [9.406e19])
    │   │   │   ├─ emit Transfer(from: 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, to: BankrollNetworkStack: [0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e], value: 94064984776383565540 [9.406e19])
    │   │   │   ├─  storage changes:
    │   │   │   │   @ 0x990106cc395ebe4d2a0ffaeb97cadaa1647f0b174ada46ddfb1b2471e99ff3d4: 0x000000000000000000000000000000000000000000000044d5d3f880a0d8321e → 0x000000000000000000000000000000000000000000000049ef3dedc767b6c102
    │   │   │   │   @ 0x245489554ac5c53fe4ed737348254408ac6a86f05c55694d61c7c561015aa31e: 0x000000000000000000000000000000000000000000000029331e6558f0e00000 → 0x00000000000000000000000000000000000000000000002419b470122a01711c
    │   │   │   └─ ← [Return] true
    │   │   ├─ [58808] BankrollNetworkStack::withdraw()
    │   │   │   ├─ [3262] WBNB::transfer(0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, 1363851513770135689714 [1.363e21])
    │   │   │   │   ├─ emit Transfer(from: BankrollNetworkStack: [0xAdEfb902CaB716B8043c5231ae9A50b8b4eE7c4e], to: 0xE63a5C681caCB8484c8A989CfDd41b8E3B7a2be2, value: 1363851513770135689714 [1.363e21])
```

_Caption: High-level call sequence showing PancakePair::swap, donatePool, buy, sell, withdraw, repayment, and final WBNB transfer to the adversary EOA._

## Impact & Losses
### Token-Level Impact
- 29.786528993752124174 WBNB lost from BankrollNetworkStack reserves.

### Narrative Impact
From the perspective of BankrollNetworkStack, artifacts/root_cause/data_collector/iter_1/tx/56/0x7226b3...ae22c/erc20_balance_diff_manual.json shows a net loss of 29.786528993752124174 WBNB (its WBNB balance falls from 29.786528993752134174 WBNB to 0.00000000000000001 WBNB) in the seed transaction. PancakePair 0x16b9...0dae loses 56.099991838611619901 USDT and gains 5.287282124643214527 WBNB, indicating that LPs also experience a value shift. The adversary EOA ends the transaction with an additional 24.586528993752124174 WBNB and 0.000870232 BNB less, so its net portfolio value in WBNB-equivalent increases by approximately 24.585658761752124174 units. Long-term BankrollNetworkStack participants collectively lose WBNB reserves backing their token positions and future dividends, while Pancake LPs suffer a one-off loss due to price movement; no protocol-owned or privileged addresses receive offsetting value.

## References
- [1] Seed tx trace and balance diffs: artifacts/root_cause/data_collector/iter_1/tx/56/0x7226b3...ae22c/
- [2] BankrollNetworkStack source code: artifacts/root_cause/data_collector/iter_1/contract/56/0xadef...7c4e/source/src/Contract.sol
- [3] BankrollNetworkStack state snapshots at blocks 51715417 and 51715418: artifacts/root_cause/data_collector/iter_2/contract/56/0xadef...7c4e/state/
- [4] Representative non-attack BankrollNetworkStack traces: artifacts/root_cause/data_collector/iter_2/tx/56/
