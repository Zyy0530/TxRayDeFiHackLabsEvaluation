# Impermax V3 bad-debt restructure exploit on Base WETH/USDC pool

## Incident Overview & TL;DR

On Base, an unprivileged adversary-controlled orchestrator contract 0x98e938899902217465f17cf0b76d12b3dca8ce1b repeatedly calls ImpermaxV3Collateral::restructureBadDebt for an underwater Uniswap V3 LP-collateralized position (tokenId 255 and other positions), then uses ImpermaxV3Borrowable and Uniswap V3 interactions to mint borrowable tokens at a favorable exchange rate, extract essentially all WETH reserves from the borrowable pools, and withdraw the resulting ETH to EOA 0xe9f853d2616ac6b04e5fc2b4be6eb654b9f224cd.

The core vulnerability is a protocol-level logic/authorization bug in Impermax V3’s bad-debt handling: ImpermaxV3Collateral::restructureBadDebt and ImpermaxV3Borrowable::restructureDebt allow any external caller to write down an underwater borrower’s debt and substantially change borrowable accounting (totalBorrows, totalBalance, totalSupply, exchangeRate) without requiring a matching repayment of underlying, enabling a permissionless actor to mint borrowable tokens and then redeem protocol reserves for profit.

## Key Background

### Protocol and Position Context
- Impermax V3 is a lending protocol where Uniswap V3 LP NFTs (here via TokenizedUniswapV3Position 0xa68f6075ae62ebd514d1600cb5035fa0e2210ef8) are pledged as collateral in ImpermaxV3Collateral 0xc1d49fa32d150b31c4a5bf1cbf23cf7ac99eaf7d against borrowable ERC20 pools ImpermaxV3Borrowable 0x5d93f216f17c225a8b5ffa34e74b7133436281ee (WETH-like 0x4200...0006 leg) and other borrowables, with liquidation and bad-debt handling implemented by CollateralMath and the restructureBadDebt/restructureDebt flows in Contract.sol.

## Vulnerability & Root Cause Analysis

The core bug is a permissionless bad-debt restructuring flow that writes down borrower debt and changes pool accounting without requiring a matching repayment of underlying WETH.

**ImpermaxV3Borrowable::restructureDebt (accounting-only debt write-down):**

```solidity
function restructureDebt(uint256 tokenId, uint256 reduceToRatio) external;
	
	/*** Borrowable Interest Rate Model ***/

	event AccrueInterest(uint interestAccumulated, uint borrowIndex, uint totalBorrows);
	event CalculateKink(uint kinkRate);
	event CalculateBorrowRate(uint borrowRate);
	
	function KINK_BORROW_RATE_MAX() external pure returns (uint);
	function KINK_BORROW_RATE_MIN() external pure returns (uint);
	function KINK_MULTIPLIER() external pure returns (uint);
	function borrowRate() external view returns (uint);
	function kinkBorrowRate() external view returns (uint);
	function kinkUtilizationRate() external view returns (uint);
	function adjustSpeed() external view returns (uint);
	function rateUpdateTimestamp() external view returns (uint32);
	function accrualTimestamp() external view returns (uint32);
	
	function accrueInterest() external;
	
	/*** Borrowable Setter ***/

	event NewReserveFactor(uint newReserveFactor);
	event NewKinkUtilizationRate(uint newKinkUtilizationRate);
	event NewAdjustSpeed(uint newAdjustSpeed);
	event NewDebtCeiling(uint newDebtCeiling);

	function RESERVE_FACTOR_MAX() external pure returns (uint);
	function KINK_UR_MIN() external pure returns (uint);
	function KINK_UR_MAX() external pure returns (uint);
	function ADJUST_SPEED_MIN() external pure returns (uint);
	function ADJUST_SPEED_MAX() external pure returns (uint);
	
	function _initialize (
		string calldata _name, 
		string calldata _symbol,
		address _underlying, 
		address _collateral
	) external;
	function _setReserveFactor(uint newReserveFactor) external;
	function _setKinkUtilizationRate(uint newKinkUtilizationRate) external;
	function _setAdjustSpeed(uint newAdjustSpeed) external;
}

// File: contracts\interfaces\ICollateral.sol

pragma solidity >=0.5.0;

interface ICollateral {
	
	/* ImpermaxERC721 */

	event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
	event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
	event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
	
	function name() external view returns (string memory);
	function symbol() external view returns (string memory);
	function balanceOf(address owner) external view returns (uint256 balance);
	function ownerOf(uint256 tokenId) external view returns (address owner);
	function getApproved(uint256 tokenId) external view returns (address operator);
	function isApprovedForAll(address owner, address operator) external view returns (bool);
	
	function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;
	function safeTransferFrom(address from, address to, uint256 tokenId) external;
	function transferFrom(address from, address to, uint256 tokenId) external;
	function approve(address to, uint256 tokenId) external;
	function setApprovalForAll(address operator, bool approved) external;
	function permit(address spender, uint tokenId, uint deadline, uint8 v, bytes32 r, bytes32 s) external;
	
	/* Collateral */
	
	event Mint(address indexed to, uint tokenId);
	event Redeem(address indexed to, uint tokenId, uint percentage, uint redeemTokenId);
	event Seize(address indexed to, uint tokenId, uint percentage, uint redeemTokenId);
	event RestructureBadDebt(uint tokenId, uint postLiquidationCollateralRatio);
	
	function underlying() external view returns (address);
	function factory() external view returns (address);
	function borrowable0() external view returns (address);
	function borrowable1() external view returns (address);
	function safetyMarginSqrt() external view returns (uint);
	function liquidationIncentive() external view returns (uint);
	function liquidationFee() external view returns (uint);
	function liquidationPenalty() external view returns (uint);

	function mint(address to, uint256 tokenId) external;
	function redeem(address to, uint256 tokenId, uint256 percentage, bytes calldata data) external returns (uint redeemTokenId);
	function redeem(address to, uint256 tokenId, uint256 percentage) external returns (uint redeemTokenId);
	function isLiquidatable(uint tokenId) external returns (bool);
	function isUnderwater(uint tokenId) external returns (bool);
	function canBorrow(uint tokenId, address borrowable, uint accountBorrows) external returns (bool);
	function restructureBadDebt(uint tokenId) external;
	function seize(uint tokenId, uint repayAmount, address liquidator, bytes calldata data) external returns (uint seizeTokenId);
	
	/* CSetter */
	
	event NewSafetyMargin(uint newSafetyMarginSqrt);
	event NewLiquidationIncentive(uint newLiquidationIncentive);
	event NewLiquidationFee(uint newLiquidationFee);

	function SAFETY_MARGIN_SQRT_MIN() external pure returns (uint);
	function SAFETY_MARGIN_SQRT_MAX() external pure returns (uint);
	function LIQUIDATION_INCENTIVE_MIN() external pure returns (uint);
	function LIQUIDATION_INCENTIVE_MAX() external pure returns (uint);
	function LIQUIDATION_FEE_MAX() external pure returns (uint);
	
	function _setFactory() external;
	function _initialize (
		string calldata _name,
		string calldata _symbol,
		address _underlying, 
		address _borrowable0, 
		address _borrowable1
	) external;
	function _setSafetyMarginSqrt(uint newSafetyMarginSqrt) external;
	function _setLiquidationIncentive(uint newLiquidationIncentive) external;
	function _setLiquidationFee(uint newLiquidationFee) external;
}

// File: contracts\interfaces\IImpermaxCallee.sol

pragma solidity >=0.5.0;

interface IImpermaxCallee {
    function impermaxV3Borrow(address sender, uint256 tokenId, uint borrowAmount, bytes calldata data) external;
    function impermaxV3Redeem(address sender, uint256 tokenId, uint256 redeemTokenId, bytes calldata data) external;
}

// File: contracts\interfaces\IERC721.sol

pragma solidity >=0.5.0;

interface IERC721 {
	event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
	event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
	event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
	
	function name() external view returns (string memory);
	function symbol() external view returns (string memory);
	function balanceOf(address owner) external view returns (uint256 balance);
	function ownerOf(uint256 tokenId) external view returns (address owner);
	function getApproved(uint256 tokenId) external view returns (address operator);
	function isApprovedForAll(address owner, address operator) external view returns (bool);
	
	function DOMAIN_SEPARATOR() external view returns (bytes32);
	function nonces(uint256 tokenId) external view returns (uint256);
	
	function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;
	function safeTransferFrom(address from, address to, uint256 tokenId) external;
	function transferFrom(address from, address to, uint256 tokenId) external;
	function approve(address to, uint256 tokenId) external;
	function setApprovalForAll(address operator, bool approved) external;
	function permit(address spender, uint tokenId, uint deadline, uint8 v, bytes32 r, bytes32 s) external;
}

// File: contracts\libraries\Math.sol

pragma solidity =0.5.16;

// a library for performing various math operations
// forked from: https://github.com/Uniswap/uniswap-v2-core/blob/master/contracts/libraries/Math.sol

library Math {
    function min(uint x, uint y) internal pure returns (uint z) {
        z = x < y ? x : y;
    }
	
    function max(uint x, uint y) internal pure returns (uint z) {
        z = x > y ? x : y;
    }

    // babylonian method (https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Babylonian_method)
    function sqrt(uint y) internal pure returns (uint z) {
        if (y > 3) {
            z = y;
            uint x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }
}

// File: contracts\ImpermaxV3Borrowable.sol

pragma solidity =0.5.16;
contract ImpermaxV3Borrowable is IBorrowable, PoolToken, BStorage, BSetter, BInterestRateModel, BAllowance {
		
	constructor() public {}

	/*** PoolToken ***/
	
	function _update() internal {
		super._update();
		_calculateBorrowRate();
	}
	
	function _mintReserves(uint _exchangeRate, uint _totalSupply) internal returns (uint) {
		uint _exchangeRateLast = exchangeRateLast;
		if (_exchangeRate > _exchangeRateLast) {
			uint _exchangeRateNew = _exchangeRate.sub( _exchangeRate.sub(_exchangeRateLast).mul(reserveFactor).div(1e18) );
			uint liquidity = _totalSupply.mul(_exchangeRate).div(_exchangeRateNew).sub(_totalSupply);
			if (liquidity > 0) {
				address reservesManager = IFactory(factory).reservesManager();
				_mint(reservesManager, liquidity);
			}
			exchangeRateLast = _exchangeRateNew;
			return _exchangeRateNew;
		}
		else return _exchangeRate;
	}
	
	function exchangeRate() public accrue returns (uint) {
		uint _totalSupply = totalSupply;
		uint _actualBalance = totalBalance.add(totalBorrows);
		if (_totalSupply == 0 || _actualBalance == 0) return initialExchangeRate;
		uint _exchangeRate = _actualBalance.mul(1e18).div(_totalSupply);
		return _mintReserves(_exchangeRate, _totalSupply);
	}
	
	// force totalBalance to match real balance
	function sync() external nonReentrant update accrue {}
	
	/*** Borrowable ***/
	
	// this is the stored borrow balance; the current borrow balance may be slightly higher
	function borrowBalance(uint256 tokenId) public view returns (uint) {
		BorrowSnapshot memory borrowSnapshot = borrowBalances[tokenId];
		if (borrowSnapshot.interestIndex == 0) return 0; // not initialized
		return uint(borrowSnapshot.principal).mul(borrowIndex).div(borrowSnapshot.interestIndex);
	}
	function currentBorrowBalance(uint256 tokenId) external accrue returns (uint) {
		return borrowBalance(tokenId);
	}
	
	function _updateBorrow(uint256 tokenId, uint borrowAmount, uint repayAmount) private returns (uint accountBorrowsPrior, uint accountBorrows, uint _totalBorrows) {
		accountBorrowsPrior = borrowBalance(tokenId);
		if (borrowAmount == repayAmount) return (accountBorrowsPrior, accountBorrowsPrior, totalBorrows);
		uint112 _borrowIndex = borrowIndex;
		if (borrowAmount > repayAmount) {
			BorrowSnapshot storage borrowSnapshot = borrowBalances[tokenId];
			uint increaseAmount = borrowAmount - repayAmount;
			accountBorrows = accountBorrowsPrior.add(increaseAmount);
			borrowSnapshot.principal = safe112(accountBorrows);
			borrowSnapshot.interestIndex = _borrowIndex;
			_totalBorrows = uint(totalBorrows).add(increaseAmount);
			totalBorrows = safe112(_totalBorrows);
			require(_totalBorrows <= debtCeiling, "ImpermaxV3Borrowable: TOTAL_BORROWS_ABOVE_DEBT_CEILING");
		}
		else {
			BorrowSnapshot storage borrowSnapshot = borrowBalances[tokenId];
			uint decreaseAmount = repayAmount - borrowAmount;		
			accountBorrows = accountBorrowsPrior > decreaseAmount ? accountBorrowsPrior - decreaseAmount : 0;
			borrowSnapshot.principal = safe112(accountBorrows);
			if(accountBorrows == 0) {
				borrowSnapshot.interestIndex = 0;
			} else {
				borrowSnapshot.interestIndex = _borrowIndex;
			}
			uint actualDecreaseAmount = accountBorrowsPrior.sub(accountBorrows);
			_totalBorrows = totalBorrows; // gas savings
			_totalBorrows = _totalBorrows > actualDecreaseAmount ? _totalBorrows - actualDecreaseAmount : 0;
			totalBorrows = safe112(_totalBorrows);			
		}
	}
	
	// this low-level function should be called from another contract
	function borrow(uint256 tokenId, address receiver, uint borrowAmount, bytes calldata data) external nonReentrant update accrue {
		uint _totalBalance = totalBalance;
		require(borrowAmount <= _totalBalance, "ImpermaxV3Borrowable: INSUFFICIENT_CASH");
		
		if (borrowAmount > 0) {
			address borrower = IERC721(collateral).ownerOf(tokenId);
			_checkBorrowAllowance(borrower, msg.sender, borrowAmount);
		}
		
		// optimistically transfer funds
		if (borrowAmount > 0) _safeTransfer(receiver, borrowAmount);
		if (data.length > 0) IImpermaxCallee(receiver).impermaxV3Borrow(msg.sender, tokenId, borrowAmount, data);
		uint balance = IERC20(underlying).balanceOf(address(this));
		
		uint repayAmount = balance.add(borrowAmount).sub(_totalBalance);
		(uint accountBorrowsPrior, uint accountBorrows, uint _totalBorrows) = _updateBorrow(tokenId, borrowAmount, repayAmount);
		
		if(borrowAmount > repayAmount) require(
			ICollateral(collateral).canBorrow(tokenId, address(this), accountBorrows),
			"ImpermaxV3Borrowable: INSUFFICIENT_LIQUIDITY"
		);
		
		emit Borrow(msg.sender, tokenId, receiver, borrowAmount, repayAmount, accountBorrowsPrior, accountBorrows, _totalBorrows);
	}

	// this low-level function should be called from another contract
	function liquidate(uint256 tokenId, uint repayAmount, address liquidator, bytes calldata data) external nonReentrant update accrue returns (uint seizeTokenId) {
		repayAmount = Math.min(repayAmount, borrowBalance(tokenId));
		seizeTokenId = ICollateral(collateral).seize(tokenId, repayAmount, liquidator, data);
		
		uint balance = IERC20(underlying).balanceOf(address(this));
		require(balance.sub(totalBalance) >= repayAmount, "ImpermaxV3Borrowable: INSUFFICIENT_ACTUAL_REPAY");
		
		(uint accountBorrowsPrior, uint accountBorrows, uint _totalBorrows) = _updateBorrow(tokenId, 0, repayAmount);
		
		emit Liquidate(msg.sender, tokenId, liquidator, seizeTokenId, repayAmount, accountBorrowsPrior, accountBorrows, _totalBorrows);
	}
	
	// this function must be called from collateral
	function restructureDebt(uint tokenId, uint reduceToRatio) public nonReentrant update accrue {
		require(msg.sender == collateral, "ImpermaxV3Borrowable: UNAUTHORIZED");
		require(reduceToRatio < 1e18, "ImpermaxV3Borrowable: NOT_UNDERWATER");
	
		uint _borrowBalance = borrowBalance(tokenId);
		if (_borrowBalance == 0) return;
		uint repayAmount = _borrowBalance.sub(_borrowBalance.mul(reduceToRatio).div(1e18));
		(uint accountBorrowsPrior, uint accountBorrows, uint _totalBorrows) = _updateBorrow(tokenId, 0, repayAmount);
		
		emit RestructureDebt(tokenId, reduceToRatio, repayAmount, accountBorrowsPrior, accountBorrows, _totalBorrows);
	}
```

_Snippet origin: Verified ImpermaxV3Borrowable source for 0x5d93...81ee on Base. It reduces `borrowBalance` and `totalBorrows` purely via `_updateBorrow`, without any transfer of underlying tokens into the pool._

**ImpermaxV3Collateral::restructureBadDebt (permissionless entrypoint):**

```solidity
function restructureBadDebt(uint tokenId) external;
	function seize(uint tokenId, uint repayAmount, address liquidator, bytes calldata data) external returns (uint seizeTokenId);
	
	/* CSetter */
	
	event NewSafetyMargin(uint newSafetyMarginSqrt);
	event NewLiquidationIncentive(uint newLiquidationIncentive);
	event NewLiquidationFee(uint newLiquidationFee);

	function SAFETY_MARGIN_SQRT_MIN() external pure returns (uint);
	function SAFETY_MARGIN_SQRT_MAX() external pure returns (uint);
	function LIQUIDATION_INCENTIVE_MIN() external pure returns (uint);
	function LIQUIDATION_INCENTIVE_MAX() external pure returns (uint);
	function LIQUIDATION_FEE_MAX() external pure returns (uint);
	
	function _setFactory() external;
	function _initialize (
		string calldata _name,
		string calldata _symbol,
		address _underlying, 
		address _borrowable0, 
		address _borrowable1
	) external;
	function _setSafetyMarginSqrt(uint newSafetyMarginSqrt) external;
	function _setLiquidationIncentive(uint newLiquidationIncentive) external;
	function _setLiquidationFee(uint newLiquidationFee) external;
}

// File: contracts\interfaces\IImpermaxCallee.sol

pragma solidity >=0.5.0;

interface IImpermaxCallee {
    function impermaxV3Borrow(address sender, uint256 tokenId, uint borrowAmount, bytes calldata data) external;
    function impermaxV3Redeem(address sender, uint256 tokenId, uint256 redeemTokenId, bytes calldata data) external;
}

// File: contracts\interfaces\INFTLP.sol

pragma solidity >=0.5.0;

interface INFTLP {
	struct RealXY {
		uint256 realX;
		uint256 realY;
	}
	
	struct RealXYs {
		RealXY lowestPrice;
		RealXY currentPrice;
		RealXY highestPrice;
	}
	
	// ERC-721
	function ownerOf(uint256 _tokenId) external view returns (address);
	function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;
	function safeTransferFrom(address from, address to, uint256 tokenId) external;
	function transferFrom(address from, address to, uint256 tokenId) external;
	
	// Global state
	function token0() external view returns (address);
	function token1() external view returns (address);
	
	// Position state
	function getPositionData(uint256 _tokenId, uint256 _safetyMarginSqrt) external returns (
		uint256 priceSqrtX96,
		RealXYs memory realXYs
	);
	
	// Interactions
	
	function split(uint256 tokenId, uint256 percentage) external returns (uint256 newTokenId);
	function join(uint256 tokenId, uint256 tokenToJoin) external;
}

// File: contracts\libraries\CollateralMath.sol

pragma solidity =0.5.16;
library CollateralMath {
	using SafeMath for uint;

    uint constant Q64 = 2**64;
    uint constant Q96 = 2**96;
    uint constant Q192 = 2**192;
	
	enum Price {LOWEST, CURRENT, HIGHEST}

	struct PositionObject {
		INFTLP.RealXYs realXYs;
		uint priceSqrtX96;
		uint debtX;
		uint debtY;
		uint liquidationPenalty;
		uint safetyMarginSqrt;
	}
	
	function newPosition(
		INFTLP.RealXYs memory realXYs,
		uint priceSqrtX96,
		uint debtX,
		uint debtY,
		uint liquidationPenalty,
		uint safetyMarginSqrt
	) internal pure returns (PositionObject memory) {
		return PositionObject({
			realXYs: realXYs,
			priceSqrtX96: priceSqrtX96,
			debtX: debtX,
			debtY: debtY,
			liquidationPenalty: liquidationPenalty,
			safetyMarginSqrt: safetyMarginSqrt
		});
	}
	
    function safeInt256(uint256 n) internal pure returns (int256) {
        require(n < 2**255, "Impermax: SAFE_INT");
        return int256(n);
    }
	
	// price
	function getRelativePriceX(uint priceSqrtX96) internal pure returns (uint) {
		return priceSqrtX96;
	}
	// 1 / price
	function getRelativePriceY(uint priceSqrtX96) internal pure returns (uint) {
		return Q192.div(priceSqrtX96);
	}
	
	// amountX * priceX + amountY * priceY
	function getValue(PositionObject memory positionObject, Price price, uint amountX, uint amountY) internal pure returns (uint) {
		uint priceSqrtX96 = positionObject.priceSqrtX96;
		if (price == Price.LOWEST) priceSqrtX96 = priceSqrtX96.mul(1e18).div(positionObject.safetyMarginSqrt);
		if (price == Price.HIGHEST) priceSqrtX96 = priceSqrtX96.mul(positionObject.safetyMarginSqrt).div(1e18);
		uint relativePriceX = getRelativePriceX(priceSqrtX96);
		uint relativePriceY = getRelativePriceY(priceSqrtX96);
		return amountX.mul(relativePriceX).div(Q64).add(amountY.mul(relativePriceY).div(Q64));
	}
	
	// realX * priceX + realY * priceY
	function getCollateralValue(PositionObject memory positionObject, Price price) internal pure returns (uint) {
		INFTLP.RealXY memory realXY = positionObject.realXYs.currentPrice;
		if (price == Price.LOWEST) realXY = positionObject.realXYs.lowestPrice;
		if (price == Price.HIGHEST) realXY = positionObject.realXYs.highestPrice;
		return getValue(positionObject, price, realXY.realX, realXY.realY);
	}

	// debtX * priceX + realY * debtY	
	function getDebtValue(PositionObject memory positionObject, Price price) internal pure returns (uint) {
		return getValue(positionObject, price, positionObject.debtX, positionObject.debtY);
	}
	
	// collateralValue - debtValue * liquidationPenalty
	function getLiquidityPostLiquidation(PositionObject memory positionObject, Price price) internal pure returns (int) {
		uint collateralNeeded = getDebtValue(positionObject, price).mul(positionObject.liquidationPenalty).div(1e18);
		uint collateralValue = getCollateralValue(positionObject, price);
		return safeInt256(collateralValue) - safeInt256(collateralNeeded);
	}
	
	// collateralValue / (debtValue * liquidationPenalty)
	function getPostLiquidationCollateralRatio(PositionObject memory positionObject) internal pure returns (uint) {
		uint collateralNeeded = getDebtValue(positionObject, Price.CURRENT).mul(positionObject.liquidationPenalty).div(1e18);
		uint collateralValue = getCollateralValue(positionObject, Price.CURRENT);
		return collateralValue.mul(1e18).div(collateralNeeded, "ImpermaxV3Collateral: NO_DEBT");
	}
	
	function isLiquidatable(PositionObject memory positionObject) internal pure returns (bool) {
		int a = getLiquidityPostLiquidation(positionObject, Price.LOWEST);
		int b = getLiquidityPostLiquidation(positionObject, Price.HIGHEST);
		return a < 0 || b < 0;
	}
	
	function isUnderwater(PositionObject memory positionObject) internal pure returns (bool) {
		int liquidity = getLiquidityPostLiquidation(positionObject, Price.CURRENT);
		return liquidity < 0;
	}
}

// File: contracts\ImpermaxV3Collateral.sol

pragma solidity =0.5.16;







contract ImpermaxV3Collateral is ICollateral, CSetter {	
	using CollateralMath for CollateralMath.PositionObject;

    uint256 internal constant Q192 = 2**192;

	constructor() public {}
	
	/*** Collateralization Model ***/
	
	function _getPositionObjectAmounts(uint tokenId, uint debtX, uint debtY) internal returns (CollateralMath.PositionObject memory positionObject) {
		if (debtX == uint(-1)) debtX = IBorrowable(borrowable0).currentBorrowBalance(tokenId);
		if (debtY == uint(-1)) debtY = IBorrowable(borrowable1).currentBorrowBalance(tokenId);
		
		(uint priceSqrtX96, INFTLP.RealXYs memory realXYs) = 
			INFTLP(underlying).getPositionData(tokenId, safetyMarginSqrt);
		require(priceSqrtX96 > 100 && priceSqrtX96 < Q192 / 100, "ImpermaxV3Collateral: PRICE_CALCULATION_ERROR");
		
		positionObject = CollateralMath.newPosition(realXYs, priceSqrtX96, debtX, debtY, liquidationPenalty(), safetyMarginSqrt);
	}
	
	function _getPositionObject(uint tokenId) internal returns (CollateralMath.PositionObject memory positionObject) {
		return _getPositionObjectAmounts(tokenId, uint(-1), uint(-1));
	}
	
	/*** ERC721 Wrapper ***/
	
	function mint(address to, uint256 tokenId) external nonReentrant {
		require(_ownerOf[tokenId] == address(0), "ImpermaxV3Collateral: NFT_ALREADY_MINTED");
		require(INFTLP(underlying).ownerOf(tokenId) == address(this), "ImpermaxV3Collateral: NFT_NOT_RECEIVED");
		_mint(to, tokenId);
		emit Mint(to, tokenId);
	}

	function redeem(address to, uint256 tokenId, uint256 percentage, bytes memory data) public nonReentrant returns (uint256 redeemTokenId) {
		require(percentage <= 1e18, "ImpermaxV3Collateral: PERCENTAGE_ABOVE_100");
		_checkAuthorized(_requireOwned(tokenId), msg.sender, tokenId);
		_approve(address(0), tokenId, address(0)); // reset approval
				
		// optimistically redeem
		if (percentage == 1e18) {
			redeemTokenId = tokenId;
			_burn(tokenId);
			INFTLP(underlying).safeTransferFrom(address(this), to, redeemTokenId);
			if (data.length > 0) IImpermaxCallee(to).impermaxV3Redeem(msg.sender, tokenId, redeemTokenId, data);
			
			// finally check that the position is not left underwater
			require(IBorrowable(borrowable0).borrowBalance(tokenId) == 0, "ImpermaxV3Collateral: INSUFFICIENT_LIQUIDITY");
			require(IBorrowable(borrowable1).borrowBalance(tokenId) == 0, "ImpermaxV3Collateral: INSUFFICIENT_LIQUIDITY");
		} else {
			redeemTokenId = INFTLP(underlying).split(tokenId, percentage);
			INFTLP(underlying).safeTransferFrom(address(this), to, redeemTokenId);
			if (data.length > 0) IImpermaxCallee(to).impermaxV3Redeem(msg.sender, tokenId, redeemTokenId, data);
			
			// finally check that the position is not left underwater
			require(!isLiquidatable(tokenId), "ImpermaxV3Collateral: INSUFFICIENT_LIQUIDITY");
		}
		
		emit Redeem(to, tokenId, percentage, redeemTokenId);
	}
	function redeem(address to, uint256 tokenId, uint256 percentage) external returns (uint256 redeemTokenId) {
		return redeem(to, tokenId, percentage, "");
	}
	
	/*** Collateral ***/
	
	function isLiquidatable(uint tokenId) public returns (bool) {
		CollateralMath.PositionObject memory positionObject = _getPositionObject(tokenId);
		return positionObject.isLiquidatable();
	}
	
	function isUnderwater(uint tokenId) public returns (bool) {
		CollateralMath.PositionObject memory positionObject = _getPositionObject(tokenId);
		return positionObject.isUnderwater();
	}
	
	function canBorrow(uint tokenId, address borrowable, uint accountBorrows) public returns (bool) {
		address _borrowable0 = borrowable0;
		address _borrowable1 = borrowable1;
		require(borrowable == _borrowable0 || borrowable == _borrowable1, "ImpermaxV3Collateral: INVALID_BORROWABLE");
		require(INFTLP(underlying).ownerOf(tokenId) == address(this), "ImpermaxV3Collateral: INVALID_NFTLP_ID");
		
		uint debtX = borrowable == _borrowable0 ? accountBorrows : uint(-1);
		uint debtY = borrowable == _borrowable1 ? accountBorrows : uint(-1);
		
		CollateralMath.PositionObject memory positionObject = _getPositionObjectAmounts(tokenId, debtX, debtY);
		return !positionObject.isLiquidatable();
	}
	
	function restructureBadDebt(uint tokenId) external nonReentrant {
		CollateralMath.PositionObject memory positionObject = _getPositionObject(tokenId);
		uint postLiquidationCollateralRatio = positionObject.getPostLiquidationCollateralRatio();
		require(postLiquidationCollateralRatio < 1e18, "ImpermaxV3Collateral: NOT_UNDERWATER");
		IBorrowable(borrowable0).restructureDebt(tokenId, postLiquidationCollateralRatio);
		IBorrowable(borrowable1).restructureDebt(tokenId, postLiquidationCollateralRatio);
		
		blockOfLastRestructureOrLiquidation[tokenId] = block.number;
		
		emit RestructureBadDebt(tokenId, postLiquidationCollateralRatio);
	}
```

_Snippet origin: Verified ImpermaxV3Collateral source for 0xc1d4...af7d on Base. Any external caller can invoke `restructureBadDebt`, which in turn calls the borrowables’ `restructureDebt` for underwater positions, without any access control beyond the underwater check._

## Adversary Flow Analysis

The adversary deploys or controls an orchestrator contract 0x98e938899902217465f17cf0b76d12b3dca8ce1b that programmatically invokes ImpermaxV3Collateral::restructureBadDebt on underwater positions, relies on ImpermaxV3Borrowable::restructureDebt’s accounting-only write-downs to create cheap claims on pool reserves, and then uses Uniswap V3 swaps plus ImpermaxV3Borrowable mint/redeem and WETH9 withdraw to convert protocol reserves into ETH withdrawn to EOA 0xe9f853d2616ac6b04e5fc2b4be6eb654b9f224cd over three adversary-crafted transactions.

### Adversary-Related Accounts

**Adversary cluster:**
- Address: `0xe3223f7e3343c2c8079f261d59ee1e513086c7c3` on Base (chainid 8453); EOA=True, contract=False. Sender of the first two orchestrator calls 0xde9030...5983 and 0x6cada3...6728 (txlist_normal.json for 0xe3223f7e...7c3), paying gas for those transactions and thereby actively initiating the bad-debt restructure sequence via 0x98e9...ce1b.
- Address: `0x98e938899902217465f17cf0b76d12b3dca8ce1b` on Base (chainid 8453); EOA=False, contract=True. Orchestrator contract called with selector 0xf1a881b9 in all three exploit transactions; decompiled code (0x98e9...-decompiled.sol) shows it as a custom contract, not part of the Impermax deployment, and balance diffs show it receiving large mints of ImpermaxV3Borrowable tokens and intermediate WETH that are then used to repay remaining debt and route value to the adversary EOA.
- Address: `0xe9f853d2616ac6b04e5fc2b4be6eb654b9f224cd` on Base (chainid 8453); EOA=True, contract=False. Receives all net ETH profit across the three exploit transactions (native_balance_deltas for 0xde9030...5983, 0x6cada3...6728, and 0x69e5d4d6...deb35e) and directly sends the third orchestrator call 0x69e5d4d6...deb35e to 0x98e9...ce1b, establishing it as the primary profit address.

**Victim-related contracts and stakeholders:**
- ImpermaxV3Borrowable (WETH leg for Uniswap V3 WETH/USDC LP) at `0x5d93f216f17c225a8b5ffa34e74b7133436281ee` on Base (chainid 8453), verified=true.
- ImpermaxV3Collateral (Uniswap V3 LP NFT collateral, tokenId 255 and related positions) at `0xc1d49fa32d150b31c4a5bf1cbf23cf7ac99eaf7d` on Base (chainid 8453), verified=true.
- Impermax V3 LP depositors and lenders (aggregated via ImpermaxV3Borrowable totalBalance and totalSupply) at `0x5d93f216f17c225a8b5ffa34e74b7133436281ee` on Base (chainid 8453), verified=true.

### Transaction-Level Lifecycle

#### Adversary orchestrator call #1 (seed transaction)

- Tx `0xde903046b5cdf27a5391b771f41e645e9cc670b649f7b87b1524fc4076f45983` on Base (chainid 8453), block 29437439, mechanism: borrow + bad-debt restructure + LP redemption + swap + WETH withdraw.

EOA 0xe3223f7e...7c3 calls 0x98e9...ce1b::f1a881b9, which identifies Impermax positions associated with Uniswap V3 WETH/USDC LP tokenId 255, invokes ImpermaxV3Collateral::restructureBadDebt(255) and ImpermaxV3Borrowable::restructureDebt to write down the underwater debt, then transfers ≈60.0903 WETH from the orchestrator into the borrowable and calls ImpermaxV3Borrowable::borrow with borrowAmount=0 to clear the remaining debt, redeems the collateral NFT back to 0x98e9...ce1b, collects fees from the Uniswap V3 position, executes swaps, and finally withdraws ≈34.596457958884485813 ETH to 0xe9f853d2...24cd.

Evidence:

- Seed trace: artifacts/root_cause/seed/8453/0xde903046b5cdf27a5391b771f41e645e9cc670b649f7b87b1524fc4076f45983/trace.cast.log (restructureBadDebt and restructureDebt calls at lines around 6699-6755; WETH transfer and borrow events at lines 6765-6785); Impermax borrowable and collateral source: artifacts/root_cause/seed/_contracts/8453/0x5d93f216f17c225a8b5ffa34e74b7133436281ee/source/src/Contract.sol and artifacts/root_cause/seed/_contracts/8453/0xc1d49fa32d150b31c4a5bf1cbf23cf7ac99eaf7d/source/src/Contract.sol; balance and WETH ERC20 diffs: artifacts/root_cause/data_collector/iter_1/tx/8453/0xde9030...5983/balance_diff_prestate.json and artifacts/root_cause/data_collector/iter_2/tx/8453/0xde9030...5983/weth_erc20_balance_diff_from_logs.json; Impermax state diff: artifacts/root_cause/data_collector/iter_3/tx/8453/0xde9030...5983/impermax_state_diff.json.

#### Adversary orchestrator call #2 (follow-up bad-debt restructure)

- Tx `0x6cada34301f9d365e3f8b157ca3f6b6ec83ff31e0aa1704cbb49b37a6796d728` on Base (chainid 8453), block 29437536, mechanism: borrow + bad-debt restructure + swap + WETH withdraw.

The same EOA 0xe3223f7e...7c3 issues a second call to 0x98e9...ce1b::f1a881b9, which repeats a similar Impermax V3 bad-debt restructure pattern, this time additionally interacting with ImpermaxV3Borrowable 0xbc303acda8b2a0dcd3d17f05adddf854edd6da59. The balance diff for tx 0x6cada3...6728 shows 0xe9f853d2...24cd receiving +4.141016260037839565 ETH (native_balance_deltas) while 0xe3223f7e...7c3 pays ≈0.001497657969840538 ETH in gas, and 0x98e9...ce1b receives an additional ≈392.829947293 ImpermaxV3Borrowable tokens of 0xbc303...da59.

Evidence:

- Trace: artifacts/root_cause/data_collector/iter_2/tx/8453/0x6cada34301f9d365e3f8b157ca3f6b6ec83ff31e0aa1704cbb49b37a6796d728/trace.cast.log; balance diff: artifacts/root_cause/data_collector/iter_3/tx/8453/0x6cada34301f9d365e3f8b157ca3f6b6ec83ff31e0aa1704cbb49b37a6796d728/balance_diff_prestate.json; orchestrator ABI/decompile: artifacts/root_cause/data_collector/iter_1/contract/8453/0x98e9...ce1b/decompile/0x98e9...ce1b-abi.json and -decompiled.sol.

#### Adversary orchestrator call #3 (final bad-debt restructure and profit realization)

- Tx `0x69e5d4d64ed4f53faa1875feadbe7b30285ea23f027856583350ae3dc1deb35e` on Base (chainid 8453), block 29437673, mechanism: borrow + bad-debt restructure + swap + WETH withdraw.

In the third transaction, EOA 0xe9f853d2...24cd directly calls 0x98e9...ce1b::f1a881b9, which again triggers Impermax bad-debt restructure logic and associated Uniswap V3 swaps on ImpermaxV3Borrowable contracts 0x900370e14093e3508b056c81c7a21e687bc350eb and 0xb362479915f2d24a284dd5e6742c4f619ad0453a. The balance diff for tx 0x69e5d4d6...deb35e shows 0xe9f853d2...24cd receiving +7.299210485939878646 ETH, while the canonical WETH address 0x4200...0006 loses -7.299248376727787757 ETH and the difference is absorbed by Base system fee addresses, indicating a net new transfer of ≈7.2992 ETH from protocol reserves to the adversary cluster after fees.

Evidence:

- Trace: artifacts/root_cause/data_collector/iter_2/tx/8453/0x69e5d4d64ed4f53faa1875feadbe7b30285ea23f027856583350ae3dc1deb35e/trace.cast.log; balance diff: artifacts/root_cause/data_collector/iter_3/tx/8453/0x69e5d4d64ed4f53faa1875feadbe7b30285ea23f027856583350ae3dc1deb35e/balance_diff_prestate.json; orchestrator txlist: artifacts/root_cause/data_collector/iter_1/address/8453/0x98e9...ce1b/txlist_normal.json.

#### Seed transaction trace excerpt (0xde9030...5983)

```text
Executing previous transactions from the block.
Traces:
  [79533013] 0x98E938899902217465f17CF0B76d12B3DCa8CE1b::f1a881b9(00000000000000000000000000000000000000000000000000000000000000c0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffcee08fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffceda400000000000000000000000000000000000000000000000000000000007fffff00000000000000000000000000000000000000000000000000000000007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffceda40000000000000000000000004200000000000000000000000000000000000006000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda029130000000000000000000000005d93f216f17c225a8b5ffa34e74b7133436281ee000000000000000000000000bc303acda8b2a0dcd3d17f05adddf854edd6da59000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913000000000000000000000000c1d49fa32d150b31c4a5bf1cbf23cf7ac99eaf7d000000000000000000000000a68f6075ae62ebd514d1600cb5035fa0e2210ef80000000000000000000000006799246165c8ce1ed2e5cf8c494fa8e7a5de447200000000000000000000000000000000000000000000000000000000000000c800000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017b7883c06916600000000000000000000000000000000000000000000000000000000012309ce540000000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000003b9aca00000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000186a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d0b53d9277642d899df5c87a3966a349a798f2240000000000000000000000000000000000000000000000000000000000000000)
    ├─ [13165] TokenizedUniswapV3Position::getPool(200) [staticcall]
    │   ├─ [2666] UniswapV3Factory::getPool(WETH9: [0x4200000000000000000000000000000000000006], FiatTokenProxy: [0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913], 200) [staticcall]
    │   │   └─ ← [Return] UniswapV3Pool: [0x1C450D7d1FD98A0b04E30deCFc83497b33A4F608]
    │   └─ ← [Return] UniswapV3Pool: [0x1C450D7d1FD98A0b04E30deCFc83497b33A4F608]
    ├─ [2696] UniswapV3Pool::slot0() [staticcall]
    │   └─ ← [Return] 3387911442864025271133835 [3.387e24], -201208 [-2.012e5], 0, 1, 1, 0, true
    ├─ [4665] TokenizedUniswapV3Position::getPool(500) [staticcall]
    │   ├─ [2666] UniswapV3Factory::getPool(WETH9: [0x4200000000000000000000000000000000000006], FiatTokenProxy: [0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913], 500) [staticcall]
    │   │   └─ ← [Return] 0xd0b53D9277642d899DF5C87A3966A349A798F224
    │   └─ ← [Return] 0xd0b53D9277642d899DF5C87A3966A349A798F224
    ├─ [2696] 0xd0b53D9277642d899DF5C87A3966A349A798F224::slot0() [staticcall]
    │   └─ ← [Return] 3370971263443308409811171 [3.37e24], -201308 [-2.013e5], 2801, 5000, 5000, 0, true
    ├─ [696] 0xd0b53D9277642d899DF5C87A3966A349A798F224::slot0() [staticcall]
    │   └─ ← [Return] 3370971263443308409811171 [3.37e24], -201308 [-2.013e5], 2801, 5000, 5000, 0, true
    ├─ [2665] TokenizedUniswapV3Position::getPool(200) [staticcall]
    │   ├─ [666] UniswapV3Factory::getPool(WETH9: [0x4200000000000000000000000000000000000006], FiatTokenProxy: [0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913], 200) [staticcall]
    │   │   └─ ← [Return] UniswapV3Pool: [0x1C450D7d1FD98A0b04E30deCFc83497b33A4F608]
    │   └─ ← [Return] UniswapV3Pool: [0x1C450D7d1FD98A0b04E30deCFc83497b33A4F608]
    ├─ [2457] WETH9::balanceOf(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb) [staticcall]
    │   └─ ← [Return] 10544813644832897955984 [1.054e22]
    ├─ [9750] FiatTokenProxy::fallback(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb) [staticcall]
    │   ├─ [2553] FiatTokenV2_2::balanceOf(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb) [delegatecall]
    │   │   └─ ← [Return] 22539727986604 [2.253e13]
    │   └─ ← [Return] 22539727986604 [2.253e13]
    ├─ [457] WETH9::balanceOf(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb) [staticcall]
    │   └─ ← [Return] 10544813644832897955984 [1.054e22]
    ├─ [1250] FiatTokenProxy::fallback(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb) [staticcall]
    │   ├─ [553] FiatTokenV2_2::balanceOf(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb) [delegatecall]
    │   │   └─ ← [Return] 22539727986604 [2.253e13]
    │   └─ ← [Return] 22539727986604 [2.253e13]
    ├─ [24399] WETH9::approve(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb, 10544813644832897955984 [1.054e22])
    │   ├─ emit Approval(owner: 0x98E938899902217465f17CF0B76d12B3DCa8CE1b, spender: 0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb, value: 10544813644832897955984 [1.054e22])
    │   ├─  storage changes:
    │   │   @ 0xafce0d33f70e4052b586abdd256012631520fc52bfb778935ec8206247f87c2d: 0 → 0x00000000000000000000000000000000000000000000023ba2afad288cf6f890
    │   └─ ← [Return] true
    ├─ [79334506] 0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb::flashLoan(WETH9: [0x4200000000000000000000000000000000000006], 10544813644832897955984 [1.054e22], 0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000004200000000000000000000000000000000000006000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda029130000000000000000000000005d93f216f17c225a8b5ffa34e74b7133436281ee000000000000000000000000bc303acda8b2a0dcd3d17f05adddf854edd6da59000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913000000000000000000000000c1d49fa32d150b31c4a5bf1cbf23cf7ac99eaf7d000000000000000000000000a68f6075ae62ebd514d1600cb5035fa0e2210ef80000000000000000000000006799246165c8ce1ed2e5cf8c494fa8e7a5de447200000000000000000000000000000000000000000000000000000000000000c800000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017b7883c06916600000000000000000000000000000000000000000000000000000000012309ce540000000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000003b9aca00000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000186a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d0b53d9277642d899df5c87a3966a349a798f2240000000000000000000000000000000000000000000000000000000000000000)
    │   ├─ emit FlashLoan(param0: 0x98E938899902217465f17CF0B76d12B3DCa8CE1b, param1: WETH9: [0x4200000000000000000000000000000000000006], param2: 10544813644832897955984 [1.054e22])
```

_Snippet origin: Foundry `cast run` trace for the first adversary-crafted orchestrator call, showing the call into `f1a881b9`, Uniswap V3 interactions, and WETH/USDC balance queries._

#### WETH ERC20 balance changes in seed transaction

```json
[
  {
    "token": "0x4200000000000000000000000000000000000006",
    "holder": "0x1c450d7d1fd98a0b04e30decfc83497b33a4f608",
    "before": "14484136283682643",
    "after": "14500029433666551",
    "delta": "15893149983908"
  },
  {
    "token": "0x4200000000000000000000000000000000000006",
    "holder": "0x5d93f216f17c225a8b5ffa34e74b7133436281ee",
    "before": "34607395078116799601",
    "after": "1",
    "delta": "-34607395078116799600"
  },
  {
    "token": "0x4200000000000000000000000000000000000006",
    "holder": "0x77eb9ceca49b87cf52d4f0c4e8fc9f86cbdd16c1",
    "before": "6371133972641415",
    "after": "6371133980003184",
    "delta": "7361769"
  },
  {
    "token": "0x4200000000000000000000000000000000000006",
    "holder": "0x98e938899902217465f17cf0b76d12b3dca8ce1b",
    "before": "0",
    "after": "34596457958884485813",
    "delta": "34596457958884485813"
  }
]
```

_Snippet origin: WETH ERC20 holder-level balance diff for tx 0xde9030...5983, showing WETH moving from ImpermaxV3Borrowable 0x5d93...81ee to orchestrator 0x98e9...ce1b and other participants._

#### Impermax state diff around seed transaction

```json
{
  "totalBorrows": {
    "before": "76008239618315329673",
    "after": "76013413017477949488"
  },
  "totalBalance": {
    "before": "34607395078116799601",
    "after": 1
  },
  "totalSupply": {
    "before": "109139856753187074663",
    "after": "152967873569401618293"
  },
  "exchangeRate": {
    "before": 1013568822432516765,
    "after": 496924035379171413
  },
  "exchangeRateLast": {
    "before": 1013521897381471130,
    "after": 1013568824923098531
  },
  "factory": "0x175712cD666FbcfE8B69866a3088D7bf17a47685",
  "reservesManager": "0xd3080518e5678DC5464B7D4079d1046929985C59",
  "reservesManager_balance": {
    "before": 4389869916374426,
    "after": 4440911335914950
  },
  "borrowBalance_token255": {
    "before": 0,
    "after": 0
  },
  "borrowSnapshot_token255": {
    "before": {
      "error": "call_failed",
      "cmd": "cast call 0x5d93f216f17c225a8b5ffa34e74b7133436281ee borrowBalances(uint256)(uint112,uint112) 255 --rpc-url https://indulgent-cosmological-smoke.base-mainnet.quiknode.pro/a6a53e47429a27dac299922d0d518c66c3875b2e --block 29437438 --json",
      "output": "Error: server returned an error response: error code 3: execution reverted"
    },
    "after": {
      "error": "call_failed",
      "cmd": "cast call 0x5d93f216f17c225a8b5ffa34e74b7133436281ee borrowBalances(uint256)(uint112,uint112) 255 --rpc-url https://indulgent-cosmological-smoke.base-mainnet.quiknode.pro/a6a53e47429a27dac299922d0d518c66c3875b2e --block 29437439 --json",
      "output": "Error: server returned an error response: error code 3: execution reverted"
    }
  }
}
```

_Snippet origin: pre/post state for ImpermaxV3Borrowable 0x5d93...81ee around the seed tx, highlighting the drop of `totalBalance` to 1 wei, increase in `totalSupply`, and exchangeRate shift used in the analysis._

## Impact & Losses

### Quantified Losses
- Token: ETH (Base L2 native via WETH 0x4200000000000000000000000000000000000006) — Amount lost: 46.033688992390620706.

Summing the deterministic ETH-native balance deltas for the adversary cluster addresses and ignoring any residual value of ImpermaxV3Borrowable ERC20 tokens minted to 0x98e9...ce1b, the adversary realizes a net gain of 46.033688992390620706 ETH across the three adversary-crafted transactions. This gain is funded entirely by Impermax V3 protocol reserves and underwater positions as evidenced by (i) the large drop in ImpermaxV3Borrowable.totalBalance from ≈34.607 WETH to effectively 0 in impermax_state_diff.json, (ii) the WETH ERC20 balance diff showing that 0x5d93...81ee’s WETH holdings decrease by 34.607395078116799600 while 0x98e9...ce1b’s WETH holdings increase by 34.596457958884485813 in the seed tx, and (iii) the additional negative WETH/ETH deltas on 0x4200...0006 in the follow-up orchestrator transactions. Thus the incident constitutes a protocol-bug-driven reserve drain against Impermax V3 lenders rather than an intended liquidation incentive or a pure MEV opportunity.

## ACT Opportunity Summary

- Pre-state block height (Sigma_B): 29437438.

### Pre-State Definition

Sigma_B is the publicly reconstructible on-chain state of Base at block 29437438, immediately before the first adversary-crafted ImpermaxV3 bad-debt restructure transaction 0xde903046b5cdf27a5391b771f41e645e9cc670b649f7b87b1524fc4076f45983 against WETH/USDC ImpermaxV3Borrowable 0x5d93f216f17c225a8b5ffa34e74b7133436281ee and ImpermaxV3Collateral 0xc1d49fa32d150b31c4a5bf1cbf23cf7ac99eaf7d.

Evidence:
- artifacts/root_cause/seed/8453/0xde903046b5cdf27a5391b771f41e645e9cc670b649f7b87b1524fc4076f45983/metadata.json
- artifacts/root_cause/seed/8453/0xde903046b5cdf27a5391b771f41e645e9cc670b649f7b87b1524fc4076f45983/trace.cast.log
- artifacts/root_cause/data_collector/iter_1/tx/8453/0xde903046b5cdf27a5391b771f41e645e9cc670b649f7b87b1524fc4076f45983/balance_diff_prestate.json
- artifacts/root_cause/data_collector/iter_2/tx/8453/0xde903046b5cdf27a5391b771f41e645e9cc670b649f7b87b1524fc4076f45983/weth_erc20_balance_diff_from_logs.json
- artifacts/root_cause/data_collector/iter_3/tx/8453/0xde903046b5cdf27a5391b771f41e645e9cc670b649f7b87b1524fc4076f45983/impermax_state_diff.json
- artifacts/root_cause/seed/_contracts/8453/0x5d93f216f17c225a8b5ffa34e74b7133436281ee/source/src/Contract.sol
- artifacts/root_cause/seed/_contracts/8453/0xc1d49fa32d150b31c4a5bf1cbf23cf7ac99eaf7d/source/src/Contract.sol

### Exploit Predicate and Profit Calculation

- Reference asset: ETH.
- Adversary address (profit reference): `0xe9f853d2616ac6b04e5fc2b4be6eb654b9f224cd`.
- Deterministic ETH profit from balance deltas: 46.033688992390620706.

Across the three adversary-crafted orchestrator calls, the adversary-related cluster {EOA 0xe3223f7e3343c2c8079f261d59ee1e513086c7c3, orchestrator contract 0x98e938899902217465f17cf0b76d12b3dca8ce1b, receiver EOA 0xe9f853d2616ac6b04e5fc2b4be6eb654b9f224cd} experiences the following ETH-native (WETH-like 0x4200000000000000000000000000000000000006) balance changes, computed from balance_diff_prestate.json and weth_erc20_balance_diff_from_logs.json:
- Tx 0xde9030...5983: 0xe9f853d2...24cd receives +34.596457958884485813 ETH (native_balance_deltas), while sender 0xe3223f7e...7c3 pays gas of 0.001498054501742780 ETH (negative native delta), and 0x98e9...ce1b receives +34.596457958884485813 WETH as an ERC20 balance before withdrawing it to ETH.
- Tx 0x6cada3...6728: 0xe9f853d2...24cd receives +4.141016260037839565 ETH and 0xe3223f7e...7c3 pays gas of 0.001497657969840538 ETH.
- Tx 0x69e5d4d6...deb35e: 0xe9f853d2...24cd receives +7.299210485939878646 ETH; the difference between the -7.299248376727787757 ETH delta on the system WETH address 0x4200...0006 and the +7.299210485939878646 ETH delta on 0xe9f853d2...24cd is fully accounted for by positive deltas on Base system fee addresses 0x4200000000000000000000000000000000000011, 0x4200000000000000000000000000000000000019, and 0x420000000000000000000000000000000000001a, reflecting transaction fees.
Summing the cluster’s gains and losses in ETH-only terms gives a deterministic net portfolio increase of (34.596457958884485813 - 0.001498054501742780) + (4.141016260037839565 - 0.001497657969840538) + 7.299210485939878646 = 46.033688992390620706 ETH, even before assigning any value to the large quantities of ImpermaxV3Borrowable ERC20 tokens minted to 0x98e9...ce1b in these transactions.

## References

- [1] Seed transaction metadata and trace for 0xde903046b5cdf27a5391b771f41e645e9cc670b649f7b87b1524fc4076f45983 — captured in analysis artifacts under `artifacts/root_cause/seed/8453/0xde903046b5cdf27a5391b771f41e645e9cc670b649f7b87b1524fc4076f45983/`.
- [2] ImpermaxV3Borrowable and ImpermaxV3Collateral source (Contract.sol) — captured in analysis artifacts under `artifacts/root_cause/seed/_contracts/8453/`.
- [3] Impermax state diff around seed tx (totalBorrows, totalBalance, totalSupply, exchangeRate) — captured in analysis artifacts under `artifacts/root_cause/data_collector/iter_3/tx/8453/0xde903046b5cdf27a5391b771f41e645e9cc670b649f7b87b1524fc4076f45983/impermax_state_diff.json`.
- [4] Balance diffs for orchestrator transactions 0x6cada343...6728 and 0x69e5d4d6...deb35e — captured in analysis artifacts under `artifacts/root_cause/data_collector/iter_3/tx/8453/`.
- [5] Orchestrator decompiled contract and ABI for 0x98e938899902217465f17cf0b76d12b3dca8ce1b — captured in analysis artifacts under `artifacts/root_cause/data_collector/iter_1/contract/8453/0x98e938899902217465f17cf0b76d12b3dca8ce1b/decompile/`.
