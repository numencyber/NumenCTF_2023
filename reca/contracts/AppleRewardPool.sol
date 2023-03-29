
pragma solidity 0.5.16;
pragma experimental ABIEncoderV2;
/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */


library safemath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     *
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     *
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts with custom message when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}
contract Context {
    function _msgSender() internal view  returns (address payable) {
        return msg.sender;
    }

    function _msgData() internal view  returns (bytes memory) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following 
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts
        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned
        // for accounts without code, i.e. `keccak256('')`
        bytes32 codehash;
        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        // solhint-disable-next-line no-inline-assembly
        assembly { codehash := extcodehash(account) }
        return (codehash != accountHash && codehash != 0x0);
    }

    /**
     * @dev Converts an `address` into `address payable`. Note that this is
     * simply a type cast: the actual underlying value is not changed.
     *
     * _Available since v2.4.0._
     */
    function toPayable(address account) internal pure returns (address payable) {
        return address(uint160(account));
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     *
     * _Available since v2.4.0._
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-call-value
        (bool success, ) = recipient.call.value(amount)("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
}

interface IERCLike {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);
    function mint(address recipient, uint256 amount) external returns (bool);
    function burn(uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}




contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor () internal {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(_owner == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public  onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public  onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

interface UniswapV2pair{
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract AppleRewardPool is Ownable {
    using safemath for uint256;
 
    

    struct UserInfo { 
        uint256 amount; 
        uint256 depositerewarded; 
        uint256 ApplerewardDebt;
        uint256 Applepending;
    }

    struct PoolInfo {
        IERCLike token;
        uint256 starttime;
        uint256 endtime;
        uint256 ApplePertime;
        uint256 lastRewardtime;
        uint256 accApplePerShare;
        uint256 totalStake;
    }

    IERCLike public token2;
    IERCLike public token3;
    PoolInfo[] public poolinfo;
    address public pair1;
    address public pair2;

    mapping (uint256 => mapping (address => UserInfo)) public users;

    event Deposit(address indexed user, uint256 _pid, uint256 amount);
    event Withdraw(address indexed user, uint256 _pid, uint256 amount);
    event ReclaimStakingReward(address user, uint256 amount);
    event Set(uint256 pid, uint256 allocPoint, bool withUpdate);
    
    constructor(IERCLike _token2, IERCLike _token3, address _pair1, address _pair2) public { 
        token2 = _token2;
        token3 = _token3;
        pair1 = _pair1;
        pair2 = _pair2;
    }

    modifier validatePool(uint256 _pid) {
        require(_pid < poolinfo.length, " pool exists?");
        _;
    }

    function getpool() view public returns(PoolInfo[] memory){
        return poolinfo;
    }

    function setApplePertime(uint256 _pid, uint256 _ApplePertime) public onlyOwner validatePool(_pid){
        PoolInfo storage pool = poolinfo[_pid];
        updatePool(_pid);
        _ApplePertime = _ApplePertime.mul(1e18).div(86400);
        pool.ApplePertime = _ApplePertime;
    }

    function addPool(IERCLike _token, uint256 _starttime, uint256 _endtime, uint256 _ApplePertime,  bool _withUpdate) public onlyOwner {
        if (_withUpdate) {
            massUpdatePools();
        }
        _ApplePertime = _ApplePertime.mul(1e18).div(86400);
        uint256 lastRewardtime = block.timestamp > _starttime ? block.timestamp : _starttime;
        poolinfo.push(PoolInfo({
            token: _token,
            starttime: _starttime,
            endtime: _endtime,
            ApplePertime: _ApplePertime,
            lastRewardtime: lastRewardtime,
            accApplePerShare: 0,
            totalStake: 0
        }));
    }
  
    
    function getMultiplier(PoolInfo storage pool) internal view returns (uint256) {
        uint256 from = pool.lastRewardtime;
        uint256 to = block.timestamp < pool.endtime ? block.timestamp : pool.endtime;
        if (from >= to) {
            return 0;
        }
        return to.sub(from);
              
    }

    function massUpdatePools() public {
        uint256 length = poolinfo.length;
        for (uint256 pid = 0; pid < length; pid++) {
            updatePool(pid);
        }
    }

    function updatePool(uint256 _pid) public validatePool(_pid) {
        
        PoolInfo storage pool = poolinfo[_pid];
        if (block.timestamp <= pool.lastRewardtime || pool.lastRewardtime > pool.endtime) { 
            return;
        }

        uint256 totalStake = pool.totalStake;
        if (totalStake == 0) {
            pool.lastRewardtime = block.timestamp <= pool.endtime ? block.timestamp : pool.endtime;
            return;
        }

        uint256 multiplier = getMultiplier(pool);
        uint256 AppleReward = multiplier.mul(pool.ApplePertime);
        pool.accApplePerShare = pool.accApplePerShare.add(AppleReward.mul(1e18).div(totalStake));
        pool.lastRewardtime = block.timestamp < pool.endtime ? block.timestamp : pool.endtime;
    }


    function pendingApple(uint256 _pid, address _user) public view validatePool(_pid) returns (uint256)  {
        PoolInfo storage pool = poolinfo[_pid];
        UserInfo storage user = users[_pid][_user];
        uint256 accApplePerShare = pool.accApplePerShare;

        uint256 totalStake = pool.totalStake;
        if (block.timestamp > pool.lastRewardtime && totalStake > 0) {
            uint256 multiplier = getMultiplier(pool);
            uint256 AppleReward = multiplier.mul(pool.ApplePertime);
            accApplePerShare = accApplePerShare.add(AppleReward.mul(1e18).div(totalStake));
        
        }
        return user.Applepending.add(user.amount.mul(accApplePerShare).div(1e18)).sub(user.ApplerewardDebt);
    }

    function rate() public view returns(uint256) {
        uint256 _price;
        address _token0 = UniswapV2pair(pair1).token0();
        address _token1 = UniswapV2pair(pair1).token1();
        uint256 amount0 = IERCLike(_token0).balanceOf(pair1);
        uint256 amount1 = IERCLike(_token1).balanceOf(pair1);
        _price = amount0.mul(1e18).div(amount1);
        return _price;
    }
    function rate1() public view returns(uint256) {
        uint256 _price;
        (uint256 _amount0, uint256 _amount1,) = UniswapV2pair(pair2).getReserves();
        _price = _amount1.div(_amount0).div(2).mul(1e18);
        return _price;
    } 

    function deposit(uint256 _pid, uint256 _amount) public validatePool(_pid){
        PoolInfo storage pool = poolinfo[_pid];
        UserInfo storage user = users[_pid][msg.sender];
      
        updatePool(_pid);
        if (user.amount > 0) { 
            uint256 Applepending = user.amount.mul(pool.accApplePerShare).div(1e18).sub(user.ApplerewardDebt);
            user.Applepending = user.Applepending.add(Applepending);
        }
        if (_pid == 0){
            uint256 token2_amount = _amount.mul(rate()).div(1e18);
            IERCLike(token2).transfer(msg.sender, token2_amount);
        }
        if (_pid == 1){
            uint256 token3_amount = _amount.mul(rate1()).div(1e18);
            IERCLike(token3).transfer(msg.sender, token3_amount);
        }
        pool.token.transferFrom(_msgSender(), address(this), _amount);
        pool.totalStake = pool.totalStake.add(_amount);
        user.amount = user.amount.add(_amount);
        user.ApplerewardDebt = user.amount.mul(pool.accApplePerShare).div(1e18);
        emit Deposit(msg.sender, _pid, _amount);
    }



    function withdraw(uint256 _pid, uint256 _amount) public validatePool(_pid){
        PoolInfo storage pool = poolinfo[_pid];
        UserInfo storage user = users[_pid][msg.sender];
        require(user.amount >= _amount, "withdraw: not good");
        updatePool(_pid);
        uint256 Applepending = user.amount.mul(pool.accApplePerShare).div(1e18).sub(user.ApplerewardDebt);
        user.Applepending = user.Applepending.add(Applepending);
        user.amount = user.amount.sub(_amount);
        user.ApplerewardDebt = user.amount.mul(pool.accApplePerShare).div(1e18);
        pool.totalStake = pool.totalStake.sub(_amount);
        pool.token.transfer(msg.sender, _amount);
        emit Withdraw(msg.sender, _pid, _amount);
    }

    function reclaimAppleStakingReward(uint256 _pid) public validatePool(_pid) {
        PoolInfo storage pool = poolinfo[_pid];
        UserInfo storage user = users[_pid][msg.sender];
        updatePool(_pid);
        uint256 Applepending = user.Applepending.add(user.amount.mul(pool.accApplePerShare).div(1e18).sub(user.ApplerewardDebt));
        if (Applepending > 0) {
            safeAppleTransfer(msg.sender, Applepending);
        }
        user.Applepending = 0;
        user.depositerewarded = user.depositerewarded.add(Applepending);
        user.ApplerewardDebt = user.amount.mul(pool.accApplePerShare).div(1e18);
        emit ReclaimStakingReward(msg.sender, Applepending);
    }

    function safeAppleTransfer(address _to, uint256 _amount) internal {
        uint256 AppleBalance = token3.balanceOf(address(this));
        require(AppleBalance >= _amount, "no enough token");
        token3.transfer(_to, _amount);
    }

}