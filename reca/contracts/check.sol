pragma solidity 0.5.16;
import "./UniswapV2Factory.sol";
import "./AppleToken.sol";
import "./AppleRewardPool.sol";

contract check {
    using safemath for uint256;
    AppleToken public token0 = new AppleToken(10000 * 10 ** 18);
    AppleToken public token1 = new AppleToken(20000 * 10 ** 18);
    AppleToken public token2 = new AppleToken(20000 * 10 ** 18);
    AppleToken public token3 = new AppleToken(10000 * 10 ** 18);
    UniswapV2Factory public factory = new UniswapV2Factory(address(this));
    AppleRewardPool public appleRewardPool;
    address public pair1;
    address public pair2;
    uint256 public starttime = block.timestamp;
    uint256 public endtime = block.timestamp + 90 days;
    constructor() public {
        pair1 = factory.createPair(address(token0),address(token1));
        token0.transfer(pair1,10000 * 10 ** 18);
        token1.transfer(pair1,10000 * 10 ** 18);        
        IUniswapV2Pair(pair1).mint(address(this));
        pair2 = factory.createPair(address(token1),address(token2));
        token1.transfer(pair2,10000 * 10 ** 18);
        token2.transfer(pair2,10000 * 10 ** 18);
        IUniswapV2Pair(pair2).mint(address(this));
        appleRewardPool = new AppleRewardPool(IERCLike(address(token2)),IERCLike(address(token3)),address(pair1),address(pair2));
        token2.transfer(address(appleRewardPool),10000 * 10 ** 18);
        token3.transfer(address(appleRewardPool),10000 * 10 ** 18);
        appleRewardPool.addPool(IERCLike(address(token1)),starttime, endtime,0,false);
        appleRewardPool.addPool(IERCLike(address(token2)),starttime, endtime,0,false);
        }
        
    function isSolved()  public view returns(bool){

        if(token3.balanceOf(address(appleRewardPool)) == 0){
           return  true;
        }
        return false;
    }
}