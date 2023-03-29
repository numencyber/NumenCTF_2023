pragma solidity 0.8.12;
contract Numen {
    address private owner;

    event SendFlag(address);

    constructor(){
        owner = msg.sender;
    }
    struct func{
        function() internal ptr;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier checkPermission(address addr){
        _;
        permission(addr);
    }

    function permission(address addr)internal view{
        bool con = calcCode(addr);
        require(con,"permission");
        require(msg.sender == addr);
    }

    function calcCode(address addr)internal view returns(bool){
        uint x;
        assembly{
            x := extcodesize(addr)
        }
        if(x == 0){return false;}
        else if(x > 12){return false;}
        else{assembly{return(0x20,0x00)}}
    }

    function execute(address target) external checkPermission(target){
        (bool success,) = target.delegatecall(abi.encode(bytes4(keccak256("func()"))));
        require(!success,"no cover!");
        uint b;
        uint v;
        (b,v) = getReturnData();
        require(b == block.number);

        func memory set;
        set.ptr = renounce;
        assembly {
            mstore(set, add(mload(set),v))
        }
        set.ptr();
    }

    function renounce()public{
        require(owner != address(0));
        owner = address(0);
    }

    function getReturnData()internal pure returns(uint b,uint v){
        assembly {
            if iszero(eq(returndatasize(), 0x40)) { revert(0, 0) }
            let ptr := mload(0x40)
            returndatacopy(ptr, 0, 0x40)
            b := and(mload(ptr), 0x00000000000000000000000000000000000000000000000000000000ffffffff)
            v := mload(add(0x20, ptr))
        }
    }

    function payforflag() public payable onlyOwner {
        require(msg.value == 1, 'I only need a little money!');
        emit SendFlag(msg.sender);
    }


    receive()external payable{
        this;
    }
    fallback()external payable{
        revert();
    }
}