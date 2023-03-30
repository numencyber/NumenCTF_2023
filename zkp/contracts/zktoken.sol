pragma solidity ^0.8.0;

import "./ZKPLibrary.sol";

contract ZKPCTF {
    using ZKPLibrary for ZKPLibrary.Proof;

    uint256 private constant TOKEN_SUPPLY = 1000;
    address owner;
    mapping(address => uint256) private balances;
    mapping(bytes32 => bool) private usedProofs;

    constructor() {
        balances[msg.sender] = TOKEN_SUPPLY;
        owner = msg.sender;
    }

    function transfer(address to, uint256 amount, ZKPLibrary.Proof memory proof) public {
        require(!usedProofs[proof.hash()], "Proof already used");
        require(ZKPLibrary.verifyProof(proof, msg.sender, to, amount), "Invalid proof");

        usedProofs[proof.hash()] = true;
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function balanceOf(address account) public view returns (uint256) {
        return balances[account];
    }

    function isSolved() public view returns (bool) {
        return balances[owner] == 0;
    }
}
