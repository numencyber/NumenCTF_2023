pragma solidity ^0.8.0;

library ZKPLibrary {
    struct Proof {
        uint256 a;
        uint256 b;
        uint256 c;
    }

    function hash(Proof memory proof) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(proof.a, proof.b, proof.c));
    }

    function verifyProof(Proof memory proof, address from, address to, uint256 amount) internal view returns (bool) {
        uint256 challenge = uint256(keccak256(abi.encodePacked(from, to, amount))) % 2**128;
        uint256 sum = proof.a + proof.b;

        if (proof.a == proof.c || proof.b == proof.c) {
            return false;
        }

        return (sum == amount) && (challenge * proof.a % 2**128 == proof.c);
    }
}
