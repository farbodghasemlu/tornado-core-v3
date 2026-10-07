// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {IHasher} from "../../src/interfaces/IHasher.sol";
import {IVerifier} from "../../src/interfaces/IVerifier.sol";
import {Groth16Verifier} from "../../src/verifier/Groth16Verifier.sol";
import {MiMCSpongeDeployer} from "../../src/hasher/MiMCSpongeDeployer.sol";

/// @dev Shared deployment + FFI bindings to js/ffi.js, which builds notes, Merkle paths and real
///      Groth16 proofs with the 2020 Tornado trusted-setup proving key.
abstract contract TornadoFixture is Test {
    uint32 internal constant LEVELS = 20;
    uint256 internal constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    IHasher internal hasher;
    /// @dev The exact trusted-setup verifier deployed on Ethereum mainnet in 2020 (solc 0.5.17).
    IVerifier internal ceremonyVerifier;
    Groth16Verifier internal groth16Verifier;

    struct Proof {
        bytes proof;
        bytes32 root;
        bytes32 nullifierHash;
    }

    function _deployCore() internal {
        hasher = MiMCSpongeDeployer.deploy();
        ceremonyVerifier = IVerifier(deployCode("src/verifier/Verifier.sol:Verifier"));
        groth16Verifier = new Groth16Verifier();
        vm.label(address(hasher), "MiMCSponge");
        vm.label(address(ceremonyVerifier), "CeremonyVerifier");
        vm.label(address(groth16Verifier), "Groth16Verifier");
    }

    /// @return commitment PedersenHash(nullifier || secret) of the note derived from `seed`
    /// @return nullifierHash PedersenHash(nullifier)
    function _note(string memory seed) internal returns (bytes32 commitment, bytes32 nullifierHash) {
        string[] memory cmd = new string[](4);
        cmd[0] = "node";
        cmd[1] = "js/ffi.js";
        cmd[2] = "note";
        cmd[3] = seed;
        (commitment, nullifierHash) = abi.decode(vm.ffi(cmd), (bytes32, bytes32));
    }

    /// @notice Real Groth16 proof that the note `seed` is in the tree made of `leaves`.
    function _prove(
        string memory seed,
        address recipient,
        address relayer,
        uint256 fee,
        uint256 refund,
        bytes32[] memory leaves
    ) internal returns (Proof memory p) {
        string[] memory cmd = new string[](9);
        cmd[0] = "node";
        cmd[1] = "js/ffi.js";
        cmd[2] = "prove";
        cmd[3] = seed;
        cmd[4] = vm.toString(recipient);
        cmd[5] = vm.toString(relayer);
        cmd[6] = vm.toString(fee);
        cmd[7] = vm.toString(refund);
        cmd[8] = _join(leaves);
        (p.proof, p.root, p.nullifierHash) = abi.decode(vm.ffi(cmd), (bytes, bytes32, bytes32));
    }

    /// @notice Root of the depth-20 MiMC tree over `leaves`, computed independently in JS.
    function _jsRoot(bytes32[] memory leaves) internal returns (bytes32) {
        string[] memory cmd = new string[](4);
        cmd[0] = "node";
        cmd[1] = "js/ffi.js";
        cmd[2] = "root";
        cmd[3] = _join(leaves);
        return abi.decode(vm.ffi(cmd), (bytes32));
    }

    function _join(bytes32[] memory leaves) internal pure returns (string memory s) {
        for (uint256 i; i < leaves.length; ++i) {
            s = i == 0 ? vm.toString(leaves[i]) : string.concat(s, ",", vm.toString(leaves[i]));
        }
    }

    function _leaves1(bytes32 a) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](1);
        l[0] = a;
    }

    function _leaves2(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](2);
        l[0] = a;
        l[1] = b;
    }

    function _inputs(Proof memory p, address recipient, address relayer, uint256 fee, uint256 refund)
        internal
        pure
        returns (uint256[6] memory)
    {
        return [
            uint256(p.root),
            uint256(p.nullifierHash),
            uint256(uint160(recipient)),
            uint256(uint160(relayer)),
            fee,
            refund
        ];
    }
}
