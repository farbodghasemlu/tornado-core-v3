// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";

/// @dev Installs the canonical Permit2 (runtime bytecode fetched from Base Sepolia) and signs witness transfers.
abstract contract Permit2Helper is Test {
    ISignatureTransfer internal constant PERMIT2 = ISignatureTransfer(0x000000000022D473030F116dDEE9F6B43aC78BA3);

    bytes32 internal constant TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
    string internal constant PERMIT_WITNESS_STUB =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";

    function _installPermit2() internal {
        if (address(PERMIT2).code.length == 0) {
            vm.etch(address(PERMIT2), vm.parseBytes(vm.trim(vm.readFile("test/fixtures/permit2.runtime.hex"))));
        }
        vm.label(address(PERMIT2), "Permit2");
    }

    function _signPermit2Witness(
        uint256 ownerKey,
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender,
        bytes32 witness,
        string memory witnessTypeString
    ) internal view returns (bytes memory) {
        bytes32 typeHash = keccak256(abi.encodePacked(PERMIT_WITNESS_STUB, witnessTypeString));
        bytes32 structHash = keccak256(
            abi.encode(
                typeHash,
                keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, permit.permitted)),
                spender,
                permit.nonce,
                permit.deadline,
                witness
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", PERMIT2.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
