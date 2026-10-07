// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Groth16 verifier for the Tornado `withdraw` circuit.
/// @dev Same ABI as the trusted-setup Verifier deployed on mainnet in 2020. `proof` is
///      `abi.encode(uint256[8])`: A.x, A.y, B.x[0], B.x[1], B.y[0], B.y[1], C.x, C.y (EVM ordering).
///      `input` is [root, nullifierHash, recipient, relayer, fee, refund].
interface IVerifier {
    function verifyProof(bytes calldata proof, uint256[6] calldata input) external view returns (bool);
}
