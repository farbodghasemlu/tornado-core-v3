// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IVerifier} from "./IVerifier.sol";

/// @notice External surface of a Tornado pool. ABI compatible with the original
///         tornado-core instances, so existing clients and relayers keep working.
interface ITornado {
    event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
    event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee);

    function deposit(bytes32 commitment) external payable;

    function withdraw(
        bytes calldata proof,
        bytes32 root,
        bytes32 nullifierHash,
        address payable recipient,
        address payable relayer,
        uint256 fee,
        uint256 refund
    ) external payable;

    function verifier() external view returns (IVerifier);
    function denomination() external view returns (uint256);
    function isKnownRoot(bytes32 root) external view returns (bool);
    function isSpent(bytes32 nullifierHash) external view returns (bool);
    function getLastRoot() external view returns (bytes32);
}
