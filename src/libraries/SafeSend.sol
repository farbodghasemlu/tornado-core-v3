// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title SafeSend
/// @notice ETH transfer that never copies return data.
/// @dev `(bool ok,) = to.call{value: v}("")` still copies the callee's entire return data into memory.
///      A hostile receiver can revert with hundreds of kilobytes, which is cheap for the callee but costs
///      the caller quadratic memory expansion and can push it out of gas. That turns "payment failed,
///      fall back" into "whole transaction reverted". Assembly `call` with a zero-length output buffer
///      avoids the copy.
library SafeSend {
    function trySend(address to, uint256 amount, uint256 gasLimit) internal returns (bool ok) {
        assembly ("memory-safe") {
            ok := call(gasLimit, to, amount, 0, 0, 0, 0)
        }
    }

    function trySend(address to, uint256 amount) internal returns (bool ok) {
        assembly ("memory-safe") {
            ok := call(gas(), to, amount, 0, 0, 0, 0)
        }
    }
}
