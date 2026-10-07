// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice OP Stack GasPriceOracle predeploy (0x420000000000000000000000000000000000000F).
/// @dev Only the functions used here. `getL1FeeUpperBound` exists since the Fjord upgrade.
interface IGasPriceOracle {
    function getL1Fee(bytes memory data) external view returns (uint256);
    function getL1FeeUpperBound(uint256 unsignedTxSize) external view returns (uint256);
    function isFjord() external view returns (bool);
}
