// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IGasPriceOracle} from "../interfaces/IGasPriceOracle.sol";

/// @title TornadoFeeQuoter
/// @notice Prices a withdrawal on an OP Stack L2 such as Base, where cost has two parts:
///         L2 execution (gas × L2 gas price) and the L1 data fee for posting the transaction to
///         Ethereum. The original relayer fee formula (gas × gasPrice) ignores the L1 part. Since
///         EIP-4844 it is usually small on Base (about 2% of a withdrawal in Oct 2026), but it tracks
///         L1 blob and base fees and can spike far above L2 execution cost, so a relayer that leaves
///         it out can lose money on every relay. Intended for `eth_call` by relayers and clients.
/// @dev On chains without the GasPriceOracle predeploy the L1 component is zero, so the same
///      quoter works on L1 and non-OP chains.
contract TornadoFeeQuoter {
    IGasPriceOracle public constant GAS_PRICE_ORACLE = IGasPriceOracle(0x420000000000000000000000000000000000000F);
    uint256 internal constant BPS = 10_000;

    /// @notice Unsigned size of a `withdraw` transaction: 4 selector + 7 head words + proof length + 256 proof
    ///         bytes, plus about 100 bytes of RLP envelope (nonce, gas fields, to, value, chain id, access list).
    uint256 public constant WITHDRAW_TX_SIZE = 4 + 7 * 32 + 32 + 256 + 100;

    /// @notice Whether this chain exposes the OP Stack GasPriceOracle (set at deployment).
    bool public immutable isOPStack;

    constructor() {
        isOPStack = address(GAS_PRICE_ORACLE).code.length > 0;
    }

    /// @notice Worst-case L1 data fee (wei) for a transaction of `unsignedTxSize` bytes.
    /// @dev Uses `getL1FeeUpperBound`, which assumes incompressible data, so relayers never under-charge.
    function l1DataFee(uint256 unsignedTxSize) public view returns (uint256) {
        if (!isOPStack) return 0;
        return GAS_PRICE_ORACLE.getL1FeeUpperBound(unsignedTxSize);
    }

    /// @notice Minimum relayer fee (in wei) for relaying a withdrawal.
    /// @param gasLimit L2 gas the withdrawal is expected to use
    /// @param gasPrice L2 gas price the relayer will pay; 0 means "use the current base fee"
    /// @param marginBps relayer margin on top of cost, in basis points
    function quoteRelayerFee(uint256 gasLimit, uint256 gasPrice, uint256 marginBps)
        external
        view
        returns (uint256 fee, uint256 l2ExecutionCost, uint256 l1DataCost)
    {
        if (gasPrice == 0) gasPrice = block.basefee;
        l2ExecutionCost = gasLimit * gasPrice;
        l1DataCost = l1DataFee(WITHDRAW_TX_SIZE);
        fee = (l2ExecutionCost + l1DataCost) * (BPS + marginBps) / BPS;
    }

    /// @notice Extra `preVerificationGas` a UserOperation needs on this chain so the bundler recovers the
    ///         L1 data fee. This is how 4337 prices L1 data on L2s: the bundler pays the L1 fee and charges
    ///         for it through `preVerificationGas`, which the paymaster pays as part of `actualGasCost`.
    /// @param userOpSize ABI-encoded size of the UserOperation inside `handleOps`
    /// @param maxFeePerGas the UserOperation's maxFeePerGas
    function l1PreVerificationGas(uint256 userOpSize, uint256 maxFeePerGas) external view returns (uint256) {
        if (maxFeePerGas == 0) return 0;
        uint256 fee = l1DataFee(userOpSize);
        return (fee + maxFeePerGas - 1) / maxFeePerGas;
    }
}
