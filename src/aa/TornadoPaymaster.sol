// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BasePaymaster} from "account-abstraction/core/BasePaymaster.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ITornado} from "../interfaces/ITornado.sol";
import {IVerifier} from "../interfaces/IVerifier.sol";
import {TornadoWithdrawAccount} from "./TornadoWithdrawAccount.sol";
import {SafeSend} from "../libraries/SafeSend.sol";

/// @title TornadoPaymaster
/// @notice ERC-4337 paymaster that sponsors Tornado ETH withdrawals and is repaid from the
///         withdrawal itself. The proof names this contract as `relayer`, so the pool pays the
///         fee here. Unused fee is refunded to the recipient in `postOp`, and the rest is deposited
///         back into the EntryPoint, so the paymaster refills itself.
/// @dev Validation is designed so that an operation that passes validation cannot then revert in
///      execution and leave the paymaster with the gas bill:
///      - zk proof verified with the ERC-7562-compatible `Groth16Verifier` (same ceremony key as the pools)
///      - nullifier unspent, root known and fee <= denomination, read from the pool. This needs the
///        paymaster to be staked: ERC-7562 STO-033 lets staked entities read non-entity storage.
///      - `callGasLimit` and `postOpGasLimit` floors, so the user cannot starve execution
///      - recipient payment failures are absorbed by `ETHTornado`'s deferred payouts
///      - the postOp refund is gas-capped, never copies return data, and cannot revert
///      What remains is a race: the same note withdrawn directly between validation and inclusion.
///      Doing that means spending the note and paying for a transaction, so it costs the attacker
///      about as much as it costs the paymaster.
contract TornadoPaymaster is BasePaymaster {
    using UserOperationLib for PackedUserOperation;

    uint256 internal constant BPS = 10_000;
    uint256 public constant MAX_FEE_MARKUP_BPS = 5_000;
    /// @notice Gas charged for `postOp` itself (it runs after `actualGasCost` is measured), and the minimum
    ///         `postOpGasLimit`. Covers the worst case: a 30k refund call that fails, then two fresh SSTOREs
    ///         to defer the refund. If postOp ran out of gas, EntryPoint would revert the whole op and the
    ///         paymaster would pay for nothing.
    uint256 public constant POST_OP_GAS = 120_000;
    /// @notice Gas forwarded with the refund to the recipient; failures keep the refund claimable.
    uint256 public constant REFUND_GAS = 30_000;
    /// @notice Floor for `callGasLimit`: a pool withdraw with the ceremony verifier uses about 350k gas.
    uint256 public constant MIN_CALL_GAS_LIMIT = 450_000;

    TornadoWithdrawAccount public immutable account;
    /// @notice Validation-safe verifier for the Tornado withdraw circuit (2020 ceremony key).
    IVerifier public immutable verifier;

    mapping(ITornado pool => bool) public isSupportedPool;
    uint256 public feeMarkupBps;
    mapping(address recipient => uint256) public pendingRefunds;
    uint256 public totalPendingRefunds;

    event PoolSupportUpdated(ITornado indexed pool, bool supported);
    event FeeMarkupUpdated(uint256 feeMarkupBps);
    event WithdrawalSponsored(
        bytes32 indexed nullifierHash, address indexed recipient, uint256 charged, uint256 refund
    );
    event RefundDeferred(address indexed recipient, uint256 amount);

    error NotWithdrawAccount();
    error UnsupportedCall();
    error UnsupportedPool(ITornado pool);
    error NonceKeyMismatch();
    error NoteAlreadySpent();
    error UnknownRoot();
    error InvalidProof();
    error FeeExceedsDenomination();
    error FeeTooLow(uint256 fee, uint256 required);
    error GasLimitTooLow();
    error MarkupTooHigh();
    error NothingToClaim();
    error TransferFailed();

    constructor(IEntryPoint _entryPoint, IVerifier _verifier, uint256 _feeMarkupBps) BasePaymaster(_entryPoint) {
        if (_feeMarkupBps > MAX_FEE_MARKUP_BPS) revert MarkupTooHigh();
        account = new TornadoWithdrawAccount(_entryPoint);
        verifier = _verifier;
        feeMarkupBps = _feeMarkupBps;
    }

    /// @notice Receives withdrawal fees from pools.
    receive() external payable {}

    // ------------------------------------------------------------------------------------------
    // ERC-4337
    // ------------------------------------------------------------------------------------------

    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32, uint256 maxCost)
        internal
        view
        override
        returns (bytes memory context, uint256 validationData)
    {
        if (userOp.sender != address(account)) revert NotWithdrawAccount();
        if (userOp.callData.length < 4 || bytes4(userOp.callData[:4]) != TornadoWithdrawAccount.withdraw.selector) {
            revert UnsupportedCall();
        }
        if (userOp.unpackCallGasLimit() < MIN_CALL_GAS_LIMIT || userOp.unpackPostOpGasLimit() < POST_OP_GAS) {
            revert GasLimitTooLow();
        }

        (ITornado pool, bytes memory proof, bytes32 root, bytes32 nullifierHash, address recipient, uint256 fee) =
            abi.decode(userOp.callData[4:], (ITornado, bytes, bytes32, bytes32, address, uint256));

        if (!isSupportedPool[pool]) revert UnsupportedPool(pool);
        if (userOp.nonce >> 64 != uint192(uint256(nullifierHash))) revert NonceKeyMismatch();
        if (fee > pool.denomination()) revert FeeExceedsDenomination();
        if (pool.isSpent(nullifierHash)) revert NoteAlreadySpent();
        if (!pool.isKnownRoot(root)) revert UnknownRoot();

        uint256 required = _applyMarkup(maxCost);
        if (fee < required) revert FeeTooLow(fee, required);

        uint256[6] memory input = [
            uint256(root), uint256(nullifierHash), uint256(uint160(recipient)), uint256(uint160(address(this))), fee, 0
        ];
        if (!verifier.verifyProof(proof, input)) revert InvalidProof();

        return (abi.encode(recipient, fee, nullifierHash), 0);
    }

    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        internal
        override
    {
        // On revert the pool paid nothing; the paymaster absorbs the gas (see contract docs for why this is bounded).
        if (mode != PostOpMode.opSucceeded) return;

        (address recipient, uint256 fee, bytes32 nullifierHash) = abi.decode(context, (address, uint256, bytes32));
        uint256 charged = _applyMarkup(actualGasCost + POST_OP_GAS * actualUserOpFeePerGas);
        if (charged > fee) charged = fee;
        uint256 refund = fee - charged;

        if (refund > 0) {
            if (!SafeSend.trySend(recipient, refund, REFUND_GAS)) {
                pendingRefunds[recipient] += refund;
                totalPendingRefunds += refund;
                emit RefundDeferred(recipient, refund);
            }
        }
        // Earnings go straight back into the EntryPoint deposit that pays for the next withdrawals.
        entryPoint.depositTo{value: charged}(address(this));
        emit WithdrawalSponsored(nullifierHash, recipient, charged, refund);
    }

    function _applyMarkup(uint256 cost) internal view returns (uint256) {
        return cost * (BPS + feeMarkupBps) / BPS;
    }

    // ------------------------------------------------------------------------------------------
    // Quoting
    // ------------------------------------------------------------------------------------------

    /// @notice Minimum `fee` to put in the proof for a UserOperation with these gas parameters.
    /// @dev Mirrors EntryPoint's maxCost: (verification + call + pm verification + postOp + preVerification) × maxFeePerGas.
    ///      On an OP Stack L2, `preVerificationGas` has to include the L1 data fee (see `TornadoFeeQuoter.l1PreVerificationGas`).
    function quoteFee(
        uint256 verificationGasLimit,
        uint256 callGasLimit,
        uint256 paymasterVerificationGasLimit,
        uint256 paymasterPostOpGasLimit,
        uint256 preVerificationGas,
        uint256 maxFeePerGas
    ) external view returns (uint256) {
        uint256 maxGas = verificationGasLimit + callGasLimit + paymasterVerificationGasLimit + paymasterPostOpGasLimit
            + preVerificationGas;
        return _applyMarkup(maxGas * maxFeePerGas);
    }

    // ------------------------------------------------------------------------------------------
    // Admin
    // ------------------------------------------------------------------------------------------

    /// @notice Only ETH pools that use the 2020 ceremony circuit are supported (the fee is taken in ETH).
    function setPoolSupport(ITornado pool, bool supported) external onlyOwner {
        isSupportedPool[pool] = supported;
        emit PoolSupportUpdated(pool, supported);
    }

    function setFeeMarkup(uint256 _feeMarkupBps) external onlyOwner {
        if (_feeMarkupBps > MAX_FEE_MARKUP_BPS) revert MarkupTooHigh();
        feeMarkupBps = _feeMarkupBps;
        emit FeeMarkupUpdated(_feeMarkupBps);
    }

    function addAccountStake(uint32 unstakeDelaySec) external payable onlyOwner {
        account.addStake{value: msg.value}(unstakeDelaySec);
    }

    function unlockAccountStake() external onlyOwner {
        account.unlockStake();
    }

    function withdrawAccountStake(address payable to) external onlyOwner {
        account.withdrawStake(to);
    }

    /// @notice Recipients whose refund could not be delivered in `postOp` collect it here.
    function claimRefund(address payable to) external {
        uint256 amount = pendingRefunds[msg.sender];
        if (amount == 0) revert NothingToClaim();
        pendingRefunds[msg.sender] = 0;
        totalPendingRefunds -= amount;
        if (!SafeSend.trySend(to, amount)) revert TransferFailed();
    }

    /// @notice Moves ETH that is not owed to anyone (e.g. fees from direct withdrawals that named this
    ///         contract as relayer) into the EntryPoint deposit.
    function depositSurplus() external {
        entryPoint.depositTo{value: address(this).balance - totalPendingRefunds}(address(this));
    }
}
