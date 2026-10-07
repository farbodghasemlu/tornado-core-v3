// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {Tornado} from "./Tornado.sol";
import {IHasher} from "./interfaces/IHasher.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {SafeSend} from "./libraries/SafeSend.sol";

/// @title ERC20Tornado
/// @notice Tornado pool for an ERC20 token, with three ways to deposit:
///         - `deposit`: classic approve + transferFrom (ABI compatible with tornado-core)
///         - `depositWithPermit`: EIP-2612 permit and deposit in a single transaction
///         - `depositWithPermit2`: Uniswap Permit2 signature transfer whose signature commits to the
///           note commitment (a Permit2 "witness"). Anyone can submit it, e.g. a relayer or a
///           4337 bundler, and nobody can redirect the funds into a different note.
/// @dev Every deposit path checks the balance delta, so fee-on-transfer or rebasing-down tokens revert
///      on deposit instead of making the pool insolvent.
contract ERC20Tornado is Tornado {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    ISignatureTransfer public immutable permit2;

    bytes32 public constant DEPOSIT_WITNESS_TYPEHASH = keccak256("Deposit(bytes32 commitment)");
    /// @dev Permit2 appends this to "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,"
    string public constant DEPOSIT_WITNESS_TYPE_STRING =
        "Deposit witness)Deposit(bytes32 commitment)TokenPermissions(address token,uint256 amount)";

    error UnexpectedValue();
    error IncorrectRefundValue();
    error WrongPermitToken();
    error IncorrectAmountReceived(uint256 received);
    error RefundFailed();

    constructor(
        IVerifier _verifier,
        IHasher _hasher,
        uint256 _denomination,
        uint32 _merkleTreeHeight,
        IERC20 _token,
        ISignatureTransfer _permit2
    ) Tornado(_verifier, _hasher, _denomination, _merkleTreeHeight) {
        token = _token;
        permit2 = _permit2;
    }

    /// @notice EIP-2612 permit + deposit. If the permit was already used (e.g. front-run), the
    ///         existing allowance is used instead so the deposit cannot be griefed.
    function depositWithPermit(bytes32 _commitment, uint256 _deadline, uint8 _v, bytes32 _r, bytes32 _s)
        external
        nonReentrant
    {
        try IERC20Permit(address(token)).permit(msg.sender, address(this), denomination, _deadline, _v, _r, _s) {}
            catch {}
        _insertCommitment(_commitment);
        _processDeposit();
    }

    /// @notice Deposit `denomination` from `_owner` using a Permit2 witness signature over `_commitment`.
    /// @dev `_owner` signs PermitWitnessTransferFrom{permitted: {token, denomination}, spender: this pool,
    ///      nonce, deadline, witness: Deposit{commitment}}. The caller can be anyone.
    function depositWithPermit2(
        bytes32 _commitment,
        address _owner,
        ISignatureTransfer.PermitTransferFrom calldata _permit,
        bytes calldata _signature
    ) external nonReentrant {
        if (_permit.permitted.token != address(token)) revert WrongPermitToken();
        _insertCommitment(_commitment);

        uint256 balanceBefore = token.balanceOf(address(this));
        permit2.permitWitnessTransferFrom(
            _permit,
            ISignatureTransfer.SignatureTransferDetails({to: address(this), requestedAmount: denomination}),
            _owner,
            keccak256(abi.encode(DEPOSIT_WITNESS_TYPEHASH, _commitment)),
            DEPOSIT_WITNESS_TYPE_STRING,
            _signature
        );
        _checkReceived(balanceBefore);
    }

    function _processDeposit() internal override {
        if (msg.value != 0) revert UnexpectedValue();
        uint256 balanceBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), denomination);
        _checkReceived(balanceBefore);
    }

    function _checkReceived(uint256 _balanceBefore) private view {
        uint256 received = token.balanceOf(address(this)) - _balanceBefore;
        if (received != denomination) revert IncorrectAmountReceived(received);
    }

    function _processWithdraw(address payable _recipient, address payable _relayer, uint256 _fee, uint256 _refund)
        internal
        override
    {
        if (msg.value != _refund) revert IncorrectRefundValue();

        token.safeTransfer(_recipient, denomination - _fee);
        if (_fee > 0) token.safeTransfer(_relayer, _fee);

        if (_refund > 0) {
            // A recipient that rejects ETH must not be able to block its own withdrawal:
            // the refund goes back to the relayer instead.
            if (!SafeSend.trySend(_recipient, _refund) && !SafeSend.trySend(_relayer, _refund)) {
                revert RefundFailed();
            }
        }
    }
}
