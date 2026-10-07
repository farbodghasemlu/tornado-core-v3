// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Tornado} from "./Tornado.sol";
import {IHasher} from "./interfaces/IHasher.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {SafeSend} from "./libraries/SafeSend.sol";

/// @title ETHTornado
/// @notice Tornado pool for the chain's native asset (ETH on Ethereum and Base).
/// @dev Difference from tornado-core: a recipient that rejects ETH (or burns all forwarded gas) no longer
///      reverts the withdrawal. The payout is credited to `pendingPayouts` and the recipient claims it.
///      In the original, a hostile recipient could make a relayer (or a 4337 paymaster) pay for a reverted
///      transaction without spending the note, then repeat that indefinitely. The recipient call never
///      copies return data (see `SafeSend`), so a "return bomb" cannot bring that back either. The relayer
///      payment still reverts on failure, since the relayer chose its own address.
contract ETHTornado is Tornado {
    /// @dev Gas kept back from the recipient call so the fallback path (SSTORE + relayer payment + event) can always finish.
    uint256 public constant PAYOUT_GAS_RESERVE = 60_000;

    mapping(address => uint256) public pendingPayouts;

    event PayoutDeferred(address indexed recipient, uint256 amount);
    event PayoutClaimed(address indexed recipient, address to, uint256 amount);

    error IncorrectDepositValue();
    error UnexpectedValue();
    error RefundNotSupported();
    error NothingToClaim();
    error PaymentFailed(address to);

    constructor(IVerifier _verifier, IHasher _hasher, uint256 _denomination, uint32 _merkleTreeHeight)
        Tornado(_verifier, _hasher, _denomination, _merkleTreeHeight)
    {}

    /// @notice Claim a payout that could not be delivered during `withdraw`.
    function claimPayout(address payable _to) external nonReentrant {
        uint256 amount = pendingPayouts[msg.sender];
        if (amount == 0) revert NothingToClaim();
        pendingPayouts[msg.sender] = 0;
        emit PayoutClaimed(msg.sender, _to, amount);
        _send(_to, amount);
    }

    function _processDeposit() internal override {
        if (msg.value != denomination) revert IncorrectDepositValue();
    }

    function _processWithdraw(address payable _recipient, address payable _relayer, uint256 _fee, uint256 _refund)
        internal
        override
    {
        if (msg.value != 0) revert UnexpectedValue();
        if (_refund != 0) revert RefundNotSupported();

        uint256 amount = denomination - _fee;
        uint256 gasLeft = gasleft();
        uint256 payoutGas = gasLeft > PAYOUT_GAS_RESERVE ? gasLeft - PAYOUT_GAS_RESERVE : 0;
        if (!SafeSend.trySend(_recipient, amount, payoutGas)) {
            pendingPayouts[_recipient] += amount;
            emit PayoutDeferred(_recipient, amount);
        }
        if (_fee > 0) _send(_relayer, _fee);
    }

    function _send(address to, uint256 amount) private {
        if (!SafeSend.trySend(to, amount)) revert PaymentFailed(to);
    }
}
