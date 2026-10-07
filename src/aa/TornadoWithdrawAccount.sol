// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {ITornado} from "../interfaces/ITornado.sol";

/// @title TornadoWithdrawAccount
/// @notice Shared, keyless ERC-4337 sender for sponsored Tornado withdrawals. The original problem:
///         the recipient of a withdrawal is a fresh address with no ETH, so it cannot pay gas, and
///         using the depositor's funded address would link the two. Without 4337 the answer is an
///         off-chain relayer network. With this account, anyone can submit a UserOperation to any
///         bundler, and `TornadoPaymaster` pays the gas out of the withdrawal fee.
/// @dev It has no owner and no signature. Authorisation comes from the zk proof, which the paymaster
///      checks during validation and the pool checks again on execution. The proof commits to
///      `recipient`, `relayer` (= paymaster) and `fee`, so a UserOperation copied from the mempool
///      cannot be redirected. The account never holds funds and never pays its own prefund.
///      Nonces: each withdrawal uses nonce key `uint192(nullifierHash)`, so concurrent withdrawals
///      from this shared sender do not queue behind each other, and a second UserOperation for the
///      same note fails nonce validation.
contract TornadoWithdrawAccount is IAccount {
    IEntryPoint public immutable entryPoint;
    /// @notice The paymaster that deployed this account and sponsors every operation.
    address public immutable paymaster;

    error NotEntryPoint();
    error NotPaymaster();

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        paymaster = msg.sender;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32, uint256 missingAccountFunds)
        external
        view
        returns (uint256)
    {
        if (msg.sender != address(entryPoint)) revert NotEntryPoint();
        // Only operations sponsored by our paymaster. Proof, nonce key and fee checks happen there.
        if (
            missingAccountFunds != 0 || userOp.paymasterAndData.length < 20
                || address(bytes20(userOp.paymasterAndData[:20])) != paymaster
        ) return SIG_VALIDATION_FAILED;
        return SIG_VALIDATION_SUCCESS;
    }

    /// @notice Executes the withdrawal, paying `fee` to the paymaster as the relayer.
    function withdraw(
        ITornado pool,
        bytes calldata proof,
        bytes32 root,
        bytes32 nullifierHash,
        address payable recipient,
        uint256 fee
    ) external {
        if (msg.sender != address(entryPoint)) revert NotEntryPoint();
        pool.withdraw(proof, root, nullifierHash, recipient, payable(paymaster), fee, 0);
    }

    // ---- stake management, forwarded by the paymaster owner ----
    // A shared sender has to be staked, otherwise bundlers cap it at a few pending UserOperations
    // in the mempool (ERC-7562 SAME_SENDER_MEMPOOL_COUNT).

    modifier onlyPaymaster() {
        if (msg.sender != paymaster) revert NotPaymaster();
        _;
    }

    function addStake(uint32 unstakeDelaySec) external payable onlyPaymaster {
        entryPoint.addStake{value: msg.value}(unstakeDelaySec);
    }

    function unlockStake() external onlyPaymaster {
        entryPoint.unlockStake();
    }

    function withdrawStake(address payable to) external onlyPaymaster {
        entryPoint.withdrawStake(to);
    }
}
