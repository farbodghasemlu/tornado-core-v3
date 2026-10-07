// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {MerkleTreeWithHistory} from "./MerkleTreeWithHistory.sol";
import {IHasher} from "./interfaces/IHasher.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";

/// @title Tornado
/// @notice Fixed-denomination shielded pool. Deposit a Pedersen commitment, later withdraw to any
///         address with a zkSNARK proving knowledge of a committed note, without revealing which one.
/// @dev ABI and event compatible with tornado-core v2.1; proofs from the original circuit and
///      trusted setup verify unchanged. Modernised for Solidity 0.8 / Cancun:
///      - EIP-1153 transient-storage reentrancy guard (no cold SSTORE on every call)
///      - immutable verifier and denomination, custom errors
///      - deposit/withdraw bodies split into internal hooks so subclasses can add entrypoints
///        (permit deposits, sponsored withdrawals) without duplicating the core logic
abstract contract Tornado is MerkleTreeWithHistory, ReentrancyGuardTransient {
    IVerifier public immutable verifier;
    uint256 public immutable denomination;

    mapping(bytes32 => bool) public nullifierHashes;
    /// @dev Guards against accidentally depositing the same note twice (the second deposit would be unwithdrawable).
    mapping(bytes32 => bool) public commitments;

    event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
    event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee);

    error InvalidDenomination();
    error CommitmentAlreadySubmitted();
    error FeeExceedsDenomination();
    error NoteAlreadySpent();
    error UnknownRoot();
    error InvalidProof();

    constructor(IVerifier _verifier, IHasher _hasher, uint256 _denomination, uint32 _merkleTreeHeight)
        MerkleTreeWithHistory(_merkleTreeHeight, _hasher)
    {
        if (_denomination == 0) revert InvalidDenomination();
        verifier = _verifier;
        denomination = _denomination;
    }

    /// @notice Deposit `denomination` into the pool. ETH pools take it as `msg.value`, ERC20 pools pull it via `transferFrom`.
    /// @param _commitment PedersenHash(nullifier || secret)
    function deposit(bytes32 _commitment) external payable nonReentrant {
        _insertCommitment(_commitment);
        _processDeposit();
    }

    /// @notice Withdraw one note.
    /// @param _proof Groth16 proof, `abi.encode(uint256[8])`
    /// @param _root A recent Merkle root (one of the last `ROOT_HISTORY_SIZE`)
    /// @param _nullifierHash PedersenHash(nullifier); marks the note as spent
    /// @param _recipient Receives `denomination - fee` (and `refund` on ERC20 pools)
    /// @param _relayer Receives `fee`
    /// @param _fee Paid to the relayer out of the note
    /// @param _refund ETH forwarded by the relayer to the recipient for gas (ERC20 pools only)
    function withdraw(
        bytes calldata _proof,
        bytes32 _root,
        bytes32 _nullifierHash,
        address payable _recipient,
        address payable _relayer,
        uint256 _fee,
        uint256 _refund
    ) external payable nonReentrant {
        _verifyAndNullify(_proof, _root, _nullifierHash, _recipient, _relayer, _fee, _refund);
        _processWithdraw(_recipient, _relayer, _fee, _refund);
        emit Withdrawal(_recipient, _nullifierHash, _relayer, _fee);
    }

    function _insertCommitment(bytes32 _commitment) internal {
        if (commitments[_commitment]) revert CommitmentAlreadySubmitted();
        commitments[_commitment] = true;
        uint32 insertedIndex = _insert(_commitment);
        emit Deposit(_commitment, insertedIndex, block.timestamp);
    }

    function _verifyAndNullify(
        bytes calldata _proof,
        bytes32 _root,
        bytes32 _nullifierHash,
        address _recipient,
        address _relayer,
        uint256 _fee,
        uint256 _refund
    ) internal {
        if (_fee > denomination) revert FeeExceedsDenomination();
        if (nullifierHashes[_nullifierHash]) revert NoteAlreadySpent();
        if (!isKnownRoot(_root)) revert UnknownRoot();
        uint256[6] memory input = [
            uint256(_root),
            uint256(_nullifierHash),
            uint256(uint160(_recipient)),
            uint256(uint160(_relayer)),
            _fee,
            _refund
        ];
        if (!_verifyProof(_proof, input)) revert InvalidProof();
        nullifierHashes[_nullifierHash] = true;
    }

    /// @dev The ceremony verifier reverts (instead of returning false) on out-of-range inputs; treat both as invalid.
    function _verifyProof(bytes calldata _proof, uint256[6] memory _input) internal view returns (bool) {
        try verifier.verifyProof(_proof, _input) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    /// @dev Collect the deposit. Called after the commitment is inserted, inside the reentrancy guard.
    function _processDeposit() internal virtual;

    /// @dev Pay out a withdrawal. Called after the nullifier is marked spent, inside the reentrancy guard.
    function _processWithdraw(address payable _recipient, address payable _relayer, uint256 _fee, uint256 _refund)
        internal
        virtual;

    function isSpent(bytes32 _nullifierHash) public view returns (bool) {
        return nullifierHashes[_nullifierHash];
    }

    function isSpentArray(bytes32[] calldata _nullifierHashes) external view returns (bool[] memory spent) {
        spent = new bool[](_nullifierHashes.length);
        for (uint256 i; i < _nullifierHashes.length; ++i) {
            spent[i] = nullifierHashes[_nullifierHashes[i]];
        }
    }
}
