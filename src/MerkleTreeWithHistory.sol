// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IHasher} from "./interfaces/IHasher.sol";

/// @title MerkleTreeWithHistory
/// @notice Append-only incremental MiMC Merkle tree that remembers its last `ROOT_HISTORY_SIZE` roots.
/// @dev Port of tornado-core's tree. The hashing, zero values and root semantics are unchanged so
///      the original `withdraw` circuit (and its 2020 trusted setup) still applies. Changes:
///      - `levels` is immutable (the original re-read it from storage on every loop iteration)
///      - hashing uses a single `staticcall` per permutation through inline assembly
///      - only the leaf is range-checked; interior nodes are MiMC outputs and always inside the field
///      - custom errors instead of revert strings
///      - the initial root is the actual empty-tree root, zeros(levels)
contract MerkleTreeWithHistory {
    uint256 public constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    /// @dev keccak256("tornado") % FIELD_SIZE
    uint256 public constant ZERO_VALUE = 21663839004416932945382355908790599225266501822907911457504978515578255421292;
    uint32 public constant ROOT_HISTORY_SIZE = 30;

    IHasher public immutable hasher;
    uint32 public immutable levels;

    // Mappings instead of fixed arrays skip the index bounds check (same trick as the original).
    mapping(uint256 => bytes32) public filledSubtrees;
    mapping(uint256 => bytes32) public roots;
    // Packed into a single slot: read and written once per insert.
    uint32 public currentRootIndex;
    uint32 public nextIndex;

    error InvalidLevels();
    error MerkleTreeFull();
    error ValueOutOfField();
    error IndexOutOfBounds();
    error HasherCallFailed();

    constructor(uint32 _levels, IHasher _hasher) {
        if (_levels == 0 || _levels >= 32) revert InvalidLevels();
        levels = _levels;
        hasher = _hasher;

        for (uint32 i; i < _levels; ++i) {
            filledSubtrees[i] = zeros(i);
        }
        // tornado-core used zeros(_levels - 1), the empty root of a tree one level too short (harmless, but wrong)
        roots[0] = zeros(_levels);
    }

    /// @notice MiMC(left, right) exactly as computed by the circuit's `HashLeftRight`. Kept public for ABI compatibility.
    function hashLeftRight(IHasher _hasher, bytes32 _left, bytes32 _right) public view returns (bytes32) {
        if (uint256(_left) >= FIELD_SIZE || uint256(_right) >= FIELD_SIZE) revert ValueOutOfField();
        return _hashLeftRight(_hasher, _left, _right);
    }

    /// @dev Sponge: absorb `left`, permute, add `right` to the rate, permute, squeeze. Inputs must be < FIELD_SIZE.
    function _hashLeftRight(IHasher _hasher, bytes32 _left, bytes32 _right) internal view returns (bytes32 result) {
        bytes4 selector = IHasher.MiMCSponge.selector;
        bytes4 err = HasherCallFailed.selector;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, selector)
            mstore(add(ptr, 0x04), _left)
            mstore(add(ptr, 0x24), 0)
            // returns (xL, xR) into ptr+0x04 so the output feeds straight into the next call
            if iszero(staticcall(gas(), _hasher, ptr, 0x44, add(ptr, 0x04), 0x40)) {
                mstore(0, err)
                revert(0, 0x04)
            }
            mstore(add(ptr, 0x04), addmod(mload(add(ptr, 0x04)), _right, FIELD_SIZE))
            if iszero(staticcall(gas(), _hasher, ptr, 0x44, add(ptr, 0x04), 0x40)) {
                mstore(0, err)
                revert(0, 0x04)
            }
            result := mload(add(ptr, 0x04))
        }
    }

    function _insert(bytes32 _leaf) internal returns (uint32 index) {
        if (uint256(_leaf) >= FIELD_SIZE) revert ValueOutOfField();
        uint32 _levels = levels;
        uint32 _nextIndex = nextIndex;
        if (_nextIndex == uint32(1) << _levels) revert MerkleTreeFull();

        IHasher _hasher = hasher;
        uint32 currentIndex = _nextIndex;
        bytes32 currentLevelHash = _leaf;
        bytes32 left;
        bytes32 right;

        for (uint32 i; i < _levels; ++i) {
            if (currentIndex & 1 == 0) {
                left = currentLevelHash;
                right = zeros(i);
                filledSubtrees[i] = currentLevelHash;
            } else {
                left = filledSubtrees[i];
                right = currentLevelHash;
            }
            currentLevelHash = _hashLeftRight(_hasher, left, right);
            currentIndex >>= 1;
        }

        uint32 newRootIndex;
        unchecked {
            newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
            nextIndex = _nextIndex + 1;
        }
        currentRootIndex = newRootIndex;
        roots[newRootIndex] = currentLevelHash;
        return _nextIndex;
    }

    /// @notice Whether `_root` is one of the last `ROOT_HISTORY_SIZE` roots.
    function isKnownRoot(bytes32 _root) public view returns (bool) {
        if (_root == 0) return false;
        uint32 _currentRootIndex = currentRootIndex;
        uint32 i = _currentRootIndex;
        do {
            if (_root == roots[i]) return true;
            if (i == 0) i = ROOT_HISTORY_SIZE;
            unchecked {
                --i;
            }
        } while (i != _currentRootIndex);
        return false;
    }

    function getLastRoot() public view returns (bytes32) {
        return roots[currentRootIndex];
    }

    /// @notice Zero (empty subtree) values of the MiMC tree. zeros(0) = ZERO_VALUE, zeros(i+1) = MiMC(zeros(i), zeros(i)).
    function zeros(uint256 i) public pure returns (bytes32) {
        if (i == 0) return bytes32(0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c);
        else if (i == 1) return bytes32(0x256a6135777eee2fd26f54b8b7037a25439d5235caee224154186d2b8a52e31d);
        else if (i == 2) return bytes32(0x1151949895e82ab19924de92c40a3d6f7bcb60d92b00504b8199613683f0c200);
        else if (i == 3) return bytes32(0x20121ee811489ff8d61f09fb89e313f14959a0f28bb428a20dba6b0b068b3bdb);
        else if (i == 4) return bytes32(0x0a89ca6ffa14cc462cfedb842c30ed221a50a3d6bf022a6a57dc82ab24c157c9);
        else if (i == 5) return bytes32(0x24ca05c2b5cd42e890d6be94c68d0689f4f21c9cec9c0f13fe41d566dfb54959);
        else if (i == 6) return bytes32(0x1ccb97c932565a92c60156bdba2d08f3bf1377464e025cee765679e604a7315c);
        else if (i == 7) return bytes32(0x19156fbd7d1a8bf5cba8909367de1b624534ebab4f0f79e003bccdd1b182bdb4);
        else if (i == 8) return bytes32(0x261af8c1f0912e465744641409f622d466c3920ac6e5ff37e36604cb11dfff80);
        else if (i == 9) return bytes32(0x0058459724ff6ca5a1652fcbc3e82b93895cf08e975b19beab3f54c217d1c007);
        else if (i == 10) return bytes32(0x1f04ef20dee48d39984d8eabe768a70eafa6310ad20849d4573c3c40c2ad1e30);
        else if (i == 11) return bytes32(0x1bea3dec5dab51567ce7e200a30f7ba6d4276aeaa53e2686f962a46c66d511e5);
        else if (i == 12) return bytes32(0x0ee0f941e2da4b9e31c3ca97a40d8fa9ce68d97c084177071b3cb46cd3372f0f);
        else if (i == 13) return bytes32(0x1ca9503e8935884501bbaf20be14eb4c46b89772c97b96e3b2ebf3a36a948bbd);
        else if (i == 14) return bytes32(0x133a80e30697cd55d8f7d4b0965b7be24057ba5dc3da898ee2187232446cb108);
        else if (i == 15) return bytes32(0x13e6d8fc88839ed76e182c2a779af5b2c0da9dd18c90427a644f7e148a6253b6);
        else if (i == 16) return bytes32(0x1eb16b057a477f4bc8f572ea6bee39561098f78f15bfb3699dcbb7bd8db61854);
        else if (i == 17) return bytes32(0x0da2cb16a1ceaabf1c16b838f7a9e3f2a3a3088d9e0a6debaa748114620696ea);
        else if (i == 18) return bytes32(0x24a3b3d822420b14b5d8cb6c28a574f01e98ea9e940551d2ebd75cee12649f9d);
        else if (i == 19) return bytes32(0x198622acbd783d1b0d9064105b1fc8e4d8889de95c4c519b3f635809fe6afc05);
        else if (i == 20) return bytes32(0x29d7ed391256ccc3ea596c86e933b89ff339d25ea8ddced975ae2fe30b5296d4);
        else if (i == 21) return bytes32(0x19be59f2f0413ce78c0c3703a3a5451b1d7f39629fa33abd11548a76065b2967);
        else if (i == 22) return bytes32(0x1ff3f61797e538b70e619310d33f2a063e7eb59104e112e95738da1254dc3453);
        else if (i == 23) return bytes32(0x10c16ae9959cf8358980d9dd9616e48228737310a10e2b6b731c1a548f036c48);
        else if (i == 24) return bytes32(0x0ba433a63174a90ac20992e75e3095496812b652685b5e1a2eae0b1bf4e8fcd1);
        else if (i == 25) return bytes32(0x019ddb9df2bc98d987d0dfeca9d2b643deafab8f7036562e627c3667266a044c);
        else if (i == 26) return bytes32(0x2d3c88b23175c5a5565db928414c66d1912b11acf974b2e644caaac04739ce99);
        else if (i == 27) return bytes32(0x2eab55f6ae4e66e32c5189eed5c470840863445760f5ed7e7b69b2a62600f354);
        else if (i == 28) return bytes32(0x002df37a2642621802383cf952bf4dd1f32e05433beeb1fd41031fb7eace979d);
        else if (i == 29) return bytes32(0x104aeb41435db66c3e62feccc1d6f5d98d0a0ed75d1374db457cf462e3a1f427);
        else if (i == 30) return bytes32(0x1f3c6fd858e9a7d4b0d1f38e256a09d81d5a5e3c963987e2d4b814cfab7c6ebb);
        else if (i == 31) return bytes32(0x2c7a07d20dff79d01fecedc1134284a8d08436606c93693b67e333f671bf69cc);
        else revert IndexOutOfBounds();
    }
}
