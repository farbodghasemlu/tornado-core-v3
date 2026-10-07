// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TornadoFixture} from "./utils/TornadoFixture.sol";
import {MerkleTreeWithHistory} from "../src/MerkleTreeWithHistory.sol";
import {IHasher} from "../src/interfaces/IHasher.sol";

contract MerkleTreeHarness is MerkleTreeWithHistory {
    constructor(uint32 levels_, IHasher hasher_) MerkleTreeWithHistory(levels_, hasher_) {}

    function insert(bytes32 leaf) external returns (uint32) {
        return _insert(leaf);
    }
}

contract MerkleTreeTest is TornadoFixture {
    MerkleTreeHarness tree;

    function setUp() public {
        _deployCore();
        tree = new MerkleTreeHarness(LEVELS, hasher);
    }

    function test_zerosAreHashChain() public {
        assertEq(uint256(tree.zeros(0)), tree.ZERO_VALUE());
        assertEq(uint256(keccak256("tornado")) % FIELD_SIZE, tree.ZERO_VALUE());
        for (uint256 i; i < 31; ++i) {
            assertEq(tree.hashLeftRight(hasher, tree.zeros(i), tree.zeros(i)), tree.zeros(i + 1));
        }
        vm.expectRevert(MerkleTreeWithHistory.IndexOutOfBounds.selector);
        tree.zeros(32);
    }

    function test_initialState() public view {
        assertEq(tree.getLastRoot(), tree.zeros(LEVELS), "empty root");
        assertEq(tree.nextIndex(), 0);
        for (uint256 i; i < LEVELS; ++i) {
            assertEq(tree.filledSubtrees(i), tree.zeros(i));
        }
        assertFalse(tree.isKnownRoot(0));
    }

    /// @dev Differential test: the on-chain incremental tree must match an independent JS implementation.
    /// forge-config: default.fuzz.runs = 24
    function testFuzz_rootMatchesJs(uint256 seed, uint8 count) public {
        count = uint8(bound(count, 1, 9));
        bytes32[] memory leaves = new bytes32[](count);
        for (uint256 i; i < count; ++i) {
            leaves[i] = bytes32(uint256(keccak256(abi.encode(seed, i))) % FIELD_SIZE);
            assertEq(tree.insert(leaves[i]), i);
        }
        assertEq(tree.getLastRoot(), _jsRoot(leaves));
        assertTrue(tree.isKnownRoot(tree.getLastRoot()));
    }

    function test_rootHistoryWindow() public {
        bytes32[] memory history = new bytes32[](ROOT_HISTORY + 1);
        history[0] = tree.getLastRoot();
        for (uint256 i = 1; i <= ROOT_HISTORY; ++i) {
            tree.insert(bytes32(i));
            history[i] = tree.getLastRoot();
        }
        // The window holds the last 30 roots; the empty-tree root was the 31st most recent and is gone.
        assertFalse(tree.isKnownRoot(history[0]));
        for (uint256 i = 1; i <= ROOT_HISTORY; ++i) {
            assertTrue(tree.isKnownRoot(history[i]));
        }
        tree.insert(bytes32(uint256(999)));
        assertFalse(tree.isKnownRoot(history[1]));
        assertTrue(tree.isKnownRoot(history[2]));
    }

    uint256 constant ROOT_HISTORY = 30;

    function test_treeFull() public {
        MerkleTreeHarness small = new MerkleTreeHarness(2, hasher);
        for (uint256 i; i < 4; ++i) {
            small.insert(bytes32(i + 1));
        }
        vm.expectRevert(MerkleTreeWithHistory.MerkleTreeFull.selector);
        small.insert(bytes32(uint256(5)));
    }

    function testFuzz_rejectsLeafOutsideField(uint256 leaf) public {
        leaf = bound(leaf, FIELD_SIZE, type(uint256).max);
        vm.expectRevert(MerkleTreeWithHistory.ValueOutOfField.selector);
        tree.insert(bytes32(leaf));
    }

    function test_rejectsBadLevels() public {
        vm.expectRevert(MerkleTreeWithHistory.InvalidLevels.selector);
        new MerkleTreeHarness(0, hasher);
        vm.expectRevert(MerkleTreeWithHistory.InvalidLevels.selector);
        new MerkleTreeHarness(32, hasher);
    }

    function testFuzz_hashLeftRightRejectsOutOfField(uint256 v) public {
        v = bound(v, FIELD_SIZE, type(uint256).max);
        vm.expectRevert(MerkleTreeWithHistory.ValueOutOfField.selector);
        tree.hashLeftRight(hasher, bytes32(v), 0);
        vm.expectRevert(MerkleTreeWithHistory.ValueOutOfField.selector);
        tree.hashLeftRight(hasher, 0, bytes32(v));
    }
}
