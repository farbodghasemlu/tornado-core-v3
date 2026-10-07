// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TornadoFixture} from "./utils/TornadoFixture.sol";
import {ETHTornado} from "../src/ETHTornado.sol";
import {Tornado} from "../src/Tornado.sol";
import {MerkleTreeWithHistory} from "../src/MerkleTreeWithHistory.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

contract RejectingRecipient {
    receive() external payable {
        revert("no thanks");
    }
}

contract GasBurningRecipient {
    receive() external payable {
        while (true) {}
    }
}

/// @dev Reverts with ~300 KB of return data: cheap for the callee, quadratic memory cost for a caller that copies it.
contract ReturnBombRecipient {
    receive() external payable {
        assembly {
            revert(0, 300000)
        }
    }
}

/// @dev Tries to re-enter the pool when it receives the payout.
contract ReentrantRecipient {
    ETHTornado immutable pool;
    bool public reentryBlocked;

    constructor(ETHTornado _pool) {
        pool = _pool;
    }

    receive() external payable {
        if (msg.sender != address(pool)) return;
        try pool.deposit{value: msg.value}(bytes32(uint256(1))) {}
        catch (bytes memory err) {
            reentryBlocked = bytes4(err) == ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector;
        }
    }
}

contract ETHTornadoTest is TornadoFixture {
    uint256 constant DENOMINATION = 1 ether;
    uint256 constant FEE = 0.01 ether;
    address constant RECIPIENT = address(0xB0B);
    address constant RELAYER = address(0x5E1A);
    address alice = makeAddr("alice");

    ETHTornado pool;
    bytes32[] leaves;

    event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
    event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee);

    function setUp() public {
        _deployCore();
        pool = new ETHTornado(ceremonyVerifier, hasher, DENOMINATION, LEVELS);
        vm.deal(alice, 100 ether);
    }

    function _deposit(string memory seed) internal returns (bytes32 commitment) {
        (commitment,) = _note(seed);
        vm.prank(alice);
        pool.deposit{value: DENOMINATION}(commitment);
        leaves.push(commitment);
    }

    function _withdraw(Proof memory p, address recipient, address relayer, uint256 fee) internal {
        vm.prank(relayer);
        pool.withdraw(p.proof, p.root, p.nullifierHash, payable(recipient), payable(relayer), fee, 0);
    }

    // ---------------------------------------------------------------------------------------
    // Happy path
    // ---------------------------------------------------------------------------------------

    function test_deposit() public {
        (bytes32 commitment,) = _note("eth-deposit");
        vm.expectEmit(address(pool));
        emit Deposit(commitment, 0, block.timestamp);
        vm.prank(alice);
        pool.deposit{value: DENOMINATION}(commitment);

        assertEq(address(pool).balance, DENOMINATION);
        assertTrue(pool.commitments(commitment));
        assertEq(pool.nextIndex(), 1);
    }

    function test_depositAndWithdrawThroughRelayer() public {
        _deposit("eth-a");
        _deposit("eth-b");
        _deposit("eth-c");
        // withdraw the middle note: exercises a non-trivial Merkle path
        Proof memory p = _prove("eth-b", RECIPIENT, RELAYER, FEE, 0, leaves);
        assertEq(p.root, pool.getLastRoot());

        vm.expectEmit(address(pool));
        emit Withdrawal(RECIPIENT, p.nullifierHash, RELAYER, FEE);
        _withdraw(p, RECIPIENT, RELAYER, FEE);

        assertEq(RECIPIENT.balance, DENOMINATION - FEE);
        assertEq(RELAYER.balance, FEE);
        assertEq(address(pool).balance, 2 * DENOMINATION);
        assertTrue(pool.isSpent(p.nullifierHash));
    }

    function test_withdrawWithOlderRootInHistory() public {
        _deposit("eth-old");
        Proof memory p = _prove("eth-old", RECIPIENT, address(0), 0, 0, leaves);
        for (uint256 i; i < 10; ++i) {
            _deposit(string.concat("filler-", vm.toString(i)));
        }
        assertTrue(p.root != pool.getLastRoot());
        _withdraw(p, RECIPIENT, address(0), 0);
        assertEq(RECIPIENT.balance, DENOMINATION);
    }

    // ---------------------------------------------------------------------------------------
    // Proof binding: a proof observed in the mempool cannot be repurposed
    // ---------------------------------------------------------------------------------------

    function test_cannotDoubleSpend() public {
        _deposit("eth-double");
        Proof memory p = _prove("eth-double", RECIPIENT, RELAYER, FEE, 0, leaves);
        _withdraw(p, RECIPIENT, RELAYER, FEE);
        vm.expectRevert(Tornado.NoteAlreadySpent.selector);
        _withdraw(p, RECIPIENT, RELAYER, FEE);
    }

    function test_cannotChangeRecipient() public {
        _deposit("eth-bind");
        Proof memory p = _prove("eth-bind", RECIPIENT, RELAYER, FEE, 0, leaves);
        vm.expectRevert(Tornado.InvalidProof.selector);
        _withdraw(p, makeAddr("attacker"), RELAYER, FEE);
    }

    function test_cannotChangeRelayer() public {
        _deposit("eth-bind");
        Proof memory p = _prove("eth-bind", RECIPIENT, RELAYER, FEE, 0, leaves);
        vm.expectRevert(Tornado.InvalidProof.selector);
        _withdraw(p, RECIPIENT, makeAddr("attacker"), FEE);
    }

    function test_cannotChangeFee() public {
        _deposit("eth-bind");
        Proof memory p = _prove("eth-bind", RECIPIENT, RELAYER, FEE, 0, leaves);
        vm.expectRevert(Tornado.InvalidProof.selector);
        _withdraw(p, RECIPIENT, RELAYER, FEE * 2);
    }

    function test_rejectsUnknownRoot() public {
        _deposit("eth-bind");
        Proof memory p = _prove("eth-bind", RECIPIENT, RELAYER, FEE, 0, leaves);
        p.root = bytes32(uint256(p.root) ^ 1);
        vm.expectRevert(Tornado.UnknownRoot.selector);
        _withdraw(p, RECIPIENT, RELAYER, FEE);
    }

    function test_rejectsGarbageProof() public {
        _deposit("eth-bind");
        Proof memory p = _prove("eth-bind", RECIPIENT, RELAYER, FEE, 0, leaves);
        p.proof = abi.encode([uint256(1), 2, 3, 4, 5, 6, 7, 8]);
        vm.expectRevert(Tornado.InvalidProof.selector);
        _withdraw(p, RECIPIENT, RELAYER, FEE);
    }

    // ---------------------------------------------------------------------------------------
    // Input validation
    // ---------------------------------------------------------------------------------------

    function test_rejectsFeeAboveDenomination() public {
        _deposit("eth-x");
        bytes32 root = pool.getLastRoot();
        vm.expectRevert(Tornado.FeeExceedsDenomination.selector);
        pool.withdraw(hex"", root, 0, payable(RECIPIENT), payable(RELAYER), DENOMINATION + 1, 0);
    }

    function test_rejectsRefundAndValue() public {
        _deposit("eth-bind");
        Proof memory p = _prove("eth-bind", RECIPIENT, RELAYER, FEE, 1, leaves);
        vm.expectRevert(ETHTornado.RefundNotSupported.selector);
        pool.withdraw(p.proof, p.root, p.nullifierHash, payable(RECIPIENT), payable(RELAYER), FEE, 1);

        Proof memory q = _prove("eth-bind", RECIPIENT, RELAYER, FEE, 0, leaves);
        vm.deal(RELAYER, 1);
        vm.prank(RELAYER);
        vm.expectRevert(ETHTornado.UnexpectedValue.selector);
        pool.withdraw{value: 1}(q.proof, q.root, q.nullifierHash, payable(RECIPIENT), payable(RELAYER), FEE, 0);
    }

    function testFuzz_rejectsWrongDepositValue(uint256 value) public {
        value = bound(value, 0, 100 ether);
        vm.assume(value != DENOMINATION);
        vm.prank(alice);
        vm.expectRevert(ETHTornado.IncorrectDepositValue.selector);
        pool.deposit{value: value}(bytes32(uint256(1)));
    }

    function test_rejectsDuplicateCommitment() public {
        bytes32 c = _deposit("eth-dup");
        vm.prank(alice);
        vm.expectRevert(Tornado.CommitmentAlreadySubmitted.selector);
        pool.deposit{value: DENOMINATION}(c);
    }

    function test_rejectsCommitmentOutsideField() public {
        vm.prank(alice);
        vm.expectRevert(MerkleTreeWithHistory.ValueOutOfField.selector);
        pool.deposit{value: DENOMINATION}(bytes32(FIELD_SIZE));
    }

    // ---------------------------------------------------------------------------------------
    // Hostile recipients cannot make the withdrawal revert (relayer/paymaster griefing)
    // ---------------------------------------------------------------------------------------

    function test_rejectingRecipientGetsDeferredPayout() public {
        address recipient = address(new RejectingRecipient());
        _deposit("eth-hostile");
        Proof memory p = _prove("eth-hostile", recipient, RELAYER, FEE, 0, leaves);
        _withdraw(p, recipient, RELAYER, FEE);

        assertTrue(pool.isSpent(p.nullifierHash));
        assertEq(RELAYER.balance, FEE, "relayer still paid");
        assertEq(pool.pendingPayouts(recipient), DENOMINATION - FEE);

        address payable sink = payable(makeAddr("sink"));
        vm.prank(recipient);
        pool.claimPayout(sink);
        assertEq(sink.balance, DENOMINATION - FEE);
        assertEq(pool.pendingPayouts(recipient), 0);

        vm.prank(recipient);
        vm.expectRevert(ETHTornado.NothingToClaim.selector);
        pool.claimPayout(sink);
    }

    function test_gasBurningRecipientGetsDeferredPayout() public {
        address recipient = address(new GasBurningRecipient());
        _deposit("eth-burner");
        Proof memory p = _prove("eth-burner", recipient, RELAYER, FEE, 0, leaves);
        vm.prank(RELAYER);
        pool.withdraw{gas: 1_000_000}(p.proof, p.root, p.nullifierHash, payable(recipient), payable(RELAYER), FEE, 0);
        assertEq(pool.pendingPayouts(recipient), DENOMINATION - FEE);
        assertEq(RELAYER.balance, FEE);
    }

    function test_returnBombRecipientGetsDeferredPayout() public {
        address recipient = address(new ReturnBombRecipient());
        _deposit("eth-bomb");
        Proof memory p = _prove("eth-bomb", recipient, RELAYER, FEE, 0, leaves);
        vm.prank(RELAYER);
        // ~what a 4337 callGasLimit gives the pool
        pool.withdraw{gas: 700_000}(p.proof, p.root, p.nullifierHash, payable(recipient), payable(RELAYER), FEE, 0);
        assertEq(pool.pendingPayouts(recipient), DENOMINATION - FEE);
        assertEq(RELAYER.balance, FEE);
    }

    function test_reentrancyBlockedByTransientGuard() public {
        ReentrantRecipient recipient = new ReentrantRecipient(pool);
        _deposit("eth-reenter");
        Proof memory p = _prove("eth-reenter", address(recipient), RELAYER, FEE, 0, leaves);
        _withdraw(p, address(recipient), RELAYER, FEE);
        assertTrue(recipient.reentryBlocked());
        assertEq(address(recipient).balance, DENOMINATION - FEE);
        assertEq(pool.nextIndex(), 1, "no reentrant deposit");
    }

    function test_isSpentArray() public {
        _deposit("eth-arr");
        Proof memory p = _prove("eth-arr", RECIPIENT, address(0), 0, 0, leaves);
        _withdraw(p, RECIPIENT, address(0), 0);
        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = p.nullifierHash;
        hashes[1] = bytes32(uint256(123));
        bool[] memory spent = pool.isSpentArray(hashes);
        assertTrue(spent[0]);
        assertFalse(spent[1]);
    }
}
