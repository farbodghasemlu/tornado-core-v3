// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TornadoFixture} from "./utils/TornadoFixture.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ETHTornado} from "../src/ETHTornado.sol";
import {ITornado} from "../src/interfaces/ITornado.sol";
import {TornadoPaymaster} from "../src/aa/TornadoPaymaster.sol";
import {TornadoWithdrawAccount} from "../src/aa/TornadoWithdrawAccount.sol";

contract EthRejecter {
    receive() external payable {
        revert();
    }
}

contract ReturnBomb {
    receive() external payable {
        assembly {
            revert(0, 300000)
        }
    }
}

/// @notice A recipient with zero ETH withdraws through any ERC-4337 bundler. No relayer is involved
///         and the gas is paid from the note itself.
contract PaymasterTest is TornadoFixture {
    uint256 constant DENOMINATION = 1 ether;
    uint256 constant FEE = 0.002 ether; // max fee committed in the proof; the unused part is refunded
    uint256 constant MARKUP_BPS = 1_000; // 10%

    uint128 constant VERIFICATION_GAS = 60_000;
    uint128 constant CALL_GAS = 500_000;
    uint128 constant PM_VERIFICATION_GAS = 350_000;
    uint128 constant PM_POSTOP_GAS = 130_000;
    uint256 constant PRE_VERIFICATION_GAS = 60_000;
    uint128 constant MAX_FEE_PER_GAS = 1 gwei;

    EntryPoint entryPoint;
    ETHTornado pool;
    TornadoPaymaster paymaster;
    TornadoWithdrawAccount account;
    address payable bundler = payable(makeAddr("bundler"));
    address recipient = makeAddr("fresh-recipient");
    bytes32[] leaves;

    function setUp() public {
        _deployCore();
        entryPoint = new EntryPoint();
        pool = new ETHTornado(ceremonyVerifier, hasher, DENOMINATION, LEVELS);
        // The paymaster validates with the ERC-7562-safe verifier; the pool keeps the ceremony one.
        paymaster = new TornadoPaymaster(entryPoint, groth16Verifier, MARKUP_BPS);
        account = paymaster.account();

        paymaster.setPoolSupport(ITornado(address(pool)), true);
        paymaster.deposit{value: 1 ether}();
        paymaster.addStake{value: 1 ether}(1 days);
        paymaster.addAccountStake{value: 1 ether}(1 days);

        vm.fee(0.5 gwei);
        vm.deal(makeAddr("alice"), 10 ether);
        assertEq(recipient.balance, 0);
    }

    function _deposit(string memory seed) internal {
        (bytes32 commitment,) = _note(seed);
        vm.prank(makeAddr("alice"));
        pool.deposit{value: DENOMINATION}(commitment);
        leaves.push(commitment);
    }

    function _userOp(Proof memory p, address to, uint256 fee) internal view returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.nonce = uint256(uint192(uint256(p.nullifierHash))) << 64;
        op.callData = abi.encodeCall(
            TornadoWithdrawAccount.withdraw,
            (ITornado(address(pool)), p.proof, p.root, p.nullifierHash, payable(to), fee)
        );
        op.accountGasLimits = bytes32((uint256(VERIFICATION_GAS) << 128) | CALL_GAS);
        op.preVerificationGas = PRE_VERIFICATION_GAS;
        op.gasFees = bytes32((uint256(MAX_FEE_PER_GAS) << 128) | MAX_FEE_PER_GAS);
        op.paymasterAndData = abi.encodePacked(address(paymaster), PM_VERIFICATION_GAS, PM_POSTOP_GAS);
    }

    function _handle(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(bundler, bundler);
        entryPoint.handleOps(ops, bundler);
    }

    function _expectAA33(bytes memory inner) internal {
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, 0, "AA33 reverted", inner));
    }

    // ---------------------------------------------------------------------------------------

    function test_sponsoredWithdrawal() public {
        _deposit("pm-a");
        Proof memory p = _prove("pm-a", recipient, address(paymaster), FEE, 0, leaves);
        uint256 depositBefore = paymaster.getDeposit();

        _handle(_userOp(p, recipient, FEE));

        assertTrue(pool.isSpent(p.nullifierHash));
        uint256 received = recipient.balance;
        assertGt(received, DENOMINATION - FEE, "unused fee refunded");
        assertLt(received, DENOMINATION);
        assertGt(paymaster.getDeposit(), depositBefore, "paymaster earned more than it spent");
        assertGt(bundler.balance, 0, "bundler compensated");
        assertEq(address(paymaster).balance, 0, "earnings re-deposited into EntryPoint");

        emit log_named_decimal_uint("recipient received (ETH)", received, 18);
        emit log_named_decimal_uint("total cost to user (ETH)", DENOMINATION - received, 18);
    }

    function test_quoteFeeMatchesValidation() public view {
        uint256 quoted = paymaster.quoteFee(
            VERIFICATION_GAS, CALL_GAS, PM_VERIFICATION_GAS, PM_POSTOP_GAS, PRE_VERIFICATION_GAS, MAX_FEE_PER_GAS
        );
        uint256 maxCost = (VERIFICATION_GAS + CALL_GAS + PM_VERIFICATION_GAS + PM_POSTOP_GAS + PRE_VERIFICATION_GAS)
            * MAX_FEE_PER_GAS;
        assertEq(quoted, maxCost * 11_000 / 10_000);
        assertLe(quoted, FEE);
    }

    /// @dev Two withdrawals from the same shared sender in one bundle: each note gets its own nonce lane.
    function test_parallelWithdrawalsInOneBundle() public {
        _deposit("pm-a");
        _deposit("pm-b");
        address recipient2 = makeAddr("fresh-recipient-2");
        Proof memory p1 = _prove("pm-a", recipient, address(paymaster), FEE, 0, leaves);
        Proof memory p2 = _prove("pm-b", recipient2, address(paymaster), FEE, 0, leaves);

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _userOp(p1, recipient, FEE);
        ops[1] = _userOp(p2, recipient2, FEE);
        vm.prank(bundler, bundler);
        entryPoint.handleOps(ops, bundler);

        assertTrue(pool.isSpent(p1.nullifierHash) && pool.isSpent(p2.nullifierHash));
        assertGt(recipient.balance, DENOMINATION - FEE);
        assertGt(recipient2.balance, DENOMINATION - FEE);
    }

    function test_replayRejectedByNonce() public {
        _deposit("pm-a");
        Proof memory p = _prove("pm-a", recipient, address(paymaster), FEE, 0, leaves);
        PackedUserOperation memory op = _userOp(p, recipient, FEE);
        _handle(op);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA25 invalid account nonce"));
        _handle(op);
    }

    /// @dev A recipient that rejects ETH must not turn into free griefing of the paymaster:
    ///      the pool defers the payout, the paymaster still collects its fee and defers the refund.
    function test_hostileRecipientCannotGriefPaymaster() public {
        address hostile = address(new EthRejecter());
        _deposit("pm-hostile");
        Proof memory p = _prove("pm-hostile", hostile, address(paymaster), FEE, 0, leaves);
        uint256 depositBefore = paymaster.getDeposit();

        _handle(_userOp(p, hostile, FEE));

        assertTrue(pool.isSpent(p.nullifierHash));
        assertEq(pool.pendingPayouts(hostile), DENOMINATION - FEE);
        assertGt(paymaster.pendingRefunds(hostile), 0);
        assertGt(paymaster.getDeposit(), depositBefore);
    }

    function test_returnBombRecipientCannotGriefPaymaster() public {
        address bomb = address(new ReturnBomb());
        _deposit("pm-bomb");
        Proof memory p = _prove("pm-bomb", bomb, address(paymaster), FEE, 0, leaves);
        uint256 depositBefore = paymaster.getDeposit();

        _handle(_userOp(p, bomb, FEE));

        assertTrue(pool.isSpent(p.nullifierHash), "op executed, not reverted");
        assertEq(pool.pendingPayouts(bomb), DENOMINATION - FEE);
        assertGt(paymaster.getDeposit(), depositBefore);
    }

    // ---------------------------------------------------------------------------------------
    // Validation: anything that would revert on-chain is rejected before the paymaster pays
    // ---------------------------------------------------------------------------------------

    function test_rejectsFeeNotMatchingProof() public {
        _deposit("pm-a");
        Proof memory p = _prove("pm-a", recipient, address(paymaster), FEE, 0, leaves);
        _expectAA33(abi.encodeWithSelector(TornadoPaymaster.InvalidProof.selector));
        _handle(_userOp(p, recipient, FEE + 1));
    }

    function test_rejectsRecipientNotMatchingProof() public {
        _deposit("pm-a");
        Proof memory p = _prove("pm-a", recipient, address(paymaster), FEE, 0, leaves);
        _expectAA33(abi.encodeWithSelector(TornadoPaymaster.InvalidProof.selector));
        _handle(_userOp(p, makeAddr("thief"), FEE));
    }

    function test_rejectsFeeBelowMaxCost() public {
        _deposit("pm-a");
        Proof memory p = _prove("pm-a", recipient, address(paymaster), FEE, 0, leaves);
        PackedUserOperation memory op = _userOp(p, recipient, FEE);
        uint128 expensive = 10 gwei;
        op.gasFees = bytes32((uint256(expensive) << 128) | expensive);
        uint256 required = (VERIFICATION_GAS + CALL_GAS + PM_VERIFICATION_GAS + PM_POSTOP_GAS + PRE_VERIFICATION_GAS)
            * expensive * 11_000 / 10_000;
        _expectAA33(abi.encodeWithSelector(TornadoPaymaster.FeeTooLow.selector, FEE, required));
        _handle(op);
    }

    function test_rejectsLowCallGasLimit() public {
        _deposit("pm-a");
        Proof memory p = _prove("pm-a", recipient, address(paymaster), FEE, 0, leaves);
        PackedUserOperation memory op = _userOp(p, recipient, FEE);
        op.accountGasLimits = bytes32((uint256(VERIFICATION_GAS) << 128) | 100_000);
        _expectAA33(abi.encodeWithSelector(TornadoPaymaster.GasLimitTooLow.selector));
        _handle(op);
    }

    function test_rejectsWrongNonceKey() public {
        _deposit("pm-a");
        Proof memory p = _prove("pm-a", recipient, address(paymaster), FEE, 0, leaves);
        PackedUserOperation memory op = _userOp(p, recipient, FEE);
        op.nonce = 0;
        _expectAA33(abi.encodeWithSelector(TornadoPaymaster.NonceKeyMismatch.selector));
        _handle(op);
    }

    function test_rejectsSpentNote() public {
        _deposit("pm-a");
        Proof memory p = _prove("pm-a", recipient, address(paymaster), FEE, 0, leaves);
        // someone pushes the same proof directly to the pool first
        pool.withdraw(p.proof, p.root, p.nullifierHash, payable(recipient), payable(address(paymaster)), FEE, 0);
        _expectAA33(abi.encodeWithSelector(TornadoPaymaster.NoteAlreadySpent.selector));
        _handle(_userOp(p, recipient, FEE));
    }

    function test_rejectsUnsupportedPool() public {
        _deposit("pm-a");
        Proof memory p = _prove("pm-a", recipient, address(paymaster), FEE, 0, leaves);
        paymaster.setPoolSupport(ITornado(address(pool)), false);
        _expectAA33(abi.encodeWithSelector(TornadoPaymaster.UnsupportedPool.selector, address(pool)));
        _handle(_userOp(p, recipient, FEE));
    }

    function test_accountRefusesUnsponsoredOps() public {
        _deposit("pm-a");
        Proof memory p = _prove("pm-a", recipient, address(paymaster), FEE, 0, leaves);
        PackedUserOperation memory op = _userOp(p, recipient, FEE);
        op.paymasterAndData = "";
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA21 didn't pay prefund"));
        _handle(op);
    }

    function test_accountOnlyCallableByEntryPoint() public {
        vm.expectRevert(TornadoWithdrawAccount.NotEntryPoint.selector);
        account.withdraw(ITornado(address(pool)), "", 0, 0, payable(recipient), 0);
        vm.expectRevert(TornadoWithdrawAccount.NotPaymaster.selector);
        account.withdrawStake(payable(address(this)));
    }

    function test_adminIsOwnerOnly() public {
        vm.startPrank(makeAddr("mallory"));
        vm.expectRevert();
        paymaster.setPoolSupport(ITornado(address(1)), true);
        vm.expectRevert();
        paymaster.setFeeMarkup(0);
        vm.stopPrank();

        vm.expectRevert(TornadoPaymaster.MarkupTooHigh.selector);
        paymaster.setFeeMarkup(5_001);
    }
}
