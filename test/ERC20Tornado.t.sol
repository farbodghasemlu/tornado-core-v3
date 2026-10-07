// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TornadoFixture} from "./utils/TornadoFixture.sol";
import {Permit2Helper} from "./utils/Permit2Helper.sol";
import {MockToken, FeeOnTransferToken} from "./utils/Tokens.sol";
import {ERC20Tornado} from "../src/ERC20Tornado.sol";
import {Tornado} from "../src/Tornado.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";

contract RejectingRecipient {
    receive() external payable {
        revert();
    }
}

contract ERC20TornadoTest is TornadoFixture, Permit2Helper {
    uint256 constant DENOMINATION = 100e18;
    uint256 constant FEE = 1e18;
    uint256 constant REFUND = 0.002 ether;
    address constant RECIPIENT = address(0xB0B);
    address constant RELAYER = address(0x5E1A);

    MockToken token;
    ERC20Tornado pool;
    address alice;
    uint256 aliceKey;
    bytes32[] leaves;

    function setUp() public {
        _deployCore();
        _installPermit2();
        (alice, aliceKey) = makeAddrAndKey("alice");
        token = new MockToken();
        pool = new ERC20Tornado(ceremonyVerifier, hasher, DENOMINATION, LEVELS, token, PERMIT2);
        token.mint(alice, 1_000e18);
        vm.deal(RELAYER, 1 ether);
    }

    function _deposit(string memory seed) internal returns (bytes32 commitment) {
        (commitment,) = _note(seed);
        vm.startPrank(alice);
        token.approve(address(pool), DENOMINATION);
        pool.deposit(commitment);
        vm.stopPrank();
        leaves.push(commitment);
    }

    function test_depositAndWithdrawWithRefund() public {
        _deposit("erc20-a");
        Proof memory p = _prove("erc20-a", RECIPIENT, RELAYER, FEE, REFUND, leaves);

        vm.prank(RELAYER);
        pool.withdraw{value: REFUND}(
            p.proof, p.root, p.nullifierHash, payable(RECIPIENT), payable(RELAYER), FEE, REFUND
        );

        assertEq(token.balanceOf(RECIPIENT), DENOMINATION - FEE);
        assertEq(token.balanceOf(RELAYER), FEE);
        assertEq(RECIPIENT.balance, REFUND, "recipient got ETH for gas");
        assertEq(token.balanceOf(address(pool)), 0);
    }

    function test_refundFallsBackToRelayer() public {
        address recipient = address(new RejectingRecipient());
        _deposit("erc20-rej");
        Proof memory p = _prove("erc20-rej", recipient, RELAYER, FEE, REFUND, leaves);

        uint256 relayerEthBefore = RELAYER.balance;
        vm.prank(RELAYER);
        pool.withdraw{value: REFUND}(
            p.proof, p.root, p.nullifierHash, payable(recipient), payable(RELAYER), FEE, REFUND
        );

        assertEq(token.balanceOf(recipient), DENOMINATION - FEE);
        assertEq(RELAYER.balance, relayerEthBefore, "refund returned to relayer");
    }

    function test_rejectsWrongRefundValue() public {
        _deposit("erc20-a");
        Proof memory p = _prove("erc20-a", RECIPIENT, RELAYER, FEE, REFUND, leaves);
        vm.prank(RELAYER);
        vm.expectRevert(ERC20Tornado.IncorrectRefundValue.selector);
        pool.withdraw{value: REFUND - 1}(
            p.proof, p.root, p.nullifierHash, payable(RECIPIENT), payable(RELAYER), FEE, REFUND
        );
    }

    function test_rejectsEthOnDeposit() public {
        vm.deal(alice, 1 ether);
        vm.startPrank(alice);
        token.approve(address(pool), DENOMINATION);
        vm.expectRevert(ERC20Tornado.UnexpectedValue.selector);
        pool.deposit{value: 1}(bytes32(uint256(1)));
        vm.stopPrank();
    }

    function test_rejectsFeeOnTransferToken() public {
        FeeOnTransferToken taxed = new FeeOnTransferToken();
        ERC20Tornado taxedPool =
            new ERC20Tornado(ceremonyVerifier, hasher, DENOMINATION, LEVELS, IERC20(address(taxed)), PERMIT2);
        taxed.mint(alice, DENOMINATION);
        vm.startPrank(alice);
        taxed.approve(address(taxedPool), DENOMINATION);
        vm.expectRevert(abi.encodeWithSelector(ERC20Tornado.IncorrectAmountReceived.selector, DENOMINATION * 99 / 100));
        taxedPool.deposit(bytes32(uint256(1)));
        vm.stopPrank();
    }

    // ---------------------------------------------------------------------------------------
    // EIP-2612
    // ---------------------------------------------------------------------------------------

    function _signPermit(uint256 deadline) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                alice,
                address(pool),
                DENOMINATION,
                token.nonces(alice),
                deadline
            )
        );
        return vm.sign(aliceKey, keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash)));
    }

    function test_depositWithPermit() public {
        (bytes32 commitment,) = _note("erc20-permit");
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(block.timestamp + 1 hours);
        vm.prank(alice);
        pool.depositWithPermit(commitment, block.timestamp + 1 hours, v, r, s);
        assertEq(token.balanceOf(address(pool)), DENOMINATION);
        assertTrue(pool.commitments(commitment));
    }

    /// @dev Someone copies the permit from the mempool and submits it first. The deposit must still go through.
    function test_depositWithPermitSurvivesFrontRun() public {
        (bytes32 commitment,) = _note("erc20-permit");
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(deadline);
        token.permit(alice, address(pool), DENOMINATION, deadline, v, r, s); // front-run

        vm.prank(alice);
        pool.depositWithPermit(commitment, deadline, v, r, s);
        assertEq(token.balanceOf(address(pool)), DENOMINATION);
    }

    // ---------------------------------------------------------------------------------------
    // Permit2 witness deposits: alice signs once, anyone can submit
    // ---------------------------------------------------------------------------------------

    function _permit2Deposit(bytes32 commitment, uint256 nonce)
        internal
        view
        returns (ISignatureTransfer.PermitTransferFrom memory permit, bytes memory sig)
    {
        permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(token), amount: DENOMINATION}),
            nonce: nonce,
            deadline: block.timestamp + 1 hours
        });
        sig = _signPermit2Witness(
            aliceKey,
            permit,
            address(pool),
            keccak256(abi.encode(pool.DEPOSIT_WITNESS_TYPEHASH(), commitment)),
            pool.DEPOSIT_WITNESS_TYPE_STRING()
        );
    }

    function test_depositWithPermit2SubmittedByRelayer() public {
        vm.prank(alice);
        token.approve(address(PERMIT2), type(uint256).max); // one-time, for every Permit2 app

        (bytes32 commitment,) = _note("erc20-permit2");
        (ISignatureTransfer.PermitTransferFrom memory permit, bytes memory sig) = _permit2Deposit(commitment, 0);

        vm.prank(RELAYER); // alice pays no gas
        pool.depositWithPermit2(commitment, alice, permit, sig);

        assertEq(token.balanceOf(address(pool)), DENOMINATION);
        assertEq(token.balanceOf(alice), 900e18);
        assertTrue(pool.commitments(commitment));

        // and the note is withdrawable like any other
        leaves.push(commitment);
        Proof memory p = _prove("erc20-permit2", RECIPIENT, RELAYER, FEE, 0, leaves);
        vm.prank(RELAYER);
        pool.withdraw(p.proof, p.root, p.nullifierHash, payable(RECIPIENT), payable(RELAYER), FEE, 0);
        assertEq(token.balanceOf(RECIPIENT), DENOMINATION - FEE);
    }

    /// @dev The signature commits to the note: a relayer cannot swap in its own commitment.
    function test_permit2SignatureBoundToCommitment() public {
        vm.prank(alice);
        token.approve(address(PERMIT2), type(uint256).max);
        (bytes32 commitment,) = _note("erc20-permit2");
        (ISignatureTransfer.PermitTransferFrom memory permit, bytes memory sig) = _permit2Deposit(commitment, 0);

        (bytes32 attackerCommitment,) = _note("attacker");
        vm.prank(RELAYER);
        vm.expectRevert(bytes4(keccak256("InvalidSigner()"))); // Permit2 SignatureVerification
        pool.depositWithPermit2(attackerCommitment, alice, permit, sig);
    }

    function test_permit2SignatureCannotBeReplayed() public {
        vm.prank(alice);
        token.approve(address(PERMIT2), type(uint256).max);
        (bytes32 commitment,) = _note("erc20-permit2");
        (ISignatureTransfer.PermitTransferFrom memory permit, bytes memory sig) = _permit2Deposit(commitment, 7);
        pool.depositWithPermit2(commitment, alice, permit, sig);

        vm.expectRevert(Tornado.CommitmentAlreadySubmitted.selector);
        pool.depositWithPermit2(commitment, alice, permit, sig);

        // same signature with a fresh commitment: Permit2 has burned the nonce
        (bytes32 other,) = _note("erc20-permit2-other");
        vm.expectRevert(bytes4(keccak256("InvalidNonce()")));
        pool.depositWithPermit2(other, alice, permit, sig);
    }

    function test_permit2RejectsOtherToken() public {
        (bytes32 commitment,) = _note("erc20-permit2");
        (ISignatureTransfer.PermitTransferFrom memory permit, bytes memory sig) = _permit2Deposit(commitment, 0);
        permit.permitted.token = address(0xdead);
        vm.expectRevert(ERC20Tornado.WrongPermitToken.selector);
        pool.depositWithPermit2(commitment, alice, permit, sig);
    }
}
