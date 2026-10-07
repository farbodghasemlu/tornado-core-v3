// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TornadoFixture} from "./utils/TornadoFixture.sol";
import {Permit2Helper} from "./utils/Permit2Helper.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {ETHTornado} from "../src/ETHTornado.sol";
import {ERC20Tornado} from "../src/ERC20Tornado.sol";
import {ITornado} from "../src/interfaces/ITornado.sol";
import {TornadoFeeQuoter} from "../src/l2/TornadoFeeQuoter.sol";
import {TornadoPaymaster} from "../src/aa/TornadoPaymaster.sol";
import {TornadoWithdrawAccount} from "../src/aa/TornadoWithdrawAccount.sol";
import {MockToken} from "./utils/Tokens.sol";

contract MockGasPriceOracle {
    function getL1FeeUpperBound(uint256 size) external pure returns (uint256) {
        return size * 1e12; // ~0.0006 ETH for a withdraw: models an L1 blob-fee spike
    }
}

contract FeeQuoterTest is TornadoFixture {
    address constant ORACLE = 0x420000000000000000000000000000000000000F;

    function test_nonOPStackHasNoL1Component() public {
        TornadoFeeQuoter quoter = new TornadoFeeQuoter();
        assertFalse(quoter.isOPStack());
        (uint256 fee, uint256 l2, uint256 l1) = quoter.quoteRelayerFee(400_000, 1 gwei, 0);
        assertEq(l1, 0);
        assertEq(fee, l2);
        assertEq(l2, 400_000 gwei);
    }

    function test_opStackAddsL1DataFee() public {
        vm.etch(ORACLE, address(new MockGasPriceOracle()).code);
        TornadoFeeQuoter quoter = new TornadoFeeQuoter();
        assertTrue(quoter.isOPStack());

        (uint256 fee, uint256 l2, uint256 l1) = quoter.quoteRelayerFee(400_000, 0.01 gwei, 2_000);
        assertEq(l1, quoter.WITHDRAW_TX_SIZE() * 1e12);
        assertEq(l2, 400_000 * 0.01 gwei);
        assertEq(fee, (l1 + l2) * 12_000 / 10_000);
        // During an L1 fee spike an L1-blind formula (gas × gasPrice) would under-charge by orders of magnitude.
        assertGt(l1, 100 * l2);
    }

    function test_l1PreVerificationGasRoundsUp() public {
        vm.etch(ORACLE, address(new MockGasPriceOracle()).code);
        TornadoFeeQuoter quoter = new TornadoFeeQuoter();
        assertEq(quoter.l1PreVerificationGas(1_000, 3 gwei), 333_334); // 1e15 / 3e9, rounded up
        assertEq(quoter.l1PreVerificationGas(1_000, 0), 0);
    }

    function test_usesCurrentBaseFeeWhenGasPriceZero() public {
        TornadoFeeQuoter quoter = new TornadoFeeQuoter();
        vm.fee(7 gwei);
        (, uint256 l2,) = quoter.quoteRelayerFee(100_000, 0, 0);
        assertEq(l2, 100_000 * 7 gwei);
    }
}

/// @notice End-to-end on a Base Sepolia fork, against the real canonical EntryPoint v0.8, Permit2
///         and OP Stack GasPriceOracle. Set BASE_SEPOLIA_RPC_URL to run (e.g. https://sepolia.base.org).
contract BaseSepoliaForkTest is TornadoFixture, Permit2Helper {
    IEntryPoint constant ENTRY_POINT = IEntryPoint(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);
    uint256 constant DENOMINATION = 0.01 ether;

    function setUp() public {
        string memory rpc = vm.envOr("BASE_SEPOLIA_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(rpc);
        assertEq(block.chainid, 84532);
        _deployCore();
    }

    function test_fork_canonicalContractsPresent() public view {
        assertGt(address(ENTRY_POINT).code.length, 0, "EntryPoint v0.8");
        assertGt(address(PERMIT2).code.length, 0, "Permit2");
        assertGt(address(0x420000000000000000000000000000000000000F).code.length, 0, "GasPriceOracle");
    }

    function test_fork_feeQuoterReadsRealL1Fee() public {
        TornadoFeeQuoter quoter = new TornadoFeeQuoter();
        assertTrue(quoter.isOPStack());
        (uint256 fee, uint256 l2, uint256 l1) = quoter.quoteRelayerFee(400_000, 0, 1_000);
        assertGt(l1, 0, "L1 data fee");
        assertGt(fee, l1 + l2);
        emit log_named_uint("L2 execution cost (wei)", l2);
        emit log_named_uint("L1 data fee (wei)     ", l1);
    }

    function test_fork_sponsoredWithdrawalViaCanonicalEntryPoint() public {
        ETHTornado pool = new ETHTornado(ceremonyVerifier, hasher, DENOMINATION, LEVELS);
        TornadoPaymaster paymaster = new TornadoPaymaster(ENTRY_POINT, groth16Verifier, 1_000);
        paymaster.setPoolSupport(ITornado(address(pool)), true);
        paymaster.deposit{value: 0.05 ether}();

        (bytes32 commitment,) = _note("base-fork");
        pool.deposit{value: DENOMINATION}(commitment);

        address recipient = makeAddr("base-fresh-recipient");
        uint256 fee = 0.001 ether;
        Proof memory p = _prove("base-fork", recipient, address(paymaster), fee, 0, _leaves1(commitment));

        PackedUserOperation memory op;
        op.sender = address(paymaster.account());
        op.nonce = uint256(uint192(uint256(p.nullifierHash))) << 64;
        op.callData = abi.encodeCall(
            TornadoWithdrawAccount.withdraw,
            (ITornado(address(pool)), p.proof, p.root, p.nullifierHash, payable(recipient), fee)
        );
        op.accountGasLimits = bytes32((uint256(60_000) << 128) | 500_000);
        op.preVerificationGas = 100_000;
        uint256 maxFee = block.basefee * 2 + 0.001 gwei;
        op.gasFees = bytes32((uint256(0.001 gwei) << 128) | maxFee);
        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(350_000), uint128(130_000));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        address payable bundler = payable(makeAddr("base-bundler"));
        vm.prank(bundler, bundler);
        ENTRY_POINT.handleOps(ops, bundler);

        assertTrue(pool.isSpent(p.nullifierHash));
        assertGt(recipient.balance, DENOMINATION - fee);
        emit log_named_uint("recipient received (wei)", recipient.balance);
    }

    function test_fork_permit2DepositWithCanonicalPermit2() public {
        (address alice, uint256 aliceKey) = makeAddrAndKey("base-alice");
        MockToken token = new MockToken();
        ERC20Tornado pool = new ERC20Tornado(ceremonyVerifier, hasher, 100e6, LEVELS, IERC20(address(token)), PERMIT2);
        token.mint(alice, 100e6);
        vm.prank(alice);
        token.approve(address(PERMIT2), type(uint256).max);

        (bytes32 commitment,) = _note("base-permit2");
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(token), amount: 100e6}),
            nonce: 0,
            deadline: block.timestamp + 1 hours
        });
        bytes memory sig = _signPermit2Witness(
            aliceKey,
            permit,
            address(pool),
            keccak256(abi.encode(pool.DEPOSIT_WITNESS_TYPEHASH(), commitment)),
            pool.DEPOSIT_WITNESS_TYPE_STRING()
        );
        pool.depositWithPermit2(commitment, alice, permit, sig);
        assertEq(token.balanceOf(address(pool)), 100e6);
    }
}
