// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {TornadoFixture} from "../utils/TornadoFixture.sol";
import {ETHTornado} from "../../src/ETHTornado.sol";

/// @dev Random deposits, real withdrawals of two pre-proven notes (also replayed), and forged withdrawals.
contract Handler is CommonBase, StdCheats, StdUtils {
    uint256 constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    ETHTornado immutable pool;
    TornadoFixture.Proof[] proofs;
    address constant RECIPIENT = address(0xB0B);

    uint256 public ghostDeposits;
    uint256 public ghostWithdrawals;
    uint256 public ghostForgeriesAccepted;
    uint256 public ghostDoubleSpends;
    mapping(bytes32 => bool) public ghostSpent;

    constructor(ETHTornado _pool, TornadoFixture.Proof[] memory _proofs) {
        pool = _pool;
        for (uint256 i; i < _proofs.length; ++i) {
            proofs.push(_proofs[i]);
        }
        vm.deal(address(this), 1_000_000 ether);
    }

    function deposit(uint256 commitment) external {
        commitment = bound(commitment, 1, FIELD_SIZE - 1);
        if (pool.commitments(bytes32(commitment))) return;
        pool.deposit{value: pool.denomination()}(bytes32(commitment));
        ++ghostDeposits;
    }

    function withdrawReal(uint256 which) external {
        TornadoFixture.Proof storage p = proofs[bound(which, 0, proofs.length - 1)];
        bool wasSpent = ghostSpent[p.nullifierHash];
        try pool.withdraw(p.proof, p.root, p.nullifierHash, payable(RECIPIENT), payable(address(0)), 0, 0) {
            if (wasSpent) ++ghostDoubleSpends;
            ghostSpent[p.nullifierHash] = true;
            ++ghostWithdrawals;
        } catch {}
    }

    function withdrawForged(uint256 which, uint256 nullifierHash, uint256 noise) external {
        TornadoFixture.Proof storage p = proofs[bound(which, 0, proofs.length - 1)];
        bytes memory forged =
            abi.encode([noise, noise >> 1, noise >> 2, noise >> 3, noise >> 4, noise >> 5, noise >> 6, noise >> 7]);
        bytes32 nh = bytes32(bound(nullifierHash, 0, FIELD_SIZE - 1));
        try pool.withdraw{gas: 2_000_000}(forged, p.root, nh, payable(RECIPIENT), payable(address(0)), 0, 0) {
            ++ghostForgeriesAccepted;
        } catch {}
    }
}

contract ETHTornadoInvariantTest is TornadoFixture {
    ETHTornado pool;
    Handler handler;

    function setUp() public {
        _deployCore();
        pool = new ETHTornado(groth16Verifier, hasher, 1 ether, LEVELS);

        bytes32[] memory leaves = new bytes32[](2);
        (leaves[0],) = _note("inv-0");
        (leaves[1],) = _note("inv-1");
        pool.deposit{value: 1 ether}(leaves[0]);
        pool.deposit{value: 1 ether}(leaves[1]);

        Proof[] memory proofs = new Proof[](2);
        proofs[0] = _prove("inv-0", address(0xB0B), address(0), 0, 0, leaves);
        proofs[1] = _prove("inv-1", address(0xB0B), address(0), 0, 0, leaves);

        handler = new Handler(pool, proofs);
        targetContract(address(handler));
    }

    /// forge-config: default.invariant.runs = 32
    /// forge-config: default.invariant.depth = 40
    function invariant_solvent() public view {
        uint256 deposits = handler.ghostDeposits() + 2;
        assertEq(address(pool).balance, (deposits - handler.ghostWithdrawals()) * 1 ether);
        assertEq(pool.nextIndex(), deposits);
    }

    /// forge-config: default.invariant.runs = 32
    /// forge-config: default.invariant.depth = 40
    function invariant_noForgeryOrDoubleSpend() public view {
        assertEq(handler.ghostForgeriesAccepted(), 0);
        assertEq(handler.ghostDoubleSpends(), 0);
        assertLe(handler.ghostWithdrawals(), 2);
    }

    /// forge-config: default.invariant.runs = 32
    /// forge-config: default.invariant.depth = 40
    function invariant_latestRootIsKnown() public view {
        assertTrue(pool.isKnownRoot(pool.getLastRoot()));
    }
}
