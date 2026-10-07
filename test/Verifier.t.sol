// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TornadoFixture} from "./utils/TornadoFixture.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";

/// @notice Both verifiers check proofs made with the original 2020 trusted setup. The assembly
///         Groth16Verifier must accept exactly the same proofs as the ceremony one, and must be safe
///         to run inside ERC-4337 validation.
contract VerifierTest is TornadoFixture {
    address constant RECIPIENT = address(0xBEEF);
    address constant RELAYER = address(0xFEE);
    uint256 constant FEE = 0.001 ether;

    Proof internal p;

    function setUp() public {
        _deployCore();
        (bytes32 commitment,) = _note("verifier");
        p = _prove("verifier", RECIPIENT, RELAYER, FEE, 0, _leaves1(commitment));
    }

    function _input() internal view returns (uint256[6] memory) {
        return _inputs(p, RECIPIENT, RELAYER, FEE, 0);
    }

    /// @dev The ceremony verifier reverts on out-of-range values; count that as "rejected".
    function _ceremonyAccepts(bytes memory proof, uint256[6] memory input) internal view returns (bool) {
        try ceremonyVerifier.verifyProof(proof, input) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    function test_realProofVerifiesOnBoth() public view {
        assertTrue(ceremonyVerifier.verifyProof(p.proof, _input()), "ceremony verifier");
        assertTrue(groth16Verifier.verifyProof(p.proof, _input()), "groth16 verifier");
    }

    /// @dev Changing any public input (root, nullifierHash, recipient, relayer, fee, refund) breaks the proof.
    function testFuzz_tamperedInputRejected(uint8 which, uint256 delta) public view {
        uint256[6] memory input = _input();
        which = uint8(bound(which, 0, 5));
        delta = bound(delta, 1, FIELD_SIZE - 1);
        input[which] = addmod(input[which], delta, FIELD_SIZE);

        assertFalse(groth16Verifier.verifyProof(p.proof, input));
        assertFalse(_ceremonyAccepts(p.proof, input));
    }

    function testFuzz_tamperedProofRejected(uint8 which, uint256 value) public view {
        uint256[8] memory words = abi.decode(p.proof, (uint256[8]));
        which = uint8(bound(which, 0, 7));
        vm.assume(value != words[which]);
        words[which] = value;
        bytes memory bad = abi.encode(words);

        bool g = groth16Verifier.verifyProof(bad, _input());
        assertFalse(g);
        assertEq(g, _ceremonyAccepts(bad, _input()), "verifiers disagree");
    }

    function test_rejectsWrongLength() public view {
        assertFalse(groth16Verifier.verifyProof(bytes.concat(p.proof, hex"00"), _input()));
        assertFalse(groth16Verifier.verifyProof(hex"", _input()));
    }

    function test_rejectsNonCanonicalInput() public view {
        uint256[6] memory input = _input();
        input[0] += FIELD_SIZE; // same value mod r, but not canonical
        assertFalse(groth16Verifier.verifyProof(p.proof, input));
        assertFalse(_ceremonyAccepts(p.proof, input));
    }

    // ---------------------------------------------------------------------------------------
    // ERC-7562: bundlers forbid `GAS` unless it is immediately followed by a *CALL opcode.
    // ---------------------------------------------------------------------------------------

    function test_groth16VerifierIsERC7562Compliant() public view {
        (uint256 gasOps, uint256 violations) = _scanGasOpcodes(address(groth16Verifier).code);
        assertGt(gasOps, 0, "expected precompile calls");
        assertEq(violations, 0, "GAS not followed by CALL");
    }

    /// @dev The 2020 verifier uses `staticcall(sub(gas(), 2000), ...)`, so it cannot run inside paymaster validation.
    function test_ceremonyVerifierViolatesERC7562() public view {
        (, uint256 violations) = _scanGasOpcodes(address(ceremonyVerifier).code);
        assertGt(violations, 0);
    }

    function _scanGasOpcodes(bytes memory code) internal pure returns (uint256 gasOps, uint256 violations) {
        // Skip the CBOR metadata appended by solc: its length is in the last two bytes.
        uint256 metaLen = (uint256(uint8(code[code.length - 2])) << 8) | uint8(code[code.length - 1]);
        uint256 end = code.length - metaLen - 2;
        for (uint256 i; i < end; ++i) {
            uint8 op = uint8(code[i]);
            if (op == 0x5a) {
                ++gasOps;
                uint8 next = i + 1 < end ? uint8(code[i + 1]) : 0;
                // CALL, CALLCODE, DELEGATECALL, STATICCALL
                if (next != 0xf1 && next != 0xf2 && next != 0xf4 && next != 0xfa) ++violations;
            } else if (op >= 0x60 && op <= 0x7f) {
                i += op - 0x5f; // skip PUSH1..PUSH32 immediates
            }
        }
    }
}
