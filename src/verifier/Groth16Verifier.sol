// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IVerifier} from "../interfaces/IVerifier.sol";

/// @title Groth16Verifier
/// @notice Verifier for the Tornado `withdraw` circuit with the verifying key from the 2020
///         trusted-setup ceremony (the same key as `Verifier.sol`, deployed on mainnet at
///         0xce172ce1F20EC0B3728c9965470eaf994A03557A). Accepts exactly the same proofs.
/// @dev Rewritten in assembly for two reasons:
///      1. ERC-7562 compliance. The 2020 verifier calls the precompiles with
///         `staticcall(sub(gas(), 2000), ...)`. ERC-4337 bundlers only allow `GAS` when it is
///         immediately followed by a `*CALL`, so that verifier cannot run inside paymaster
///         validation. Here `gas()` is always the last argument evaluated before `STATICCALL`
///         (checked against the bytecode in `test/Verifier.t.sol`).
///      2. Lower cost: no memory structs or dynamic arrays, and invalid input returns `false`
///         instead of `invalid()`, which burned all remaining gas.
contract Groth16Verifier is IVerifier {
    // BN254 base field
    uint256 internal constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    // BN254 scalar field
    uint256 internal constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 internal constant ALPHA_X = 20692898189092739278193869274495556617788530808486270118371701516666252877969;
    uint256 internal constant ALPHA_Y = 11713062878292653967971378194351968039596396853904572879488166084231740557279;
    uint256 internal constant BETA_X0 = 12168528810181263706895252315640534818222943348193302139358377162645029937006;
    uint256 internal constant BETA_X1 = 281120578337195720357474965979947690431622127986816839208576358024608803542;
    uint256 internal constant BETA_Y0 = 16129176515713072042442734839012966563817890688785805090011011570989315559913;
    uint256 internal constant BETA_Y1 = 9011703453772030375124466642203641636825223906145908770308724549646909480510;
    uint256 internal constant GAMMA_X0 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant GAMMA_X1 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant GAMMA_Y0 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 internal constant GAMMA_Y1 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 internal constant DELTA_X0 = 21280594949518992153305586783242820682644996932183186320680800072133486887432;
    uint256 internal constant DELTA_X1 = 150879136433974552800030963899771162647715069685890547489132178314736470662;
    uint256 internal constant DELTA_Y0 = 1081836006956609894549771334721413187913047383331561601606260283167615953295;
    uint256 internal constant DELTA_Y1 = 11434086686358152335540554643130007307617078324975981257823476472104616196090;

    uint256 internal constant IC0_X = 16225148364316337376768119297456868908427925829817748684139175309620217098814;
    uint256 internal constant IC0_Y = 5167268689450204162046084442581051565997733233062478317813755636162413164690;
    uint256 internal constant IC1_X = 12882377842072682264979317445365303375159828272423495088911985689463022094260;
    uint256 internal constant IC1_Y = 19488215856665173565526758360510125932214252767275816329232454875804474844786;
    uint256 internal constant IC2_X = 13083492661683431044045992285476184182144099829507350352128615182516530014777;
    uint256 internal constant IC2_Y = 602051281796153692392523702676782023472744522032670801091617246498551238913;
    uint256 internal constant IC3_X = 9732465972180335629969421513785602934706096902316483580882842789662669212890;
    uint256 internal constant IC3_Y = 2776526698606888434074200384264824461688198384989521091253289776235602495678;
    uint256 internal constant IC4_X = 8586364274534577154894611080234048648883781955345622578531233113180532234842;
    uint256 internal constant IC4_Y = 21276134929883121123323359450658320820075698490666870487450985603988214349407;
    uint256 internal constant IC5_X = 4910628533171597675018724709631788948355422829499855033965018665300386637884;
    uint256 internal constant IC5_Y = 20532468890024084510431799098097081600480376127870299142189696620752500664302;
    uint256 internal constant IC6_X = 15335858102289947642505450692012116222827233918185150176888641903531542034017;
    uint256 internal constant IC6_Y = 5311597067667671581646709998171703828965875677637292315055030353779531404812;

    /// @inheritdoc IVerifier
    function verifyProof(bytes calldata proof, uint256[6] calldata input) external view returns (bool valid) {
        if (proof.length != 256) return false;
        assembly ("memory-safe") {
            // Every proof element must be a canonical base-field element, every input a scalar-field element.
            function checkRanges(p, in_) -> ok {
                ok := 1
                for { let i := 0 } lt(i, 0x100) { i := add(i, 0x20) } {
                    ok := and(ok, lt(calldataload(add(p, i)), Q))
                }
                for { let i := 0 } lt(i, 0xc0) { i := add(i, 0x20) } {
                    ok := and(ok, lt(calldataload(add(in_, i)), R))
                }
            }

            // acc += s * (x, y). `acc` is the G1 point at m, scratch space at m+0x40..m+0xa0.
            function mulAcc(m, x, y, s) -> ok {
                mstore(add(m, 0x40), x)
                mstore(add(m, 0x60), y)
                mstore(add(m, 0x80), s)
                ok := staticcall(gas(), 0x07, add(m, 0x40), 0x60, add(m, 0x40), 0x40)
                if ok { ok := staticcall(gas(), 0x06, m, 0x80, m, 0x40) }
            }

            let ok := checkRanges(proof.offset, input)
            let m := mload(0x40)

            // vk_x = IC0 + Σ input[i] · IC[i+1]
            mstore(m, IC0_X)
            mstore(add(m, 0x20), IC0_Y)
            if ok { ok := mulAcc(m, IC1_X, IC1_Y, calldataload(input)) }
            if ok { ok := mulAcc(m, IC2_X, IC2_Y, calldataload(add(input, 0x20))) }
            if ok { ok := mulAcc(m, IC3_X, IC3_Y, calldataload(add(input, 0x40))) }
            if ok { ok := mulAcc(m, IC4_X, IC4_Y, calldataload(add(input, 0x60))) }
            if ok { ok := mulAcc(m, IC5_X, IC5_Y, calldataload(add(input, 0x80))) }
            if ok { ok := mulAcc(m, IC6_X, IC6_Y, calldataload(add(input, 0xa0))) }

            if ok {
                // e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
                let vkx := mload(m)
                let vky := mload(add(m, 0x20))
                let p := proof.offset

                mstore(m, calldataload(p)) // A.x
                mstore(add(m, 0x20), mod(sub(Q, calldataload(add(p, 0x20))), Q)) // -A.y
                calldatacopy(add(m, 0x40), add(p, 0x40), 0x80) // B
                mstore(add(m, 0xc0), ALPHA_X)
                mstore(add(m, 0xe0), ALPHA_Y)
                mstore(add(m, 0x100), BETA_X0)
                mstore(add(m, 0x120), BETA_X1)
                mstore(add(m, 0x140), BETA_Y0)
                mstore(add(m, 0x160), BETA_Y1)
                mstore(add(m, 0x180), vkx)
                mstore(add(m, 0x1a0), vky)
                mstore(add(m, 0x1c0), GAMMA_X0)
                mstore(add(m, 0x1e0), GAMMA_X1)
                mstore(add(m, 0x200), GAMMA_Y0)
                mstore(add(m, 0x220), GAMMA_Y1)
                calldatacopy(add(m, 0x240), add(p, 0xc0), 0x40) // C
                mstore(add(m, 0x280), DELTA_X0)
                mstore(add(m, 0x2a0), DELTA_X1)
                mstore(add(m, 0x2c0), DELTA_Y0)
                mstore(add(m, 0x2e0), DELTA_Y1)

                ok := staticcall(gas(), 0x08, m, 0x300, m, 0x20)
                valid := and(ok, mload(m))
            }
        }
    }
}
