// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {TornadoFixture} from "./utils/TornadoFixture.sol";
import {MockToken} from "./utils/Tokens.sol";
import {ETHTornado} from "../src/ETHTornado.sol";
import {ERC20Tornado} from "../src/ERC20Tornado.sol";
import {ITornado} from "../src/interfaces/ITornado.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";

/// @notice Side-by-side gas: the original tornado-core contracts (solc 0.7.6, compiled from
///         test/legacy) vs this port, same hasher, same ceremony verifier, same real proof.
///         All touched accounts are cooled before each call, so every number is a cold first call
///         (excluding the 21k intrinsic gas and calldata cost, which are identical for both), and the
///         recipient/relayer start empty every time.
///         Results are written to snapshots/GasComparisonTest.json.
contract GasComparisonTest is TornadoFixture {
    uint256 constant DENOMINATION = 1 ether;
    address constant RECIPIENT = address(0xB0B);
    address constant RELAYER = address(0x5E1A);
    uint256 constant FEE = 0.01 ether;

    function setUp() public {
        _deployCore();
    }

    function _measure(address target, uint256 value, bytes memory data, address[] memory touched)
        internal
        returns (uint256 used)
    {
        // Cooling resets warm/cold access but not account emptiness: give the recipient and relayer a
        // fresh, empty state before every call so each pool pays the same new-account and zero-to-nonzero costs.
        vm.deal(RECIPIENT, 0);
        vm.deal(RELAYER, 0);
        if (address(token) != address(0)) {
            deal(address(token), RECIPIENT, 0);
            deal(address(token), RELAYER, 0);
        }
        for (uint256 i; i < touched.length; ++i) {
            vm.cool(touched[i]);
        }
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        used = g - gasleft();
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    function _touched(address pool, address extra) internal view returns (address[] memory t) {
        t = new address[](4);
        t[0] = pool;
        t[1] = address(hasher);
        t[2] = address(ceremonyVerifier);
        t[3] = extra == address(0) ? address(groth16Verifier) : extra;
    }

    function _row(string memory name, uint256 legacy, uint256 modern) internal {
        vm.snapshotValue(string.concat(name, "_legacy"), legacy);
        vm.snapshotValue(string.concat(name, "_modern"), modern);
        int256 delta = int256(modern) - int256(legacy);
        string memory change =
            string.concat(vm.toString(delta), ", ", vm.toString(delta * 10_000 / int256(legacy)), " bps");
        emit log_named_string(name, string.concat(vm.toString(legacy), " -> ", vm.toString(modern), "  (", change, ")"));
    }

    ITornado legacyEth;
    ITornado modernEth;
    ITornado modernEthG16;

    function _deployEthPools() internal {
        legacyEth = ITornado(
            deployCode(
                "test/legacy/ETHTornado.sol:ETHTornado", abi.encode(ceremonyVerifier, hasher, DENOMINATION, LEVELS)
            )
        );
        modernEth = ITornado(address(new ETHTornado(ceremonyVerifier, hasher, DENOMINATION, LEVELS)));
        // Same pool, but verifying with the assembly Groth16Verifier (same ceremony key).
        modernEthG16 = ITornado(address(new ETHTornado(groth16Verifier, hasher, DENOMINATION, LEVELS)));
    }

    function test_gas_ETH() public {
        _deployEthPools();
        bytes32[] memory leaves = new bytes32[](3);
        string[3] memory names = ["eth_deposit_first", "eth_deposit_second", "eth_deposit_third"];
        for (uint256 i; i < 3; ++i) {
            (leaves[i],) = _note(string.concat("gas-", vm.toString(i)));
            bytes memory data = abi.encodeCall(ITornado.deposit, (leaves[i]));
            uint256 dl = _measure(address(legacyEth), DENOMINATION, data, _touched(address(legacyEth), address(0)));
            uint256 dm = _measure(address(modernEth), DENOMINATION, data, _touched(address(modernEth), address(0)));
            _row(names[i], dl, dm);
            modernEthG16.deposit{value: DENOMINATION}(leaves[i]);
        }
        assertEq(legacyEth.getLastRoot(), modernEth.getLastRoot(), "identical trees");

        // One proof, valid for all three pools (identical trees; proofs are not bound to a pool address).
        Proof memory p = _prove("gas-1", RECIPIENT, RELAYER, FEE, 0, leaves);
        bytes memory w = abi.encodeCall(
            ITornado.withdraw, (p.proof, p.root, p.nullifierHash, payable(RECIPIENT), payable(RELAYER), FEE, 0)
        );
        uint256 wl = _measure(address(legacyEth), 0, w, _touched(address(legacyEth), RECIPIENT));
        uint256 wm = _measure(address(modernEth), 0, w, _touched(address(modernEth), RECIPIENT));
        _row("eth_withdraw", wl, wm);
        uint256 wg = _measure(address(modernEthG16), 0, w, _touched(address(modernEthG16), RECIPIENT));
        _row("eth_withdraw_groth16Verifier", wl, wg);
    }

    MockToken token;
    ITornado legacyErc20;
    ITornado modernErc20;

    function _deployErc20Pools() internal {
        token = new MockToken();
        legacyErc20 = ITornado(
            deployCode(
                "test/legacy/ERC20Tornado.sol:ERC20Tornado",
                abi.encode(ceremonyVerifier, hasher, DENOMINATION, LEVELS, token)
            )
        );
        modernErc20 = ITornado(
            address(
                new ERC20Tornado(ceremonyVerifier, hasher, DENOMINATION, LEVELS, token, ISignatureTransfer(address(0)))
            )
        );
        token.mint(address(this), 10 ether);
        token.approve(address(legacyErc20), type(uint256).max);
        token.approve(address(modernErc20), type(uint256).max);
    }

    function test_gas_ERC20() public {
        _deployErc20Pools();
        (bytes32 c,) = _note("gas-erc20");
        bytes memory data = abi.encodeCall(ITornado.deposit, (c));
        _row(
            "erc20_deposit",
            _measure(address(legacyErc20), 0, data, _touched(address(legacyErc20), address(token))),
            _measure(address(modernErc20), 0, data, _touched(address(modernErc20), address(token)))
        );

        Proof memory p = _prove("gas-erc20", RECIPIENT, RELAYER, FEE, 0, _leaves1(c));
        data = abi.encodeCall(
            ITornado.withdraw, (p.proof, p.root, p.nullifierHash, payable(RECIPIENT), payable(RELAYER), FEE, 0)
        );
        _row(
            "erc20_withdraw",
            _measure(address(legacyErc20), 0, data, _touched(address(legacyErc20), address(token))),
            _measure(address(modernErc20), 0, data, _touched(address(modernErc20), address(token)))
        );
    }
}
