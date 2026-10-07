// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {ETHTornado} from "../src/ETHTornado.sol";
import {ERC20Tornado} from "../src/ERC20Tornado.sol";
import {ITornado} from "../src/interfaces/ITornado.sol";
import {IHasher} from "../src/interfaces/IHasher.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {Groth16Verifier} from "../src/verifier/Groth16Verifier.sol";
import {MiMCSpongeDeployer} from "../src/hasher/MiMCSpongeDeployer.sol";
import {TornadoPaymaster} from "../src/aa/TornadoPaymaster.sol";
import {TornadoFeeQuoter} from "../src/l2/TornadoFeeQuoter.sol";

/// @notice Deploys the full system. Defaults target Base Sepolia.
///
///   forge script script/Deploy.s.sol --rpc-url base_sepolia --account <keystore> --broadcast --verify
///
/// Env (all optional):
///   ETH_DENOMINATIONS   comma-separated wei amounts      (default 0.001, 0.01, 0.1 ether)
///   TOKEN               ERC20 for the token pool          (default Base Sepolia USDC; address(0) to skip)
///   TOKEN_DENOMINATION  token pool denomination           (default 100e6 = 100 USDC)
///   PAYMASTER_DEPOSIT   EntryPoint deposit for gas        (default 0.01 ether)
///   PAYMASTER_STAKE     stake for paymaster AND account   (default 0.01 ether each)
///   FEE_MARKUP_BPS      paymaster markup                  (default 1000 = 10%)
contract Deploy is Script {
    IEntryPoint constant ENTRY_POINT_V08 = IEntryPoint(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);
    ISignatureTransfer constant PERMIT2 = ISignatureTransfer(0x000000000022D473030F116dDEE9F6B43aC78BA3);
    address constant BASE_SEPOLIA_USDC = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;
    uint32 constant LEVELS = 20; // fixed by the 2020 trusted-setup circuit
    uint32 constant UNSTAKE_DELAY = 1 days;

    struct Deployment {
        IHasher hasher;
        IVerifier ceremonyVerifier;
        Groth16Verifier groth16Verifier;
        TornadoFeeQuoter feeQuoter;
        TornadoPaymaster paymaster;
        ETHTornado[] ethPools;
        ERC20Tornado tokenPool;
    }

    function run() external returns (Deployment memory d) {
        uint256[] memory defaults = new uint256[](3);
        defaults[0] = 0.001 ether;
        defaults[1] = 0.01 ether;
        defaults[2] = 0.1 ether;
        uint256[] memory denominations = vm.envOr("ETH_DENOMINATIONS", ",", defaults);
        address token = vm.envOr("TOKEN", BASE_SEPOLIA_USDC);
        uint256 tokenDenomination = vm.envOr("TOKEN_DENOMINATION", uint256(100e6));
        uint256 pmDeposit = vm.envOr("PAYMASTER_DEPOSIT", uint256(0.01 ether));
        uint256 pmStake = vm.envOr("PAYMASTER_STAKE", uint256(0.01 ether));
        uint256 markup = vm.envOr("FEE_MARKUP_BPS", uint256(1_000));

        require(address(ENTRY_POINT_V08).code.length > 0, "EntryPoint v0.8 not deployed on this chain");

        vm.startBroadcast();

        d.hasher = MiMCSpongeDeployer.deploy();
        // Pools keep the 2020 ceremony verifier bytecode (the audited one, unchanged since 2020).
        // The assembly verifier is used only by the paymaster to decide what to sponsor.
        d.ceremonyVerifier = IVerifier(deployCode("src/verifier/Verifier.sol:Verifier"));
        d.groth16Verifier = new Groth16Verifier();
        d.feeQuoter = new TornadoFeeQuoter();
        d.paymaster = new TornadoPaymaster(ENTRY_POINT_V08, d.groth16Verifier, markup);

        d.ethPools = new ETHTornado[](denominations.length);
        for (uint256 i; i < denominations.length; ++i) {
            d.ethPools[i] = new ETHTornado(d.ceremonyVerifier, d.hasher, denominations[i], LEVELS);
            d.paymaster.setPoolSupport(ITornado(address(d.ethPools[i])), true);
        }
        if (token != address(0) && token.code.length > 0) {
            d.tokenPool =
                new ERC20Tornado(d.ceremonyVerifier, d.hasher, tokenDenomination, LEVELS, IERC20(token), PERMIT2);
        }

        if (pmDeposit > 0) d.paymaster.deposit{value: pmDeposit}();
        if (pmStake > 0) {
            d.paymaster.addStake{value: pmStake}(UNSTAKE_DELAY);
            d.paymaster.addAccountStake{value: pmStake}(UNSTAKE_DELAY);
        }

        vm.stopBroadcast();

        _log(d, denominations);
    }

    function _log(Deployment memory d, uint256[] memory denominations) internal view {
        console.log("chain id          ", block.chainid);
        console.log("MiMCSponge hasher ", address(d.hasher));
        console.log("Verifier (2020)   ", address(d.ceremonyVerifier));
        console.log("Groth16Verifier   ", address(d.groth16Verifier));
        console.log("TornadoFeeQuoter  ", address(d.feeQuoter));
        console.log("TornadoPaymaster  ", address(d.paymaster));
        console.log("WithdrawAccount   ", address(d.paymaster.account()));
        for (uint256 i; i < d.ethPools.length; ++i) {
            console.log("ETHTornado", denominations[i], address(d.ethPools[i]));
        }
        if (address(d.tokenPool) != address(0)) console.log("ERC20Tornado      ", address(d.tokenPool));
    }
}
