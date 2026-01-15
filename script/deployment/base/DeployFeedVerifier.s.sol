// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {IEOFeedVerifier} from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import {IBLS} from "target-contracts/src/interfaces/IBLS.sol";

abstract contract FeedVerifierDeployer is Script {
    function deployFeedVerifier(address proxyAdmin, address owner, IBLS bls) internal returns (address proxyAddr) {
        // Deploy EOFeedVerifier from target-contracts
        // Note: This deploys the EOFeedVerifier contract from the target-contracts library
        bytes memory initData = abi.encodeWithSignature("initialize(address,address)", owner, address(bls));

        proxyAddr = Upgrades.deployTransparentProxy("EOFeedVerifier.sol:EOFeedVerifier", proxyAdmin, initData);
    }
}

contract DeployFeedVerifier is FeedVerifierDeployer {
    function run(address proxyAdmin, address owner, IBLS bls) external returns (address proxyAddr) {
        return deployFeedVerifier(proxyAdmin, owner, bls);
    }
}
