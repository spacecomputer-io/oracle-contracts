// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {stdJson} from "forge-std/Script.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {FeedVerifierDeployer} from "./base/DeployFeedVerifier.s.sol";
import {IBLS} from "target-contracts/src/interfaces/IBLS.sol";
import {EOJsonUtils} from "../utils/EOJsonUtils.sol";
import {console} from "forge-std/Script.sol";

/// @title DeployNewFeedVerifier
/// @notice Script to deploy EOFeedVerifier contract
/// @dev Deployment command: FOUNDRY_PROFILE="deployment" forge script script/deployment/DeployNewFeedVerifier.s.sol
///      --rpc-url $RPC_URL --private-key $DEPLOYER_PRIVATE_KEY -vvv --slow --verify --broadcast
contract DeployNewFeedVerifier is FeedVerifierDeployer {
    using stdJson for string;

    function run() external {
        vm.startBroadcast();
        execute(msg.sender);
        vm.stopBroadcast();
    }

    function execute(address broadcastFrom) public {
        EOJsonUtils.Config memory configStructured = EOJsonUtils.getParsedConfig();

        require(configStructured.targetChainId == block.chainid, "Wrong chain id for this config.");

        require(
            configStructured.eoracleChainId == vm.envUint("EORACLE_CHAIN_ID"), "Wrong EORACLE_CHAIN_ID for this config."
        );

        string memory outputConfig = EOJsonUtils.initOutputConfig();

        // Read timelock and BLS from output config
        address timelock = outputConfig.readAddress(".timelock");
        address bls = outputConfig.readAddress(".bls");

        console.log("=== Deploying FeedVerifier ===");
        console.log("Timelock:", timelock);
        console.log("BLS:", bls);

        address feedVerifierProxy = deployFeedVerifier(timelock, broadcastFrom, IBLS(bls));

        console.log("FeedVerifier Proxy deployed at:", feedVerifierProxy);

        EOJsonUtils.OUTPUT_CONFIG.serialize("feedVerifier", feedVerifierProxy);

        address implementationAddress = Upgrades.getImplementationAddress(feedVerifierProxy);
        string memory outputConfigJson =
            EOJsonUtils.OUTPUT_CONFIG.serialize("feedVerifierImplementation", implementationAddress);

        console.log("FeedVerifier Implementation:", implementationAddress);

        EOJsonUtils.writeConfig(outputConfigJson);

        console.log("=== FeedVerifier Deployment Complete ===");
    }
}
