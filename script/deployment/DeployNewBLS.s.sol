// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {stdJson} from "forge-std/Script.sol";
import {BLS} from "target-contracts/src/common/BLS.sol";
import {EOJsonUtils} from "../utils/EOJsonUtils.sol";
import {Script, console} from "forge-std/Script.sol";

/// @title DeployNewBLS
/// @notice Script to deploy BLS contract
/// @dev Deployment command: FOUNDRY_PROFILE="deployment" forge script script/deployment/DeployNewBLS.s.sol
///      --rpc-url $RPC_URL --private-key $DEPLOYER_PRIVATE_KEY -vvv --slow --verify --broadcast
contract DeployNewBLS is Script {
    using stdJson for string;

    function run() external {
        execute(msg.sender);
    }

    function execute(address broadcastFrom) public {
        vm.startBroadcast(broadcastFrom);

        EOJsonUtils.Config memory configStructured = EOJsonUtils.getParsedConfig();

        require(configStructured.targetChainId == block.chainid, "Wrong chain id for this config.");

        require(
            configStructured.eoracleChainId == vm.envUint("EORACLE_CHAIN_ID"), "Wrong EORACLE_CHAIN_ID for this config."
        );

        EOJsonUtils.initOutputConfig();

        console.log("=== Deploying BLS ===");

        address bls = address(new BLS());

        console.log("BLS deployed at:", bls);

        string memory outputConfigJson = EOJsonUtils.OUTPUT_CONFIG.serialize("bls", bls);
        EOJsonUtils.writeConfig(outputConfigJson);

        console.log("=== BLS Deployment Complete ===");

        vm.stopBroadcast();
    }
}
