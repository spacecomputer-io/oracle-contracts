// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/Script.sol";
import {OrbitportVRFAdapter} from "../../src/OrbitportVRFAdapter.sol";
import {EOJsonUtils} from "../utils/EOJsonUtils.sol";

/// @title DeployVRFAdapter
/// @notice Script to deploy OrbitportVRFAdapter contract
/// @dev Requires BeaconManager to be deployed first
contract DeployVRFAdapter is Script {
    using stdJson for string;

    function run() external returns (address vrfAdapterAddress) {
        // Read configuration from environment variables
        address beaconManager = vm.envAddress("BEACON_MANAGER_PROXY_ADDRESS");
        uint256 beaconId = vm.envOr("BEACON_ID", uint256(1));

        console.log("=== Deploying OrbitportVRFAdapter ===");
        console.log("Beacon Manager:", beaconManager);
        console.log("Beacon ID:", beaconId);

        // Validate addresses
        require(beaconManager != address(0), "BeaconManager address cannot be zero");

        vm.startBroadcast();

        // Deploy VRFAdapter
        OrbitportVRFAdapter vrfAdapter = new OrbitportVRFAdapter(beaconManager, beaconId);
        vrfAdapterAddress = address(vrfAdapter);
        console.log("VRFAdapter deployed at:", vrfAdapterAddress);

        // Verify deployment
        require(vrfAdapter.getBeaconManager() == beaconManager, "BeaconManager verification failed");
        require(vrfAdapter.getBeaconId() == beaconId, "BeaconId verification failed");
        require(vrfAdapter.owner() == msg.sender, "Owner verification failed");

        console.log("=== Deployment Successful ===");
        console.log("VRFAdapter:", vrfAdapterAddress);

        vm.stopBroadcast();

        return vrfAdapterAddress;
    }

    /// @notice Execute deployment with JSON config support
    function executeWithConfig(address broadcastFrom) external returns (address vrfAdapterAddress) {
        EOJsonUtils.Config memory configStructured = EOJsonUtils.getParsedConfig();

        require(configStructured.targetChainId == block.chainid, "Wrong chain id for this config.");
        require(
            configStructured.eoracleChainId == vm.envUint("EORACLE_CHAIN_ID"), "Wrong EORACLE_CHAIN_ID for this config."
        );

        string memory outputConfig = EOJsonUtils.initOutputConfig();
        address beaconManager = outputConfig.readAddress(".beaconManager");
        uint256 beaconId = vm.envOr("BEACON_ID", uint256(1));

        vm.startBroadcast(broadcastFrom);

        OrbitportVRFAdapter vrfAdapter = new OrbitportVRFAdapter(beaconManager, beaconId);
        vrfAdapterAddress = address(vrfAdapter);

        string memory outputConfigJson = EOJsonUtils.OUTPUT_CONFIG.serialize("vrfAdapter", vrfAdapterAddress);
        EOJsonUtils.writeConfig(outputConfigJson);

        vm.stopBroadcast();

        return vrfAdapterAddress;
    }
}
