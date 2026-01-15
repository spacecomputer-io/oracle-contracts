// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {OrbitportVRFAdapter} from "../src/OrbitportVRFAdapter.sol";

/// @title DeployVRFAdapter
/// @notice Script to deploy OrbitportVRFAdapter contract
/// @dev Requires FeedManager to be deployed first
contract DeployVRFAdapter is Script {
    function run() external returns (address vrfAdapterAddress) {
        // Read configuration from environment variables
        address beaconManager = vm.envAddress("FEED_MANAGER_PROXY_ADDRESS");
        uint256 beaconId = vm.envOr("BEACON_ID", uint256(1));

        console.log("=== Deploying OrbitportVRFAdapter ===");
        console.log("Beacon Manager (FeedManager):", beaconManager);
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
}
