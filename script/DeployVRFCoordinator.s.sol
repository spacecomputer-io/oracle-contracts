// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {OrbitportVRFCoordinator} from "../src/OrbitportVRFCoordinator.sol";

/// @title DeployVRFCoordinator
/// @notice Script to deploy OrbitportVRFCoordinator contract
/// @dev Requires FeedManager to be deployed first
contract DeployVRFCoordinator is Script {
    function run() external returns (address vrfCoordinatorAddress) {
        // Read configuration from environment variables
        address beaconManager = vm.envAddress("FEED_MANAGER_PROXY_ADDRESS");
        uint256 beaconId = vm.envOr("BEACON_ID", uint256(1));

        console.log("=== Deploying OrbitportVRFCoordinator ===");
        console.log("Beacon Manager (FeedManager):", beaconManager);
        console.log("Beacon ID:", beaconId);

        // Validate addresses
        require(beaconManager != address(0), "BeaconManager address cannot be zero");

        vm.startBroadcast();

        // Deploy VRFCoordinator
        OrbitportVRFCoordinator vrfCoordinator = new OrbitportVRFCoordinator(beaconManager, beaconId);
        vrfCoordinatorAddress = address(vrfCoordinator);
        console.log("VRFCoordinator deployed at:", vrfCoordinatorAddress);

        // Verify deployment
        require(vrfCoordinator.getBeaconManager() == beaconManager, "BeaconManager verification failed");
        require(vrfCoordinator.getBeaconId() == beaconId, "BeaconId verification failed");
        require(vrfCoordinator.owner() == msg.sender, "Owner verification failed");

        console.log("=== Deployment Successful ===");
        console.log("VRFCoordinator:", vrfCoordinatorAddress);

        vm.stopBroadcast();

        return vrfCoordinatorAddress;
    }
}

