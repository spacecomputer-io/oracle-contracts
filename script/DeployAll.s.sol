// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {DeployFeedManager} from "./DeployFeedManager.s.sol";
import {DeployVRFCoordinator} from "./DeployVRFCoordinator.s.sol";
import {OrbitportFeedManager} from "../src/OrbitportFeedManager.sol";

/// @title DeployAll
/// @notice Script to deploy both contracts sequentially and link them
/// @dev Handles dependencies: FeedManager → VRFCoordinator → Authorization
contract DeployAll is Script {
    function run() external {
        console.log("=== Starting Full Deployment ===");

        // Step 1: Deploy FeedManager
        console.log("\n--- Step 1: Deploying FeedManager ---");
        DeployFeedManager feedManagerDeployer = new DeployFeedManager();
        (address implAddress, address proxyAddress) = feedManagerDeployer.run();

        // Update environment for next step
        vm.setEnv("FEED_MANAGER_PROXY_ADDRESS", vm.toString(proxyAddress));

        // Step 2: Deploy VRFCoordinator
        console.log("\n--- Step 2: Deploying VRFCoordinator ---");
        DeployVRFCoordinator vrfCoordinatorDeployer = new DeployVRFCoordinator();
        address vrfCoordinatorAddress = vrfCoordinatorDeployer.run();

        // Step 3: Authorize VRFCoordinator in FeedManager
        console.log("\n--- Step 3: Authorizing VRFCoordinator in FeedManager ---");
        vm.startBroadcast();

        OrbitportFeedManager feedManager = OrbitportFeedManager(payable(proxyAddress));
        
        address[] memory callers = new address[](1);
        callers[0] = vrfCoordinatorAddress;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;

        feedManager.setAuthorizedCallers(callers, isAuthorized);
        console.log("VRFCoordinator authorized in FeedManager");

        // Step 4: Optional - Set initial supported feeds (if provided)
        string memory supportedFeedsStr = vm.envOr("INITIAL_SUPPORTED_FEEDS", string(""));
        if (bytes(supportedFeedsStr).length > 0) {
            console.log("\n--- Step 4: Setting initial supported feeds ---");
            // Parse comma-separated feed IDs
            string[] memory feedIdsStr = vm.split(supportedFeedsStr, ",");
            uint256[] memory feedIds = new uint256[](feedIdsStr.length);
            bool[] memory isSupported = new bool[](feedIdsStr.length);
            
            for (uint256 i = 0; i < feedIdsStr.length; i++) {
                feedIds[i] = vm.parseUint(feedIdsStr[i]);
                isSupported[i] = true;
            }
            
            feedManager.setSupportedFeeds(feedIds, isSupported);
            console.log("Initial supported feeds configured");
        }

        // Step 5: Optional - Whitelist initial publishers (if provided)
        string memory publishersStr = vm.envOr("INITIAL_PUBLISHERS", string(""));
        if (bytes(publishersStr).length > 0) {
            console.log("\n--- Step 5: Whitelisting initial publishers ---");
            // Parse comma-separated publisher addresses
            string[] memory publishersStrArray = vm.split(publishersStr, ",");
            address[] memory publishers = new address[](publishersStrArray.length);
            bool[] memory isWhitelisted = new bool[](publishersStrArray.length);
            
            for (uint256 i = 0; i < publishersStrArray.length; i++) {
                publishers[i] = vm.parseAddress(publishersStrArray[i]);
                isWhitelisted[i] = true;
            }
            
            feedManager.whitelistPublishers(publishers, isWhitelisted);
            console.log("Initial publishers whitelisted");
        }

        vm.stopBroadcast();

        console.log("\n=== Full Deployment Complete ===");
        console.log("FeedManager Implementation:", implAddress);
        console.log("FeedManager Proxy:", proxyAddress);
        console.log("VRFCoordinator:", vrfCoordinatorAddress);
        console.log("\nNext steps:");
        console.log("1. Set FEED_MANAGER_PROXY_ADDRESS=", proxyAddress);
        console.log("2. Set VRF_COORDINATOR_ADDRESS=", vrfCoordinatorAddress);
    }
}

