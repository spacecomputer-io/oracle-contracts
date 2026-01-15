// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {OrbitportFeedManager} from "../src/OrbitportFeedManager.sol";
import {OrbitportVRFAdapter} from "../src/OrbitportVRFAdapter.sol";

/// @title AdminOperations
/// @notice Script for executing critical admin operations
/// @dev Supports pause/unpause, whitelisting, and authorization operations
contract AdminOperations is Script {
    /// @notice Pause the FeedManager contract
    /// @dev Requires pauser role
    function pauseFeedManager() external {
        address feedManagerAddress = vm.envAddress("FEED_MANAGER_PROXY_ADDRESS");
        OrbitportFeedManager feedManager = OrbitportFeedManager(payable(feedManagerAddress));

        console.log("=== Pausing FeedManager ===");
        console.log("FeedManager:", feedManagerAddress);

        vm.startBroadcast();
        feedManager.pause();
        vm.stopBroadcast();

        require(feedManager.paused(), "FeedManager pause failed");
        console.log("FeedManager paused successfully");
    }

    /// @notice Unpause the FeedManager contract
    /// @dev Requires unpauser role
    function unpauseFeedManager() external {
        address feedManagerAddress = vm.envAddress("FEED_MANAGER_PROXY_ADDRESS");
        OrbitportFeedManager feedManager = OrbitportFeedManager(payable(feedManagerAddress));

        console.log("=== Unpausing FeedManager ===");
        console.log("FeedManager:", feedManagerAddress);

        vm.startBroadcast();
        feedManager.unpause();
        vm.stopBroadcast();

        require(!feedManager.paused(), "FeedManager unpause failed");
        console.log("FeedManager unpaused successfully");
    }

    /// @notice Whitelist or remove publishers
    /// @param publishers Array of publisher addresses
    /// @param isWhitelisted Array of booleans indicating whitelist status
    function whitelistPublishers(address[] memory publishers, bool[] memory isWhitelisted) external {
        address feedManagerAddress = vm.envAddress("FEED_MANAGER_PROXY_ADDRESS");
        OrbitportFeedManager feedManager = OrbitportFeedManager(payable(feedManagerAddress));

        console.log("=== Whitelisting Publishers ===");
        console.log("FeedManager:", feedManagerAddress);
        console.log("Number of publishers:", publishers.length);

        require(publishers.length == isWhitelisted.length, "Arrays length mismatch");

        vm.startBroadcast();
        feedManager.whitelistPublishers(publishers, isWhitelisted);
        vm.stopBroadcast();

        // Verify
        for (uint256 i = 0; i < publishers.length; i++) {
            require(
                feedManager.isWhitelistedPublisher(publishers[i]) == isWhitelisted[i],
                "Whitelist verification failed"
            );
            console.log("Publisher:", publishers[i], "Whitelisted:", isWhitelisted[i]);
        }

        console.log("Publishers whitelisted successfully");
    }

    /// @notice Authorize or deauthorize retrievers for VRFAdapter
    /// @param retrievers Array of retriever addresses
    /// @param isAuthorized Array of booleans indicating authorization status
    function authorizeRetrievers(address[] memory retrievers, bool[] memory isAuthorized) external {
        address vrfAdapterAddress = vm.envAddress("VRF_ADAPTER_ADDRESS");
        OrbitportVRFAdapter vrfAdapter = OrbitportVRFAdapter(payable(vrfAdapterAddress));

        console.log("=== Authorizing Retrievers ===");
        console.log("VRFAdapter:", vrfAdapterAddress);
        console.log("Number of retrievers:", retrievers.length);

        require(retrievers.length == isAuthorized.length, "Arrays length mismatch");

        vm.startBroadcast();
        vrfAdapter.setAuthorizedRetrievers(retrievers, isAuthorized);
        vm.stopBroadcast();

        // Verify
        for (uint256 i = 0; i < retrievers.length; i++) {
            require(
                vrfAdapter.isAuthorizedRetriever(retrievers[i]) == isAuthorized[i],
                "Retriever authorization verification failed"
            );
            console.log("Retriever:", retrievers[i], "Authorized:", isAuthorized[i]);
        }

        console.log("Retrievers authorized successfully");
    }

    /// @notice Authorize or deauthorize fulfillers for VRFAdapter
    /// @param fulfillers Array of fulfiller addresses
    /// @param isAuthorized Array of booleans indicating authorization status
    function authorizeFulfillers(address[] memory fulfillers, bool[] memory isAuthorized) external {
        address vrfAdapterAddress = vm.envAddress("VRF_ADAPTER_ADDRESS");
        OrbitportVRFAdapter vrfAdapter = OrbitportVRFAdapter(payable(vrfAdapterAddress));

        console.log("=== Authorizing Fulfillers ===");
        console.log("VRFAdapter:", vrfAdapterAddress);
        console.log("Number of fulfillers:", fulfillers.length);

        require(fulfillers.length == isAuthorized.length, "Arrays length mismatch");

        vm.startBroadcast();
        vrfAdapter.setAuthorizedFulfillers(fulfillers, isAuthorized);
        vm.stopBroadcast();

        // Verify
        for (uint256 i = 0; i < fulfillers.length; i++) {
            require(
                vrfAdapter.isAuthorizedFulfiller(fulfillers[i]) == isAuthorized[i],
                "Fulfiller authorization verification failed"
            );
            console.log("Fulfiller:", fulfillers[i], "Authorized:", isAuthorized[i]);
        }

        console.log("Fulfillers authorized successfully");
    }

    /// @notice Authorize or deauthorize callers for FeedManager
    /// @param callers Array of caller addresses
    /// @param isAuthorized Array of booleans indicating authorization status
    function authorizeCallers(address[] memory callers, bool[] memory isAuthorized) external {
        address feedManagerAddress = vm.envAddress("FEED_MANAGER_PROXY_ADDRESS");
        OrbitportFeedManager feedManager = OrbitportFeedManager(payable(feedManagerAddress));

        console.log("=== Authorizing Callers ===");
        console.log("FeedManager:", feedManagerAddress);
        console.log("Number of callers:", callers.length);

        require(callers.length == isAuthorized.length, "Arrays length mismatch");

        vm.startBroadcast();
        feedManager.setAuthorizedCallers(callers, isAuthorized);
        vm.stopBroadcast();

        // Verify
        for (uint256 i = 0; i < callers.length; i++) {
            require(
                feedManager.isAuthorizedCaller(callers[i]) == isAuthorized[i],
                "Caller authorization verification failed"
            );
            console.log("Caller:", callers[i], "Authorized:", isAuthorized[i]);
        }

        console.log("Callers authorized successfully");
    }
}
