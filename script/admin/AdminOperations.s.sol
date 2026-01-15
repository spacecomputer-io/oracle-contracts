// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {OrbitportBeaconManager} from "../../src/OrbitportBeaconManager.sol";
import {OrbitportVRFAdapter} from "../../src/OrbitportVRFAdapter.sol";

/// @title AdminOperations
/// @notice Script for executing critical admin operations
/// @dev Supports pause/unpause, whitelisting, and authorization operations
contract AdminOperations is Script {
    /// @notice Pause the BeaconManager contract
    /// @dev Requires pauser role
    function pauseBeaconManager() external {
        address beaconManagerAddress = vm.envAddress("BEACON_MANAGER_PROXY_ADDRESS");
        OrbitportBeaconManager beaconManager = OrbitportBeaconManager(payable(beaconManagerAddress));

        console.log("=== Pausing BeaconManager ===");
        console.log("BeaconManager:", beaconManagerAddress);

        vm.startBroadcast();
        beaconManager.pause();
        vm.stopBroadcast();

        require(beaconManager.paused(), "BeaconManager pause failed");
        console.log("BeaconManager paused successfully");
    }

    /// @notice Unpause the BeaconManager contract
    /// @dev Requires unpauser role
    function unpauseBeaconManager() external {
        address beaconManagerAddress = vm.envAddress("BEACON_MANAGER_PROXY_ADDRESS");
        OrbitportBeaconManager beaconManager = OrbitportBeaconManager(payable(beaconManagerAddress));

        console.log("=== Unpausing BeaconManager ===");
        console.log("BeaconManager:", beaconManagerAddress);

        vm.startBroadcast();
        beaconManager.unpause();
        vm.stopBroadcast();

        require(!beaconManager.paused(), "BeaconManager unpause failed");
        console.log("BeaconManager unpaused successfully");
    }

    /// @notice Whitelist or remove publishers
    /// @param publishers Array of publisher addresses
    /// @param isWhitelisted Array of booleans indicating whitelist status
    function whitelistPublishers(address[] memory publishers, bool[] memory isWhitelisted) external {
        address beaconManagerAddress = vm.envAddress("BEACON_MANAGER_PROXY_ADDRESS");
        OrbitportBeaconManager beaconManager = OrbitportBeaconManager(payable(beaconManagerAddress));

        console.log("=== Whitelisting Publishers ===");
        console.log("BeaconManager:", beaconManagerAddress);
        console.log("Number of publishers:", publishers.length);

        require(publishers.length == isWhitelisted.length, "Arrays length mismatch");

        vm.startBroadcast();
        beaconManager.whitelistPublishers(publishers, isWhitelisted);
        vm.stopBroadcast();

        // Verify
        for (uint256 i = 0; i < publishers.length; i++) {
            require(
                beaconManager.isWhitelistedPublisher(publishers[i]) == isWhitelisted[i],
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

    /// @notice Authorize or deauthorize callers for BeaconManager
    /// @param callers Array of caller addresses
    /// @param isAuthorized Array of booleans indicating authorization status
    function authorizeCallers(address[] memory callers, bool[] memory isAuthorized) external {
        address beaconManagerAddress = vm.envAddress("BEACON_MANAGER_PROXY_ADDRESS");
        OrbitportBeaconManager beaconManager = OrbitportBeaconManager(payable(beaconManagerAddress));

        console.log("=== Authorizing Callers ===");
        console.log("BeaconManager:", beaconManagerAddress);
        console.log("Number of callers:", callers.length);

        require(callers.length == isAuthorized.length, "Arrays length mismatch");

        vm.startBroadcast();
        beaconManager.setAuthorizedCallers(callers, isAuthorized);
        vm.stopBroadcast();

        // Verify
        for (uint256 i = 0; i < callers.length; i++) {
            require(
                beaconManager.isAuthorizedCaller(callers[i]) == isAuthorized[i],
                "Caller authorization verification failed"
            );
            console.log("Caller:", callers[i], "Authorized:", isAuthorized[i]);
        }

        console.log("Callers authorized successfully");
    }

    /// @notice Set supported beacons for BeaconManager
    /// @param beaconIds Array of beacon IDs
    /// @param isSupported Array of booleans indicating support status
    function setSupportedBeacons(uint256[] memory beaconIds, bool[] memory isSupported) external {
        address beaconManagerAddress = vm.envAddress("BEACON_MANAGER_PROXY_ADDRESS");
        OrbitportBeaconManager beaconManager = OrbitportBeaconManager(payable(beaconManagerAddress));

        console.log("=== Setting Supported Beacons ===");
        console.log("BeaconManager:", beaconManagerAddress);
        console.log("Number of beacons:", beaconIds.length);

        require(beaconIds.length == isSupported.length, "Arrays length mismatch");

        vm.startBroadcast();
        beaconManager.setSupportedBeacons(beaconIds, isSupported);
        vm.stopBroadcast();

        // Verify
        for (uint256 i = 0; i < beaconIds.length; i++) {
            require(
                beaconManager.isSupportedBeacon(beaconIds[i]) == isSupported[i],
                "Supported beacon verification failed"
            );
            console.log("Beacon:", beaconIds[i], "Supported:", isSupported[i]);
        }

        console.log("Supported beacons set successfully");
    }
}
