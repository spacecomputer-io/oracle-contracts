// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/Script.sol";
import {BLS} from "target-contracts/src/common/BLS.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {IBLS} from "target-contracts/src/interfaces/IBLS.sol";
import {OrbitportBeaconManager} from "../../src/OrbitportBeaconManager.sol";
import {OrbitportVRFAdapter} from "../../src/OrbitportVRFAdapter.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {EOJsonUtils} from "../utils/EOJsonUtils.sol";

/// @title DeployAll
/// @notice Script to deploy all contracts sequentially and link them
/// @dev Handles dependencies: BLS → FeedVerifier → BeaconManager → VRFAdapter → Authorization
contract DeployAll is Script {
    using stdJson for string;

    function run() external {
        console.log("=== Starting Full Deployment ===");

        // Read configuration from environment variables
        address owner = vm.envOr("OWNER_ADDRESS", msg.sender);
        address pauserRegistry = vm.envAddress("PAUSER_REGISTRY_ADDRESS");
        address beaconDeployer = vm.envAddress("BEACON_DEPLOYER_ADDRESS");
        uint256 beaconId = vm.envOr("BEACON_ID", uint256(1));
        bool deployBls = vm.envOr("DEPLOY_BLS", true);
        bool deployFeedVerifier = vm.envOr("DEPLOY_FEED_VERIFIER", true);

        vm.startBroadcast();

        address blsAddress;
        address feedVerifierProxy;

        // Step 1: Deploy BLS (if needed)
        if (deployBls) {
            console.log("\n--- Step 1: Deploying BLS ---");
            BLS bls = new BLS();
            blsAddress = address(bls);
            console.log("BLS deployed at:", blsAddress);
        } else {
            blsAddress = vm.envAddress("BLS_ADDRESS");
            console.log("\n--- Step 1: Using existing BLS ---");
            console.log("BLS:", blsAddress);
        }

        // Step 2: Deploy FeedVerifier (if needed)
        if (deployFeedVerifier) {
            console.log("\n--- Step 2: Deploying FeedVerifier ---");
            // Use owner as timelock for simplicity (can be changed later)
            address timelock = vm.envOr("TIMELOCK_ADDRESS", owner);
            bytes memory initData = abi.encodeWithSignature("initialize(address,address)", owner, blsAddress);
            feedVerifierProxy = Upgrades.deployTransparentProxy("EOFeedVerifier.sol:EOFeedVerifier", timelock, initData);
            console.log("FeedVerifier Proxy deployed at:", feedVerifierProxy);
        } else {
            feedVerifierProxy = vm.envAddress("FEED_VERIFIER_ADDRESS");
            console.log("\n--- Step 2: Using existing FeedVerifier ---");
            console.log("FeedVerifier:", feedVerifierProxy);
        }

        // Step 3: Deploy BeaconManager
        console.log("\n--- Step 3: Deploying BeaconManager ---");
        OrbitportBeaconManager beaconManagerImpl = new OrbitportBeaconManager();
        address beaconManagerImplAddress = address(beaconManagerImpl);
        console.log("BeaconManager Implementation:", beaconManagerImplAddress);

        bytes memory beaconManagerInitData = abi.encodeWithSelector(
            OrbitportBeaconManager.initialize.selector,
            feedVerifierProxy,
            owner,
            pauserRegistry,
            beaconDeployer
        );
        ERC1967Proxy beaconManagerProxy = new ERC1967Proxy(beaconManagerImplAddress, beaconManagerInitData);
        address beaconManagerProxyAddress = address(beaconManagerProxy);
        console.log("BeaconManager Proxy:", beaconManagerProxyAddress);

        // Step 4: Deploy VRFAdapter
        console.log("\n--- Step 4: Deploying VRFAdapter ---");
        OrbitportVRFAdapter vrfAdapter = new OrbitportVRFAdapter(beaconManagerProxyAddress, beaconId);
        address vrfAdapterAddress = address(vrfAdapter);
        console.log("VRFAdapter deployed at:", vrfAdapterAddress);

        // Step 5: Authorize VRFAdapter in BeaconManager
        console.log("\n--- Step 5: Authorizing VRFAdapter in BeaconManager ---");
        OrbitportBeaconManager beaconManager = OrbitportBeaconManager(payable(beaconManagerProxyAddress));

        address[] memory callers = new address[](1);
        callers[0] = vrfAdapterAddress;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;

        beaconManager.setAuthorizedCallers(callers, isAuthorized);
        console.log("VRFAdapter authorized in BeaconManager");

        // Step 6: Optional - Set initial supported beacons (if provided)
        string memory supportedBeaconsStr = vm.envOr("INITIAL_SUPPORTED_BEACONS", string(""));
        if (bytes(supportedBeaconsStr).length > 0) {
            console.log("\n--- Step 6: Setting initial supported beacons ---");
            // Parse comma-separated beacon IDs
            string[] memory beaconIdsStr = vm.split(supportedBeaconsStr, ",");
            uint256[] memory beaconIds = new uint256[](beaconIdsStr.length);
            bool[] memory isSupported = new bool[](beaconIdsStr.length);

            for (uint256 i = 0; i < beaconIdsStr.length; i++) {
                beaconIds[i] = vm.parseUint(beaconIdsStr[i]);
                isSupported[i] = true;
            }

            beaconManager.setSupportedBeacons(beaconIds, isSupported);
            console.log("Initial supported beacons configured");
        }

        // Step 7: Optional - Whitelist initial publishers (if provided)
        string memory publishersStr = vm.envOr("INITIAL_PUBLISHERS", string(""));
        if (bytes(publishersStr).length > 0) {
            console.log("\n--- Step 7: Whitelisting initial publishers ---");
            // Parse comma-separated publisher addresses
            string[] memory publishersStrArray = vm.split(publishersStr, ",");
            address[] memory publishers = new address[](publishersStrArray.length);
            bool[] memory isWhitelisted = new bool[](publishersStrArray.length);

            for (uint256 i = 0; i < publishersStrArray.length; i++) {
                publishers[i] = vm.parseAddress(publishersStrArray[i]);
                isWhitelisted[i] = true;
            }

            beaconManager.whitelistPublishers(publishers, isWhitelisted);
            console.log("Initial publishers whitelisted");
        }

        vm.stopBroadcast();

        console.log("\n=== Full Deployment Complete ===");
        console.log("BLS:", blsAddress);
        console.log("FeedVerifier Proxy:", feedVerifierProxy);
        console.log("BeaconManager Implementation:", beaconManagerImplAddress);
        console.log("BeaconManager Proxy:", beaconManagerProxyAddress);
        console.log("VRFAdapter:", vrfAdapterAddress);
        console.log("\nEnvironment variables to set:");
        console.log("  BLS_ADDRESS=", blsAddress);
        console.log("  FEED_VERIFIER_ADDRESS=", feedVerifierProxy);
        console.log("  BEACON_MANAGER_PROXY_ADDRESS=", beaconManagerProxyAddress);
        console.log("  VRF_ADAPTER_ADDRESS=", vrfAdapterAddress);
    }

    /// @notice Execute deployment with JSON config support
    function executeWithConfig(address broadcastFrom) external {
        EOJsonUtils.Config memory configStructured = EOJsonUtils.getParsedConfig();

        require(configStructured.targetChainId == block.chainid, "Wrong chain id for this config.");
        require(
            configStructured.eoracleChainId == vm.envUint("EORACLE_CHAIN_ID"), "Wrong EORACLE_CHAIN_ID for this config."
        );

        EOJsonUtils.initOutputConfig();

        vm.startBroadcast(broadcastFrom);

        // Deploy BLS
        BLS bls = new BLS();
        address blsAddress = address(bls);
        EOJsonUtils.OUTPUT_CONFIG.serialize("bls", blsAddress);

        // Deploy FeedVerifier
        address timelock = vm.envOr("TIMELOCK_ADDRESS", broadcastFrom);
        bytes memory feedVerifierInitData = abi.encodeWithSignature("initialize(address,address)", broadcastFrom, blsAddress);
        address feedVerifierProxy = Upgrades.deployTransparentProxy("EOFeedVerifier.sol:EOFeedVerifier", timelock, feedVerifierInitData);
        address feedVerifierImpl = Upgrades.getImplementationAddress(feedVerifierProxy);
        EOJsonUtils.OUTPUT_CONFIG.serialize("feedVerifier", feedVerifierProxy);
        EOJsonUtils.OUTPUT_CONFIG.serialize("feedVerifierImplementation", feedVerifierImpl);

        // Deploy BeaconManager
        OrbitportBeaconManager beaconManagerImpl = new OrbitportBeaconManager();
        bytes memory beaconManagerInitData = abi.encodeWithSelector(
            OrbitportBeaconManager.initialize.selector,
            feedVerifierProxy,
            broadcastFrom,
            configStructured.pauserRegistry.unpauser, // Use unpauser as pauserRegistry placeholder
            configStructured.beaconDeployer
        );
        ERC1967Proxy beaconManagerProxy = new ERC1967Proxy(address(beaconManagerImpl), beaconManagerInitData);
        EOJsonUtils.OUTPUT_CONFIG.serialize("beaconManager", address(beaconManagerProxy));
        EOJsonUtils.OUTPUT_CONFIG.serialize("beaconManagerImplementation", address(beaconManagerImpl));

        // Deploy VRFAdapter
        uint256 beaconId = vm.envOr("BEACON_ID", uint256(1));
        OrbitportVRFAdapter vrfAdapter = new OrbitportVRFAdapter(address(beaconManagerProxy), beaconId);
        EOJsonUtils.OUTPUT_CONFIG.serialize("vrfAdapter", address(vrfAdapter));

        // Authorize VRFAdapter
        OrbitportBeaconManager(payable(address(beaconManagerProxy))).setAuthorizedCallers(
            _toArray(address(vrfAdapter)),
            _toBoolArray(true)
        );

        string memory outputConfigJson = EOJsonUtils.OUTPUT_CONFIG.serialize("deployed", true);
        EOJsonUtils.writeConfig(outputConfigJson);

        vm.stopBroadcast();
    }

    function _toArray(address addr) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = addr;
        return arr;
    }

    function _toBoolArray(bool val) internal pure returns (bool[] memory) {
        bool[] memory arr = new bool[](1);
        arr[0] = val;
        return arr;
    }
}
