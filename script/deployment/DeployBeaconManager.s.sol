// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/Script.sol";
import {OrbitportBeaconManager} from "../../src/OrbitportBeaconManager.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {EOJsonUtils} from "../utils/EOJsonUtils.sol";

/// @title DeployBeaconManager
/// @notice Script to deploy OrbitportBeaconManager as an upgradeable contract
/// @dev Deploys implementation and proxy, then initializes the proxy
contract DeployBeaconManager is Script {
    using stdJson for string;

    function run() external returns (address implAddress, address proxyAddress) {
        // Read configuration from environment variables
        address feedVerifier = vm.envAddress("FEED_VERIFIER_ADDRESS");
        address owner = vm.envOr("OWNER_ADDRESS", msg.sender);
        address pauserRegistry = vm.envAddress("PAUSER_REGISTRY_ADDRESS");
        address beaconDeployer = vm.envAddress("BEACON_DEPLOYER_ADDRESS");

        console.log("=== Deploying OrbitportBeaconManager ===");
        console.log("Feed Verifier:", feedVerifier);
        console.log("Owner:", owner);
        console.log("Pauser Registry:", pauserRegistry);
        console.log("Beacon Deployer:", beaconDeployer);

        // Validate addresses
        require(feedVerifier != address(0), "FeedVerifier address cannot be zero");
        require(pauserRegistry != address(0), "PauserRegistry address cannot be zero");
        require(beaconDeployer != address(0), "BeaconDeployer address cannot be zero");

        vm.startBroadcast();

        // Deploy implementation
        OrbitportBeaconManager impl = new OrbitportBeaconManager();
        implAddress = address(impl);
        console.log("Implementation deployed at:", implAddress);

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            OrbitportBeaconManager.initialize.selector,
            feedVerifier,
            owner,
            pauserRegistry,
            beaconDeployer
        );

        // Deploy proxy
        ERC1967Proxy proxy = new ERC1967Proxy(implAddress, initData);
        proxyAddress = address(proxy);
        console.log("Proxy deployed at:", proxyAddress);

        // Verify deployment
        OrbitportBeaconManager beaconManager = OrbitportBeaconManager(payable(proxyAddress));
        require(beaconManager.owner() == owner, "Owner verification failed");
        require(address(beaconManager.getFeedVerifier()) == feedVerifier, "Verifier verification failed");
        require(beaconManager.getBeaconDeployer() == beaconDeployer, "BeaconDeployer verification failed");

        console.log("=== Deployment Successful ===");
        console.log("Implementation:", implAddress);
        console.log("Proxy (use this address):", proxyAddress);

        vm.stopBroadcast();

        return (implAddress, proxyAddress);
    }

    /// @notice Execute deployment with JSON config support
    function executeWithConfig(address broadcastFrom) external returns (address implAddress, address proxyAddress) {
        EOJsonUtils.Config memory configStructured = EOJsonUtils.getParsedConfig();

        require(configStructured.targetChainId == block.chainid, "Wrong chain id for this config.");
        require(
            configStructured.eoracleChainId == vm.envUint("EORACLE_CHAIN_ID"), "Wrong EORACLE_CHAIN_ID for this config."
        );

        string memory outputConfig = EOJsonUtils.initOutputConfig();
        address feedVerifier = outputConfig.readAddress(".feedVerifier");
        address pauserRegistry = outputConfig.readAddress(".pauserRegistry");

        vm.startBroadcast(broadcastFrom);

        // Deploy implementation
        OrbitportBeaconManager impl = new OrbitportBeaconManager();
        implAddress = address(impl);

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            OrbitportBeaconManager.initialize.selector,
            feedVerifier,
            broadcastFrom,
            pauserRegistry,
            configStructured.beaconDeployer
        );

        // Deploy proxy
        ERC1967Proxy proxy = new ERC1967Proxy(implAddress, initData);
        proxyAddress = address(proxy);

        EOJsonUtils.OUTPUT_CONFIG.serialize("beaconManager", proxyAddress);
        string memory outputConfigJson = EOJsonUtils.OUTPUT_CONFIG.serialize("beaconManagerImplementation", implAddress);
        EOJsonUtils.writeConfig(outputConfigJson);

        vm.stopBroadcast();

        return (implAddress, proxyAddress);
    }
}
