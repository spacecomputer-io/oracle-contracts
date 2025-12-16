// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {OrbitportFeedManager} from "../src/OrbitportFeedManager.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title DeployFeedManager
/// @notice Script to deploy OrbitportFeedManager as an upgradeable contract
/// @dev Deploys implementation and proxy, then initializes the proxy
contract DeployFeedManager is Script {
    function run() external returns (address implAddress, address proxyAddress) {
        // Read configuration from environment variables
        address feedVerifier = vm.envAddress("FEED_VERIFIER_ADDRESS");
        address owner = vm.envOr("OWNER_ADDRESS", msg.sender);
        address pauserRegistry = vm.envAddress("PAUSER_REGISTRY_ADDRESS");
        address feedDeployer = vm.envAddress("FEED_DEPLOYER_ADDRESS");

        console.log("=== Deploying OrbitportFeedManager ===");
        console.log("Feed Verifier:", feedVerifier);
        console.log("Owner:", owner);
        console.log("Pauser Registry:", pauserRegistry);
        console.log("Feed Deployer:", feedDeployer);

        // Validate addresses
        require(feedVerifier != address(0), "FeedVerifier address cannot be zero");
        require(pauserRegistry != address(0), "PauserRegistry address cannot be zero");
        require(feedDeployer != address(0), "FeedDeployer address cannot be zero");

        vm.startBroadcast();

        // Deploy implementation
        OrbitportFeedManager impl = new OrbitportFeedManager();
        implAddress = address(impl);
        console.log("Implementation deployed at:", implAddress);

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            OrbitportFeedManager.initialize.selector,
            feedVerifier,
            owner,
            pauserRegistry,
            feedDeployer
        );

        // Deploy proxy
        ERC1967Proxy proxy = new ERC1967Proxy(implAddress, initData);
        proxyAddress = address(proxy);
        console.log("Proxy deployed at:", proxyAddress);

        // Verify deployment
        OrbitportFeedManager feedManager = OrbitportFeedManager(payable(proxyAddress));
        require(feedManager.owner() == owner, "Owner verification failed");
        require(address(feedManager.getFeedVerifier()) == feedVerifier, "Verifier verification failed");
        require(feedManager.getFeedDeployer() == feedDeployer, "FeedDeployer verification failed");

        console.log("=== Deployment Successful ===");
        console.log("Implementation:", implAddress);
        console.log("Proxy (use this address):", proxyAddress);

        vm.stopBroadcast();

        return (implAddress, proxyAddress);
    }
}

