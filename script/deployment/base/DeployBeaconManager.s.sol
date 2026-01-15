// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {OrbitportBeaconManager} from "../../../src/OrbitportBeaconManager.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

abstract contract BeaconManagerDeployer is Script {
    function deployBeaconManager(
        address feedVerifier,
        address owner,
        address pauserRegistry,
        address beaconDeployer
    ) internal returns (address implAddress, address proxyAddress) {
        // Deploy implementation
        OrbitportBeaconManager impl = new OrbitportBeaconManager();
        implAddress = address(impl);

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
    }
}

contract DeployBeaconManager is BeaconManagerDeployer {
    function run(
        address feedVerifier,
        address owner,
        address pauserRegistry,
        address beaconDeployer
    ) external returns (address implAddress, address proxyAddress) {
        return deployBeaconManager(feedVerifier, owner, pauserRegistry, beaconDeployer);
    }
}
