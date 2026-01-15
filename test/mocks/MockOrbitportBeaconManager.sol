// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IOrbitportBeaconManager} from "../../src/interfaces/IOrbitportBeaconManager.sol";

/// @title MockOrbitportBeaconManager
/// @notice Mock implementation of OrbitportBeaconManager for testing
contract MockOrbitportBeaconManager {
    mapping(uint256 => IOrbitportBeaconManager.CTRNGData) public latestBeaconData;
    mapping(uint256 => mapping(uint256 => IOrbitportBeaconManager.CTRNGData)) public beaconDataBySequence;
    mapping(bytes32 => mapping(address => bool)) public roles;

    function setLatestCTRNGBeacon(uint256 beaconId, IOrbitportBeaconManager.CTRNGData memory data) external {
        latestBeaconData[beaconId] = data;
    }

    function setCTRNGBeaconBySequence(uint256 beaconId, uint256 sequence, IOrbitportBeaconManager.CTRNGData memory data) external {
        beaconDataBySequence[beaconId][sequence] = data;
    }

    function getLatestCTRNGBeacon(uint256 beaconId) external view returns (IOrbitportBeaconManager.CTRNGData memory) {
        return latestBeaconData[beaconId];
    }

    function getCTRNGBeaconBySequence(uint256 beaconId, uint256 sequence) external view returns (IOrbitportBeaconManager.CTRNGData memory) {
        return beaconDataBySequence[beaconId][sequence];
    }

    function hasRole(bytes32 role, address account) external view returns (bool) {
        return roles[role][account];
    }

    function setRole(bytes32 role, address account, bool has) external {
        roles[role][account] = has;
    }
}
