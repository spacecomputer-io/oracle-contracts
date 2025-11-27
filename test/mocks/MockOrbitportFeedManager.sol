// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IOrbitportFeedManager} from "../../src/interfaces/IOrbitportFeedManager.sol";

/// @title MockOrbitportFeedManager
/// @notice Mock implementation of OrbitportFeedManager for testing
contract MockOrbitportFeedManager {
    mapping(uint256 => IOrbitportFeedManager.CTRNGData) public latestFeedData;
    mapping(uint256 => mapping(uint256 => IOrbitportFeedManager.CTRNGData)) public feedDataBySequence;
    mapping(bytes32 => mapping(address => bool)) public roles;

    function setLatestCTRNGFeed(uint256 feedId, IOrbitportFeedManager.CTRNGData memory data) external {
        latestFeedData[feedId] = data;
    }
    
    function setCTRNGFeedBySequence(uint256 feedId, uint256 sequence, IOrbitportFeedManager.CTRNGData memory data) external {
        feedDataBySequence[feedId][sequence] = data;
    }

    function getLatestCTRNGFeed(uint256 feedId) external view returns (IOrbitportFeedManager.CTRNGData memory) {
        return latestFeedData[feedId];
    }

    function getCTRNGFeedBySequence(uint256 feedId, uint256 sequence) external view returns (IOrbitportFeedManager.CTRNGData memory) {
        return feedDataBySequence[feedId][sequence];
    }
    
    function hasRole(bytes32 role, address account) external view returns (bool) {
        return roles[role][account];
    }
    
    function setRole(bytes32 role, address account, bool has) external {
        roles[role][account] = has;
    }
}

