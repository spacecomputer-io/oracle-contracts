// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @title MockOrbitportFeedAdapter
/// @notice Mock implementation of OrbitportFeedAdapter for testing
contract MockOrbitportFeedAdapter {
    uint256[] public latestCTRNG;
    
    function setLatestCTRNGData(uint256[] memory data) external {
        latestCTRNG = data;
    }

    function getLatestCTRNGData() external view returns (uint256[] memory) {
        return latestCTRNG;
    }
}

