// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @title AggregatorV3Interface
/// @notice Chainlink compatible aggregator interface
interface AggregatorV3Interface {
    function decimals() external view returns (uint8);

    function description() external view returns (string memory);

    function version() external view returns (uint256);

    /// @notice Get the latest round data
    /// @return roundId Round ID
    /// @return answer Answer value
    /// @return startedAt Start timestamp
    /// @return updatedAt Update timestamp
    /// @return answeredInRound Round ID in which the answer was computed
    function latestRoundData()
        external
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);

    /// @notice Get round data for a specific round
    /// @param roundId Round ID
    /// @return roundId Round ID
    /// @return answer Answer value
    /// @return startedAt Start timestamp
    /// @return updatedAt Update timestamp
    /// @return answeredInRound Round ID in which the answer was computed
    function getRoundData(uint80 roundId)
        external
        returns (uint80, int256, uint256, uint256, uint80);
}

/// @title IOrbitportFeedAdapter
/// @notice Interface for Orbitport Feed Adapter contract
interface IOrbitportFeedAdapter is AggregatorV3Interface {
    /// @notice Set the feed manager address
    /// @param feedManager Address of the CTRNG feed manager
    function setFeedManager(address feedManager) external;

    /// @notice Set the feed ID
    /// @param feedId Feed ID to read from
    function setFeedId(uint256 feedId) external;

    /// @notice Get the feed manager address
    /// @return address Feed manager address
    function getFeedManager() external view returns (address);

    /// @notice Get the feed ID
    /// @return uint256 Feed ID
    function getFeedId() external view returns (uint256);

    /// @notice Get the latest raw CTRNG data
    /// @return ctrng Array of raw CTRNG values
    function getLatestCTRNGData() external returns (uint256[] memory ctrng);

    /// @notice Get raw CTRNG data for a specific round
    /// @param roundId Round ID (sequence number). If 0, returns latest round data
    /// @return ctrng Array of raw CTRNG values
    function getCTRNGDataByRound(uint80 roundId) external returns (uint256[] memory ctrng);
}

