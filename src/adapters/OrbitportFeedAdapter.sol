// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import { IOrbitportFeedAdapter } from "../interfaces/IOrbitportFeedAdapter.sol";
import { IOrbitportFeedManager } from "../interfaces/IOrbitportFeedManager.sol";
import { InvalidAddress, FeedNotSupported } from "../interfaces/Errors.sol";
import { AccessControl } from "openzeppelin-contracts/contracts/access/AccessControl.sol";

/// @title OrbitportFeedAdapter
/// @notice Chainlink-compatible adapter for CTRNG feed data
/// @dev Implements AggregatorV3Interface to provide compatibility with Chainlink price feeds
contract OrbitportFeedAdapter is IOrbitportFeedAdapter, AccessControl {
    /// @dev Role allowed to access feed data
    bytes32 public constant RETRIEVER_ROLE = keccak256("RETRIEVER_ROLE");

    /// @dev Reference to the CTRNG feed manager
    IOrbitportFeedManager internal _feedManager;

    /// @dev Feed ID to read from
    uint256 internal _feedId;

    /// @dev Decimals for the answer (0 since its a random value)
    uint8 internal constant DECIMALS = 0;

    /// @dev Description string
    string internal constant DESCRIPTION = "CTRNG Feed";

    /// @dev Version number
    uint256 internal constant VERSION = 1;

    /// @notice Event emitted when feed manager is set
    event FeedManagerSet(address indexed feedManager);

    /// @notice Event emitted when feed ID is set
    event FeedIdSet(uint256 indexed feedId);

    /// @notice Constructor
    /// @param feedManager Address of the CTRNG feed manager
    /// @param feedId Feed ID to read from
    constructor(address feedManager, uint256 feedId) {
        if (feedManager == address(0)) revert InvalidAddress();
        _feedManager = IOrbitportFeedManager(feedManager);
        _feedId = feedId;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        emit FeedManagerSet(feedManager);
        emit FeedIdSet(feedId);
    }

    /// @notice Set the feed manager address
    /// @param feedManager Address of the CTRNG feed manager
    function setFeedManager(address feedManager) external {
        if (feedManager == address(0)) revert InvalidAddress();
        _feedManager = IOrbitportFeedManager(feedManager);
        emit FeedManagerSet(feedManager);
    }

    /// @notice Set the feed ID
    /// @param feedId Feed ID to read from
    function setFeedId(uint256 feedId) external {
        _feedId = feedId;
        emit FeedIdSet(feedId);
    }

    /// @notice Get the feed manager address
    /// @return address Feed manager address
    function getFeedManager() external view returns (address) {
        return address(_feedManager);
    }

    /// @notice Get the feed ID
    /// @return uint256 Feed ID
    function getFeedId() external view returns (uint256) {
        return _feedId;
    }

    /// @notice Get the number of decimals for the answer
    /// @return uint8 Number of decimals
    function decimals() external pure override returns (uint8) {
        return DECIMALS;
    }

    /// @notice Get the description
    /// @return string Description string
    function description() external pure override returns (string memory) {
        return DESCRIPTION;
    }

    /// @notice Get the version
    /// @return uint256 Version number
    function version() external pure override returns (uint256) {
        return VERSION;
    }

    /// @notice Get the latest round data
    /// @return roundId Round ID (sequence number)
    /// @return answer Answer value (derived from CTRNG array)
    /// @return startedAt Start timestamp
    /// @return updatedAt Update timestamp
    /// @return answeredInRound Round ID in which the answer was computed
    function latestRoundData()
        external
        override
        onlyRole(RETRIEVER_ROLE)
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        IOrbitportFeedManager.CTRNGData memory data = _feedManager.getLatestCTRNGFeed(_feedId);
        uint256 answerValue = _deriveAnswer(data.ctrng);
        return (
            uint80(data.sequence),
            int256(answerValue),
            data.timestamp,
            data.timestamp,
            uint80(data.sequence)
        );
    }

    /// @notice Get round data for a specific round
    /// @param roundId Round ID (sequence number). If 0, returns latest round data
    /// @return roundId Round ID
    /// @return answer Answer value
    /// @return startedAt Start timestamp
    /// @return updatedAt Update timestamp
    /// @return answeredInRound Round ID in which the answer was computed
    function getRoundData(uint80 roundId)
        external
        override
        onlyRole(RETRIEVER_ROLE)
        returns (uint80, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        IOrbitportFeedManager.CTRNGData memory data;

        if (roundId == 0) {
            data = _feedManager.getLatestCTRNGFeed(_feedId);
        } else {
            data = _feedManager.getCTRNGFeedBySequence(_feedId, uint256(roundId));
        }

        uint256 answerValue = _deriveAnswer(data.ctrng);
        return (
            uint80(data.sequence),
            int256(answerValue),
            data.timestamp,
            data.timestamp,
            uint80(data.sequence)
        );
    }

    /// @notice Get the latest raw CTRNG data
    /// @return ctrng Array of raw CTRNG values
    function getLatestCTRNGData() external onlyRole(RETRIEVER_ROLE) returns (uint256[] memory) {
        IOrbitportFeedManager.CTRNGData memory data = _feedManager.getLatestCTRNGFeed(_feedId);
        return data.ctrng;
    }

    /// @notice Get raw CTRNG data for a specific round
    /// @param roundId Round ID (sequence number). If 0, returns latest round data
    /// @return ctrng Array of raw CTRNG values
    function getCTRNGDataByRound(uint80 roundId) external onlyRole(RETRIEVER_ROLE) returns (uint256[] memory) {
        IOrbitportFeedManager.CTRNGData memory data;

        if (roundId == 0) {
            data = _feedManager.getLatestCTRNGFeed(_feedId);
        } else {
            data = _feedManager.getCTRNGFeedBySequence(_feedId, uint256(roundId));
        }

        return data.ctrng;
    }

    /// @notice Derive answer value from CTRNG array
    /// @dev Uses keccak256 hash of the CTRNG array for Chainlink compatibility
    /// @param ctrng Array of CTRNG values
    /// @return uint256 Derived answer value
    function _deriveAnswer(uint256[] memory ctrng) internal pure returns (uint256) {
        if (ctrng.length == 0) {
            return 0;
        }
        // Hash the entire CTRNG array and use it as the answer
        // This provides a deterministic value that represents the randomness
        // Note: For raw CTRNG data, use getLatestCTRNGData() or getCTRNGDataByRound()
        bytes32 hash = keccak256(abi.encodePacked(ctrng));
        return uint256(hash);
    }
}

