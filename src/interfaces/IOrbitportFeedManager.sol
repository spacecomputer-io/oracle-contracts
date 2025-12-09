// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import { IEOFeedVerifier } from "target-contracts/src/interfaces/IEOFeedVerifier.sol";

/// @title IOrbitportFeedManager
/// @notice Interface for Orbitport Feed Manager contract
interface IOrbitportFeedManager {
    /// @notice CTRNG data structure
    struct CTRNGData {
        uint256 sequence;
        uint256 timestamp;
        uint256[] ctrng;
        uint256 blockNumber;
    }

    /// @notice Event emitted when CTRNG data is updated
    event CTRNGUpdated(
        uint256 indexed feedId,
        uint256 sequence,
        uint256 timestamp,
        uint256[] ctrng
    );

    /// @notice Event emitted when feed verifier is set
    event FeedVerifierSet(address feedVerifier);

    /// @notice Event emitted when feed deployer is set
    event FeedDeployerSet(address feedDeployer);

    /// @notice Event emitted when supported feeds are updated
    event SupportedFeedsUpdated(uint256 indexed feedId, bool isSupported);

    /// @notice Event emitted when publisher is whitelisted
    event PublisherWhitelisted(address indexed publisher, bool isWhitelisted);

    /// @notice Event emitted when pauser registry is set
    event PauserRegistrySet(address pauserRegistry);

    /// @notice Event emitted when authorized caller is updated
    event AuthorizedCallerUpdated(address indexed caller, bool isAuthorized);

    /// @notice Update a single CTRNG feed
    /// @param input Leaf input for verification
    /// @param vParams Verification parameters
    function updateFeed(
        IEOFeedVerifier.LeafInput calldata input,
        IEOFeedVerifier.VerificationParams calldata vParams
    ) external;

    /// @notice Update multiple CTRNG feeds
    /// @param inputs Array of leaf inputs for verification
    /// @param vParams Verification parameters
    function updateFeeds(
        IEOFeedVerifier.LeafInput[] calldata inputs,
        IEOFeedVerifier.VerificationParams calldata vParams
    ) external;

    /// @notice Get the latest CTRNG feed data for a feed ID
    /// @param feedId Feed ID
    /// @return CTRNGData struct containing sequence, timestamp, ctrng array, and blockNumber
    function getLatestCTRNGFeed(uint256 feedId) external returns (CTRNGData memory);

    /// @notice Get CTRNG feed data by feed ID and sequence
    /// @param feedId Feed ID
    /// @param sequence Sequence number
    /// @return CTRNGData struct containing sequence, timestamp, ctrng array, and blockNumber
    function getCTRNGFeedBySequence(
        uint256 feedId,
        uint256 sequence
    ) external returns (CTRNGData memory);

    /// @notice Check if a publisher is whitelisted
    /// @param publisher Publisher address
    /// @return bool True if whitelisted
    function isWhitelistedPublisher(address publisher) external returns (bool);

    /// @notice Check if a feed ID is supported
    /// @param feedId Feed ID
    /// @return bool True if supported
    function isSupportedFeed(uint256 feedId) external returns (bool);

    /// @notice Get the feed verifier address
    /// @return IEOFeedVerifier Feed verifier contract
    function getFeedVerifier() external returns (IEOFeedVerifier);

    /// @notice Get the feed deployer address
    /// @return address Feed deployer address
    function getFeedDeployer() external returns (address);
}

