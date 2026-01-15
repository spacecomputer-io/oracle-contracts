// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import { IEOFeedVerifier } from "target-contracts/src/interfaces/IEOFeedVerifier.sol";

/// @title IOrbitportBeaconManager
/// @notice Interface for Orbitport Beacon Manager contract
interface IOrbitportBeaconManager {
    /// @notice CTRNG data structure
    struct CTRNGData {
        uint256 sequence;
        uint256 timestamp;
        uint256[] ctrng;
        uint256 blockNumber;
    }

    /// @notice Event emitted when CTRNG data is updated
    event CTRNGUpdated(
        uint256 indexed beaconId,
        uint256 sequence,
        uint256 timestamp,
        uint256[] ctrng
    );

    /// @notice Event emitted when feed verifier is set
    event FeedVerifierSet(address feedVerifier);

    /// @notice Event emitted when beacon deployer is set
    event BeaconDeployerSet(address beaconDeployer);

    /// @notice Event emitted when supported beacons are updated
    event SupportedBeaconsUpdated(uint256 indexed beaconId, bool isSupported);

    /// @notice Event emitted when publisher is whitelisted
    event PublisherWhitelisted(address indexed publisher, bool isWhitelisted);

    /// @notice Event emitted when pauser registry is set
    event PauserRegistrySet(address pauserRegistry);

    /// @notice Event emitted when authorized caller is updated
    event AuthorizedCallerUpdated(address indexed caller, bool isAuthorized);

    /// @notice Update a single CTRNG beacon
    /// @param input Leaf input for verification
    /// @param vParams Verification parameters
    function updateBeacon(
        IEOFeedVerifier.LeafInput calldata input,
        IEOFeedVerifier.VerificationParams calldata vParams
    ) external;

    /// @notice Update multiple CTRNG beacons
    /// @param inputs Array of leaf inputs for verification
    /// @param vParams Verification parameters
    function updateBeacons(
        IEOFeedVerifier.LeafInput[] calldata inputs,
        IEOFeedVerifier.VerificationParams calldata vParams
    ) external;

    /// @notice Get the latest CTRNG beacon data for a beacon ID
    /// @param beaconId Beacon ID
    /// @return CTRNGData struct containing sequence, timestamp, ctrng array, and blockNumber
    function getLatestCTRNGBeacon(uint256 beaconId) external view returns (CTRNGData memory);

    /// @notice Get CTRNG beacon data by beacon ID and sequence
    /// @param beaconId Beacon ID
    /// @param sequence Sequence number
    /// @return CTRNGData struct containing sequence, timestamp, ctrng array, and blockNumber
    function getCTRNGBeaconBySequence(
        uint256 beaconId,
        uint256 sequence
    ) external view returns (CTRNGData memory);

    /// @notice Check if a publisher is whitelisted
    /// @param publisher Publisher address
    /// @return bool True if whitelisted
    function isWhitelistedPublisher(address publisher) external returns (bool);

    /// @notice Check if a beacon ID is supported
    /// @param beaconId Beacon ID
    /// @return bool True if supported
    function isSupportedBeacon(uint256 beaconId) external returns (bool);

    /// @notice Get the feed verifier address
    /// @return IEOFeedVerifier Feed verifier contract
    function getFeedVerifier() external returns (IEOFeedVerifier);

    /// @notice Get the beacon deployer address
    /// @return address Beacon deployer address
    function getBeaconDeployer() external returns (address);
}
