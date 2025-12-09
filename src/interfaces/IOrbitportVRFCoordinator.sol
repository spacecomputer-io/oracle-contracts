// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @title IOrbitportVRFCoordinator
/// @notice Interface for Orbitport VRF Coordinator contract
interface IOrbitportVRFCoordinator {
    /// @notice Request structure for random words
    struct RandomWordsRequest {
        address requester;
        bytes32 keyHash;
        uint64 subId;
        uint16 requestConfirmations;
        uint32 callbackGasLimit;
        uint32 numWords;
        uint256 timestamp;
    }

    /// @notice Event emitted when random words are requested
    event RandomWordsRequested(
        uint256 indexed requestId,
        address indexed requester,
        bytes32 keyHash,
        uint64 subId,
        uint16 requestConfirmations,
        uint32 callbackGasLimit,
        uint32 numWords
    );

    /// @notice Event emitted when random words are fulfilled
    event RandomWordsFulfilled(
        uint256 indexed requestId,
        uint256[] randomWords
    );

    /// @notice Request random words asynchronously
    /// @param keyHash Key hash for the request
    /// @param subId Subscription ID
    /// @param requestConfirmations Number of confirmations required
    /// @param callbackGasLimit Gas limit for the callback
    /// @param numWords Number of random words requested
    /// @return requestId Request ID
    function requestRandomWords(
        bytes32 keyHash,
        uint64 subId,
        uint16 requestConfirmations,
        uint32 callbackGasLimit,
        uint32 numWords
    ) external returns (uint256 requestId);

    /// @notice Fulfill random words request
    /// @param requestId Request ID
    /// @param randomWords Array of random words
    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) external;

    /// @notice Get instant randomness synchronously (request + fulfill immediately)
    /// @param numWords Number of random words requested
    /// @return requestId Request ID that was created and fulfilled
    /// @return randomWords Array of random words
    function getInstantRandomness(uint32 numWords) external returns (uint256 requestId, uint256[] memory randomWords);

    /// @notice Get the beacon manager address
    /// @return address Beacon manager address
    function getBeaconManager() external view returns (address);

    /// @notice Set the beacon manager address
    /// @param beaconManager Address of the beacon manager
    function setBeaconManager(address beaconManager) external;

    /// @notice Get the beacon ID
    /// @return uint256 Beacon ID
    function getBeaconId() external view returns (uint256);

    /// @notice Set the beacon ID
    /// @param beaconId Beacon ID to read from
    function setBeaconId(uint256 beaconId) external;

    /// @notice Get the latest raw CTRNG data
    /// @return ctrng Array of raw CTRNG values
    function getLatestCTRNGData() external returns (uint256[] memory);

    /// @notice Get raw CTRNG data for a specific round
    /// @param roundId Round ID (sequence number). If 0, returns latest round data
    /// @return ctrng Array of raw CTRNG values
    function getCTRNGDataByRound(uint80 roundId) external returns (uint256[] memory);
}

