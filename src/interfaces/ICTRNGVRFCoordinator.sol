// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @title ICTRNGVRFCoordinator
/// @notice Interface for CTRNG VRF Coordinator contract
interface ICTRNGVRFCoordinator {
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

    /// @notice Get instant randomness synchronously
    /// @return randomness Random value derived from latest feed data and gas price
    function getInstantRandomness() external view returns (uint256);

    /// @notice Get the feed adapter address
    /// @return address Feed adapter address
    function getFeedAdapter() external view returns (address);

    /// @notice Set the feed adapter address
    /// @param feedAdapter Address of the feed adapter
    function setFeedAdapter(address feedAdapter) external;
}

