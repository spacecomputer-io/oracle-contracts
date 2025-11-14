// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import { IOrbitportVRFCoordinator } from "./interfaces/IOrbitportVRFCoordinator.sol";
import { IOrbitportFeedAdapter } from "./interfaces/IOrbitportFeedAdapter.sol";
import { InvalidAddress, RequestNotFound } from "./interfaces/Errors.sol";

/// @title OrbitportVRFCoordinator
/// @notice Simplified VRF Coordinator contract that uses CTRNG feed data for randomness
/// @dev Maintains compatibility with Chainlink VRF interface while using CTRNG feed adapter
contract OrbitportVRFCoordinator is IOrbitportVRFCoordinator {
    /// @dev Reference to the CTRNG feed adapter
    IOrbitportFeedAdapter internal _feedAdapter;

    /// @dev Request counter for generating unique request IDs
    uint256 internal _requestCounter;

    /// @dev Map of request ID to request data
    mapping(uint256 => RandomWordsRequest) internal _requests;

    /// @dev Map of request ID to fulfilled random words
    mapping(uint256 => uint256[]) internal _fulfilledRandomWords;

    /// @dev Map of request ID to fulfillment status
    mapping(uint256 => bool) internal _fulfilled;

    /// @notice Constructor
    /// @param feedAdapter Address of the CTRNG feed adapter
    constructor(address feedAdapter) {
        if (feedAdapter == address(0)) revert InvalidAddress();
        _feedAdapter = IOrbitportFeedAdapter(feedAdapter);
    }

    /// @notice Request random words asynchronously
    /// @param keyHash Key hash for the request (not used in simplified version but kept for compatibility)
    /// @param subId Subscription ID (not used in simplified version but kept for compatibility)
    /// @param requestConfirmations Number of confirmations required (not used in simplified version but kept for compatibility)
    /// @param callbackGasLimit Gas limit for the callback (not used in simplified version but kept for compatibility)
    /// @param numWords Number of random words requested
    /// @return requestId Request ID
    function requestRandomWords(
        bytes32 keyHash,
        uint64 subId,
        uint16 requestConfirmations,
        uint32 callbackGasLimit,
        uint32 numWords
    ) external override returns (uint256 requestId) {
        requestId = ++_requestCounter;

        _requests[requestId] = RandomWordsRequest({
            requester: msg.sender,
            keyHash: keyHash,
            subId: subId,
            requestConfirmations: requestConfirmations,
            callbackGasLimit: callbackGasLimit,
            numWords: numWords,
            timestamp: block.timestamp
        });

        emit RandomWordsRequested(requestId, msg.sender, keyHash, subId, requestConfirmations, callbackGasLimit, numWords);

        // In simplified version, fulfill immediately
        // In a real implementation, this would be fulfilled by an oracle after confirmations
        _fulfillRequest(requestId, numWords);
    }

    /// @notice Fulfill random words request
    /// @param requestId Request ID
    /// @param randomWords Array of random words
    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) external override {
        if (_requests[requestId].requester == address(0)) revert RequestNotFound(requestId);
        if (_fulfilled[requestId]) revert RequestNotFound(requestId); // Already fulfilled

        _fulfilledRandomWords[requestId] = randomWords;
        _fulfilled[requestId] = true;

        emit RandomWordsFulfilled(requestId, randomWords);
    }

    /// @notice Get instant randomness synchronously
    /// @dev Gets latest round data from adapter and combines with gas price and timestamp
    /// @return randomness Random value derived from latest feed data and gas price
    function getInstantRandomness() external view override returns (uint256) {
        // Get latest round data from adapter
        (, int256 answer, , , ) = _feedAdapter.latestRoundData();

        // Combine with transaction gas price and block timestamp for uniqueness
        // This ensures unique randomness even if feed data hasn't updated
        bytes32 hash = keccak256(
            abi.encodePacked(
                answer,
                tx.gasprice,
                block.timestamp,
                block.number,
                msg.sender
            )
        );

        return uint256(hash);
    }

    /// @notice Get the feed adapter address
    /// @return address Feed adapter address
    function getFeedAdapter() external view override returns (address) {
        return address(_feedAdapter);
    }

    /// @notice Set the feed adapter address
    /// @param feedAdapter Address of the feed adapter
    function setFeedAdapter(address feedAdapter) external override {
        if (feedAdapter == address(0)) revert InvalidAddress();
        _feedAdapter = IOrbitportFeedAdapter(feedAdapter);
    }

    /// @notice Get request data for a request ID
    /// @param requestId Request ID
    /// @return RandomWordsRequest struct
    function getRequest(uint256 requestId) external view returns (RandomWordsRequest memory) {
        if (_requests[requestId].requester == address(0)) revert RequestNotFound(requestId);
        return _requests[requestId];
    }

    /// @notice Get fulfilled random words for a request ID
    /// @param requestId Request ID
    /// @return uint256[] Array of random words
    function getFulfilledRandomWords(uint256 requestId) external view returns (uint256[] memory) {
        if (!_fulfilled[requestId]) revert RequestNotFound(requestId);
        return _fulfilledRandomWords[requestId];
    }

    /// @notice Check if a request is fulfilled
    /// @param requestId Request ID
    /// @return bool True if fulfilled
    function isFulfilled(uint256 requestId) external view returns (bool) {
        return _fulfilled[requestId];
    }

    /* ============ Internal Functions ============ */

    /// @notice Fulfill a request internally
    /// @param requestId Request ID
    /// @param numWords Number of random words to generate
    function _fulfillRequest(uint256 requestId, uint32 numWords) internal {
        uint256[] memory randomWords = new uint256[](numWords);

        // Generate random words using latest feed data and request-specific data
        (, int256 answer, , , ) = _feedAdapter.latestRoundData();

        for (uint32 i = 0; i < numWords; i++) {
            bytes32 hash = keccak256(
                abi.encodePacked(
                    answer,
                    requestId,
                    i,
                    block.timestamp,
                    block.number,
                    msg.sender
                )
            );
            randomWords[i] = uint256(hash);
        }

        _fulfilledRandomWords[requestId] = randomWords;
        _fulfilled[requestId] = true;

        emit RandomWordsFulfilled(requestId, randomWords);
    }
}

