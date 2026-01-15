// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import { IOrbitportVRFAdapter } from "./interfaces/IOrbitportVRFAdapter.sol";
import { IOrbitportFeedManager } from "./interfaces/IOrbitportFeedManager.sol";
import { InvalidAddress, RequestNotFound, CallerIsNotRetriever, CallerIsNotFulfiller, StaleCTRNGData, InvalidRandomWordsLength, InvalidInput } from "./interfaces/Errors.sol";
import { Ownable } from "openzeppelin-contracts/contracts/access/Ownable.sol";

/// @title OrbitportVRFAdapter
/// @notice Simplified VRF Adapter contract that uses CTRNG beacon data for randomness
/// @dev Maintains compatibility with Chainlink VRF interface while using CTRNG beacon manager directly
contract OrbitportVRFAdapter is IOrbitportVRFAdapter, Ownable {
    /// @dev Map of authorized retrievers (retriever => is authorized)
    mapping(address => bool) internal _authorizedRetrievers;

    /// @dev Map of authorized fulfillers (fulfiller => is authorized)
    mapping(address => bool) internal _authorizedFulfillers;

    /// @dev Reference to the CTRNG beacon manager
    IOrbitportFeedManager internal _beaconManager;

    /// @dev Beacon ID to read from
    uint256 internal _beaconId;

    /// @dev Maximum age of CTRNG data in seconds (default: 3600 = 1 hour)
    uint256 internal _maxCTRNGAge = 3600;

    /// @dev Request counter for generating unique request IDs
    uint256 internal _requestCounter;

    /// @dev Map of request ID to request data
    mapping(uint256 => RandomWordsRequest) internal _requests;

    /// @dev Map of request ID to fulfilled random words
    mapping(uint256 => uint256[]) internal _fulfilledRandomWords;

    /// @dev Map of request ID to fulfillment status
    mapping(uint256 => bool) internal _fulfilled;

    /// @dev Map of consumed randomness values to ensure global uniqueness
    mapping(uint256 => bool) internal _consumedRandomness;

    /// @notice Event emitted when authorized retriever is updated
    event AuthorizedRetrieverUpdated(address indexed retriever, bool isAuthorized);

    /// @notice Event emitted when authorized fulfiller is updated
    event AuthorizedFulfillerUpdated(address indexed fulfiller, bool isAuthorized);

    /// @notice Event emitted when beacon manager is set
    event BeaconManagerSet(address indexed beaconManager);

    /// @notice Event emitted when beacon ID is set
    event BeaconIdSet(uint256 indexed beaconId);

    /// @notice Event emitted when max CTRNG age is set
    event MaxCTRNGAgeSet(uint256 maxAge);

    /// @notice Constructor
    /// @param beaconManager Address of the CTRNG beacon manager
    /// @param beaconId Beacon ID to read from
    constructor(address beaconManager, uint256 beaconId) Ownable(msg.sender) {
        if (beaconManager == address(0)) revert InvalidAddress();
        _beaconManager = IOrbitportFeedManager(beaconManager);
        _beaconId = beaconId;
    }

    /* ============ Modifiers ============ */

    /// @dev Allows only authorized retrievers to call the function
    modifier onlyAuthorizedRetriever() {
        if (!_authorizedRetrievers[msg.sender]) revert CallerIsNotRetriever(msg.sender);
        _;
    }

    /// @dev Allows only authorized fulfillers to call the function
    modifier onlyAuthorizedFulfiller() {
        if (!_authorizedFulfillers[msg.sender]) revert CallerIsNotFulfiller(msg.sender);
        _;
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
    }

    /// @notice Fulfill random words request
    /// @dev Only authorized fulfillers can fulfill requests
    /// @param requestId Request ID
    /// @param randomWords Array of random words
    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) external override onlyAuthorizedFulfiller {
        RandomWordsRequest memory req = _requests[requestId];
        if (req.requester == address(0)) revert RequestNotFound(requestId);
        if (_fulfilled[requestId]) revert RequestNotFound(requestId); // Already fulfilled
        if (randomWords.length != req.numWords) revert InvalidRandomWordsLength(req.numWords, randomWords.length);

        _fulfilledRandomWords[requestId] = randomWords;
        _fulfilled[requestId] = true;

        emit RandomWordsFulfilled(requestId, randomWords);
    }

    /// @notice Get instant randomness synchronously (request + fulfill immediately)
    /// @dev Gets raw CTRNG data from beacon manager and combines with gas price for randomness
    /// @param numWords Number of random words requested
    /// @return requestId Request ID that was created and fulfilled
    /// @return randomWords Array of random words
    function getInstantRandomness(uint32 numWords) external onlyAuthorizedRetriever returns (uint256 requestId, uint256[] memory randomWords) {
        // Create a request
        requestId = ++_requestCounter;

        _requests[requestId] = RandomWordsRequest({
            requester: msg.sender,
            keyHash: bytes32(0),
            subId: 0,
            requestConfirmations: 0,
            callbackGasLimit: 0,
            numWords: numWords,
            timestamp: block.timestamp
        });

        emit RandomWordsRequested(requestId, msg.sender, bytes32(0), 0, 0, 0, numWords);

        // Fulfill immediately using raw CTRNG data
        randomWords = _fulfillInstantRequest(requestId, numWords);
    }

    /// @notice Get the beacon manager address
    /// @return address Beacon manager address
    function getBeaconManager() external view override returns (address) {
        return address(_beaconManager);
    }

    /// @notice Set the beacon manager address
    /// @param beaconManager Address of the beacon manager
    function setBeaconManager(address beaconManager) external override onlyOwner {
        if (beaconManager == address(0)) revert InvalidAddress();
        _beaconManager = IOrbitportFeedManager(beaconManager);
        emit BeaconManagerSet(beaconManager);
    }

    /// @notice Get the beacon ID
    /// @return uint256 Beacon ID
    function getBeaconId() external view override returns (uint256) {
        return _beaconId;
    }

    /// @notice Set the beacon ID
    /// @param beaconId Beacon ID to read from
    function setBeaconId(uint256 beaconId) external override onlyOwner {
        _beaconId = beaconId;
        emit BeaconIdSet(beaconId);
    }

    /// @notice Get the maximum CTRNG age in seconds
    /// @return uint256 Maximum age in seconds
    function getMaxCTRNGAge() external view returns (uint256) {
        return _maxCTRNGAge;
    }

    /// @notice Set the maximum CTRNG age in seconds
    /// @param maxAge Maximum age in seconds
    function setMaxCTRNGAge(uint256 maxAge) external onlyOwner {
        _maxCTRNGAge = maxAge;
        emit MaxCTRNGAgeSet(maxAge);
    }

    /// @notice Authorize or deauthorize retrievers
    /// @param retrievers Array of retriever addresses
    /// @param isAuthorized Array of booleans indicating whether the retriever is authorized
    function setAuthorizedRetrievers(address[] calldata retrievers, bool[] calldata isAuthorized) external onlyOwner {
        if (retrievers.length != isAuthorized.length) revert InvalidInput();
        for (uint256 i = 0; i < retrievers.length; i++) {
            if (retrievers[i] == address(0)) revert InvalidAddress();
            _authorizedRetrievers[retrievers[i]] = isAuthorized[i];
            emit AuthorizedRetrieverUpdated(retrievers[i], isAuthorized[i]);
        }
    }

    /// @notice Authorize or deauthorize fulfillers
    /// @param fulfillers Array of fulfiller addresses
    /// @param isAuthorized Array of booleans indicating whether the fulfiller is authorized
    function setAuthorizedFulfillers(address[] calldata fulfillers, bool[] calldata isAuthorized) external onlyOwner {
        if (fulfillers.length != isAuthorized.length) revert InvalidInput();
        for (uint256 i = 0; i < fulfillers.length; i++) {
            if (fulfillers[i] == address(0)) revert InvalidAddress();
            _authorizedFulfillers[fulfillers[i]] = isAuthorized[i];
            emit AuthorizedFulfillerUpdated(fulfillers[i], isAuthorized[i]);
        }
    }

    /// @notice Check if a retriever is authorized
    /// @param retriever Retriever address
    /// @return bool True if authorized
    function isAuthorizedRetriever(address retriever) external view returns (bool) {
        return _authorizedRetrievers[retriever];
    }

    /// @notice Check if a fulfiller is authorized
    /// @param fulfiller Fulfiller address
    /// @return bool True if authorized
    function isAuthorizedFulfiller(address fulfiller) external view returns (bool) {
        return _authorizedFulfillers[fulfiller];
    }

    /// @notice Get the latest raw CTRNG data
    /// @return ctrng Array of raw CTRNG values
    function getLatestCTRNGData() external onlyAuthorizedRetriever returns (uint256[] memory) {
        IOrbitportFeedManager.CTRNGData memory data = _beaconManager.getLatestCTRNGFeed(_beaconId);
        return data.ctrng;
    }

    /// @notice Get raw CTRNG data for a specific round
    /// @param roundId Round ID (sequence number). If 0, returns latest round data
    /// @return ctrng Array of raw CTRNG values
    function getCTRNGDataByRound(uint80 roundId) external onlyAuthorizedRetriever returns (uint256[] memory) {
        IOrbitportFeedManager.CTRNGData memory data;

        if (roundId == 0) {
            data = _beaconManager.getLatestCTRNGFeed(_beaconId);
        } else {
            data = _beaconManager.getCTRNGFeedBySequence(_beaconId, uint256(roundId));
        }

        return data.ctrng;
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

    /// @notice Fulfill an instant request internally using raw CTRNG data
    /// @param requestId Request ID
    /// @param numWords Number of random words to generate
    /// @return randomWords Array of random words
    function _fulfillInstantRequest(uint256 requestId, uint32 numWords) internal returns (uint256[] memory) {
        // Get raw CTRNG data from beacon manager
        IOrbitportFeedManager.CTRNGData memory data = _beaconManager.getLatestCTRNGFeed(_beaconId);

        // Validate freshness of CTRNG data
        uint256 currentTime = block.timestamp;
        if (currentTime > data.timestamp && (currentTime - data.timestamp) > _maxCTRNGAge) {
            revert StaleCTRNGData(data.timestamp, currentTime, _maxCTRNGAge);
        }

        uint256[] memory ctrng = data.ctrng;

        // Generate random words using raw CTRNG data and transaction-specific data
        uint256[] memory randomWords = new uint256[](numWords);
        for (uint32 i = 0; i < numWords; i++) {
            uint256 nonce = 0;
            uint256 randomWord;
            bool unique = false;

            // Keep regenerating until we find a unique random word
            while (!unique) {
                bytes32 hash = keccak256(
                    abi.encodePacked(
                        ctrng,
                        tx.gasprice,
                        requestId,
                        i,
                        block.timestamp,
                        block.number,
                        msg.sender,
                        nonce
                    )
                );
                randomWord = uint256(hash);

                if (!_consumedRandomness[randomWord]) {
                    unique = true;
                    _consumedRandomness[randomWord] = true;
                } else {
                    nonce++;
                }
            }

            randomWords[i] = randomWord;
        }

        _fulfilledRandomWords[requestId] = randomWords;
        _fulfilled[requestId] = true;

        emit RandomWordsFulfilled(requestId, randomWords);
        return randomWords;
    }
}
