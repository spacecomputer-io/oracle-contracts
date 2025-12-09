// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import { OwnableUpgradeable } from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { PausableUpgradeable } from "openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol";
import { IPauserRegistry } from "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import { IEOFeedVerifier } from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import { IOrbitportFeedManager } from "./interfaces/IOrbitportFeedManager.sol";
import {
    InvalidAddress,
    CallerIsNotWhitelisted,
    MissingLeafInputs,
    FeedNotSupported,
    InvalidInput,
    CallerIsNotPauser,
    CallerIsNotUnpauser,
    CallerIsNotFeedDeployer,
    SequenceNotFound,
    CallerIsNotRetriever
} from "./interfaces/Errors.sol";

/// @title OrbitportFeedManager
/// @notice The OrbitportFeedManager contract is responsible for receiving CTRNG feed updates from whitelisted publishers.
/// These updates are verified using the logic in the EOFeedVerifier. Upon successful verification, the CTRNG data
/// is stored in the OrbitportFeedManager and made available for other smart contracts to read. Only supported feed IDs
/// can be published to the feed manager.
contract OrbitportFeedManager is IOrbitportFeedManager, OwnableUpgradeable, PausableUpgradeable {
    /// @dev Map of feed id to CTRNG data by sequence (feed id => sequence => CTRNGData)
    mapping(uint256 => mapping(uint256 => CTRNGData)) internal _ctrngFeeds;

    /// @dev Map of feed id to latest sequence (feed id => latest sequence)
    mapping(uint256 => uint256) internal _latestSequences;

    /// @dev Map of whitelisted publishers (publisher => is whitelisted)
    mapping(address => bool) internal _whitelistedPublishers;

    /// @dev Map of supported feeds, (feed id => is supported)
    mapping(uint256 => bool) internal _supportedFeedIds;

    /// @dev Map of authorized callers (caller => is authorized)
    mapping(address => bool) internal _authorizedCallers;

    /// @dev feed verifier contract
    IEOFeedVerifier internal _feedVerifier;

    /// @notice Address of the `PauserRegistry` contract that this contract defers to for determining access control
    /// (for pausing).
    IPauserRegistry internal _pauserRegistry;

    /// @dev Address of the feed deployer
    address internal _feedDeployer;

    /* ============ Modifiers ============ */

    /// @dev Allows only whitelisted publishers to call the function
    modifier onlyWhitelisted() {
        if (!_whitelistedPublishers[msg.sender]) revert CallerIsNotWhitelisted(msg.sender);
        _;
    }

    /// @dev Allows only non-zero addresses
    modifier onlyNonZeroAddress(address addr) {
        if (addr == address(0)) revert InvalidAddress();
        _;
    }

    modifier onlyPauser() {
        if (!_pauserRegistry.isPauser(msg.sender)) revert CallerIsNotPauser();
        _;
    }

    modifier onlyUnpauser() {
        if (msg.sender != _pauserRegistry.unpauser()) revert CallerIsNotUnpauser();
        _;
    }

    modifier onlyFeedDeployer() {
        if (msg.sender != _feedDeployer) revert CallerIsNotFeedDeployer();
        _;
    }

    /// @dev Allows only authorized callers to call the function
    modifier onlyAuthorizedCaller() {
        if (!_authorizedCallers[msg.sender]) revert CallerIsNotRetriever(msg.sender);
        _;
    }

    /* ============ Constructor ============ */

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /* ============ Initializer ============ */

    /// @notice Initialize the contract with the feed verifier address
    /// @dev The feed verifier contract must be deployed first
    /// @param feedVerifier Address of the feed verifier contract
    /// @param owner Owner of the contract
    /// @param pauserRegistry Address of the pauser registry contract
    /// @param feedDeployer Address of the feed deployer
    function initialize(
        address feedVerifier,
        address owner,
        address pauserRegistry,
        address feedDeployer
    )
        external
        onlyNonZeroAddress(feedVerifier)
        onlyNonZeroAddress(feedDeployer)
        onlyNonZeroAddress(pauserRegistry)
        initializer
    {
        __Ownable_init(owner);
        __Pausable_init();
        _feedVerifier = IEOFeedVerifier(feedVerifier);
        _pauserRegistry = IPauserRegistry(pauserRegistry);
        _feedDeployer = feedDeployer;
    }

    /* ============ External Functions ============ */

    /// @notice Set the feed verifier contract address
    /// @param feedVerifier Address of the feed verifier contract
    function setFeedVerifier(address feedVerifier) external onlyOwner onlyNonZeroAddress(feedVerifier) {
        _feedVerifier = IEOFeedVerifier(feedVerifier);
        emit FeedVerifierSet(feedVerifier);
    }

    /// @notice Set the feed deployer
    /// @param feedDeployer The feed deployer address
    function setFeedDeployer(address feedDeployer) external onlyOwner onlyNonZeroAddress(feedDeployer) {
        _feedDeployer = feedDeployer;
        emit FeedDeployerSet(feedDeployer);
    }

    /// @notice Set the supported feeds
    /// @param feedIds Array of feed ids
    /// @param isSupported Array of booleans indicating whether the feed is supported
    function setSupportedFeeds(uint256[] calldata feedIds, bool[] calldata isSupported) external onlyOwner {
        if (feedIds.length != isSupported.length) revert InvalidInput();
        for (uint256 i = 0; i < feedIds.length; i++) {
            _supportedFeedIds[feedIds[i]] = isSupported[i];
            emit SupportedFeedsUpdated(feedIds[i], isSupported[i]);
        }
    }

    /// @notice Add supported feeds
    /// @param feedIds Array of feed ids
    function addSupportedFeeds(uint256[] calldata feedIds) external onlyFeedDeployer {
        for (uint256 i = 0; i < feedIds.length; i++) {
            _supportedFeedIds[feedIds[i]] = true;
            emit SupportedFeedsUpdated(feedIds[i], true);
        }
    }

    /// @notice Whitelist publishers
    /// @param publishers Array of publisher addresses
    /// @param isWhitelisted Array of booleans indicating whether the publisher is whitelisted
    function whitelistPublishers(address[] calldata publishers, bool[] calldata isWhitelisted) external onlyOwner {
        if (publishers.length != isWhitelisted.length) revert InvalidInput();
        for (uint256 i = 0; i < publishers.length; i++) {
            if (publishers[i] == address(0)) revert InvalidAddress();
            _whitelistedPublishers[publishers[i]] = isWhitelisted[i];
            emit PublisherWhitelisted(publishers[i], isWhitelisted[i]);
        }
    }

    /// @notice Authorize or deauthorize callers
    /// @param callers Array of caller addresses
    /// @param isAuthorized Array of booleans indicating whether the caller is authorized
    function setAuthorizedCallers(address[] calldata callers, bool[] calldata isAuthorized) external onlyOwner {
        if (callers.length != isAuthorized.length) revert InvalidInput();
        for (uint256 i = 0; i < callers.length; i++) {
            if (callers[i] == address(0)) revert InvalidAddress();
            _authorizedCallers[callers[i]] = isAuthorized[i];
            emit AuthorizedCallerUpdated(callers[i], isAuthorized[i]);
        }
    }

    /// @notice Update a single CTRNG feed
    /// @param input Leaf input for verification
    /// @param vParams Verification parameters
    function updateFeed(
        IEOFeedVerifier.LeafInput calldata input,
        IEOFeedVerifier.VerificationParams calldata vParams
    )
        external
        onlyWhitelisted
        whenNotPaused
    {
        bytes memory data = _feedVerifier.verify(input, vParams);
        _processVerifiedCTRNG(data, vParams.blockNumber);
    }

    /// @notice Update multiple CTRNG feeds
    /// @param inputs Array of leaf inputs for verification
    /// @param vParams Verification parameters
    function updateFeeds(
        IEOFeedVerifier.LeafInput[] calldata inputs,
        IEOFeedVerifier.VerificationParams calldata vParams
    )
        external
        onlyWhitelisted
        whenNotPaused
    {
        if (inputs.length == 0) revert MissingLeafInputs();

        bytes[] memory data = _feedVerifier.batchVerify(inputs, vParams);
        for (uint256 i = 0; i < data.length; i++) {
            _processVerifiedCTRNG(data[i], vParams.blockNumber);
        }
    }

    /// @notice Set the pauser registry contract address
    /// @param pauserRegistry Address of the pauser registry contract
    function setPauserRegistry(address pauserRegistry) external onlyOwner onlyNonZeroAddress(pauserRegistry) {
        _pauserRegistry = IPauserRegistry(pauserRegistry);
        emit PauserRegistrySet(pauserRegistry);
    }

    /// @notice Pause the feed manager
    function pause() external onlyPauser {
        _pause();
    }

    /// @notice Unpause the feed manager
    function unpause() external onlyUnpauser {
        _unpause();
    }

    /// @notice Get the latest CTRNG feed data for a feed ID
    /// @param feedId Feed ID
    /// @return CTRNGData struct
    function getLatestCTRNGFeed(uint256 feedId) external onlyAuthorizedCaller returns (CTRNGData memory) {
        if (!_supportedFeedIds[feedId]) revert FeedNotSupported(feedId);
        uint256 latestSequence = _latestSequences[feedId];
        if (latestSequence == 0) revert SequenceNotFound(latestSequence);
        return _ctrngFeeds[feedId][latestSequence];
    }

    /// @notice Get CTRNG feed data by feed ID and sequence
    /// @param feedId Feed ID
    /// @param sequence Sequence number
    /// @return CTRNGData struct
    function getCTRNGFeedBySequence(
        uint256 feedId,
        uint256 sequence
    ) external onlyAuthorizedCaller returns (CTRNGData memory) {
        if (!_supportedFeedIds[feedId]) revert FeedNotSupported(feedId);
        CTRNGData memory data = _ctrngFeeds[feedId][sequence];
        if (data.sequence == 0 && sequence != 0) revert SequenceNotFound(sequence);
        return data;
    }

    /// @notice Check if a publisher is whitelisted
    /// @param publisher Publisher address
    /// @return bool True if whitelisted
    function isWhitelistedPublisher(address publisher) external view returns (bool) {
        return _whitelistedPublishers[publisher];
    }

    /// @notice Check if a feed ID is supported
    /// @param feedId Feed ID
    /// @return bool True if supported
    function isSupportedFeed(uint256 feedId) external view returns (bool) {
        return _supportedFeedIds[feedId];
    }

    /// @notice Get the feed deployer address
    /// @return address Feed deployer address
    function getFeedDeployer() external view returns (address) {
        return _feedDeployer;
    }

    /// @notice Get the feed verifier address
    /// @return IEOFeedVerifier Feed verifier contract
    function getFeedVerifier() external view returns (IEOFeedVerifier) {
        return _feedVerifier;
    }

    /// @notice Get the latest sequence for a feed ID
    /// @param feedId Feed ID
    /// @return uint256 Latest sequence number
    function getLatestSequence(uint256 feedId) external onlyAuthorizedCaller returns (uint256) {
        return _latestSequences[feedId];
    }

    /// @notice Check if a caller is authorized
    /// @param caller Caller address
    /// @return bool True if authorized
    function isAuthorizedCaller(address caller) external view returns (bool) {
        return _authorizedCallers[caller];
    }

    /* ============ Internal Functions ============ */

    /// @notice Process the verified CTRNG data, validate it and store it. If the timestamp is newer than the
    /// existing timestamp, updates the CTRNG feed and emits CTRNGUpdated. Otherwise skips.
    /// @param data verified CTRNG data, abi encoded (uint256 feedId, uint256 sequence, uint256 timestamp, uint256[] ctrng)
    /// @param blockNumber eoracle chain block number
    function _processVerifiedCTRNG(bytes memory data, uint256 blockNumber) internal {
        (uint256 feedId, uint256 sequence, uint256 timestamp, uint256[] memory ctrng) = abi.decode(
            data,
            (uint256, uint256, uint256, uint256[])
        );
        if (!_supportedFeedIds[feedId]) revert FeedNotSupported(feedId);

        uint256 latestSequence = _latestSequences[feedId];
        if (sequence > latestSequence || latestSequence == 0) {
            _ctrngFeeds[feedId][sequence] = CTRNGData(sequence, timestamp, ctrng, blockNumber);
            _latestSequences[feedId] = sequence;
            emit CTRNGUpdated(feedId, sequence, timestamp, ctrng);
        }
    }

    /// @dev Gap for future storage variables in upgradeable contract.
    /// See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
    // solhint-disable ordering
    // slither-disable-next-line unused-state,naming-convention
    uint256[45] private __gap;
    // solhint-disable enable
}

