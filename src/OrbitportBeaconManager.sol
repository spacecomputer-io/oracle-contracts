// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import { OwnableUpgradeable } from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { PausableUpgradeable } from "openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol";
import { IPauserRegistry } from "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import { IEOFeedVerifier } from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import { IOrbitportBeaconManager } from "./interfaces/IOrbitportBeaconManager.sol";
import {
    InvalidAddress,
    CallerIsNotWhitelisted,
    MissingLeafInputs,
    BeaconNotSupported,
    InvalidInput,
    CallerIsNotPauser,
    CallerIsNotUnpauser,
    CallerIsNotBeaconDeployer,
    SequenceNotFound,
    CallerIsNotRetriever
} from "./interfaces/Errors.sol";

/// @title OrbitportBeaconManager
/// @notice The OrbitportBeaconManager contract is responsible for receiving CTRNG beacon updates from whitelisted publishers.
/// These updates are verified using the logic in the EOFeedVerifier. Upon successful verification, the CTRNG data
/// is stored in the OrbitportBeaconManager and made available for other smart contracts to read. Only supported beacon IDs
/// can be published to the beacon manager.
contract OrbitportBeaconManager is IOrbitportBeaconManager, OwnableUpgradeable, PausableUpgradeable {
    /// @dev Map of beacon id to CTRNG data by sequence (beacon id => sequence => CTRNGData)
    mapping(uint256 => mapping(uint256 => CTRNGData)) internal _ctrngBeacons;

    /// @dev Map of beacon id to latest sequence (beacon id => latest sequence)
    mapping(uint256 => uint256) internal _latestSequences;

    /// @dev Map of whitelisted publishers (publisher => is whitelisted)
    mapping(address => bool) internal _whitelistedPublishers;

    /// @dev Map of supported beacons, (beacon id => is supported)
    mapping(uint256 => bool) internal _supportedBeaconIds;

    /// @dev Map of authorized callers (caller => is authorized)
    mapping(address => bool) internal _authorizedCallers;

    /// @dev feed verifier contract
    IEOFeedVerifier internal _feedVerifier;

    /// @notice Address of the `PauserRegistry` contract that this contract defers to for determining access control
    /// (for pausing).
    IPauserRegistry internal _pauserRegistry;

    /// @dev Address of the beacon deployer
    address internal _beaconDeployer;

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

    modifier onlyBeaconDeployer() {
        if (msg.sender != _beaconDeployer) revert CallerIsNotBeaconDeployer();
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
    /// @param beaconDeployer Address of the beacon deployer
    function initialize(
        address feedVerifier,
        address owner,
        address pauserRegistry,
        address beaconDeployer
    )
        external
        onlyNonZeroAddress(feedVerifier)
        onlyNonZeroAddress(beaconDeployer)
        onlyNonZeroAddress(pauserRegistry)
        initializer
    {
        __Ownable_init(owner);
        __Pausable_init();
        _feedVerifier = IEOFeedVerifier(feedVerifier);
        _pauserRegistry = IPauserRegistry(pauserRegistry);
        _beaconDeployer = beaconDeployer;
    }

    /* ============ External Functions ============ */

    /// @notice Set the feed verifier contract address
    /// @param feedVerifier Address of the feed verifier contract
    function setFeedVerifier(address feedVerifier) external onlyOwner onlyNonZeroAddress(feedVerifier) {
        _feedVerifier = IEOFeedVerifier(feedVerifier);
        emit FeedVerifierSet(feedVerifier);
    }

    /// @notice Set the beacon deployer
    /// @param beaconDeployer The beacon deployer address
    function setBeaconDeployer(address beaconDeployer) external onlyOwner onlyNonZeroAddress(beaconDeployer) {
        _beaconDeployer = beaconDeployer;
        emit BeaconDeployerSet(beaconDeployer);
    }

    /// @notice Set the supported beacons
    /// @param beaconIds Array of beacon ids
    /// @param isSupported Array of booleans indicating whether the beacon is supported
    function setSupportedBeacons(uint256[] calldata beaconIds, bool[] calldata isSupported) external onlyOwner {
        if (beaconIds.length != isSupported.length) revert InvalidInput();
        for (uint256 i = 0; i < beaconIds.length; i++) {
            _supportedBeaconIds[beaconIds[i]] = isSupported[i];
            emit SupportedBeaconsUpdated(beaconIds[i], isSupported[i]);
        }
    }

    /// @notice Add supported beacons
    /// @param beaconIds Array of beacon ids
    function addSupportedBeacons(uint256[] calldata beaconIds) external onlyBeaconDeployer {
        for (uint256 i = 0; i < beaconIds.length; i++) {
            _supportedBeaconIds[beaconIds[i]] = true;
            emit SupportedBeaconsUpdated(beaconIds[i], true);
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

    /// @notice Update a single CTRNG beacon
    /// @param input Leaf input for verification
    /// @param vParams Verification parameters
    function updateBeacon(
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

    /// @notice Update multiple CTRNG beacons
    /// @param inputs Array of leaf inputs for verification
    /// @param vParams Verification parameters
    function updateBeacons(
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

    /// @notice Pause the beacon manager
    function pause() external onlyPauser {
        _pause();
    }

    /// @notice Unpause the beacon manager
    function unpause() external onlyUnpauser {
        _unpause();
    }

    /// @notice Get the latest CTRNG beacon data for a beacon ID
    /// @param beaconId Beacon ID
    /// @return CTRNGData struct
    function getLatestCTRNGBeacon(uint256 beaconId) external view onlyAuthorizedCaller returns (CTRNGData memory) {
        if (!_supportedBeaconIds[beaconId]) revert BeaconNotSupported(beaconId);
        uint256 latestSequence = _latestSequences[beaconId];
        if (latestSequence == 0) revert SequenceNotFound(latestSequence);
        return _ctrngBeacons[beaconId][latestSequence];
    }

    /// @notice Get CTRNG beacon data by beacon ID and sequence
    /// @param beaconId Beacon ID
    /// @param sequence Sequence number
    /// @return CTRNGData struct
    function getCTRNGBeaconBySequence(
        uint256 beaconId,
        uint256 sequence
    ) external view onlyAuthorizedCaller returns (CTRNGData memory) {
        if (!_supportedBeaconIds[beaconId]) revert BeaconNotSupported(beaconId);
        CTRNGData memory data = _ctrngBeacons[beaconId][sequence];
        if (data.sequence == 0 && sequence != 0) revert SequenceNotFound(sequence);
        return data;
    }

    /// @notice Check if a publisher is whitelisted
    /// @param publisher Publisher address
    /// @return bool True if whitelisted
    function isWhitelistedPublisher(address publisher) external view returns (bool) {
        return _whitelistedPublishers[publisher];
    }

    /// @notice Check if a beacon ID is supported
    /// @param beaconId Beacon ID
    /// @return bool True if supported
    function isSupportedBeacon(uint256 beaconId) external view returns (bool) {
        return _supportedBeaconIds[beaconId];
    }

    /// @notice Get the beacon deployer address
    /// @return address Beacon deployer address
    function getBeaconDeployer() external view returns (address) {
        return _beaconDeployer;
    }

    /// @notice Get the feed verifier address
    /// @return IEOFeedVerifier Feed verifier contract
    function getFeedVerifier() external view returns (IEOFeedVerifier) {
        return _feedVerifier;
    }

    /// @notice Get the latest sequence for a beacon ID
    /// @param beaconId Beacon ID
    /// @return uint256 Latest sequence number
    function getLatestSequence(uint256 beaconId) external view onlyAuthorizedCaller returns (uint256) {
        return _latestSequences[beaconId];
    }

    /// @notice Check if a caller is authorized
    /// @param caller Caller address
    /// @return bool True if authorized
    function isAuthorizedCaller(address caller) external view returns (bool) {
        return _authorizedCallers[caller];
    }

    /* ============ Internal Functions ============ */

    /// @notice Process the verified CTRNG data, validate it and store it. If the timestamp is newer than the
    /// existing timestamp, updates the CTRNG beacon and emits CTRNGUpdated. Otherwise skips.
    /// @param data verified CTRNG data, abi encoded (uint256 beaconId, uint256 sequence, uint256 timestamp, uint256[] ctrng)
    /// @param blockNumber eoracle chain block number
    function _processVerifiedCTRNG(bytes memory data, uint256 blockNumber) internal {
        (uint256 beaconId, uint256 sequence, uint256 timestamp, uint256[] memory ctrng) = abi.decode(
            data,
            (uint256, uint256, uint256, uint256[])
        );
        if (!_supportedBeaconIds[beaconId]) revert BeaconNotSupported(beaconId);

        uint256 latestSequence = _latestSequences[beaconId];
        if (sequence > latestSequence || latestSequence == 0) {
            _ctrngBeacons[beaconId][sequence] = CTRNGData(sequence, timestamp, ctrng, blockNumber);
            _latestSequences[beaconId] = sequence;
            emit CTRNGUpdated(beaconId, sequence, timestamp, ctrng);
        }
    }

    /// @dev Gap for future storage variables in upgradeable contract.
    /// See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
    // solhint-disable ordering
    // slither-disable-next-line unused-state,naming-convention
    uint256[45] private __gap;
    // solhint-enable ordering
}
