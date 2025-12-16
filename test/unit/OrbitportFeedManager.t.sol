// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportFeedManager} from "../../src/OrbitportFeedManager.sol";
import {IOrbitportFeedManager} from "../../src/interfaces/IOrbitportFeedManager.sol";
import {IEOFeedVerifier} from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {
    CallerIsNotRetriever,
    InvalidAddress,
    CallerIsNotWhitelisted,
    MissingLeafInputs,
    FeedNotSupported,
    InvalidInput,
    CallerIsNotPauser,
    CallerIsNotUnpauser,
    CallerIsNotFeedDeployer,
    SequenceNotFound
} from "../../src/interfaces/Errors.sol";
import {MockEOFeedVerifier} from "../mocks/MockEOFeedVerifier.sol";
import {MockPauserRegistry} from "../mocks/MockPauserRegistry.sol";

contract OrbitportFeedManagerTest is Test {
    OrbitportFeedManager public feedManager;
    MockEOFeedVerifier public verifier;
    MockPauserRegistry public pauserRegistry;
    address public owner;
    address public pauser;
    address public unpauser;
    address public feedDeployer;
    address public publisher;
    address public user;
    address public retriever;

    uint256 public constant FEED_ID = 1;
    uint256 public constant SEQUENCE = 12345;
    uint256 public constant TIMESTAMP = 1704067200;
    uint256[] public ctrngValues;

    function setUp() public {
        owner = address(0x1);
        pauser = address(0x2);
        unpauser = address(0x3);
        feedDeployer = address(0x4);
        publisher = address(0x5);
        user = address(0x6);
        retriever = address(0x7);

        verifier = new MockEOFeedVerifier();
        pauserRegistry = new MockPauserRegistry(unpauser);
        pauserRegistry.setPauser(pauser, true);

        vm.startPrank(owner);
        feedManager = new OrbitportFeedManager();
        
        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            OrbitportFeedManager.initialize.selector,
            address(verifier),
            owner,
            address(pauserRegistry),
            feedDeployer
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(feedManager), initData);
        feedManager = OrbitportFeedManager(payable(address(proxy)));

        // Setup initial data
        ctrngValues = new uint256[](5);
        ctrngValues[0] = 10;
        ctrngValues[1] = 20;
        ctrngValues[2] = 30;
        ctrngValues[3] = 40;
        ctrngValues[4] = 50;

        // Whitelist publisher
        address[] memory publishers = new address[](1);
        publishers[0] = publisher;
        bool[] memory isWhitelisted = new bool[](1);
        isWhitelisted[0] = true;
        feedManager.whitelistPublishers(publishers, isWhitelisted);

        // Set supported feed
        uint256[] memory feedIds = new uint256[](1);
        feedIds[0] = FEED_ID;
        bool[] memory supported = new bool[](1);
        supported[0] = true;
        feedManager.setSupportedFeeds(feedIds, supported);
        
        // Authorize retriever
        address[] memory authorizedCallers = new address[](1);
        authorizedCallers[0] = retriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        feedManager.setAuthorizedCallers(authorizedCallers, isAuthorized);

        vm.stopPrank();
    }

    /* ============ Access Control Tests ============ */

    function test_RevertWhen_CallerIsNotAuthorized_GetLatestCTRNGFeed() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, user));
        feedManager.getLatestCTRNGFeed(FEED_ID);
    }

    function test_RevertWhen_CallerIsNotAuthorized_GetCTRNGFeedBySequence() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, user));
        feedManager.getCTRNGFeedBySequence(FEED_ID, SEQUENCE);
    }

    function test_RevertWhen_CallerIsNotAuthorized_GetLatestSequence() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, user));
        feedManager.getLatestSequence(FEED_ID);
    }

    function test_AuthorizeCaller_GivenOwner() public {
        address newRetriever = address(0x99);
        
        // First, publish some data so we can test retrieval
        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData, verifiedData);
        vm.prank(publisher);
        feedManager.updateFeed(input, vParams);
        
        // Now authorize the new retriever
        address[] memory authorizedCallers = new address[](1);
        authorizedCallers[0] = newRetriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        
        vm.prank(owner);
        feedManager.setAuthorizedCallers(authorizedCallers, isAuthorized);
        
        assertTrue(feedManager.isAuthorizedCaller(newRetriever));
        
        // Should be able to call now
        vm.prank(newRetriever);
        IOrbitportFeedManager.CTRNGData memory data = feedManager.getLatestCTRNGFeed(FEED_ID);
        assertEq(data.sequence, SEQUENCE);
    }

    function test_DeauthorizeCaller_GivenOwner() public {
        address[] memory authorizedCallers = new address[](1);
        authorizedCallers[0] = retriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = false;
        
        vm.prank(owner);
        feedManager.setAuthorizedCallers(authorizedCallers, isAuthorized);
        
        assertFalse(feedManager.isAuthorizedCaller(retriever));
        
        // Should fail now
        vm.prank(retriever);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, retriever));
        feedManager.getLatestCTRNGFeed(FEED_ID);
    }

    /* ============ Functionality Tests ============ */

    function test_Initialize_GivenAdmin() public {
        // No longer needs retriever role for these view functions
        vm.startPrank(user);
        assertEq(address(feedManager.getFeedVerifier()), address(verifier));
        assertEq(feedManager.getFeedDeployer(), feedDeployer);
        assertTrue(feedManager.isSupportedFeed(FEED_ID));
        assertTrue(feedManager.isWhitelistedPublisher(publisher));
        vm.stopPrank();
        
        assertEq(feedManager.owner(), owner);
    }

    function test_UpdateFeed_GivenPublisher() public {
        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData, verifiedData);

        vm.prank(publisher);
        feedManager.updateFeed(input, vParams);

        vm.prank(retriever);
        IOrbitportFeedManager.CTRNGData memory data = feedManager.getLatestCTRNGFeed(FEED_ID);
        assertEq(data.sequence, SEQUENCE);
        assertEq(data.timestamp, TIMESTAMP);
        assertEq(data.ctrng.length, ctrngValues.length);
        assertEq(data.ctrng[0], ctrngValues[0]);
    }

    function test_GetCTRNGFeedBySequence_GivenExistingSequence() public {
        // First update feed
        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData, verifiedData);

        vm.prank(publisher);
        feedManager.updateFeed(input, vParams);

        // Get by sequence
        vm.prank(retriever);
        IOrbitportFeedManager.CTRNGData memory data = feedManager.getCTRNGFeedBySequence(FEED_ID, SEQUENCE);
        assertEq(data.sequence, SEQUENCE);
        assertEq(data.timestamp, TIMESTAMP);
    }

    /* ============ Constructor Tests ============ */

    function test_Constructor_DisablesInitializers() public {
        OrbitportFeedManager newManager = new OrbitportFeedManager();
        
        bytes memory initData = abi.encodeWithSelector(
            OrbitportFeedManager.initialize.selector,
            address(verifier),
            owner,
            address(pauserRegistry),
            feedDeployer
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(newManager), initData);
        OrbitportFeedManager proxiedManager = OrbitportFeedManager(payable(address(proxy)));
        
        // Try to initialize again - should revert
        vm.expectRevert();
        proxiedManager.initialize(address(verifier), owner, address(pauserRegistry), feedDeployer);
    }

    /* ============ Initialize Tests ============ */

    function test_RevertWhen_FeedVerifierIsZero_Initialize() public {
        OrbitportFeedManager newManager = new OrbitportFeedManager();
        bytes memory initData = abi.encodeWithSelector(
            OrbitportFeedManager.initialize.selector,
            address(0),
            owner,
            address(pauserRegistry),
            feedDeployer
        );
        
        // Proxy construction should revert because initialize will revert
        vm.expectRevert(InvalidAddress.selector);
        new ERC1967Proxy(address(newManager), initData);
    }

    function test_RevertWhen_PauserRegistryIsZero_Initialize() public {
        OrbitportFeedManager newManager = new OrbitportFeedManager();
        bytes memory initData = abi.encodeWithSelector(
            OrbitportFeedManager.initialize.selector,
            address(verifier),
            owner,
            address(0),
            feedDeployer
        );
        
        // Proxy construction should revert because initialize will revert
        vm.expectRevert(InvalidAddress.selector);
        new ERC1967Proxy(address(newManager), initData);
    }

    function test_RevertWhen_FeedDeployerIsZero_Initialize() public {
        OrbitportFeedManager newManager = new OrbitportFeedManager();
        bytes memory initData = abi.encodeWithSelector(
            OrbitportFeedManager.initialize.selector,
            address(verifier),
            owner,
            address(pauserRegistry),
            address(0)
        );
        
        // Proxy construction should revert because initialize will revert
        vm.expectRevert(InvalidAddress.selector);
        new ERC1967Proxy(address(newManager), initData);
    }

    /* ============ setFeedVerifier Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetFeedVerifier() public {
        address newVerifier = address(0x99);
        vm.prank(user);
        vm.expectRevert();
        feedManager.setFeedVerifier(newVerifier);
    }

    function test_RevertWhen_FeedVerifierIsZero_SetFeedVerifier() public {
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        feedManager.setFeedVerifier(address(0));
    }

    function test_SetFeedVerifier_GivenOwner() public {
        address newVerifier = address(0x99);
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportFeedManager.FeedVerifierSet(newVerifier);
        feedManager.setFeedVerifier(newVerifier);
        
        assertEq(address(feedManager.getFeedVerifier()), newVerifier);
    }

    /* ============ setFeedDeployer Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetFeedDeployer() public {
        address newDeployer = address(0x99);
        vm.prank(user);
        vm.expectRevert();
        feedManager.setFeedDeployer(newDeployer);
    }

    function test_RevertWhen_FeedDeployerIsZero_SetFeedDeployer() public {
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        feedManager.setFeedDeployer(address(0));
    }

    function test_SetFeedDeployer_GivenOwner() public {
        address newDeployer = address(0x99);
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportFeedManager.FeedDeployerSet(newDeployer);
        feedManager.setFeedDeployer(newDeployer);
        
        assertEq(feedManager.getFeedDeployer(), newDeployer);
    }

    /* ============ setSupportedFeeds Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetSupportedFeeds() public {
        uint256[] memory feedIds = new uint256[](1);
        feedIds[0] = 2;
        bool[] memory supported = new bool[](1);
        supported[0] = true;
        
        vm.prank(user);
        vm.expectRevert();
        feedManager.setSupportedFeeds(feedIds, supported);
    }

    function test_RevertWhen_ArrayLengthMismatch_SetSupportedFeeds() public {
        uint256[] memory feedIds = new uint256[](2);
        feedIds[0] = 2;
        feedIds[1] = 3;
        bool[] memory supported = new bool[](1);
        supported[0] = true;
        
        vm.prank(owner);
        vm.expectRevert(InvalidInput.selector);
        feedManager.setSupportedFeeds(feedIds, supported);
    }

    function test_SetSupportedFeeds_GivenOwner() public {
        uint256[] memory feedIds = new uint256[](2);
        feedIds[0] = 2;
        feedIds[1] = 3;
        bool[] memory supported = new bool[](2);
        supported[0] = true;
        supported[1] = false;
        
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportFeedManager.SupportedFeedsUpdated(feedIds[0], true);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportFeedManager.SupportedFeedsUpdated(feedIds[1], false);
        feedManager.setSupportedFeeds(feedIds, supported);
        
        assertTrue(feedManager.isSupportedFeed(feedIds[0]));
        assertFalse(feedManager.isSupportedFeed(feedIds[1]));
    }

    /* ============ addSupportedFeeds Tests ============ */

    function test_RevertWhen_CallerIsNotFeedDeployer_AddSupportedFeeds() public {
        uint256[] memory feedIds = new uint256[](1);
        feedIds[0] = 2;
        
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotFeedDeployer.selector));
        feedManager.addSupportedFeeds(feedIds);
    }

    function test_AddSupportedFeeds_GivenFeedDeployer() public {
        uint256[] memory feedIds = new uint256[](2);
        feedIds[0] = 2;
        feedIds[1] = 3;
        
        vm.prank(feedDeployer);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportFeedManager.SupportedFeedsUpdated(feedIds[0], true);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportFeedManager.SupportedFeedsUpdated(feedIds[1], true);
        feedManager.addSupportedFeeds(feedIds);
        
        assertTrue(feedManager.isSupportedFeed(feedIds[0]));
        assertTrue(feedManager.isSupportedFeed(feedIds[1]));
    }

    /* ============ whitelistPublishers Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_WhitelistPublishers() public {
        address[] memory publishers = new address[](1);
        publishers[0] = address(0x99);
        bool[] memory isWhitelisted = new bool[](1);
        isWhitelisted[0] = true;
        
        vm.prank(user);
        vm.expectRevert();
        feedManager.whitelistPublishers(publishers, isWhitelisted);
    }

    function test_RevertWhen_ArrayLengthMismatch_WhitelistPublishers() public {
        address[] memory publishers = new address[](2);
        publishers[0] = address(0x99);
        publishers[1] = address(0x98);
        bool[] memory isWhitelisted = new bool[](1);
        isWhitelisted[0] = true;
        
        vm.prank(owner);
        vm.expectRevert(InvalidInput.selector);
        feedManager.whitelistPublishers(publishers, isWhitelisted);
    }

    function test_RevertWhen_PublisherIsZero_WhitelistPublishers() public {
        address[] memory publishers = new address[](1);
        publishers[0] = address(0);
        bool[] memory isWhitelisted = new bool[](1);
        isWhitelisted[0] = true;
        
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        feedManager.whitelistPublishers(publishers, isWhitelisted);
    }

    function test_WhitelistPublishers_GivenOwner() public {
        address newPublisher = address(0x99);
        address[] memory publishers = new address[](1);
        publishers[0] = newPublisher;
        bool[] memory isWhitelisted = new bool[](1);
        isWhitelisted[0] = true;
        
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportFeedManager.PublisherWhitelisted(newPublisher, true);
        feedManager.whitelistPublishers(publishers, isWhitelisted);
        
        assertTrue(feedManager.isWhitelistedPublisher(newPublisher));
    }

    /* ============ setAuthorizedCallers Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetAuthorizedCallers() public {
        address[] memory callers = new address[](1);
        callers[0] = address(0x99);
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        
        vm.prank(user);
        vm.expectRevert();
        feedManager.setAuthorizedCallers(callers, isAuthorized);
    }

    function test_RevertWhen_ArrayLengthMismatch_SetAuthorizedCallers() public {
        address[] memory callers = new address[](2);
        callers[0] = address(0x99);
        callers[1] = address(0x98);
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        
        vm.prank(owner);
        vm.expectRevert(InvalidInput.selector);
        feedManager.setAuthorizedCallers(callers, isAuthorized);
    }

    function test_RevertWhen_CallerIsZero_SetAuthorizedCallers() public {
        address[] memory callers = new address[](1);
        callers[0] = address(0);
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        feedManager.setAuthorizedCallers(callers, isAuthorized);
    }

    /* ============ updateFeed Tests ============ */

    function test_RevertWhen_CallerIsNotWhitelisted_UpdateFeed() public {
        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData, verifiedData);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotWhitelisted.selector, user));
        feedManager.updateFeed(input, vParams);
    }

    function test_RevertWhen_ContractIsPaused_UpdateFeed() public {
        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData, verifiedData);
        
        // Pause the contract
        vm.prank(pauser);
        feedManager.pause();
        
        vm.prank(publisher);
        vm.expectRevert();
        feedManager.updateFeed(input, vParams);
    }

    function test_RevertWhen_FeedNotSupported_UpdateFeed() public {
        uint256 unsupportedFeedId = 999;
        bytes memory inputData = abi.encode(unsupportedFeedId, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(unsupportedFeedId, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData, verifiedData);
        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(FeedNotSupported.selector, unsupportedFeedId));
        feedManager.updateFeed(input, vParams);
    }

    function test_UpdateFeed_SkipsWhenSequenceNotGreater() public {
        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData, verifiedData);
        vm.prank(publisher);
        feedManager.updateFeed(input, vParams);
        
        // Try to update with same sequence - should skip
        vm.prank(publisher);
        feedManager.updateFeed(input, vParams);
        
        // Verify only one update occurred
        vm.prank(retriever);
        IOrbitportFeedManager.CTRNGData memory data = feedManager.getLatestCTRNGFeed(FEED_ID);
        assertEq(data.sequence, SEQUENCE);
    }

    /* ============ updateFeeds Tests ============ */

    function test_RevertWhen_CallerIsNotWhitelisted_UpdateFeeds() public {
        IEOFeedVerifier.LeafInput[] memory inputs = new IEOFeedVerifier.LeafInput[](1);
        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        inputs[0] = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData, abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues));
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotWhitelisted.selector, user));
        feedManager.updateFeeds(inputs, vParams);
    }

    function test_RevertWhen_ContractIsPaused_UpdateFeeds() public {
        IEOFeedVerifier.LeafInput[] memory inputs = new IEOFeedVerifier.LeafInput[](1);
        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        inputs[0] = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData, abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues));
        
        // Pause the contract
        vm.prank(pauser);
        feedManager.pause();
        
        vm.prank(publisher);
        vm.expectRevert();
        feedManager.updateFeeds(inputs, vParams);
    }

    function test_RevertWhen_InputsEmpty_UpdateFeeds() public {
        IEOFeedVerifier.LeafInput[] memory inputs = new IEOFeedVerifier.LeafInput[](0);
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        vm.prank(publisher);
        vm.expectRevert(MissingLeafInputs.selector);
        feedManager.updateFeeds(inputs, vParams);
    }

    function test_UpdateFeeds_GivenPublisher() public {
        IEOFeedVerifier.LeafInput[] memory inputs = new IEOFeedVerifier.LeafInput[](2);
        bytes memory inputData1 = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory inputData2 = abi.encode(FEED_ID, SEQUENCE + 1, TIMESTAMP + 1, ctrngValues);
        
        inputs[0] = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData1,
            proof: new bytes32[](0)
        });
        inputs[1] = IEOFeedVerifier.LeafInput({
            leafIndex: 1,
            unhashedLeaf: inputData2,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData1, abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues));
        verifier.setVerifiedData(inputData2, abi.encode(FEED_ID, SEQUENCE + 1, TIMESTAMP + 1, ctrngValues));
        
        vm.prank(publisher);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportFeedManager.CTRNGUpdated(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportFeedManager.CTRNGUpdated(FEED_ID, SEQUENCE + 1, TIMESTAMP + 1, ctrngValues);
        feedManager.updateFeeds(inputs, vParams);
        
        vm.prank(retriever);
        IOrbitportFeedManager.CTRNGData memory data = feedManager.getLatestCTRNGFeed(FEED_ID);
        assertEq(data.sequence, SEQUENCE + 1);
    }

    /* ============ setPauserRegistry Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetPauserRegistry() public {
        MockPauserRegistry newRegistry = new MockPauserRegistry(unpauser);
        vm.prank(user);
        vm.expectRevert();
        feedManager.setPauserRegistry(address(newRegistry));
    }

    function test_RevertWhen_PauserRegistryIsZero_SetPauserRegistry() public {
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        feedManager.setPauserRegistry(address(0));
    }

    function test_SetPauserRegistry_GivenOwner() public {
        MockPauserRegistry newRegistry = new MockPauserRegistry(unpauser);
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportFeedManager.PauserRegistrySet(address(newRegistry));
        feedManager.setPauserRegistry(address(newRegistry));
    }

    /* ============ pause Tests ============ */

    function test_RevertWhen_CallerIsNotPauser_Pause() public {
        vm.prank(user);
        vm.expectRevert(CallerIsNotPauser.selector);
        feedManager.pause();
    }

    function test_Pause_GivenPauser() public {
        vm.prank(pauser);
        feedManager.pause();
        
        assertTrue(feedManager.paused());
    }

    /* ============ unpause Tests ============ */

    function test_RevertWhen_CallerIsNotUnpauser_Unpause() public {
        // First pause
        vm.prank(pauser);
        feedManager.pause();
        
        vm.prank(user);
        vm.expectRevert(CallerIsNotUnpauser.selector);
        feedManager.unpause();
    }

    function test_Unpause_GivenUnpauser() public {
        // First pause
        vm.prank(pauser);
        feedManager.pause();
        assertTrue(feedManager.paused());
        
        vm.prank(unpauser);
        feedManager.unpause();
        assertFalse(feedManager.paused());
    }

    /* ============ getLatestCTRNGFeed Tests ============ */

    function test_RevertWhen_FeedNotSupported_GetLatestCTRNGFeed() public {
        uint256 unsupportedFeedId = 999;
        vm.prank(retriever);
        vm.expectRevert(abi.encodeWithSelector(FeedNotSupported.selector, unsupportedFeedId));
        feedManager.getLatestCTRNGFeed(unsupportedFeedId);
    }

    function test_RevertWhen_SequenceIsZero_GetLatestCTRNGFeed() public {
        // Feed is supported but no data has been published
        vm.prank(retriever);
        vm.expectRevert(abi.encodeWithSelector(SequenceNotFound.selector, 0));
        feedManager.getLatestCTRNGFeed(FEED_ID);
    }

    /* ============ getCTRNGFeedBySequence Tests ============ */

    function test_RevertWhen_FeedNotSupported_GetCTRNGFeedBySequence() public {
        uint256 unsupportedFeedId = 999;
        vm.prank(retriever);
        vm.expectRevert(abi.encodeWithSelector(FeedNotSupported.selector, unsupportedFeedId));
        feedManager.getCTRNGFeedBySequence(unsupportedFeedId, SEQUENCE);
    }

    function test_RevertWhen_SequenceNotFound_GetCTRNGFeedBySequence() public {
        uint256 nonExistentSequence = 99999;
        vm.prank(retriever);
        vm.expectRevert(abi.encodeWithSelector(SequenceNotFound.selector, nonExistentSequence));
        feedManager.getCTRNGFeedBySequence(FEED_ID, nonExistentSequence);
    }
}
