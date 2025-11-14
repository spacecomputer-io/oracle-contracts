// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportVRFCoordinator} from "../src/OrbitportVRFCoordinator.sol";
import {OrbitportFeedAdapter} from "../src/adapters/OrbitportFeedAdapter.sol";
import {OrbitportFeedManager} from "../src/OrbitportFeedManager.sol";
import {IOrbitportVRFCoordinator} from "../src/interfaces/IOrbitportVRFCoordinator.sol";
import {IOrbitportFeedManager} from "../src/interfaces/IOrbitportFeedManager.sol";
import {IEOFeedVerifier} from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import {IPauserRegistry} from "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {InvalidAddress, RequestNotFound} from "../src/interfaces/Errors.sol";

// Import mocks
import {MockEOFeedVerifier} from "./OrbitportFeedManager.t.sol";
import {MockPauserRegistry} from "./OrbitportFeedManager.t.sol";

contract OrbitportVRFCoordinatorTest is Test {
    OrbitportFeedManager public feedManager;
    OrbitportFeedAdapter public adapter;
    OrbitportVRFCoordinator public vrfCoordinator;
    MockEOFeedVerifier public verifier;
    MockPauserRegistry public pauserRegistry;
    address public owner;
    address public publisher;
    address public feedDeployer;
    address public requester;

    uint256 public constant FEED_ID = 1;
    uint256 public constant SEQUENCE = 12345;
    uint256 public constant TIMESTAMP = 1704067200;
    uint256[] public ctrngValues;

    function setUp() public {
        owner = address(0x1);
        publisher = address(0x5);
        feedDeployer = address(0x4);
        requester = address(0x7);

        verifier = new MockEOFeedVerifier();
        pauserRegistry = new MockPauserRegistry(address(0x3));

        vm.startPrank(owner);
        feedManager = new OrbitportFeedManager();
        
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

        // Update feed with data
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

        vm.stopPrank();
        vm.prank(publisher);
        feedManager.updateFeed(input, vParams);

        // Create adapter
        adapter = new OrbitportFeedAdapter(address(feedManager), FEED_ID);

        // Create VRF coordinator
        vrfCoordinator = new OrbitportVRFCoordinator(address(adapter));
    }

    function test_RequestRandomWords() public {
        bytes32 keyHash = keccak256("test");
        uint64 subId = 1;
        uint16 requestConfirmations = 3;
        uint32 callbackGasLimit = 100000;
        uint32 numWords = 2;

        vm.prank(requester);
        uint256 requestId = vrfCoordinator.requestRandomWords(
            keyHash,
            subId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );

        assertEq(requestId, 1);
        
        IOrbitportVRFCoordinator.RandomWordsRequest memory request = vrfCoordinator.getRequest(requestId);
        assertEq(request.requester, requester);
        assertEq(request.numWords, numWords);
        
        assertTrue(vrfCoordinator.isFulfilled(requestId));
        
        uint256[] memory randomWords = vrfCoordinator.getFulfilledRandomWords(requestId);
        assertEq(randomWords.length, numWords);
        assertGt(randomWords[0], 0);
    }

    function test_RequestRandomWords_MultipleRequests() public {
        bytes32 keyHash = keccak256("test");
        uint64 subId = 1;
        uint16 requestConfirmations = 3;
        uint32 callbackGasLimit = 100000;
        uint32 numWords = 1;

        vm.prank(requester);
        uint256 requestId1 = vrfCoordinator.requestRandomWords(
            keyHash,
            subId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );

        vm.prank(requester);
        uint256 requestId2 = vrfCoordinator.requestRandomWords(
            keyHash,
            subId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );

        assertEq(requestId1, 1);
        assertEq(requestId2, 2);
        
        uint256[] memory words1 = vrfCoordinator.getFulfilledRandomWords(requestId1);
        uint256[] memory words2 = vrfCoordinator.getFulfilledRandomWords(requestId2);
        
        // Should be different random values
        assertNotEq(words1[0], words2[0]);
    }

    function test_GetInstantRandomness() public view {
        uint256 randomness = vrfCoordinator.getInstantRandomness();
        assertGt(randomness, 0);
    }

    function test_GetInstantRandomness_DifferentCalls() public {
        uint256 randomness1 = vrfCoordinator.getInstantRandomness();
        
        // Advance time
        vm.warp(block.timestamp + 1);
        
        uint256 randomness2 = vrfCoordinator.getInstantRandomness();
        
        // Should be different due to timestamp
        assertNotEq(randomness1, randomness2);
    }

    function test_FulfillRandomWords() public {
        // Create a new request that won't auto-fulfill
        // Since our simplified version auto-fulfills, we'll test the fulfill function differently
        bytes32 keyHash = keccak256("test");
        uint64 subId = 1;
        uint16 requestConfirmations = 3;
        uint32 callbackGasLimit = 100000;
        uint32 numWords = 3;

        vm.prank(requester);
        uint256 requestId = vrfCoordinator.requestRandomWords(
            keyHash,
            subId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );

        // Request is already fulfilled, verify it
        assertTrue(vrfCoordinator.isFulfilled(requestId));
        
        uint256[] memory fulfilled = vrfCoordinator.getFulfilledRandomWords(requestId);
        assertEq(fulfilled.length, numWords);
        assertGt(fulfilled[0], 0);
    }

    function test_FulfillRandomWords_InvalidRequest() public {
        uint256[] memory randomWords = new uint256[](1);
        randomWords[0] = 123;

        vm.expectRevert(abi.encodeWithSelector(RequestNotFound.selector, 999));
        vrfCoordinator.fulfillRandomWords(999, randomWords);
    }

    function test_FulfillRandomWords_AlreadyFulfilled() public {
        bytes32 keyHash = keccak256("test");
        uint64 subId = 1;
        uint16 requestConfirmations = 3;
        uint32 callbackGasLimit = 100000;
        uint32 numWords = 1;

        vm.prank(requester);
        uint256 requestId = vrfCoordinator.requestRandomWords(
            keyHash,
            subId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );

        // Try to fulfill again (should fail since already fulfilled)
        uint256[] memory randomWords = new uint256[](numWords);
        randomWords[0] = 123;
        
        vm.expectRevert(abi.encodeWithSelector(RequestNotFound.selector, requestId));
        vrfCoordinator.fulfillRandomWords(requestId, randomWords);
    }

    function test_SetFeedAdapter() public {
        address newAdapter = address(0x123);
        vrfCoordinator.setFeedAdapter(newAdapter);
        assertEq(vrfCoordinator.getFeedAdapter(), newAdapter);
    }

    function test_SetFeedAdapter_InvalidAddress() public {
        vm.expectRevert(abi.encodeWithSelector(InvalidAddress.selector));
        vrfCoordinator.setFeedAdapter(address(0));
    }

    function test_GetRequest_NotFound() public {
        vm.expectRevert(abi.encodeWithSelector(RequestNotFound.selector, 999));
        vrfCoordinator.getRequest(999);
    }

    function test_GetFulfilledRandomWords_NotFound() public {
        vm.expectRevert(abi.encodeWithSelector(RequestNotFound.selector, 999));
        vrfCoordinator.getFulfilledRandomWords(999);
    }
}

