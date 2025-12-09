// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportVRFCoordinator} from "../../src/OrbitportVRFCoordinator.sol";
import {IOrbitportVRFCoordinator} from "../../src/interfaces/IOrbitportVRFCoordinator.sol";
import {IOrbitportFeedManager} from "../../src/interfaces/IOrbitportFeedManager.sol";
import {MockOrbitportFeedManager} from "../mocks/MockOrbitportFeedManager.sol";
import {RequestNotFound, CallerIsNotRetriever, CallerIsNotFulfiller} from "../../src/interfaces/Errors.sol";

contract OrbitportVRFCoordinatorTest is Test {
    MockOrbitportFeedManager public mockFeedManager;
    OrbitportVRFCoordinator public vrfCoordinator;
    address public owner;
    address public requester;
    address public retriever;
    address public fulfiller;

    uint256 public constant BEACON_ID = 1;
    uint256[] public ctrngValues;

    function setUp() public {
        owner = address(0x1);
        requester = address(0x7);
        retriever = address(0x8);
        fulfiller = address(0x9);

        mockFeedManager = new MockOrbitportFeedManager();
        
        vm.prank(owner);
        vrfCoordinator = new OrbitportVRFCoordinator(address(mockFeedManager), BEACON_ID);
        
        // Authorize retrievers
        address[] memory retrievers = new address[](1);
        retrievers[0] = retriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        vm.prank(owner);
        vrfCoordinator.setAuthorizedRetrievers(retrievers, isAuthorized);
        
        // Authorize fulfillers
        address[] memory fulfillers = new address[](1);
        fulfillers[0] = fulfiller;
        vm.prank(owner);
        vrfCoordinator.setAuthorizedFulfillers(fulfillers, isAuthorized);
        
        // Setup mock data
        ctrngValues = new uint256[](5);
        ctrngValues[0] = 10;
        ctrngValues[1] = 20;
        ctrngValues[2] = 30;
        ctrngValues[3] = 40;
        ctrngValues[4] = 50;
        
        IOrbitportFeedManager.CTRNGData memory data = IOrbitportFeedManager.CTRNGData({
            sequence: 1,
            timestamp: block.timestamp,
            ctrng: ctrngValues,
            blockNumber: block.number
        });
        mockFeedManager.setLatestCTRNGFeed(BEACON_ID, data);
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
        
        // Request should not be fulfilled yet (async like Chainlink)
        assertFalse(vrfCoordinator.isFulfilled(requestId));
    }

    /* ============ Access Control Tests ============ */

    function test_RevertWhen_CallerIsNotRetriever_GetInstantRandomness() public {
        uint32 numWords = 1;
        
        vm.prank(requester);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, requester));
        vrfCoordinator.getInstantRandomness(numWords);
    }

    function test_GetInstantRandomness_GivenRetriever() public {
        uint32 numWords = 2;
        
        vm.prank(retriever);
        (uint256 requestId, uint256[] memory randomWords) = vrfCoordinator.getInstantRandomness(numWords);
        
        assertGt(requestId, 0);
        assertEq(randomWords.length, numWords);
        assertTrue(vrfCoordinator.isFulfilled(requestId));
    }

    function test_AuthorizeRetriever_GivenOwner() public {
        address newRetriever = address(0x99);
        
        address[] memory retrievers = new address[](1);
        retrievers[0] = newRetriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        
        vm.prank(owner);
        vrfCoordinator.setAuthorizedRetrievers(retrievers, isAuthorized);
        
        assertTrue(vrfCoordinator.isAuthorizedRetriever(newRetriever));
        
        // Should be able to call now
        vm.prank(newRetriever);
        vrfCoordinator.getInstantRandomness(1);
    }

    function test_DeauthorizeRetriever_GivenOwner() public {
        address[] memory retrievers = new address[](1);
        retrievers[0] = retriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = false;
        
        vm.prank(owner);
        vrfCoordinator.setAuthorizedRetrievers(retrievers, isAuthorized);
        
        assertFalse(vrfCoordinator.isAuthorizedRetriever(retriever));
        
        // Should fail now
        vm.prank(retriever);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, retriever));
        vrfCoordinator.getInstantRandomness(1);
    }

    function test_RevertWhen_CallerIsNotOwner_AuthorizeRetriever() public {
        address newRetriever = address(0x99);
        
        address[] memory retrievers = new address[](1);
        retrievers[0] = newRetriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        
        vm.prank(requester);
        vm.expectRevert();
        vrfCoordinator.setAuthorizedRetrievers(retrievers, isAuthorized);
    }

    /* ============ Uniqueness Tests ============ */

    function test_GetInstantRandomness_GivenRetriever_ReturnsUniqueValues() public {
        uint32 numWords = 5;
        
        vm.prank(retriever);
        (, uint256[] memory randomWords) = vrfCoordinator.getInstantRandomness(numWords);
        
        // Check uniqueness within the batch
        for (uint i = 0; i < numWords; i++) {
            for (uint j = i + 1; j < numWords; j++) {
                assertNotEq(randomWords[i], randomWords[j]);
            }
        }
    }

    function test_GetInstantRandomness_MultipleCalls_ReturnsUniqueValues() public {
        uint32 numWords = 1;
        
        vm.prank(retriever);
        (, uint256[] memory words1) = vrfCoordinator.getInstantRandomness(numWords);
        
        // Same block/time, same requester, same everything except internal nonce/counter
        vm.prank(retriever);
        (, uint256[] memory words2) = vrfCoordinator.getInstantRandomness(numWords);
        
        assertNotEq(words1[0], words2[0]);
    }
    
    function test_GetInstantRandomness_GivenLargeNumWords() public {
        uint32 numWords = 20;
        
        vm.prank(retriever);
        (, uint256[] memory randomWords) = vrfCoordinator.getInstantRandomness(numWords);
        
        assertEq(randomWords.length, numWords);
        
        // Verify all are unique
        for (uint i = 0; i < numWords; i++) {
            for (uint j = i + 1; j < numWords; j++) {
                assertNotEq(randomWords[i], randomWords[j]);
            }
        }
    }

    /* ============ FulfillRandomWords Tests ============ */

    function test_FulfillRandomWords_GivenFulfiller() public {
        bytes32 keyHash = keccak256("test");
        uint64 subId = 1;
        uint16 requestConfirmations = 3;
        uint32 callbackGasLimit = 100000;
        uint32 numWords = 2;

        // Request random words
        vm.prank(requester);
        uint256 requestId = vrfCoordinator.requestRandomWords(
            keyHash,
            subId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );

        assertFalse(vrfCoordinator.isFulfilled(requestId));

        // Fulfill the request
        uint256[] memory randomWords = new uint256[](numWords);
        randomWords[0] = 12345;
        randomWords[1] = 67890;

        vm.prank(fulfiller);
        vrfCoordinator.fulfillRandomWords(requestId, randomWords);

        assertTrue(vrfCoordinator.isFulfilled(requestId));
        uint256[] memory fulfilledWords = vrfCoordinator.getFulfilledRandomWords(requestId);
        assertEq(fulfilledWords.length, numWords);
        assertEq(fulfilledWords[0], randomWords[0]);
        assertEq(fulfilledWords[1], randomWords[1]);
    }

    function test_RevertWhen_CallerIsNotFulfiller_FulfillRandomWords() public {
        bytes32 keyHash = keccak256("test");
        uint64 subId = 1;
        uint16 requestConfirmations = 3;
        uint32 callbackGasLimit = 100000;
        uint32 numWords = 2;

        // Request random words
        vm.prank(requester);
        uint256 requestId = vrfCoordinator.requestRandomWords(
            keyHash,
            subId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );

        // Try to fulfill without being authorized
        uint256[] memory randomWords = new uint256[](numWords);
        randomWords[0] = 12345;
        randomWords[1] = 67890;

        vm.prank(requester);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotFulfiller.selector, requester));
        vrfCoordinator.fulfillRandomWords(requestId, randomWords);
    }

    function test_RevertWhen_RequestNotFound_FulfillRandomWords() public {
        uint256[] memory randomWords = new uint256[](2);
        randomWords[0] = 12345;
        randomWords[1] = 67890;

        vm.prank(fulfiller);
        vm.expectRevert(abi.encodeWithSelector(RequestNotFound.selector, 999));
        vrfCoordinator.fulfillRandomWords(999, randomWords);
    }

    function test_RevertWhen_AlreadyFulfilled_FulfillRandomWords() public {
        bytes32 keyHash = keccak256("test");
        uint64 subId = 1;
        uint16 requestConfirmations = 3;
        uint32 callbackGasLimit = 100000;
        uint32 numWords = 2;

        // Request random words
        vm.prank(requester);
        uint256 requestId = vrfCoordinator.requestRandomWords(
            keyHash,
            subId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );

        // Fulfill the request
        uint256[] memory randomWords = new uint256[](numWords);
        randomWords[0] = 12345;
        randomWords[1] = 67890;

        vm.prank(fulfiller);
        vrfCoordinator.fulfillRandomWords(requestId, randomWords);

        // Try to fulfill again
        vm.prank(fulfiller);
        vm.expectRevert(abi.encodeWithSelector(RequestNotFound.selector, requestId));
        vrfCoordinator.fulfillRandomWords(requestId, randomWords);
    }

    function test_AuthorizeFulfiller_GivenOwner() public {
        address newFulfiller = address(0x99);
        
        address[] memory fulfillers = new address[](1);
        fulfillers[0] = newFulfiller;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        
        vm.prank(owner);
        vrfCoordinator.setAuthorizedFulfillers(fulfillers, isAuthorized);
        
        assertTrue(vrfCoordinator.isAuthorizedFulfiller(newFulfiller));
        
        // Should be able to fulfill now
        vm.prank(requester);
        uint256 requestId = vrfCoordinator.requestRandomWords(
            keccak256("test"),
            1,
            3,
            100000,
            1
        );

        uint256[] memory randomWords = new uint256[](1);
        randomWords[0] = 12345;

        vm.prank(newFulfiller);
        vrfCoordinator.fulfillRandomWords(requestId, randomWords);
        assertTrue(vrfCoordinator.isFulfilled(requestId));
    }

    function test_DeauthorizeFulfiller_GivenOwner() public {
        address[] memory fulfillers = new address[](1);
        fulfillers[0] = fulfiller;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = false;
        
        vm.prank(owner);
        vrfCoordinator.setAuthorizedFulfillers(fulfillers, isAuthorized);
        
        assertFalse(vrfCoordinator.isAuthorizedFulfiller(fulfiller));
        
        // Should fail now
        vm.prank(requester);
        uint256 requestId = vrfCoordinator.requestRandomWords(
            keccak256("test"),
            1,
            3,
            100000,
            1
        );

        uint256[] memory randomWords = new uint256[](1);
        randomWords[0] = 12345;

        vm.prank(fulfiller);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotFulfiller.selector, fulfiller));
        vrfCoordinator.fulfillRandomWords(requestId, randomWords);
    }
}
