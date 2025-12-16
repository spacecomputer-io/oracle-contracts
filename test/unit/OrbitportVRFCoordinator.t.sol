// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportVRFCoordinator} from "../../src/OrbitportVRFCoordinator.sol";
import {IOrbitportVRFCoordinator} from "../../src/interfaces/IOrbitportVRFCoordinator.sol";
import {IOrbitportFeedManager} from "../../src/interfaces/IOrbitportFeedManager.sol";
import {MockOrbitportFeedManager} from "../mocks/MockOrbitportFeedManager.sol";
import {
    RequestNotFound,
    CallerIsNotRetriever,
    CallerIsNotFulfiller,
    InvalidAddress,
    InvalidInput,
    InvalidRandomWordsLength,
    StaleCTRNGData
} from "../../src/interfaces/Errors.sol";

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

    /* ============ Constructor Tests ============ */

    function test_RevertWhen_BeaconManagerIsZero_Constructor() public {
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        new OrbitportVRFCoordinator(address(0), BEACON_ID);
    }

    function test_Constructor_GivenValidParams() public {
        MockOrbitportFeedManager newManager = new MockOrbitportFeedManager();
        vm.prank(owner);
        OrbitportVRFCoordinator newCoordinator = new OrbitportVRFCoordinator(address(newManager), BEACON_ID);
        
        assertEq(newCoordinator.getBeaconManager(), address(newManager));
        assertEq(newCoordinator.getBeaconId(), BEACON_ID);
    }

    /* ============ setBeaconManager Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetBeaconManager() public {
        MockOrbitportFeedManager newManager = new MockOrbitportFeedManager();
        vm.prank(requester);
        vm.expectRevert();
        vrfCoordinator.setBeaconManager(address(newManager));
    }

    function test_RevertWhen_BeaconManagerIsZero_SetBeaconManager() public {
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        vrfCoordinator.setBeaconManager(address(0));
    }

    function test_SetBeaconManager_GivenOwner() public {
        MockOrbitportFeedManager newManager = new MockOrbitportFeedManager();
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit OrbitportVRFCoordinator.BeaconManagerSet(address(newManager));
        vrfCoordinator.setBeaconManager(address(newManager));
        
        assertEq(vrfCoordinator.getBeaconManager(), address(newManager));
    }

    /* ============ setBeaconId Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetBeaconId() public {
        vm.prank(requester);
        vm.expectRevert();
        vrfCoordinator.setBeaconId(2);
    }

    function test_SetBeaconId_GivenOwner() public {
        uint256 newBeaconId = 2;
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit OrbitportVRFCoordinator.BeaconIdSet(newBeaconId);
        vrfCoordinator.setBeaconId(newBeaconId);
        
        assertEq(vrfCoordinator.getBeaconId(), newBeaconId);
    }

    /* ============ setMaxCTRNGAge Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetMaxCTRNGAge() public {
        vm.prank(requester);
        vm.expectRevert();
        vrfCoordinator.setMaxCTRNGAge(7200);
    }

    function test_SetMaxCTRNGAge_GivenOwner() public {
        uint256 newMaxAge = 7200;
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit OrbitportVRFCoordinator.MaxCTRNGAgeSet(newMaxAge);
        vrfCoordinator.setMaxCTRNGAge(newMaxAge);
        
        assertEq(vrfCoordinator.getMaxCTRNGAge(), newMaxAge);
    }

    /* ============ getMaxCTRNGAge Tests ============ */

    function test_GetMaxCTRNGAge() public {
        uint256 maxAge = vrfCoordinator.getMaxCTRNGAge();
        assertEq(maxAge, 3600); // Default value
    }

    /* ============ getBeaconManager Tests ============ */

    function test_GetBeaconManager() public {
        assertEq(vrfCoordinator.getBeaconManager(), address(mockFeedManager));
    }

    /* ============ getBeaconId Tests ============ */

    function test_GetBeaconId() public {
        assertEq(vrfCoordinator.getBeaconId(), BEACON_ID);
    }

    /* ============ getLatestCTRNGData Tests ============ */

    function test_RevertWhen_CallerIsNotRetriever_GetLatestCTRNGData() public {
        vm.prank(requester);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, requester));
        vrfCoordinator.getLatestCTRNGData();
    }

    function test_GetLatestCTRNGData_GivenRetriever() public {
        vm.prank(retriever);
        uint256[] memory data = vrfCoordinator.getLatestCTRNGData();
        assertEq(data.length, ctrngValues.length);
        assertEq(data[0], ctrngValues[0]);
    }

    /* ============ getCTRNGDataByRound Tests ============ */

    function test_RevertWhen_CallerIsNotRetriever_GetCTRNGDataByRound() public {
        vm.prank(requester);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, requester));
        vrfCoordinator.getCTRNGDataByRound(0);
    }

    function test_GetCTRNGDataByRound_WhenRoundIdIsZero() public {
        vm.prank(retriever);
        uint256[] memory data = vrfCoordinator.getCTRNGDataByRound(0);
        assertEq(data.length, ctrngValues.length);
        assertEq(data[0], ctrngValues[0]);
    }

    function test_GetCTRNGDataByRound_WhenRoundIdGreaterThanZero() public {
        uint80 roundId = 1;
        IOrbitportFeedManager.CTRNGData memory roundData = IOrbitportFeedManager.CTRNGData({
            sequence: uint256(roundId),
            timestamp: block.timestamp,
            ctrng: ctrngValues,
            blockNumber: block.number
        });
        mockFeedManager.setCTRNGFeedBySequence(BEACON_ID, uint256(roundId), roundData);
        
        vm.prank(retriever);
        uint256[] memory data = vrfCoordinator.getCTRNGDataByRound(roundId);
        assertEq(data.length, ctrngValues.length);
        assertEq(data[0], ctrngValues[0]);
    }

    /* ============ getRequest Tests ============ */

    function test_RevertWhen_RequestNotFound_GetRequest() public {
        vm.expectRevert(abi.encodeWithSelector(RequestNotFound.selector, 999));
        vrfCoordinator.getRequest(999);
    }

    function test_GetRequest_GivenExistingRequest() public {
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

        IOrbitportVRFCoordinator.RandomWordsRequest memory request = vrfCoordinator.getRequest(requestId);
        assertEq(request.requester, requester);
        assertEq(request.keyHash, keyHash);
        assertEq(request.subId, subId);
        assertEq(request.numWords, numWords);
    }

    /* ============ getFulfilledRandomWords Tests ============ */

    function test_RevertWhen_RequestNotFulfilled_GetFulfilledRandomWords() public {
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

        vm.expectRevert(abi.encodeWithSelector(RequestNotFound.selector, requestId));
        vrfCoordinator.getFulfilledRandomWords(requestId);
    }

    function test_GetFulfilledRandomWords_GivenFulfilledRequest() public {
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

        uint256[] memory randomWords = new uint256[](numWords);
        randomWords[0] = 12345;
        randomWords[1] = 67890;

        vm.prank(fulfiller);
        vrfCoordinator.fulfillRandomWords(requestId, randomWords);

        uint256[] memory fulfilledWords = vrfCoordinator.getFulfilledRandomWords(requestId);
        assertEq(fulfilledWords.length, numWords);
        assertEq(fulfilledWords[0], randomWords[0]);
        assertEq(fulfilledWords[1], randomWords[1]);
    }

    /* ============ setAuthorizedRetrievers Tests ============ */

    function test_RevertWhen_ArrayLengthMismatch_SetAuthorizedRetrievers() public {
        address[] memory retrievers = new address[](2);
        retrievers[0] = address(0x99);
        retrievers[1] = address(0x98);
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        
        vm.prank(owner);
        vm.expectRevert(InvalidInput.selector);
        vrfCoordinator.setAuthorizedRetrievers(retrievers, isAuthorized);
    }

    function test_RevertWhen_RetrieverIsZero_SetAuthorizedRetrievers() public {
        address[] memory retrievers = new address[](1);
        retrievers[0] = address(0);
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        vrfCoordinator.setAuthorizedRetrievers(retrievers, isAuthorized);
    }

    /* ============ setAuthorizedFulfillers Tests ============ */

    function test_RevertWhen_ArrayLengthMismatch_SetAuthorizedFulfillers() public {
        address[] memory fulfillers = new address[](2);
        fulfillers[0] = address(0x99);
        fulfillers[1] = address(0x98);
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        
        vm.prank(owner);
        vm.expectRevert(InvalidInput.selector);
        vrfCoordinator.setAuthorizedFulfillers(fulfillers, isAuthorized);
    }

    function test_RevertWhen_FulfillerIsZero_SetAuthorizedFulfillers() public {
        address[] memory fulfillers = new address[](1);
        fulfillers[0] = address(0);
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        vrfCoordinator.setAuthorizedFulfillers(fulfillers, isAuthorized);
    }

    /* ============ fulfillRandomWords Tests ============ */

    function test_RevertWhen_RandomWordsLengthMismatch_FulfillRandomWords() public {
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

        // Wrong length
        uint256[] memory randomWords = new uint256[](1);
        randomWords[0] = 12345;

        vm.prank(fulfiller);
        vm.expectRevert(abi.encodeWithSelector(InvalidRandomWordsLength.selector, numWords, 1));
        vrfCoordinator.fulfillRandomWords(requestId, randomWords);
    }

    /* ============ getInstantRandomness Tests ============ */

    function test_RevertWhen_StaleCTRNGData_GetInstantRandomness() public {
        // Set a future timestamp to avoid underflow
        uint256 futureTimestamp = block.timestamp + 10000;
        vm.warp(futureTimestamp);
        
        // Set old timestamp (more than max age of 3600)
        uint256 staleTimestamp = futureTimestamp - 4000;
        IOrbitportFeedManager.CTRNGData memory staleData = IOrbitportFeedManager.CTRNGData({
            sequence: 1,
            timestamp: staleTimestamp,
            ctrng: ctrngValues,
            blockNumber: block.number
        });
        mockFeedManager.setLatestCTRNGFeed(BEACON_ID, staleData);
        
        vm.prank(retriever);
        vm.expectRevert(
            abi.encodeWithSelector(
                StaleCTRNGData.selector,
                staleTimestamp,
                futureTimestamp,
                3600
            )
        );
        vrfCoordinator.getInstantRandomness(1);
    }
}
