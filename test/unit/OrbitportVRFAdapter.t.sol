// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportVRFAdapter} from "../../src/OrbitportVRFAdapter.sol";
import {IOrbitportVRFAdapter} from "../../src/interfaces/IOrbitportVRFAdapter.sol";
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

contract OrbitportVRFAdapterTest is Test {
    MockOrbitportFeedManager public mockFeedManager;
    OrbitportVRFAdapter public vrfAdapter;
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
        vrfAdapter = new OrbitportVRFAdapter(address(mockFeedManager), BEACON_ID);

        // Authorize retrievers
        address[] memory retrievers = new address[](1);
        retrievers[0] = retriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        vm.prank(owner);
        vrfAdapter.setAuthorizedRetrievers(retrievers, isAuthorized);

        // Authorize fulfillers
        address[] memory fulfillers = new address[](1);
        fulfillers[0] = fulfiller;
        vm.prank(owner);
        vrfAdapter.setAuthorizedFulfillers(fulfillers, isAuthorized);

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
        uint256 requestId = vrfAdapter.requestRandomWords(
            keyHash,
            subId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );

        assertEq(requestId, 1);

        IOrbitportVRFAdapter.RandomWordsRequest memory request = vrfAdapter.getRequest(requestId);
        assertEq(request.requester, requester);
        assertEq(request.numWords, numWords);

        // Request should not be fulfilled yet (async like Chainlink)
        assertFalse(vrfAdapter.isFulfilled(requestId));
    }

    /* ============ Access Control Tests ============ */

    function test_RevertWhen_CallerIsNotRetriever_GetInstantRandomness() public {
        uint32 numWords = 1;

        vm.prank(requester);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, requester));
        vrfAdapter.getInstantRandomness(numWords);
    }

    function test_GetInstantRandomness_GivenRetriever() public {
        uint32 numWords = 2;

        vm.prank(retriever);
        (uint256 requestId, uint256[] memory randomWords) = vrfAdapter.getInstantRandomness(numWords);

        assertGt(requestId, 0);
        assertEq(randomWords.length, numWords);
        assertTrue(vrfAdapter.isFulfilled(requestId));
    }

    function test_AuthorizeRetriever_GivenOwner() public {
        address newRetriever = address(0x99);

        address[] memory retrievers = new address[](1);
        retrievers[0] = newRetriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;

        vm.prank(owner);
        vrfAdapter.setAuthorizedRetrievers(retrievers, isAuthorized);

        assertTrue(vrfAdapter.isAuthorizedRetriever(newRetriever));

        // Should be able to call now
        vm.prank(newRetriever);
        vrfAdapter.getInstantRandomness(1);
    }

    function test_DeauthorizeRetriever_GivenOwner() public {
        address[] memory retrievers = new address[](1);
        retrievers[0] = retriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = false;

        vm.prank(owner);
        vrfAdapter.setAuthorizedRetrievers(retrievers, isAuthorized);

        assertFalse(vrfAdapter.isAuthorizedRetriever(retriever));

        // Should fail now
        vm.prank(retriever);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, retriever));
        vrfAdapter.getInstantRandomness(1);
    }

    function test_RevertWhen_CallerIsNotOwner_AuthorizeRetriever() public {
        address newRetriever = address(0x99);

        address[] memory retrievers = new address[](1);
        retrievers[0] = newRetriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;

        vm.prank(requester);
        vm.expectRevert();
        vrfAdapter.setAuthorizedRetrievers(retrievers, isAuthorized);
    }

    /* ============ Uniqueness Tests ============ */

    function test_GetInstantRandomness_GivenRetriever_ReturnsUniqueValues() public {
        uint32 numWords = 5;

        vm.prank(retriever);
        (, uint256[] memory randomWords) = vrfAdapter.getInstantRandomness(numWords);

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
        (, uint256[] memory words1) = vrfAdapter.getInstantRandomness(numWords);

        // Same block/time, same requester, same everything except internal nonce/counter
        vm.prank(retriever);
        (, uint256[] memory words2) = vrfAdapter.getInstantRandomness(numWords);

        assertNotEq(words1[0], words2[0]);
    }

    function test_GetInstantRandomness_GivenLargeNumWords() public {
        uint32 numWords = 20;

        vm.prank(retriever);
        (, uint256[] memory randomWords) = vrfAdapter.getInstantRandomness(numWords);

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
        uint256 requestId = vrfAdapter.requestRandomWords(
            keyHash,
            subId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );

        assertFalse(vrfAdapter.isFulfilled(requestId));

        // Fulfill the request
        uint256[] memory randomWords = new uint256[](numWords);
        randomWords[0] = 12345;
        randomWords[1] = 67890;

        vm.prank(fulfiller);
        vrfAdapter.fulfillRandomWords(requestId, randomWords);

        assertTrue(vrfAdapter.isFulfilled(requestId));
        uint256[] memory fulfilledWords = vrfAdapter.getFulfilledRandomWords(requestId);
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
        uint256 requestId = vrfAdapter.requestRandomWords(
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
        vrfAdapter.fulfillRandomWords(requestId, randomWords);
    }

    function test_RevertWhen_RequestNotFound_FulfillRandomWords() public {
        uint256[] memory randomWords = new uint256[](2);
        randomWords[0] = 12345;
        randomWords[1] = 67890;

        vm.prank(fulfiller);
        vm.expectRevert(abi.encodeWithSelector(RequestNotFound.selector, 999));
        vrfAdapter.fulfillRandomWords(999, randomWords);
    }

    function test_RevertWhen_AlreadyFulfilled_FulfillRandomWords() public {
        bytes32 keyHash = keccak256("test");
        uint64 subId = 1;
        uint16 requestConfirmations = 3;
        uint32 callbackGasLimit = 100000;
        uint32 numWords = 2;

        // Request random words
        vm.prank(requester);
        uint256 requestId = vrfAdapter.requestRandomWords(
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
        vrfAdapter.fulfillRandomWords(requestId, randomWords);

        // Try to fulfill again
        vm.prank(fulfiller);
        vm.expectRevert(abi.encodeWithSelector(RequestNotFound.selector, requestId));
        vrfAdapter.fulfillRandomWords(requestId, randomWords);
    }

    function test_AuthorizeFulfiller_GivenOwner() public {
        address newFulfiller = address(0x99);

        address[] memory fulfillers = new address[](1);
        fulfillers[0] = newFulfiller;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;

        vm.prank(owner);
        vrfAdapter.setAuthorizedFulfillers(fulfillers, isAuthorized);

        assertTrue(vrfAdapter.isAuthorizedFulfiller(newFulfiller));

        // Should be able to fulfill now
        vm.prank(requester);
        uint256 requestId = vrfAdapter.requestRandomWords(
            keccak256("test"),
            1,
            3,
            100000,
            1
        );

        uint256[] memory randomWords = new uint256[](1);
        randomWords[0] = 12345;

        vm.prank(newFulfiller);
        vrfAdapter.fulfillRandomWords(requestId, randomWords);
        assertTrue(vrfAdapter.isFulfilled(requestId));
    }

    function test_DeauthorizeFulfiller_GivenOwner() public {
        address[] memory fulfillers = new address[](1);
        fulfillers[0] = fulfiller;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = false;

        vm.prank(owner);
        vrfAdapter.setAuthorizedFulfillers(fulfillers, isAuthorized);

        assertFalse(vrfAdapter.isAuthorizedFulfiller(fulfiller));

        // Should fail now
        vm.prank(requester);
        uint256 requestId = vrfAdapter.requestRandomWords(
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
        vrfAdapter.fulfillRandomWords(requestId, randomWords);
    }

    /* ============ Constructor Tests ============ */

    function test_RevertWhen_BeaconManagerIsZero_Constructor() public {
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        new OrbitportVRFAdapter(address(0), BEACON_ID);
    }

    function test_Constructor_GivenValidParams() public {
        MockOrbitportFeedManager newManager = new MockOrbitportFeedManager();
        vm.prank(owner);
        OrbitportVRFAdapter newAdapter = new OrbitportVRFAdapter(address(newManager), BEACON_ID);

        assertEq(newAdapter.getBeaconManager(), address(newManager));
        assertEq(newAdapter.getBeaconId(), BEACON_ID);
    }

    /* ============ setBeaconManager Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetBeaconManager() public {
        MockOrbitportFeedManager newManager = new MockOrbitportFeedManager();
        vm.prank(requester);
        vm.expectRevert();
        vrfAdapter.setBeaconManager(address(newManager));
    }

    function test_RevertWhen_BeaconManagerIsZero_SetBeaconManager() public {
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        vrfAdapter.setBeaconManager(address(0));
    }

    function test_SetBeaconManager_GivenOwner() public {
        MockOrbitportFeedManager newManager = new MockOrbitportFeedManager();
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit OrbitportVRFAdapter.BeaconManagerSet(address(newManager));
        vrfAdapter.setBeaconManager(address(newManager));

        assertEq(vrfAdapter.getBeaconManager(), address(newManager));
    }

    /* ============ setBeaconId Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetBeaconId() public {
        vm.prank(requester);
        vm.expectRevert();
        vrfAdapter.setBeaconId(2);
    }

    function test_SetBeaconId_GivenOwner() public {
        uint256 newBeaconId = 2;
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit OrbitportVRFAdapter.BeaconIdSet(newBeaconId);
        vrfAdapter.setBeaconId(newBeaconId);

        assertEq(vrfAdapter.getBeaconId(), newBeaconId);
    }

    /* ============ setMaxCTRNGAge Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetMaxCTRNGAge() public {
        vm.prank(requester);
        vm.expectRevert();
        vrfAdapter.setMaxCTRNGAge(7200);
    }

    function test_SetMaxCTRNGAge_GivenOwner() public {
        uint256 newMaxAge = 7200;
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit OrbitportVRFAdapter.MaxCTRNGAgeSet(newMaxAge);
        vrfAdapter.setMaxCTRNGAge(newMaxAge);

        assertEq(vrfAdapter.getMaxCTRNGAge(), newMaxAge);
    }

    /* ============ getMaxCTRNGAge Tests ============ */

    function test_GetMaxCTRNGAge() public {
        uint256 maxAge = vrfAdapter.getMaxCTRNGAge();
        assertEq(maxAge, 3600); // Default value
    }

    /* ============ getBeaconManager Tests ============ */

    function test_GetBeaconManager() public {
        assertEq(vrfAdapter.getBeaconManager(), address(mockFeedManager));
    }

    /* ============ getBeaconId Tests ============ */

    function test_GetBeaconId() public {
        assertEq(vrfAdapter.getBeaconId(), BEACON_ID);
    }

    /* ============ getLatestCTRNGData Tests ============ */

    function test_RevertWhen_CallerIsNotRetriever_GetLatestCTRNGData() public {
        vm.prank(requester);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, requester));
        vrfAdapter.getLatestCTRNGData();
    }

    function test_GetLatestCTRNGData_GivenRetriever() public {
        vm.prank(retriever);
        uint256[] memory data = vrfAdapter.getLatestCTRNGData();
        assertEq(data.length, ctrngValues.length);
        assertEq(data[0], ctrngValues[0]);
    }

    /* ============ getCTRNGDataByRound Tests ============ */

    function test_RevertWhen_CallerIsNotRetriever_GetCTRNGDataByRound() public {
        vm.prank(requester);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, requester));
        vrfAdapter.getCTRNGDataByRound(0);
    }

    function test_GetCTRNGDataByRound_WhenRoundIdIsZero() public {
        vm.prank(retriever);
        uint256[] memory data = vrfAdapter.getCTRNGDataByRound(0);
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
        uint256[] memory data = vrfAdapter.getCTRNGDataByRound(roundId);
        assertEq(data.length, ctrngValues.length);
        assertEq(data[0], ctrngValues[0]);
    }

    /* ============ getRequest Tests ============ */

    function test_RevertWhen_RequestNotFound_GetRequest() public {
        vm.expectRevert(abi.encodeWithSelector(RequestNotFound.selector, 999));
        vrfAdapter.getRequest(999);
    }

    function test_GetRequest_GivenExistingRequest() public {
        bytes32 keyHash = keccak256("test");
        uint64 subId = 1;
        uint16 requestConfirmations = 3;
        uint32 callbackGasLimit = 100000;
        uint32 numWords = 2;

        vm.prank(requester);
        uint256 requestId = vrfAdapter.requestRandomWords(
            keyHash,
            subId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );

        IOrbitportVRFAdapter.RandomWordsRequest memory request = vrfAdapter.getRequest(requestId);
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
        uint256 requestId = vrfAdapter.requestRandomWords(
            keyHash,
            subId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );

        vm.expectRevert(abi.encodeWithSelector(RequestNotFound.selector, requestId));
        vrfAdapter.getFulfilledRandomWords(requestId);
    }

    function test_GetFulfilledRandomWords_GivenFulfilledRequest() public {
        bytes32 keyHash = keccak256("test");
        uint64 subId = 1;
        uint16 requestConfirmations = 3;
        uint32 callbackGasLimit = 100000;
        uint32 numWords = 2;

        vm.prank(requester);
        uint256 requestId = vrfAdapter.requestRandomWords(
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
        vrfAdapter.fulfillRandomWords(requestId, randomWords);

        uint256[] memory fulfilledWords = vrfAdapter.getFulfilledRandomWords(requestId);
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
        vrfAdapter.setAuthorizedRetrievers(retrievers, isAuthorized);
    }

    function test_RevertWhen_RetrieverIsZero_SetAuthorizedRetrievers() public {
        address[] memory retrievers = new address[](1);
        retrievers[0] = address(0);
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;

        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        vrfAdapter.setAuthorizedRetrievers(retrievers, isAuthorized);
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
        vrfAdapter.setAuthorizedFulfillers(fulfillers, isAuthorized);
    }

    function test_RevertWhen_FulfillerIsZero_SetAuthorizedFulfillers() public {
        address[] memory fulfillers = new address[](1);
        fulfillers[0] = address(0);
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;

        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        vrfAdapter.setAuthorizedFulfillers(fulfillers, isAuthorized);
    }

    /* ============ fulfillRandomWords Tests ============ */

    function test_RevertWhen_RandomWordsLengthMismatch_FulfillRandomWords() public {
        bytes32 keyHash = keccak256("test");
        uint64 subId = 1;
        uint16 requestConfirmations = 3;
        uint32 callbackGasLimit = 100000;
        uint32 numWords = 2;

        vm.prank(requester);
        uint256 requestId = vrfAdapter.requestRandomWords(
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
        vrfAdapter.fulfillRandomWords(requestId, randomWords);
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
        vrfAdapter.getInstantRandomness(1);
    }
}
