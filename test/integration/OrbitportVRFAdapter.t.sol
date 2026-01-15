// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportVRFAdapter} from "../../src/OrbitportVRFAdapter.sol";
import {OrbitportBeaconManager} from "../../src/OrbitportBeaconManager.sol";
import {IOrbitportVRFAdapter} from "../../src/interfaces/IOrbitportVRFAdapter.sol";
import {IOrbitportBeaconManager} from "../../src/interfaces/IOrbitportBeaconManager.sol";
import {IEOFeedVerifier} from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import {IPauserRegistry} from "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {InvalidAddress, RequestNotFound, CallerIsNotRetriever, CallerIsNotFulfiller} from "../../src/interfaces/Errors.sol";

// Import mocks
import {MockEOFeedVerifier} from "../mocks/MockEOFeedVerifier.sol";
import {MockPauserRegistry} from "../mocks/MockPauserRegistry.sol";

contract OrbitportVRFAdapterIntegrationTest is Test {
    OrbitportBeaconManager public beaconManager;
    OrbitportVRFAdapter public vrfAdapter;
    MockEOFeedVerifier public verifier;
    MockPauserRegistry public pauserRegistry;
    address public owner;
    address public publisher;
    address public beaconDeployer;
    address public requester;
    address public retriever;
    address public fulfiller;

    uint256 public constant BEACON_ID = 1;
    uint256 public constant SEQUENCE = 12345;
    uint256 public constant TIMESTAMP = 1704067200;
    uint256[] public ctrngValues;

    function setUp() public {
        owner = address(0x1);
        publisher = address(0x5);
        beaconDeployer = address(0x4);
        requester = address(0x7);
        retriever = address(0x8);
        fulfiller = address(0x9);

        verifier = new MockEOFeedVerifier();
        pauserRegistry = new MockPauserRegistry(address(0x3));

        vm.startPrank(owner);
        beaconManager = new OrbitportBeaconManager();

        bytes memory initData = abi.encodeWithSelector(
            OrbitportBeaconManager.initialize.selector,
            address(verifier),
            owner,
            address(pauserRegistry),
            beaconDeployer
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(beaconManager), initData);
        beaconManager = OrbitportBeaconManager(payable(address(proxy)));

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
        beaconManager.whitelistPublishers(publishers, isWhitelisted);

        // Set supported beacon
        uint256[] memory beaconIds = new uint256[](1);
        beaconIds[0] = BEACON_ID;
        bool[] memory supported = new bool[](1);
        supported[0] = true;
        beaconManager.setSupportedBeacons(beaconIds, supported);

        // Authorize VRF adapter to call beacon manager
        address[] memory authorizedCallers = new address[](1);
        authorizedCallers[0] = address(0); // Will be set after adapter deployment
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;

        // Update beacon with data
        bytes memory inputData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);

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
        beaconManager.updateBeacon(input, vParams);

        // Create VRF adapter
        vm.prank(owner);
        vrfAdapter = new OrbitportVRFAdapter(address(beaconManager), BEACON_ID);

        // Authorize VRF adapter to call beacon manager
        authorizedCallers[0] = address(vrfAdapter);
        vm.prank(owner);
        beaconManager.setAuthorizedCallers(authorizedCallers, isAuthorized);

        // Authorize retrievers
        address[] memory retrievers = new address[](1);
        retrievers[0] = retriever;
        vm.prank(owner);
        vrfAdapter.setAuthorizedRetrievers(retrievers, isAuthorized);

        // Authorize fulfillers
        address[] memory fulfillers = new address[](1);
        fulfillers[0] = fulfiller;
        vm.prank(owner);
        vrfAdapter.setAuthorizedFulfillers(fulfillers, isAuthorized);
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

    function test_GetInstantRandomness_WithRetriever() public {
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
}
