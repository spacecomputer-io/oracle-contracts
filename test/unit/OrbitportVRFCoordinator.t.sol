// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportVRFCoordinator} from "../../src/OrbitportVRFCoordinator.sol";
import {IOrbitportVRFCoordinator} from "../../src/interfaces/IOrbitportVRFCoordinator.sol";
import {MockOrbitportFeedAdapter} from "../mocks/MockOrbitportFeedAdapter.sol";
import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {RequestNotFound} from "../../src/interfaces/Errors.sol";

contract OrbitportVRFCoordinatorTest is Test {
    MockOrbitportFeedAdapter public mockAdapter;
    OrbitportVRFCoordinator public vrfCoordinator;
    address public owner;
    address public requester;
    address public retriever;
    address public fulfiller;

    uint256[] public ctrngValues;
    bytes32 public constant RETRIEVER_ROLE = keccak256("RETRIEVER_ROLE");
    bytes32 public constant FULFILLER_ROLE = keccak256("FULFILLER_ROLE");

    function setUp() public {
        owner = address(0x1);
        requester = address(0x7);
        retriever = address(0x8);
        fulfiller = address(0x9);

        mockAdapter = new MockOrbitportFeedAdapter();
        
        vm.prank(owner);
        vrfCoordinator = new OrbitportVRFCoordinator(address(mockAdapter));
        
        // Grant RETRIEVER_ROLE to retriever
        vm.prank(owner);
        vrfCoordinator.grantRole(RETRIEVER_ROLE, retriever);
        
        // Grant FULFILLER_ROLE to fulfiller
        vm.prank(owner);
        vrfCoordinator.grantRole(FULFILLER_ROLE, fulfiller);
        
        // Setup mock data
        ctrngValues = new uint256[](5);
        ctrngValues[0] = 10;
        ctrngValues[1] = 20;
        ctrngValues[2] = 30;
        ctrngValues[3] = 40;
        ctrngValues[4] = 50;
        
        mockAdapter.setLatestCTRNGData(ctrngValues);
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
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                requester,
                RETRIEVER_ROLE
            )
        );
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

    function test_GrantRole_GivenAdmin() public {
        address newRetriever = address(0x99);
        
        vm.prank(owner);
        vrfCoordinator.grantRole(RETRIEVER_ROLE, newRetriever);
        
        assertTrue(vrfCoordinator.hasRole(RETRIEVER_ROLE, newRetriever));
        
        // Should be able to call now
        vm.prank(newRetriever);
        vrfCoordinator.getInstantRandomness(1);
    }

    function test_RevokeRole_GivenAdmin() public {
        vm.prank(owner);
        vrfCoordinator.revokeRole(RETRIEVER_ROLE, retriever);
        
        assertFalse(vrfCoordinator.hasRole(RETRIEVER_ROLE, retriever));
        
        // Should fail now
        vm.prank(retriever);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                retriever,
                RETRIEVER_ROLE
            )
        );
        vrfCoordinator.getInstantRandomness(1);
    }

    function test_RevertWhen_CallerIsNotAdmin_GrantRole() public {
        address newRetriever = address(0x99);
        
        vm.startPrank(requester);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                requester,
                vrfCoordinator.DEFAULT_ADMIN_ROLE()
            )
        );
        vrfCoordinator.grantRole(RETRIEVER_ROLE, newRetriever);
        vm.stopPrank();
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

        // Try to fulfill without FULFILLER_ROLE
        uint256[] memory randomWords = new uint256[](numWords);
        randomWords[0] = 12345;
        randomWords[1] = 67890;

        vm.prank(requester);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                requester,
                FULFILLER_ROLE
            )
        );
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

    function test_GrantFulfillerRole_GivenAdmin() public {
        address newFulfiller = address(0x99);
        
        vm.prank(owner);
        vrfCoordinator.grantRole(FULFILLER_ROLE, newFulfiller);
        
        assertTrue(vrfCoordinator.hasRole(FULFILLER_ROLE, newFulfiller));
        
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

    function test_RevokeFulfillerRole_GivenAdmin() public {
        vm.prank(owner);
        vrfCoordinator.revokeRole(FULFILLER_ROLE, fulfiller);
        
        assertFalse(vrfCoordinator.hasRole(FULFILLER_ROLE, fulfiller));
        
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
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                fulfiller,
                FULFILLER_ROLE
            )
        );
        vrfCoordinator.fulfillRandomWords(requestId, randomWords);
    }
}
