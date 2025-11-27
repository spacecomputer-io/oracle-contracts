// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportVRFCoordinator} from "../../src/OrbitportVRFCoordinator.sol";
import {IOrbitportVRFCoordinator} from "../../src/interfaces/IOrbitportVRFCoordinator.sol";
import {MockOrbitportFeedAdapter} from "../mocks/MockOrbitportFeedAdapter.sol";
import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";

contract OrbitportVRFCoordinatorTest is Test {
    MockOrbitportFeedAdapter public mockAdapter;
    OrbitportVRFCoordinator public vrfCoordinator;
    address public owner;
    address public requester;
    address public retriever;

    uint256[] public ctrngValues;
    bytes32 public constant RETRIEVER_ROLE = keccak256("RETRIEVER_ROLE");

    function setUp() public {
        owner = address(0x1);
        requester = address(0x7);
        retriever = address(0x8);

        mockAdapter = new MockOrbitportFeedAdapter();
        
        vm.prank(owner);
        vrfCoordinator = new OrbitportVRFCoordinator(address(mockAdapter));
        
        // Grant RETRIEVER_ROLE to retriever
        vm.prank(owner);
        vrfCoordinator.grantRole(RETRIEVER_ROLE, retriever);
        
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
}
