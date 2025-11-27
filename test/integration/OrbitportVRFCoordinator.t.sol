// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportVRFCoordinator} from "../../src/OrbitportVRFCoordinator.sol";
import {OrbitportFeedAdapter} from "../../src/adapters/OrbitportFeedAdapter.sol";
import {OrbitportFeedManager} from "../../src/OrbitportFeedManager.sol";
import {IOrbitportVRFCoordinator} from "../../src/interfaces/IOrbitportVRFCoordinator.sol";
import {IOrbitportFeedManager} from "../../src/interfaces/IOrbitportFeedManager.sol";
import {IEOFeedVerifier} from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import {IPauserRegistry} from "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {InvalidAddress, RequestNotFound} from "../../src/interfaces/Errors.sol";
import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";

// Import mocks
import {MockEOFeedVerifier} from "../mocks/MockEOFeedVerifier.sol";
import {MockPauserRegistry} from "../mocks/MockPauserRegistry.sol";

contract OrbitportVRFCoordinatorIntegrationTest is Test {
    OrbitportFeedManager public feedManager;
    OrbitportFeedAdapter public adapter;
    OrbitportVRFCoordinator public vrfCoordinator;
    MockEOFeedVerifier public verifier;
    MockPauserRegistry public pauserRegistry;
    address public owner;
    address public publisher;
    address public feedDeployer;
    address public requester;
    address public retriever;

    uint256 public constant FEED_ID = 1;
    uint256 public constant SEQUENCE = 12345;
    uint256 public constant TIMESTAMP = 1704067200;
    uint256[] public ctrngValues;
    bytes32 public constant RETRIEVER_ROLE = keccak256("RETRIEVER_ROLE");

    function setUp() public {
        owner = address(0x1);
        publisher = address(0x5);
        feedDeployer = address(0x4);
        requester = address(0x7);
        retriever = address(0x8);

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
        vm.prank(owner);
        adapter = new OrbitportFeedAdapter(address(feedManager), FEED_ID);

        // Create VRF coordinator
        vm.prank(owner);
        vrfCoordinator = new OrbitportVRFCoordinator(address(adapter));
        
        // Grant RETRIEVER_ROLE to the adapter for the coordinator to call it
        vm.prank(owner);
        adapter.grantRole(RETRIEVER_ROLE, address(vrfCoordinator));
        
        // Grant RETRIEVER_ROLE to the manager for the adapter to call it
        vm.prank(owner);
        feedManager.grantRole(RETRIEVER_ROLE, address(adapter));

        // Grant RETRIEVER_ROLE to retriever
        vm.prank(owner);
        vrfCoordinator.grantRole(RETRIEVER_ROLE, retriever);
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

    function test_GetInstantRandomness_WithRetrieverRole() public {
        uint32 numWords = 2;
        
        vm.prank(retriever);
        (uint256 requestId, uint256[] memory randomWords) = vrfCoordinator.getInstantRandomness(numWords);
        
        assertGt(requestId, 0);
        assertEq(randomWords.length, numWords);
        assertTrue(vrfCoordinator.isFulfilled(requestId));
    }

    function test_GrantRetrieverRole_GivenAdmin() public {
        address newRetriever = address(0x99);
        
        vm.prank(owner);
        vrfCoordinator.grantRole(RETRIEVER_ROLE, newRetriever);
        
        assertTrue(vrfCoordinator.hasRole(RETRIEVER_ROLE, newRetriever));
        
        // Should be able to call now
        vm.prank(newRetriever);
        vrfCoordinator.getInstantRandomness(1);
    }

    function test_RevokeRetrieverRole_GivenAdmin() public {
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
