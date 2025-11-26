// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportFeedAdapter} from "../src/adapters/OrbitportFeedAdapter.sol";
import {OrbitportFeedManager} from "../src/OrbitportFeedManager.sol";
import {IOrbitportFeedManager} from "../src/interfaces/IOrbitportFeedManager.sol";
import {IEOFeedVerifier} from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import {IPauserRegistry} from "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {InvalidAddress} from "../src/interfaces/Errors.sol";
import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";

// Import mocks from FeedManager test
import {MockEOFeedVerifier} from "./OrbitportFeedManager.t.sol";
import {MockPauserRegistry} from "./OrbitportFeedManager.t.sol";

contract OrbitportFeedAdapterTest is Test {
    OrbitportFeedManager public feedManager;
    OrbitportFeedAdapter public adapter;
    MockEOFeedVerifier public verifier;
    MockPauserRegistry public pauserRegistry;
    address public owner;
    address public publisher;
    address public feedDeployer;
    address public retriever;
    address public unauthorized;

    uint256 public constant FEED_ID = 1;
    uint256 public constant SEQUENCE = 12345;
    uint256 public constant TIMESTAMP = 1704067200;
    uint256[] public ctrngValues;
    bytes32 public constant RETRIEVER_ROLE = keccak256("RETRIEVER_ROLE");

    function setUp() public {
        owner = address(0x1);
        publisher = address(0x5);
        feedDeployer = address(0x4);
        retriever = address(0x8);
        unauthorized = address(0x9);

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
        
        // Grant RETRIEVER_ROLE to retriever
        vm.prank(owner);
        adapter.grantRole(RETRIEVER_ROLE, retriever);
        
        // Grant RETRIEVER_ROLE to manager for adapter
        vm.prank(owner);
        feedManager.grantRole(RETRIEVER_ROLE, address(adapter));
    }

    /* ============ Access Control Tests ============ */

    function test_RevertWhen_NotRetriever_LatestRoundData() public {
        vm.prank(unauthorized);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorized,
                RETRIEVER_ROLE
            )
        );
        adapter.latestRoundData();
    }

    function test_RevertWhen_NotRetriever_GetRoundData() public {
        vm.prank(unauthorized);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorized,
                RETRIEVER_ROLE
            )
        );
        adapter.getRoundData(uint80(SEQUENCE));
    }

    function test_RevertWhen_NotRetriever_GetLatestCTRNGData() public {
        vm.prank(unauthorized);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorized,
                RETRIEVER_ROLE
            )
        );
        adapter.getLatestCTRNGData();
    }

    function test_RevertWhen_NotRetriever_GetCTRNGDataByRound() public {
        vm.prank(unauthorized);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorized,
                RETRIEVER_ROLE
            )
        );
        adapter.getCTRNGDataByRound(uint80(SEQUENCE));
    }

    /* ============ Functionality Tests (with role) ============ */

    function test_LatestRoundData_WithRetrieverRole() public {
        vm.prank(retriever);
        (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = adapter.latestRoundData();

        assertEq(roundId, SEQUENCE);
        assertGt(answer, 0);
        assertEq(startedAt, TIMESTAMP);
        assertEq(updatedAt, TIMESTAMP);
        assertEq(answeredInRound, SEQUENCE);
    }

    function test_GetRoundData_WithRetrieverRole() public {
        vm.prank(retriever);
        (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = adapter.getRoundData(uint80(SEQUENCE));

        assertEq(roundId, SEQUENCE);
        assertGt(answer, 0);
        assertEq(startedAt, TIMESTAMP);
        assertEq(updatedAt, TIMESTAMP);
        assertEq(answeredInRound, SEQUENCE);
    }

    function test_GetRoundData_Zero_WithRetrieverRole() public {
        // When roundId is 0, should return latest round data
        vm.prank(retriever);
        (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = adapter.getRoundData(0);

        assertEq(roundId, SEQUENCE);
        assertGt(answer, 0);
        assertEq(startedAt, TIMESTAMP);
        assertEq(updatedAt, TIMESTAMP);
        assertEq(answeredInRound, SEQUENCE);
    }
    
    function test_GetLatestCTRNGData_WithRetrieverRole() public {
        vm.prank(retriever);
        uint256[] memory ctrng = adapter.getLatestCTRNGData();
        
        assertEq(ctrng.length, ctrngValues.length);
        assertEq(ctrng[0], ctrngValues[0]);
    }

    function test_GetCTRNGDataByRound_WithRetrieverRole() public {
        vm.prank(retriever);
        uint256[] memory ctrng = adapter.getCTRNGDataByRound(uint80(SEQUENCE));
        
        assertEq(ctrng.length, ctrngValues.length);
        assertEq(ctrng[0], ctrngValues[0]);
    }

    /* ============ View Functions (Unrestricted) ============ */

    function test_Decimals() public view {
        assertEq(adapter.decimals(), 0);
    }

    function test_Description() public view {
        assertEq(keccak256(bytes(adapter.description())), keccak256(bytes("CTRNG Feed")));
    }

    function test_Version() public view {
        assertEq(adapter.version(), 1);
    }
    
    function test_GrantRetrieverRole() public {
        address newRetriever = address(0x99);
        
        vm.prank(owner);
        adapter.grantRole(RETRIEVER_ROLE, newRetriever);
        
        assertTrue(adapter.hasRole(RETRIEVER_ROLE, newRetriever));
        
        // Should be able to call now
        vm.prank(newRetriever);
        adapter.latestRoundData();
    }
}