// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportFeedManager} from "../../src/OrbitportFeedManager.sol";
import {IOrbitportFeedManager} from "../../src/interfaces/IOrbitportFeedManager.sol";
import {IEOFeedVerifier} from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";
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
    bytes32 public constant RETRIEVER_ROLE = keccak256("RETRIEVER_ROLE");

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
        
        // Grant RETRIEVER_ROLE to retriever
        feedManager.grantRole(RETRIEVER_ROLE, retriever);

        vm.stopPrank();
    }

    /* ============ Access Control Tests ============ */

    function test_RevertWhen_CallerIsNotRetriever_GetLatestCTRNGFeed() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                user,
                RETRIEVER_ROLE
            )
        );
        feedManager.getLatestCTRNGFeed(FEED_ID);
    }

    function test_RevertWhen_CallerIsNotRetriever_GetCTRNGFeedBySequence() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                user,
                RETRIEVER_ROLE
            )
        );
        feedManager.getCTRNGFeedBySequence(FEED_ID, SEQUENCE);
    }

    function test_RevertWhen_CallerIsNotRetriever_GetLatestSequence() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                user,
                RETRIEVER_ROLE
            )
        );
        feedManager.getLatestSequence(FEED_ID);
    }

    function test_GrantRole_Retriever() public {
        address newRetriever = address(0x99);
        
        vm.prank(owner);
        feedManager.grantRole(RETRIEVER_ROLE, newRetriever);
        
        assertTrue(feedManager.hasRole(RETRIEVER_ROLE, newRetriever));
        
        // Should be able to call now
        vm.prank(newRetriever);
        feedManager.isSupportedFeed(FEED_ID);
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
}
