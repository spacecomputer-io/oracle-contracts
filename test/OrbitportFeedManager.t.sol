// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportFeedManager} from "../src/OrbitportFeedManager.sol";
import {IOrbitportFeedManager} from "../src/interfaces/IOrbitportFeedManager.sol";
import {IEOFeedVerifier} from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import {IPauserRegistry} from "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import {
    InvalidAddress,
    CallerIsNotWhitelisted,
    FeedNotSupported,
    CallerIsNotPauser,
    CallerIsNotUnpauser,
    CallerIsNotFeedDeployer,
    SequenceNotFound
} from "../src/interfaces/Errors.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";

/// @title MockEOFeedVerifier
/// @notice Mock implementation of EOFeedVerifier for testing
contract MockEOFeedVerifier is IEOFeedVerifier {
    mapping(bytes32 => bytes) public verifiedData;

    function setVerifiedData(bytes memory input, bytes memory output) external {
        verifiedData[keccak256(input)] = output;
    }

    function verify(
        LeafInput calldata input,
        VerificationParams calldata
    ) external view override returns (bytes memory) {
        bytes memory data = verifiedData[keccak256(input.unhashedLeaf)];
        require(data.length > 0, "Data not found");
        return data;
    }

    function batchVerify(
        LeafInput[] calldata inputs,
        VerificationParams calldata
    ) external view override returns (bytes[] memory) {
        bytes[] memory results = new bytes[](inputs.length);
        for (uint256 i = 0; i < inputs.length; i++) {
            bytes memory data = verifiedData[keccak256(inputs[i].unhashedLeaf)];
            require(data.length > 0, "Data not found");
            results[i] = data;
        }
        return results;
    }
}

/// @title MockPauserRegistry
/// @notice Mock implementation of PauserRegistry for testing
contract MockPauserRegistry is IPauserRegistry {
    mapping(address => bool) public pausers;
    address public unpauserAddress;

    constructor(address _unpauser) {
        unpauserAddress = _unpauser;
    }

    function setPauser(address pauser, bool isPauserAccount) external {
        pausers[pauser] = isPauserAccount;
    }

    function isPauser(address account) external view override returns (bool) {
        return pausers[account];
    }

    function unpauser() external view override returns (address) {
        return unpauserAddress;
    }
}

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

    function test_RevertWhen_NotRetriever_GetLatestCTRNGFeed() public {
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

    function test_RevertWhen_NotRetriever_GetCTRNGFeedBySequence() public {
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

    function test_RevertWhen_NotRetriever_IsWhitelistedPublisher() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                user,
                RETRIEVER_ROLE
            )
        );
        feedManager.isWhitelistedPublisher(publisher);
    }

    function test_RevertWhen_NotRetriever_IsSupportedFeed() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                user,
                RETRIEVER_ROLE
            )
        );
        feedManager.isSupportedFeed(FEED_ID);
    }
    
    function test_RevertWhen_NotRetriever_GetFeedVerifier() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                user,
                RETRIEVER_ROLE
            )
        );
        feedManager.getFeedVerifier();
    }
    
    function test_RevertWhen_NotRetriever_GetFeedDeployer() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                user,
                RETRIEVER_ROLE
            )
        );
        feedManager.getFeedDeployer();
    }
    
    function test_RevertWhen_NotRetriever_GetLatestSequence() public {
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

    function test_GrantRetrieverRole() public {
        address newRetriever = address(0x99);
        
        vm.prank(owner);
        feedManager.grantRole(RETRIEVER_ROLE, newRetriever);
        
        assertTrue(feedManager.hasRole(RETRIEVER_ROLE, newRetriever));
        
        // Should be able to call now
        vm.prank(newRetriever);
        feedManager.isSupportedFeed(FEED_ID);
    }

    /* ============ Functionality Tests (with role) ============ */

    function test_Initialize() public {
        vm.startPrank(retriever);
        assertEq(address(feedManager.getFeedVerifier()), address(verifier));
        assertEq(feedManager.getFeedDeployer(), feedDeployer);
        assertTrue(feedManager.isSupportedFeed(FEED_ID));
        assertTrue(feedManager.isWhitelistedPublisher(publisher));
        vm.stopPrank();
        
        assertEq(feedManager.owner(), owner);
    }

    function test_UpdateFeed() public {
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

    function test_GetCTRNGFeedBySequence() public {
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