// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {CTRNGFeedManager} from "../src/CTRNGFeedManager.sol";
import {ICTRNGFeedManager} from "../src/interfaces/ICTRNGFeedManager.sol";
import {IEOFeedVerifier} from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import {IPauserRegistry} from "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import {
    InvalidAddress,
    CallerIsNotWhitelisted,
    FeedNotSupported,
    CallerIsNotPauser,
    CallerIsNotUnpauser,
    CallerIsNotFeedDeployer
} from "../src/interfaces/Errors.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

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
        bytes memory data = verifiedData[keccak256(input.data)];
        require(data.length > 0, "Data not found");
        return data;
    }

    function batchVerify(
        LeafInput[] calldata inputs,
        VerificationParams calldata
    ) external view override returns (bytes[] memory) {
        bytes[] memory results = new bytes[](inputs.length);
        for (uint256 i = 0; i < inputs.length; i++) {
            bytes memory data = verifiedData[keccak256(inputs[i].data)];
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

contract CTRNGFeedManagerTest is Test {
    CTRNGFeedManager public feedManager;
    MockEOFeedVerifier public verifier;
    MockPauserRegistry public pauserRegistry;
    address public owner;
    address public pauser;
    address public unpauser;
    address public feedDeployer;
    address public publisher;
    address public user;

    uint256 public constant FEED_ID = 1;
    uint256 public constant SEQUENCE = 12345;
    uint256 public constant TIMESTAMP = 1704067200;
    uint256[] public ctrngValues;

    function setUp() public {
        owner = address(0x1);
        pauser = address(0x2);
        unpauser = address(0x3);
        feedDeployer = address(0x4);
        publisher = address(0x5);
        user = address(0x6);

        verifier = new MockEOFeedVerifier();
        pauserRegistry = new MockPauserRegistry(unpauser);
        pauserRegistry.setPauser(pauser, true);

        vm.startPrank(owner);
        feedManager = new CTRNGFeedManager();
        
        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            CTRNGFeedManager.initialize.selector,
            address(verifier),
            owner,
            address(pauserRegistry),
            feedDeployer
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(feedManager), initData);
        feedManager = CTRNGFeedManager(payable(address(proxy)));

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

        vm.stopPrank();
    }

    function test_Initialize() public {
        assertEq(address(feedManager.getFeedVerifier()), address(verifier));
        assertEq(feedManager.getFeedDeployer(), feedDeployer);
        assertEq(feedManager.owner(), owner);
        assertTrue(feedManager.isSupportedFeed(FEED_ID));
        assertTrue(feedManager.isWhitelistedPublisher(publisher));
    }

    function test_UpdateFeed() public {
        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({data: inputData});
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: block.number,
            proof: new bytes[](0),
            root: bytes32(0)
        });

        verifier.setVerifiedData(inputData, verifiedData);

        vm.prank(publisher);
        feedManager.updateFeed(input, vParams);

        ICTRNGFeedManager.CTRNGData memory data = feedManager.getLatestCTRNGFeed(FEED_ID);
        assertEq(data.sequence, SEQUENCE);
        assertEq(data.timestamp, TIMESTAMP);
        assertEq(data.ctrng.length, ctrngValues.length);
        assertEq(data.ctrng[0], ctrngValues[0]);
    }

    function test_UpdateFeed_NotWhitelisted() public {
        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({data: inputData});
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: block.number,
            proof: new bytes[](0),
            root: bytes32(0)
        });

        verifier.setVerifiedData(inputData, verifiedData);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotWhitelisted.selector, user));
        feedManager.updateFeed(input, vParams);
    }

    function test_UpdateFeed_UnsupportedFeed() public {
        bytes memory inputData = abi.encode(999, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(999, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({data: inputData});
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: block.number,
            proof: new bytes[](0),
            root: bytes32(0)
        });

        verifier.setVerifiedData(inputData, verifiedData);

        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(FeedNotSupported.selector, 999));
        feedManager.updateFeed(input, vParams);
    }

    function test_GetCTRNGFeedBySequence() public {
        // First update feed
        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({data: inputData});
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: block.number,
            proof: new bytes[](0),
            root: bytes32(0)
        });

        verifier.setVerifiedData(inputData, verifiedData);

        vm.prank(publisher);
        feedManager.updateFeed(input, vParams);

        // Get by sequence
        ICTRNGFeedManager.CTRNGData memory data = feedManager.getCTRNGFeedBySequence(FEED_ID, SEQUENCE);
        assertEq(data.sequence, SEQUENCE);
        assertEq(data.timestamp, TIMESTAMP);
    }

    function test_Pause() public {
        vm.prank(pauser);
        feedManager.pause();

        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({data: inputData});
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: block.number,
            proof: new bytes[](0),
            root: bytes32(0)
        });

        verifier.setVerifiedData(inputData, verifiedData);

        vm.prank(publisher);
        vm.expectRevert(); // Pausable: EnforcedPause
        feedManager.updateFeed(input, vParams);
    }

    function test_Unpause() public {
        vm.prank(pauser);
        feedManager.pause();

        vm.prank(unpauser);
        feedManager.unpause();

        // Should work now
        bytes memory inputData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input = IEOFeedVerifier.LeafInput({data: inputData});
        IEOFeedVerifier.VerificationParams memory vParams = IEOFeedVerifier.VerificationParams({
            blockNumber: block.number,
            proof: new bytes[](0),
            root: bytes32(0)
        });

        verifier.setVerifiedData(inputData, verifiedData);

        vm.prank(publisher);
        feedManager.updateFeed(input, vParams);
    }

    function test_AddSupportedFeeds() public {
        uint256[] memory feedIds = new uint256[](2);
        feedIds[0] = 100;
        feedIds[1] = 200;

        vm.prank(feedDeployer);
        feedManager.addSupportedFeeds(feedIds);

        assertTrue(feedManager.isSupportedFeed(100));
        assertTrue(feedManager.isSupportedFeed(200));
    }

    function test_AddSupportedFeeds_NotDeployer() public {
        uint256[] memory feedIds = new uint256[](1);
        feedIds[0] = 100;

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotFeedDeployer.selector));
        feedManager.addSupportedFeeds(feedIds);
    }
}

