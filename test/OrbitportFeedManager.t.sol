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

        IOrbitportFeedManager.CTRNGData memory data = feedManager.getLatestCTRNGFeed(FEED_ID);
        assertEq(data.sequence, SEQUENCE);
        assertEq(data.timestamp, TIMESTAMP);
        assertEq(data.ctrng.length, ctrngValues.length);
        assertEq(data.ctrng[0], ctrngValues[0]);
    }

    function test_UpdateFeed_NotWhitelisted() public {
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

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotWhitelisted.selector, user));
        feedManager.updateFeed(input, vParams);
    }

    function test_UpdateFeed_UnsupportedFeed() public {
        bytes memory inputData = abi.encode(999, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(999, SEQUENCE, TIMESTAMP, ctrngValues);
        
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
        vm.expectRevert(abi.encodeWithSelector(FeedNotSupported.selector, 999));
        feedManager.updateFeed(input, vParams);
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
        IOrbitportFeedManager.CTRNGData memory data = feedManager.getCTRNGFeedBySequence(FEED_ID, SEQUENCE);
        assertEq(data.sequence, SEQUENCE);
        assertEq(data.timestamp, TIMESTAMP);
    }

    function test_Pause() public {
        vm.prank(pauser);
        feedManager.pause();

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

    function test_UpdateFeed_NewSequence() public {
        // First update feed with initial sequence
        bytes memory inputData1 = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData1 = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input1 = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData1,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams1 = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData1, verifiedData1);

        vm.prank(publisher);
        feedManager.updateFeed(input1, vParams1);

        // Verify initial sequence
        assertEq(feedManager.getLatestSequence(FEED_ID), SEQUENCE);
        IOrbitportFeedManager.CTRNGData memory data1 = feedManager.getCTRNGFeedBySequence(FEED_ID, SEQUENCE);
        assertEq(data1.sequence, SEQUENCE);
        assertEq(data1.ctrng[0], ctrngValues[0]);

        // Update feed with new sequence and different data
        uint256 newSequence = SEQUENCE + 1;
        uint256 newTimestamp = TIMESTAMP + 100;
        uint256[] memory newCtrngValues = new uint256[](3);
        newCtrngValues[0] = 100;
        newCtrngValues[1] = 200;
        newCtrngValues[2] = 300;

        bytes memory inputData2 = abi.encode(FEED_ID, newSequence, newTimestamp, newCtrngValues);
        bytes memory verifiedData2 = abi.encode(FEED_ID, newSequence, newTimestamp, newCtrngValues);
        
        IEOFeedVerifier.LeafInput memory input2 = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData2,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams2 = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number + 1),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData2, verifiedData2);

        vm.prank(publisher);
        feedManager.updateFeed(input2, vParams2);

        // Verify latest sequence is updated
        assertEq(feedManager.getLatestSequence(FEED_ID), newSequence);

        // Verify getLatestCTRNGFeed returns the new sequence data
        IOrbitportFeedManager.CTRNGData memory latestData = feedManager.getLatestCTRNGFeed(FEED_ID);
        assertEq(latestData.sequence, newSequence);
        assertEq(latestData.timestamp, newTimestamp);
        assertEq(latestData.ctrng.length, newCtrngValues.length);
        assertEq(latestData.ctrng[0], newCtrngValues[0]);
        assertEq(latestData.ctrng[1], newCtrngValues[1]);
        assertEq(latestData.ctrng[2], newCtrngValues[2]);

        // Verify getCTRNGFeedBySequence works for the new sequence
        IOrbitportFeedManager.CTRNGData memory data2 = feedManager.getCTRNGFeedBySequence(FEED_ID, newSequence);
        assertEq(data2.sequence, newSequence);
        assertEq(data2.timestamp, newTimestamp);
        assertEq(data2.ctrng.length, newCtrngValues.length);
        assertEq(data2.ctrng[0], newCtrngValues[0]);

        // Verify getCTRNGFeedBySequence still works for the old sequence
        IOrbitportFeedManager.CTRNGData memory oldData = feedManager.getCTRNGFeedBySequence(FEED_ID, SEQUENCE);
        assertEq(oldData.sequence, SEQUENCE);
        assertEq(oldData.timestamp, TIMESTAMP);
        assertEq(oldData.ctrng.length, ctrngValues.length);
        assertEq(oldData.ctrng[0], ctrngValues[0]);
    }

    function test_UpdateFeed_OlderSequence_NoUpdate() public {
        // First update feed with initial sequence
        bytes memory inputData1 = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData1 = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input1 = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData1,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams1 = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData1, verifiedData1);

        vm.prank(publisher);
        feedManager.updateFeed(input1, vParams1);

        // Update feed with newer sequence
        uint256 newSequence = SEQUENCE + 10;
        uint256 newTimestamp = TIMESTAMP + 100;
        uint256[] memory newCtrngValues = new uint256[](3);
        newCtrngValues[0] = 100;
        newCtrngValues[1] = 200;
        newCtrngValues[2] = 300;

        bytes memory inputData2 = abi.encode(FEED_ID, newSequence, newTimestamp, newCtrngValues);
        bytes memory verifiedData2 = abi.encode(FEED_ID, newSequence, newTimestamp, newCtrngValues);
        
        IEOFeedVerifier.LeafInput memory input2 = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData2,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams2 = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number + 1),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData2, verifiedData2);

        vm.prank(publisher);
        feedManager.updateFeed(input2, vParams2);

        // Verify latest sequence is the new one
        assertEq(feedManager.getLatestSequence(FEED_ID), newSequence);
        IOrbitportFeedManager.CTRNGData memory latestData = feedManager.getLatestCTRNGFeed(FEED_ID);
        assertEq(latestData.sequence, newSequence);
        assertEq(latestData.ctrng[0], newCtrngValues[0]);

        // Now try to update with an older sequence (between initial and new)
        uint256 olderSequence = SEQUENCE + 5; // Older than newSequence but newer than SEQUENCE
        uint256 olderTimestamp = TIMESTAMP + 50;
        uint256[] memory olderCtrngValues = new uint256[](2);
        olderCtrngValues[0] = 999;
        olderCtrngValues[1] = 888;

        bytes memory inputData3 = abi.encode(FEED_ID, olderSequence, olderTimestamp, olderCtrngValues);
        bytes memory verifiedData3 = abi.encode(FEED_ID, olderSequence, olderTimestamp, olderCtrngValues);
        
        IEOFeedVerifier.LeafInput memory input3 = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData3,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams3 = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number + 2),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData3, verifiedData3);

        vm.prank(publisher);
        feedManager.updateFeed(input3, vParams3);

        // Verify that nothing changed - latest sequence should still be newSequence
        assertEq(feedManager.getLatestSequence(FEED_ID), newSequence);
        
        // Verify latest feed data is unchanged
        IOrbitportFeedManager.CTRNGData memory unchangedData = feedManager.getLatestCTRNGFeed(FEED_ID);
        assertEq(unchangedData.sequence, newSequence);
        assertEq(unchangedData.timestamp, newTimestamp);
        assertEq(unchangedData.ctrng[0], newCtrngValues[0]);
        assertEq(unchangedData.ctrng.length, newCtrngValues.length);

        // Verify that the older sequence data was NOT stored
        // Since olderSequence (SEQUENCE + 5) is between SEQUENCE and newSequence,
        // and we never stored it (because it's older than the latest), 
        // getCTRNGFeedBySequence should revert with SequenceNotFound
        vm.expectRevert(abi.encodeWithSelector(SequenceNotFound.selector, olderSequence));
        feedManager.getCTRNGFeedBySequence(FEED_ID, olderSequence);
    }

    function test_UpdateFeed_SameSequence_NoUpdate() public {
        // First update feed with initial sequence
        bytes memory inputData1 = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData1 = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        
        IEOFeedVerifier.LeafInput memory input1 = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData1,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams1 = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData1, verifiedData1);

        vm.prank(publisher);
        feedManager.updateFeed(input1, vParams1);

        // Verify initial sequence
        assertEq(feedManager.getLatestSequence(FEED_ID), SEQUENCE);

        // Try to update with the same sequence but different data
        uint256[] memory differentCtrngValues = new uint256[](2);
        differentCtrngValues[0] = 999;
        differentCtrngValues[1] = 888;

        bytes memory inputData2 = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP + 50, differentCtrngValues);
        bytes memory verifiedData2 = abi.encode(FEED_ID, SEQUENCE, TIMESTAMP + 50, differentCtrngValues);
        
        IEOFeedVerifier.LeafInput memory input2 = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData2,
            proof: new bytes32[](0)
        });
        IEOFeedVerifier.VerificationParams memory vParams2 = IEOFeedVerifier.VerificationParams({
            blockNumber: uint64(block.number + 1),
            chainId: uint32(1),
            aggregator: address(1),
            eventRoot: bytes32(0),
            blockHash: bytes32(0),
            signature: [uint256(0), uint256(0)],
            apkG2: [uint256(0), uint256(0), uint256(0), uint256(0)],
            nonSignersBitmap: bytes("0")
        });

        verifier.setVerifiedData(inputData2, verifiedData2);

        vm.prank(publisher);
        feedManager.updateFeed(input2, vParams2);

        // Verify that nothing changed - latest sequence should still be SEQUENCE
        assertEq(feedManager.getLatestSequence(FEED_ID), SEQUENCE);
        
        // Verify latest feed data is unchanged (still has original ctrngValues)
        IOrbitportFeedManager.CTRNGData memory unchangedData = feedManager.getLatestCTRNGFeed(FEED_ID);
        assertEq(unchangedData.sequence, SEQUENCE);
        assertEq(unchangedData.timestamp, TIMESTAMP); // Should still be original timestamp
        assertEq(unchangedData.ctrng.length, ctrngValues.length);
        assertEq(unchangedData.ctrng[0], ctrngValues[0]); // Should still be original value, not 999
    }
}

