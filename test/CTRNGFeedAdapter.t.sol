// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {CTRNGFeedAdapter} from "../src/adapters/CTRNGFeedAdapter.sol";
import {CTRNGFeedManager} from "../src/CTRNGFeedManager.sol";
import {ICTRNGFeedManager} from "../src/interfaces/ICTRNGFeedManager.sol";
import {IEOFeedVerifier} from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import {IPauserRegistry} from "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {InvalidAddress} from "../src/interfaces/Errors.sol";

// Import mocks from FeedManager test
import {MockEOFeedVerifier} from "./CTRNGFeedManager.t.sol";
import {MockPauserRegistry} from "./CTRNGFeedManager.t.sol";

contract CTRNGFeedAdapterTest is Test {
    CTRNGFeedManager public feedManager;
    CTRNGFeedAdapter public adapter;
    MockEOFeedVerifier public verifier;
    MockPauserRegistry public pauserRegistry;
    address public owner;
    address public publisher;
    address public feedDeployer;

    uint256 public constant FEED_ID = 1;
    uint256 public constant SEQUENCE = 12345;
    uint256 public constant TIMESTAMP = 1704067200;
    uint256[] public ctrngValues;

    function setUp() public {
        owner = address(0x1);
        publisher = address(0x5);
        feedDeployer = address(0x4);

        verifier = new MockEOFeedVerifier();
        pauserRegistry = new MockPauserRegistry(address(0x3));

        vm.startPrank(owner);
        feedManager = new CTRNGFeedManager();
        
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
        adapter = new CTRNGFeedAdapter(address(feedManager), FEED_ID);
    }

    function test_LatestRoundData() public {
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

    function test_GetRoundData() public {
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

    function test_GetRoundData_Zero() public {
        // When roundId is 0, should return latest round data
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

    function test_Decimals() public view {
        assertEq(adapter.decimals(), 18);
    }

    function test_Description() public view {
        assertEq(keccak256(bytes(adapter.description())), keccak256(bytes("CTRNG Feed")));
    }

    function test_Version() public view {
        assertEq(adapter.version(), 1);
    }

    function test_SetFeedManager() public {
        address newFeedManager = address(0x123);
        adapter.setFeedManager(newFeedManager);
        assertEq(adapter.getFeedManager(), newFeedManager);
    }

    function test_SetFeedManager_InvalidAddress() public {
        vm.expectRevert(abi.encodeWithSelector(InvalidAddress.selector));
        adapter.setFeedManager(address(0));
    }

    function test_SetFeedId() public {
        adapter.setFeedId(999);
        assertEq(adapter.getFeedId(), 999);
    }
}

