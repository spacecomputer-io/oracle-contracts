// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportFeedAdapter} from "../../src/adapters/OrbitportFeedAdapter.sol";
import {IOrbitportFeedManager} from "../../src/interfaces/IOrbitportFeedManager.sol";
import {MockOrbitportFeedManager} from "../mocks/MockOrbitportFeedManager.sol";
import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";

contract OrbitportFeedAdapterTest is Test {
    MockOrbitportFeedManager public mockFeedManager;
    OrbitportFeedAdapter public adapter;
    address public owner;
    address public retriever;
    address public unauthorized;

    uint256 public constant FEED_ID = 1;
    uint256 public constant SEQUENCE = 12345;
    uint256 public constant TIMESTAMP = 1704067200;
    uint256[] public ctrngValues;
    bytes32 public constant RETRIEVER_ROLE = keccak256("RETRIEVER_ROLE");

    function setUp() public {
        owner = address(0x1);
        retriever = address(0x8);
        unauthorized = address(0x9);

        mockFeedManager = new MockOrbitportFeedManager();
        
        vm.prank(owner);
        adapter = new OrbitportFeedAdapter(address(mockFeedManager), FEED_ID);
        
        // Grant RETRIEVER_ROLE to retriever
        vm.prank(owner);
        adapter.grantRole(RETRIEVER_ROLE, retriever);
        
        // Setup mock data
        ctrngValues = new uint256[](5);
        ctrngValues[0] = 10;
        ctrngValues[1] = 20;
        ctrngValues[2] = 30;
        ctrngValues[3] = 40;
        ctrngValues[4] = 50;
        
        IOrbitportFeedManager.CTRNGData memory data = IOrbitportFeedManager.CTRNGData({
            sequence: SEQUENCE,
            timestamp: TIMESTAMP,
            ctrng: ctrngValues,
            blockNumber: block.number
        });
        
        mockFeedManager.setLatestCTRNGFeed(FEED_ID, data);
        mockFeedManager.setCTRNGFeedBySequence(FEED_ID, SEQUENCE, data);
    }

    /* ============ Access Control Tests ============ */

    function test_RevertWhen_CallerIsNotRetriever_LatestRoundData() public {
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

    function test_RevertWhen_CallerIsNotRetriever_GetRoundData() public {
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

    function test_RevertWhen_CallerIsNotRetriever_GetLatestCTRNGData() public {
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

    function test_RevertWhen_CallerIsNotRetriever_GetCTRNGDataByRound() public {
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

    /* ============ Functionality Tests ============ */

    function test_LatestRoundData_GivenRetriever() public {
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

    function test_GetRoundData_GivenRetriever_AndValidRoundId() public {
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

    function test_GetRoundData_GivenRetriever_AndRoundIdZero() public {
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
    
    function test_GetLatestCTRNGData_GivenRetriever() public {
        vm.prank(retriever);
        uint256[] memory ctrng = adapter.getLatestCTRNGData();
        
        assertEq(ctrng.length, ctrngValues.length);
        assertEq(ctrng[0], ctrngValues[0]);
    }

    function test_GetCTRNGDataByRound_GivenRetriever() public {
        vm.prank(retriever);
        uint256[] memory ctrng = adapter.getCTRNGDataByRound(uint80(SEQUENCE));
        
        assertEq(ctrng.length, ctrngValues.length);
        assertEq(ctrng[0], ctrngValues[0]);
    }

    /* ============ View Functions ============ */

    function test_Decimals() public view {
        assertEq(adapter.decimals(), 0);
    }

    function test_Description() public view {
        assertEq(keccak256(bytes(adapter.description())), keccak256(bytes("CTRNG Feed")));
    }

    function test_Version() public view {
        assertEq(adapter.version(), 1);
    }
    
    function test_GrantRole_GivenAdmin() public {
        address newRetriever = address(0x99);
        
        vm.prank(owner);
        adapter.grantRole(RETRIEVER_ROLE, newRetriever);
        
        assertTrue(adapter.hasRole(RETRIEVER_ROLE, newRetriever));
        
        // Should be able to call now
        vm.prank(newRetriever);
        adapter.latestRoundData();
    }
}
