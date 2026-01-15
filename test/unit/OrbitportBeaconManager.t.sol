// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {OrbitportBeaconManager} from "../../src/OrbitportBeaconManager.sol";
import {IOrbitportBeaconManager} from "../../src/interfaces/IOrbitportBeaconManager.sol";
import {IEOFeedVerifier} from "target-contracts/src/interfaces/IEOFeedVerifier.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {
    CallerIsNotRetriever,
    InvalidAddress,
    CallerIsNotWhitelisted,
    MissingLeafInputs,
    BeaconNotSupported,
    InvalidInput,
    CallerIsNotPauser,
    CallerIsNotUnpauser,
    CallerIsNotBeaconDeployer,
    SequenceNotFound
} from "../../src/interfaces/Errors.sol";
import {MockEOFeedVerifier} from "../mocks/MockEOFeedVerifier.sol";
import {MockPauserRegistry} from "../mocks/MockPauserRegistry.sol";

contract OrbitportBeaconManagerTest is Test {
    OrbitportBeaconManager public beaconManager;
    MockEOFeedVerifier public verifier;
    MockPauserRegistry public pauserRegistry;
    address public owner;
    address public pauser;
    address public unpauser;
    address public beaconDeployer;
    address public publisher;
    address public user;
    address public retriever;

    uint256 public constant BEACON_ID = 1;
    uint256 public constant SEQUENCE = 12345;
    uint256 public constant TIMESTAMP = 1704067200;
    uint256[] public ctrngValues;

    function setUp() public {
        owner = address(0x1);
        pauser = address(0x2);
        unpauser = address(0x3);
        beaconDeployer = address(0x4);
        publisher = address(0x5);
        user = address(0x6);
        retriever = address(0x7);

        verifier = new MockEOFeedVerifier();
        pauserRegistry = new MockPauserRegistry(unpauser);
        pauserRegistry.setPauser(pauser, true);

        vm.startPrank(owner);
        beaconManager = new OrbitportBeaconManager();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            OrbitportBeaconManager.initialize.selector,
            address(verifier),
            owner,
            address(pauserRegistry),
            beaconDeployer
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(beaconManager), initData);
        beaconManager = OrbitportBeaconManager(payable(address(proxy)));

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
        beaconManager.whitelistPublishers(publishers, isWhitelisted);

        // Set supported beacon
        uint256[] memory beaconIds = new uint256[](1);
        beaconIds[0] = BEACON_ID;
        bool[] memory supported = new bool[](1);
        supported[0] = true;
        beaconManager.setSupportedBeacons(beaconIds, supported);

        // Authorize retriever
        address[] memory authorizedCallers = new address[](1);
        authorizedCallers[0] = retriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;
        beaconManager.setAuthorizedCallers(authorizedCallers, isAuthorized);

        vm.stopPrank();
    }

    /* ============ Access Control Tests ============ */

    function test_RevertWhen_CallerIsNotAuthorized_GetLatestCTRNGBeacon() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, user));
        beaconManager.getLatestCTRNGBeacon(BEACON_ID);
    }

    function test_RevertWhen_CallerIsNotAuthorized_GetCTRNGBeaconBySequence() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, user));
        beaconManager.getCTRNGBeaconBySequence(BEACON_ID, SEQUENCE);
    }

    function test_RevertWhen_CallerIsNotAuthorized_GetLatestSequence() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, user));
        beaconManager.getLatestSequence(BEACON_ID);
    }

    function test_AuthorizeCaller_GivenOwner() public {
        address newRetriever = address(0x99);

        // First, publish some data so we can test retrieval
        bytes memory inputData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);

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
        beaconManager.updateBeacon(input, vParams);

        // Now authorize the new retriever
        address[] memory authorizedCallers = new address[](1);
        authorizedCallers[0] = newRetriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;

        vm.prank(owner);
        beaconManager.setAuthorizedCallers(authorizedCallers, isAuthorized);

        assertTrue(beaconManager.isAuthorizedCaller(newRetriever));

        // Should be able to call now
        vm.prank(newRetriever);
        IOrbitportBeaconManager.CTRNGData memory data = beaconManager.getLatestCTRNGBeacon(BEACON_ID);
        assertEq(data.sequence, SEQUENCE);
    }

    function test_DeauthorizeCaller_GivenOwner() public {
        address[] memory authorizedCallers = new address[](1);
        authorizedCallers[0] = retriever;
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = false;

        vm.prank(owner);
        beaconManager.setAuthorizedCallers(authorizedCallers, isAuthorized);

        assertFalse(beaconManager.isAuthorizedCaller(retriever));

        // Should fail now
        vm.prank(retriever);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotRetriever.selector, retriever));
        beaconManager.getLatestCTRNGBeacon(BEACON_ID);
    }

    /* ============ Functionality Tests ============ */

    function test_Initialize_GivenAdmin() public {
        // No longer needs retriever role for these view functions
        vm.startPrank(user);
        assertEq(address(beaconManager.getFeedVerifier()), address(verifier));
        assertEq(beaconManager.getBeaconDeployer(), beaconDeployer);
        assertTrue(beaconManager.isSupportedBeacon(BEACON_ID));
        assertTrue(beaconManager.isWhitelistedPublisher(publisher));
        vm.stopPrank();

        assertEq(beaconManager.owner(), owner);
    }

    function test_UpdateBeacon_GivenPublisher() public {
        bytes memory inputData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);

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
        beaconManager.updateBeacon(input, vParams);

        vm.prank(retriever);
        IOrbitportBeaconManager.CTRNGData memory data = beaconManager.getLatestCTRNGBeacon(BEACON_ID);
        assertEq(data.sequence, SEQUENCE);
        assertEq(data.timestamp, TIMESTAMP);
        assertEq(data.ctrng.length, ctrngValues.length);
        assertEq(data.ctrng[0], ctrngValues[0]);
    }

    function test_GetCTRNGBeaconBySequence_GivenExistingSequence() public {
        // First update beacon
        bytes memory inputData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);

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
        beaconManager.updateBeacon(input, vParams);

        // Get by sequence
        vm.prank(retriever);
        IOrbitportBeaconManager.CTRNGData memory data = beaconManager.getCTRNGBeaconBySequence(BEACON_ID, SEQUENCE);
        assertEq(data.sequence, SEQUENCE);
        assertEq(data.timestamp, TIMESTAMP);
    }

    /* ============ Constructor Tests ============ */

    function test_Constructor_DisablesInitializers() public {
        OrbitportBeaconManager newManager = new OrbitportBeaconManager();

        bytes memory initData = abi.encodeWithSelector(
            OrbitportBeaconManager.initialize.selector,
            address(verifier),
            owner,
            address(pauserRegistry),
            beaconDeployer
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(newManager), initData);
        OrbitportBeaconManager proxiedManager = OrbitportBeaconManager(payable(address(proxy)));

        // Try to initialize again - should revert
        vm.expectRevert();
        proxiedManager.initialize(address(verifier), owner, address(pauserRegistry), beaconDeployer);
    }

    /* ============ Initialize Tests ============ */

    function test_RevertWhen_FeedVerifierIsZero_Initialize() public {
        OrbitportBeaconManager newManager = new OrbitportBeaconManager();
        bytes memory initData = abi.encodeWithSelector(
            OrbitportBeaconManager.initialize.selector,
            address(0),
            owner,
            address(pauserRegistry),
            beaconDeployer
        );

        // Proxy construction should revert because initialize will revert
        vm.expectRevert(InvalidAddress.selector);
        new ERC1967Proxy(address(newManager), initData);
    }

    function test_RevertWhen_PauserRegistryIsZero_Initialize() public {
        OrbitportBeaconManager newManager = new OrbitportBeaconManager();
        bytes memory initData = abi.encodeWithSelector(
            OrbitportBeaconManager.initialize.selector,
            address(verifier),
            owner,
            address(0),
            beaconDeployer
        );

        // Proxy construction should revert because initialize will revert
        vm.expectRevert(InvalidAddress.selector);
        new ERC1967Proxy(address(newManager), initData);
    }

    function test_RevertWhen_BeaconDeployerIsZero_Initialize() public {
        OrbitportBeaconManager newManager = new OrbitportBeaconManager();
        bytes memory initData = abi.encodeWithSelector(
            OrbitportBeaconManager.initialize.selector,
            address(verifier),
            owner,
            address(pauserRegistry),
            address(0)
        );

        // Proxy construction should revert because initialize will revert
        vm.expectRevert(InvalidAddress.selector);
        new ERC1967Proxy(address(newManager), initData);
    }

    /* ============ setFeedVerifier Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetFeedVerifier() public {
        address newVerifier = address(0x99);
        vm.prank(user);
        vm.expectRevert();
        beaconManager.setFeedVerifier(newVerifier);
    }

    function test_RevertWhen_FeedVerifierIsZero_SetFeedVerifier() public {
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        beaconManager.setFeedVerifier(address(0));
    }

    function test_SetFeedVerifier_GivenOwner() public {
        address newVerifier = address(0x99);
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportBeaconManager.FeedVerifierSet(newVerifier);
        beaconManager.setFeedVerifier(newVerifier);

        assertEq(address(beaconManager.getFeedVerifier()), newVerifier);
    }

    /* ============ setBeaconDeployer Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetBeaconDeployer() public {
        address newDeployer = address(0x99);
        vm.prank(user);
        vm.expectRevert();
        beaconManager.setBeaconDeployer(newDeployer);
    }

    function test_RevertWhen_BeaconDeployerIsZero_SetBeaconDeployer() public {
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        beaconManager.setBeaconDeployer(address(0));
    }

    function test_SetBeaconDeployer_GivenOwner() public {
        address newDeployer = address(0x99);
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportBeaconManager.BeaconDeployerSet(newDeployer);
        beaconManager.setBeaconDeployer(newDeployer);

        assertEq(beaconManager.getBeaconDeployer(), newDeployer);
    }

    /* ============ setSupportedBeacons Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetSupportedBeacons() public {
        uint256[] memory beaconIds = new uint256[](1);
        beaconIds[0] = 2;
        bool[] memory supported = new bool[](1);
        supported[0] = true;

        vm.prank(user);
        vm.expectRevert();
        beaconManager.setSupportedBeacons(beaconIds, supported);
    }

    function test_RevertWhen_ArrayLengthMismatch_SetSupportedBeacons() public {
        uint256[] memory beaconIds = new uint256[](2);
        beaconIds[0] = 2;
        beaconIds[1] = 3;
        bool[] memory supported = new bool[](1);
        supported[0] = true;

        vm.prank(owner);
        vm.expectRevert(InvalidInput.selector);
        beaconManager.setSupportedBeacons(beaconIds, supported);
    }

    function test_SetSupportedBeacons_GivenOwner() public {
        uint256[] memory beaconIds = new uint256[](2);
        beaconIds[0] = 2;
        beaconIds[1] = 3;
        bool[] memory supported = new bool[](2);
        supported[0] = true;
        supported[1] = false;

        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportBeaconManager.SupportedBeaconsUpdated(beaconIds[0], true);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportBeaconManager.SupportedBeaconsUpdated(beaconIds[1], false);
        beaconManager.setSupportedBeacons(beaconIds, supported);

        assertTrue(beaconManager.isSupportedBeacon(beaconIds[0]));
        assertFalse(beaconManager.isSupportedBeacon(beaconIds[1]));
    }

    /* ============ addSupportedBeacons Tests ============ */

    function test_RevertWhen_CallerIsNotBeaconDeployer_AddSupportedBeacons() public {
        uint256[] memory beaconIds = new uint256[](1);
        beaconIds[0] = 2;

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotBeaconDeployer.selector));
        beaconManager.addSupportedBeacons(beaconIds);
    }

    function test_AddSupportedBeacons_GivenBeaconDeployer() public {
        uint256[] memory beaconIds = new uint256[](2);
        beaconIds[0] = 2;
        beaconIds[1] = 3;

        vm.prank(beaconDeployer);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportBeaconManager.SupportedBeaconsUpdated(beaconIds[0], true);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportBeaconManager.SupportedBeaconsUpdated(beaconIds[1], true);
        beaconManager.addSupportedBeacons(beaconIds);

        assertTrue(beaconManager.isSupportedBeacon(beaconIds[0]));
        assertTrue(beaconManager.isSupportedBeacon(beaconIds[1]));
    }

    /* ============ whitelistPublishers Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_WhitelistPublishers() public {
        address[] memory publishers = new address[](1);
        publishers[0] = address(0x99);
        bool[] memory isWhitelisted = new bool[](1);
        isWhitelisted[0] = true;

        vm.prank(user);
        vm.expectRevert();
        beaconManager.whitelistPublishers(publishers, isWhitelisted);
    }

    function test_RevertWhen_ArrayLengthMismatch_WhitelistPublishers() public {
        address[] memory publishers = new address[](2);
        publishers[0] = address(0x99);
        publishers[1] = address(0x98);
        bool[] memory isWhitelisted = new bool[](1);
        isWhitelisted[0] = true;

        vm.prank(owner);
        vm.expectRevert(InvalidInput.selector);
        beaconManager.whitelistPublishers(publishers, isWhitelisted);
    }

    function test_RevertWhen_PublisherIsZero_WhitelistPublishers() public {
        address[] memory publishers = new address[](1);
        publishers[0] = address(0);
        bool[] memory isWhitelisted = new bool[](1);
        isWhitelisted[0] = true;

        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        beaconManager.whitelistPublishers(publishers, isWhitelisted);
    }

    function test_WhitelistPublishers_GivenOwner() public {
        address newPublisher = address(0x99);
        address[] memory publishers = new address[](1);
        publishers[0] = newPublisher;
        bool[] memory isWhitelisted = new bool[](1);
        isWhitelisted[0] = true;

        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportBeaconManager.PublisherWhitelisted(newPublisher, true);
        beaconManager.whitelistPublishers(publishers, isWhitelisted);

        assertTrue(beaconManager.isWhitelistedPublisher(newPublisher));
    }

    /* ============ setAuthorizedCallers Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetAuthorizedCallers() public {
        address[] memory callers = new address[](1);
        callers[0] = address(0x99);
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;

        vm.prank(user);
        vm.expectRevert();
        beaconManager.setAuthorizedCallers(callers, isAuthorized);
    }

    function test_RevertWhen_ArrayLengthMismatch_SetAuthorizedCallers() public {
        address[] memory callers = new address[](2);
        callers[0] = address(0x99);
        callers[1] = address(0x98);
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;

        vm.prank(owner);
        vm.expectRevert(InvalidInput.selector);
        beaconManager.setAuthorizedCallers(callers, isAuthorized);
    }

    function test_RevertWhen_CallerIsZero_SetAuthorizedCallers() public {
        address[] memory callers = new address[](1);
        callers[0] = address(0);
        bool[] memory isAuthorized = new bool[](1);
        isAuthorized[0] = true;

        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        beaconManager.setAuthorizedCallers(callers, isAuthorized);
    }

    /* ============ updateBeacon Tests ============ */

    function test_RevertWhen_CallerIsNotWhitelisted_UpdateBeacon() public {
        bytes memory inputData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);

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
        beaconManager.updateBeacon(input, vParams);
    }

    function test_RevertWhen_ContractIsPaused_UpdateBeacon() public {
        bytes memory inputData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);

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

        // Pause the contract
        vm.prank(pauser);
        beaconManager.pause();

        vm.prank(publisher);
        vm.expectRevert();
        beaconManager.updateBeacon(input, vParams);
    }

    function test_RevertWhen_BeaconNotSupported_UpdateBeacon() public {
        uint256 unsupportedBeaconId = 999;
        bytes memory inputData = abi.encode(unsupportedBeaconId, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(unsupportedBeaconId, SEQUENCE, TIMESTAMP, ctrngValues);

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
        vm.expectRevert(abi.encodeWithSelector(BeaconNotSupported.selector, unsupportedBeaconId));
        beaconManager.updateBeacon(input, vParams);
    }

    function test_UpdateBeacon_SkipsWhenSequenceNotGreater() public {
        bytes memory inputData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory verifiedData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);

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
        beaconManager.updateBeacon(input, vParams);

        // Try to update with same sequence - should skip
        vm.prank(publisher);
        beaconManager.updateBeacon(input, vParams);

        // Verify only one update occurred
        vm.prank(retriever);
        IOrbitportBeaconManager.CTRNGData memory data = beaconManager.getLatestCTRNGBeacon(BEACON_ID);
        assertEq(data.sequence, SEQUENCE);
    }

    /* ============ updateBeacons Tests ============ */

    function test_RevertWhen_CallerIsNotWhitelisted_UpdateBeacons() public {
        IEOFeedVerifier.LeafInput[] memory inputs = new IEOFeedVerifier.LeafInput[](1);
        bytes memory inputData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        inputs[0] = IEOFeedVerifier.LeafInput({
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

        verifier.setVerifiedData(inputData, abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues));
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CallerIsNotWhitelisted.selector, user));
        beaconManager.updateBeacons(inputs, vParams);
    }

    function test_RevertWhen_ContractIsPaused_UpdateBeacons() public {
        IEOFeedVerifier.LeafInput[] memory inputs = new IEOFeedVerifier.LeafInput[](1);
        bytes memory inputData = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        inputs[0] = IEOFeedVerifier.LeafInput({
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

        verifier.setVerifiedData(inputData, abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues));

        // Pause the contract
        vm.prank(pauser);
        beaconManager.pause();

        vm.prank(publisher);
        vm.expectRevert();
        beaconManager.updateBeacons(inputs, vParams);
    }

    function test_RevertWhen_InputsEmpty_UpdateBeacons() public {
        IEOFeedVerifier.LeafInput[] memory inputs = new IEOFeedVerifier.LeafInput[](0);
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

        vm.prank(publisher);
        vm.expectRevert(MissingLeafInputs.selector);
        beaconManager.updateBeacons(inputs, vParams);
    }

    function test_UpdateBeacons_GivenPublisher() public {
        IEOFeedVerifier.LeafInput[] memory inputs = new IEOFeedVerifier.LeafInput[](2);
        bytes memory inputData1 = abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        bytes memory inputData2 = abi.encode(BEACON_ID, SEQUENCE + 1, TIMESTAMP + 1, ctrngValues);

        inputs[0] = IEOFeedVerifier.LeafInput({
            leafIndex: 0,
            unhashedLeaf: inputData1,
            proof: new bytes32[](0)
        });
        inputs[1] = IEOFeedVerifier.LeafInput({
            leafIndex: 1,
            unhashedLeaf: inputData2,
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

        verifier.setVerifiedData(inputData1, abi.encode(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues));
        verifier.setVerifiedData(inputData2, abi.encode(BEACON_ID, SEQUENCE + 1, TIMESTAMP + 1, ctrngValues));

        vm.prank(publisher);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportBeaconManager.CTRNGUpdated(BEACON_ID, SEQUENCE, TIMESTAMP, ctrngValues);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportBeaconManager.CTRNGUpdated(BEACON_ID, SEQUENCE + 1, TIMESTAMP + 1, ctrngValues);
        beaconManager.updateBeacons(inputs, vParams);

        vm.prank(retriever);
        IOrbitportBeaconManager.CTRNGData memory data = beaconManager.getLatestCTRNGBeacon(BEACON_ID);
        assertEq(data.sequence, SEQUENCE + 1);
    }

    /* ============ setPauserRegistry Tests ============ */

    function test_RevertWhen_CallerIsNotOwner_SetPauserRegistry() public {
        MockPauserRegistry newRegistry = new MockPauserRegistry(unpauser);
        vm.prank(user);
        vm.expectRevert();
        beaconManager.setPauserRegistry(address(newRegistry));
    }

    function test_RevertWhen_PauserRegistryIsZero_SetPauserRegistry() public {
        vm.prank(owner);
        vm.expectRevert(InvalidAddress.selector);
        beaconManager.setPauserRegistry(address(0));
    }

    function test_SetPauserRegistry_GivenOwner() public {
        MockPauserRegistry newRegistry = new MockPauserRegistry(unpauser);
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IOrbitportBeaconManager.PauserRegistrySet(address(newRegistry));
        beaconManager.setPauserRegistry(address(newRegistry));
    }

    /* ============ pause Tests ============ */

    function test_RevertWhen_CallerIsNotPauser_Pause() public {
        vm.prank(user);
        vm.expectRevert(CallerIsNotPauser.selector);
        beaconManager.pause();
    }

    function test_Pause_GivenPauser() public {
        vm.prank(pauser);
        beaconManager.pause();

        assertTrue(beaconManager.paused());
    }

    /* ============ unpause Tests ============ */

    function test_RevertWhen_CallerIsNotUnpauser_Unpause() public {
        // First pause
        vm.prank(pauser);
        beaconManager.pause();

        vm.prank(user);
        vm.expectRevert(CallerIsNotUnpauser.selector);
        beaconManager.unpause();
    }

    function test_Unpause_GivenUnpauser() public {
        // First pause
        vm.prank(pauser);
        beaconManager.pause();
        assertTrue(beaconManager.paused());

        vm.prank(unpauser);
        beaconManager.unpause();
        assertFalse(beaconManager.paused());
    }

    /* ============ getLatestCTRNGBeacon Tests ============ */

    function test_RevertWhen_BeaconNotSupported_GetLatestCTRNGBeacon() public {
        uint256 unsupportedBeaconId = 999;
        vm.prank(retriever);
        vm.expectRevert(abi.encodeWithSelector(BeaconNotSupported.selector, unsupportedBeaconId));
        beaconManager.getLatestCTRNGBeacon(unsupportedBeaconId);
    }

    function test_RevertWhen_SequenceIsZero_GetLatestCTRNGBeacon() public {
        // Beacon is supported but no data has been published
        vm.prank(retriever);
        vm.expectRevert(abi.encodeWithSelector(SequenceNotFound.selector, 0));
        beaconManager.getLatestCTRNGBeacon(BEACON_ID);
    }

    /* ============ getCTRNGBeaconBySequence Tests ============ */

    function test_RevertWhen_BeaconNotSupported_GetCTRNGBeaconBySequence() public {
        uint256 unsupportedBeaconId = 999;
        vm.prank(retriever);
        vm.expectRevert(abi.encodeWithSelector(BeaconNotSupported.selector, unsupportedBeaconId));
        beaconManager.getCTRNGBeaconBySequence(unsupportedBeaconId, SEQUENCE);
    }

    function test_RevertWhen_SequenceNotFound_GetCTRNGBeaconBySequence() public {
        uint256 nonExistentSequence = 99999;
        vm.prank(retriever);
        vm.expectRevert(abi.encodeWithSelector(SequenceNotFound.selector, nonExistentSequence));
        beaconManager.getCTRNGBeaconBySequence(BEACON_ID, nonExistentSequence);
    }
}
