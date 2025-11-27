// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IEOFeedVerifier} from "target-contracts/src/interfaces/IEOFeedVerifier.sol";

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

