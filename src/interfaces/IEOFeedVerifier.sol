// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @title IEOFeedVerifier
/// @notice Interface for EO Feed Verifier contract
interface IEOFeedVerifier {
    /// @notice Leaf input structure for verification
    struct LeafInput {
        bytes data;
        // Add other fields as needed based on EOFeedVerifier implementation
    }

    /// @notice Verification parameters
    struct VerificationParams {
        uint256 blockNumber;
        bytes[] proof;
        bytes32 root;
        // Add other fields as needed based on EOFeedVerifier implementation
    }

    /// @notice Verify a single leaf input
    /// @param input Leaf input to verify
    /// @param vParams Verification parameters
    /// @return bytes Verified data
    function verify(
        LeafInput calldata input,
        VerificationParams calldata vParams
    ) external view returns (bytes memory);

    /// @notice Batch verify multiple leaf inputs
    /// @param inputs Array of leaf inputs to verify
    /// @param vParams Verification parameters
    /// @return bytes[] Array of verified data
    function batchVerify(
        LeafInput[] calldata inputs,
        VerificationParams calldata vParams
    ) external view returns (bytes[] memory);
}

