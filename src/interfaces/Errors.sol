// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @notice Thrown when an invalid address is provided
error InvalidAddress();

/// @notice Thrown when the caller is not whitelisted
error CallerIsNotWhitelisted(address caller);

/// @notice Thrown when leaf inputs are missing
error MissingLeafInputs();

/// @notice Thrown when feed ID is not supported
error FeedNotSupported(uint256 feedId);

/// @notice Thrown when input is invalid
error InvalidInput();

/// @notice Thrown when caller is not a pauser
error CallerIsNotPauser();

/// @notice Thrown when caller is not an unpauser
error CallerIsNotUnpauser();

/// @notice Thrown when caller is not the feed deployer
error CallerIsNotFeedDeployer();

/// @notice Thrown when sequence is not found
error SequenceNotFound(uint256 sequence);

/// @notice Thrown when request ID is not found
error RequestNotFound(uint256 requestId);

