# Orbitport Oracle

Orbitport Oracle provides secure and verifiable data feeds and randomness for the SpaceComputer ecosystem. It leverages eoracle's architecture to bring real-world data and randomness on-chain.

## Overview

The system consists of three primary smart contracts:

### OrbitportFeedManager

The `OrbitportFeedManager` is the core contract responsible for receiving and verifying feed updates. It:

- Verifies updates using `EOFeedVerifier` (or compatible verifier).
- Stores the latest and historical feed data (CTRNG values).
- Manages access control for publishers and retrievers.
- Supports multiple feed IDs.

### OrbitportFeedAdapter

The `OrbitportFeedAdapter` acts as a standard interface (Chainlink-compatible) for consuming data from the FeedManager. It:

- Connects to a specific Feed ID in the FeedManager.
- Provides standard `latestRoundData` and `getRoundData` functions.
- Exposes raw CTRNG data for specialized consumers.

### OrbitportVRFCoordinator

The `OrbitportVRFCoordinator` provides Verifiable Random Function (VRF) capabilities using the CTRNG data from the adapter. It:

- Allows users to request random words.
- Provides `getInstantRandomness` for immediate random values derived from the secure feed.
- Ensures uniqueness and non-predictability of served randomness.

## Repository Structure

```
├── src/
│   ├── adapters/          # Feed adapters
│   ├── interfaces/        # Interfaces
│   ├── OrbitportFeedManager.sol
│   └── OrbitportVRFCoordinator.sol
├── test/
│   ├── unit/              # Unit tests with mocks
│   │   ├── OrbitportFeedManager.t.sol
│   │   ├── OrbitportFeedManager.tree
│   │   └── ...
│   ├── integration/       # Integration tests with real contracts
│   │   ├── OrbitportFeedAdapter.t.sol
│   │   └── ...
│   └── mocks/             # Test mocks
```

## Usage

This is a list of the most frequently needed commands.

### Build

Build the contracts:

```sh
forge build
```

### Test

Run the unit tests:

```sh
forge test
```

Run only unit tests:

```sh
forge test --match-path "test/unit/*"
```

Run only integration tests:

```sh
forge test --match-path "test/integration/*"
```

### Coverage

Get a test coverage report:

```sh
forge coverage
```

## License

This project is licensed under MIT.
