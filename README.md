# Orbitport Oracle

Orbitport Oracle provides secure and verifiable data feeds and randomness for the SpaceComputer ecosystem. It leverages eoracle's architecture to bring real-world data and randomness on-chain.

## Overview

The system consists of two primary smart contracts:

### OrbitportFeedManager

The `OrbitportFeedManager` is the core contract responsible for receiving and verifying feed updates. It:

- Verifies updates using `EOFeedVerifier` (or compatible verifier).
- Stores the latest and historical feed data (CTRNG values).
- Manages access control for publishers and retrievers.
- Supports multiple feed IDs.
- Upgradeable via ERC1967 proxy pattern.

### OrbitportVRFAdapter

The `OrbitportVRFAdapter` provides Verifiable Random Function (VRF) capabilities using the CTRNG data from the FeedManager. It:

- Allows users to request random words (Chainlink VRF-compatible interface).
- Provides `getInstantRandomness` for immediate random values derived from the secure feed.
- Ensures uniqueness and non-predictability of served randomness.
- Manages authorized retrievers and fulfillers.

## Repository Structure

```
├── src/
│   ├── interfaces/              # Contract interfaces
│   │   ├── IOrbitportFeedManager.sol
│   │   ├── IOrbitportVRFAdapter.sol
│   │   └── Errors.sol
│   ├── OrbitportFeedManager.sol
│   └── OrbitportVRFAdapter.sol
├── script/
│   ├── DeployAll.s.sol          # Full deployment script
│   ├── DeployFeedManager.s.sol  # FeedManager deployment
│   ├── DeployVRFAdapter.s.sol   # VRFAdapter deployment
│   └── AdminOperations.s.sol    # Admin operations
├── test/
│   ├── unit/                    # Unit tests with mocks
│   │   ├── OrbitportFeedManager.t.sol
│   │   ├── OrbitportVRFAdapter.t.sol
│   │   └── *.tree               # Test specification trees
│   ├── integration/             # Integration tests
│   │   ├── OrbitportVRFAdapter.t.sol
│   │   └── *.tree
│   └── mocks/                   # Test mocks
```

## Usage

### Build

Build the contracts:

```sh
forge build
```

### Test

Run all tests:

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

Run a specific test:

```sh
forge test --match-test "test_GetInstantRandomness"
```

### Coverage

Get a test coverage report:

```sh
forge coverage
```

## Deployment

### Environment Variables

Create a `.env` file with the required variables:

```sh
# Required for FeedManager deployment
FEED_VERIFIER_ADDRESS=0x...
PAUSER_REGISTRY_ADDRESS=0x...
FEED_DEPLOYER_ADDRESS=0x...
OWNER_ADDRESS=0x...  # Optional, defaults to deployer

# Required for VRFAdapter deployment (after FeedManager is deployed)
FEED_MANAGER_PROXY_ADDRESS=0x...
BEACON_ID=1  # Optional, defaults to 1

# Optional for full deployment
INITIAL_SUPPORTED_FEEDS=1,2,3  # Comma-separated feed IDs
INITIAL_PUBLISHERS=0x...,0x...  # Comma-separated addresses
```

### Deploy FeedManager Only

```sh
# Using private key
forge script script/DeployFeedManager.s.sol:DeployFeedManager \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY> \
  --broadcast

# Using hardware wallet / keystore
forge script script/DeployFeedManager.s.sol:DeployFeedManager \
  --rpc-url <RPC_URL> \
  --account <ACCOUNT_NAME> \
  --broadcast
```

### Deploy VRFAdapter Only

```sh
# Requires FEED_MANAGER_PROXY_ADDRESS to be set
forge script script/DeployVRFAdapter.s.sol:DeployVRFAdapter \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY> \
  --broadcast
```

### Deploy Both Contracts (Full Deployment)

```sh
forge script script/DeployAll.s.sol:DeployAll \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY> \
  --broadcast
```

### Dry Run (Simulation)

Add `--dry-run` or omit `--broadcast` to simulate without sending transactions:

```sh
forge script script/DeployAll.s.sol:DeployAll \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY>
```

## Admin Operations

The `AdminOperations.s.sol` script provides functions for critical admin operations.

### Environment Variables for Admin Operations

```sh
FEED_MANAGER_PROXY_ADDRESS=0x...
VRF_ADAPTER_ADDRESS=0x...
```

### Pause FeedManager

```sh
forge script script/AdminOperations.s.sol:AdminOperations \
  --sig "pauseFeedManager()" \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY> \
  --broadcast
```

### Unpause FeedManager

```sh
forge script script/AdminOperations.s.sol:AdminOperations \
  --sig "unpauseFeedManager()" \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY> \
  --broadcast
```

### Whitelist Publishers

```sh
forge script script/AdminOperations.s.sol:AdminOperations \
  --sig "whitelistPublishers(address[],bool[])" \
  "[0x1234...5678,0xabcd...ef01]" "[true,true]" \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY> \
  --broadcast
```

### Authorize Retrievers (VRFAdapter)

```sh
forge script script/AdminOperations.s.sol:AdminOperations \
  --sig "authorizeRetrievers(address[],bool[])" \
  "[0x1234...5678]" "[true]" \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY> \
  --broadcast
```

### Authorize Fulfillers (VRFAdapter)

```sh
forge script script/AdminOperations.s.sol:AdminOperations \
  --sig "authorizeFulfillers(address[],bool[])" \
  "[0x1234...5678]" "[true]" \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY> \
  --broadcast
```

### Authorize Callers (FeedManager)

```sh
forge script script/AdminOperations.s.sol:AdminOperations \
  --sig "authorizeCallers(address[],bool[])" \
  "[0x1234...5678]" "[true]" \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY> \
  --broadcast
```

### Using Keystore Account

For all admin operations, you can use a keystore account instead of a private key:

```sh
forge script script/AdminOperations.s.sol:AdminOperations \
  --sig "pauseFeedManager()" \
  --rpc-url <RPC_URL> \
  --account AdminWallet \
  --broadcast
```

## License

This project is licensed under MIT.
