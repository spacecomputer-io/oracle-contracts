// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IPauserRegistry} from "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";

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

