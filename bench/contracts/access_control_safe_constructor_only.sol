// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ImmutableSetupRegistry {
    address public administrator;
    uint256 public immutable configuredAt;

    constructor() {
        administrator = msg.sender;
        configuredAt = block.timestamp;
    }

    function isAdministrator(address account) external view returns (bool) {
        return account == administrator;
    }
}
