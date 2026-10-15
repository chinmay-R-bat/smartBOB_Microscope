// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AdminRegistryGuarded {
    address public administrator;

    constructor() payable {
        administrator = msg.sender;
    }

    modifier administratorOnly() {
        require(msg.sender == administrator, "not administrator");
        _;
    }

    receive() external payable {}

    function replaceAdministrator(address next) external administratorOnly {
        administrator = next;
    }
}
