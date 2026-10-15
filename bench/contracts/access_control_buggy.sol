// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AdminRegistry {
    address public administrator;

    constructor() payable {
        administrator = msg.sender;
    }

    receive() external payable {}

    function replaceAdministrator(address next) external {
        administrator = next;
    }

    function release() external {
        require(msg.sender == administrator, "not administrator");
        (bool ok,) = administrator.call{value: address(this).balance}("");
        require(ok, "send failed");
    }
}
