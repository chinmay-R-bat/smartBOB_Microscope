// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// DEMO FIXTURE (intentionally vulnerable): access control.
/// setOwner() has no authorization check.
contract VulnerableTreasury {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    receive() external payable {}

    function setOwner(address newOwner) external { // BUG: anyone can call
        owner = newOwner;
    }

    function withdrawAll() external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "transfer failed");
    }
}
