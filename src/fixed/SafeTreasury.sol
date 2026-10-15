// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// PATCHED version: setOwner restricted to current owner.
contract SafeTreasury {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() payable {
        owner = msg.sender;
    }

    receive() external payable {}

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function withdrawAll() external onlyOwner {
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "transfer failed");
    }
}
