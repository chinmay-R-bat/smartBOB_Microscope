// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CreditPoolMutex {
    mapping(address => uint256) public credits;
    bool private entered;

    modifier serialized() {
        require(!entered, "reentrant call");
        entered = true;
        _;
        entered = false;
    }

    function contribute() external payable {
        credits[msg.sender] += msg.value;
    }

    function claim() external serialized {
        uint256 amount = credits[msg.sender];
        require(amount > 0, "empty credit");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        credits[msg.sender] = 0;
    }
}
