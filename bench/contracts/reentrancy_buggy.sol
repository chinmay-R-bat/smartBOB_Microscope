// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CreditPool {
    mapping(address => uint256) public credits;

    function contribute() external payable {
        credits[msg.sender] += msg.value;
    }

    function claim() external {
        uint256 amount = credits[msg.sender];
        require(amount > 0, "empty credit");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        credits[msg.sender] = 0;
    }
}
