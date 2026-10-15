// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CreditPoolCEI {
    mapping(address => uint256) public credits;

    function contribute() external payable {
        credits[msg.sender] += msg.value;
    }

    function claim() external {
        uint256 amount = credits[msg.sender];
        require(amount > 0, "empty credit");
        credits[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}
