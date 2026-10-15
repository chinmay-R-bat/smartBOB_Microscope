// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// DEMO FIXTURE (intentionally vulnerable): reentrancy.
/// withdraw() sends ETH BEFORE zeroing the balance.
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}(""); // interaction first (BUG)
        require(ok, "transfer failed");
        balances[msg.sender] = 0;                          // effect last (BUG)
    }
}
