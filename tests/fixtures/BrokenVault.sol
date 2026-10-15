pragma solidity ^0.8.24;

contract BrokenVault {
    uint256 public balance

    function deposit() external payable {
        balance += msg.value;
    }
}
