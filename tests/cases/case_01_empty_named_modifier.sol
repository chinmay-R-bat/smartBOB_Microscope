pragma solidity ^0.8.24;
contract C01 {
    address private boss;
    modifier onlyOwner() { _; }
    function observe() external view { require(msg.sender == boss); }
    function mutate(address next) external onlyOwner { boss = next; }
}
