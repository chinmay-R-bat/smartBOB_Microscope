pragma solidity ^0.8.24;
contract C09 {
    address private admin;
    uint256 public value;
    constructor() { admin = msg.sender; }
    function setValue(uint256 next) external { value = next; }
}
