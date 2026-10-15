pragma solidity ^0.8.24;
contract C17 {
    address private admin;
    uint256 private value;
    constructor() { admin = msg.sender; }
    function update(uint256 next) external { value = next; }
}
