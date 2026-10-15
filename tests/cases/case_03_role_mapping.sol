pragma solidity ^0.8.24;
contract C03 {
    mapping(address => bool) private admins;
    function checkRole() external view { require(admins[msg.sender]); }
    function grant(address who) external { admins[who] = true; }
}
