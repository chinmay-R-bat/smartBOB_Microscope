pragma solidity ^0.8.24;
interface IRegistry { function isAdmin(address who) external view returns (bool); }
contract C05 {
    IRegistry private registry;
    address private admin;
    function observe() external view { require(msg.sender == admin); }
    modifier gate() { require(registry.isAdmin(msg.sender)); _; }
    function change(address next) external gate { admin = next; }
}
