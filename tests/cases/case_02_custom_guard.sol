pragma solidity ^0.8.24;
contract C02 {
    address private admin;
    modifier gate() { require(msg.sender == admin); _; }
    function change(address next) external gate { admin = next; }
}
