pragma solidity ^0.8.24;
contract C07 {
    address private admin;
    function observe() external view { require(msg.sender == admin); }
    function change(address next) external {
        assembly { sstore(admin.slot, next) }
        admin = next;
    }
}
