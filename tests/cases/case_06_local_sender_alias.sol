pragma solidity ^0.8.24;
contract C06 {
    address private admin;
    function observe() external view { require(msg.sender == admin); }
    modifier gate() {
        address caller = msg.sender;
        require(caller == admin);
        _;
    }
    function change(address next) external gate { admin = next; }
}
