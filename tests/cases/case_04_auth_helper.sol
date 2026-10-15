pragma solidity ^0.8.24;
contract C04 {
    error Unauthorized();
    address private admin;
    function observe() external view { require(msg.sender == admin); }
    modifier gate() { _check(); _; }
    function _check() internal view { if (msg.sender != admin) revert Unauthorized(); }
    function change(address next) external gate { admin = next; }
}
