pragma solidity ^0.8.24;
contract C08 {
    mapping(address => uint256) private credits;
    mapping(address => bool) private claimed;
    function claim(uint256 amount) external {
        require(credits[msg.sender] >= amount);
        claimed[msg.sender] = true;
    }
}
