pragma solidity ^0.8.24;
contract C12 {
    mapping(address => uint256) private credits;
    function withdraw(uint256 amount) external {
        require(credits[msg.sender] >= amount);
        payable(msg.sender).transfer(amount);
        credits[msg.sender] -= amount;
    }
}
