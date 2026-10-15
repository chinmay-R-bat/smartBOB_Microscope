pragma solidity ^0.8.24;
contract C11 {
    mapping(address => uint256) private credits;
    uint256 private counter;
    function trigger() external {
        uint256 amount = credits[msg.sender];
        require(amount > 0);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        counter++;
    }
}
