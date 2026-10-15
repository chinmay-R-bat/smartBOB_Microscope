pragma solidity ^0.8.24;
contract C13 {
    mapping(address => uint256) private credits;
    function withdraw() external {
        uint256 amount = credits[msg.sender];
        credits[msg.sender] = 0;
        _send(amount);
    }
    function _send(uint256 amount) internal {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
