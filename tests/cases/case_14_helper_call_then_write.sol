pragma solidity ^0.8.24;
contract C14 {
    mapping(address => uint256) private credits;
    function withdraw() external {
        uint256 amount = credits[msg.sender];
        _send(amount);
        credits[msg.sender] = 0;
    }
    function _send(uint256 amount) internal {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
