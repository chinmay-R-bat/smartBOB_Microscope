pragma solidity ^0.8.24;
contract C15 {
    mapping(address => uint256) private credits;
    function deposit() external payable { credits[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = credits[msg.sender];
        require(amount > 0);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        credits[msg.sender] = 0;
    }
}
