pragma solidity ^0.8.24;
contract C10 {
    mapping(address => uint256) public credits;
    bool private locked;
    modifier mutex() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }
    function deposit() external payable { credits[msg.sender] += msg.value; }
    function withdraw() external mutex {
        uint256 amount = credits[msg.sender];
        require(amount > 0);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        credits[msg.sender] = 0;
    }
}
