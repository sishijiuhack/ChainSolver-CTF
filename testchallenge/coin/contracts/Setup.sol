pragma solidity ^0.5.11;

import "./Coin.sol";

contract Setup {
    Coin public coin;
    string public flag;
    bool public solved;

    constructor(address _coin, string memory _flag) public {
        coin = Coin(_coin);
        flag = _flag;
        solved = false;
    }

    function getFlag() public returns (string memory) {
        require(coin.balanceOf(address(this)) >= 10000, "Need at least 10000 COIN");
        solved = true;
        return flag;
    }

    function isSolved() public view returns (bool) {
        return solved;
    }
}