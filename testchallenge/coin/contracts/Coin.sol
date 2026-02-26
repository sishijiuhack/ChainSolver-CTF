pragma solidity ^0.5.11;

contract Coin {
    mapping(address => uint) public balanceOf;
    mapping(address => mapping(address => uint)) public allowance;
    
    string public name = "CTF Coin";
    string public symbol = "COIN";
    uint8 public decimals = 0;
    
    constructor() public {
        balanceOf[msg.sender] = 1000000;
    }
    
    function transfer(address to, uint value) public returns(bool) {
        require(balanceOf[msg.sender] >= value, "balance too low");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        return true;
    }
    
    function approve(address spender, uint value) public returns(bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }
    
    function transferFrom(address from, address to, uint value) public returns(bool) {
        require(balanceOf[from] >= value, "balance too low");
        require(allowance[from][msg.sender] >= value, "allowance too low");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;
        return true;
    }
}