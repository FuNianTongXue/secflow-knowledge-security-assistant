pragma solidity ^0.8.20;

contract SafeWallet {
    address public owner;

    function withdraw() external {
        require(msg.sender == owner, "not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}
