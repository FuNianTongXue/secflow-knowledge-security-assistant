pragma solidity ^0.8.20;

contract VulnerableWallet {
    address public owner;

    function withdraw() external {
        require(tx.origin == owner, "not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}
