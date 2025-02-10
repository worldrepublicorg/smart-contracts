// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract AddressBook {
    mapping(address => bool) public hasClaimed;
    address public owner;
    address public authorizedWriter;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    modifier onlyAuthorizedWriter() {
        require(
            msg.sender == authorizedWriter || 
            msg.sender == owner, 
            "Not authorized to write"
        );
        _;
    }

    function setAuthorizedWriter(address _writer) external onlyOwner {
        authorizedWriter = _writer;
    }

    function markClaimed(address recipient) external onlyAuthorizedWriter {
        hasClaimed[recipient] = true;
    }

    function checkClaimStatus(address user) public view returns (bool) {
        return hasClaimed[user];
    }
}