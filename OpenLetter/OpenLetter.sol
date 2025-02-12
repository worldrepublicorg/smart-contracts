// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract OpenLetter {
    struct Letter {
        string title;
        string content;
        uint256 signatureCount;
    }

    Letter public letter;
    mapping(address => bool) public signatures;

    constructor(string memory _title, string memory _content) {
        letter.title = _title;
        letter.content = _content;
        letter.signatureCount = 0;
    }

    function sign() external {
        require(!signatures[msg.sender], "Already signed");

        signatures[msg.sender] = true;
        letter.signatureCount++;
    }

    function removeSignature() external {
        require(signatures[msg.sender], "Not signed yet");

        signatures[msg.sender] = false;
        letter.signatureCount--;
    }

    function hasSignedLetter(address _signer) external view returns (bool) {
        return signatures[_signer];
    }

    function getLetterInfo() external view returns (
        string memory title,
        string memory content,
        uint256 signatureCount
    ) {
        return (
            letter.title,
            letter.content,
            letter.signatureCount
        );
    }
}