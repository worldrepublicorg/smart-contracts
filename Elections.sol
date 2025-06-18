// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title IAddressBook
 * @dev Interface for the contract that stores verified World ID addresses
 */
interface IAddressBook {
    function addressVerifiedUntil(address addr) external view returns (uint256);
}

/**
 * @title Elections
 * @notice A contract for conducting recurring elections.
 * @dev A reusable contract where the owner can start new election cycles. Allows verified users to cast, change, and remove their votes in the current election.
 * @custom:security-contact security@example.com
 */
contract Elections is Ownable {
    // ================ EXTERNAL CONTRACTS ================
    IAddressBook public immutable addressBook;

    // ================ STATE VARIABLES ================
    uint256 public currentElectionId;
    mapping(uint256 => mapping(uint256 => uint256)) public electionVotes; // electionId -> partyId -> vote count
    mapping(uint256 => mapping(address => uint256)) public userVotes;     // electionId -> user address -> partyId

    // ================ EVENTS ================
    event NewElectionStarted(uint256 indexed electionId, address indexed startedBy);
    event VoteCast(uint256 indexed electionId, address indexed voter, uint256 oldPartyId, uint256 newPartyId);
    event VoteRemoved(uint256 indexed electionId, address indexed voter, uint256 partyId);

    // ================ ERRORS ================
    error AddressZero();
    error NotVerified();
    error InvalidPartyId();
    error CannotVoteForSameParty();
    error NoVoteToRemove();

    // ================ CONSTRUCTOR ================
    /**
     * @notice Initializes the election contract
     * @param _addressBookContract The address of the IAddressBook verification contract.
     * @param _initialOwner The owner of the contract.
     */
    constructor(address _addressBookContract, address _initialOwner) Ownable(_initialOwner) {
        if (_addressBookContract == address(0)) revert AddressZero();
        addressBook = IAddressBook(_addressBookContract);
        currentElectionId = 1;
    }

    // ================ EXTERNAL FUNCTIONS ================
    
    /**
     * @notice Starts a new election period.
     * @dev Only the owner can call this. It increments the election ID, allowing a new round of voting.
     */
    function startNewElection() external onlyOwner {
        currentElectionId++;
        emit NewElectionStarted(currentElectionId, msg.sender);
    }

    /**
     * @notice Cast or change a vote for a specific party for the current election.
     * @dev A user must be verified to vote. They can change their vote by calling this function again with a different partyId.
     * @param _partyId The ID of the party to vote for.
     */
    function vote(uint256 _partyId) external {
        if (addressBook.addressVerifiedUntil(msg.sender) == 0) revert NotVerified();
        if (_partyId == 0) revert InvalidPartyId();

        uint256 oldVote = userVotes[currentElectionId][msg.sender];
        if (oldVote == _partyId) revert CannotVoteForSameParty();
        
        if (oldVote != 0) {
            electionVotes[currentElectionId][oldVote]--;
        }
        
        electionVotes[currentElectionId][_partyId]++;
        userVotes[currentElectionId][msg.sender] = _partyId;
        
        emit VoteCast(currentElectionId, msg.sender, oldVote, _partyId);
    }

    /**
     * @notice Removes the sender's current vote for the current election.
     * @dev Allows a user to retract their vote completely without choosing a new party.
     */
    function removeVote() external {
        uint256 currentVote = userVotes[currentElectionId][msg.sender];
        if (currentVote == 0) revert NoVoteToRemove();

        electionVotes[currentElectionId][currentVote]--;
        userVotes[currentElectionId][msg.sender] = 0;

        emit VoteRemoved(currentElectionId, msg.sender, currentVote);
    }
} 