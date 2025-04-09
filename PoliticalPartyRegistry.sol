// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// ByteHasher library for World ID integration
library ByteHasher {
    /// @dev Creates a keccak256 hash of a bytestring.
    /// @param value The bytestring to hash
    /// @return The hash of the specified value
    /// @dev `>> 8` makes sure that the result is included in our field
    function hashToField(bytes memory value) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(value))) >> 8;
    }
}

// World ID interface
interface IWorldID {
    /// @notice Reverts if the zero-knowledge proof is invalid.
    /// @param root The of the Merkle tree
    /// @param groupId The id of the Semaphore group
    /// @param signalHash A keccak256 hash of the Semaphore signal
    /// @param nullifierHash The nullifier hash
    /// @param externalNullifierHash A keccak256 hash of the external nullifier
    /// @param proof The zero-knowledge proof
    function verifyProof(
        uint256 root,
        uint256 groupId,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) external view;
}

/**
 * @title IAddressBook
 * @dev Interface for the contract that stores verified World ID addresses
 */
interface IAddressBook {
    function addressVerifiedUntil(address addr) external view returns (uint256);
}

/**
 * @title PoliticalPartyRegistry
 * @notice A contract to manage political parties
 * @dev Implements a system for party creation, management, and statistical tracking
 * @custom:security-contact security@example.com
 */
contract PoliticalPartyRegistry is ReentrancyGuard, Pausable, Ownable {
    using ByteHasher for bytes;

    // ================ CONSTANTS ================
    uint256 private constant MAX_STRING_LENGTH = 256;
    uint256 private constant MAX_SHORT_NAME_LENGTH = 16;
    uint256 private constant NOT_LEADER = type(uint256).max;
    uint256 private constant NO_PARTY = 0; // 0 means not a member of any party
    
    // World ID constants
    uint256 internal constant GROUP_ID = 1;
    
    // ================ TYPES ================
    // Party status enum instead of constants
    enum PartyStatus { PENDING, ACTIVE, INACTIVE }
    
    // ================ CUSTOM ERRORS ================
    error AddressZero();
    error AlreadyLeader();
    error AlreadyMemberOfAnotherParty();
    error AlreadyPartyMember();
    error BannedFromParty();
    error CannotRemoveLeader();
    error IndexOutOfBounds();
    error InvalidPartyId();
    error InvalidProof();
    error LeaderCannotLeave();
    error LeaderHasActiveParty();
    error LeadershipActiveElsewhere();
    error NewLeaderAlreadyLeadsActiveParty();
    error NotMember();
    error NotOwnerOrLeader();
    error NotPartyLeader();
    error NotPartyMember();
    error NullifierHashAlreadyUsed();
    error PartyAlreadyInactive();
    error PartyNotActive();
    error PartyNotInactive();
    error PartyNotPending();
    error StringEmpty();
    error StringTooLong();
    
    // ================ DATA STRUCTURES ================
    struct Party {
        string name;
        string shortName;
        string description;
        string officialLink;
        address founder;
        address currentLeader;
        uint256 creationTime;
        PartyStatus status;
        mapping(address => bool) members;
        mapping(address => bool) bannedMembers;
        uint256 memberCount;
        uint256 documentVerifiedMemberCount; // Count of document-verified members
        uint256 verifiedMemberCount; // Count of Orb-verified members
    }

    // ================ STATE VARIABLES ================
    // External contract references
    address public immutable addressBookContract;
    IWorldID public immutable worldId;
    
    // World ID verification
    uint256 internal immutable externalNullifier;
    
    // Party counts
    uint256 public totalPartyCount;
    uint256 public activePartiesCount;
    uint256 public pendingPartiesCount;
    
    // Mappings for party management
    mapping(uint256 => Party) private parties;
    mapping(uint256 => bool) public nullifierHashes;
    mapping(address => bool) public documentVerifiedMembers;
    mapping(address => uint256) public userParty;
    mapping(address => bool) public isLeader;
    
    // ================ EVENTS ================
    event PartyCreated(uint256 indexed partyId, string name, string shortName, address indexed founder, address indexed initialLeader, uint256 timestamp);
    event PartyJoined(uint256 indexed partyId, address indexed member, uint256 blockNumber, uint256 timestamp, bool isVerified, bool isDocumentVerified);
    event PartyLeft(uint256 indexed partyId, address indexed member, uint256 blockNumber, uint256 timestamp, bool wasVerified, bool wasDocumentVerified);
    event MemberRemoved(uint256 indexed partyId, address indexed member, address indexed remover, uint256 timestamp, bool wasVerified, bool wasDocumentVerified);
    event LeadershipTransferred(uint256 indexed partyId, address indexed previousLeader, address indexed newLeader, bool forced, uint256 timestamp);
    event PartyStatusChanged(uint256 indexed partyId, uint8 oldStatus, uint8 newStatus, address indexed by, uint256 timestamp);
    event OfficialLinkUpdated(uint256 indexed partyId, string officialLink, uint256 timestamp);
    event PartyNameUpdated(uint256 indexed partyId, string name, uint256 timestamp);
    event PartyDescriptionUpdated(uint256 indexed partyId, string description, uint256 timestamp);
    event PartyShortNameUpdated(uint256 indexed partyId, string shortName, uint256 timestamp);
    event EmergencyPause(bool indexed paused, address indexed by, uint256 timestamp);
    event WorldIdVerified(address indexed member, uint256 nullifierHash, uint256 timestamp);
    event RegistryDeployed(address indexed initialOwner, uint256 timestamp);
    event MemberBanned(uint256 indexed partyId, address indexed member, address indexed by, uint256 timestamp);
    event MemberUnbanned(uint256 indexed partyId, address indexed member, address indexed by, uint256 timestamp);

    // ================ MODIFIERS ================
    modifier onlyPartyMember(uint256 _partyId) {
        if (!parties[_partyId].members[msg.sender]) revert NotPartyMember();
        _;
    }

    modifier onlyPartyLeader(uint256 _partyId) {
        if (msg.sender != parties[_partyId].currentLeader) revert NotPartyLeader();
        _;
    }

    modifier partyExists(uint256 _partyId) {
        if (_partyId == 0 || _partyId > totalPartyCount) revert InvalidPartyId();
        _;
    }

    modifier partyPending(uint256 _partyId) {
        if (parties[_partyId].status != PartyStatus.PENDING) revert PartyNotPending();
        _;
    }
    
    modifier validString(string memory str) {
        if (bytes(str).length == 0) revert StringEmpty();
        if (bytes(str).length > MAX_STRING_LENGTH) revert StringTooLong();
        _;
    }

    modifier validShortName(string memory str) {
        if (bytes(str).length == 0) revert StringEmpty();
        if (bytes(str).length > MAX_SHORT_NAME_LENGTH) revert StringTooLong();
        _;
    }

    // ================ CONSTRUCTOR ================
    /**
     * @notice Initialize the contract with owner address, address book, and World ID
     * @param initialOwner The initial owner of the contract
     * @param _addressBookContract The address of the World ID verification contract
     * @param _worldId The World ID contract address
     * @param _appId The World ID app ID
     * @param _actionId The World ID action ID for this specific action
     */
    constructor(
        address initialOwner, 
        address _addressBookContract,
        IWorldID _worldId,
        string memory _appId,
        string memory _actionId
    ) 
        Ownable(initialOwner) 
    {
        if (_addressBookContract == address(0)) revert AddressZero();
        addressBookContract = _addressBookContract;
        
        // Initialize World ID verification
        worldId = _worldId;
        externalNullifier = abi.encodePacked(abi.encodePacked(_appId).hashToField(), _actionId).hashToField();
        
        emit RegistryDeployed(initialOwner, block.timestamp);
    }
    
    // ================ EXTERNAL FUNCTIONS ================
    
    // -------- Party Creation and Administration --------

    /**
     * @notice Create a new political party (in pending state)
     * @param _name Name of the party
     * @param _shortName Short name/abbreviation of the party
     * @param _description Brief description of the party
     * @param _officialLink Link to party website or community (can be empty)
     * @return partyId ID of the created party
     */
    function createParty(
        string memory _name,
        string memory _shortName,
        string memory _description, 
        string memory _officialLink
    ) 
        external 
        whenNotPaused 
        nonReentrant
        validString(_name)
        validShortName(_shortName)
        validString(_description)
        returns (uint256 partyId)
    {
        // Check if user is already a member of another party
        if (userParty[msg.sender] != NO_PARTY) {
            revert AlreadyMemberOfAnotherParty();
        }
        
        // Start party IDs from 1 instead of 0
        uint256 newPartyId = totalPartyCount + 1;
        totalPartyCount = newPartyId;
        
        Party storage party = parties[newPartyId];
        
        party.name = _name;
        party.shortName = _shortName;
        party.description = _description;
        party.officialLink = _officialLink;
        party.founder = msg.sender;
        party.currentLeader = msg.sender;
        party.creationTime = block.timestamp;
        party.status = PartyStatus.PENDING;
        party.members[msg.sender] = true;
        party.memberCount = 1;
        
        // Set user's current party
        userParty[msg.sender] = newPartyId;
        
        // Mark user as a leader
        isLeader[msg.sender] = true;
        
        // Check if founder is verified with Orb
        bool isVerified = IAddressBook(addressBookContract).addressVerifiedUntil(msg.sender) > 0;
        if (isVerified) {
            party.verifiedMemberCount = 1;
        } else {
            party.verifiedMemberCount = 0;
        }
        
        // Check if founder is document verified
        bool isDocumentVerified = documentVerifiedMembers[msg.sender];
        if (isDocumentVerified) {
            party.documentVerifiedMemberCount = 1;
        } else {
            party.documentVerifiedMemberCount = 0;
        }
        
        pendingPartiesCount++;
        
        emit PartyCreated(newPartyId, _name, _shortName, msg.sender, msg.sender, block.timestamp);
        return newPartyId;
    }

    /**
     * @notice Approve a pending party (only owner)
     * @param _partyId ID of the party to approve
     */
    function approveParty(uint256 _partyId) external 
        partyExists(_partyId) 
        partyPending(_partyId) 
        onlyOwner
        whenNotPaused
        nonReentrant
    {
        PartyStatus oldStatus = parties[_partyId].status;
        parties[_partyId].status = PartyStatus.ACTIVE;
        
        pendingPartiesCount--;
        activePartiesCount++;
        
        emit PartyStatusChanged(_partyId, uint8(oldStatus), uint8(PartyStatus.ACTIVE), msg.sender, block.timestamp);
    }
    
    /**
     * @notice Deactivate a party (only owner or leader)
     * @param _partyId ID of the party to deactivate
     */
    function deactivateParty(uint256 _partyId) external 
        partyExists(_partyId)
        whenNotPaused
        nonReentrant
    {
        if (msg.sender != owner() && msg.sender != parties[_partyId].currentLeader) {
            revert NotOwnerOrLeader();
        }
        if (parties[_partyId].status == PartyStatus.INACTIVE) {
            revert PartyAlreadyInactive();
        }
        
        PartyStatus oldStatus = parties[_partyId].status;
        parties[_partyId].status = PartyStatus.INACTIVE;
        
        if (oldStatus == PartyStatus.ACTIVE) {
            activePartiesCount--;
        } else if (oldStatus == PartyStatus.PENDING) {
            pendingPartiesCount--;
        }
        
        emit PartyStatusChanged(_partyId, uint8(oldStatus), uint8(PartyStatus.INACTIVE), msg.sender, block.timestamp);
    }

    /**
     * @notice Reactivate a party (only owner) - Sets to pending state, not active
     * @param _partyId ID of the party to reactivate
     */
    function reactivateParty(uint256 _partyId) external 
        partyExists(_partyId) 
        onlyOwner
        whenNotPaused
        nonReentrant
    {
        if (parties[_partyId].status != PartyStatus.INACTIVE) {
            revert PartyNotInactive();
        }
        
        parties[_partyId].status = PartyStatus.PENDING;
        
        pendingPartiesCount++;
        
        emit PartyStatusChanged(_partyId, uint8(PartyStatus.INACTIVE), uint8(PartyStatus.PENDING), msg.sender, block.timestamp);
    }
    
    // -------- Party Membership Functions --------
    
    /**
     * @notice Join a party
     * @param _partyId ID of the party
     */
    function joinParty(uint256 _partyId) external
        partyExists(_partyId)
        whenNotPaused
        nonReentrant
    {
        if (parties[_partyId].members[msg.sender]) {
            revert AlreadyPartyMember();
        }
        
        // Check if user is already a member of another party
        if (userParty[msg.sender] != NO_PARTY) {
            revert AlreadyMemberOfAnotherParty();
        }
        
        // Check if user is banned from this party
        if (parties[_partyId].bannedMembers[msg.sender]) revert BannedFromParty();
        
        parties[_partyId].members[msg.sender] = true;
        parties[_partyId].memberCount++;
        
        // Record user's current party
        userParty[msg.sender] = _partyId;
        
        // Check if new member is orb verified
        bool isVerified = IAddressBook(addressBookContract).addressVerifiedUntil(msg.sender) > 0;
        if (isVerified) {
            parties[_partyId].verifiedMemberCount++;
        }
        
        // Check if new member is document verified
        bool isDocumentVerified = documentVerifiedMembers[msg.sender];
        if (isDocumentVerified) {
            parties[_partyId].documentVerifiedMemberCount++;
        }
        
        emit PartyJoined(_partyId, msg.sender, block.number, block.timestamp, isVerified, isDocumentVerified);
    }

    /**
     * @notice Verify an existing member with World ID
     * @param _partyId ID of the party
     * @param root The root of the Merkle tree
     * @param nullifierHash The nullifier hash for this proof
     * @param proof The zero-knowledge proof
     */
    function verifyMemberWithWorldID(
        uint256 _partyId,
        uint256 root,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) 
        external 
        partyExists(_partyId) 
        onlyPartyMember(_partyId)
        whenNotPaused
        nonReentrant
    {
        // Ensure this nullifier hash hasn't been used before
        if (nullifierHashes[nullifierHash]) revert NullifierHashAlreadyUsed();
        
        // Verify proof of personhood with World ID
        worldId.verifyProof(
            root,
            GROUP_ID,
            abi.encodePacked(msg.sender).hashToField(),
            nullifierHash,
            externalNullifier,
            proof
        );
        
        // Mark the nullifier hash as used
        nullifierHashes[nullifierHash] = true;
        
        // Check if the member was previously document verified
        bool wasDocumentVerified = documentVerifiedMembers[msg.sender];
        
        // Mark the user as document verified if not already
        if (!wasDocumentVerified) {
            documentVerifiedMembers[msg.sender] = true;
            parties[_partyId].documentVerifiedMemberCount++;
        }
        
        emit WorldIdVerified(msg.sender, nullifierHash, block.timestamp);
    }

    /**
     * @notice Leave a political party
     * @param _partyId ID of the party to leave
     */
    function leaveParty(uint256 _partyId) external 
        partyExists(_partyId) 
        onlyPartyMember(_partyId)
        whenNotPaused
        nonReentrant
    {
        if (msg.sender == parties[_partyId].currentLeader) {
            revert LeaderCannotLeave();
        }
        
        // Check if leaving member is verified before removing
        bool wasDocumentVerified = documentVerifiedMembers[msg.sender];
        bool wasVerified = IAddressBook(addressBookContract).addressVerifiedUntil(msg.sender) > 0;
        
        parties[_partyId].members[msg.sender] = false;
        parties[_partyId].memberCount--;
        
        // Clear user's current party
        userParty[msg.sender] = NO_PARTY;
        
        if (wasDocumentVerified) {
            parties[_partyId].documentVerifiedMemberCount--;
        }
        
        if (wasVerified) {
            parties[_partyId].verifiedMemberCount--;
        }
        
        emit PartyLeft(_partyId, msg.sender, block.number, block.timestamp, wasDocumentVerified, wasVerified);
    }
    
    /**
     * @notice Remove a member from a party (leader only)
     * @param _partyId ID of the party
     * @param _member Address of the member to remove
     */
    function removeMember(uint256 _partyId, address _member) external
        partyExists(_partyId)
        onlyPartyLeader(_partyId)
        whenNotPaused
        nonReentrant
    {
        if (_member == address(0)) revert AddressZero();
        if (!parties[_partyId].members[_member]) revert NotMember();
        if (_member == parties[_partyId].currentLeader) revert CannotRemoveLeader();
        
        // Check if member being removed is verified
        bool wasDocumentVerified = documentVerifiedMembers[_member];
        bool wasVerified = IAddressBook(addressBookContract).addressVerifiedUntil(_member) > 0;
        
        parties[_partyId].members[_member] = false;
        parties[_partyId].memberCount--;
        
        // Clear user's current party
        userParty[_member] = NO_PARTY;
        
        if (wasDocumentVerified) {
            parties[_partyId].documentVerifiedMemberCount--;
        }
        
        if (wasVerified) {
            parties[_partyId].verifiedMemberCount--;
        }
        
        emit MemberRemoved(_partyId, _member, msg.sender, block.timestamp, wasDocumentVerified, wasVerified);
    }
    
    // -------- Leadership Functions --------

    /**
     * @notice Transfer party leadership to another member
     * @param _partyId ID of the party
     * @param _newLeader Address of the new leader
     */
    function transferLeadership(uint256 _partyId, address _newLeader) external 
        partyExists(_partyId) 
        onlyPartyLeader(_partyId)
        whenNotPaused
        nonReentrant
    {
        if (_newLeader == address(0)) revert AddressZero();
        if (!parties[_partyId].members[_newLeader]) revert NotMember();
        if (_newLeader == msg.sender) revert AlreadyLeader();
        
        address previousLeader = parties[_partyId].currentLeader;
        parties[_partyId].currentLeader = _newLeader;
        
        // Update leader status
        isLeader[previousLeader] = false;
        isLeader[_newLeader] = true;
        
        emit LeadershipTransferred(_partyId, previousLeader, _newLeader, false, block.timestamp);
    }
    
    /**
     * @notice Force leadership change (owner function)
     * @param _partyId ID of the party
     * @param _newLeader Address of the new leader
     */
    function forceLeadershipChange(uint256 _partyId, address _newLeader) external 
        partyExists(_partyId) 
        onlyOwner
        whenNotPaused
        nonReentrant
    {
        if (_newLeader == address(0)) revert AddressZero();
        if (!parties[_partyId].members[_newLeader]) revert NotMember();
        
        address previousLeader = parties[_partyId].currentLeader;
        parties[_partyId].currentLeader = _newLeader;
        
        // Update leader status
        isLeader[previousLeader] = false;
        isLeader[_newLeader] = true;
        
        emit LeadershipTransferred(_partyId, previousLeader, _newLeader, true, block.timestamp);
    }
    
    // -------- Party Information Update Functions --------

    /**
     * @notice Update party's name
     * @param _partyId ID of the party
     * @param _name New party name
     */
    function updatePartyName(uint256 _partyId, string memory _name) external 
        partyExists(_partyId) 
        onlyPartyLeader(_partyId)
        whenNotPaused
        nonReentrant
        validString(_name)
    {
        parties[_partyId].name = _name;
        
        emit PartyNameUpdated(_partyId, _name, block.timestamp);
    }

    /**
     * @notice Update party's short name
     * @param _partyId ID of the party
     * @param _shortName New party short name
     */
    function updatePartyShortName(uint256 _partyId, string memory _shortName) external 
        partyExists(_partyId) 
        onlyPartyLeader(_partyId)
        whenNotPaused
        nonReentrant
        validShortName(_shortName)
    {
        parties[_partyId].shortName = _shortName;
        
        emit PartyShortNameUpdated(_partyId, _shortName, block.timestamp);
    }

    /**
     * @notice Update party's description
     * @param _partyId ID of the party
     * @param _description New party description
     */
    function updatePartyDescription(uint256 _partyId, string memory _description) external 
        partyExists(_partyId) 
        onlyPartyLeader(_partyId)
        whenNotPaused
        nonReentrant
        validString(_description)
    {
        parties[_partyId].description = _description;
        
        emit PartyDescriptionUpdated(_partyId, _description, block.timestamp);
    }

    /**
     * @notice Update party's official link
     * @param _partyId ID of the party
     * @param _officialLink New official link
     */
    function updateOfficialLink(uint256 _partyId, string memory _officialLink) external 
        partyExists(_partyId) 
        onlyPartyLeader(_partyId)
        whenNotPaused
        nonReentrant
        validString(_officialLink)
    {
        parties[_partyId].officialLink = _officialLink;
        
        emit OfficialLinkUpdated(_partyId, _officialLink, block.timestamp);
    }
    
    // -------- Administrative Functions --------
    
    /**
     * @notice Pause the contract in case of emergency (owner only)
     */
    function togglePause() external onlyOwner nonReentrant {
        if (paused()) {
            _unpause();
        } else {
            _pause();
        }
        
        emit EmergencyPause(paused(), msg.sender, block.timestamp);
    }
    
    /**
     * @notice Ban a member from a party, preventing them from rejoining
     * @param _partyId ID of the party
     * @param _member Address of the member to ban
     */
    function banMember(uint256 _partyId, address _member) external
        partyExists(_partyId)
        onlyPartyLeader(_partyId)
        whenNotPaused
        nonReentrant
    {
        if (_member == address(0)) revert AddressZero();
        if (_member == parties[_partyId].currentLeader) revert CannotRemoveLeader();
        
        // Set banned status
        parties[_partyId].bannedMembers[_member] = true;
        
        // If they are a current member, remove them
        if (parties[_partyId].members[_member]) {
            // Check if member being removed is verified
            bool wasDocumentVerified = documentVerifiedMembers[_member];
            bool wasVerified = IAddressBook(addressBookContract).addressVerifiedUntil(_member) > 0;
            
            parties[_partyId].members[_member] = false;
            parties[_partyId].memberCount--;
            
            // Clear user's current party
            userParty[_member] = NO_PARTY;
            
            if (wasDocumentVerified) {
                parties[_partyId].documentVerifiedMemberCount--;
            }
            
            if (wasVerified) {
                parties[_partyId].verifiedMemberCount--;
            }
        }
        
        emit MemberBanned(_partyId, _member, msg.sender, block.timestamp);
    }
    
    /**
     * @notice Unban a member from a party, allowing them to rejoin
     * @param _partyId ID of the party
     * @param _member Address of the member to unban
     */
    function unbanMember(uint256 _partyId, address _member) external
        partyExists(_partyId)
        onlyPartyLeader(_partyId)
        whenNotPaused
        nonReentrant
    {
        if (_member == address(0)) revert AddressZero();
        
        // Clear banned status
        parties[_partyId].bannedMembers[_member] = false;
        
        emit MemberUnbanned(_partyId, _member, msg.sender, block.timestamp);
    }
    
    // ================ VIEW FUNCTIONS ================
    
    /**
     * @notice Get party details
     * @param _partyId ID of the party
     * @return name Party name
     * @return shortName Party short name/abbreviation
     * @return description Party description
     * @return officialLink Party official link
     * @return founder Address of party founder
     * @return currentLeader Address of current party leader
     * @return creationTime Timestamp when party was created
     * @return status Party status (0=pending, 1=active, 2=inactive)
     * @return memberCount Total number of members
     * @return documentVerifiedMemberCount Number of document-verified members
     * @return verifiedMemberCount Number of verified members
     */
    function getPartyDetails(uint256 _partyId) external view
        partyExists(_partyId)
        returns (
            string memory name,
            string memory shortName,
            string memory description,
            string memory officialLink,
            address founder,
            address currentLeader,
            uint256 creationTime,
            uint8 status,
            uint256 memberCount,
            uint256 documentVerifiedMemberCount,
            uint256 verifiedMemberCount
        )
    {
        Party storage party = parties[_partyId];
        name = party.name;
        shortName = party.shortName;
        description = party.description;
        officialLink = party.officialLink;
        founder = party.founder;
        currentLeader = party.currentLeader;
        creationTime = party.creationTime;
        status = uint8(party.status);
        memberCount = party.memberCount;
        documentVerifiedMemberCount = party.documentVerifiedMemberCount;
        verifiedMemberCount = party.verifiedMemberCount;
    }
}
