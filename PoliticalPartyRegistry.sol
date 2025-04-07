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
 * @title IPoliticalPartyRegistry
 * @dev Interface for the Political Party Registry contract
 */
interface IPoliticalPartyRegistry {
    function getPartyStatus(uint256 _partyId) external view returns (uint8);
    function getPartyCount() external view returns (uint256);
    function getPartyMemberCounts(uint256 _partyId) external view returns (uint256 memberCount, uint256 documentVerifiedMemberCount, uint256 verifiedMemberCount);
}

/**
 * @title PoliticalPartyRegistry
 * @notice A contract to manage political parties
 * @dev Implements a system for party creation, management, and statistical tracking
 * @custom:security-contact security@example.com
 */
contract PoliticalPartyRegistry is ReentrancyGuard, Pausable, Ownable, IPoliticalPartyRegistry {
    using ByteHasher for bytes;

    // ================ CUSTOM ERRORS ================
    error ZeroAddress();
    error InvalidPartyId();
    error StringEmpty();
    error StringTooLong();
    error NotPartyMember();
    error NotPartyLeader();
    error AlreadyPartyMember();
    error LeaderCannotLeave();
    error LeadershipActiveElsewhere();
    error PartyNotPending();
    error PartyNotInactive();
    error PartyAlreadyInactive();
    error IndexOutOfBounds();
    error LeaderHasActiveParty();
    error NotOwnerOrLeader();
    error PartyNotActive();
    error NotMember();
    error CannotRemoveLeader();
    error NewLeaderAlreadyLeadsActiveParty();
    error AlreadyLeader();
    error NullifierHashAlreadyUsed();
    error InvalidProof();
    
    // ================ CONSTANTS ================
    uint256 private constant MAX_STRING_LENGTH = 256;
    uint256 private constant MAX_SHORT_NAME_LENGTH = 16;
    uint256 private constant NOT_LEADER = type(uint256).max;
    
    // Party status enum instead of constants
    enum PartyStatus { PENDING, ACTIVE, INACTIVE }
    
    // World ID constants
    uint256 internal constant GROUP_ID = 1;
    
    // ================ DATA STRUCTURES ================
    struct PartyStats {
        uint256 leadershipChanges;
        uint256 memberJoins;
        uint256 memberLeaves;
        uint256 lastActivityTimestamp;
    }
    
    struct LeadershipChange {
        address previousLeader;
        address newLeader;
        uint256 timestamp;
        bool forced;
    }
    
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
        uint256 memberCount;
        uint256 documentVerifiedMemberCount; // Count of document-verified members
        uint256 verifiedMemberCount; // Count of Orb-verified members
        PartyStats stats;
        LeadershipChange[] leadershipHistory;
    }

    // ================ STATE VARIABLES ================
    // Address Book contract address - should be made configurable
    address public addressBookContract;
    
    // World ID integration
    IWorldID public worldId;
    uint256 internal externalNullifier;
    
    // Mapping to track verified World ID nullifier hashes
    mapping(uint256 => bool) public nullifierHashes;
    
    // Mapping to track document-verified party members
    mapping(address => bool) public documentVerifiedMembers;
    
    // Party storage
    mapping(uint256 => Party) private parties;
    uint256 public partyCount;
    uint256 private _activePartiesCount;
    uint256 private _pendingPartiesCount;
    
    // Optimized mappings to avoid loops
    mapping(address => uint256[]) private _userParties;
    mapping(address => uint256[]) private _userLeaderships;
    
    // ================ EVENTS ================
    event PartyCreated(uint256 indexed partyId, string name, address indexed founder, address indexed initialLeader, uint256 timestamp);
    event PartyJoined(uint256 indexed partyId, address indexed member, uint256 blockNumber, uint256 timestamp, bool isVerified, bool isDocumentVerified);
    event PartyLeft(uint256 indexed partyId, address indexed member, uint256 blockNumber, uint256 timestamp, bool wasVerified, bool wasDocumentVerified);
    event MemberRemoved(uint256 indexed partyId, address indexed member, address indexed remover, uint256 timestamp, bool wasVerified, bool wasDocumentVerified);
    event LeadershipTransferred(uint256 indexed partyId, address indexed previousLeader, address indexed newLeader, bool forced, uint256 timestamp);
    event PartyStatusChanged(uint256 indexed partyId, uint8 oldStatus, uint8 newStatus, address indexed by, uint256 timestamp);
    event OfficialLinkUpdated(uint256 indexed partyId, string officialLink, uint256 timestamp);
    event PartyNameUpdated(uint256 indexed partyId, string name, uint256 timestamp);
    event PartyDescriptionUpdated(uint256 indexed partyId, string description, uint256 timestamp);
    event EmergencyPause(bool indexed paused, address indexed by, uint256 timestamp);
    event SnapshotTaken(uint256 timestamp, uint256 blockNumber, uint256 partiesProcessed);
    event PartyMembershipSnapshot(uint256 indexed partyId, uint256 snapshotId, uint256 memberCount, uint256 verifiedMemberCount, uint256 documentVerifiedMemberCount, uint256 timestamp);
    event RegistryDeployed(address indexed initialOwner, uint256 timestamp);
    event PartyShortNameUpdated(uint256 indexed partyId, string shortName, uint256 timestamp);
    event AddressBookUpdated(address indexed oldAddress, address indexed newAddress);
    event WorldIdVerified(address indexed member, uint256 nullifierHash, uint256 timestamp);
    event WorldIdUpdated(address indexed oldWorldId, address indexed newWorldId);

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
        if (_partyId >= partyCount) revert InvalidPartyId();
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
        if (_addressBookContract == address(0)) revert ZeroAddress();
        addressBookContract = _addressBookContract;
        
        // Initialize World ID verification
        worldId = _worldId;
        externalNullifier = abi.encodePacked(abi.encodePacked(_appId).hashToField(), _actionId).hashToField();
        
        emit RegistryDeployed(initialOwner, block.timestamp);
    }
    
    // ================ EXTERNAL FUNCTIONS ================
    // Group 1: Party Creation and Administration

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
        uint256 newPartyId = partyCount++;
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
        
        // Check if founder is verified with Orb
        bool isVerified = isAddressVerified(msg.sender);
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
        
        party.stats.lastActivityTimestamp = block.timestamp;
        
        _userParties[msg.sender].push(newPartyId);
        _userLeaderships[msg.sender].push(newPartyId);
        _pendingPartiesCount++;
        
        emit PartyCreated(newPartyId, _name, msg.sender, msg.sender, block.timestamp);
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
        address leader = parties[_partyId].currentLeader;
        
        // Check if the leader already leads an active party
        (bool hasLeadership, ) = _hasActiveLeadership(leader);
        if (hasLeadership) {
            revert LeaderHasActiveParty();
        }
        
        PartyStatus oldStatus = parties[_partyId].status;
        parties[_partyId].status = PartyStatus.ACTIVE;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        _pendingPartiesCount--;
        _activePartiesCount++;
        
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
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        if (oldStatus == PartyStatus.ACTIVE) {
            _activePartiesCount--;
        } else if (oldStatus == PartyStatus.PENDING) {
            _pendingPartiesCount--;
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
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        _pendingPartiesCount++;
        
        emit PartyStatusChanged(_partyId, uint8(PartyStatus.INACTIVE), uint8(PartyStatus.PENDING), msg.sender, block.timestamp);
    }
    
    // Group 2: Party Membership Functions
    
    /**
     * @notice Join a political party
     * @param _partyId ID of the party to join
     */
    function joinParty(uint256 _partyId) external 
        partyExists(_partyId) 
        whenNotPaused
        nonReentrant
    {
        if (parties[_partyId].members[msg.sender]) {
            revert AlreadyPartyMember();
        }
        
        parties[_partyId].members[msg.sender] = true;
        parties[_partyId].memberCount++;
        
        // Check if new member is orb verified
        bool isVerified = isAddressVerified(msg.sender);
        if (isVerified) {
            parties[_partyId].verifiedMemberCount++;
        }
        
        // Check if new member is document verified
        bool isDocumentVerified = documentVerifiedMembers[msg.sender];
        if (isDocumentVerified) {
            parties[_partyId].documentVerifiedMemberCount++;
        }
        
        _userParties[msg.sender].push(_partyId);
        
        parties[_partyId].stats.memberJoins++;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        emit PartyJoined(_partyId, msg.sender, block.number, block.timestamp, isVerified, isDocumentVerified);
    }

    /**
     * @notice Join a political party with World ID verification
     * @param _partyId ID of the party to join
     * @param root The root of the Merkle tree
     * @param nullifierHash The nullifier hash for this proof
     * @param proof The zero-knowledge proof
     */
    function joinPartyWithWorldID(
        uint256 _partyId,
        uint256 root,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) 
        external 
        partyExists(_partyId) 
        whenNotPaused
        nonReentrant
    {
        if (parties[_partyId].members[msg.sender]) {
            revert AlreadyPartyMember();
        }
        
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
        
        // Mark the user as document verified
        documentVerifiedMembers[msg.sender] = true;
        
        // Join the party
        parties[_partyId].members[msg.sender] = true;
        parties[_partyId].memberCount++;
        
        // Check if new member is orb verified
        bool isVerified = isAddressVerified(msg.sender);
        if (isVerified) {
            parties[_partyId].verifiedMemberCount++;
        }
        
        // Add to document verified count
        parties[_partyId].documentVerifiedMemberCount++;
        
        _userParties[msg.sender].push(_partyId);
        
        parties[_partyId].stats.memberJoins++;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        emit WorldIdVerified(msg.sender, nullifierHash, block.timestamp);
        emit PartyJoined(_partyId, msg.sender, block.number, block.timestamp, isVerified, true);
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
        bool wasVerified = isAddressVerified(msg.sender);
        
        parties[_partyId].members[msg.sender] = false;
        parties[_partyId].memberCount--;
        
        if (wasDocumentVerified) {
            parties[_partyId].documentVerifiedMemberCount--;
        }
        
        if (wasVerified) {
            parties[_partyId].verifiedMemberCount--;
        }
        
        _removeFromUserParties(msg.sender, _partyId);
        
        parties[_partyId].stats.memberLeaves++;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
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
        if (_member == address(0)) revert ZeroAddress();
        if (!parties[_partyId].members[_member]) revert NotMember();
        if (_member == parties[_partyId].currentLeader) revert CannotRemoveLeader();
        
        // Check if member being removed is verified
        bool wasDocumentVerified = documentVerifiedMembers[_member];
        bool wasVerified = isAddressVerified(_member);
        
        parties[_partyId].members[_member] = false;
        parties[_partyId].memberCount--;
        
        if (wasDocumentVerified) {
            parties[_partyId].documentVerifiedMemberCount--;
        }
        
        if (wasVerified) {
            parties[_partyId].verifiedMemberCount--;
        }
        
        _removeFromUserParties(_member, _partyId);
        
        parties[_partyId].stats.memberLeaves++;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        emit MemberRemoved(_partyId, _member, msg.sender, block.timestamp, wasDocumentVerified, wasVerified);
    }
    
    // Group 3: Leadership Functions

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
        if (_newLeader == address(0)) revert ZeroAddress();
        if (!parties[_partyId].members[_newLeader]) revert NotMember();
        if (_newLeader == msg.sender) revert AlreadyLeader();
        
        // For active parties, check if the new leader already leads an active party
        if (parties[_partyId].status == PartyStatus.ACTIVE) {
            (bool hasLeadership, ) = _hasActiveLeadership(_newLeader);
            if (hasLeadership) {
                revert NewLeaderAlreadyLeadsActiveParty();
            }
        }
        
        address previousLeader = parties[_partyId].currentLeader;
        parties[_partyId].currentLeader = _newLeader;
        
        _removeFromLeadershipList(previousLeader, _partyId);
        _userLeaderships[_newLeader].push(_partyId);
        
        _recordLeadershipChange(_partyId, previousLeader, _newLeader, false);
        
        parties[_partyId].stats.leadershipChanges++;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
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
        if (_newLeader == address(0)) revert ZeroAddress();
        if (!parties[_partyId].members[_newLeader]) revert NotMember();
        
        // For active parties, check if the new leader already leads an active party
        if (parties[_partyId].status == PartyStatus.ACTIVE) {
            (bool hasLeadership, uint256 leadPartyId) = _hasActiveLeadership(_newLeader);
            if (hasLeadership && leadPartyId != _partyId) {
                revert NewLeaderAlreadyLeadsActiveParty();
            }
        }
        
        address previousLeader = parties[_partyId].currentLeader;
        parties[_partyId].currentLeader = _newLeader;
        
        _removeFromLeadershipList(previousLeader, _partyId);
        _userLeaderships[_newLeader].push(_partyId);
        
        _recordLeadershipChange(_partyId, previousLeader, _newLeader, true);
        
        parties[_partyId].stats.leadershipChanges++;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        emit LeadershipTransferred(_partyId, previousLeader, _newLeader, true, block.timestamp);
    }
    
    // Group 4: Party Information Update Functions

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
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
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
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
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
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
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
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        emit OfficialLinkUpdated(_partyId, _officialLink, block.timestamp);
    }
    
    // Group 5: Administrative Functions
    
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
     * @notice Update the address book contract (owner only)
     * @param _newAddressBook New address book contract address
     */
    function updateAddressBook(address _newAddressBook) external onlyOwner nonReentrant {
        if (_newAddressBook == address(0)) revert ZeroAddress();
        address oldAddressBook = addressBookContract;
        addressBookContract = _newAddressBook;
        emit AddressBookUpdated(oldAddressBook, _newAddressBook);
    }
    
    // ================ PUBLIC FUNCTIONS ================

    /**
     * @notice Check if an address is verified in the Address Book
     * @param _address Address to check
     * @return True if the address has valid verification
     */
    function isAddressVerified(address _address) public view returns (bool) {
        return IAddressBook(addressBookContract).addressVerifiedUntil(_address) > 0;
    }

    // ================ WORLD ID FUNCTIONS ================

    /**
     * @notice Update the World ID contract (owner only)
     * @param _newWorldId New World ID contract address
     */
    function updateWorldId(IWorldID _newWorldId) external onlyOwner nonReentrant {
        if (address(_newWorldId) == address(0)) revert ZeroAddress();
        address oldWorldId = address(worldId);
        worldId = _newWorldId;
        emit WorldIdUpdated(oldWorldId, address(_newWorldId));
    }
    
    // ================ VIEW FUNCTIONS ================
    // Party Status & Counts
    
    /**
     * @notice Get party status
     * @param _partyId ID of the party
     * @return status Party status (0=pending, 1=active, 2=inactive)
     */
    function getPartyStatus(uint256 _partyId) external view override
        partyExists(_partyId)
        returns (uint8 status)
    {
        return uint8(parties[_partyId].status);
    }
    
    /**
     * @notice Get party member counts
     * @param _partyId ID of the party
     * @return memberCount Total number of members
     * @return documentVerifiedMemberCount Number of document-verified members
     * @return verifiedMemberCount Number of verified members
     */
    function getPartyMemberCounts(uint256 _partyId) external view override
        partyExists(_partyId)
        returns (uint256 memberCount, uint256 documentVerifiedMemberCount, uint256 verifiedMemberCount) 
    {
        memberCount = parties[_partyId].memberCount;
        documentVerifiedMemberCount = parties[_partyId].documentVerifiedMemberCount;
        verifiedMemberCount = parties[_partyId].verifiedMemberCount;
        return (memberCount, documentVerifiedMemberCount, verifiedMemberCount);
    }

    /**
     * @notice Get total number of parties created
     * @return count Total number of parties
     */
    function getPartyCount() external view override returns (uint256 count) {
        return partyCount;
    }
    
    /**
     * @notice Get number of active parties
     * @return count Number of active parties
     */
    function getActivePartyCount() external view returns (uint256 count) {
        return _activePartiesCount;
    }
    
    /**
     * @notice Get number of pending parties
     * @return count Number of pending parties
     */
    function getPendingPartyCount() external view returns (uint256 count) {
        return _pendingPartiesCount;
    }
    
    // Party Membership

    /**
     * @notice Check if an address is a member of a party
     * @param _partyId ID of the party
     * @param _member Address to check
     * @return True if the address is a member
     */
    function isMember(uint256 _partyId, address _member) external view
        partyExists(_partyId)
        returns (bool)
    {
        return parties[_partyId].members[_member];
    }
    
    // Party Details
    
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
    
    /**
     * @notice Get party statistics
     * @param _partyId ID of the party
     * @return leadershipChanges Number of leadership changes
     * @return memberJoins Number of member joins
     * @return memberLeaves Number of member leaves
     * @return lastActivityTimestamp Timestamp of last activity
     */
    function getPartyStats(uint256 _partyId) external view
        partyExists(_partyId)
        returns (
            uint256 leadershipChanges,
            uint256 memberJoins,
            uint256 memberLeaves,
            uint256 lastActivityTimestamp
        )
    {
        PartyStats storage stats = parties[_partyId].stats;
        leadershipChanges = stats.leadershipChanges;
        memberJoins = stats.memberJoins;
        memberLeaves = stats.memberLeaves;
        lastActivityTimestamp = stats.lastActivityTimestamp;
    }
    
    // Leadership History
    
    /**
     * @notice Get the count of leadership changes for a party
     * @param _partyId ID of the party
     * @return count Number of leadership changes
     */
    function getLeadershipHistoryCount(uint256 _partyId) external view
        partyExists(_partyId)
        returns (uint256 count)
    {
        return parties[_partyId].leadershipHistory.length;
    }
    
    /**
     * @notice Get a specific leadership history entry for a party
     * @param _partyId ID of the party
     * @param _index Index of the leadership change to retrieve
     * @return previousLeader Address of previous leader
     * @return newLeader Address of new leader
     * @return timestamp Timestamp when the change occurred
     * @return forced Whether the change was forced by the owner
     */
    function getLeadershipHistoryEntry(uint256 _partyId, uint256 _index) external view
        partyExists(_partyId)
        returns (
            address previousLeader,
            address newLeader,
            uint256 timestamp,
            bool forced
        )
    {
        if (_index >= parties[_partyId].leadershipHistory.length) revert IndexOutOfBounds();
        
        LeadershipChange storage change = parties[_partyId].leadershipHistory[_index];
        previousLeader = change.previousLeader;
        newLeader = change.newLeader;
        timestamp = change.timestamp;
        forced = change.forced;
    }
    
    // User Participation
    
    /**
     * @notice Get all parties a user is a member of
     * @param _user Address of the user
     * @return partyIds Array of party IDs
     */
    function getUserParties(address _user) external view returns (uint256[] memory partyIds) {
        return _userParties[_user];
    }
    
    /**
     * @notice Get all parties a user is a leader of
     * @param _user Address of the user
     * @return leaderships Array of party IDs
     */
    function getUserLeaderships(address _user) external view returns (uint256[] memory leaderships) {
        return _userLeaderships[_user];
    }
    
    /**
     * @notice Check if a user is a leader of any party
     * @param _user Address of the user
     * @return isLeader True if the user is a leader of any party
     * @return partyId ID of the first party the user leads (or NOT_LEADER if none)
     */
    function isUserLeader(address _user) external view returns (bool isLeader, uint256 partyId) {
        uint256[] storage leaderships = _userLeaderships[_user];
        if (leaderships.length > 0) {
            return (true, leaderships[0]);
        }
        return (false, NOT_LEADER);
    }
    
    // ================ INTERNAL FUNCTIONS ================
    
    /**
     * @dev Removes a party ID from a user's party list
     * @param _user Address of the user
     * @param _partyId ID of the party to remove
     */
    function _removeFromUserParties(address _user, uint256 _partyId) internal {
        uint256[] storage userPartyList = _userParties[_user];
        uint256 length = userPartyList.length;
        
        for (uint256 i = 0; i < length; i++) {
            if (userPartyList[i] == _partyId) {
                if (i < length - 1) {
                    userPartyList[i] = userPartyList[length - 1];
                }
                userPartyList.pop();
                break;
            }
        }
    }

    /**
     * @dev Removes a party ID from a user's leadership list
     * @param _user Address of the user
     * @param _partyId ID of the party to remove
     */
    function _removeFromLeadershipList(address _user, uint256 _partyId) internal {
        uint256[] storage leadershipList = _userLeaderships[_user];
        uint256 length = leadershipList.length;
        
        for (uint256 i = 0; i < length; i++) {
            if (leadershipList[i] == _partyId) {
                if (i < length - 1) {
                    leadershipList[i] = leadershipList[length - 1];
                }
                leadershipList.pop();
                break;
            }
        }
    }

    /**
     * @dev Records a leadership change in the party's history
     * @param _partyId ID of the party
     * @param _previousLeader Address of the previous leader
     * @param _newLeader Address of the new leader
     * @param _forced Whether the change was forced by the owner
     */
    function _recordLeadershipChange(
        uint256 _partyId, 
        address _previousLeader, 
        address _newLeader, 
        bool _forced
    ) internal {
        parties[_partyId].leadershipHistory.push();
        LeadershipChange storage change = parties[_partyId].leadershipHistory[parties[_partyId].leadershipHistory.length - 1];
        change.previousLeader = _previousLeader;
        change.newLeader = _newLeader;
        change.timestamp = block.timestamp;
        change.forced = _forced;
    }

    /**
     * @dev Checks if an address already leads an active party
     * @param _address Address to check
     * @return hasLeadership Whether the address already leads an active party
     * @return leadPartyId The ID of the active party led by this address (if any)
     */
    function _hasActiveLeadership(address _address) internal view returns (bool hasLeadership, uint256 leadPartyId) {
        for (uint256 i = 0; i < _userLeaderships[_address].length; i++) {
            uint256 partyId = _userLeaderships[_address][i];
            if (parties[partyId].status == PartyStatus.ACTIVE) {
                return (true, partyId);
            }
        }
        return (false, 0);
    }
}
