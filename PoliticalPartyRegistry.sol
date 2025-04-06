// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title PoliticalPartyRegistry
 * @notice A contract to manage political parties with changeable leadership
 * @dev Implements a system for party creation, management, and statistical tracking
 * @custom:security-contact security@example.com
 */
contract PoliticalPartyRegistry is ReentrancyGuard, Pausable, Ownable {
    // Constants
    uint256 private constant MAX_STRING_LENGTH = 256;
    uint256 private constant NOT_LEADER = type(uint256).max;
    
    // Party status constants
    uint8 private constant PARTY_STATUS_PENDING = 0;
    uint8 private constant PARTY_STATUS_ACTIVE = 1;
    uint8 private constant PARTY_STATUS_INACTIVE = 2;

    // Data structures
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
        string description;
        string officialLink;
        address founder;
        address currentLeader;
        uint256 creationTime;
        uint8 status; // 0=pending, 1=active, 2=inactive
        mapping(address => bool) members;
        uint256 memberCount;
        PartyStats stats;
        LeadershipChange[] leadershipHistory;
    }

    struct MembershipSnapshot {
        uint256 timestamp;
        uint256 blockNumber;
        uint256 memberCount;
    }

    // State variables
    mapping(uint256 => Party) private parties;
    uint256 public partyCount;
    uint256 private _activePartiesCount;
    uint256 private _pendingPartiesCount;
    
    // Optimized mappings to avoid loops
    mapping(address => uint256[]) private _userParties;
    mapping(address => uint256[]) private _userLeaderships;
    
    mapping(uint256 => MembershipSnapshot[]) private _partySnapshots;
    uint256 private _lastSnapshotTime;
    uint256 private _snapshotRetentionCount = 10;
    
    // Events with enhanced information
    event PartyCreated(uint256 indexed partyId, string name, address indexed founder, address indexed initialLeader, uint256 timestamp);
    event PartyJoined(uint256 indexed partyId, address indexed member, uint256 indexed blockNumber, uint256 timestamp);
    event PartyLeft(uint256 indexed partyId, address indexed member, uint256 indexed blockNumber, uint256 timestamp);
    event MemberRemoved(uint256 indexed partyId, address indexed member, address indexed remover, uint256 timestamp);
    event LeadershipTransferred(uint256 indexed partyId, address indexed previousLeader, address indexed newLeader, bool forced, uint256 timestamp);
    event PartyStatusChanged(uint256 indexed partyId, uint8 oldStatus, uint8 newStatus, address indexed by, uint256 timestamp);
    event OfficialLinkUpdated(uint256 indexed partyId, string officialLink, uint256 timestamp);
    event PartyNameUpdated(uint256 indexed partyId, string name, uint256 timestamp);
    event PartyDescriptionUpdated(uint256 indexed partyId, string description, uint256 timestamp);
    event EmergencyPause(bool indexed paused, address indexed by, uint256 timestamp);
    event SnapshotTaken(uint256 indexed timestamp, uint256 indexed blockNumber, uint256 partiesProcessed);
    event PartyMembershipSnapshot(uint256 indexed partyId, uint256 indexed snapshotId, uint256 memberCount, uint256 timestamp);
    event RegistryDeployed(address indexed initialOwner, uint256 timestamp);

    // Modifiers
    modifier onlyPartyMember(uint256 _partyId) {
        require(parties[_partyId].members[msg.sender], "Not a party member");
        _;
    }

    modifier onlyPartyLeader(uint256 _partyId) {
        require(msg.sender == parties[_partyId].currentLeader, "Not the party leader");
        _;
    }

    modifier partyExists(uint256 _partyId) {
        require(_partyId < partyCount, "Party does not exist");
        _;
    }

    modifier partyActive(uint256 _partyId) {
        require(parties[_partyId].status == PARTY_STATUS_ACTIVE, "Party is not active");
        _;
    }
    
    modifier partyPending(uint256 _partyId) {
        require(parties[_partyId].status == PARTY_STATUS_PENDING, "Party is not pending");
        _;
    }
    
    modifier validString(string memory str) {
        require(bytes(str).length > 0, "String cannot be empty");
        require(bytes(str).length <= MAX_STRING_LENGTH, "String too long");
        _;
    }

    /**
     * @notice Initialize the contract with owner address
     * @param initialOwner The initial owner of the contract
     */
    constructor(address initialOwner) 
        Ownable(initialOwner) 
    {
        emit RegistryDeployed(initialOwner, block.timestamp);
    }

    /**
     * @notice Create a new political party (in pending state)
     * @param _name Name of the party
     * @param _description Brief description of the party
     * @param _officialLink Link to party website or community
     * @return partyId ID of the created party
     */
    function createParty(
        string memory _name, 
        string memory _description, 
        string memory _officialLink
    ) 
        external 
        whenNotPaused 
        nonReentrant
        validString(_name)
        validString(_description)
        validString(_officialLink)
        returns (uint256 partyId)
    {
        uint256 newPartyId = partyCount++;
        Party storage party = parties[newPartyId];
        
        party.name = _name;
        party.description = _description;
        party.officialLink = _officialLink;
        party.founder = msg.sender;
        party.currentLeader = msg.sender;
        party.creationTime = block.timestamp;
        party.status = PARTY_STATUS_PENDING; // Start in pending state
        party.members[msg.sender] = true;
        party.memberCount = 1;
        
        party.stats.lastActivityTimestamp = block.timestamp;
        
        _userParties[msg.sender].push(newPartyId);
        _userLeaderships[msg.sender].push(newPartyId);
        _pendingPartiesCount++;
        
        emit PartyCreated(newPartyId, _name, msg.sender, msg.sender, block.timestamp);
        return newPartyId;
    }

    /**
     * @notice Join a political party
     * @param _partyId ID of the party to join
     */
    function joinParty(uint256 _partyId) external 
        partyExists(_partyId) 
        partyActive(_partyId) 
        whenNotPaused
        nonReentrant
    {
        require(!parties[_partyId].members[msg.sender], "Already a member");
        
        parties[_partyId].members[msg.sender] = true;
        parties[_partyId].memberCount++;
        
        _userParties[msg.sender].push(_partyId);
        
        parties[_partyId].stats.memberJoins++;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        emit PartyJoined(_partyId, msg.sender, block.number, block.timestamp);
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
        require(msg.sender != parties[_partyId].currentLeader, "Current leader cannot leave");
        
        parties[_partyId].members[msg.sender] = false;
        parties[_partyId].memberCount--;
        
        _removeFromUserParties(msg.sender, _partyId);
        
        parties[_partyId].stats.memberLeaves++;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        emit PartyLeft(_partyId, msg.sender, block.number, block.timestamp);
    }
    
    /**
     * @notice Remove a member from a party (leader only)
     * @param _partyId ID of the party
     * @param _member Address of the member to remove
     */
    function removeMember(uint256 _partyId, address _member) external
        partyExists(_partyId)
        partyActive(_partyId)
        onlyPartyLeader(_partyId)
        whenNotPaused
        nonReentrant
    {
        require(_member != address(0), "Zero address");
        require(parties[_partyId].members[_member], "Not a member");
        require(_member != parties[_partyId].currentLeader, "Cannot remove leader");
        
        parties[_partyId].members[_member] = false;
        parties[_partyId].memberCount--;
        
        _removeFromUserParties(_member, _partyId);
        
        parties[_partyId].stats.memberLeaves++;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        emit MemberRemoved(_partyId, _member, msg.sender, block.timestamp);
    }

    /**
     * @notice Transfer party leadership to another member
     * @param _partyId ID of the party
     * @param _newLeader Address of the new leader
     */
    function transferLeadership(uint256 _partyId, address _newLeader) external 
        partyExists(_partyId) 
        partyActive(_partyId) 
        onlyPartyLeader(_partyId)
        whenNotPaused
        nonReentrant
    {
        require(_newLeader != address(0), "Zero address");
        require(parties[_partyId].members[_newLeader], "New leader must be a party member");
        require(_newLeader != msg.sender, "Already the leader");
        
        // Check if the new leader already leads an active party
        (bool hasLeadership, ) = _hasActiveLeadership(_newLeader);
        if (hasLeadership) {
            revert("New leader already leads an active party");
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
     * @notice Update party's official link
     * @param _partyId ID of the party
     * @param _officialLink New official link
     */
    function updateOfficialLink(uint256 _partyId, string memory _officialLink) external 
        partyExists(_partyId) 
        partyActive(_partyId) 
        onlyPartyLeader(_partyId)
        whenNotPaused
        validString(_officialLink)
    {
        parties[_partyId].officialLink = _officialLink;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        emit OfficialLinkUpdated(_partyId, _officialLink, block.timestamp);
    }

    /**
     * @notice Update party's name
     * @param _partyId ID of the party
     * @param _name New party name
     */
    function updatePartyName(uint256 _partyId, string memory _name) external 
        partyExists(_partyId) 
        partyActive(_partyId) 
        onlyPartyLeader(_partyId)
        whenNotPaused
        validString(_name)
    {
        parties[_partyId].name = _name;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        emit PartyNameUpdated(_partyId, _name, block.timestamp);
    }

    /**
     * @notice Update party's description
     * @param _partyId ID of the party
     * @param _description New party description
     */
    function updatePartyDescription(uint256 _partyId, string memory _description) external 
        partyExists(_partyId) 
        partyActive(_partyId) 
        onlyPartyLeader(_partyId)
        whenNotPaused
        validString(_description)
    {
        parties[_partyId].description = _description;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        emit PartyDescriptionUpdated(_partyId, _description, block.timestamp);
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
        require(msg.sender == owner() || msg.sender == parties[_partyId].currentLeader, 
                "Only owner or leader can deactivate");
        require(parties[_partyId].status != PARTY_STATUS_INACTIVE, "Party already inactive");
        
        uint8 oldStatus = parties[_partyId].status;
        parties[_partyId].status = PARTY_STATUS_INACTIVE;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        
        if (oldStatus == PARTY_STATUS_ACTIVE) {
            _activePartiesCount--;
        } else if (oldStatus == PARTY_STATUS_PENDING) {
            _pendingPartiesCount--;
        }
        
        emit PartyStatusChanged(_partyId, oldStatus, PARTY_STATUS_INACTIVE, msg.sender, block.timestamp);
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
        require(parties[_partyId].status == PARTY_STATUS_INACTIVE, "Party not inactive");
        
        parties[_partyId].status = PARTY_STATUS_PENDING;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        _pendingPartiesCount++;
        
        emit PartyStatusChanged(_partyId, PARTY_STATUS_INACTIVE, PARTY_STATUS_PENDING, msg.sender, block.timestamp);
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
            revert("Leader already has an active party");
        }
        
        parties[_partyId].status = PARTY_STATUS_ACTIVE;
        parties[_partyId].stats.lastActivityTimestamp = block.timestamp;
        _pendingPartiesCount--;
        _activePartiesCount++;
        
        emit PartyStatusChanged(_partyId, PARTY_STATUS_PENDING, PARTY_STATUS_ACTIVE, msg.sender, block.timestamp);
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
        require(_newLeader != address(0), "Zero address");
        require(parties[_partyId].members[_newLeader], "New leader must be a party member");
        
        // For active parties, check if the new leader already leads an active party
        if (parties[_partyId].status == PARTY_STATUS_ACTIVE) {
            (bool hasLeadership, uint256 leadPartyId) = _hasActiveLeadership(_newLeader);
            if (hasLeadership && leadPartyId != _partyId) {
                revert("New leader already leads an active party");
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
    
    /**
     * @notice Pause the contract in case of emergency (owner only)
     */
    function togglePause() external onlyOwner {
        if (paused()) {
            _unpause();
        } else {
            _pause();
        }
        
        emit EmergencyPause(paused(), msg.sender, block.timestamp);
    }

    /**
     * @notice Set how many snapshots to retain per party
     * @param _count Number of snapshots to keep (0 means keep all)
     */
    function setSnapshotRetentionCount(uint256 _count) external onlyOwner {
        _snapshotRetentionCount = _count;
    }

    /**
     * @notice Take a membership snapshot of active parties with pagination
     * @param _startPartyId ID to start processing from (inclusive)
     * @param _batchSize Maximum number of parties to process in this transaction
     * @return nextPartyId The next party ID to process (for subsequent calls)
     * @return processed Number of parties processed in this call
     */
    function takeSnapshotBatch(uint256 _startPartyId, uint256 _batchSize) external 
        onlyOwner 
        nonReentrant 
        returns (uint256 nextPartyId, uint256 processed) 
    {
        require(_startPartyId < partyCount, "Invalid start ID");
        require(_batchSize > 0, "Batch size must be positive");
        
        uint256 currentTime = block.timestamp;
        uint256 currentBlock = block.number;
        
        uint256 processedCount = 0;
        uint256 i = _startPartyId;
        uint256 endId = _startPartyId + _batchSize;
        
        if (endId > partyCount) {
            endId = partyCount;
        }
        
        for (; i < endId; i++) {
            if (parties[i].status == PARTY_STATUS_ACTIVE) {
                _partySnapshots[i].push(MembershipSnapshot({
                    timestamp: currentTime,
                    blockNumber: currentBlock,
                    memberCount: parties[i].memberCount
                }));
                
                if (_snapshotRetentionCount > 0 && _partySnapshots[i].length > _snapshotRetentionCount) {
                    uint256 excessCount = _partySnapshots[i].length - _snapshotRetentionCount;
                    
                    MembershipSnapshot[] memory tempSnapshots = new MembershipSnapshot[](_snapshotRetentionCount);
                    for (uint256 j = 0; j < _snapshotRetentionCount; j++) {
                        tempSnapshots[j] = _partySnapshots[i][excessCount + j];
                    }
                    
                    delete _partySnapshots[i];
                    for (uint256 j = 0; j < _snapshotRetentionCount; j++) {
                        _partySnapshots[i].push(tempSnapshots[j]);
                    }
                }
                
                emit PartyMembershipSnapshot(i, _partySnapshots[i].length - 1, parties[i].memberCount, currentTime);
                processedCount++;
            }
        }
        
        // Update last snapshot time only after complete snapshot
        if (i >= partyCount) {
            _lastSnapshotTime = currentTime;
            emit SnapshotTaken(currentTime, currentBlock, processedCount);
        }
        
        return (i < partyCount ? i : 0, processedCount);
    }
    
    /**
     * @notice Helper function to check snapshot status
     * @return lastSnapshotTime Last time a complete snapshot was taken
     * @return totalParties Total number of parties
     * @return activeParties Total number of active parties
     * @return pendingParties Total number of pending parties
     */
    function getSnapshotStatus() external view returns (
        uint256 lastSnapshotTime,
        uint256 totalParties,
        uint256 activeParties,
        uint256 pendingParties
    ) {
        return (_lastSnapshotTime, partyCount, _activePartiesCount, _pendingPartiesCount);
    }

    /**
     * @notice Get a party's latest membership snapshot
     * @param _partyId ID of the party
     * @return timestamp When the snapshot was taken
     * @return blockNumber Block number when snapshot was taken
     * @return memberCount Number of members at snapshot time
     */
    function getLatestPartySnapshot(uint256 _partyId) external view
        partyExists(_partyId)
        returns (uint256 timestamp, uint256 blockNumber, uint256 memberCount)
    {
        require(_partySnapshots[_partyId].length > 0, "No snapshots exist for this party");
        
        MembershipSnapshot storage snapshot = _partySnapshots[_partyId][_partySnapshots[_partyId].length - 1];
        return (snapshot.timestamp, snapshot.blockNumber, snapshot.memberCount);
    }

    /**
     * @notice Get the snapshot history for a party
     * @param _partyId ID of the party
     * @param _startIndex Starting index (0 is oldest if not pruned)
     * @param _count Number of snapshots to retrieve
     * @return timestamps Array of snapshot timestamps
     * @return memberCounts Array of member counts
     */
    function getPartySnapshotHistory(
        uint256 _partyId, 
        uint256 _startIndex, 
        uint256 _count
    ) 
        external 
        view
        partyExists(_partyId)
        returns (
            uint256[] memory timestamps,
            uint256[] memory memberCounts
        ) 
    {
        uint256 snapshotCount = _partySnapshots[_partyId].length;
        require(snapshotCount > 0, "No snapshots for this party");
        require(_startIndex < snapshotCount, "Start index out of range");
        
        uint256 endIndex = _startIndex + _count;
        if (endIndex > snapshotCount) {
            endIndex = snapshotCount;
        }
        
        uint256 resultSize = endIndex - _startIndex;
        timestamps = new uint256[](resultSize);
        memberCounts = new uint256[](resultSize);
        
        for (uint256 i = 0; i < resultSize; i++) {
            uint256 index = _startIndex + i;
            timestamps[i] = _partySnapshots[_partyId][index].timestamp;
            memberCounts[i] = _partySnapshots[_partyId][index].memberCount;
        }
        
        return (timestamps, memberCounts);
    }

    /**
     * @dev Internal function to remove a party ID from a user's list
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
     * @dev Internal function to remove a party ID from a user's leadership list
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
     * @notice Internal function to record leadership changes
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
            if (parties[partyId].status == PARTY_STATUS_ACTIVE) {
                return (true, partyId);
            }
        }
        return (false, 0);
    }

    // View functions

    /**
     * @notice Check if an address is a member of a party
     * @param _partyId ID of the party
     * @param _member Address to check
     * @return True if address is a member
     */
    function isMember(uint256 _partyId, address _member) external view 
        partyExists(_partyId) 
        returns (bool) 
    {
        return parties[_partyId].members[_member];
    }

    /**
     * @notice Get party details
     * @param _partyId ID of the party
     * @return name The name of the party
     * @return description Brief description of the party
     * @return officialLink Link to party website or community
     * @return founder Address of the party founder
     * @return currentLeader Address of the current party leader
     * @return creationTime Timestamp when the party was created
     * @return status Party status (0=pending, 1=active, 2=inactive)
     * @return memberCount Number of members in the party
     */
    function getPartyDetails(uint256 _partyId) external view 
        partyExists(_partyId) 
        returns (
            string memory name,
            string memory description,
            string memory officialLink,
            address founder,
            address currentLeader,
            uint256 creationTime,
            uint8 status,
            uint256 memberCount
        ) 
    {
        Party storage party = parties[_partyId];
        return (
            party.name,
            party.description,
            party.officialLink,
            party.founder,
            party.currentLeader,
            party.creationTime,
            party.status,
            party.memberCount
        );
    }
    
    /**
     * @notice Get party statistics
     * @param _partyId ID of the party
     * @return leadershipChanges Number of times leadership has changed
     * @return memberJoins Number of times members have joined
     * @return memberLeaves Number of times members have left
     * @return lastActivityTimestamp Timestamp of the last activity in the party
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
        return (
            stats.leadershipChanges,
            stats.memberJoins,
            stats.memberLeaves,
            stats.lastActivityTimestamp
        );
    }
    
    /**
     * @notice Get leadership history count
     * @param _partyId ID of the party
     * @return Number of leadership changes
     */
    function getLeadershipHistoryCount(uint256 _partyId) external view
        partyExists(_partyId)
        returns (uint256)
    {
        return parties[_partyId].leadershipHistory.length;
    }
    
    /**
     * @notice Get leadership history entry
     * @param _partyId ID of the party
     * @param _index Index of the leadership change
     * @return previousLeader Address of the previous leader
     * @return newLeader Address of the new leader
     * @return timestamp Time when the leadership change occurred
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
        require(_index < parties[_partyId].leadershipHistory.length, "Index out of bounds");
        LeadershipChange storage change = parties[_partyId].leadershipHistory[_index];
        return (
            change.previousLeader,
            change.newLeader,
            change.timestamp,
            change.forced
        );
    }

    /**
     * @notice Get all parties a user is a member of
     * @param _user Address of the user
     * @return Array of party IDs the user belongs to
     */
    function getUserParties(address _user) external view returns (uint256[] memory) {
        require(_user != address(0), "Zero address");
        return _userParties[_user];
    }

    /**
     * @notice Get all parties a user leads (includes active, pending, and inactive)
     * @param _user Address of the user
     * @return Array of party IDs the user leads in any status
     */
    function getUserLeaderships(address _user) external view returns (uint256[] memory) {
        require(_user != address(0), "Zero address");
        return _userLeaderships[_user];
    }

    /**
     * @notice Check if user is a leader of any parties (in any status)
     * @param _user Address of the user
     * @return isLeader Whether the user is a leader of any party
     * @return leadershipCount Number of parties the user leads
     */
    function isUserLeader(address _user) external view returns (bool isLeader, uint256 leadershipCount) {
        require(_user != address(0), "Zero address");
        leadershipCount = _userLeaderships[_user].length;
        return (leadershipCount > 0, leadershipCount);
    }

    /**
     * @notice Get total number of active parties
     * @return Number of active parties
     */
    function getActivePartyCount() external view returns (uint256) {
        return _activePartiesCount;
    }
    
    /**
     * @notice Get total number of pending parties
     * @return Number of pending parties
     */
    function getPendingPartyCount() external view returns (uint256) {
        return _pendingPartiesCount;
    }
    
    /**
     * @notice Get status of a party
     * @param _partyId ID of the party
     * @return status Party status (0=pending, 1=active, 2=inactive)
     */
    function getPartyStatus(uint256 _partyId) external view
        partyExists(_partyId)
        returns (uint8)
    {
        return parties[_partyId].status;
    }

    /**
     * @notice Check if a user already leads an active party
     * @param _user The address of the user to check
     * @return hasLeadership Whether the user leads an active party
     * @return leadPartyId The ID of the active party they lead (if any)
     */
    function hasActiveLeadership(address _user) external view returns (bool hasLeadership, uint256 leadPartyId) {
        return _hasActiveLeadership(_user);
    }
}
