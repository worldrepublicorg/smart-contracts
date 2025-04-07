// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// Interface for the main contract to interact with snapshot manager
interface IPoliticalPartyRegistry {
    function getPartyStatus(uint256 _partyId) external view returns (uint8);
    function getPartyCount() external view returns (uint256);
    function getPartyMemberCounts(uint256 _partyId) external view returns (uint256 memberCount, uint256 verifiedMemberCount);
}

contract PartySnapshotManager is Ownable, ReentrancyGuard {
    // Data structure for snapshots
    struct MembershipSnapshot {
        uint256 timestamp;
        uint256 blockNumber;
        uint256 memberCount;
        uint256 verifiedMemberCount;
    }
    
    // Storage variables
    mapping(uint256 => MembershipSnapshot[]) private _partySnapshots;
    uint256 private _lastSnapshotTime;
    uint256 private _snapshotRetentionCount = 10;
    
    // Registry contract reference
    IPoliticalPartyRegistry public partyRegistry;
    
    // Events
    event SnapshotTaken(uint256 indexed timestamp, uint256 indexed blockNumber, uint256 partiesProcessed);
    event PartyMembershipSnapshot(uint256 indexed partyId, uint256 indexed snapshotId, uint256 memberCount, uint256 verifiedMemberCount, uint256 timestamp);
    event RegistryAddressUpdated(address indexed oldRegistry, address indexed newRegistry);
    
    // Constants
    uint8 private constant PARTY_STATUS_ACTIVE = 1;
    
    constructor(address initialOwner, address _partyRegistry) Ownable(initialOwner) {
        partyRegistry = IPoliticalPartyRegistry(_partyRegistry);
    }
    
    // Update registry address if needed (e.g., if registry is upgraded)
    function setRegistryAddress(address _newRegistry) external onlyOwner {
        address oldRegistry = address(partyRegistry);
        partyRegistry = IPoliticalPartyRegistry(_newRegistry);
        emit RegistryAddressUpdated(oldRegistry, _newRegistry);
    }
    
    // Set snapshot retention policy
    function setSnapshotRetentionCount(uint256 _count) external onlyOwner {
        _snapshotRetentionCount = _count;
    }
    
    // Take snapshots in batches
    function takeSnapshotBatch(uint256 _startPartyId, uint256 _batchSize) external 
        onlyOwner 
        nonReentrant 
        returns (uint256 nextPartyId, uint256 processed) 
    {
        uint256 partyCount = partyRegistry.getPartyCount();
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
            if (partyRegistry.getPartyStatus(i) == PARTY_STATUS_ACTIVE) {
                (uint256 memberCount, uint256 verifiedMemberCount) = partyRegistry.getPartyMemberCounts(i);
                
                _partySnapshots[i].push(MembershipSnapshot({
                    timestamp: currentTime,
                    blockNumber: currentBlock,
                    memberCount: memberCount,
                    verifiedMemberCount: verifiedMemberCount
                }));
                
                // Manage retention policy
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
                
                emit PartyMembershipSnapshot(i, _partySnapshots[i].length - 1, memberCount, 
                    verifiedMemberCount, currentTime);
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
    
    // View functions for accessing snapshot data
    function getLatestPartySnapshot(uint256 _partyId) external view
        returns (uint256 timestamp, uint256 blockNumber, uint256 memberCount, uint256 verifiedMemberCount)
    {
        require(_partySnapshots[_partyId].length > 0, "No snapshots exist for this party");
        
        MembershipSnapshot storage snapshot = _partySnapshots[_partyId][_partySnapshots[_partyId].length - 1];
        return (snapshot.timestamp, snapshot.blockNumber, snapshot.memberCount, snapshot.verifiedMemberCount);
    }
    
    function getPartySnapshotHistory(
        uint256 _partyId, 
        uint256 _startIndex, 
        uint256 _count
    ) 
        external 
        view
        returns (
            uint256[] memory timestamps,
            uint256[] memory memberCounts,
            uint256[] memory verifiedMemberCounts
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
        verifiedMemberCounts = new uint256[](resultSize);
        
        for (uint256 i = 0; i < resultSize; i++) {
            uint256 index = _startIndex + i;
            timestamps[i] = _partySnapshots[_partyId][index].timestamp;
            memberCounts[i] = _partySnapshots[_partyId][index].memberCount;
            verifiedMemberCounts[i] = _partySnapshots[_partyId][index].verifiedMemberCount;
        }
        
        return (timestamps, memberCounts, verifiedMemberCounts);
    }
    
    function getSnapshotStatus() external view returns (
        uint256 lastSnapshotTime,
        uint256 totalParties,
        uint256 retentionPolicy
    ) {
        return (_lastSnapshotTime, partyRegistry.getPartyCount(), _snapshotRetentionCount);
    }
}
