// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// ByteHasher library inlined
library ByteHasher {
    /// @dev Creates a keccak256 hash of a bytestring.
    /// @param value The bytestring to hash
    /// @return The hash of the specified value
    /// @dev `>> 8` makes sure that the result is included in our field
    function hashToField(bytes memory value) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(value))) >> 8;
    }
}

// IWorldID interface inlined
interface IWorldID {
    /// @notice Reverts if the zero-knowledge proof is invalid.
    /// @param root The of the Merkle tree
    /// @param groupId The id of the Semaphore group
    /// @param signalHash A keccak256 hash of the Semaphore signal
    /// @param nullifierHash The nullifier hash
    /// @param externalNullifierHash A keccak256 hash of the external nullifier
    /// @param proof The zero-knowledge proof
    /// @dev  Note that a double-signaling check is not included here, and should be carried by the caller.
    function verifyProof(
        uint256 root,
        uint256 groupId,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) external view;
}

// Interface for the World Address Book contract
interface IAddressBook {
    function addressVerifiedUntil(address addr) external view returns (uint256);
}

/**
 * @title SecureDocumentReferralReward
 * @dev A contract that allows verified accounts to reward one other user with tokens, once.
 * Uses both World ID and AddressBook for verification.
 */
contract SecureDocumentReferralReward is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using ByteHasher for bytes;

    // The ERC20 token used for rewards
    IERC20 public immutable rewardToken;
    
    // Hardcoded address of the verification contract
    address public constant ADDRESS_BOOK = 0x57b930D551e677CC36e2fA036Ae2fe8FdaE0330D;
    
    // World ID integration
    uint256 internal constant GROUP_ID = 1;
    IWorldID internal immutable WORLD_ID;
    uint256 internal immutable EXTERNAL_NULLIFIER;
    
    // Fixed reward amount
    uint256 public constant REWARD_AMOUNT = 50 * 10**18; // 50 tokens with 18 decimals
    
    // Mapping to track who has rewarded whom (rewarder => rewarded)
    // If address(0), the rewarder has not rewarded anyone yet
    mapping(address => address) public rewardedUser;
    
    // Mapping to track how many times an address has been rewarded
    mapping(address => uint256) public rewardCount;
    
    // Mapping to track verified World ID nullifier hashes
    mapping(uint256 => bool) public nullifierHashes;
    
    // Events
    event RewardSent(address indexed sender, address indexed recipient, uint256 amount);
    event TokensDeposited(address indexed owner, uint256 amount);
    event TokensWithdrawn(address indexed owner, uint256 amount);

    /**
     * @dev Constructor sets the reward token and World ID parameters
     * @param _rewardToken The ERC20 token to be used for rewards
     * @param _worldId The World ID instance to verify against
     * @param _appId The World ID app ID
     * @param _actionId The World ID action ID for this specific action
     */
    constructor(
        address _rewardToken,
        IWorldID _worldId,
        string memory _appId,
        string memory _actionId
    ) Ownable(msg.sender) {
        require(_rewardToken != address(0), "Invalid token address");
        rewardToken = IERC20(_rewardToken);
        
        // Initialize World ID verification
        WORLD_ID = _worldId;
        EXTERNAL_NULLIFIER = abi.encodePacked(abi.encodePacked(_appId).hashToField(), _actionId).hashToField();
    }

    /**
     * @dev Allows a verified user to reward another user with tokens
     * @param recipient The address of the recipient
     * @param root The root of the Merkle tree used for verification
     * @param nullifierHash The nullifier hash for this proof
     * @param proof The zero-knowledge proof that demonstrates user is registered with World ID
     */
    function rewardUser(
        address recipient,
        uint256 root,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) external nonReentrant {
        // Verify sender using AddressBook
        require(
            IAddressBook(ADDRESS_BOOK).addressVerifiedUntil(msg.sender) == 0,
            "Sender not verified in AddressBook"
        );
        
        // Check that sender isn't rewarding themselves
        require(msg.sender != recipient, "Cannot reward yourself");
        
        // Check that recipient is not address(0)
        require(recipient != address(0), "Cannot reward zero address");
        
        // Check that sender hasn't already rewarded someone
        require(rewardedUser[msg.sender] == address(0), "Already rewarded someone");

        // Ensure this nullifier hash hasn't been used before
        require(!nullifierHashes[nullifierHash], "Nullifier hash has been already used");
        
        // Verify proof of personhood with World ID
        WORLD_ID.verifyProof(
            root,
            GROUP_ID,
            abi.encodePacked(msg.sender).hashToField(),
            nullifierHash,
            EXTERNAL_NULLIFIER,
            proof
        );
        
        // Mark the nullifier hash as used
        nullifierHashes[nullifierHash] = true;
        
        // Check contract has enough balance
        require(rewardToken.balanceOf(address(this)) >= REWARD_AMOUNT, "Insufficient contract balance");
        
        // Record who the sender rewarded
        rewardedUser[msg.sender] = recipient;
        
        // Increment the reward count for the recipient
        rewardCount[recipient]++;
        
        // Send the tokens
        rewardToken.safeTransfer(recipient, REWARD_AMOUNT);
        
        emit RewardSent(msg.sender, recipient, REWARD_AMOUNT);
    }

    /**
     * @dev Allows the owner to deposit reward tokens
     * @param amount The amount of tokens to deposit
     */
    function depositTokens(uint256 amount) external onlyOwner nonReentrant {
        require(amount > 0, "Amount must be greater than 0");
        
        rewardToken.safeTransferFrom(msg.sender, address(this), amount);
        
        emit TokensDeposited(msg.sender, amount);
    }

    /**
     * @dev Allows the owner to withdraw reward tokens
     * @param amount The amount of tokens to withdraw
     */
    function withdrawTokens(uint256 amount) external onlyOwner nonReentrant {
        require(amount > 0, "Amount must be greater than 0");
        require(rewardToken.balanceOf(address(this)) >= amount, "Insufficient balance");
        
        rewardToken.safeTransfer(msg.sender, amount);
        
        emit TokensWithdrawn(msg.sender, amount);
    }
    
    /**
     * @dev Checks if a sender has already rewarded someone
     * @param sender The sender address to check
     * @return hasRewarded Whether the sender has rewarded anyone
     * @return recipient The address that was rewarded (if any)
     */
    function checkReward(address sender) external view returns (bool hasRewarded, address recipient) {
        recipient = rewardedUser[sender];
        hasRewarded = recipient != address(0);
        return (hasRewarded, recipient);
    }
    
    /**
     * @dev Gets the number of times an address has been rewarded
     * @param user The address to check
     * @return The number of times the address has been rewarded
     */
    function getRewardCount(address user) external view returns (uint256) {
        return rewardCount[user];
    }
    
    /**
     * @dev Check if a user is eligible to reward (verified in AddressBook and hasn't rewarded already)
     * @param user The address to check
     * @return Whether the user can reward someone
     */
    function canReward(address user) external view returns (bool) {
        return IAddressBook(ADDRESS_BOOK).addressVerifiedUntil(user) == 0 && 
               rewardedUser[user] == address(0);
    }
    
    /**
     * @dev Gets the total token balance of the contract
     * @return The token balance
     */
    function getContractBalance() external view returns (uint256) {
        return rewardToken.balanceOf(address(this));
    }
} 