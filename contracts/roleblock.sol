// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title Roleblack
 * @dev A smart contract for role-based access control with blacklisting functionality
 * @author Roleblack Team
 */
contract Roleblack {
    
    // Events
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    event AddressBlacklisted(address indexed account, address indexed sender);
    event AddressWhitelisted(address indexed account, address indexed sender);
    
    // Role definitions
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MODERATOR_ROLE = keccak256("MODERATOR_ROLE");
    bytes32 public constant USER_ROLE = keccak256("USER_ROLE");
    
    // Storage
    mapping(bytes32 => mapping(address => bool)) private _roles;
    mapping(address => bool) private _blacklisted;
    mapping(bytes32 => uint256) private _roleCount;
    
    address public owner;
    uint256 public totalBlacklisted;
    
    // Modifiers
    modifier onlyRole(bytes32 role) {
        require(hasRole(role, msg.sender), "Roleblack: insufficient permissions");
        _;
    }
    
    modifier notBlacklisted(address account) {
        require(!_blacklisted[account], "Roleblack: address is blacklisted");
        _;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Roleblack: caller is not the owner");
        _;
    }
    
    constructor() {
        owner = msg.sender;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
    
    /**
     * @dev Core Function 1: Role Management
     * Grant or revoke roles to/from addresses
     */
    function manageRole(bytes32 role, address account, bool grant) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
        notBlacklisted(account) 
    {
        require(account != address(0), "Roleblack: invalid address");
        
        if (grant) {
            if (!hasRole(role, account)) {
                _grantRole(role, account);
            }
        } else {
            if (hasRole(role, account)) {
                _revokeRole(role, account);
            }
        }
    }
    
    /**
     * @dev Core Function 2: Blacklist Management
     * Add or remove addresses from blacklist
     */
    function manageBlacklist(address account, bool blacklist) 
        external 
        onlyRole(MODERATOR_ROLE) 
    {
        require(account != address(0), "Roleblack: invalid address");
        require(account != owner, "Roleblack: cannot blacklist owner");
        require(_blacklisted[account] != blacklist, "Roleblack: address already in desired state");
        
        _blacklisted[account] = blacklist;
        
        if (blacklist) {
            // Remove all roles when blacklisting
            _revokeAllRoles(account);
            totalBlacklisted++;
            emit AddressBlacklisted(account, msg.sender);
        } else {
            totalBlacklisted--;
            emit AddressWhitelisted(account, msg.sender);
        }
    }
    
    /**
     * @dev Core Function 3: Access Control Check
     * Comprehensive permission checking for external contracts
     */
    function checkAccess(address account, bytes32 role) 
        external 
        view 
        returns (bool hasAccess, string memory status) 
    {
        if (_blacklisted[account]) {
            return (false, "BLACKLISTED");
        }
        
        if (hasRole(role, account)) {
            return (true, "AUTHORIZED");
        }
        
        if (hasRole(DEFAULT_ADMIN_ROLE, account)) {
            return (true, "ADMIN_ACCESS");
        }
        
        return (false, "INSUFFICIENT_PERMISSIONS");
    }
    
    // View functions
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }
    
    function isBlacklisted(address account) external view returns (bool) {
        return _blacklisted[account];
    }
    
    function getRoleCount(bytes32 role) external view returns (uint256) {
        return _roleCount[role];
    }
    
    function getContractStats() external view returns (
        uint256 adminCount,
        uint256 moderatorCount,
        uint256 userCount,
        uint256 blacklistedCount
    ) {
        return (
            _roleCount[DEFAULT_ADMIN_ROLE],
            _roleCount[MODERATOR_ROLE],
            _roleCount[USER_ROLE],
            totalBlacklisted
        );
    }
    
    // Internal functions
    function _grantRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
        _roleCount[role]++;
        emit RoleGranted(role, account, msg.sender);
    }
    
    function _revokeRole(bytes32 role, address account) internal {
        _roles[role][account] = false;
        _roleCount[role]--;
        emit RoleRevoked(role, account, msg.sender);
    }
    
    function _revokeAllRoles(address account) internal {
        if (_roles[DEFAULT_ADMIN_ROLE][account]) {
            _revokeRole(DEFAULT_ADMIN_ROLE, account);
        }
        if (_roles[MODERATOR_ROLE][account]) {
            _revokeRole(MODERATOR_ROLE, account);
        }
        if (_roles[USER_ROLE][account]) {
            _revokeRole(USER_ROLE, account);
        }
    }
    
    // Emergency functions
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Roleblack: new owner is the zero address");
        require(!_blacklisted[newOwner], "Roleblack: new owner is blacklisted");
        
        _revokeRole(DEFAULT_ADMIN_ROLE, owner);
        _grantRole(DEFAULT_ADMIN_ROLE, newOwner);
        owner = newOwner;
    }

C:\Users\princ\OneDrive\Pictures\Screenshots 1\Screenshot 2025-09-30 041306.png
