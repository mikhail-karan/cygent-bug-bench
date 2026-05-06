// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract GovernanceToken is ERC20, Ownable {
    mapping(address => bool) public blacklisted;

    event TokensMinted(address indexed to, uint256 amount);
    event UserStatusUpdated(address indexed user, bool status);

    constructor() ERC20("DeFiHub Governance", "DFHG") Ownable(msg.sender) {
        _mint(msg.sender, 1000000 * 10 ** decimals());
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
        emit TokensMinted(to, amount);
    }

    function updateUserStatus(address user, bool status) external onlyOwner {
        blacklisted[user] = status;
        emit UserStatusUpdated(user, status);
    }

    function transfer(address to, uint256 value) public override returns (bool) {
        require(!blacklisted[msg.sender], "Sender is blacklisted");
        require(!blacklisted[to], "Recipient is blacklisted");
        return super.transfer(to, value);
    }

    function transferFrom(address from, address to, uint256 value) public override returns (bool) {
        require(!blacklisted[from], "Sender is blacklisted");
        require(!blacklisted[to], "Recipient is blacklisted");
        return super.transferFrom(from, to, value);
    }
}

contract GroupStaking is Ownable {
    struct StakingGroup {
        uint256 id;
        uint256 totalAmount;
        address owner;
        address[] members;
        uint256[] weights;
        bool exists;
    }

    GovernanceToken public immutable token;
    uint256 private nextGroupId = 1;

    mapping(uint256 => StakingGroup) private groups;
    mapping(uint256 => mapping(address => bool)) private memberInGroup;

    constructor(address tokenAddress) Ownable(msg.sender) {
        token = GovernanceToken(tokenAddress);
    }

    function createStakingGroup(
        address[] memory members,
        uint256[] memory weights
    ) external returns (uint256 groupId) {
        require(members.length > 0, "Empty members list");
        require(members.length == weights.length, "Members and weights length mismatch");

        uint256 totalWeight;
        for (uint256 i = 0; i < weights.length; i++) {
            totalWeight += weights[i];
        }
        require(totalWeight == 100, "Weights must sum to 100");

        groupId = nextGroupId;
        nextGroupId += 1;

        StakingGroup storage group = groups[groupId];
        group.id = groupId;
        group.owner = msg.sender;
        group.exists = true;

        for (uint256 i = 0; i < members.length; i++) {
            group.members.push(members[i]);
            group.weights.push(weights[i]);
            memberInGroup[groupId][members[i]] = true;
        }
    }

    function stakeToGroup(uint256 groupId, uint256 amount) external {
        StakingGroup storage group = groups[groupId];
        require(group.exists, "Group does not exist");

        token.transferFrom(msg.sender, address(this), amount);
        group.totalAmount += amount;
    }

    function withdrawFromGroup(uint256 groupId, uint256 amount) external {
        StakingGroup storage group = groups[groupId];
        require(group.exists, "Group does not exist");
        require(group.totalAmount >= amount, "Insufficient group balance");
        require(msg.sender == group.owner, "Not the group owner");

        group.totalAmount -= amount;

        for (uint256 i = 0; i < group.members.length; i++) {
            uint256 share = (amount * group.weights[i]) / 100;
            if (share > 0) {
                token.transfer(group.members[i], share);
            }
        }
    }

    function getGroupInfo(
        uint256 groupId
    )
        external
        view
        returns (
            uint256 id,
            uint256 totalAmount,
            address[] memory members,
            uint256[] memory weights
        )
    {
        StakingGroup storage group = groups[groupId];
        require(group.exists, "Group does not exist");

        return (group.id, group.totalAmount, group.members, group.weights);
    }

    function isMemberOfGroup(uint256 groupId, address member) external view returns (bool) {
        return memberInGroup[groupId][member];
    }
}
