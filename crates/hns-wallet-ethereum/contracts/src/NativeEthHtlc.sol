// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.35;

/// @notice One immutable native-ETH-only HTLC implementation. This contract
/// has no administrator, owner, proxy, upgrade, pause, token, fee, arbitrary
/// call, or mutable-configuration surface.
contract NativeEthHtlc {
    enum Status {
        None,
        Locked,
        Redeemed,
        Refunded
    }

    struct LockState {
        bytes32 hashlock;
        address receiver;
        address refundAddress;
        uint64 timelock;
        uint256 amount;
        Status status;
    }

    mapping(bytes32 swapId => LockState) public locks;

    event Locked(
        bytes32 indexed swapId,
        bytes32 indexed hashlock,
        address indexed receiver,
        address refundAddress,
        uint256 amount,
        uint64 timelock
    );
    event Redeemed(bytes32 indexed swapId, bytes32 preimage, address indexed receiver);
    event Refunded(bytes32 indexed swapId, address indexed refundAddress);

    error AlreadyExists();
    error InvalidTerms();
    error InvalidState();
    error Unauthorized();
    error HashlockMismatch();
    error TimelockNotReached();
    error TransferFailed();

    function lock(
        bytes32 swapId,
        bytes32 hashlock,
        address receiver,
        address refundAddress,
        uint64 timelock
    ) external payable {
        if (
            swapId == bytes32(0) || hashlock == bytes32(0) || receiver == address(0)
                || refundAddress == address(0) || receiver == refundAddress || msg.value == 0
                || timelock <= block.timestamp
        ) revert InvalidTerms();
        if (locks[swapId].status != Status.None) revert AlreadyExists();

        locks[swapId] = LockState({
            hashlock: hashlock,
            receiver: receiver,
            refundAddress: refundAddress,
            timelock: timelock,
            amount: msg.value,
            status: Status.Locked
        });
        emit Locked(swapId, hashlock, receiver, refundAddress, msg.value, timelock);
    }

    function redeem(bytes32 swapId, bytes32 preimage) external {
        LockState storage state = locks[swapId];
        if (state.status != Status.Locked) revert InvalidState();
        if (msg.sender != state.receiver) revert Unauthorized();
        if (sha256(abi.encodePacked(preimage)) != state.hashlock) revert HashlockMismatch();

        uint256 amount = state.amount;
        address receiver = state.receiver;
        state.status = Status.Redeemed;
        emit Redeemed(swapId, preimage, receiver);
        (bool sent,) = receiver.call{value: amount}("");
        if (!sent) revert TransferFailed();
    }

    function refund(bytes32 swapId) external {
        LockState storage state = locks[swapId];
        if (state.status != Status.Locked) revert InvalidState();
        if (msg.sender != state.refundAddress) revert Unauthorized();
        if (block.timestamp < state.timelock) revert TimelockNotReached();

        uint256 amount = state.amount;
        address refundAddress = state.refundAddress;
        state.status = Status.Refunded;
        emit Refunded(swapId, refundAddress);
        (bool sent,) = refundAddress.call{value: amount}("");
        if (!sent) revert TransferFailed();
    }
}
