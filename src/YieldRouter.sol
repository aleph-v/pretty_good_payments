// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {IEntrypoint} from "./interfaces/IEntrypoint.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {
    NotBridge,
    TokenNotTransferred,
    TokenNotEnabled,
    AlreadyPaid,
    SequencerChallenged,
    EpochNotFinished
} from "./library/Errors.sol";

/// @title YieldRouter
/// @notice Routes deposited assets to ERC4626 yield sources and distributes earned yield to sequencers
/// @dev Tracks yield per period and allows sequencers to claim proportional rewards based on their blob usage

contract YieldRouter is Ownable {
    // The bridge is the contract which accepts the user deposits
    address public immutable bridge;
    mapping(address => IERC4626) public sources;

    // For tracking the yields for sequencer payouts
    address[] public trackedYieldSources;
    // Tracks the prior recorded total balance without any yield adjustments
    mapping(address => uint256) public priorBalances;
    // Maps the asset to the period to the period total payout for the asset
    mapping(address => mapping(uint256 => uint256)) public periodPayouts;
    // True if period has already been reported
    mapping(uint256 => bool) public reportedPeriod;
    // True if the sequencer has withdrawn this epoch
    mapping(address => mapping(uint256 => mapping(address => bool))) public paidOut;
    // Assets which have a max interest in each period
    mapping(address => uint256) public maxInterest;

    // Constants to track the
    uint256 immutable EPOCHS_PER_PERIOD;
    uint256 immutable START = block.timestamp;
    uint256 immutable PERIOD_LENGTH;

    /// @notice Initializes the yield router with timing parameters and tracked assets
    /// @param periodLength Duration of each yield period in seconds
    /// @param epochPerPeriod Number of epochs per yield period (yield is split evenly across epochs)
    /// @param _bridge Address of the bridge contract (only caller allowed for deposits/withdrawals)
    /// @param tracked Initial list of token addresses to track yield for
    constructor(uint256 periodLength, uint256 epochPerPeriod, address _bridge, address[] memory tracked) {
        EPOCHS_PER_PERIOD = epochPerPeriod;
        PERIOD_LENGTH = periodLength;
        bridge = _bridge;
        trackedYieldSources = tracked;
    }

    modifier onlyBridge() {
        _onlyBridge();
        _;
    }

    function _onlyBridge() internal view {
        if (msg.sender != bridge) revert NotBridge();
    }

    /// @notice This function triggers a deposit
    /// @param asset The asset we are depositing
    /// @param amount The amount of asset we are depositing
    function triggerDeposit(address asset, uint256 amount) external onlyBridge {
        if (IERC20(asset).balanceOf(address(this)) < amount) revert TokenNotTransferred();
        if (address(sources[asset]) == address(0)) revert TokenNotEnabled();
        priorBalances[asset] += amount;
        sources[asset].deposit(amount, address(this));
    }

    /// @notice This function allows the bridge to get out some assets, if there has been loss we only redeem
    ///         proportionally.
    /// @param asset The asset we are withdrawing
    /// @param amount The amount of asset we are withdrawing
    /// @param destination The place we send the funds to.
    function triggerWithdraw(address asset, uint256 amount, address destination) external onlyBridge {
        uint256 totalShares = sources[asset].balanceOf(address(this));
        uint256 currentGlobalValue = sources[asset].previewRedeem(totalShares);
        uint256 userAmount = amount;
        if (priorBalances[asset] > currentGlobalValue) {
            uint256 fixedPercent = (priorBalances[asset] * 1e18) / currentGlobalValue;
            userAmount = fixedPercent * amount / 1e18;
        }
        sources[asset].withdraw(userAmount, destination, address(this));
        priorBalances[asset] -= userAmount;
    }

    /// @notice Allows the owner to change the yield source, should be behind a long timelock to allow withdraws
    /// @param token Which token we want to change the yield source of
    /// @param newSource An erc4646 compatible yield source which we will use
    function changeYieldSource(address token, IERC4626 newSource) external onlyOwner {
        // First we withdraw from the source that currently has funds
        IERC4626 cachedSource = sources[token];
        uint256 priorBalance = 0;
        if (address(cachedSource) != address(0)) {
            uint256 shares = cachedSource.balanceOf(address(this));
            priorBalance = IERC20(token).balanceOf(address(this));
            cachedSource.redeem(shares, address(this), address(this));
            IERC20(token).approve(address(cachedSource), 0);
        }

        // Now we move the funds into a new source
        uint256 toMove = IERC20(token).balanceOf(address(this)) - priorBalance;
        IERC20(token).approve(address(newSource), type(uint256).max);
        newSource.deposit(toMove, address(this));
        sources[token] = newSource;
    }

    /// @notice Records yield for all tracked assets in the current period
    /// @dev Iterates through trackedYieldSources and calls _record for each. No-op if period already reported.
    ///      If yield exceeds maxInterest for an asset, excess is held for the next period.
    function poke() public {
        uint256 period = currentPeriod();
        if (!reportedPeriod[period]) {
            for (uint256 i = 0; i < trackedYieldSources.length; i++) {
                address token = trackedYieldSources[i];
                _record(token, period);
            }
            reportedPeriod[period] = true;
        }
    }

    /// @notice Allows us to report yield for tokens which are not in the tracked list
    /// @param token The token we will record the interest of in this period
    function recognizeYield(address token) public {
        uint256 period = currentPeriod();
        _record(token, period);
    }

    /// @notice Internal function which actually does the math for interest recording, has no effect after the first time
    /// @param token The token which has earned yield
    /// @param period The period we are recording in
    function _record(address token, uint256 period) internal {
        if (periodPayouts[token][period] == 0) {
            uint256 lastBalance = priorBalances[token];
            uint256 totalShares = sources[token].balanceOf(address(this));
            uint256 value = sources[token].previewRedeem(totalShares);
            // Compute the actual value of the interest
            uint256 payment = value >= lastBalance ? value - lastBalance : 0;
            // If the period has more interest than max we move it into the next
            // by only increasing the tracked prior balance by 'maxInterest'
            if (maxInterest[token] != 0 && payment > maxInterest[token]) {
                payment = maxInterest[token];
            }
            periodPayouts[token][period] = payment;
            priorBalances[token] += payment;
        }
    }

    /// @notice Helper function to group many calls to sequencerWithdrawAsset
    /// @param sequencer The credited sequencer
    /// @param epochs The epocs we will claim all assets for
    function withdrawMany(address sequencer, uint256[] memory epochs) external {
        for (uint256 i = 0; i < trackedYieldSources.length; i++) {
            for (uint256 j = 0; j < epochs.length; j++) {
                sequencerWithdrawAsset(trackedYieldSources[i], sequencer, epochs[j]);
            }
        }
    }

    /// @notice Withdraws a single asset based on the percent and total yield for an epoch
    /// @param token The asset we will withdraw value for
    /// @param sequencer The credited sequencer
    /// @param epoch The epoch number
    function sequencerWithdrawAsset(address token, address sequencer, uint256 epoch) public {
        if (paidOut[sequencer][epoch][token]) revert AlreadyPaid();
        IEntrypoint cached = IEntrypoint(bridge);
        if (cached.isChallenged(sequencer)) revert SequencerChallenged();
        if (!cached.isFinalized(epoch)) revert EpochNotFinished();
        uint256 percent = cached.getPercentInEpoch(sequencer, epoch);

        uint256 period = epoch / EPOCHS_PER_PERIOD;
        uint256 paidInEpoch = periodPayouts[token][period] / EPOCHS_PER_PERIOD;
        uint256 amount = (paidInEpoch * percent) / 1e18;
        paidOut[sequencer][epoch][token] = true;
        sources[token].withdraw(amount, sequencer, address(this));
    }

    /// @notice Computes the current period based on elapsed time since contract deployment
    /// @return The current period number (0-indexed)
    function currentPeriod() public view returns (uint256) {
        return ((block.timestamp - START) / PERIOD_LENGTH);
    }

    /// @notice Changes the tracked yield source array
    /// @param addresses The new tracked addresses
    function changeTrackedYieldSources(address[] memory addresses) external onlyOwner {
        trackedYieldSources = addresses;
    }

    /// @notice Sets a max interest value for an asset
    /// @param token The token we are setting the max for
    /// @param max The most interest we pay out for this
    function setMaxInterest(address token, uint256 max) external onlyOwner {
        maxInterest[token] = max;
    }
}
