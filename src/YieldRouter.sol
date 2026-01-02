// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {Ownable} from "solady/auth/Ownable.sol";

// TODO we can optimism this state usage a lot I think. Possibly we can do this with a globalized payout system?
//      At very least I think we can do a period power system instead of an epoch system?

contract YieldRouter is Ownable {
    // The bridge is the contract which accepts the user deposits
    address immutable bridge;
    mapping(address => IERC4626) sources;

    // For tracking the yields for sequencer payouts
    address[] trackedYieldSources;
    // Tracks the prior recorded total balance without any yield adjustments
    mapping(address => uint256) priorBalances;
    // Maps the asset to the period to the period total payout for the asset
    mapping(address => mapping(uint256 => uint256)) periodPayouts;
    // Maps the sequencer address to the epoch, and then maps it to a percent reported by bridge
    mapping(address => mapping(uint256 => uint256)) sequencerPercents;
    // True if period has already been reported
    mapping(uint256 => bool) reportedPeriod;
    // True if the sequencer has withdrawn this epoch
    mapping(address => mapping(uint256 => bool)) paidOut;
    // Assets which have a max interest in each period
    mapping(address => uint256) maxInterest;

    // Constants to track the
    uint256 immutable EPOCHS_PER_PERIOD;
    uint256 immutable START = block.timestamp;
    uint256 immutable PERIOD_LENGTH;

    constructor(uint256 periodLength, uint256 epochPerPeriod) {
        EPOCHS_PER_PERIOD = epochPerPeriod;
        PERIOD_LENGTH = periodLength;
    }

    modifier onlyBridge() {
        assert(msg.sender == bridge);
        _;
    }

    /// @notice This function triggers a deposit
    /// @param asset The asset we are depositing
    /// @param amount The amount of asset we are depositing
    function triggerDeposit(address asset, uint256 amount) external onlyBridge {
        require(IERC20(asset).balanceOf(address(this)) >= amount, "Not Transferred");
        require(address(sources[asset]) != address(0), "ERC20 not enabled");
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
        if (priorBalances[asset] < currentGlobalValue) {
            uint256 fixedPercent = (priorBalances[asset] * 1e18) / currentGlobalValue;
            userAmount = fixedPercent * amount / 1e18;
        }
        sources[asset].withdraw(userAmount, destination, address(this));
        priorBalances[asset] -= amount;
    }

    /// @notice Allows the owner to change the yield source, should be behind a long timelock to allow withdraws
    /// @param token Which token we want to change the yield source of
    /// @param newSource An erc4646 compatible yield source which we will use
    function changeYieldSource(address token, IERC4626 newSource) external onlyOwner {
        // First we withdraw from the source that currently has funds
        IERC4626 cachedSource = sources[token];
        uint256 shares = cachedSource.balanceOf(address(this));
        uint256 priorBalance = IERC20(token).balanceOf(address(this));
        cachedSource.redeem(shares, address(this), address(this));
        IERC20(token).approve(address(cachedSource), 0);

        // Now we move the funds into a new source
        uint256 toMove = IERC20(token).balanceOf(address(this)) - priorBalance;
        IERC20(token).approve(address(newSource), type(uint256).max);
        newSource.deposit(toMove, address(this));
        sources[token] = newSource;
    }

    /// @notice Tracks the increases in value of those assets in the "trackedYieldSources" array, if the increases is
    ///         more than max increase then the value is held for the next period.
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

    /// @notice Allows the bridge address to report the percent (encoded as a fixed point 1e18) earned by a sequencer
    /// @param sequencer The credited sequencer
    /// @param percent The percent earned by this sequencer in this epoch encoded in 1e18 fixed point
    /// @param epoch Which epoch, if this is repeated the prior value is overwritten
    function reportPayoutPercent(address sequencer, uint256 percent, uint256 epoch) external onlyBridge {
        poke();
        // We don't want to lock up in the case there is a bug in the percent payments reporting, so we
        // just soft ignore impossible values
        if (percent <= 1e18) {
            sequencerPercents[sequencer][epoch] = percent;
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
        require(!paidOut[sequencer][epoch]);
        uint256 period = epoch / EPOCHS_PER_PERIOD;
        uint256 paidInEpoch = periodPayouts[token][period] / EPOCHS_PER_PERIOD;
        uint256 amount = (paidInEpoch * sequencerPercents[sequencer][epoch]) / 1e18;
        paidOut[sequencer][epoch] = true;
        sources[token].withdraw(amount, sequencer, address(this));
    }

    /// @notice Computes the current period
    function currentPeriod() public view returns (uint256) {
        return ((block.timestamp - START) % PERIOD_LENGTH);
    }
}
