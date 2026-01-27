// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {ERC20} from "solady/tokens/ERC20.sol";
import {Ownable} from "solady/auth/Ownable.sol";

/// @title TestnetERC20
/// @notice ERC20 token for testnet deployments with owner-restricted minting/burning
/// @dev Only the owner (deployer) can mint and burn tokens
contract TestnetERC20 is ERC20, Ownable {
    string private _name;
    string private _symbol;

    constructor(string memory tokenName, string memory tokenSymbol) {
        _name = tokenName;
        _symbol = tokenSymbol;
        _initializeOwner(msg.sender);
    }

    /// @notice Mint tokens to an address (owner only)
    /// @param to Recipient address
    /// @param amount Amount to mint
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    /// @notice Burn tokens from an address (owner only)
    /// @param from Address to burn from
    /// @param amount Amount to burn
    function burn(address from, uint256 amount) external onlyOwner {
        _burn(from, amount);
    }

    function name() public view override returns (string memory) {
        return _name;
    }

    function symbol() public view override returns (string memory) {
        return _symbol;
    }
}
