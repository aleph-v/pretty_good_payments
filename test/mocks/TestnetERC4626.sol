// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {TestnetERC20} from "./TestnetERC20.sol";

/// @title TestnetERC4626
/// @notice ERC4626 vault for testnet deployments with owner-restricted yield simulation
/// @dev Only the owner can simulate yield by minting tokens to the vault
contract TestnetERC4626 is IERC4626, Ownable {
    using SafeERC20 for IERC20;

    TestnetERC20 public immutable underlying;

    // ERC20 state for vault shares
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;

    // Track total assets deposited (before yield)
    uint256 public totalDeposited;

    string private _name;
    string private _symbol;

    constructor(TestnetERC20 _underlying, string memory vaultName, string memory vaultSymbol) {
        underlying = _underlying;
        _name = vaultName;
        _symbol = vaultSymbol;
        _initializeOwner(msg.sender);
    }

    // ==================== ERC20 Implementation ====================

    function name() external view override returns (string memory) {
        return _name;
    }

    function symbol() external view override returns (string memory) {
        return _symbol;
    }

    function decimals() external pure override returns (uint8) {
        return 18;
    }

    function totalSupply() external view override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) external view override returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function allowance(address owner_, address spender) external view override returns (uint256) {
        return _allowances[owner_][spender];
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        uint256 allowed = _allowances[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "ERC20: insufficient allowance");
            _allowances[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(_balances[from] >= amount, "ERC20: insufficient balance");
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        _totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        require(_balances[from] >= amount, "ERC20: insufficient balance");
        _balances[from] -= amount;
        _totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }

    // ==================== ERC4626 Implementation ====================

    function asset() external view override returns (address) {
        return address(underlying);
    }

    function totalAssets() public view override returns (uint256) {
        return underlying.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view override returns (uint256) {
        uint256 supply = _totalSupply;
        uint256 total = totalAssets();
        if (supply == 0 || total == 0) return assets;
        return (assets * supply) / total;
    }

    function convertToAssets(uint256 shares) public view override returns (uint256) {
        uint256 supply = _totalSupply;
        if (supply == 0) return shares;
        return (shares * totalAssets()) / supply;
    }

    function maxDeposit(address) external pure override returns (uint256) {
        return type(uint256).max;
    }

    function maxMint(address) external pure override returns (uint256) {
        return type(uint256).max;
    }

    function maxWithdraw(address owner_) external view override returns (uint256) {
        return convertToAssets(_balances[owner_]);
    }

    function maxRedeem(address owner_) external view override returns (uint256) {
        return _balances[owner_];
    }

    function previewDeposit(uint256 assets) public view override returns (uint256) {
        return convertToShares(assets);
    }

    function previewMint(uint256 shares) public view override returns (uint256) {
        uint256 supply = _totalSupply;
        uint256 total = totalAssets();
        if (supply == 0 || total == 0) return shares;
        return (shares * total + supply - 1) / supply; // Round up
    }

    function previewWithdraw(uint256 assets) public view override returns (uint256) {
        uint256 supply = _totalSupply;
        uint256 total = totalAssets();
        if (supply == 0 || total == 0) return assets;
        return (assets * supply + total - 1) / total; // Round up
    }

    function previewRedeem(uint256 shares) public view override returns (uint256) {
        return convertToAssets(shares);
    }

    function deposit(uint256 assets, address receiver) external override returns (uint256 shares) {
        shares = previewDeposit(assets);
        IERC20(address(underlying)).safeTransferFrom(msg.sender, address(this), assets);
        totalDeposited += assets;
        _mint(receiver, shares);
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function mint(uint256 shares, address receiver) external override returns (uint256 assets) {
        assets = previewMint(shares);
        IERC20(address(underlying)).safeTransferFrom(msg.sender, address(this), assets);
        totalDeposited += assets;
        _mint(receiver, shares);
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function withdraw(uint256 assets, address receiver, address owner_) external override returns (uint256 shares) {
        shares = previewWithdraw(assets);
        if (msg.sender != owner_) {
            uint256 allowed = _allowances[owner_][msg.sender];
            if (allowed != type(uint256).max) {
                require(allowed >= shares, "ERC4626: allowance exceeded");
                _allowances[owner_][msg.sender] = allowed - shares;
            }
        }
        _burn(owner_, shares);
        IERC20(address(underlying)).safeTransfer(receiver, assets);
        emit Withdraw(msg.sender, receiver, owner_, assets, shares);
    }

    function redeem(uint256 shares, address receiver, address owner_) external override returns (uint256 assets) {
        assets = previewRedeem(shares);
        if (msg.sender != owner_) {
            uint256 allowed = _allowances[owner_][msg.sender];
            if (allowed != type(uint256).max) {
                require(allowed >= shares, "ERC4626: allowance exceeded");
                _allowances[owner_][msg.sender] = allowed - shares;
            }
        }
        _burn(owner_, shares);
        IERC20(address(underlying)).safeTransfer(receiver, assets);
        emit Withdraw(msg.sender, receiver, owner_, assets, shares);
    }

    // ==================== YIELD SIMULATION ====================

    /// @notice Get the current yield (profit/loss) since deposits
    /// @dev To simulate yield: token owner calls token.mint(address(vault), amount)
    ///      To simulate loss: token owner calls token.burn(address(vault), amount)
    function currentYield() external view returns (int256) {
        return int256(totalAssets()) - int256(totalDeposited);
    }
}
