// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ERC20} from "solady/tokens/ERC20.sol";

contract FakeERC20 is ERC20 {
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }

    function name() public pure override returns (string memory) {
        return ("");
    }

    function symbol() public pure override returns (string memory) {
        return ("");
    }
}
