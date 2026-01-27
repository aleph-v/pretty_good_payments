// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Deploy} from "./Deploy.s.sol";
import {FakeZK} from "../../test/mocks/FakeZk.sol";
import {MockYieldRouter} from "../../test/mocks/MockYieldRouter.sol";
import {FakeERC20} from "../../test/mocks/FakeErc20.sol";

/// @title DeployLocal
/// @notice Local/test deployment using mock verifiers and FakeERC20
/// @dev Uses real Entrypoint with mock dependencies for integration testing
///      Run Anvil with: --hardfork cancun --disable-block-gas-limit --disable-code-size-limit
contract DeployLocal is Deploy {
    /// @notice Deploy FakeZK as the transfer verifier
    function deployTransferVerifier() internal override returns (address) {
        FakeZK fakeZK = new FakeZK();
        return address(fakeZK);
    }

    /// @notice Deploy FakeZK as the update verifier (same as transfer for simplicity)
    function deployUpdateVerifier() internal override returns (address) {
        // In local testing, we can reuse the same FakeZK instance
        // But for cleaner separation, we deploy a separate one
        FakeZK fakeZK = new FakeZK();
        return address(fakeZK);
    }

    /// @notice Deploy MockYieldRouter
    function deployYieldRouter(
        address /* entrypoint */
    )
        internal
        override
        returns (address)
    {
        MockYieldRouter yieldRouter = new MockYieldRouter();
        return address(yieldRouter);
    }

    /// @notice Deploy FakeERC20 for testing
    function getTokenAddress() internal override returns (address) {
        FakeERC20 token = new FakeERC20();
        return address(token);
    }
}
