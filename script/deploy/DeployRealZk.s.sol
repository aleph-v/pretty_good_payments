// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Deploy} from "./Deploy.s.sol";
import {FakeZK} from "../../test/mocks/FakeZk.sol";
import {MockYieldRouter} from "../../test/mocks/MockYieldRouter.sol";
import {FakeERC20} from "../../test/mocks/FakeErc20.sol";
import {UpdateVerifier} from "../../circuits/verifiers/predictableUpdateVerifier.sol";

/// @title DeployRealZk
/// @notice Local deployment using real Groth16 verifier for predictableUpdate
/// @dev Uses real Entrypoint with mock dependencies, but real ZK verifier for tree updates
///      This is useful for integration testing with real snarkjs-generated proofs
///      Run Anvil with: --hardfork cancun --disable-block-gas-limit --disable-code-size-limit
contract DeployRealZk is Deploy {
    /// @notice Deploy FakeZK as the transfer verifier (not tested in tree update scenarios)
    function deployTransferVerifier() internal override returns (address) {
        FakeZK fakeZK = new FakeZK();
        return address(fakeZK);
    }

    /// @notice Deploy the real Groth16 verifier for predictableUpdate circuit
    function deployUpdateVerifier() internal override returns (address) {
        UpdateVerifier verifier = new UpdateVerifier();
        return address(verifier);
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
