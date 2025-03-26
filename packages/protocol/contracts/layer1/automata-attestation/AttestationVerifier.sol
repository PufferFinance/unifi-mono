//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../shared/common/EssentialContract.sol";
import "./interfaces/IAttestationV2.sol";
import "./interfaces/IAttestationVerifier.sol";

/// @title AttestationVerifier
contract AttestationVerifier is IAttestationVerifier, EssentialContract {
    IAttestationV2 public automataDcapAttestation; // slot 1
    mapping(bytes32 pcr10 => bool trusted) public trustedPcr10; // slot 2
    bool internal checkPcr10; // slot3

    uint256[47] private __gap;

function init(
    address _owner,
    address _automataDcapAttestation,
    bool _checkPcr10
)
    external
    initializer
{
    __Essential_init(_owner);
    automataDcapAttestation = IAttestationV2(_automataDcapAttestation);
    checkPcr10 = _checkPcr10;
    emit AttestationVerifierInitialized(_owner, _automataDcapAttestation, _checkPcr10);
}

    /// @notice Sets whether PCR10 verification is enabled
    /// @param _check If true, PCR10 values will be verified against trusted values
    function setCheckPcr10(bool _check) external onlyOwner {
        checkPcr10 = _check;
        emit CheckPcr10Updated(_check);
    }

    /// @notice Sets whether a specific PCR10 value is trusted
    /// @param _pcr10 The PCR10 value to configure
    /// @param _trusted If true, this PCR10 value will be considered trusted
    function setImagePcr10(bytes32 _pcr10, bool _trusted) external onlyOwner {
        trustedPcr10[_pcr10] = _trusted;
        emit ImagePcr10Updated(_pcr10, _trusted);
    }

    /// @notice Verifies an attestation report
    /// @param _report The attestation report to verify
    /// @param _userData User data that should match the report data
    /// @param _ext Additional TPM information encoded as ExtTpmInfo
    /// @dev Verifies that:
    ///      1. The report is valid via automataDcapAttestation
    ///      2. The report data matches the hash of (akDer + userData)
    ///      3. If checkPcr10 is enabled, verifies pcr10 is trusted
    /// @inheritdoc IAttestationVerifier
    function verifyAttestation(
        bytes calldata _report,
        bytes32 _userData,
        bytes calldata _ext
    )
        external
    {
        if (address(automataDcapAttestation) == address(0)) return;

        (bool succ, bytes memory output) = automataDcapAttestation.verifyAndAttestOnChain(_report);
        if (!succ) revert INVALID_REPORT();

        if (output.length < 32) revert INVALID_REPORT_DATA();

        bytes32 quoteBodyLast32;
        assembly {
            // Calculate offset directly using output length
            quoteBodyLast32 := mload(add(output, mload(output)))
        }

        ExtTpmInfo memory info = abi.decode(_ext, (ExtTpmInfo));

        bytes32 dataWithNonce = sha256(abi.encodePacked(info.akDer, _userData));
        if (quoteBodyLast32 != dataWithNonce) {
            revert REPORT_DATA_MISMATCH(quoteBodyLast32, dataWithNonce);
        }

        if (checkPcr10 && !trustedPcr10[info.pcr10]) revert INVALID_PRC10(info.pcr10);
    }
}
