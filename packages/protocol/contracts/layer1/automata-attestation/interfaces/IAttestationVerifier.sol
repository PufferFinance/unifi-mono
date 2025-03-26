//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IAttestationVerifier
interface IAttestationVerifier {
    /// @dev TPM Extended Information structure containing attestation-related data
    struct ExtTpmInfo {
        bytes32 pcr10;     /// Platform Configuration Register 10 value
        bytes quote;       /// TPM quote data
        bytes signature;   /// Signature over the quote
        bytes akDer;      /// Attestation Key in DER format
    }

    error INVALID_REPORT();
    error INVALID_REPORT_DATA();
    error REPORT_DATA_MISMATCH(bytes32 want, bytes32 got);
    error INVALID_PRC10(bytes32 pcr10);

    event AttestationVerifierInitialized(address owner, address attestation, bool checkPcr10);
    event CheckPcr10Updated(bool check);
    event ImagePcr10Updated(bytes32 pcr10, bool trusted);

    /// @notice Sets the trust status for a PCR10 value
    /// @param _pcr10 The PCR10 value to configure
    /// @param _trusted If true, this PCR10 value will be considered trusted
    function setImagePcr10(bytes32 _pcr10, bool _trusted) external;

    /// @notice Verifies an attestation report and its associated data
    /// @param _report The attestation report to verify
    /// @param _userData User data that should match the report data
    /// @param ext Additional TPM information encoded as ExtTpmInfo
    /// @dev If attestation contract is set to address(0), verification is bypassed (mock mode)
    function verifyAttestation(
        bytes calldata _report,
        bytes32 _userData,
        bytes calldata ext
    )
        external;
}
