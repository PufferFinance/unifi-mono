// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IVerifier.sol";

interface IProverRegistry {
    struct ProverInstance {
        address addr;
        uint256 validUntil;
        uint256 teeType; // 1: IntelTDX
    }

    struct SignedPoe {
        TaikoData.Transition transition;
        uint256 id;
        address newInstance;
        bytes signature;
        uint256 teeType; // 1: IntelTDX
    }

    struct Proof {
        SignedPoe poe;
        IVerifier.Context ctx;
    }

    struct ReportData {
        address addr;
        uint256 teeType;
        uint256 referenceBlockNumber;
        bytes32 referenceBlockHash;
        bytes32 binHash;
        bytes ext;
    }

    error INVALID_BLOCK_NUMBER();
    error BLOCK_NUMBER_OUT_OF_DATE();
    error BLOCK_NUMBER_MISMATCH();
    error REPORT_USED();
    error INVALID_PROVER_INSTANCE();
    error PROVER_INVALID_PROOF();
    error PROVER_INVALID_INSTANCE_ID(uint256);
    error PROVER_INVALID_ADDR(address);
    error PROVER_TYPE_MISMATCH();
    error PROVER_ADDR_MISMATCH(address, address);
    error PROVER_OUT_OF_DATE(uint256);
    error INVALID_ATTEST_VALIDITY_SECONDS();
    error MAX_BLOCK_NUMBER_DIFF_TOO_LARGE();

    // attestation verifier
    error INVALID_REPORT();
    error INVALID_REPORT_DATA();
    error REPORT_DATA_MISMATCH(bytes32 want, bytes32 got);
    error INVALID_PRC10(bytes32 pcr10);

    event InstanceAdded(
        uint256 indexed id, address indexed instance, address replaced, uint256 validUntil
    );
    event VerifyProof(uint256 proofs);
    event ProverRegistryInitialized(
        address verifier,
        uint256 attestValiditySeconds,
        uint256 maxBlockNumberDiff
    );

    /**
     * @notice Register a new prover instance with attestation quote
     * @param _report The attestation report containing the TEE quote
     * @param _data The report data containing prover details:
     *        - addr: The prover's address
     *        - teeType: Type of TEE (1 for IntelTDX)
     *        - referenceBlockNumber: Block number for verification
     *        - referenceBlockHash: Block hash for verification
     *        - binHash: Hash of the binary
     *        - ext: Additional extension data
     */
    function register(bytes calldata _report, ReportData calldata _data) external;

    /**
     * @notice Validate a prover instance
     * @param _instanceID The unique identifier of the prover instance
     * @param _proverAddr The address of the prover to validate
     * @return ProverInstance containing:
     *         - addr: The prover's address
     *         - validUntil: Timestamp until which the prover is valid
     *         - teeType: Type of TEE (1 for IntelTDX)
     * @dev Reverts if instance ID is invalid, prover address mismatch, or instance expired
     */
    function checkProver(
        uint256 _instanceID,
        address _proverAddr
    )
        external
        view
        returns (ProverInstance memory);
}
