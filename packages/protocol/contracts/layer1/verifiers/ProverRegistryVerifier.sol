// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../../shared/common/EssentialContract.sol";
import "../automata-attestation/interfaces/IAttestationVerifier.sol";
import "../../shared/common/LibStrings.sol";
import "../based/ITaikoL1.sol";
import "../based/TaikoData.sol";
import "./IProverRegistry.sol";
import "./IVerifier.sol";
import "./LibPublicInput.sol";

contract ProverRegistryVerifier is IVerifier, IProverRegistry, EssentialContract {
    IAttestationVerifier public verifier; // slot 1

    // Pack these variables into a single slot 2
    uint64 public attestValiditySeconds;
    uint64 public maxBlockNumberDiff;
    uint128 public nextInstanceId;

    mapping(bytes32 reportHash => bool used) public attestedReports; // slot 3
    mapping(uint256 proverInstanceID => ProverInstance) public attestedProvers; // slor 4

    uint256[46] private __gap;

    function init(
        address _owner,
        address _rollupAddressManager,
        address _verifierAddr,
        uint256 _attestValiditySeconds,
        uint256 _maxBlockNumberDiff
    )
        external
        initializer
    {
        __Essential_init(_owner, _rollupAddressManager);

        if (_verifierAddr == address(0)) revert PROVER_INVALID_ADDR(_verifierAddr);
        if (_attestValiditySeconds == 0) revert INVALID_ATTEST_VALIDITY_SECONDS();
        if (_maxBlockNumberDiff > 256) revert MAX_BLOCK_NUMBER_DIFF_TOO_LARGE();

        verifier = IAttestationVerifier(_verifierAddr);
        attestValiditySeconds = uint64(_attestValiditySeconds);
        maxBlockNumberDiff = uint64(_maxBlockNumberDiff);
        emit ProverRegistryInitialized(_verifierAddr, _attestValiditySeconds, _maxBlockNumberDiff);
    }

    /// @notice Reinitializes the contract with new parameters
    /// @param i The version number for reinitialization
    /// @param _verifierAddr The address of the new attestation verifier
    /// @param _attestValiditySeconds New duration for attestation validity
    /// @param _maxBlockNumberDiff New maximum block number difference allowed
    /// @dev Can only be called by the owner and uses OpenZeppelin's reinitializer
    function reinitialize(
        uint8 i,
        address _verifierAddr,
        uint256 _attestValiditySeconds,
        uint256 _maxBlockNumberDiff
    )
        external
        onlyOwner
        reinitializer(i)
    {
        if (_verifierAddr == address(0)) revert PROVER_INVALID_ADDR(_verifierAddr);
        if (_attestValiditySeconds == 0) revert INVALID_ATTEST_VALIDITY_SECONDS();
        if (_maxBlockNumberDiff > 256) revert MAX_BLOCK_NUMBER_DIFF_TOO_LARGE();

        verifier = IAttestationVerifier(_verifierAddr);
        attestValiditySeconds = uint64(_attestValiditySeconds);
        maxBlockNumberDiff = uint64(_maxBlockNumberDiff);
        emit ProverRegistryInitialized(_verifierAddr, _attestValiditySeconds, _maxBlockNumberDiff);
    }

    /**
     * @notice Register a new prover instance with TEE attestation quote
     * @param _report The attestation report containing the TEE quote to be verified
     * @param _data The report data containing prover details:
     *        - addr: The prover's address
     *        - teeType: Type of TEE (1 for IntelTDX)
     *        - referenceBlockNumber: Block number for verification
     *        - referenceBlockHash: Block hash for verification
     *        - binHash: Hash of the binary
     *        - ext: Additional extension data
     * @dev Verifies the attestation report, checks for uniqueness and registers the prover.
     * Emits an InstanceAdded event on successful registration.
     * Reverts if block number validation fails, report was already used, or attestation verification fails.
     */
    function register(bytes calldata _report, ReportData calldata _data) external {
        _checkBlockNumber(_data.referenceBlockNumber, _data.referenceBlockHash);
        bytes32 dataHash = keccak256(abi.encode(_data));

        verifier.verifyAttestation(_report, dataHash, _data.ext);

        bytes32 reportHash = keccak256(_report);
        if (attestedReports[reportHash]) revert REPORT_USED();
        attestedReports[reportHash] = true;

        uint256 instanceID = ++nextInstanceId;

        uint256 validUnitl = block.timestamp + attestValiditySeconds;
        attestedProvers[instanceID] = ProverInstance(_data.addr, validUnitl, _data.teeType);

        emit InstanceAdded(instanceID, _data.addr, address(0), validUnitl);
    }

    /// @notice Verifies a proof submitted by a prover
    /// @param _ctx The verification context including prover address and metadata
    /// @param _tran The transition data for the proof
    /// @param _proof The tier proof data containing instance ID and signatures
    /// @dev Verifies the prover's signature and updates instance address if needed
    /// @dev Does not run verification if contesting an existing proof
    function verifyProof(
        IVerifier.Context calldata _ctx,
        TaikoData.Transition calldata _tran,
        TaikoData.TierProof calldata _proof
    )
        external
        onlyFromNamedEither(LibStrings.B_TAIKO, LibStrings.B_TIER_TDX)
    {
        // Do not run proof verification to contest an existing proof
        if (_ctx.isContesting) return;

        // Size is: 89 bytes
        // 4 bytes + 20 bytes + 65 bytes (signature) = 89
        if (_proof.data.length != 89) revert PROVER_INVALID_PROOF();

        uint32 id = uint32(bytes4(_proof.data[:4]));
        address newInstance = address(bytes20(_proof.data[4:24]));

        address oldInstance = ECDSA.recover(
            LibPublicInput.hashPublicInputs(
                _tran, address(this), newInstance, _ctx.prover, _ctx.metaHash, uniFiChainId()
            ),
            _proof.data[24:]
        );

        ProverInstance memory prover = checkProver(id, oldInstance);
        if (_proof.tier != prover.teeType) revert PROVER_TYPE_MISMATCH();
        if (oldInstance != newInstance) {
            attestedProvers[id].addr = newInstance;
            emit InstanceAdded(id, oldInstance, newInstance, prover.validUntil);
        }
    }

    /// @notice Verifies a batch of proofs
    /// @dev Currently not implemented
    function verifyBatchProof(
        IVerifier.ContextV2[] calldata /* _ctxs */,
        TaikoData.TierProof calldata /* _proof */
    )
        external
        pure
        notImplemented
    { }

    /// @notice Validates a prover instance
    /// @param _instanceID The ID of the prover instance to check
    /// @param _proverAddr The expected address of the prover
    /// @return ProverInstance The validated prover instance data
    /// @dev Checks if:
    ///      1. Instance ID is valid (not 0)
    ///      2. Prover address matches registered address
    ///      3. Instance hasn't expired
    function checkProver(
        uint256 _instanceID,
        address _proverAddr
    )
        public
        view
        returns (ProverInstance memory)
    {
        ProverInstance memory prover;
        if (_instanceID == 0) revert PROVER_INVALID_INSTANCE_ID(_instanceID);
        if (_proverAddr == address(0)) revert PROVER_INVALID_ADDR(_proverAddr);
        prover = attestedProvers[_instanceID];
        if (prover.addr != _proverAddr) revert PROVER_ADDR_MISMATCH(prover.addr, _proverAddr);
        if (prover.validUntil < block.timestamp) revert PROVER_OUT_OF_DATE(prover.validUntil);
        return prover;
        if (prover.validUntil < block.timestamp) revert PROVER_OUT_OF_DATE(prover.validUntil);
        return prover;
    }

    /// @notice Gets the UniFi chain ID from the TaikoL1 contract
    /// @return The chain ID as configured in TaikoL1
    function uniFiChainId() public view virtual returns (uint64) {
        return ITaikoL1(resolve(LibStrings.B_TAIKO, false)).getConfig().chainId;
    }

    // Due to the inherent unpredictability of blockHash, it mitigates the risk of mass-generation
    //   of attestation reports in a short time frame, preventing their delayed and gradual
    // exploitation.
    // This function will make sure the attestation report generated in recent ${maxBlockNumberDiff}
    // blocks
    function _checkBlockNumber(uint256 blockNumber, bytes32 blockHash) private view {
        if (blockNumber >= block.number) revert INVALID_BLOCK_NUMBER();
        unchecked {
            if (block.number - blockNumber >= maxBlockNumberDiff) {
                revert BLOCK_NUMBER_OUT_OF_DATE();
            }
        }
        if (blockhash(blockNumber) != blockHash) revert BLOCK_NUMBER_MISMATCH();
    }
}
