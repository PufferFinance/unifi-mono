// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../based/TaikoL1TestBase.sol";
import "../../../contracts/layer1/verifiers/IProverRegistry.sol";
import "../../../contracts/layer1/automata-attestation/interfaces/IAttestationV2.sol";
import "../../../contracts/layer1/automata-attestation/interfaces/IAttestationVerifier.sol";
import "../automata-attestation/MockAutomataDcapAttestation.sol";

contract ProverRegistryVerifierTest is TaikoL1TestBase {
    bytes fakeReport = hex"01020203";
    address KNOWN_ADDRESS = address(0xAAAAAFE838B80D164535CD4d50058E456A4f9E16);
    uint256 KNOWN_ADDRESS_PRIV_KEY =
        0xde9b0c39e60bb0404347b588c6891947db2c873942b553d5d15c03ea30c04c63;
    address KNOWN_ADDRESS_V2 = address(0x3B65e7318AC8ba9B7e488f581aAC5E64DC70eC9b);
    uint256 KNOWN_ADDRESS_PRIV_KEY_V2 =
        0xc793ff2348b2667c400eded183c779a846997dc79d644ed336d26adadfd9fd80;

    AttestationVerifier mockAttestationVerifier;
    AttestationVerifier attestationVerifier;
    IAttestationV2 mockAutomataDcapAttestation;
    ProverRegistryVerifier pv;

    function deployTaikoL1() internal override returns (TaikoL1) {
        return
            TaikoL1(payable(deployProxy({ name: "taiko", impl: address(new TaikoL1()), data: "" })));
    }

    function setUp() public override {
        super.setUp();

        mockAutomataDcapAttestation = new MockAutomataDcapAttestation();

        mockAttestationVerifier = AttestationVerifier(
            deployProxy({
                name: "mock_attestation_verifier",
                impl: address(new AttestationVerifier()),
                data: abi.encodeCall(AttestationVerifier.init, (address(0), address(0), true))
            })
        );

        attestationVerifier = AttestationVerifier(
            deployProxy({
                name: "attestation_verifier",
                impl: address(new AttestationVerifier()),
                data: abi.encodeCall(
                    AttestationVerifier.init, (address(0), address(mockAutomataDcapAttestation), true)
                )
            })
        );
        attestationVerifier.setCheckPcr10(true);

        pv = ProverRegistryVerifier(
            deployProxy({
                name: "tier_tdx",
                impl: address(new ProverRegistryVerifier()),
                data: abi.encodeCall(
                    ProverRegistryVerifier.init,
                    (address(0), address(addressManager), address(mockAttestationVerifier), 86_400, 25)
                )
            })
        );

        registerAddress("tier_tdx", address(pv));
    }

    function _reportData(uint256 teeType)
        internal
        view
        returns (IProverRegistry.ReportData memory)
    {
        uint256 refBlockNumber = block.number - 1;
        bytes32 refBlockHash = blockhash(refBlockNumber);
        bytes32 binHash = bytes32(0);
        bytes memory ext = new bytes(0);
        IProverRegistry.ReportData memory data = IProverRegistry.ReportData(
            address(KNOWN_ADDRESS), teeType, refBlockNumber, refBlockHash, binHash, ext
        );
        return data;
    }

    function _proofContext() internal view returns (IVerifier.Context memory ctx) {
        ctx = IVerifier.Context({
            metaHash: bytes32("ab"),
            blobHash: bytes32("cd"),
            prover: KNOWN_ADDRESS,
            msgSender: KNOWN_ADDRESS,
            blockId: 10,
            isContesting: false,
            blobUsed: false
        });
    }

    function _proofTransition() internal pure returns (TaikoData.Transition memory transition) {
        transition = TaikoData.Transition({
            parentHash: bytes32("12"),
            blockHash: bytes32("34"),
            stateRoot: bytes32("56"),
            graffiti: bytes32("78")
        });
    }

    function _tierProof(
        uint32 id,
        uint16 tier,
        address newSigner,
        IVerifier.Context memory _ctx,
        TaikoData.Transition memory _trans
    )
        internal
        view
        returns (TaikoData.TierProof memory proof)
    {
        uint64 chainId = L1.getConfig().chainId;
        bytes32 signedHash = LibPublicInput.hashPublicInputs(
            _trans, address(pv), newSigner, _ctx.prover, _ctx.metaHash, chainId
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(KNOWN_ADDRESS_PRIV_KEY, signedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        proof = TaikoData.TierProof({
            tier: tier,
            data: abi.encodePacked(id, newSigner, signature)
        });
    }

    function test_upgrade() external {
        address verifierAddr1 = address(new ProverRegistryVerifier());
        address verifierAddr2 = address(new ProverRegistryVerifier());
        ProverRegistryVerifier verifier = ProverRegistryVerifier(
            deployProxy({
                name: "tier_tdx_upgrade",
                impl: verifierAddr1,
                data: abi.encodeCall(
                    ProverRegistryVerifier.init,
                    (address(0), address(addressManager), address(mockAttestationVerifier), 86_400, 25)
                )
            })
        );
        assertEq(verifier.maxBlockNumberDiff(), 25);
        assertEq(verifier.attestValiditySeconds(), 86_400);



        verifier.upgradeToAndCall(verifierAddr2, abi.encodeCall(
            ProverRegistryVerifier.reinitialize,
            (2, address(mockAttestationVerifier), 123, 10)
        ));
        assertEq(verifier.maxBlockNumberDiff(), 10);
        assertEq(verifier.attestValiditySeconds(), 123);
    }

    function test_register() external {
        uint256 expectInstanceId = pv.nextInstanceId() + 1;
        pv.register(fakeReport, _reportData(1));

        IProverRegistry.ProverInstance memory prover =
            pv.checkProver(expectInstanceId, KNOWN_ADDRESS);
        assertEq(prover.addr, KNOWN_ADDRESS, "prover registered");
        assertEq(block.timestamp + 86_400, prover.validUntil, "valid time mismatch");
    }

    function test_registerCornerCases() external {
        IProverRegistry.ReportData memory reportData = _reportData(1);
        reportData.referenceBlockNumber = block.number;
        vm.expectRevert(abi.encodeWithSignature("INVALID_BLOCK_NUMBER()"));
        pv.register(fakeReport, reportData);

        reportData.referenceBlockNumber = block.number - 1;
        reportData.referenceBlockHash = 0x0;
        vm.expectRevert(abi.encodeWithSignature("BLOCK_NUMBER_MISMATCH()"));
        pv.register(fakeReport, reportData);

        reportData.referenceBlockHash = blockhash(reportData.referenceBlockNumber);
        pv.register(hex"010d0d0d", reportData); // should success
        vm.expectRevert(abi.encodeWithSignature("REPORT_USED()"));
        pv.register(hex"010d0d0d", reportData);

        vm.roll(block.number + 50);
        vm.expectRevert(abi.encodeWithSignature("BLOCK_NUMBER_OUT_OF_DATE()"));
        pv.register(fakeReport, reportData);
    }

    function test_verifyProof() external {
        uint32 id = uint32(pv.nextInstanceId()) + 1;
        pv.register(hex"01020202", _reportData(100));

        IVerifier.Context memory _ctx = _proofContext();
        TaikoData.Transition memory _trans = _proofTransition();
        TaikoData.TierProof memory _proof = _tierProof(id, 100, KNOWN_ADDRESS_V2, _ctx, _trans);

        vm.stopPrank();

        // Caller should be TaikoL1 contract
        vm.startPrank(address(L1));

        pv.verifyProof(_ctx, _trans, _proof);
    }

    function test_verifyProofReverts() external {
        uint32 id = uint32(pv.nextInstanceId()) + 1;
        pv.register(hex"0102020304", _reportData(101));

        IVerifier.Context memory _ctx = _proofContext();
        TaikoData.Transition memory _trans = _proofTransition();
        TaikoData.TierProof memory _proof = _tierProof(id, 100, KNOWN_ADDRESS, _ctx, _trans);

        vm.expectRevert(abi.encodeWithSignature("RESOLVER_DENIED()"));
        pv.verifyProof(_ctx, _trans, _proof);

        vm.stopPrank();
        vm.startPrank(address(L1));

        _proof.data = new bytes(0);
        vm.expectRevert(abi.encodeWithSignature("PROVER_INVALID_PROOF()"));
        pv.verifyProof(_ctx, _trans, _proof);

        _proof = _tierProof(id, 100, KNOWN_ADDRESS, _ctx, _trans);
        vm.expectRevert(abi.encodeWithSignature("PROVER_TYPE_MISMATCH()"));
        pv.verifyProof(_ctx, _trans, _proof);

        _ctx.metaHash = bytes32("abc");
        vm.expectRevert();
        pv.verifyProof(_ctx, _trans, _proof);

        _ctx.metaHash = bytes32("ab");
        _proof = _tierProof(id + 1, 100, KNOWN_ADDRESS, _ctx, _trans);
        vm.expectRevert();
        pv.verifyProof(_ctx, _trans, _proof);

        _proof.data = new bytes(80);
        vm.expectRevert(abi.encodeWithSignature("PROVER_INVALID_PROOF()"));
        pv.verifyProof(_ctx, _trans, _proof);
    }

    function test_chainID() external {
        assertEq(pv.uniFiChainId(), L1.getConfig().chainId);
    }

    function test_attestation() external {
        bytes32 pcr10 = bytes32("pcr10");
        bytes32 userData = bytes32("userData");
        IAttestationVerifier.ExtTpmInfo memory tpm = IAttestationVerifier.ExtTpmInfo({
            akDer: new bytes(0),
            quote: new bytes(0),
            signature: new bytes(0),
            pcr10: pcr10
        });
        bytes memory ext = abi.encode(tpm);
        bytes32 reportData = sha256(abi.encodePacked(tpm.akDer, userData));
        bytes32 wrongReportData = sha256(abi.encodePacked(tpm.akDer, bytes32("wrongUserData")));
        bytes memory mockReport = abi.encodePacked(reportData);

        attestationVerifier.setCheckPcr10(true);
        vm.expectRevert(abi.encodeWithSignature("INVALID_PRC10(bytes32)", pcr10));
        attestationVerifier.verifyAttestation(mockReport, userData, ext);

        {
            // should pass when disabled the pcr10 checking
            attestationVerifier.setCheckPcr10(false);
            attestationVerifier.verifyAttestation(mockReport, userData, ext);
            attestationVerifier.setCheckPcr10(true);
        }

        attestationVerifier.setImagePcr10(pcr10, true);
        attestationVerifier.verifyAttestation(mockReport, userData, ext);

        vm.expectRevert(
            abi.encodeWithSignature(
                "REPORT_DATA_MISMATCH(bytes32,bytes32)", reportData, wrongReportData
            )
        );
        attestationVerifier.verifyAttestation(mockReport, bytes32("wrongUserData"), ext);

        vm.expectRevert(abi.encodeWithSignature("INVALID_REPORT_DATA()"));
        attestationVerifier.verifyAttestation(bytes("invalidReport"), userData, ext);
    }
}
