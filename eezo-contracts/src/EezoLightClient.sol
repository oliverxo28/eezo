// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Optional external verifier interface (hook up your STARK verifier later).
interface IVerifier {
    function verify(bytes calldata proof, bytes calldata publicInputs) external view returns (bool);
}

contract EezoLightClient {
    event HeaderStored(
        uint64 height,
        uint32 circuitVersion,
        bytes32 txRootV2,
        bytes32 stateRootV2,
        bytes32 sigBatchDigest, // v2 only (zero for v1)
        uint32 batchLen         // v2 only (zero for v1)
    );
    event VerifierChanged(address indexed oldVerifier, address indexed newVerifier);
    event CircuitAllowed(uint32 indexed version, bool allowed);
    event ChainIdSet(bytes20 chainId20);
    // T34.0 — suite rotation
    event SuiteRotationScheduled(uint32 active, uint32 next, uint64 dualAcceptUntil);
    event SuiteActivated(uint32 newActive);
    // ── new: canonical PI digest storage & event ───────────────────────────────────
    event PiDigestStored(uint64 indexed height, bytes32 piDigest);
    event PiDigestStaged(uint64 indexed height, bytes32 digest); // ADDED: Staging event

    struct HeaderV2 {
        uint32 circuitVersion;
        // 2
        uint64 height;
        bytes32 txRootV2;
        bytes32 stateRootV2;
        bytes32 sigBatchDigest;
        // new in v2
        uint32 batchLen;
        // new in v2
        bytes20 chainId20; // T33.6: bind header to EEZO chain id (20 bytes)
        // T34.2: crypto suite used to sign/attest this header
        uint32 suiteId;    // 1 = ml-dsa-44, 2 = sphincs+, ...
    }

    struct HeaderV1 {
        uint32 circuitVersion;
        // 1
        uint64 height;
        bytes32 txRootV2;
        bytes32 stateRootV2;
        // no sigBatchDigest / batchLen
    }

    // Stored canonical headers by height
    mapping(uint64 => HeaderV2) public headers;
    IVerifier public verifier; // settable hook (can be address(0) during bring-up)
    address public admin;
    // T33.6: hardening controls
    mapping(uint32 => bool) public allowedCircuit;   // circuit allowlist
    bytes20 public expectedChainId20;                // EEZO chain id binding
    uint64  public latestHeight;                     // monotonic progress
    // T34.0: suite rotation state
    uint32  public activeSuiteId;    // default 1
    uint32  public nextSuiteId;      // 0 = none
    uint64  public dualAcceptUntil;  // height (inclusive), 0 = disabled
    mapping(uint64 => uint32) public suiteOf; // suite per stored header
    // ── new: canonical PI digest storage ──────────────────────────────────────────
    // height => canonical PI digest (STARK-certified public-inputs digest)
    mapping(uint64 => bytes32) public piDigestOf;
    mapping(uint64 => bytes32) private _stagedPiDigest; // ADDED: Staging buffer

    constructor(address _verifier) {
        admin = msg.sender;
        verifier = IVerifier(_verifier);
        activeSuiteId = 1; // ml-dsa-44 by default
        nextSuiteId = 0;
        dualAcceptUntil = 0;
    }

    function setVerifier(address _verifier) external {
        require(msg.sender == admin, "only admin");
        emit VerifierChanged(address(verifier), _verifier);
        verifier = IVerifier(_verifier);
    }

    // T33.6 admin controls
    function setCircuitAllowed(uint32 version, bool allowed) external {
        require(msg.sender == admin, "only admin");
        allowedCircuit[version] = allowed;
        emit CircuitAllowed(version, allowed);
    }

    function setExpectedChainId(bytes20 chainId20_) external {
        require(msg.sender == admin, "only admin");
        expectedChainId20 = chainId20_;
        emit ChainIdSet(chainId20_);
    }

    // --- T34.0: suite rotation admin ---
    function scheduleSuiteRotation(uint32 _active, uint32 _next, uint64 _dualUntil) external {
        require(msg.sender == admin, "only admin");
        activeSuiteId   = _active;
        nextSuiteId     = _next;      // 0 disables dual-accept
        dualAcceptUntil = _dualUntil; // 0 disables dual-accept
        emit SuiteRotationScheduled(_active, _next, _dualUntil);
    }

    function activateSuite(uint32 _newActive) external {
        require(msg.sender == admin, "only admin");
        activeSuiteId   = _newActive;
        nextSuiteId     = 0;
        dualAcceptUntil = 0;
        emit SuiteActivated(_newActive);
    }

    // ── new: PI digest storage (UPDATED WITH STAGING LOGIC) ───────────────────────
    function storePiDigest(uint64 height, bytes32 digest) external {
        require(msg.sender == admin, "only admin");
        
        // If header already exists → commit immediately
        if (headers[height].height == height) {
            piDigestOf[height] = digest;
            emit PiDigestStored(height, digest);
        } else {
            // Otherwise, stage and let header commit later
            _stagedPiDigest[height] = digest;
            emit PiDigestStaged(height, digest);
        }
        // Note: The previous 'require(headers[height].height == height, "header not stored");' is removed.
    }

    /// Accepts either V1 or V2 public inputs.
    // Caller must pass the correct ABI-encoded blob.
    /// - For V2: abi.encode(HeaderV2)
    /// - For V1: abi.encode(HeaderV1)  (we up-convert to V2 with zeros for new fields)
    function verifyAndStore(bytes calldata proof, bytes calldata publicInputs) external {
        // Peek circuitVersion (first 32 bytes of ABI-encoded struct)
        require(publicInputs.length >= 32, "bad inputs");
        uint32 cv;
        assembly {
            cv := calldataload(publicInputs.offset)
        }
        require(cv == 1 || cv == 2, "unsupported circuitVersion");
        require(allowedCircuit[cv], "circuit not allowed");

        // Delegate to verifier if set (can be a stub acceptor during dev)
        if (address(verifier) != address(0)) {
            require(verifier.verify(proof, publicInputs), "bad proof");
        }

        if (cv == 2) {
            // ABI layout must match: (uint32,uint64,bytes32,bytes32,bytes32,uint32,bytes20,uint32)
            HeaderV2 memory h = abi.decode(publicInputs, (HeaderV2));
            // T33.6 guards
            require(h.txRootV2 != bytes32(0) && h.stateRootV2 != bytes32(0), "zero root");
            require(h.batchLen > 0, "zero batchLen");
            if (expectedChainId20 != bytes20(0)) {
                require(h.chainId20 == expectedChainId20, "wrong chain");
            }
            // idempotent semantics for same-height re-submission
            if (h.height < latestHeight) revert("non-monotonic height");
            if (h.height == latestHeight) {
                HeaderV2 storage old2 = headers[h.height];
                require(old2.height != 0, "lc inconsistent");
                require(
                    old2.txRootV2 == h.txRootV2 &&
                    old2.stateRootV2 == h.stateRootV2 &&
                    old2.sigBatchDigest == h.sigBatchDigest &&
                    old2.batchLen == h.batchLen &&
                    old2.chainId20 == h.chainId20 &&
                    old2.suiteId == h.suiteId,
                    "header mismatch"
                );
                // re-emit for visibility and return without write
                emit HeaderStored(h.height, h.circuitVersion, h.txRootV2, h.stateRootV2, h.sigBatchDigest, h.batchLen);
                return;
            }
            require(_acceptSuiteAt(h.height, h.suiteId), "suite not accepted");
            _storeV2(h);
            latestHeight = h.height;
        } else {
            HeaderV1 memory h1 = abi.decode(publicInputs, (HeaderV1));
            HeaderV2 memory h = HeaderV2({
                circuitVersion: 1,
                height: h1.height,
                txRootV2: h1.txRootV2,
                stateRootV2: h1.stateRootV2,
                sigBatchDigest: bytes32(0),
                batchLen: 0,
                // V1 had no chain id in inputs; bind to expected (if set) to avoid accidental mismatch.
                chainId20: expectedChainId20,
                // Default V1 to current active suite.
                suiteId: activeSuiteId
            });
            // T33.6 guards for V1
            require(h.txRootV2 != bytes32(0) && h.stateRootV2 != bytes32(0), "zero root");
            if (expectedChainId20 != bytes20(0)) {
                require(h.chainId20 == expectedChainId20, "wrong chain");
            }
            // idempotent semantics for same-height re-submission
            if (h.height < latestHeight) revert("non-monotonic height");
            if (h.height == latestHeight) {
                HeaderV2 storage old2 = headers[h.height];
                require(old2.height != 0, "lc inconsistent");
                require(
                    old2.txRootV2 == h.txRootV2 &&
                    old2.stateRootV2 == h.stateRootV2 &&
                    old2.sigBatchDigest == h.sigBatchDigest &&
                    old2.batchLen == h.batchLen &&
                    old2.chainId20 == h.chainId20 &&
                    old2.suiteId == h.suiteId,
                    "header mismatch"
                );
                // re-emit for visibility and return without write
                emit HeaderStored(h.height, h.circuitVersion, h.txRootV2, h.stateRootV2, h.sigBatchDigest, h.batchLen);
                return;
            }
            require(_acceptSuiteAt(h.height, h.suiteId), "suite not accepted");
            _storeV2(h);
            latestHeight = h.height;
        }
    }

    function _storeV2(HeaderV2 memory h) internal {
        // Monotonic or equal-height update policy (choose your policy)
        HeaderV2 storage cur = headers[h.height];
        // idempotent store allowed
        if (
            cur.height == 0 ||
            (cur.txRootV2 == h.txRootV2 && cur.stateRootV2 == h.stateRootV2 && cur.circuitVersion == h.circuitVersion)
        ) {
            headers[h.height] = h;
            suiteOf[h.height] = h.suiteId;
            emit HeaderStored(h.height, h.circuitVersion, h.txRootV2, h.stateRootV2, h.sigBatchDigest, h.batchLen);

            // NEW: auto-commit staged PI digest if one exists for this height
            bytes32 staged = _stagedPiDigest[h.height];
            if (staged != bytes32(0)) {
                piDigestOf[h.height] = staged;
                delete _stagedPiDigest[h.height];
                emit PiDigestStored(h.height, staged);
            }
        } else {
            revert("conflict at height");
        }
    }

    // Convenience view: returns true if a header is recorded for height.
    function hasHeader(uint64 height) external view returns (bool) {
        return headers[height].height != 0;
    }

    // ------------- T33.4: Merkle inclusion ----------------

    // keccak256-based binary Merkle using abi.encodePacked concatenation.
    // index LSB = level 0 (leaf level); 0 = left, 1 = right.
    function _merkleUp(bytes32 leaf, uint256 index, bytes32[] memory branch)
        internal
        pure
        returns (bytes32 root)
    {
        bytes32 h = leaf;
        unchecked {
            for (uint256 i = 0; i < branch.length; i++) {
                bytes32 sib = branch[i];
                if ((index & 1) == 0) {
                    // h is left child
                    h = keccak256(abi.encodePacked(h, sib));
                } else {
                    // h is right child
                    h = keccak256(abi.encodePacked(sib, h));
                }
                index >>= 1;
            }
        }
        return h;
    }

    /// View checker: is {leaf,index,branch} included under the stored txRootV2?
    function verifyInclusion(
        uint64 height,
        bytes32 leaf,
        uint256 index,
        bytes32[] calldata branch
    ) external view returns (bool ok) {
        HeaderV2 memory h = headers[height];
        require(h.height != 0, "unknown height");
        require(branch.length <= 64, "branch too deep"); // T33.6: depth cap
        return _merkleUp(leaf, index, branch) == h.txRootV2;
    }

    event TxIncluded(uint64 height, bytes32 leaf, uint256 index);

    /// Optional stateful variant that emits an audit event.
    function assertInclusion(
        uint64 height,
        bytes32 leaf,
        uint256 index,
        bytes32[] calldata branch
    ) external {
        // repeat checks here to avoid re-call gas; mirrors verifyInclusion
        HeaderV2 memory h = headers[height];
        require(h.height != 0, "unknown height");
        require(branch.length <= 64, "branch too deep");
        require(_merkleUp(leaf, index, branch) == h.txRootV2, "bad branch");
        emit TxIncluded(height, leaf, index);
    }

    // --- T34.0: rotation predicate
    function _acceptSuiteAt(uint64 height, uint32 suiteId_) internal view returns (bool) {
        if (suiteId_ == activeSuiteId) return true;
        if (nextSuiteId != 0 && suiteId_ == nextSuiteId && dualAcceptUntil != 0 && height <= dualAcceptUntil) {
            return true;
        }
        return false;
    }
}