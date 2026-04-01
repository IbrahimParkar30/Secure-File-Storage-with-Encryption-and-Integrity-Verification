// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// FileStorageContract.sol
// Real Ethereum Smart Contract for Secure File Storage.
// Deployed on local Ganache blockchain — free, no real ETH.
//
// Smart Contract Rules (auto-enforced, cannot be bypassed):
//   1. File size must not exceed maxFileSize
//   2. File type must be in the approved whitelist
//   3. Total files must not exceed maxFiles quota
//   4. No duplicate file registrations
//   5. File integrity verified via SHA-256 hash comparison
//   6. File expiry enforced at download time
//   7. Revoked files cannot be downloaded
// ============================================================

contract FileStorageContract {

    // ── State Variables ─────────────────────────────────────
    address public owner;
    uint256 public fileCount;

    // Contract rules — owner can update these
    uint256 public maxFileSize    = 10 * 1024 * 1024;       // 10 MB in bytes
    uint256 public maxFiles       = 20;                      // max 20 files
    uint256 public expirySeconds  = 30 * 24 * 60 * 60;      // 30 days

    // Approved file type whitelist
    mapping(string => bool) public allowedTypes;

    // ── File Record Structure ────────────────────────────────
    struct FileRecord {
        uint256 index;          // Sequential file number
        string  fileName;       // Original file name
        string  fileHash;       // SHA-256 of encrypted file
        string  fileType;       // Extension (pdf, txt, etc.)
        uint256 fileSize;       // Size in bytes
        uint256 uploadTime;     // Unix timestamp of upload
        bool    exists;         // True if registered
        bool    revoked;        // True if owner revoked access
    }

    // fileName => FileRecord (permanent on-chain storage)
    mapping(string => FileRecord) private records;

    // Ordered list of all registered file names
    string[] private fileList;

    // ── Events (permanently logged on blockchain) ────────────
    // These are visible in Ganache transaction logs forever

    event FileRegistered(
        string  indexed fileName,
        string          fileHash,
        uint256         fileSize,
        uint256         uploadTime,
        uint256 indexed ethBlockNumber
    );

    event IntegrityVerified(
        string  indexed fileName,
        bool            passed,
        uint256         timestamp
    );

    event TamperDetected(
        string  indexed fileName,
        string          storedHash,
        string          computedHash,
        uint256         timestamp
    );

    event FileRevoked(
        string  indexed fileName,
        uint256         timestamp
    );

    event ContractAlert(
        string  alertType,
        string  message,
        uint256 timestamp
    );

    // ── Modifiers ────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the contract owner can call this.");
        _;
    }

    modifier fileExists(string memory _fileName) {
        require(records[_fileName].exists, "File not found on blockchain.");
        _;
    }

    modifier notRevoked(string memory _fileName) {
        require(!records[_fileName].revoked, "File access has been revoked.");
        _;
    }

    // ── Constructor — runs ONCE when contract is deployed ────
    constructor() {
        owner = msg.sender;

        // Set approved file types
        allowedTypes["txt"]  = true;
        allowedTypes["pdf"]  = true;
        allowedTypes["png"]  = true;
        allowedTypes["jpg"]  = true;
        allowedTypes["jpeg"] = true;
        allowedTypes["gif"]  = true;
        allowedTypes["docx"] = true;
        allowedTypes["xlsx"] = true;
        allowedTypes["csv"]  = true;
        allowedTypes["zip"]  = true;
        allowedTypes["mp3"]  = true;
        allowedTypes["mp4"]  = true;
    }

    // ============================================================
    // SMART CONTRACT 1 — registerFile()
    // Called on every upload. Enforces all upload rules.
    // If any rule fails → entire transaction reverted, nothing saved.
    // ============================================================
    function registerFile(
        string memory _fileName,
        string memory _fileHash,
        string memory _fileType,
        uint256       _fileSize
    )
        public
        onlyOwner
        returns (uint256 index)
    {
        // Rule 1: No duplicate filenames
        require(
            !records[_fileName].exists,
            "CONTRACT REJECTED: File already registered on blockchain."
        );

        // Rule 2: File size limit
        require(
            _fileSize <= maxFileSize,
            "CONTRACT REJECTED: File exceeds maximum allowed size."
        );

        // Rule 3: Approved file types only
        require(
            allowedTypes[_fileType],
            "CONTRACT REJECTED: File type not in approved whitelist."
        );

        // Rule 4: Storage quota
        require(
            fileCount < maxFiles,
            "CONTRACT REJECTED: Storage quota reached. Delete files first."
        );

        // All rules passed — store permanently on blockchain
        records[_fileName] = FileRecord({
            index:      fileCount,
            fileName:   _fileName,
            fileHash:   _fileHash,
            fileType:   _fileType,
            fileSize:   _fileSize,
            uploadTime: block.timestamp,
            exists:     true,
            revoked:    false
        });

        fileList.push(_fileName);
        fileCount++;

        // Emit event — permanently logged on Ethereum
        emit FileRegistered(
            _fileName,
            _fileHash,
            _fileSize,
            block.timestamp,
            block.number
        );

        return fileCount - 1;
    }

    // ============================================================
    // SMART CONTRACT 2 — verifyIntegrity()
    // Called on every download. Compares hash with stored record.
    // Emits TamperDetected event if mismatch found.
    // ============================================================
    function verifyIntegrity(
        string memory _fileName,
        string memory _computedHash
    )
        public
        fileExists(_fileName)
        notRevoked(_fileName)
        returns (bool passed)
    {
        FileRecord memory r = records[_fileName];

        // Rule: File expiry check
        require(
            block.timestamp <= r.uploadTime + expirySeconds,
            "CONTRACT REJECTED: File has expired."
        );

        // Compare SHA-256 hashes using keccak256 encoding
        passed = (
            keccak256(abi.encodePacked(r.fileHash)) ==
            keccak256(abi.encodePacked(_computedHash))
        );

        if (!passed) {
            // Emit tamper alert — visible in Ganache forever
            emit TamperDetected(
                _fileName,
                r.fileHash,
                _computedHash,
                block.timestamp
            );
            emit ContractAlert(
                "TAMPER_DETECTED",
                string(abi.encodePacked("Hash mismatch for file: ", _fileName)),
                block.timestamp
            );
        }

        emit IntegrityVerified(_fileName, passed, block.timestamp);
        return passed;
    }

    // ============================================================
    // SMART CONTRACT 3 — revokeFile()
    // Owner can permanently revoke access to a file.
    // Once revoked, file cannot be downloaded — ever.
    // ============================================================
    function revokeFile(string memory _fileName)
        public
        onlyOwner
        fileExists(_fileName)
    {
        records[_fileName].revoked = true;
        emit FileRevoked(_fileName, block.timestamp);
        emit ContractAlert(
            "FILE_REVOKED",
            string(abi.encodePacked("Access revoked for: ", _fileName)),
            block.timestamp
        );
    }

    // ── Read Functions (no gas cost — view only) ─────────────

    function getFileRecord(string memory _fileName)
        public
        view
        fileExists(_fileName)
        returns (
            uint256 index,
            string  memory fileName,
            string  memory fileHash,
            string  memory fileType,
            uint256 fileSize,
            uint256 uploadTime,
            bool    revoked
        )
    {
        FileRecord memory r = records[_fileName];
        return (
            r.index,
            r.fileName,
            r.fileHash,
            r.fileType,
            r.fileSize,
            r.uploadTime,
            r.revoked
        );
    }

    function getAllFiles() public view returns (string[] memory) {
        return fileList;
    }

    function doesFileExist(string memory _fileName) public view returns (bool) {
        return records[_fileName].exists;
    }

    function isFileExpired(string memory _fileName)
        public
        view
        fileExists(_fileName)
        returns (bool)
    {
        return block.timestamp > records[_fileName].uploadTime + expirySeconds;
    }

    function isFileRevoked(string memory _fileName)
        public
        view
        fileExists(_fileName)
        returns (bool)
    {
        return records[_fileName].revoked;
    }

    // ── Owner Administration Functions ───────────────────────

    function setMaxFileSize(uint256 _bytes) public onlyOwner {
        maxFileSize = _bytes;
    }

    function setMaxFiles(uint256 _max) public onlyOwner {
        maxFiles = _max;
    }

    function setExpirySeconds(uint256 _seconds) public onlyOwner {
        expirySeconds = _seconds;
    }

    function addAllowedType(string memory _ext) public onlyOwner {
        allowedTypes[_ext] = true;
    }

    function removeAllowedType(string memory _ext) public onlyOwner {
        allowedTypes[_ext] = false;
    }

    function getContractInfo()
        public
        view
        returns (
            address contractOwner,
            uint256 totalFiles,
            uint256 maxFilesAllowed,
            uint256 maxFileSizeBytes,
            uint256 expiryDays
        )
    {
        return (
            owner,
            fileCount,
            maxFiles,
            maxFileSize,
            expirySeconds / 86400
        );
    }
}
