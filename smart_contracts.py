"""
smart_contracts.py
Simulates blockchain smart contracts in pure Python.
Each contract defines a CONDITION and an ACTION that executes automatically
when triggered — mimicking how Ethereum smart contracts work, but locally.

Contracts are stored in contracts.json and their execution logs are
appended to the blockchain.
"""

import json
import os
import time
from datetime import datetime

CONTRACTS_FILE = "contracts.json"


# ============================================================
# BASE CONTRACT CLASS
# ============================================================

class SmartContract:
    """
    Base class for all smart contracts.
    Every contract has:
      - name        : unique identifier
      - description : human-readable explanation
      - enabled     : can be toggled on/off
      - execute()   : the logic that runs automatically
    """

    def __init__(self, name: str, description: str, enabled: bool = True):
        self.name        = name
        self.description = description
        self.enabled     = enabled

    def execute(self, context: dict) -> dict:
        """
        Run the contract logic.
        context : dict of data passed by the triggering event
        Returns : { "passed": bool, "message": str, "action": str }
        """
        raise NotImplementedError("Each contract must implement execute()")

    def to_dict(self) -> dict:
        return {
            "name":        self.name,
            "description": self.description,
            "enabled":     self.enabled,
            "type":        self.__class__.__name__,
        }


# ============================================================
# CONTRACT 1 — FILE EXPIRY
# ============================================================

class FileExpiryContract(SmartContract):
    """
    Blocks file download if the file was uploaded more than
    `max_days` days ago. Auto-enforced on every download attempt.
    """

    def __init__(self, max_days: int = 30, enabled: bool = True):
        super().__init__(
            name        = "FileExpiryContract",
            description = f"Block download of files older than {max_days} days.",
            enabled     = enabled,
        )
        self.max_days = max_days

    def execute(self, context: dict) -> dict:
        """
        context must contain:
            upload_timestamp : float (Unix time when file was uploaded)
            file_name        : str
        """
        if not self.enabled:
            return {"passed": True, "message": "Contract disabled.", "action": "SKIPPED"}

        upload_ts = context.get("upload_timestamp", 0)
        age_days  = (time.time() - upload_ts) / 86400   # seconds → days
        file_name = context.get("file_name", "unknown")

        if age_days > self.max_days:
            return {
                "passed":  False,
                "message": (
                    f"CONTRACT REJECTED: '{file_name}' is {age_days:.1f} days old. "
                    f"Maximum allowed age is {self.max_days} days."
                ),
                "action":  "BLOCK_DOWNLOAD",
            }

        remaining = self.max_days - age_days
        return {
            "passed":  True,
            "message": f"File valid. {remaining:.1f} days remaining before expiry.",
            "action":  "ALLOW",
        }

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["max_days"] = self.max_days
        return d


# ============================================================
# CONTRACT 2 — FILE SIZE LIMIT
# ============================================================

class FileSizeLimitContract(SmartContract):
    """
    Rejects any file upload that exceeds `max_bytes` in size.
    Enforced at upload time before encryption.
    """

    def __init__(self, max_bytes: int = 10 * 1024 * 1024, enabled: bool = True):
        # Default: 10 MB
        super().__init__(
            name        = "FileSizeLimitContract",
            description = f"Reject uploads larger than {max_bytes // (1024*1024)} MB.",
            enabled     = enabled,
        )
        self.max_bytes = max_bytes

    def execute(self, context: dict) -> dict:
        """
        context must contain:
            file_size : int (bytes)
            file_name : str
        """
        if not self.enabled:
            return {"passed": True, "message": "Contract disabled.", "action": "SKIPPED"}

        file_size = context.get("file_size", 0)
        file_name = context.get("file_name", "unknown")
        size_mb   = file_size / (1024 * 1024)
        limit_mb  = self.max_bytes / (1024 * 1024)

        if file_size > self.max_bytes:
            return {
                "passed":  False,
                "message": (
                    f"CONTRACT REJECTED: '{file_name}' is {size_mb:.2f} MB. "
                    f"Maximum allowed size is {limit_mb:.0f} MB."
                ),
                "action":  "BLOCK_UPLOAD",
            }

        return {
            "passed":  True,
            "message": f"File size {size_mb:.2f} MB is within the {limit_mb:.0f} MB limit.",
            "action":  "ALLOW",
        }

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["max_bytes"] = self.max_bytes
        d["max_mb"]    = self.max_bytes // (1024 * 1024)
        return d


# ============================================================
# CONTRACT 3 — FILE TYPE RESTRICTION
# ============================================================

class FileTypeRestrictionContract(SmartContract):
    """
    Only allows files with extensions in the approved whitelist.
    Enforced at upload time.
    """

    DEFAULT_ALLOWED = {"txt", "pdf", "png", "jpg", "jpeg", "docx", "xlsx", "csv"}

    def __init__(self, allowed_types: set = None, enabled: bool = True):
        self.allowed_types = allowed_types or self.DEFAULT_ALLOWED
        super().__init__(
            name        = "FileTypeRestrictionContract",
            description = f"Only allow file types: {', '.join(sorted(self.allowed_types))}.",
            enabled     = enabled,
        )

    def execute(self, context: dict) -> dict:
        """
        context must contain:
            file_name : str  (original filename with extension)
        """
        if not self.enabled:
            return {"passed": True, "message": "Contract disabled.", "action": "SKIPPED"}

        file_name = context.get("file_name", "")
        ext       = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""

        if ext not in self.allowed_types:
            return {
                "passed":  False,
                "message": (
                    f"CONTRACT REJECTED: '.{ext}' files are not permitted. "
                    f"Allowed types: {', '.join(sorted(self.allowed_types))}."
                ),
                "action":  "BLOCK_UPLOAD",
            }

        return {
            "passed":  True,
            "message": f"File type '.{ext}' is approved by the contract.",
            "action":  "ALLOW",
        }

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["allowed_types"] = sorted(list(self.allowed_types))
        return d


# ============================================================
# CONTRACT 4 — MAX UPLOADS LIMIT
# ============================================================

class MaxUploadsContract(SmartContract):
    """
    Prevents new uploads once the total stored file count
    reaches `max_files`. Acts like a storage quota.
    """

    def __init__(self, max_files: int = 20, enabled: bool = True):
        super().__init__(
            name        = "MaxUploadsContract",
            description = f"Limit total stored files to {max_files}.",
            enabled     = enabled,
        )
        self.max_files = max_files

    def execute(self, context: dict) -> dict:
        """
        context must contain:
            current_count : int  (number of files currently stored)
        """
        if not self.enabled:
            return {"passed": True, "message": "Contract disabled.", "action": "SKIPPED"}

        current_count = context.get("current_count", 0)

        if current_count >= self.max_files:
            return {
                "passed":  False,
                "message": (
                    f"CONTRACT REJECTED: Storage quota reached. "
                    f"{current_count}/{self.max_files} files stored. "
                    f"Delete files before uploading new ones."
                ),
                "action":  "BLOCK_UPLOAD",
            }

        remaining = self.max_files - current_count
        return {
            "passed":  True,
            "message": f"{current_count}/{self.max_files} files stored. {remaining} slots remaining.",
            "action":  "ALLOW",
        }

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["max_files"] = self.max_files
        return d


# ============================================================
# CONTRACT 5 — INTEGRITY CONTRACT
# ============================================================

class IntegrityContract(SmartContract):
    """
    Automatically verifies the SHA-256 hash of the encrypted file
    against the blockchain record on every download attempt.
    This is the core security contract — always enabled.
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            name        = "IntegrityContract",
            description = "Auto-verify SHA-256 hash against blockchain on every download.",
            enabled     = enabled,
        )

    def execute(self, context: dict) -> dict:
        """
        context must contain:
            stored_hash   : str  (hash from blockchain)
            computed_hash : str  (freshly computed hash of file on disk)
            file_name     : str
        """
        if not self.enabled:
            return {"passed": True, "message": "Contract disabled.", "action": "SKIPPED"}

        stored_hash   = context.get("stored_hash",   "")
        computed_hash = context.get("computed_hash", "")
        file_name     = context.get("file_name",     "unknown")

        if stored_hash != computed_hash:
            return {
                "passed":  False,
                "message": (
                    f"CONTRACT REJECTED: Integrity check failed for '{file_name}'. "
                    f"Stored hash does not match computed hash. FILE TAMPERED!"
                ),
                "action":  "BLOCK_DOWNLOAD",
            }

        return {
            "passed":  True,
            "message": f"Integrity verified for '{file_name}'. Hashes match perfectly.",
            "action":  "ALLOW",
        }


# ============================================================
# CONTRACT ENGINE
# ============================================================

class ContractEngine:
    """
    Manages all smart contracts.
    Loads/saves contract settings from contracts.json.
    Provides execute_upload_contracts() and execute_download_contracts()
    which run all relevant contracts and return a combined result.
    """

    def __init__(self):
        self.contracts = self._load_contracts()
        self.execution_log: list[dict] = []

    # ----------------------------------------------------------
    def _default_contracts(self) -> list[SmartContract]:
        """Return the default set of contracts on first run."""
        return [
            FileSizeLimitContract(max_bytes=10 * 1024 * 1024, enabled=True),
            FileTypeRestrictionContract(enabled=True),
            MaxUploadsContract(max_files=20, enabled=True),
            FileExpiryContract(max_days=30, enabled=True),
            IntegrityContract(enabled=True),
        ]

    # ----------------------------------------------------------
    def _load_contracts(self) -> list[SmartContract]:
        """
        Load contract settings from contracts.json.
        If file doesn't exist, create defaults.
        """
        if not os.path.exists(CONTRACTS_FILE):
            contracts = self._default_contracts()
            self._save_contracts(contracts)
            return contracts

        try:
            with open(CONTRACTS_FILE, "r") as f:
                data = json.load(f)

            contracts = []
            for item in data:
                ctype   = item.get("type", "")
                enabled = item.get("enabled", True)

                if ctype == "FileSizeLimitContract":
                    contracts.append(FileSizeLimitContract(
                        max_bytes = item.get("max_bytes", 10 * 1024 * 1024),
                        enabled   = enabled,
                    ))
                elif ctype == "FileTypeRestrictionContract":
                    contracts.append(FileTypeRestrictionContract(
                        allowed_types = set(item.get("allowed_types", [])),
                        enabled       = enabled,
                    ))
                elif ctype == "MaxUploadsContract":
                    contracts.append(MaxUploadsContract(
                        max_files = item.get("max_files", 20),
                        enabled   = enabled,
                    ))
                elif ctype == "FileExpiryContract":
                    contracts.append(FileExpiryContract(
                        max_days = item.get("max_days", 30),
                        enabled  = enabled,
                    ))
                elif ctype == "IntegrityContract":
                    contracts.append(IntegrityContract(enabled=enabled))

            return contracts

        except (json.JSONDecodeError, KeyError):
            contracts = self._default_contracts()
            self._save_contracts(contracts)
            return contracts

    # ----------------------------------------------------------
    def _save_contracts(self, contracts: list[SmartContract]) -> None:
        with open(CONTRACTS_FILE, "w") as f:
            json.dump([c.to_dict() for c in contracts], f, indent=4)

    # ----------------------------------------------------------
    def save(self) -> None:
        self._save_contracts(self.contracts)

    # ----------------------------------------------------------
    def get_contract(self, name: str) -> SmartContract | None:
        for c in self.contracts:
            if c.name == name:
                return c
        return None

    # ----------------------------------------------------------
    def toggle_contract(self, name: str) -> bool:
        """Enable/disable a contract by name. Returns new enabled state."""
        contract = self.get_contract(name)
        if contract:
            contract.enabled = not contract.enabled
            self.save()
            return contract.enabled
        return False

    # ----------------------------------------------------------
    def _log_execution(self, contract_name: str, result: dict, context: dict) -> dict:
        """Record a contract execution to the in-memory log."""
        entry = {
            "contract":  contract_name,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "passed":    result["passed"],
            "message":   result["message"],
            "action":    result["action"],
            "file":      context.get("file_name", "N/A"),
        }
        self.execution_log.append(entry)
        return entry

    # ----------------------------------------------------------
    def execute_upload_contracts(self, context: dict) -> dict:
        """
        Run all upload-phase contracts:
            FileSizeLimitContract
            FileTypeRestrictionContract
            MaxUploadsContract

        Returns first failure, or success if all pass.
        context must contain: file_name, file_size, current_count
        """
        upload_contracts = [
            "FileSizeLimitContract",
            "FileTypeRestrictionContract",
            "MaxUploadsContract",
        ]

        results = []
        for c in self.contracts:
            if c.name not in upload_contracts:
                continue
            result = c.execute(context)
            self._log_execution(c.name, result, context)
            results.append({"contract": c.name, **result})
            if not result["passed"]:
                return {
                    "passed":  False,
                    "message": result["message"],
                    "action":  result["action"],
                    "results": results,
                }

        return {
            "passed":  True,
            "message": "All upload contracts passed.",
            "action":  "ALLOW",
            "results": results,
        }

    # ----------------------------------------------------------
    def execute_download_contracts(self, context: dict) -> dict:
        """
        Run all download-phase contracts:
            IntegrityContract
            FileExpiryContract

        Returns first failure, or success if all pass.
        context must contain: file_name, stored_hash, computed_hash, upload_timestamp
        """
        download_contracts = [
            "IntegrityContract",
            "FileExpiryContract",
        ]

        results = []
        for c in self.contracts:
            if c.name not in download_contracts:
                continue
            result = c.execute(context)
            self._log_execution(c.name, result, context)
            results.append({"contract": c.name, **result})
            if not result["passed"]:
                return {
                    "passed":  False,
                    "message": result["message"],
                    "action":  result["action"],
                    "results": results,
                }

        return {
            "passed":  True,
            "message": "All download contracts passed.",
            "action":  "ALLOW",
            "results": results,
        }

    # ----------------------------------------------------------
    def get_all_contracts_info(self) -> list[dict]:
        return [c.to_dict() for c in self.contracts]

    # ----------------------------------------------------------
    def get_execution_log(self) -> list[dict]:
        return list(reversed(self.execution_log))
