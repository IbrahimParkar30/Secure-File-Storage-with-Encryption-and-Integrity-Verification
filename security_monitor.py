"""
security_monitor.py
Detects filename tampering, triggers alerts, and auto-heals
by locating files via their SHA-256 hash when names are changed.

Core idea:
  - Every .enc file has a known hash stored in the blockchain
  - If filename on disk doesn't match blockchain record → ALERT
  - But we scan all .enc files, find the one whose hash matches
  - Restore the correct filename silently and safely
  - File is never lost, never corrupted
"""

import hashlib
import json
import os
import time
from datetime import datetime

ALERT_LOG_FILE   = "security_alerts.json"
ENCRYPTED_FOLDER = "encrypted"


# ──────────────────────────────────────────────────────────────────────
# SHA-256 helper
# ──────────────────────────────────────────────────────────────────────

def sha256_of_file(path: str) -> str:
    """Compute SHA-256 of a file in 64 KB chunks (memory safe)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ──────────────────────────────────────────────────────────────────────
# Alert Logger
# ──────────────────────────────────────────────────────────────────────

class SecurityAlertLogger:
    """
    Logs every security event to security_alerts.json.
    Each alert has:
        - alert_type    : what kind of attack/anomaly was detected
        - severity      : LOW / MEDIUM / HIGH / CRITICAL
        - timestamp     : when it happened
        - description   : human-readable explanation
        - details       : technical details (hashes, filenames, etc.)
        - resolved      : whether the system auto-healed it
    """

    SEVERITY_COLORS = {
        "LOW":      "secondary",
        "MEDIUM":   "warning",
        "HIGH":     "danger",
        "CRITICAL": "danger",
    }

    def __init__(self):
        self.alerts: list[dict] = self._load()

    def _load(self) -> list[dict]:
        if os.path.exists(ALERT_LOG_FILE):
            try:
                with open(ALERT_LOG_FILE, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []

    def _save(self) -> None:
        with open(ALERT_LOG_FILE, "w") as f:
            json.dump(self.alerts, f, indent=4)

    def log(
        self,
        alert_type:  str,
        severity:    str,
        description: str,
        details:     dict,
        resolved:    bool = False,
        resolution:  str  = "",
    ) -> dict:
        """Create and persist a new security alert."""
        alert = {
            "id":          len(self.alerts) + 1,
            "alert_type":  alert_type,
            "severity":    severity,
            "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "description": description,
            "details":     details,
            "resolved":    resolved,
            "resolution":  resolution,
            "color":       self.SEVERITY_COLORS.get(severity, "secondary"),
        }
        self.alerts.append(alert)
        self._save()
        print(f"[SECURITY ALERT] [{severity}] {alert_type}: {description}")
        return alert

    def get_all(self) -> list[dict]:
        return list(reversed(self.alerts))   # newest first

    def get_unresolved(self) -> list[dict]:
        return [a for a in self.alerts if not a["resolved"]]

    def count_by_severity(self) -> dict:
        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for a in self.alerts:
            sev = a.get("severity", "LOW")
            if sev in counts:
                counts[sev] += 1
        return counts


# ──────────────────────────────────────────────────────────────────────
# Security Monitor — Core Logic
# ──────────────────────────────────────────────────────────────────────

class SecurityMonitor:
    """
    The main security engine.

    On every download/verify request it:
      1. Checks if the expected .enc file exists by filename
      2. If missing → scans all .enc files to find one with matching hash
      3. If found   → ALERT logged, file auto-renamed back, operation continues
      4. If content hash mismatch → ALERT logged, download blocked
      5. All alerts written to security_alerts.json
    """

    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.logger     = SecurityAlertLogger()

    # ──────────────────────────────────────────────────────────────────
    def find_file_by_hash(self, expected_hash: str) -> str | None:
        """
        Scan every .enc file in the encrypted/ folder.
        Return the path of the file whose SHA-256 matches expected_hash.
        Returns None if no match found.
        """
        if not os.path.exists(ENCRYPTED_FOLDER):
            return None

        for fname in os.listdir(ENCRYPTED_FOLDER):
            if not fname.endswith(".enc"):
                continue
            fpath    = os.path.join(ENCRYPTED_FOLDER, fname)
            computed = sha256_of_file(fpath)
            if computed == expected_hash:
                return fpath

        return None

    # ──────────────────────────────────────────────────────────────────
    def verify_and_heal(self, filename: str) -> dict:
        """
        Full security check for a given filename.

        Returns a result dict:
        {
            "safe":         bool,   # True = safe to proceed with download
            "alert":        bool,   # True = a security event was detected
            "enc_path":     str,    # Actual path to use for decryption
            "alert_obj":    dict,   # The alert that was raised (if any)
            "message":      str,    # Human-readable summary
            "action_taken": str,    # What the system did
        }
        """
        expected_enc_path = os.path.join(ENCRYPTED_FOLDER, filename + ".enc")

        # ── Step 1: Find the blockchain record ────────────────────────
        block = self.blockchain.find_block_by_filename(filename)

        if block is None:
            # No record at all — this file was never uploaded legitimately
            alert = self.logger.log(
                alert_type  = "UNKNOWN_FILE_ACCESS",
                severity    = "HIGH",
                description = (
                    f"Download attempted for '{filename}' which has "
                    f"no blockchain record. Possible unauthorized file injection."
                ),
                details     = {
                    "requested_file": filename,
                    "blockchain_record": "NOT FOUND",
                },
                resolved    = False,
                resolution  = "Download blocked. No blockchain record exists.",
            )
            return {
                "safe":         False,
                "alert":        True,
                "enc_path":     None,
                "alert_obj":    alert,
                "message":      (
                    f"No blockchain record found for '{filename}'. "
                    f"This file was never legitimately uploaded."
                ),
                "action_taken": "BLOCKED — No blockchain record",
            }

        stored_hash = block.file_hash

        # ── Step 2: Check if expected file exists ─────────────────────
        if os.path.exists(expected_enc_path):

            # File found at expected location — verify hash
            computed_hash = sha256_of_file(expected_enc_path)

            if computed_hash == stored_hash:
                # ✅ Perfect — filename correct, hash correct
                return {
                    "safe":         True,
                    "alert":        False,
                    "enc_path":     expected_enc_path,
                    "alert_obj":    None,
                    "message":      f"'{filename}' verified successfully. All checks passed.",
                    "action_taken": "ALLOWED — File name and hash both verified",
                }

            else:
                # ⚠️ File exists but content was tampered
                alert = self.logger.log(
                    alert_type  = "FILE_CONTENT_TAMPERED",
                    severity    = "CRITICAL",
                    description = (
                        f"'{filename}' exists but its SHA-256 hash does not "
                        f"match the blockchain record. Content has been tampered."
                    ),
                    details     = {
                        "filename":      filename,
                        "stored_hash":   stored_hash,
                        "computed_hash": computed_hash,
                    },
                    resolved    = False,
                    resolution  = "Download blocked. Content integrity compromised.",
                )
                return {
                    "safe":         False,
                    "alert":        True,
                    "enc_path":     expected_enc_path,
                    "alert_obj":    alert,
                    "message":      (
                        f"CRITICAL: '{filename}' content has been tampered. "
                        f"Hash mismatch detected. Download blocked."
                    ),
                    "action_taken": "BLOCKED — Content tampered",
                }

        # ── Step 3: File NOT at expected location — scan by hash ───────
        # This is the rename detection + auto-heal logic

        found_path = self.find_file_by_hash(stored_hash)

        if found_path is not None:
            # Found the file under a DIFFERENT name — filename was changed
            current_filename = os.path.basename(found_path)

            # ── AUTO-HEAL: rename the file back to correct name ────────
            os.rename(found_path, expected_enc_path)

            # Log the alert
            alert = self.logger.log(
                alert_type  = "FILENAME_TAMPERED",
                severity    = "HIGH",
                description = (
                    f"'{filename}.enc' was renamed to '{current_filename}' on disk. "
                    f"File was located by hash scan and automatically renamed back."
                ),
                details     = {
                    "original_name":  filename + ".enc",
                    "found_as":       current_filename,
                    "file_hash":      stored_hash,
                    "auto_healed":    True,
                },
                resolved    = True,
                resolution  = (
                    f"Auto-healed: renamed '{current_filename}' back "
                    f"to '{filename}.enc'. File content unchanged and safe."
                ),
            )

            return {
                "safe":         True,
                "alert":        True,             # alert WAS raised
                "enc_path":     expected_enc_path,# now exists at correct path
                "alert_obj":    alert,
                "message":      (
                    f"SECURITY ALERT: '{filename}.enc' was renamed to "
                    f"'{current_filename}'. File was found by hash, "
                    f"automatically restored, and is safe to use."
                ),
                "action_taken": (
                    f"AUTO-HEALED — Renamed '{current_filename}' "
                    f"back to '{filename}.enc'"
                ),
            }

        # ── Step 4: File not found anywhere ───────────────────────────
        alert = self.logger.log(
            alert_type  = "FILE_MISSING",
            severity    = "CRITICAL",
            description = (
                f"'{filename}.enc' is missing from disk and could not be "
                f"found by hash scan. File may have been deleted."
            ),
            details     = {
                "filename":    filename,
                "stored_hash": stored_hash,
                "scanned_dir": ENCRYPTED_FOLDER,
            },
            resolved    = False,
            resolution  = "Cannot recover. File is permanently missing.",
        )

        return {
            "safe":         False,
            "alert":        True,
            "enc_path":     None,
            "alert_obj":    alert,
            "message":      (
                f"'{filename}' is missing from storage and could not be "
                f"located by hash scan. File may have been deleted."
            ),
            "action_taken": "BLOCKED — File missing, cannot recover",
        }

    # ──────────────────────────────────────────────────────────────────
    def scan_all_files(self) -> list[dict]:
        """
        Full integrity scan of all files in encrypted/.
        Compares every .enc file against its blockchain record.
        Returns a list of scan results — one per file.
        """
        results = []

        if not os.path.exists(ENCRYPTED_FOLDER):
            return results

        all_blocks = {
            b["file_name"]: b
            for b in self.blockchain.get_all_blocks()
            if b["file_name"] != "GENESIS"
        }

        for fname in os.listdir(ENCRYPTED_FOLDER):
            if not fname.endswith(".enc"):
                continue

            original_name = fname.replace(".enc", "")
            fpath         = os.path.join(ENCRYPTED_FOLDER, fname)
            computed_hash = sha256_of_file(fpath)

            if original_name in all_blocks:
                stored_hash = all_blocks[original_name]["file_hash"]
                status      = "OK" if computed_hash == stored_hash else "TAMPERED"
            else:
                stored_hash = "N/A — No blockchain record"
                status      = "UNKNOWN"

            results.append({
                "filename":      original_name,
                "physical_file": fname,
                "computed_hash": computed_hash,
                "stored_hash":   stored_hash,
                "status":        status,
            })

        return results
