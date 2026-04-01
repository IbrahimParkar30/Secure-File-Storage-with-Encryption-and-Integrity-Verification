"""
ethereum.py
Web3.py interface between Flask and the deployed Solidity smart contract.
Replaces the custom blockchain.py with real Ethereum interaction.

Works with local Ganache blockchain — completely free, no real ETH needed.

Key methods (same interface as the old Blockchain class):
    add_block(filename, file_hash, file_type, file_size)
    find_block_by_filename(filename)
    get_all_blocks()
    is_chain_valid()
    verify_integrity(filename, computed_hash)
"""

import json
import os
import time

from web3 import Web3
from web3.exceptions import ContractLogicError

# ── Config ───────────────────────────────────────────────────────────────
GANACHE_URL           = os.environ.get("GANACHE_URL", "http://127.0.0.1:8545")
CONTRACT_ABI_FILE     = "contract_abi.json"
CONTRACT_ADDRESS_FILE = "contract_address.txt"


# ── EthBlock — mimics the old Block class for template compatibility ──────

class EthBlock:
    """
    Wraps an Ethereum contract record to look like the old Block object.
    Provides .file_hash, .timestamp, .to_dict() so existing templates work.
    """

    def __init__(
        self,
        index:        int,
        file_name:    str,
        file_hash:    str,
        file_type:    str,
        file_size:    int,
        timestamp:    int,
        revoked:      bool,
        tx_hash:      str = "",
        block_number: int = 0,
    ):
        self.index        = index
        self.file_name    = file_name
        self.file_hash    = file_hash
        self.file_type    = file_type
        self.file_size    = file_size
        self.timestamp    = timestamp
        self.revoked      = revoked
        self.tx_hash      = tx_hash
        self.block_number = block_number

        # Compatibility with old templates that reference .hash / .previous_hash
        self.hash          = tx_hash or file_hash
        self.previous_hash = "Managed by Ethereum Network"

    def to_dict(self) -> dict:
        return {
            "index":        self.index,
            "file_name":    self.file_name,
            "file_hash":    self.file_hash,
            "file_type":    self.file_type,
            "file_size":    self.file_size,
            "timestamp":    self.timestamp,
            "revoked":      self.revoked,
            "tx_hash":      self.tx_hash,
            "block_number": self.block_number,
            # Kept for template compatibility
            "hash":          self.tx_hash or self.file_hash,
            "previous_hash": "Managed by Ethereum Network",
        }


# ── EthereumBlockchain ────────────────────────────────────────────────────

class EthereumBlockchain:
    """
    Main interface between Flask and the deployed Solidity smart contract.
    Every file upload → Ethereum transaction.
    Every file download → Ethereum contract call.
    """

    def __init__(self):
        self.w3       = Web3(Web3.HTTPProvider(GANACHE_URL))
        self.contract = None
        self.account  = None
        self._connect()

    # ── Connection ────────────────────────────────────────────

    def _connect(self) -> None:
        """Connect to Ganache and load the deployed contract."""
        if not self.w3.is_connected():
            print("[ethereum] ⚠️  Cannot connect to Ganache at", GANACHE_URL)
            print("[ethereum] Make sure Ganache is running: ganache")
            return

        # Use the first Ganache account as the owner
        self.account = self.w3.eth.accounts[0]
        print(f"[ethereum] Connected to Ganache. Account: {self.account}")

        # Load contract
        if os.path.exists(CONTRACT_ABI_FILE) and os.path.exists(CONTRACT_ADDRESS_FILE):
            try:
                with open(CONTRACT_ABI_FILE) as f:
                    abi = json.load(f)
                with open(CONTRACT_ADDRESS_FILE) as f:
                    address = f.read().strip()

                checksum_address = Web3.to_checksum_address(address)
                self.contract    = self.w3.eth.contract(
                    address = checksum_address,
                    abi     = abi,
                )
                print(f"[ethereum] Contract loaded at {checksum_address}")
            except Exception as exc:
                print(f"[ethereum] ⚠️  Failed to load contract: {exc}")
        else:
            print("[ethereum] ⚠️  Contract not deployed yet. Run: python deploy.py")

    def is_connected(self) -> bool:
        return self.w3.is_connected() and self.contract is not None

    def get_status(self) -> dict:
        """Return connection and contract status for the dashboard."""
        connected = self.w3.is_connected()
        status = {
            "connected":        connected,
            "ganache_url":      GANACHE_URL,
            "account":          None,
            "balance_eth":      None,
            "contract_address": None,
            "total_files":      0,
            "network_id":       None,
            "block_number":     None,
            "max_files":        0,
            "max_size_mb":      0,
            "expiry_days":      0,
        }
        if connected:
            status["account"]     = self.account
            status["network_id"]  = self.w3.net.version
            status["block_number"]= self.w3.eth.block_number
            try:
                bal = self.w3.eth.get_balance(self.account)
                status["balance_eth"] = round(self.w3.from_wei(bal, "ether"), 4)
            except Exception:
                pass

        if self.contract:
            try:
                status["contract_address"] = self.contract.address
                info = self.contract.functions.getContractInfo().call()
                status["total_files"] = info[1]
                status["max_files"]   = info[2]
                status["max_size_mb"] = info[3] // (1024 * 1024)
                status["expiry_days"] = info[4]
            except Exception:
                pass

        return status

    # ── Upload — register file on Ethereum ────────────────────

    def add_block(
        self,
        file_name: str,
        file_hash: str,
        file_type: str  = "",
        file_size: int  = 0,
    ) -> EthBlock:
        """
        Register a file on the Ethereum smart contract.
        Sends a real Ethereum transaction to Ganache.
        Returns an EthBlock with transaction details.
        """
        if not self.is_connected():
            raise RuntimeError("Not connected to Ethereum. Run Ganache and deploy.py first.")

        # Extract file extension if not provided
        if not file_type and "." in file_name:
            file_type = file_name.rsplit(".", 1)[-1].lower()

        try:
            # Send transaction to Solidity registerFile()
            tx_hash = self.contract.functions.registerFile(
                file_name,
                file_hash,
                file_type,
                file_size,
            ).transact({
                "from": self.account,
                "gas":  500000,
            })

            # Wait for transaction to be mined
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"[ethereum] File '{file_name}' registered. TX: {tx_hash.hex()}")

            # Read back the stored record
            record = self.contract.functions.getFileRecord(file_name).call()

            return EthBlock(
                index        = record[0],
                file_name    = record[1],
                file_hash    = record[2],
                file_type    = record[3],
                file_size    = record[4],
                timestamp    = record[5],
                revoked      = record[6],
                tx_hash      = tx_hash.hex(),
                block_number = receipt["blockNumber"],
            )

        except ContractLogicError as exc:
            # Solidity require() was triggered — extract message
            msg = str(exc)
            if "CONTRACT REJECTED" in msg:
                raise ValueError(msg)
            raise

    # ── Download — verify integrity via Ethereum ──────────────

    def verify_integrity(self, file_name: str, computed_hash: str) -> dict:
        """
        Call verifyIntegrity() on the Solidity smart contract.
        The contract compares hashes and emits events on chain.
        Returns dict with passed=True/False and tx_hash.
        """
        if not self.is_connected():
            raise RuntimeError("Not connected to Ethereum.")

        try:
            # This is a state-changing call (emits events) → transact
            tx_hash = self.contract.functions.verifyIntegrity(
                file_name,
                computed_hash,
            ).transact({
                "from": self.account,
                "gas":  300000,
            })

            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # Call (read-only) to get the return value
            passed = self.contract.functions.verifyIntegrity(
                file_name,
                computed_hash,
            ).call()

            return {
                "passed":       passed,
                "tx_hash":      tx_hash.hex(),
                "block_number": receipt["blockNumber"],
            }

        except ContractLogicError as exc:
            msg = str(exc)
            return {
                "passed":   False,
                "tx_hash":  "",
                "error":    msg,
            }

    # ── Find file record ──────────────────────────────────────

    def find_block_by_filename(self, file_name: str) -> EthBlock | None:
        """
        Read file record from the Ethereum smart contract.
        Returns EthBlock or None if file not registered.
        """
        if not self.is_connected():
            return None

        try:
            exists = self.contract.functions.doesFileExist(file_name).call()
            if not exists:
                return None

            record = self.contract.functions.getFileRecord(file_name).call()
            return EthBlock(
                index     = record[0],
                file_name = record[1],
                file_hash = record[2],
                file_type = record[3],
                file_size = record[4],
                timestamp = record[5],
                revoked   = record[6],
            )

        except Exception:
            return None

    # ── Get all blocks ────────────────────────────────────────

    def get_all_blocks(self) -> list[dict]:
        """
        Read all registered files from the smart contract.
        Returns list of dicts for the blockchain explorer page.
        """
        if not self.is_connected():
            return []

        try:
            file_names = self.contract.functions.getAllFiles().call()
            blocks     = []

            for name in file_names:
                try:
                    record = self.contract.functions.getFileRecord(name).call()
                    blocks.append({
                        "index":        record[0],
                        "file_name":    record[1],
                        "file_hash":    record[2],
                        "file_type":    record[3],
                        "file_size":    record[4],
                        "timestamp":    record[5],
                        "revoked":      record[6],
                        # Template compatibility
                        "hash":          record[2],
                        "previous_hash": "Managed by Ethereum Network",
                    })
                except Exception:
                    continue

            return blocks

        except Exception as exc:
            print(f"[ethereum] get_all_blocks error: {exc}")
            return []

    # ── Chain validity — Ethereum is always valid ─────────────

    def is_chain_valid(self) -> bool:
        """
        On Ethereum, chain integrity is guaranteed by the network.
        Returns True if connected, False if offline.
        """
        return self.is_connected()

    # ── Revoke file ───────────────────────────────────────────

    def revoke_file(self, file_name: str) -> str:
        """Revoke access to a file. Returns tx_hash."""
        if not self.is_connected():
            raise RuntimeError("Not connected to Ethereum.")

        tx_hash = self.contract.functions.revokeFile(file_name).transact({
            "from": self.account,
            "gas":  200000,
        })
        self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash.hex()

    # ── Get recent Ethereum events ────────────────────────────

    def get_recent_events(self, count: int = 20) -> list[dict]:
        """
        Fetch recent contract events from Ganache.
        Events are permanently stored on the blockchain.
        """
        if not self.is_connected():
            return []

        events = []
        try:
            latest = self.w3.eth.block_number

            # FileRegistered events
            reg_filter = self.contract.events.FileRegistered.create_filter(
                from_block = max(0, latest - 1000),
                to_block   = "latest",
            )
            for e in reg_filter.get_all_entries():
                events.append({
                    "type":         "FileRegistered",
                    "file_name":    e["args"]["fileName"],
                    "file_hash":    e["args"]["fileHash"],
                    "block_number": e["blockNumber"],
                    "tx_hash":      e["transactionHash"].hex(),
                })

            # TamperDetected events
            tamp_filter = self.contract.events.TamperDetected.create_filter(
                from_block = max(0, latest - 1000),
                to_block   = "latest",
            )
            for e in tamp_filter.get_all_entries():
                events.append({
                    "type":         "TamperDetected",
                    "file_name":    e["args"]["fileName"],
                    "stored_hash":  e["args"]["storedHash"],
                    "computed_hash":e["args"]["computedHash"],
                    "block_number": e["blockNumber"],
                    "tx_hash":      e["transactionHash"].hex(),
                })

            # IntegrityVerified events
            ver_filter = self.contract.events.IntegrityVerified.create_filter(
                from_block = max(0, latest - 1000),
                to_block   = "latest",
            )
            for e in ver_filter.get_all_entries():
                events.append({
                    "type":         "IntegrityVerified",
                    "file_name":    e["args"]["fileName"],
                    "passed":       e["args"]["passed"],
                    "block_number": e["blockNumber"],
                    "tx_hash":      e["transactionHash"].hex(),
                })

        except Exception as exc:
            print(f"[ethereum] get_recent_events error: {exc}")

        # Sort by block number descending
        events.sort(key=lambda x: x.get("block_number", 0), reverse=True)
        return events[:count]
