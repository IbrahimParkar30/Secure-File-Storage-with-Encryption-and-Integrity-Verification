"""
blockchain.py
Custom in-process blockchain stored as chain.json.
Each block records file upload metadata and links to the previous block
via SHA-256 hashing, making tampering detectable.
"""

import hashlib
import json
import os
import time

CHAIN_FILE = "chain.json"


class Block:
    """Represents a single block in the blockchain."""

    def __init__(
        self,
        index: int,
        timestamp: float,
        file_name: str,
        file_hash: str,
        previous_hash: str,
    ):
        self.index         = index
        self.timestamp     = timestamp
        self.file_name     = file_name
        self.file_hash     = file_hash          # SHA-256 of the encrypted file
        self.previous_hash = previous_hash
        self.hash          = self.calculate_hash()

    # ------------------------------------------------------------------
    def calculate_hash(self) -> str:
        """
        Compute the SHA-256 hash of this block's contents.
        All fields are concatenated as a UTF-8 string before hashing.
        """
        block_string = (
            str(self.index)
            + str(self.timestamp)
            + self.file_name
            + self.file_hash
            + self.previous_hash
        )
        return hashlib.sha256(block_string.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        """Serialise the block to a plain Python dict for JSON storage."""
        return {
            "index":         self.index,
            "timestamp":     self.timestamp,
            "file_name":     self.file_name,
            "file_hash":     self.file_hash,
            "previous_hash": self.previous_hash,
            "hash":          self.hash,
        }

    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict) -> "Block":
        """Rebuild a Block object from a dict (loaded from JSON)."""
        block = cls(
            index         = data["index"],
            timestamp     = data["timestamp"],
            file_name     = data["file_name"],
            file_hash     = data["file_hash"],
            previous_hash = data["previous_hash"],
        )
        # Override the freshly computed hash with the stored one so we
        # can detect tampering when is_chain_valid() reruns the hash.
        block.hash = data["hash"]
        return block


# ======================================================================

class Blockchain:
    """
    A simple append-only blockchain backed by a JSON file (chain.json).
    The first block is always the hardcoded Genesis block.
    """

    def __init__(self):
        self.chain: list[Block] = []
        self._load_or_init()

    # ------------------------------------------------------------------
    def _create_genesis_block(self) -> Block:
        """Return the fixed genesis (first) block with zeroed hashes."""
        return Block(
            index         = 0,
            timestamp     = 0.0,
            file_name     = "GENESIS",
            file_hash     = "0" * 64,
            previous_hash = "0" * 64,
        )

    # ------------------------------------------------------------------
    def _load_or_init(self) -> None:
        """
        Load chain from chain.json if it exists and is valid.
        Otherwise start a fresh chain with only the Genesis block.
        """
        if os.path.exists(CHAIN_FILE):
            try:
                with open(CHAIN_FILE, "r") as f:
                    data = json.load(f)
                self.chain = [Block.from_dict(b) for b in data]
                print(f"[blockchain] Loaded {len(self.chain)} block(s) from {CHAIN_FILE}.")
                return
            except (json.JSONDecodeError, KeyError) as exc:
                print(f"[blockchain] WARNING – could not parse {CHAIN_FILE}: {exc}. Starting fresh.")

        # Fresh start
        self.chain = [self._create_genesis_block()]
        self._save()
        print(f"[blockchain] Initialised new chain with Genesis block.")

    # ------------------------------------------------------------------
    def _save(self) -> None:
        """Persist the entire chain to chain.json."""
        with open(CHAIN_FILE, "w") as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=4)

    # ------------------------------------------------------------------
    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    # ------------------------------------------------------------------
    def add_block(self, file_name: str, file_hash: str) -> Block:
        """
        Append a new block that records an uploaded file.

        Args:
            file_name : Original name of the uploaded file.
            file_hash : SHA-256 hash of the encrypted file bytes.

        Returns:
            The newly created Block.
        """
        new_block = Block(
            index         = len(self.chain),
            timestamp     = time.time(),
            file_name     = file_name,
            file_hash     = file_hash,
            previous_hash = self.last_block.hash,
        )
        self.chain.append(new_block)
        self._save()
        print(f"[blockchain] Block #{new_block.index} added for '{file_name}'.")
        return new_block

    # ------------------------------------------------------------------
    def is_chain_valid(self) -> bool:
        """
        Walk every block (skipping Genesis) and verify:
          1. The stored hash matches a freshly computed hash.
          2. previous_hash matches the actual hash of the preceding block.

        Returns True only if all checks pass.
        """
        for i in range(1, len(self.chain)):
            current  = self.chain[i]
            previous = self.chain[i - 1]

            # Re-compute hash and compare with stored value
            recomputed = Block(
                index         = current.index,
                timestamp     = current.timestamp,
                file_name     = current.file_name,
                file_hash     = current.file_hash,
                previous_hash = current.previous_hash,
            ).calculate_hash()

            if current.hash != recomputed:
                print(f"[blockchain] Block #{i} hash mismatch!")
                return False

            if current.previous_hash != previous.hash:
                print(f"[blockchain] Block #{i} previous_hash mismatch!")
                return False

        return True

    # ------------------------------------------------------------------
    def find_block_by_filename(self, file_name: str) -> Block | None:
        """
        Search the chain for the most-recent block matching file_name.
        Returns None if not found.
        """
        for block in reversed(self.chain):
            if block.file_name == file_name:
                return block
        return None

    # ------------------------------------------------------------------
    def get_all_blocks(self) -> list[dict]:
        """Return all blocks as a list of dicts (for display)."""
        return [b.to_dict() for b in self.chain]
