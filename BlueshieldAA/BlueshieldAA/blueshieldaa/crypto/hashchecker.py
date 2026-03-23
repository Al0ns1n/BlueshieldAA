"""
blueshieldaa.crypto.hashchecker
---------------------------------
Hash generation, verification, and file integrity utilities.
"""

import hashlib
import hmac
import os
from typing import Optional, Dict


SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]


class HashChecker:
    """
    Hash and integrity utilities for blue team analysis.

    Example:
        hc = HashChecker()
        print(hc.hash_string("password", algorithm="sha256"))
        print(hc.verify_file("malware.exe", expected="abc123...", algorithm="sha256"))
    """

    def hash_string(self, text: str, algorithm: str = "sha256") -> str:
        """
        Compute the hash of a plain string.

        Args:
            text: Input string.
            algorithm: Hash algorithm (md5, sha1, sha256, sha512...).

        Returns:
            Hex digest string.
        """
        self._validate_algorithm(algorithm)
        return hashlib.new(algorithm, text.encode()).hexdigest()

    def hash_file(self, filepath: str, algorithm: str = "sha256", chunk_size: int = 8192) -> str:
        """
        Compute the hash of a file efficiently (chunked reading).

        Args:
            filepath: Path to the file.
            algorithm: Hash algorithm to use.
            chunk_size: Read chunk size in bytes.

        Returns:
            Hex digest string.
        """
        self._validate_algorithm(algorithm)
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()

    def verify_file(self, filepath: str, expected: str, algorithm: str = "sha256") -> bool:
        """
        Verify file integrity against an expected hash.

        Args:
            filepath: Path to the file to verify.
            expected: Expected hash value.
            algorithm: Hash algorithm.

        Returns:
            True if the file matches the expected hash, False otherwise.
        """
        actual = self.hash_file(filepath, algorithm)
        return hmac.compare_digest(actual.lower(), expected.lower())

    def hash_all_algorithms(self, text: str) -> Dict[str, str]:
        """
        Return hashes of a string using all supported algorithms.

        Args:
            text: Input string.

        Returns:
            Dict mapping algorithm name to hex digest.
        """
        return {algo: self.hash_string(text, algo) for algo in SUPPORTED_ALGORITHMS}

    def identify_hash(self, hash_value: str) -> Optional[str]:
        """
        Guess the algorithm based on hash length.

        Args:
            hash_value: A hash string to identify.

        Returns:
            Probable algorithm name or None.
        """
        length_map = {
            32: "md5",
            40: "sha1",
            56: "sha224",
            64: "sha256",
            96: "sha384",
            128: "sha512",
        }
        return length_map.get(len(hash_value.strip()))

    def generate_random_token(self, length: int = 32) -> str:
        """
        Generate a cryptographically secure random hex token.

        Args:
            length: Number of random bytes (output will be 2x in hex).

        Returns:
            Secure hex token string.
        """
        return os.urandom(length).hex()

    @staticmethod
    def _validate_algorithm(algorithm: str):
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm: '{algorithm}'. "
                f"Choose from: {SUPPORTED_ALGORITHMS}"
            )
