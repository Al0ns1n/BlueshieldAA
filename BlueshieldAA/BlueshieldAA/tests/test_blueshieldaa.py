"""
Tests for BlueshieldAA
Run with: python -m pytest tests/ -v
"""

import pytest
from blueshieldaa.crypto import HashChecker


class TestHashChecker:
    def setup_method(self):
        self.hc = HashChecker()

    def test_hash_string_sha256(self):
        result = self.hc.hash_string("hello", algorithm="sha256")
        assert result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_hash_string_md5(self):
        result = self.hc.hash_string("password", algorithm="md5")
        assert result == "5f4dcc3b5aa765d61d8327deb882cf99"

    def test_identify_hash_md5(self):
        assert self.hc.identify_hash("5f4dcc3b5aa765d61d8327deb882cf99") == "md5"

    def test_identify_hash_sha256(self):
        h = "a" * 64
        assert self.hc.identify_hash(h) == "sha256"

    def test_identify_hash_sha512(self):
        h = "b" * 128
        assert self.hc.identify_hash(h) == "sha512"

    def test_hash_all_algorithms(self):
        results = self.hc.hash_all_algorithms("test")
        assert "md5" in results
        assert "sha256" in results
        assert "sha512" in results

    def test_invalid_algorithm(self):
        with pytest.raises(ValueError):
            self.hc.hash_string("test", algorithm="sha999")

    def test_random_token_length(self):
        token = self.hc.generate_random_token(16)
        assert len(token) == 32  # 16 bytes → 32 hex chars


class TestPortScanner:
    def test_import(self):
        from blueshieldaa.network import PortScanner
        scanner = PortScanner("127.0.0.1")
        assert scanner.target == "127.0.0.1"

    def test_resolve_localhost(self):
        from blueshieldaa.network import PortScanner
        scanner = PortScanner("localhost")
        ip = scanner.resolve_host()
        assert ip == "127.0.0.1"


class TestLogParser:
    def test_import(self):
        from blueshieldaa.logs import LogParser
        assert LogParser is not None
