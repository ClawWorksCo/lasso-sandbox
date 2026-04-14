"""Tests for cryptographic utilities — key generation, signing, and hashing."""

import hashlib

from lasso.utils.crypto import generate_key, hash_file, sign_config, verify_config

# ---------------------------------------------------------------------------
# generate_key
# ---------------------------------------------------------------------------

class TestGenerateKey:
    def test_returns_bytes(self):
        key = generate_key()
        assert isinstance(key, bytes)

    def test_default_length_32(self):
        key = generate_key()
        assert len(key) == 32

    def test_custom_length(self):
        key = generate_key(length=64)
        assert len(key) == 64

    def test_unique_each_call(self):
        keys = {generate_key() for _ in range(50)}
        assert len(keys) == 50

    def test_small_key(self):
        key = generate_key(length=1)
        assert len(key) == 1


# ---------------------------------------------------------------------------
# sign_config + verify_config
# ---------------------------------------------------------------------------

class TestSignAndVerify:
    def test_sign_returns_hex_string(self):
        key = generate_key()
        sig = sign_config('{"name": "test"}', key)
        assert isinstance(sig, str)
        # SHA-256 hex digest is 64 chars
        assert len(sig) == 64
        # All hex characters
        assert all(c in "0123456789abcdef" for c in sig)

    def test_signed_config_verifies_true(self):
        key = generate_key()
        config = '{"profile": "evaluation", "network": "none"}'
        sig = sign_config(config, key)
        assert verify_config(config, sig, key) is True

    def test_tampered_config_verifies_false(self):
        key = generate_key()
        config = '{"profile": "evaluation", "network": "none"}'
        sig = sign_config(config, key)
        tampered = '{"profile": "evaluation", "network": "full"}'
        assert verify_config(tampered, sig, key) is False

    def test_wrong_key_verifies_false(self):
        key1 = generate_key()
        key2 = generate_key()
        config = '{"data": "sensitive"}'
        sig = sign_config(config, key1)
        assert verify_config(config, sig, key2) is False

    def test_empty_config(self):
        key = generate_key()
        sig = sign_config("", key)
        assert verify_config("", sig, key) is True
        assert verify_config("x", sig, key) is False

    def test_tampered_signature_verifies_false(self):
        key = generate_key()
        config = '{"secure": true}'
        sig = sign_config(config, key)
        tampered_sig = "0" * 64
        assert verify_config(config, tampered_sig, key) is False

    def test_deterministic_signature(self):
        key = generate_key()
        config = '{"deterministic": "test"}'
        sig1 = sign_config(config, key)
        sig2 = sign_config(config, key)
        assert sig1 == sig2


# ---------------------------------------------------------------------------
# hash_file
# ---------------------------------------------------------------------------

class TestHashFile:
    def test_correct_sha256_for_known_content(self, tmp_path):
        f = tmp_path / "known.txt"
        content = b"hello world\n"
        f.write_bytes(content)

        result = hash_file(f)
        expected = hashlib.sha256(content).hexdigest()
        assert result == expected

    def test_different_content_gives_different_hash(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_bytes(b"content A")
        f2.write_bytes(b"content B")

        h1 = hash_file(f1)
        h2 = hash_file(f2)
        assert h1 != h2

    def test_same_content_gives_same_hash(self, tmp_path):
        f1 = tmp_path / "copy1.txt"
        f2 = tmp_path / "copy2.txt"
        f1.write_bytes(b"identical content")
        f2.write_bytes(b"identical content")

        assert hash_file(f1) == hash_file(f2)

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")

        result = hash_file(f)
        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_returns_hex_string(self, tmp_path):
        f = tmp_path / "hex.txt"
        f.write_bytes(b"data")

        result = hash_file(f)
        assert isinstance(result, str)
        assert len(result) == 64

    def test_binary_file(self, tmp_path):
        f = tmp_path / "binary.bin"
        f.write_bytes(bytes(range(256)))

        result = hash_file(f)
        expected = hashlib.sha256(bytes(range(256))).hexdigest()
        assert result == expected

    def test_accepts_string_path(self, tmp_path):
        f = tmp_path / "strpath.txt"
        f.write_bytes(b"via string")

        result = hash_file(str(f))
        expected = hashlib.sha256(b"via string").hexdigest()
        assert result == expected
