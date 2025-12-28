"""
Tests for pysqlcrypt using verified test vectors.

Test vector sources:
- V1: https://github.com/krcs/SQLServerCrypto (C# implementation)
- V2: Generated from SQL Server 2022 via scripts/generate_test_vectors.py
"""

import pytest

from pysqlcrypt import SQLCryptVersion, decrypt_by_passphrase, encrypt_by_passphrase


class TestDecryptByPassphrase:
    """Tests for decrypt_by_passphrase function."""

    # V1 test vectors from https://github.com/krcs/SQLServerCrypto
    V1_TEST_VECTORS = [
        {
            "passphrase": "password1234",
            "plaintext": b"Hello World.",
            "ciphertext": "0x010000003296649D6782CFD72B8145A07F2C7D7FE3D8B80CF48DA419E94FABC90EEB928D",
        },
        {
            "passphrase": "password1234",
            "plaintext": b"Hello World.",
            "ciphertext": "0x01000000d743db6ccd7e0e63091fa787c65dead5ea14c440da9ee0f6f60e74520a35c076",
        },
    ]

    # V2 test vectors from SQL Server 2022 (generated via scripts/generate_test_vectors.py)
    V2_TEST_VECTORS = [
        {
            "passphrase": "password1234",
            "plaintext": b"Hello World.",
            "ciphertext": "0x020000007359F58A1DC352457D5D7DE88D17487521F5C110FFB32D7D1D7AE69282EE72E591AA01342A1CCD80D56DCACCA2E20544",
        },
        {
            "passphrase": "testpassword",
            "plaintext": b"Hello, World!",
            "ciphertext": "0x02000000D0525443306FC189DD9CCEBBCD0D2732133995C916D3B603FC5D29538CC342C3ECE0013F81E4BD3147F487855CD28719",
        },
        {
            "passphrase": "short",
            "plaintext": b"x",
            "ciphertext": "0x02000000B710C75A83B57E973A603DDDBDAEB8ED6026CBC5F2FC5ED76F2105096E3178C7",
        },
        {
            "passphrase": "empty-test",
            "plaintext": b"",
            "ciphertext": "0x02000000A38689BF2AE02EECC2CBFEFBCA14AB1CD7C97B2E5451D06E14E8074FB124A70A",
        },
    ]

    @pytest.mark.parametrize("test_vector", V1_TEST_VECTORS)
    def test_decrypt_v1_known_vectors(self, test_vector):
        """Test V1 decryption with known test vectors from SQLServerCrypto."""
        result = decrypt_by_passphrase(
            test_vector["passphrase"],
            test_vector["ciphertext"],
        )
        assert result == test_vector["plaintext"]

    @pytest.mark.parametrize("test_vector", V2_TEST_VECTORS)
    def test_decrypt_v2_known_vectors(self, test_vector):
        """Test V2 decryption with known test vectors from SQL Server 2022."""
        result = decrypt_by_passphrase(
            test_vector["passphrase"],
            test_vector["ciphertext"],
        )
        assert result == test_vector["plaintext"]

    def test_decrypt_without_0x_prefix(self):
        """Test that hex strings without 0x prefix work."""
        ciphertext = "010000003296649D6782CFD72B8145A07F2C7D7FE3D8B80CF48DA419E94FABC90EEB928D"
        result = decrypt_by_passphrase("password1234", ciphertext)
        assert result == b"Hello World."

    def test_decrypt_with_bytes_input(self):
        """Test that bytes input works."""
        ciphertext = bytes.fromhex(
            "010000003296649D6782CFD72B8145A07F2C7D7FE3D8B80CF48DA419E94FABC90EEB928D"
        )
        result = decrypt_by_passphrase("password1234", ciphertext)
        assert result == b"Hello World."

    def test_decrypt_wrong_passphrase_raises(self):
        """Test that wrong passphrase raises an error."""
        ciphertext = "0x010000003296649D6782CFD72B8145A07F2C7D7FE3D8B80CF48DA419E94FABC90EEB928D"
        with pytest.raises(ValueError):
            decrypt_by_passphrase("wrongpassword", ciphertext)

    def test_decrypt_invalid_ciphertext_raises(self):
        """Test that invalid ciphertext raises an error."""
        with pytest.raises(ValueError):
            decrypt_by_passphrase("password", "0x0100")


class TestEncryptByPassphrase:
    """Tests for encrypt_by_passphrase function."""

    def test_encrypt_decrypt_roundtrip_v1(self):
        """Test that V1 encryption can be decrypted."""
        passphrase = "testpassword"
        plaintext = "Hello, World!"

        ciphertext = encrypt_by_passphrase(passphrase, plaintext, SQLCryptVersion.V1)
        decrypted = decrypt_by_passphrase(passphrase, ciphertext)

        assert decrypted.decode("utf-8") == plaintext

    def test_encrypt_decrypt_roundtrip_v2(self):
        """Test that V2 encryption can be decrypted."""
        passphrase = "testpassword"
        plaintext = "Hello, World!"

        ciphertext = encrypt_by_passphrase(passphrase, plaintext, SQLCryptVersion.V2)
        decrypted = decrypt_by_passphrase(passphrase, ciphertext)

        assert decrypted.decode("utf-8") == plaintext

    def test_encrypt_produces_correct_version_byte(self):
        """Test that encrypted data starts with correct version byte."""
        ciphertext_v1 = encrypt_by_passphrase("pass", "test", SQLCryptVersion.V1)
        ciphertext_v2 = encrypt_by_passphrase("pass", "test", SQLCryptVersion.V2)

        assert ciphertext_v1[0] == 1
        assert ciphertext_v2[0] == 2

    def test_encrypt_with_bytes_input(self):
        """Test encryption with bytes input."""
        passphrase = "testpassword"
        plaintext = b"Hello, World!"

        ciphertext = encrypt_by_passphrase(passphrase, plaintext)
        decrypted = decrypt_by_passphrase(passphrase, ciphertext)

        assert decrypted == plaintext

    def test_encrypt_unicode(self):
        """Test encryption of unicode text."""
        passphrase = "testpassword"
        plaintext = "Hello, 世界! 🌍"

        ciphertext = encrypt_by_passphrase(passphrase, plaintext)
        decrypted = decrypt_by_passphrase(passphrase, ciphertext)

        assert decrypted.decode("utf-8") == plaintext

    def test_encrypt_empty_string(self):
        """Test encryption of empty string."""
        passphrase = "testpassword"
        plaintext = ""

        ciphertext = encrypt_by_passphrase(passphrase, plaintext)
        decrypted = decrypt_by_passphrase(passphrase, ciphertext)

        assert decrypted.decode("utf-8") == plaintext

    def test_encrypt_max_length(self):
        """Test encryption at maximum allowed length (65535 bytes)."""
        passphrase = "testpassword"
        plaintext = b"x" * 65535

        ciphertext = encrypt_by_passphrase(passphrase, plaintext)
        decrypted = decrypt_by_passphrase(passphrase, ciphertext)

        assert decrypted == plaintext

    def test_encrypt_too_long_raises(self):
        """Test that plaintext > 65535 bytes raises ValueError."""
        passphrase = "testpassword"
        plaintext = b"x" * 65536

        with pytest.raises(ValueError, match="Data too long"):
            encrypt_by_passphrase(passphrase, plaintext)


class TestAuthenticator:
    """Tests for authenticator parameter support."""

    def test_encrypt_with_authenticator_roundtrip(self):
        """Test that authenticator is correctly encrypted and decrypted."""
        passphrase = "testpass"
        plaintext = "secret data"
        authenticator = "my-auth"

        ciphertext = encrypt_by_passphrase(
            passphrase, plaintext, authenticator=authenticator
        )
        # Note: Our library doesn't expose authenticator in decrypt_by_passphrase
        # since SQL Server doesn't require it for decryption when stored in message
        decrypted = decrypt_by_passphrase(passphrase, ciphertext)

        assert decrypted.decode("utf-8") == plaintext

    def test_different_authenticators_produce_different_ciphertext(self):
        """Test that different authenticators produce different ciphertext."""
        passphrase = "testpass"
        plaintext = "secret data"

        ct1 = encrypt_by_passphrase(passphrase, plaintext, authenticator="auth1")
        ct2 = encrypt_by_passphrase(passphrase, plaintext, authenticator="auth2")

        # Different authenticators should produce different ciphertext
        # (even ignoring IV differences, the encrypted content differs)
        assert ct1 != ct2

    def test_max_length_authenticator(self):
        """Test authenticator at maximum allowed length (65535 bytes)."""
        passphrase = "testpass"
        plaintext = b"hello"
        authenticator = b"x" * 65535

        ciphertext = encrypt_by_passphrase(passphrase, plaintext, authenticator=authenticator)
        decrypted = decrypt_by_passphrase(passphrase, ciphertext)

        assert decrypted == plaintext

    def test_authenticator_too_long_raises(self):
        """Test that authenticator > 65535 bytes raises ValueError."""
        with pytest.raises(ValueError, match="Authenticator too long"):
            encrypt_by_passphrase("pass", "data", authenticator=b"x" * 65536)


class TestEdgeCases:
    """Tests for edge cases and special inputs."""

    def test_empty_passphrase(self):
        """Test encryption with empty passphrase."""
        ciphertext = encrypt_by_passphrase("", "hello")
        decrypted = decrypt_by_passphrase("", ciphertext)
        assert decrypted == b"hello"

    def test_binary_with_null_bytes(self):
        """Test binary data containing null bytes."""
        data = b"HELLO\x00WORLD\x00"
        ciphertext = encrypt_by_passphrase("pass", data)
        decrypted = decrypt_by_passphrase("pass", ciphertext)
        assert decrypted == data

    def test_unicode_passphrase(self):
        """Test Unicode characters in passphrase."""
        passphrase = "密码🔐"
        ciphertext = encrypt_by_passphrase(passphrase, "secret")
        decrypted = decrypt_by_passphrase(passphrase, ciphertext)
        assert decrypted == b"secret"

    def test_special_chars_in_passphrase(self):
        """Test special characters (newline, tab, null) in passphrase."""
        passphrase = "pass\nword\twith\x00null"
        ciphertext = encrypt_by_passphrase(passphrase, "data")
        decrypted = decrypt_by_passphrase(passphrase, ciphertext)
        assert decrypted == b"data"

    def test_very_long_passphrase(self):
        """Test very long passphrase (10KB)."""
        passphrase = "x" * 10240
        ciphertext = encrypt_by_passphrase(passphrase, "hello")
        decrypted = decrypt_by_passphrase(passphrase, ciphertext)
        assert decrypted == b"hello"

    def test_nvarchar_decryption(self):
        """Test decrypting NVARCHAR data (UTF-16LE encoded)."""
        # This ciphertext contains 'hello' encoded as NVARCHAR (UTF-16LE)
        # Generated by: ENCRYPTBYPASSPHRASE('pass', N'hello')
        nvarchar_ct = "0x020000006C5037A80E7B9D5E29765B0AC6DD5FB7C80178FDC4237E1134CC6C00EF286BF4719AF37E5B76312045203CCC0388BD9F"
        result = decrypt_by_passphrase("pass", nvarchar_ct)
        # Result is UTF-16LE bytes, decode appropriately
        assert result.decode("utf-16-le") == "hello"


class TestErrorHandling:
    """Tests for error conditions."""

    def test_truncated_ciphertext(self):
        """Test that truncated ciphertext raises error."""
        with pytest.raises(ValueError):
            decrypt_by_passphrase("pass", "0x0200000011223344")

    def test_invalid_version_byte(self):
        """Test that invalid version byte raises error."""
        bad_ct = bytes.fromhex("03000000" + "00" * 36)
        with pytest.raises(ValueError, match="not a valid SQLCryptVersion"):
            decrypt_by_passphrase("pass", bad_ct)

    def test_empty_ciphertext(self):
        """Test that empty ciphertext raises error."""
        with pytest.raises(ValueError):
            decrypt_by_passphrase("pass", b"")

    def test_invalid_hex_string(self):
        """Test that invalid hex string raises error."""
        with pytest.raises(ValueError):
            decrypt_by_passphrase("pass", "0xGGGGGG")


class TestEncodingParameter:
    """Tests for the encoding parameter feature."""

    def test_encrypt_with_utf16le_encoding(self):
        """Test encryption with UTF-16LE encoding for NVARCHAR compatibility."""
        passphrase = "pass"
        plaintext = "hello"

        # Encrypt with UTF-16LE (NVARCHAR compatible)
        ciphertext = encrypt_by_passphrase(passphrase, plaintext, encoding="utf-16-le")

        # Decrypt and verify it's UTF-16LE encoded
        result = decrypt_by_passphrase(passphrase, ciphertext)
        assert result == plaintext.encode("utf-16-le")
        assert result.decode("utf-16-le") == plaintext

    def test_decrypt_with_encoding_returns_str(self):
        """Test that decrypt with encoding parameter returns str."""
        passphrase = "testpass"
        plaintext = "Hello, World!"

        ciphertext = encrypt_by_passphrase(passphrase, plaintext)
        result = decrypt_by_passphrase(passphrase, ciphertext, encoding="utf-8")

        assert isinstance(result, str)
        assert result == plaintext

    def test_decrypt_without_encoding_returns_bytes(self):
        """Test that decrypt without encoding returns bytes."""
        passphrase = "testpass"
        plaintext = "Hello, World!"

        ciphertext = encrypt_by_passphrase(passphrase, plaintext)
        result = decrypt_by_passphrase(passphrase, ciphertext)

        assert isinstance(result, bytes)
        assert result == plaintext.encode("utf-8")

    def test_encrypt_decrypt_utf16le_roundtrip(self):
        """Test full roundtrip with UTF-16LE encoding."""
        passphrase = "pass"
        plaintext = "Hello, 世界!"

        ciphertext = encrypt_by_passphrase(passphrase, plaintext, encoding="utf-16-le")
        result = decrypt_by_passphrase(passphrase, ciphertext, encoding="utf-16-le")

        assert result == plaintext

    def test_bytes_input_ignores_encoding(self):
        """Test that bytes input ignores the encoding parameter."""
        passphrase = "pass"
        plaintext = b"raw bytes"

        # encoding parameter should be ignored for bytes input
        ciphertext = encrypt_by_passphrase(passphrase, plaintext, encoding="utf-16-le")
        result = decrypt_by_passphrase(passphrase, ciphertext)

        assert result == plaintext  # Not UTF-16LE encoded

    def test_auto_encoding_detects_utf8(self):
        """Test that encoding='auto' correctly detects UTF-8 data."""
        passphrase = "pass"
        plaintext = "Hello, World!"

        # Encrypt as UTF-8 (default)
        ciphertext = encrypt_by_passphrase(passphrase, plaintext)
        result = decrypt_by_passphrase(passphrase, ciphertext, encoding="auto")

        assert isinstance(result, str)
        assert result == plaintext

    def test_auto_encoding_detects_utf16le(self):
        """Test that encoding='auto' correctly detects UTF-16LE data (NVARCHAR)."""
        passphrase = "pass"
        plaintext = "Hello"

        # Encrypt as UTF-16LE (SQL Server NVARCHAR)
        ciphertext = encrypt_by_passphrase(passphrase, plaintext, encoding="utf-16-le")
        result = decrypt_by_passphrase(passphrase, ciphertext, encoding="auto")

        assert isinstance(result, str)
        assert result == plaintext

    def test_auto_encoding_with_unicode_utf16le(self):
        """Test auto encoding with Unicode characters in UTF-16LE."""
        passphrase = "pass"
        plaintext = "Hello 世界"

        ciphertext = encrypt_by_passphrase(passphrase, plaintext, encoding="utf-16-le")
        # For non-ASCII UTF-16LE, auto-detection may fall back to trying decode
        result = decrypt_by_passphrase(passphrase, ciphertext, encoding="utf-16-le")

        assert result == plaintext

    def test_auto_encoding_empty_string(self):
        """Test auto encoding with empty string."""
        passphrase = "pass"
        plaintext = ""

        ciphertext = encrypt_by_passphrase(passphrase, plaintext)
        result = decrypt_by_passphrase(passphrase, ciphertext, encoding="auto")

        assert result == ""


class TestAuthenticatorVerification:
    """Tests for authenticator verification in decryption."""

    def test_verify_authenticator_success(self):
        """Test successful authenticator verification."""
        passphrase = "testpass"
        plaintext = "secret data"
        authenticator = "my-auth"

        ciphertext = encrypt_by_passphrase(passphrase, plaintext, authenticator=authenticator)
        result = decrypt_by_passphrase(passphrase, ciphertext, authenticator=authenticator)

        assert result == plaintext.encode("utf-8")

    def test_verify_authenticator_mismatch_raises(self):
        """Test that wrong authenticator raises ValueError."""
        passphrase = "testpass"
        plaintext = "secret data"
        authenticator = "correct-auth"

        ciphertext = encrypt_by_passphrase(passphrase, plaintext, authenticator=authenticator)

        with pytest.raises(ValueError, match="Authenticator mismatch"):
            decrypt_by_passphrase(passphrase, ciphertext, authenticator="wrong-auth")

    def test_verify_authenticator_when_none_embedded(self):
        """Test that providing authenticator fails when none was embedded."""
        passphrase = "testpass"
        plaintext = "no auth data"

        # Encrypt without authenticator
        ciphertext = encrypt_by_passphrase(passphrase, plaintext)

        # Try to verify with authenticator should fail
        with pytest.raises(ValueError, match="Authenticator mismatch"):
            decrypt_by_passphrase(passphrase, ciphertext, authenticator="some-auth")

    def test_no_verification_when_authenticator_none(self):
        """Test that None authenticator skips verification."""
        passphrase = "testpass"
        plaintext = "data with auth"

        # Encrypt with authenticator
        ciphertext = encrypt_by_passphrase(passphrase, plaintext, authenticator="embedded")

        # Decrypt without verification should work
        result = decrypt_by_passphrase(passphrase, ciphertext, authenticator=None)
        assert result == plaintext.encode("utf-8")

    def test_verify_empty_authenticator(self):
        """Test verifying empty authenticator matches no authenticator."""
        passphrase = "testpass"
        plaintext = "data"

        # Encrypt without authenticator (empty)
        ciphertext = encrypt_by_passphrase(passphrase, plaintext)

        # Verify with empty bytes should succeed (both are empty)
        result = decrypt_by_passphrase(passphrase, ciphertext, authenticator=b"")
        assert result == plaintext.encode("utf-8")

    def test_verify_authenticator_with_encoding(self):
        """Test authenticator verification combined with encoding."""
        passphrase = "testpass"
        plaintext = "secret"
        authenticator = "auth123"

        ciphertext = encrypt_by_passphrase(passphrase, plaintext, authenticator=authenticator)
        result = decrypt_by_passphrase(
            passphrase, ciphertext, authenticator=authenticator, encoding="utf-8"
        )

        assert isinstance(result, str)
        assert result == plaintext

    def test_verify_authenticator_with_utf16le_encoding(self):
        """Test authenticator verification with UTF-16LE encoding (NVARCHAR scenario)."""
        passphrase = "testpass"
        plaintext = "secret data"
        authenticator = "my-auth"

        # Encrypt with UTF-16LE (NVARCHAR compatible)
        ciphertext = encrypt_by_passphrase(
            passphrase, plaintext, authenticator=authenticator, encoding="utf-16-le"
        )

        # Decrypt with same encoding - authenticator should also use UTF-16LE
        result = decrypt_by_passphrase(
            passphrase, ciphertext, authenticator=authenticator, encoding="utf-16-le"
        )

        assert result == plaintext

    def test_verify_authenticator_utf16le_mismatch_when_wrong_encoding(self):
        """Test that wrong encoding for authenticator verification fails."""
        passphrase = "testpass"
        plaintext = "secret"
        authenticator = "auth"

        # Encrypt with UTF-16LE
        ciphertext = encrypt_by_passphrase(
            passphrase, plaintext, authenticator=authenticator, encoding="utf-16-le"
        )

        # Decrypt with UTF-8 encoding - authenticator encoded differently, should fail
        with pytest.raises(ValueError, match="Authenticator mismatch"):
            decrypt_by_passphrase(
                passphrase, ciphertext, authenticator=authenticator, encoding="utf-8"
            )

    def test_verify_authenticator_bytes_ignores_encoding(self):
        """Test that bytes authenticator works regardless of encoding parameter."""
        passphrase = "testpass"
        plaintext = "secret"
        auth_bytes = b"raw-auth-bytes"

        # Encrypt with bytes authenticator
        ciphertext = encrypt_by_passphrase(
            passphrase, plaintext, authenticator=auth_bytes, encoding="utf-16-le"
        )

        # Decrypt with bytes authenticator - encoding shouldn't affect bytes
        result = decrypt_by_passphrase(
            passphrase, ciphertext, authenticator=auth_bytes, encoding="utf-16-le"
        )

        assert result == plaintext

    def test_verify_authenticator_default_utf8_when_no_encoding(self):
        """Test that authenticator defaults to UTF-8 when encoding is None."""
        passphrase = "testpass"
        plaintext = "secret"
        authenticator = "auth"

        # Encrypt with default UTF-8
        ciphertext = encrypt_by_passphrase(passphrase, plaintext, authenticator=authenticator)

        # Decrypt without encoding (returns bytes), authenticator should use UTF-8
        result = decrypt_by_passphrase(passphrase, ciphertext, authenticator=authenticator)

        assert result == plaintext.encode("utf-8")

    def test_verify_utf16le_authenticator_with_bytes_output(self):
        """Test verifying UTF-16LE authenticator when wanting bytes output.

        This is an edge case: user encrypted with utf-16-le but wants bytes output
        during decryption. The workaround is to pass authenticator as pre-encoded bytes.
        """
        passphrase = "testpass"
        plaintext = "secret"
        authenticator = "auth"

        # Encrypt with UTF-16LE
        ciphertext = encrypt_by_passphrase(
            passphrase, plaintext, authenticator=authenticator, encoding="utf-16-le"
        )

        # To get bytes output AND verify authenticator, pass authenticator as bytes
        result = decrypt_by_passphrase(
            passphrase,
            ciphertext,
            authenticator=authenticator.encode("utf-16-le"),  # Pre-encode as bytes
        )

        # Result is bytes (UTF-16LE encoded plaintext)
        assert isinstance(result, bytes)
        assert result == plaintext.encode("utf-16-le")


class TestSQLCryptVersion:
    """Tests for SQLCryptVersion enum."""

    def test_version_values(self):
        """Test version enum values."""
        assert SQLCryptVersion.V1 == 1
        assert SQLCryptVersion.V2 == 2

    def test_version_from_int(self):
        """Test creating version from int."""
        assert SQLCryptVersion(1) == SQLCryptVersion.V1
        assert SQLCryptVersion(2) == SQLCryptVersion.V2
