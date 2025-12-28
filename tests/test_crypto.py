"""Tests for pysqlcrypt. Test vectors from github.com/krcs/SQLServerCrypto and SQL Server 2022."""

import pytest

from pysqlcrypt import SQLCryptVersion, decrypt_by_passphrase, encrypt_by_passphrase


class TestDecryptByPassphrase:

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
        result = decrypt_by_passphrase(test_vector["passphrase"], test_vector["ciphertext"])
        assert result == test_vector["plaintext"]

    @pytest.mark.parametrize("test_vector", V2_TEST_VECTORS)
    def test_decrypt_v2_known_vectors(self, test_vector):
        result = decrypt_by_passphrase(test_vector["passphrase"], test_vector["ciphertext"])
        assert result == test_vector["plaintext"]

    def test_decrypt_without_0x_prefix(self):
        ciphertext = "010000003296649D6782CFD72B8145A07F2C7D7FE3D8B80CF48DA419E94FABC90EEB928D"
        result = decrypt_by_passphrase("password1234", ciphertext)
        assert result == b"Hello World."

    def test_decrypt_with_bytes_input(self):
        ciphertext = bytes.fromhex(
            "010000003296649D6782CFD72B8145A07F2C7D7FE3D8B80CF48DA419E94FABC90EEB928D"
        )
        result = decrypt_by_passphrase("password1234", ciphertext)
        assert result == b"Hello World."

    def test_decrypt_wrong_passphrase_raises(self):
        ciphertext = "0x010000003296649D6782CFD72B8145A07F2C7D7FE3D8B80CF48DA419E94FABC90EEB928D"
        with pytest.raises(ValueError):
            decrypt_by_passphrase("wrongpassword", ciphertext)

    def test_decrypt_invalid_ciphertext_raises(self):
        with pytest.raises(ValueError):
            decrypt_by_passphrase("password", "0x0100")


class TestEncryptByPassphrase:

    def test_encrypt_decrypt_roundtrip_v1(self):
        ciphertext = encrypt_by_passphrase("testpassword", "Hello, World!", SQLCryptVersion.V1)
        decrypted = decrypt_by_passphrase("testpassword", ciphertext)
        assert decrypted.decode("utf-8") == "Hello, World!"

    def test_encrypt_decrypt_roundtrip_v2(self):
        ciphertext = encrypt_by_passphrase("testpassword", "Hello, World!", SQLCryptVersion.V2)
        decrypted = decrypt_by_passphrase("testpassword", ciphertext)
        assert decrypted.decode("utf-8") == "Hello, World!"

    def test_encrypt_produces_correct_version_byte(self):
        ciphertext_v1 = encrypt_by_passphrase("pass", "test", SQLCryptVersion.V1)
        ciphertext_v2 = encrypt_by_passphrase("pass", "test", SQLCryptVersion.V2)
        assert ciphertext_v1[0] == 1
        assert ciphertext_v2[0] == 2

    def test_encrypt_with_bytes_input(self):
        ciphertext = encrypt_by_passphrase("testpassword", b"Hello, World!")
        decrypted = decrypt_by_passphrase("testpassword", ciphertext)
        assert decrypted == b"Hello, World!"

    def test_encrypt_unicode(self):
        ciphertext = encrypt_by_passphrase("testpassword", "Hello, 世界! 🌍")
        decrypted = decrypt_by_passphrase("testpassword", ciphertext)
        assert decrypted.decode("utf-8") == "Hello, 世界! 🌍"

    def test_encrypt_empty_string(self):
        ciphertext = encrypt_by_passphrase("testpassword", "")
        decrypted = decrypt_by_passphrase("testpassword", ciphertext)
        assert decrypted.decode("utf-8") == ""

    def test_encrypt_max_length(self):
        plaintext = b"x" * 65535
        ciphertext = encrypt_by_passphrase("testpassword", plaintext)
        decrypted = decrypt_by_passphrase("testpassword", ciphertext)
        assert decrypted == plaintext

    def test_encrypt_too_long_raises(self):
        with pytest.raises(ValueError, match="Data too long"):
            encrypt_by_passphrase("testpassword", b"x" * 65536)


class TestAuthenticator:

    def test_encrypt_with_authenticator_roundtrip(self):
        ciphertext = encrypt_by_passphrase("testpass", "secret data", authenticator="my-auth")
        decrypted = decrypt_by_passphrase("testpass", ciphertext)
        assert decrypted.decode("utf-8") == "secret data"

    def test_different_authenticators_produce_different_ciphertext(self):
        ct1 = encrypt_by_passphrase("testpass", "secret data", authenticator="auth1")
        ct2 = encrypt_by_passphrase("testpass", "secret data", authenticator="auth2")
        assert ct1 != ct2

    def test_max_length_authenticator(self):
        ciphertext = encrypt_by_passphrase("testpass", b"hello", authenticator=b"x" * 65535)
        decrypted = decrypt_by_passphrase("testpass", ciphertext)
        assert decrypted == b"hello"

    def test_authenticator_too_long_raises(self):
        with pytest.raises(ValueError, match="Authenticator too long"):
            encrypt_by_passphrase("pass", "data", authenticator=b"x" * 65536)


class TestEdgeCases:

    def test_empty_passphrase(self):
        ciphertext = encrypt_by_passphrase("", "hello")
        decrypted = decrypt_by_passphrase("", ciphertext)
        assert decrypted == b"hello"

    def test_binary_with_null_bytes(self):
        data = b"HELLO\x00WORLD\x00"
        ciphertext = encrypt_by_passphrase("pass", data)
        decrypted = decrypt_by_passphrase("pass", ciphertext)
        assert decrypted == data

    def test_unicode_passphrase(self):
        ciphertext = encrypt_by_passphrase("密码🔐", "secret")
        decrypted = decrypt_by_passphrase("密码🔐", ciphertext)
        assert decrypted == b"secret"

    def test_special_chars_in_passphrase(self):
        ciphertext = encrypt_by_passphrase("pass\nword\twith\x00null", "data")
        decrypted = decrypt_by_passphrase("pass\nword\twith\x00null", ciphertext)
        assert decrypted == b"data"

    def test_very_long_passphrase(self):
        ciphertext = encrypt_by_passphrase("x" * 10240, "hello")
        decrypted = decrypt_by_passphrase("x" * 10240, ciphertext)
        assert decrypted == b"hello"

    def test_nvarchar_decryption(self):
        # Ciphertext contains 'hello' as NVARCHAR (UTF-16LE) from SQL Server
        nvarchar_ct = "0x020000006C5037A80E7B9D5E29765B0AC6DD5FB7C80178FDC4237E1134CC6C00EF286BF4719AF37E5B76312045203CCC0388BD9F"
        result = decrypt_by_passphrase("pass", nvarchar_ct)
        assert result.decode("utf-16-le") == "hello"


class TestErrorHandling:

    def test_truncated_ciphertext(self):
        with pytest.raises(ValueError):
            decrypt_by_passphrase("pass", "0x0200000011223344")

    def test_invalid_version_byte(self):
        bad_ct = bytes.fromhex("03000000" + "00" * 36)
        with pytest.raises(ValueError, match="not a valid SQLCryptVersion"):
            decrypt_by_passphrase("pass", bad_ct)

    def test_empty_ciphertext(self):
        with pytest.raises(ValueError):
            decrypt_by_passphrase("pass", b"")

    def test_invalid_hex_string(self):
        with pytest.raises(ValueError):
            decrypt_by_passphrase("pass", "0xGGGGGG")


class TestEncodingParameter:

    def test_encrypt_with_utf16le_encoding(self):
        ciphertext = encrypt_by_passphrase("pass", "hello", encoding="utf-16-le")
        result = decrypt_by_passphrase("pass", ciphertext)
        assert result == "hello".encode("utf-16-le")
        assert result.decode("utf-16-le") == "hello"

    def test_decrypt_with_encoding_returns_str(self):
        ciphertext = encrypt_by_passphrase("testpass", "Hello, World!")
        result = decrypt_by_passphrase("testpass", ciphertext, encoding="utf-8")
        assert isinstance(result, str)
        assert result == "Hello, World!"

    def test_decrypt_without_encoding_returns_bytes(self):
        ciphertext = encrypt_by_passphrase("testpass", "Hello, World!")
        result = decrypt_by_passphrase("testpass", ciphertext)
        assert isinstance(result, bytes)
        assert result == b"Hello, World!"

    def test_encrypt_decrypt_utf16le_roundtrip(self):
        ciphertext = encrypt_by_passphrase("pass", "Hello, 世界!", encoding="utf-16-le")
        result = decrypt_by_passphrase("pass", ciphertext, encoding="utf-16-le")
        assert result == "Hello, 世界!"

    def test_bytes_input_ignores_encoding(self):
        ciphertext = encrypt_by_passphrase("pass", b"raw bytes", encoding="utf-16-le")
        result = decrypt_by_passphrase("pass", ciphertext)
        assert result == b"raw bytes"

    def test_auto_encoding_detects_utf8(self):
        ciphertext = encrypt_by_passphrase("pass", "Hello, World!")
        result = decrypt_by_passphrase("pass", ciphertext, encoding="auto")
        assert isinstance(result, str)
        assert result == "Hello, World!"

    def test_auto_encoding_detects_utf16le(self):
        ciphertext = encrypt_by_passphrase("pass", "Hello", encoding="utf-16-le")
        result = decrypt_by_passphrase("pass", ciphertext, encoding="auto")
        assert isinstance(result, str)
        assert result == "Hello"

    def test_auto_encoding_with_unicode_utf16le(self):
        ciphertext = encrypt_by_passphrase("pass", "Hello 世界", encoding="utf-16-le")
        result = decrypt_by_passphrase("pass", ciphertext, encoding="utf-16-le")
        assert result == "Hello 世界"

    def test_auto_encoding_empty_string(self):
        ciphertext = encrypt_by_passphrase("pass", "")
        result = decrypt_by_passphrase("pass", ciphertext, encoding="auto")
        assert result == ""


class TestAuthenticatorVerification:

    def test_verify_authenticator_success(self):
        ciphertext = encrypt_by_passphrase("testpass", "secret data", authenticator="my-auth")
        result = decrypt_by_passphrase("testpass", ciphertext, authenticator="my-auth")
        assert result == b"secret data"

    def test_verify_authenticator_mismatch_raises(self):
        ciphertext = encrypt_by_passphrase("testpass", "secret data", authenticator="correct-auth")
        with pytest.raises(ValueError, match="Authenticator mismatch"):
            decrypt_by_passphrase("testpass", ciphertext, authenticator="wrong-auth")

    def test_verify_authenticator_when_none_embedded(self):
        ciphertext = encrypt_by_passphrase("testpass", "no auth data")
        with pytest.raises(ValueError, match="Authenticator mismatch"):
            decrypt_by_passphrase("testpass", ciphertext, authenticator="some-auth")

    def test_no_verification_when_authenticator_none(self):
        ciphertext = encrypt_by_passphrase("testpass", "data with auth", authenticator="embedded")
        result = decrypt_by_passphrase("testpass", ciphertext, authenticator=None)
        assert result == b"data with auth"

    def test_verify_empty_authenticator(self):
        ciphertext = encrypt_by_passphrase("testpass", "data")
        result = decrypt_by_passphrase("testpass", ciphertext, authenticator=b"")
        assert result == b"data"

    def test_verify_authenticator_with_encoding(self):
        ciphertext = encrypt_by_passphrase("testpass", "secret", authenticator="auth123")
        result = decrypt_by_passphrase("testpass", ciphertext, authenticator="auth123", encoding="utf-8")
        assert isinstance(result, str)
        assert result == "secret"

    def test_verify_authenticator_with_utf16le_encoding(self):
        ciphertext = encrypt_by_passphrase(
            "testpass", "secret data", authenticator="my-auth", encoding="utf-16-le"
        )
        result = decrypt_by_passphrase(
            "testpass", ciphertext, authenticator="my-auth", encoding="utf-16-le"
        )
        assert result == "secret data"

    def test_verify_authenticator_utf16le_mismatch_when_wrong_encoding(self):
        ciphertext = encrypt_by_passphrase(
            "testpass", "secret", authenticator="auth", encoding="utf-16-le"
        )
        with pytest.raises(ValueError, match="Authenticator mismatch"):
            decrypt_by_passphrase("testpass", ciphertext, authenticator="auth", encoding="utf-8")

    def test_verify_authenticator_bytes_ignores_encoding(self):
        ciphertext = encrypt_by_passphrase(
            "testpass", "secret", authenticator=b"raw-auth-bytes", encoding="utf-16-le"
        )
        result = decrypt_by_passphrase(
            "testpass", ciphertext, authenticator=b"raw-auth-bytes", encoding="utf-16-le"
        )
        assert result == "secret"

    def test_verify_authenticator_default_utf8_when_no_encoding(self):
        ciphertext = encrypt_by_passphrase("testpass", "secret", authenticator="auth")
        result = decrypt_by_passphrase("testpass", ciphertext, authenticator="auth")
        assert result == b"secret"

    def test_verify_utf16le_authenticator_with_bytes_output(self):
        ciphertext = encrypt_by_passphrase(
            "testpass", "secret", authenticator="auth", encoding="utf-16-le"
        )
        result = decrypt_by_passphrase(
            "testpass", ciphertext, authenticator="auth".encode("utf-16-le")
        )
        assert isinstance(result, bytes)
        assert result == "secret".encode("utf-16-le")


class TestSQLCryptVersion:

    def test_version_values(self):
        assert SQLCryptVersion.V1 == 1
        assert SQLCryptVersion.V2 == 2

    def test_version_from_int(self):
        assert SQLCryptVersion(1) == SQLCryptVersion.V1
        assert SQLCryptVersion(2) == SQLCryptVersion.V2
