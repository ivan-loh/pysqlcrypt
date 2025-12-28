"""SQL Server ENCRYPTBYPASSPHRASE/DECRYPTBYPASSPHRASE implementation."""

import hashlib
import os
import struct
from enum import IntEnum
from typing import Literal, Optional, Union, overload

from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad


def _detect_encoding(data: bytes) -> str:
    """Detect UTF-16LE vs UTF-8 encoding from byte patterns."""
    if len(data) == 0:
        return "utf-8"

    if len(data) >= 2 and data[0] == 0xFF and data[1] == 0xFE:
        return "utf-16-le"

    if len(data) >= 2 and len(data) % 2 == 0:
        is_utf16le_ascii = True
        for i in range(1, len(data), 2):
            if data[i] != 0:
                is_utf16le_ascii = False
                break
        if is_utf16le_ascii:
            return "utf-16-le"

    try:
        data.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        pass

    return "latin-1"


class SQLCryptVersion(IntEnum):
    V1 = 1  # SQL Server 2008-2016: 3DES-CBC + SHA1
    V2 = 2  # SQL Server 2017+: AES-256-CBC + SHA256


# Marker used by SQL Server to verify successful decryption
_MAGIC = 0xBAADF00D


def _key_v1(passphrase: str) -> bytes:
    k = hashlib.sha1(passphrase.encode("utf-16-le")).digest()[:16]
    return k + k[:8]


def _key_v2(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode("utf-16-le")).digest()


def _pack(data: bytes, auth: bytes = b"") -> bytes:
    if len(data) > 65535:
        raise ValueError(f"Data too long: {len(data)} bytes (max 65535)")
    if len(auth) > 65535:
        raise ValueError(f"Authenticator too long: {len(auth)} bytes (max 65535)")
    return struct.pack("<IHH", _MAGIC, len(auth), len(data)) + auth + data


def _unpack(buf: bytes) -> tuple[bytes, bytes]:
    if len(buf) < 8:
        raise ValueError("Decrypted data too short")
    magic, auth_len, data_len = struct.unpack("<IHH", buf[:8])
    if magic != _MAGIC:
        raise ValueError(f"Invalid magic: {hex(magic)}")
    end = 8 + auth_len + data_len
    if end > len(buf):
        raise ValueError("Data length exceeds buffer")
    return buf[8 : 8 + auth_len], buf[8 + auth_len : end]


def encrypt_by_passphrase(
    passphrase: str,
    plaintext: Union[str, bytes],
    version: SQLCryptVersion = SQLCryptVersion.V1,
    authenticator: Union[str, bytes, None] = None,
    *,
    encoding: str = "utf-8",
) -> bytes:
    """Encrypt data compatible with SQL Server's ENCRYPTBYPASSPHRASE."""
    data = plaintext.encode(encoding) if isinstance(plaintext, str) else plaintext
    auth = b""
    if authenticator is not None:
        auth = authenticator.encode(encoding) if isinstance(authenticator, str) else authenticator
    msg = _pack(data, auth)

    if version == SQLCryptVersion.V1:
        iv = os.urandom(8)
        enc = DES3.new(_key_v1(passphrase), DES3.MODE_CBC, iv).encrypt(pad(msg, 8))
    else:
        iv = os.urandom(16)
        enc = AES.new(_key_v2(passphrase), AES.MODE_CBC, iv).encrypt(pad(msg, 16))

    return bytes([version, 0, 0, 0]) + iv + enc


@overload
def decrypt_by_passphrase(
    passphrase: str,
    ciphertext: Union[str, bytes],
    *,
    authenticator: Union[str, bytes, None] = None,
    encoding: None = None,
) -> bytes: ...


@overload
def decrypt_by_passphrase(
    passphrase: str,
    ciphertext: Union[str, bytes],
    *,
    authenticator: Union[str, bytes, None] = None,
    encoding: Literal["auto"],
) -> str: ...


@overload
def decrypt_by_passphrase(
    passphrase: str,
    ciphertext: Union[str, bytes],
    *,
    authenticator: Union[str, bytes, None] = None,
    encoding: str,
) -> str: ...


def decrypt_by_passphrase(
    passphrase: str,
    ciphertext: Union[str, bytes],
    *,
    authenticator: Union[str, bytes, None] = None,
    encoding: Optional[str] = None,
) -> Union[bytes, str]:
    """Decrypt data from SQL Server's ENCRYPTBYPASSPHRASE."""
    if isinstance(ciphertext, str):
        if ciphertext.lower().startswith("0x"):
            ciphertext = ciphertext[2:]
        ciphertext = bytes.fromhex(ciphertext)

    if len(ciphertext) < 4:
        raise ValueError("Ciphertext too short")

    ver = SQLCryptVersion(ciphertext[0])

    if ver == SQLCryptVersion.V1:
        if len(ciphertext) < 12:
            raise ValueError("Ciphertext too short for V1")
        iv, enc = ciphertext[4:12], ciphertext[12:]
        dec = unpad(DES3.new(_key_v1(passphrase), DES3.MODE_CBC, iv).decrypt(enc), 8)
    else:
        if len(ciphertext) < 20:
            raise ValueError("Ciphertext too short for V2")
        iv, enc = ciphertext[4:20], ciphertext[20:]
        dec = unpad(AES.new(_key_v2(passphrase), AES.MODE_CBC, iv).decrypt(enc), 16)

    embedded_auth, data = _unpack(dec)

    if authenticator is not None:
        if isinstance(authenticator, str):
            exp = authenticator.encode(encoding or "utf-8")
        else:
            exp = authenticator
        if exp != embedded_auth:
            raise ValueError("Authenticator mismatch")

    if encoding == "auto":
        return data.decode(_detect_encoding(data))
    return data.decode(encoding) if encoding else data
