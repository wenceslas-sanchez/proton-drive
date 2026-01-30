"""
Cryptographic domain models.
"""

from dataclasses import dataclass
from enum import IntEnum


class SymmetricAlgorithm(IntEnum):
    """OpenPGP symmetric algorithm identifiers."""

    PLAINTEXT = 0
    IDEA = 1
    TRIPLE_DES = 2
    CAST5 = 3
    BLOWFISH = 4
    AES_128 = 7
    AES_192 = 8
    AES_256 = 9
    TWOFISH = 10
    CAMELLIA_128 = 11
    CAMELLIA_192 = 12
    CAMELLIA_256 = 13

    @property
    def key_size(self) -> int:
        """Get key size in bytes for this algorithm."""
        match self:
            case self.AES_128 | self.CAST5 | self.BLOWFISH | self.CAMELLIA_128:
                return 16
            case self.AES_192 | self.TRIPLE_DES | self.CAMELLIA_192:
                return 24
            case self.AES_256 | self.TWOFISH | self.CAMELLIA_256:
                return 32
            case _:
                return 0

    @property
    def block_size(self) -> int:
        """Get block size in bytes for this algorithm."""
        match self:
            case self.CAST5 | self.BLOWFISH | self.TRIPLE_DES:
                return 8
            case (
                self.AES_128
                | self.AES_192
                | self.AES_256
                | self.TWOFISH
                | self.CAMELLIA_128
                | self.CAMELLIA_192
                | self.CAMELLIA_256
            ):
                return 16
            case _:
                return 0


class PublicKeyAlgorithm(IntEnum):
    """OpenPGP public key algorithm identifiers."""

    RSA_ENCRYPT_OR_SIGN = 1
    RSA_ENCRYPT_ONLY = 2
    RSA_SIGN_ONLY = 3
    ELGAMAL_ENCRYPT_ONLY = 16
    DSA = 17
    ECDH = 18
    ECDSA = 19
    ELGAMAL_ENCRYPT_OR_SIGN = 20
    EDDSA = 22
    X25519 = 25
    ED25519 = 27


@dataclass(frozen=True, kw_only=True)
class SessionKey:
    """
    Represents a decrypted session key for file encryption.

    Attributes:
        algorithm: The symmetric algorithm used.
        key_data: The raw key bytes.
    """

    algorithm: SymmetricAlgorithm
    key_data: bytes

    def __post_init__(self) -> None:
        """Validate key size matches algorithm."""
        expected = self.algorithm.key_size
        if not expected or (len(self.key_data) == expected):
            return
        msg = f"Key size mismatch: {self.algorithm.name} expects {expected} bytes, got {len(self.key_data)}"
        raise ValueError(msg)

    @property
    def block_size(self) -> int:
        """Get the block size for this key's algorithm."""
        return self.algorithm.block_size


@dataclass(frozen=True, kw_only=True)
class EncryptedMessage:
    """
    Represents an encrypted PGP message.

    Attributes:
        armored: ASCII-armored message content.
        is_binary: Whether the underlying data is binary.
    """

    armored: str
    is_binary: bool = False


@dataclass(frozen=True, kw_only=True)
class KeyBundle:
    """
    A PGP key with its associated passphrase.

    Used for the key hierarchy where each level's key unlocks the next.
    This is an internal model - the actual key objects are managed by the backend.
    """

    key_id: str
    armored_key: str
    # Note: passphrase is stored in SecureBytes in the actual implementation


@dataclass(frozen=True, kw_only=True)
class PKESKPacket:
    """
    Public-Key Encrypted Session Key packet data.

    Parsed from ContentKeyPacket for extracting session keys.
    """

    version: int
    key_id: bytes  # 8 bytes
    algorithm: PublicKeyAlgorithm
    encrypted_session_key: bytes


@dataclass(frozen=True, kw_only=True)
class SEIPDPacket:
    """
    Symmetrically Encrypted Integrity Protected Data packet.

    Used for file block encryption.
    """

    version: int
    encrypted_data: bytes
