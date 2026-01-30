"""
PGP backend protocol definition.

This defines the interface for PGP operations, allowing different implementations
(pgpy, custom parser, etc.) to be swapped without changing the rest of the codebase.
"""

from typing import Any, Protocol, runtime_checkable

from proton_drive.crypto.secure_bytes import SecureBytes
from proton_drive.models.crypto import SessionKey


@runtime_checkable
class PrivateKey(Protocol):
    """Protocol for a private key object."""

    @property
    def key_id(self) -> str:
        """Get the key ID."""
        ...

    @property
    def fingerprint(self) -> str:
        """Get the key fingerprint."""
        ...


@runtime_checkable
class PGPBackend(Protocol):
    """
    Abstract interface for PGP operations.

    Implementations can use pgpy, python-gnupg, or a custom parser.
    This allows swapping the underlying PGP library without changing
    the rest of the codebase.
    """

    def load_private_key(self, armored_key: str) -> PrivateKey:
        """
        Load a private key from ASCII-armored format.

        Args:
            armored_key: ASCII-armored private key.

        Returns:
            A PrivateKey object that can be used for decryption.

        Raises:
            CryptoError: If the key cannot be parsed.
        """
        ...

    def decrypt_message(
        self,
        encrypted_message: str,
        private_key: PrivateKey,
        passphrase: SecureBytes,
    ) -> bytes:
        """
        Decrypt a PGP message.

        Args:
            encrypted_message: ASCII-armored encrypted message.
            private_key: Private key for decryption.
            passphrase: Key passphrase.

        Returns:
            Decrypted message content.

        Raises:
            KeyDecryptionError: If decryption fails.
        """
        ...

    def extract_session_key(
        self,
        content_key_packet: bytes,
        private_key: PrivateKey,
        passphrase: SecureBytes,
    ) -> SessionKey:
        """
        Extract session key from a ContentKeyPacket.

        The ContentKeyPacket is a PKESK (Public-Key Encrypted Session Key) packet
        that contains the symmetric key used to encrypt file content.

        Args:
            content_key_packet: Raw bytes of the ContentKeyPacket.
            private_key: Private key for decryption.
            passphrase: Key passphrase.

        Returns:
            SessionKey containing the algorithm and key bytes.

        Raises:
            SessionKeyError: If extraction fails.
        """
        ...

    def unlock_key(self, private_key: PrivateKey, passphrase: SecureBytes) -> Any:
        """
        Unlock a key with its passphrase for use in operations.

        Some backends require explicit key unlocking before operations.

        Args:
            private_key: Private key to unlock.
            passphrase: Key passphrase.

        Returns:
            Context manager or unlocked key object.

        Raises:
            KeyDecryptionError: If the passphrase is incorrect.
        """
        ...
