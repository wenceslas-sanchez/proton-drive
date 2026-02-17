"""
PGP backend implementation using pgpy library.

This is the current implementation that can be swapped out later
if we need to move to a custom OpenPGP parser or different library.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

import pgpy
from pgpy.packet.fields import MPI

from proton_drive.crypto.secure_bytes import SecureBytes
from proton_drive.crypto.session_key import parse_pkesk_packet
from proton_drive.exceptions import CryptoError, KeyDecryptionError, SessionKeyError
from proton_drive.models.crypto import PKESKPacket, SessionKey, SymmetricAlgorithm

_VALID_KEY_SIZES = (16, 24, 32)


@dataclass
class PgpyPrivateKey:
    """Wrapper around pgpy.PGPKey to implement PrivateKey protocol."""

    _key: pgpy.PGPKey

    @property
    def key_id(self) -> str:
        return str(self._key.fingerprint.keyid)

    @property
    def fingerprint(self) -> str:
        return str(self._key.fingerprint)

    @property
    def pgpy_key(self) -> pgpy.PGPKey:
        return self._key


class PgpyBackend:
    """
    PGP backend implementation using pgpy.

    Example:
        backend = PgpyBackend()
        key = backend.load_private_key(armored_key)
        decrypted = backend.decrypt_message(encrypted, key, passphrase)
    """

    @staticmethod
    def load_private_key(armored_key: str) -> PgpyPrivateKey:
        """
        Load a private key from ASCII-armored format.

        Args:
            armored_key: ASCII-armored private key.

        Returns:
            PgpyPrivateKey wrapper.

        Raises:
            CryptoError: If the key cannot be parsed.
        """
        try:
            key, _ = pgpy.PGPKey.from_blob(armored_key)
            return PgpyPrivateKey(_key=key)
        except Exception as e:
            msg = f"Failed to load private key: {e}"
            raise CryptoError(msg) from e

    def decrypt_message(
        self,
        encrypted_message: str,
        private_key: PgpyPrivateKey,
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
        try:
            message = pgpy.PGPMessage.from_blob(encrypted_message)
            with private_key.pgpy_key.unlock(passphrase.decode()):
                decrypted = private_key.pgpy_key.decrypt(message)
                return self._normalize_decrypted_content(decrypted.message)
        except pgpy.errors.PGPDecryptionError as e:
            msg = f"Failed to decrypt message: {e}"
            raise KeyDecryptionError(msg) from e
        except Exception as e:
            msg = f"Decryption failed: {e}"
            raise KeyDecryptionError(msg) from e

    def extract_session_key(
        self,
        content_key_packet: bytes,
        private_key: PgpyPrivateKey,
        passphrase: SecureBytes,
    ) -> SessionKey:
        """
        Extract session key from a ContentKeyPacket.

        Args:
            content_key_packet: Raw bytes of the ContentKeyPacket (base64-decoded).
            private_key: Node key for decryption.
            passphrase: Node key passphrase.

        Returns:
            SessionKey containing the algorithm and key bytes.

        Raises:
            SessionKeyError: If extraction fails.
        """
        try:
            pkesk = parse_pkesk_packet(content_key_packet)
            with private_key.pgpy_key.unlock(passphrase.decode()):
                encryption_key = self._find_encryption_key(private_key.pgpy_key)
                decrypted_payload = self._decrypt_session_key_mpi(encryption_key, pkesk)
                return self._parse_session_key_payload(decrypted_payload)
        except SessionKeyError:
            raise
        except Exception as e:
            msg = f"Failed to extract session key: {e}"
            raise SessionKeyError(msg) from e

    @contextmanager
    def unlock_key(self, private_key: PgpyPrivateKey, passphrase: SecureBytes) -> Iterator[Any]:
        """
        Unlock a key with its passphrase.

        Args:
            private_key: Private key to unlock.
            passphrase: Key passphrase.

        Yields:
            The unlocked key context.

        Raises:
            KeyDecryptionError: If the passphrase is incorrect.
        """
        try:
            with private_key.pgpy_key.unlock(passphrase.decode()):
                yield private_key
        except Exception as e:
            msg = f"Failed to unlock key: {e}"
            raise KeyDecryptionError(msg) from e

    @staticmethod
    def _normalize_decrypted_content(content: bytes | str | bytearray) -> bytes:
        if isinstance(content, (bytes, bytearray)):
            return bytes(content)
        return content.encode("utf-8")

    @staticmethod
    def _find_encryption_key(key: pgpy.PGPKey) -> pgpy.PGPKey:
        for subkey in key.subkeys.values():
            if subkey.is_public is False:
                return subkey
        return key

    @staticmethod
    def _decrypt_session_key_mpi(encryption_key: pgpy.PGPKey, pkesk: PKESKPacket) -> bytes:
        try:
            encrypted_mpi = MPI(pkesk.encrypted_session_key)
            decrypted = encryption_key._key.keymaterial.decrypt(encrypted_mpi)
            return bytes(decrypted)
        except Exception as e:
            msg = f"Manual PKESK decryption failed: {e}"
            raise SessionKeyError(msg) from e

    def _parse_session_key_payload(self, payload: bytes) -> SessionKey:
        """Parse decrypted session key payload: [algo(1)] + [key(N)] + [checksum(2)]."""
        self._validate_payload_length(payload)
        algorithm = self._parse_algorithm(payload[0])
        key_size = self._determine_key_size(algorithm, len(payload))
        key_data = payload[1 : 1 + key_size]
        checksum = payload[1 + key_size : 1 + key_size + 2]
        self._verify_checksum(key_data, checksum)
        return SessionKey(algorithm=algorithm, key_data=key_data)

    @staticmethod
    def _validate_payload_length(payload: bytes) -> None:
        if len(payload) >= 3:
            return
        msg = f"Session key payload too short: {len(payload)} bytes"
        raise SessionKeyError(msg)

    @staticmethod
    def _parse_algorithm(algorithm_id: int) -> SymmetricAlgorithm:
        try:
            return SymmetricAlgorithm(algorithm_id)
        except ValueError:
            msg = f"Unknown symmetric algorithm: {algorithm_id}"
            raise SessionKeyError(msg) from None

    @staticmethod
    def _determine_key_size(algorithm: SymmetricAlgorithm, payload_length: int) -> int:
        key_size = algorithm.key_size
        if key_size > 0:
            return key_size
        inferred_size = payload_length - 3
        if inferred_size not in _VALID_KEY_SIZES:
            msg = f"Cannot determine key size for algorithm {algorithm.value}"
            raise SessionKeyError(msg)
        return inferred_size

    @staticmethod
    def _verify_checksum(key_data: bytes, checksum: bytes) -> None:
        computed = sum(key_data) % 65536
        expected = int.from_bytes(checksum, "big")
        if computed == expected:
            return
        msg = "Session key checksum mismatch"
        raise SessionKeyError(msg)
