"""
PGP backend implementation using pgpy library.

This is the current implementation that can be swapped out later
if we need to move to a custom OpenPGP parser or different library.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

import pgpy

from proton_drive.crypto.secure_bytes import SecureBytes
from proton_drive.exceptions import CryptoError, KeyDecryptionError, SessionKeyError
from proton_drive.models.crypto import SessionKey, SymmetricAlgorithm


@dataclass
class PgpyPrivateKey:
    """Wrapper around pgpy.PGPKey to implement PrivateKey protocol."""

    _key: pgpy.PGPKey

    @property
    def key_id(self) -> str:
        """Get the key ID."""
        return str(self._key.fingerprint.keyid)

    @property
    def fingerprint(self) -> str:
        """Get the key fingerprint."""
        return str(self._key.fingerprint)

    @property
    def pgpy_key(self) -> pgpy.PGPKey:
        """Get the underlying pgpy key object."""
        return self._key


class PgpyBackend:
    """
    PGP backend implementation using pgpy.

    Example:
        backend = PgpyBackend()
        key = backend.load_private_key(armored_key)
        decrypted = backend.decrypt_message(encrypted, key, passphrase)
    """

    def load_private_key(self, armored_key: str) -> PgpyPrivateKey:
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
            raise CryptoError(f"Failed to load private key: {e}") from e

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

            # Unlock key and decrypt
            with private_key.pgpy_key.unlock(passphrase.decode()):
                decrypted = private_key.pgpy_key.decrypt(message)

                # Handle both bytes and string results
                if isinstance(decrypted.message, bytes):
                    return decrypted.message
                return decrypted.message.encode("utf-8")

        except pgpy.errors.PGPDecryptionError as e:
            raise KeyDecryptionError(f"Failed to decrypt message: {e}") from e
        except Exception as e:
            raise KeyDecryptionError(f"Decryption failed: {e}") from e

    def extract_session_key(
        self,
        content_key_packet: bytes,
        private_key: PgpyPrivateKey,
        passphrase: SecureBytes,
    ) -> SessionKey:
        """
        Extract session key from a ContentKeyPacket.

        The ContentKeyPacket is a PKESK packet. We need to decrypt it and
        extract the symmetric session key.

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
            # Create a minimal valid PGP message from the PKESK packet
            # by appending a dummy SEIPD packet
            pgp_message = self._create_minimal_message(content_key_packet)

            # Try to parse and decrypt
            with private_key.pgpy_key.unlock(passphrase.decode()):
                # Use pgpy's internal session key extraction
                # This is a workaround since pgpy doesn't directly expose session keys
                message = pgpy.PGPMessage.from_blob(pgp_message)

                # Decrypt - this will fail on the dummy data but we can extract
                # the session key from the decryption attempt
                try:
                    decrypted = private_key.pgpy_key.decrypt(message)
                    # If we get here, the message was somehow valid
                    # Extract session key from the decryption result
                    return self._extract_from_decrypted(decrypted)
                except Exception:
                    # Expected - fall back to manual extraction
                    pass

            # Fall back to manual PKESK parsing
            return self._parse_pkesk_manual(content_key_packet, private_key, passphrase)

        except SessionKeyError:
            raise
        except Exception as e:
            raise SessionKeyError(f"Failed to extract session key: {e}") from e

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
            raise KeyDecryptionError(f"Failed to unlock key: {e}") from e

    def _create_minimal_message(self, pkesk_bytes: bytes) -> bytes:
        """
        Create a minimal valid PGP message from a PKESK packet.

        Appends a minimal SEIPD packet so pgpy can parse the message.
        """
        # Create minimal SEIPD packet (tag 18)
        # Version 1 + minimal encrypted data
        dummy_encrypted = bytes([0x01]) + bytes(50)  # Version 1 + dummy data

        # Build SEIPD packet header (new format)
        seipd_length = len(dummy_encrypted)
        if seipd_length < 192:
            seipd_header = bytes([0xD2, seipd_length])
        else:
            seipd_header = bytes(
                [0xD2, ((seipd_length - 192) >> 8) + 192, (seipd_length - 192) & 0xFF]
            )

        return pkesk_bytes + seipd_header + dummy_encrypted

    def _extract_from_decrypted(self, decrypted: Any) -> SessionKey:
        """Extract session key from a pgpy decryption result."""
        # pgpy doesn't directly expose this, so we need to parse the result
        # This is a placeholder - actual implementation depends on pgpy internals
        raise SessionKeyError("Direct extraction not supported, using manual parsing")

    def _parse_pkesk_manual(
        self,
        packet_bytes: bytes,
        private_key: PgpyPrivateKey,
        passphrase: SecureBytes,
    ) -> SessionKey:
        """
        Manually parse and decrypt a PKESK packet.

        This is used when pgpy's built-in methods don't work for our use case.
        """
        # Import here to avoid circular dependency
        from proton_drive.crypto.session_key import parse_pkesk_packet

        pkesk = parse_pkesk_packet(packet_bytes)

        # Decrypt the session key using the private key
        with private_key.pgpy_key.unlock(passphrase.decode()):
            # Use pgpy's RSA/curve decryption
            # Get the key's private key material for decryption
            key = private_key.pgpy_key

            # Find the encryption subkey (or use primary if it can encrypt)
            enc_key = None
            for subkey in key.subkeys.values():
                if subkey.is_public is False:
                    enc_key = subkey
                    break

            if enc_key is None:
                enc_key = key

            # Decrypt using pgpy's internal methods
            # This requires accessing private APIs which may break
            try:
                from pgpy.packet.fields import MPI

                # Parse the encrypted MPI from the PKESK
                encrypted_mpi = MPI(pkesk.encrypted_session_key)

                # Use pgpy's decryption
                decrypted_sk = enc_key._key.keymaterial.decrypt(encrypted_mpi)

                # Parse the decrypted session key: [algo(1)] + [key(N)] + [checksum(2)]
                return self._parse_session_key_payload(bytes(decrypted_sk))

            except Exception as e:
                raise SessionKeyError(
                    f"Manual PKESK decryption failed: {e}. "
                    "Consider implementing native OpenPGP parser."
                ) from e

    def _parse_session_key_payload(self, payload: bytes) -> SessionKey:
        """
        Parse decrypted session key payload.

        Format: [algo(1)] + [key(N)] + [checksum(2)]
        """
        if len(payload) < 3:
            raise SessionKeyError(f"Session key payload too short: {len(payload)} bytes")

        algorithm_id = payload[0]

        try:
            algorithm = SymmetricAlgorithm(algorithm_id)
        except ValueError:
            raise SessionKeyError(f"Unknown symmetric algorithm: {algorithm_id}") from None

        key_size = algorithm.key_size
        if key_size == 0:
            # Try to infer from payload length
            key_size = len(payload) - 3
            if key_size not in (16, 24, 32):
                raise SessionKeyError(f"Cannot determine key size for algorithm {algorithm_id}")

        key_data = payload[1 : 1 + key_size]
        checksum = payload[1 + key_size : 1 + key_size + 2]

        # Verify checksum (sum of key bytes mod 65536)
        computed = sum(key_data) % 65536
        expected = int.from_bytes(checksum, "big")
        if computed != expected:
            raise SessionKeyError("Session key checksum mismatch")

        return SessionKey(algorithm=algorithm, key_data=key_data)


# Create a default instance
default_backend = PgpyBackend()
