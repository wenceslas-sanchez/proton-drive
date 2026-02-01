"""
Key hierarchy management for Proton Drive.

Handles the chain of key derivation:
User Key → Address Key → Share Key → Node Keys

Each level's key unlocks the next, with passphrases encrypted to the parent key.
"""

import base64

import bcrypt
import structlog

from proton_drive.crypto.pgpy_backend import PgpyBackend
from proton_drive.crypto.protocol import PGPBackend, PrivateKey
from proton_drive.crypto.secure_bytes import SecureBytes
from proton_drive.exceptions import KeyDecryptionError, KeyUnlockError
from proton_drive.models.auth import AddressKey, KeySalt, UserKey

logger = structlog.get_logger(__name__)


class KeyManager:
    """
    Manages the Proton Drive key hierarchy.

    The key hierarchy is:
    1. User Key: protected by bcrypt-derived passphrase
    2. Address Key: protected by User Key (via Token field)
    3. Share Key: passphrase encrypted to Address Key
    4. Node Keys: passphrase encrypted to parent's Node Key (or Share Key for root)
    """

    def __init__(self, pgp_backend: PGPBackend | None = None) -> None:
        """
        Args:
            pgp_backend: PGP backend for crypto operations. Defaults to PgpyBackend.
        """
        self._pgp = pgp_backend if pgp_backend is not None else PgpyBackend()  # todo remove default
        self._unlocked_passphrases: dict[str, SecureBytes] = {}  # key_id -> passphrase
        self._loaded_keys: dict[str, PrivateKey] = {}  # key_id -> key

    def unlock_user_key(self, user_key: UserKey, password: str, key_salt: KeySalt) -> SecureBytes:
        """
        Unlock a user's primary key.

        Args:
            user_key: User key from API.
            password: User's login password.
            key_salt: Key salt from API.

        Returns:
            The passphrase (for unlocking address keys that use Token).

        Raises:
            KeyUnlockError: If unlocking fails.
        """
        try:
            passphrase = self._derive_key_passphrase(password, key_salt)
            key = self._load_and_verify_key(user_key.armored_key, passphrase)

            # Cache the key and passphrase
            self._loaded_keys[user_key.key_id] = key
            self._unlocked_passphrases[user_key.key_id] = passphrase

            logger.debug("Unlocked user key", key_id=user_key.key_id[:8])
            return passphrase

        except KeyDecryptionError:
            raise
        except Exception as e:
            msg = f"Failed to unlock user key: {e}"
            raise KeyUnlockError(msg) from e

    def unlock_address_key(self, address_key: AddressKey, user_key_id: str) -> SecureBytes:
        """
        Unlock an address key using the user key.

        Address keys may have their passphrase in a Token field (encrypted to user key)
        or share the same passphrase as the user key.

        Args:
            address_key: Address key from API.
            user_key_id: ID of the unlocked user key.

        Returns:
            The passphrase for this address key.

        Raises:
            KeyDecryptionError: If unlocking fails.
        """
        if address_key.key_id in self._unlocked_passphrases:
            return self._unlocked_passphrases[address_key.key_id]

        if user_key_id not in self._unlocked_passphrases:
            msg = "User key not unlocked"
            raise KeyDecryptionError(msg, key_type="user")

        user_passphrase = self._unlocked_passphrases[user_key_id]
        user_key = self._loaded_keys[user_key_id]

        try:
            if address_key.token:
                passphrase_bytes = self._pgp.decrypt_message(
                    address_key.token, user_key, user_passphrase
                )
                passphrase = SecureBytes(passphrase_bytes)
            else:
                # Address key uses the same passphrase as user key
                passphrase = user_passphrase

            key = self._load_and_verify_key(address_key.armored_key, passphrase)

            self._loaded_keys[address_key.key_id] = key
            self._unlocked_passphrases[address_key.key_id] = passphrase

            logger.debug("Unlocked address key", key_id=address_key.key_id[:8])
            return passphrase

        except Exception as e:
            msg = f"Failed to unlock address key: {e}"
            raise KeyDecryptionError(msg, key_type="address") from e

    def unlock_share_key(
        self,
        share_key_armored: str,
        encrypted_passphrase: str,
        address_key_id: str,
    ) -> tuple[PrivateKey, SecureBytes]:
        """
        Unlock a share key using an address key.

        Args:
            share_key_armored: ASCII-armored share key.
            encrypted_passphrase: Passphrase encrypted to address key.
            address_key_id: ID of the unlocked address key.

        Returns:
            Tuple of (share_key, passphrase).

        Raises:
            KeyDecryptionError: If unlocking fails.
        """
        if address_key_id not in self._unlocked_passphrases:
            msg = "Address key not unlocked"
            raise KeyDecryptionError(msg, key_type="address")

        addr_passphrase = self._unlocked_passphrases[address_key_id]
        addr_key = self._loaded_keys[address_key_id]

        try:
            passphrase_bytes = self._pgp.decrypt_message(
                encrypted_passphrase, addr_key, addr_passphrase
            )
            passphrase = SecureBytes(passphrase_bytes)

            share_key = self._load_and_verify_key(share_key_armored, passphrase)

            logger.debug("Unlocked share key")
            return share_key, passphrase

        except Exception as e:
            msg = f"Failed to unlock share key: {e}"
            raise KeyDecryptionError(msg, key_type="share") from e

    def unlock_node_key(
        self,
        node_key_armored: str | None,
        encrypted_passphrase: str | None,
        parent_key: PrivateKey,
        parent_passphrase: SecureBytes,
    ) -> tuple[PrivateKey, SecureBytes]:
        """
        Unlock a node key using its parent's key.

        Args:
            node_key_armored: ASCII-armored node key (may be None for some nodes).
            encrypted_passphrase: Passphrase encrypted to parent key.
            parent_key: Parent's unlocked key.
            parent_passphrase: Parent's passphrase.

        Returns:
            Tuple of (node_key, passphrase). Returns parent's key/passphrase if
            node has no key of its own.

        Raises:
            KeyDecryptionError: If unlocking fails.
        """
        if not node_key_armored:
            return parent_key, parent_passphrase

        try:
            if encrypted_passphrase:
                passphrase_bytes = self._pgp.decrypt_message(
                    encrypted_passphrase, parent_key, parent_passphrase
                )
                passphrase = SecureBytes(passphrase_bytes)
            else:
                passphrase = parent_passphrase

            node_key = self._load_and_verify_key(node_key_armored, passphrase)

            return node_key, passphrase

        except Exception as e:
            msg = f"Failed to unlock node key: {e}"
            raise KeyDecryptionError(msg, key_type="node") from e

    def decrypt_name(
        self,
        encrypted_name: str,
        parent_key: PrivateKey,
        parent_passphrase: SecureBytes,
    ) -> str:
        """
        Decrypt a file or folder name.

        Args:
            encrypted_name: PGP-encrypted name.
            parent_key: Parent's key (used to encrypt the name).
            parent_passphrase: Parent's passphrase.

        Returns:
            Decrypted name string.
        """
        if not encrypted_name:
            return ""

        try:
            decrypted = self._pgp.decrypt_message(encrypted_name, parent_key, parent_passphrase)
            return decrypted.decode("utf-8")
        except Exception as e:
            logger.warning("Failed to decrypt name", error=str(e))
            return f"[encrypted: {str(e)[:20]}]"

    def get_loaded_key(self, key_id: str) -> PrivateKey | None:
        """Get a loaded key by ID."""
        return self._loaded_keys.get(key_id)

    def get_passphrase(self, key_id: str) -> SecureBytes | None:
        """Get an unlocked passphrase by key ID."""
        return self._unlocked_passphrases.get(key_id)

    def clear(self) -> None:
        """Clear all cached keys and passphrases."""
        for passphrase in self._unlocked_passphrases.values():
            passphrase.clear()
        self._unlocked_passphrases.clear()
        self._loaded_keys.clear()

    def _load_and_verify_key(self, armored_key: str, passphrase: SecureBytes) -> PrivateKey:
        key = self._pgp.load_private_key(armored_key)
        with self._pgp.unlock_key(key, passphrase):
            pass
        return key

    @staticmethod
    def _derive_key_passphrase(password: str, key_salt: KeySalt) -> SecureBytes:
        """
        Derive key passphrase from user password and salt.

        Uses bcrypt with Proton's specific salt encoding.

        Args:
            password: User's login password.
            key_salt: KeySalt from the API.

        Returns:
            SecureBytes containing the derived passphrase.
        """
        salt_binary = base64.b64decode(key_salt.salt)

        # Convert to bcrypt's base64 alphabet
        standard_b64 = base64.b64encode(salt_binary[:16]).decode("ascii")
        standard_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        bcrypt_alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

        translation_table = str.maketrans(standard_alphabet, bcrypt_alphabet)
        bcrypt_salt = standard_b64.translate(translation_table)[:22]
        bcrypt_hash = bcrypt.hashpw(
            password.encode("utf-8"), f"$2y$10${bcrypt_salt}".encode("utf-8")
        )

        # Return last 31 bytes
        return SecureBytes(bcrypt_hash[-31:])
