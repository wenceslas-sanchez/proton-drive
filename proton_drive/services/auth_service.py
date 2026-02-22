"""
Authentication service for Proton Drive.

Handles SRP authentication, 2FA, and key unlocking.
"""

import asyncio
import base64
import hmac
import shutil
import tempfile
from typing import Any

import gnupg
import structlog
from proton.constants import SRP_MODULUS_KEY, SRP_MODULUS_KEY_FINGERPRINT
from proton.srp import User as SrpUser

from proton_drive.api.endpoints.auth import (
    authenticate,
    get_auth_info,
    logout,
    provide_2fa,
)
from proton_drive.api.endpoints.user import get_key_salts, get_user_keys
from proton_drive.api.http_client import AsyncHttpClient
from proton_drive.crypto.key_manager import KeyManager
from proton_drive.crypto.secure_bytes import SecureBytes
from proton_drive.exceptions import (
    AuthenticationError,
    InvalidCredentialsError,
    TwoFactorInvalidError,
)
from proton_drive.models.auth import AuthScope, SessionInfo

logger = structlog.get_logger(__name__)


class AuthService:
    """
    Handles Proton authentication.

    Manages the SRP authentication flow, 2FA, and key unlocking.
    Tokens live exclusively in AsyncHttpClient; this service only tracks scopes.

    Security notes:
    - Password is temporarily stored in memory (using SecureBytes) to support:
      1. 2FA key unlock after initial authentication
      2. Key unlock after 2FA completion
    - Password is cleared on: logout, authentication failure, or service cleanup

    Concurrency:
    - Methods are protected by an internal lock for thread-safety
    - Concurrent authenticate() calls will execute sequentially; the second call
      will overwrite the first session
    """

    def __init__(
        self,
        http_client: AsyncHttpClient,
        key_manager: KeyManager,
    ) -> None:
        """
        Args:
            http_client: HTTP client for API requests.
            key_manager: Key manager for unlocking keys.
        """
        self._http = http_client
        self._key_manager = key_manager

        self._scopes: frozenset[str] | None = None
        self._password: SecureBytes | None = None  # Kept for 2FA key unlock
        self._lock = asyncio.Lock()  # Protects session state

        # Use isolated GPG home to avoid conflicts and security issues
        self._gpg_dir = tempfile.mkdtemp(prefix="proton_gpg_")
        self._gpg = gnupg.GPG(gnupghome=self._gpg_dir)
        self._gpg.import_keys(SRP_MODULUS_KEY)

    @property
    def is_authenticated(self) -> bool:
        """Check if authenticated."""
        return self._scopes is not None

    @property
    def requires_2fa(self) -> bool:
        """Check if 2FA is required."""
        return (
            self._scopes is not None
            and AuthScope.DRIVE not in self._scopes
            and AuthScope.FULL not in self._scopes
        )

    @property
    def has_drive_access(self) -> bool:
        """Check if we have drive access."""
        return self._scopes is not None and (
            AuthScope.DRIVE in self._scopes or AuthScope.FULL in self._scopes
        )

    async def authenticate(self, username: str, password: str) -> SessionInfo:
        """
        Authenticate with Proton using SRP.

        Note: This method is protected by a lock for thread-safety. If called
        concurrently from multiple tasks, the second call will wait for the first
        to complete, then proceed and overwrite the first session. To prevent this,
        ensure authenticate() is only called once, or wait for completion before
        calling again.

        Args:
            username: Proton email/username.
            password: Account password.

        Returns:
            SessionInfo with scopes.

        Raises:
            InvalidCredentialsError: If credentials are wrong or empty.
            AuthenticationError: If authentication fails.
        """
        logger.info("Starting authentication")

        if (len(username) == 0) or (len(password) == 0):
            msg = "Username and password required"
            raise InvalidCredentialsError(msg)

        async with self._lock:
            try:
                auth_info = await get_auth_info(self._http, username)
                auth_response = await self._perform_srp_auth(username, password, auth_info)

                scope_string = auth_response.get("Scope", "")
                scopes = frozenset(scope_string.split()) if scope_string else frozenset()

                # NOTE: on failure after this point, tokens remain in http_client
                # until overwritten by next authenticate() or context manager exit.
                await self._http.set_session(
                    uid=auth_response["UID"],
                    access_token=auth_response["AccessToken"],
                    refresh_token=auth_response["RefreshToken"],
                )
                self._scopes = scopes
                self._store_credentials(password)

                logger.info(
                    "Authentication successful",
                    requires_2fa=self.requires_2fa,
                )

                if self.has_drive_access:
                    await self._unlock_keys()

                return SessionInfo(scopes=scopes)

            except (InvalidCredentialsError, AuthenticationError):
                self._clear_state()
                raise
            except Exception as e:
                self._clear_state()
                msg = "Authentication failed"
                logger.error(msg, error_type=type(e).__name__)
                raise AuthenticationError(msg) from e

    async def provide_2fa(self, code: str) -> SessionInfo:
        """
        Provide 2FA code to complete authentication.

        Args:
            code: 6-digit 2FA code.

        Returns:
            Updated SessionInfo with full scopes.

        Raises:
            TwoFactorInvalidError: If the code is invalid.
            AuthenticationError: If not in 2FA state.
        """
        if not code or not code.isdigit() or len(code) != 6:
            msg = "Invalid 2FA code format"
            raise TwoFactorInvalidError(msg)

        async with self._lock:
            if self._scopes is None:
                msg = "Not authenticated. Call authenticate() first."
                raise AuthenticationError(msg)

            if not self.requires_2fa:
                msg = "2FA not required"
                raise AuthenticationError(msg)

            logger.info("Providing 2FA code")

            try:
                response = await provide_2fa(self._http, code)
            except TwoFactorInvalidError:
                raise
            except Exception as e:
                logger.error("2FA failed", error_type=type(e).__name__)
                msg = "2FA failed"
                raise AuthenticationError(msg) from e

            previous_scopes = self._scopes
            self._scopes = frozenset(response.get("Scopes", frozenset()))

            logger.info("2FA successful")

            try:
                if (self._password is not None) and self.has_drive_access:
                    await self._unlock_keys()
            except Exception as e:
                logger.warning(
                    "Failed to unlock keys after 2FA, rolling back scopes",
                    error_type=type(e).__name__,
                )
                self._scopes = previous_scopes
                raise

            return SessionInfo(scopes=self._scopes)

    async def logout(self) -> None:
        """Logout and clear session."""
        logger.info("Logging out")

        async with self._lock:
            if self._scopes is not None:
                try:
                    await logout(self._http)
                except Exception as e:
                    logger.warning("Logout request failed", error_type=type(e).__name__, exc_info=e)

            self._clear_state()

    async def _perform_srp_auth(
        self,
        username: str,
        password: str,
        auth_info: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Perform the full SRP authentication handshake.

        Args:
            username: Proton username.
            password: Account password.
            auth_info: Server auth info (modulus, salt, ephemeral, etc.).

        Returns:
            Raw auth response dict from the API.

        Raises:
            AuthenticationError: If SRP challenge or verification fails.
            InvalidCredentialsError: If server proof is invalid.
        """
        modulus = await self._verify_modulus(auth_info["Modulus"])
        server_ephemeral = base64.b64decode(auth_info["ServerEphemeral"])
        salt = base64.b64decode(auth_info["Salt"])
        version = auth_info["Version"]

        srp_user = SrpUser(password, modulus)
        client_ephemeral = srp_user.get_challenge()
        client_proof = srp_user.process_challenge(salt, server_ephemeral, version)

        if client_proof is None:
            msg = "Invalid SRP challenge"
            raise AuthenticationError(msg)

        auth_response = await authenticate(
            self._http,
            username=username,
            client_ephemeral=base64.b64encode(client_ephemeral).decode("utf-8"),
            client_proof=base64.b64encode(client_proof).decode("utf-8"),
            srp_session=auth_info["SRPSession"],
        )

        self._verify_server_proof(srp_user, auth_response)

        return auth_response

    async def _verify_modulus(self, armored_modulus: str) -> bytes:
        verified = await asyncio.to_thread(self._gpg.decrypt, armored_modulus)

        if not verified.valid:
            msg = "Invalid modulus signature"
            raise AuthenticationError(msg)

        # Use constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(
            verified.fingerprint.lower(),
            SRP_MODULUS_KEY_FINGERPRINT.lower(),
        ):
            msg = "Invalid modulus fingerprint"
            raise AuthenticationError(msg)

        return base64.b64decode(verified.data.strip())

    @staticmethod
    def _verify_server_proof(
        srp_user: SrpUser,
        auth_response: dict[str, Any],
    ) -> None:
        if "ServerProof" not in auth_response:
            msg = "Invalid password"
            raise InvalidCredentialsError(msg)

        srp_user.verify_session(base64.b64decode(auth_response["ServerProof"]))

        if not srp_user.authenticated():
            msg = "Server proof verification failed"
            raise InvalidCredentialsError(msg)

    def _store_credentials(self, password: str) -> None:
        """
        Store password securely in memory for 2FA key unlock.

        Security design: The plaintext password must be retained in memory after
        initial SRP authentication because Proton's key unlock flow requires it
        in two distinct phases:
        1. Immediately after auth (no 2FA): used to derive the bcrypt passphrase
           that unlocks the user's PGP private key.
        2. After 2FA completion: the same derivation is needed to unlock keys once
           the session gains full scope.

        Storing the derived key passphrase instead of the raw password is not
        feasible because the passphrase depends on a per-key salt fetched from the
        API, which is only retrieved during `_unlock_keys()`.

        Mitigations:
        - Password is wrapped in `SecureBytes` (memory-locked, zeroed on clear).
        - `_clear_state()` zeroes and discards it on logout, auth failure, or cleanup.
        - The previous `SecureBytes` instance (if any) is overwritten and its memory
          zeroed before the new one is stored.
        """
        if self._password is not None:
            self._password.clear()
        self._password = SecureBytes.from_string(password)

    def _clear_state(self) -> None:
        """
        Clear all authentication state.

        Securely wipes password from memory, clears scopes, and clears key manager.
        Note: HTTP client session tokens are managed separately.
        """
        if self._password is not None:
            self._password.clear()
            self._password = None
        self._scopes = None
        self._key_manager.clear()

    def cleanup(self) -> None:
        """
        Clean up resources including GPG temporary directory.

        Should be called when the service is no longer needed.
        """
        self._clear_state()
        try:
            shutil.rmtree(self._gpg_dir, ignore_errors=True)
        except Exception as e:
            logger.warning("Failed to clean up GPG directory", error_type=type(e).__name__)

    async def _unlock_keys(self) -> None:
        """Unlock user keys using stored credentials."""
        if self._password is None:
            msg = "No credentials available for key unlock"
            raise AuthenticationError(msg)

        logger.debug("Unlocking user keys")

        try:
            user_keys = await get_user_keys(self._http)
            key_salts = await get_key_salts(self._http)

            if len(user_keys) == 0:
                msg = "No user keys found"
                raise AuthenticationError(msg)

            primary_key = next((k for k in user_keys if k.is_primary), user_keys[0])

            salt = next((s for s in key_salts if s.key_id == primary_key.key_id), None)
            if salt is None:
                msg = f"No salt found for key {primary_key.key_id}"
                raise AuthenticationError(msg)

            self._key_manager.unlock_user_key(primary_key, self._password, salt)
            logger.debug("User keys unlocked")

        except AuthenticationError:
            raise
        except Exception as e:
            logger.warning("Failed to unlock keys", error_type=type(e).__name__)
            msg = "Failed to unlock keys"
            raise AuthenticationError(msg) from e
