"""
Proton Drive exception hierarchy.

All exceptions inherit from ProtonDriveError for easy catching.
"""

from typing import Any


class ProtonDriveError(Exception):
    """Base exception for all proton_drive errors."""

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context = context

    def __str__(self) -> str:
        if self.context:
            ctx = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{self.message} ({ctx})"
        return self.message


class AuthenticationError(ProtonDriveError):
    """Authentication failed."""


class InvalidCredentialsError(AuthenticationError):
    """Invalid username or password."""


class TwoFactorRequiredError(AuthenticationError):
    """Two-factor authentication code required to proceed."""

    def __init__(self, message: str = "2FA code required for Drive access") -> None:
        super().__init__(message)


class TwoFactorInvalidError(AuthenticationError):
    """Provided two-factor code is invalid."""


class SessionExpiredError(AuthenticationError):
    """Session has expired and refresh failed."""


class KeyUnlockError(AuthenticationError):
    """Failed to unlock user keys with provided password."""


class CryptoError(ProtonDriveError):
    """Cryptographic operation failed."""


class KeyDecryptionError(CryptoError):
    """Failed to decrypt a key in the hierarchy."""

    def __init__(self, message: str, *, key_type: str | None = None) -> None:
        super().__init__(message, key_type=key_type)
        self.key_type = key_type


class SessionKeyError(CryptoError):
    """Failed to extract or use session key."""


class BlockDecryptionError(CryptoError):
    """Failed to decrypt file block."""

    def __init__(self, message: str, *, block_index: int | None = None) -> None:
        super().__init__(message, block_index=block_index)
        self.block_index = block_index


class IntegrityError(CryptoError):
    """Data integrity verification failed (hash mismatch, MDC failure)."""


class APIError(ProtonDriveError):
    """API request failed."""

    def __init__(self, message: str, *, code: int, endpoint: str | None = None) -> None:
        super().__init__(message, code=code, endpoint=endpoint)
        self.code = code
        self.endpoint = endpoint


class NotFoundError(APIError):
    """Resource not found (file, folder, share)."""

    def __init__(self, message: str, *, endpoint: str | None = None) -> None:
        super().__init__(message, code=404, endpoint=endpoint)


class RateLimitError(APIError):
    """Rate limited by API."""

    def __init__(
        self, message: str = "Rate limit exceeded", *, retry_after: int | None = None
    ) -> None:
        super().__init__(message, code=429)
        self.retry_after = retry_after


class ServerError(APIError):
    """Server-side error (5xx)."""

    def __init__(self, message: str, *, code: int = 500) -> None:
        super().__init__(message, code=code)


class NetworkError(ProtonDriveError):
    """Network-level error (connection failed, timeout)."""


class PathError(ProtonDriveError):
    """Path-related error."""

    def __init__(self, message: str, *, path: str) -> None:
        super().__init__(message, path=path)
        self.path = path


class PathNotFoundError(PathError):
    """Path does not exist in the drive."""


class NotAFileError(PathError):
    """Expected a file but got a folder."""


class NotAFolderError(PathError):
    """Expected a folder but got a file."""
