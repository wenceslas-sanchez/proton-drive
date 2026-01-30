"""
Proton Drive Python Client.

A modern, async Python client for Proton Drive with full encryption support.

Example:
    ```python
    from proton_drive import ProtonDriveClient

    async with ProtonDriveClient() as client:
        await client.authenticate("user@proton.me", "password")

        if client.requires_2fa:
            await client.provide_2fa("123456")

        # List files
        root = await client.build_tree()
        print(root.format_tree())

        # Download a file
        await client.download_to_file("/docs/report.pdf", "report.pdf")
    ```
"""

from proton_drive.client import ProtonDriveClient
from proton_drive.config import ProtonDriveConfig
from proton_drive.exceptions import (
    APIError,
    AuthenticationError,
    BlockDecryptionError,
    CryptoError,
    IntegrityError,
    InvalidCredentialsError,
    InvalidPathError,
    KeyDecryptionError,
    KeyUnlockError,
    NetworkError,
    NotAFileError,
    NotAFolderError,
    NotFoundError,
    PathError,
    PathNotFoundError,
    ProtonDriveError,
    RateLimitError,
    ServerError,
    SessionExpiredError,
    SessionKeyError,
    TwoFactorInvalidError,
    TwoFactorRequiredError,
    UnsupportedAlgorithmError,
)
from proton_drive.models.drive import DriveNode, NodeType

__version__ = "0.1.0"

__all__ = [
    # Main client
    "ProtonDriveClient",
    "ProtonDriveConfig",
    # Models
    "DriveNode",
    "NodeType",
    # Exceptions
    "ProtonDriveError",
    "AuthenticationError",
    "InvalidCredentialsError",
    "TwoFactorRequiredError",
    "TwoFactorInvalidError",
    "SessionExpiredError",
    "KeyUnlockError",
    "CryptoError",
    "KeyDecryptionError",
    "SessionKeyError",
    "BlockDecryptionError",
    "IntegrityError",
    "UnsupportedAlgorithmError",
    "APIError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "NetworkError",
    "PathError",
    "InvalidPathError",
    "PathNotFoundError",
    "NotAFileError",
    "NotAFolderError",
]
