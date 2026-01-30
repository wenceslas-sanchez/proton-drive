"""
Domain models for Proton Drive.

These are immutable (frozen) dataclasses representing the core domain concepts.
"""

from proton_drive.models.auth import (
    AddressKey,
    AuthScope,
    KeySalt,
    SessionInfo,
    UserKey,
)
from proton_drive.models.crypto import (
    EncryptedMessage,
    KeyBundle,
    PKESKPacket,
    PublicKeyAlgorithm,
    SEIPDPacket,
    SessionKey,
    SymmetricAlgorithm,
)
from proton_drive.models.drive import (
    DriveNode,
    FileBlock,
    FileRevision,
    Link,
    LinkState,
    NodeType,
    Share,
    Volume,
)

__all__ = [
    # Auth
    "AuthScope",
    "SessionInfo",
    "UserKey",
    "AddressKey",
    "KeySalt",
    # Drive
    "Volume",
    "Share",
    "Link",
    "LinkState",
    "NodeType",
    "DriveNode",
    "FileRevision",
    "FileBlock",
    # Crypto
    "SymmetricAlgorithm",
    "PublicKeyAlgorithm",
    "SessionKey",
    "EncryptedMessage",
    "KeyBundle",
    "PKESKPacket",
    "SEIPDPacket",
]
