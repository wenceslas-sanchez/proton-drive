"""
Authentication-related domain models.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class AuthScope(StrEnum):
    """Proton API authentication scopes."""

    SELF = "self"
    ORGANIZATION = "organization"
    PAYMENTS = "payments"
    MAIL = "mail"
    DRIVE = "drive"
    CALENDAR = "calendar"
    CONTACTS = "contacts"
    FULL = "full"
    PASSWORD = "password"
    LOCKED = "locked"
    NONDELINQUENT = "nondelinquent"


@dataclass(frozen=True, kw_only=True)
class SessionInfo:
    """
    Represents an authenticated Proton session.

    Attributes:
        uid: Unique session identifier.
        access_token: Bearer token for API requests.
        refresh_token: Token for refreshing access_token.
        scopes: List of granted scopes.
        created_at: When the session was created.
    """

    uid: str
    access_token: str
    refresh_token: str
    scopes: frozenset[str]
    created_at: datetime = field(default_factory=datetime.now)

    @property
    def has_drive_scope(self) -> bool:
        """Check if session has Drive access."""
        return AuthScope.DRIVE in self.scopes or AuthScope.FULL in self.scopes

    @property
    def requires_2fa(self) -> bool:
        """Check if 2FA is needed (no drive scope yet)."""
        return not self.has_drive_scope


@dataclass(frozen=True, kw_only=True)
class UserKey:
    """
    Represents a user's PGP key.

    Attributes:
        key_id: Unique key identifier.
        armored_key: ASCII-armored private key.
        is_primary: Whether this is the primary key.
        fingerprint: Key fingerprint.
    """

    key_id: str
    armored_key: str
    is_primary: bool = False
    fingerprint: str | None = None


@dataclass(frozen=True, kw_only=True)
class AddressKey:
    """
    Represents an address-specific PGP key.

    Attributes:
        key_id: Unique key identifier.
        address_id: Associated address ID.
        armored_key: ASCII-armored private key.
        token: Encrypted token for key derivation (if present).
        is_primary: Whether this is the primary key for the address.
    """

    key_id: str
    address_id: str
    armored_key: str
    token: str | None = None
    is_primary: bool = False


@dataclass(frozen=True, kw_only=True)
class KeySalt:
    """
    Key salt for password-based key derivation.

    Attributes:
        key_id: The key this salt belongs to.
        salt: Base64-encoded salt value.
    """

    key_id: str
    salt: str
