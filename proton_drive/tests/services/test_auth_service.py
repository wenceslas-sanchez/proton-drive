import base64
from unittest.mock import AsyncMock, Mock, patch

import pytest

from proton_drive.exceptions import (
    AuthenticationError,
    InvalidCredentialsError,
    TwoFactorInvalidError,
)
from proton_drive.models.auth import AuthScope, SessionInfo
from proton_drive.services.auth_service import AuthService

TEST_UID = "7a9f2c1e4b3d4f8a9c2e1d5f3a7b9c4e"
TEST_ACCESS_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test_payload"
TEST_REFRESH_TOKEN = "refresh_9d8c7b6a5e4f3d2c1b0a9f8e7d6c5b4a"
TEST_SRP_SESSION = "srp_session_7f8a9c2e1d3b4f6a"
TEST_USER_KEY_ID = "user_key_3f7e9c2d1a4b6f8e"
TEST_MODULUS_ARMORED = """-----BEGIN PGP MESSAGE-----

hQIMA1234567890ABAQP/test_armored_modulus_content
=abcd
-----END PGP MESSAGE-----"""

TEST_SERVER_EPHEMERAL = base64.b64encode(b"server_ephemeral_32_bytes_data_").decode()
TEST_SALT = base64.b64encode(b"salt_16bytes_da").decode()
TEST_CLIENT_EPHEMERAL = b"\x00" * 256  # 2048-bit
TEST_CLIENT_PROOF = b"\x00" * 32  # SHA-256
TEST_SERVER_PROOF = base64.b64encode(b"\x00" * 32).decode()
TEST_MODULUS_BYTES = b"\x00" * 256  # 2048-bit modulus
SCOPE_LIMITED = frozenset(["password", "locked"])  # Requires 2FA
SCOPE_FULL = frozenset([AuthScope.FULL])
SCOPE_DRIVE = frozenset([AuthScope.DRIVE])
SCOPE_FULL_AND_DRIVE = frozenset([AuthScope.FULL, AuthScope.DRIVE])


def make_auth_info_response() -> dict:
    return {
        "Modulus": TEST_MODULUS_ARMORED,
        "ServerEphemeral": TEST_SERVER_EPHEMERAL,
        "Salt": TEST_SALT,
        "Version": 4,
        "SRPSession": TEST_SRP_SESSION,
    }


def make_auth_response(scope: str = "full") -> dict:
    return {
        "UID": TEST_UID,
        "AccessToken": TEST_ACCESS_TOKEN,
        "RefreshToken": TEST_REFRESH_TOKEN,
        "ServerProof": TEST_SERVER_PROOF,
        "Scope": scope,
    }


def make_2fa_response(scopes: frozenset[str] = SCOPE_FULL_AND_DRIVE) -> dict:
    """Create realistic 2FA response."""
    return {"Scopes": scopes}


@pytest.fixture
def mock_http() -> Mock:
    return Mock()


@pytest.fixture
def auth_service(mock_http: Mock, mock_key_manager: Mock, mock_gpg: Mock) -> AuthService:
    """Create AuthService with mocked dependencies."""
    with patch("proton_drive.services.auth_service.gnupg.GPG") as mock_gpg_class:
        mock_gpg_class.return_value = mock_gpg
        service = AuthService(mock_http, mock_key_manager)
    return service


@pytest.mark.asyncio
async def test_full_authentication_flow_with_2fa(
    auth_service: AuthService,
    mock_http: Mock,
    mock_key_manager: Mock,
) -> None:
    """Test complete authentication flow: login → 2FA → key unlock → logout."""
    mock_http.set_session = AsyncMock()

    assert not auth_service.is_authenticated
    assert not auth_service.has_drive_access
    assert not auth_service.requires_2fa

    with (
        patch("proton_drive.services.auth_service.get_auth_info") as mock_get_auth_info,
        patch("proton_drive.services.auth_service.authenticate") as mock_auth_endpoint,
        patch("proton_drive.services.auth_service.provide_2fa") as mock_2fa_endpoint,
        patch("proton_drive.services.auth_service.get_user_keys") as mock_get_user_keys,
        patch("proton_drive.services.auth_service.get_key_salts") as mock_get_key_salts,
        patch("proton_drive.services.auth_service.logout") as mock_logout_endpoint,
        patch.object(auth_service, "_verify_modulus") as mock_verify_modulus,
        patch("proton_drive.services.auth_service.SrpUser") as mock_srp_class,
    ):
        # Setup mocks
        mock_get_auth_info.return_value = make_auth_info_response()
        mock_verify_modulus.return_value = TEST_MODULUS_BYTES

        mock_srp = Mock()
        mock_srp.get_challenge.return_value = TEST_CLIENT_EPHEMERAL
        mock_srp.process_challenge.return_value = TEST_CLIENT_PROOF
        mock_srp.authenticated.return_value = True
        mock_srp_class.return_value = mock_srp

        # STEP 1: Initial authentication returns limited scope (requires 2FA)
        mock_auth_endpoint.return_value = make_auth_response(scope="password locked")

        await auth_service.authenticate("user@proton.me", "secure_password")

        assert auth_service.is_authenticated
        assert auth_service.requires_2fa
        assert not auth_service.has_drive_access
        mock_key_manager.unlock_user_key.assert_not_called()

        # STEP 2: Provide 2FA code to get full access
        mock_2fa_endpoint.return_value = make_2fa_response()

        user_key = Mock()
        user_key.is_primary = True
        user_key.key_id = TEST_USER_KEY_ID
        mock_get_user_keys.return_value = [user_key]

        key_salt = Mock()
        key_salt.key_id = TEST_USER_KEY_ID
        mock_get_key_salts.return_value = [key_salt]

        result2 = await auth_service.provide_2fa("123456")

        assert not auth_service.requires_2fa
        assert auth_service.has_drive_access
        assert AuthScope.FULL in result2.scopes
        assert AuthScope.DRIVE in result2.scopes
        mock_key_manager.unlock_user_key.assert_called_once()

        # STEP 3: Logout clears everything
        await auth_service.logout()

        assert not auth_service.is_authenticated
        assert not auth_service.has_drive_access
        mock_logout_endpoint.assert_called_once()
        mock_key_manager.clear.assert_called_once()


def test_is_authenticated_returns_false_initially(auth_service: AuthService) -> None:
    assert auth_service.is_authenticated is False


def test_requires_2fa_returns_true_with_limited_scope(auth_service: AuthService) -> None:
    auth_service._scopes = SCOPE_LIMITED
    assert auth_service.requires_2fa is True


@pytest.mark.asyncio
async def test_authenticate_raises_error_on_empty_credentials(auth_service: AuthService) -> None:
    with pytest.raises(InvalidCredentialsError, match="Username and password required"):
        await auth_service.authenticate("", "password")

    with pytest.raises(InvalidCredentialsError, match="Username and password required"):
        await auth_service.authenticate("user@example.com", "")


@pytest.mark.asyncio
async def test_provide_2fa_raises_error_on_invalid_code(auth_service: AuthService) -> None:
    with pytest.raises(TwoFactorInvalidError, match="Invalid 2FA code format"):
        await auth_service.provide_2fa("")

    with pytest.raises(TwoFactorInvalidError, match="Invalid 2FA code format"):
        await auth_service.provide_2fa("12345a")

    with pytest.raises(TwoFactorInvalidError, match="Invalid 2FA code format"):
        await auth_service.provide_2fa("12345")


@pytest.mark.asyncio
async def test_authenticate_with_full_access_unlocks_keys(
    auth_service: AuthService,
    mock_http: Mock,
    mock_key_manager: Mock,
) -> None:
    """Test successful authentication with full access unlocks keys."""
    mock_http.set_session = AsyncMock()

    with (
        patch("proton_drive.services.auth_service.get_auth_info") as mock_get_auth_info,
        patch("proton_drive.services.auth_service.authenticate") as mock_auth_endpoint,
        patch("proton_drive.services.auth_service.get_user_keys") as mock_get_user_keys,
        patch("proton_drive.services.auth_service.get_key_salts") as mock_get_key_salts,
        patch.object(auth_service, "_verify_modulus") as mock_verify_modulus,
        patch("proton_drive.services.auth_service.SrpUser") as mock_srp_class,
    ):
        mock_get_auth_info.return_value = {
            "Modulus": "armored",
            "ServerEphemeral": base64.b64encode(b"ephemeral").decode(),
            "Salt": base64.b64encode(b"salt").decode(),
            "Version": 4,
            "SRPSession": "session",
        }
        mock_verify_modulus.return_value = b"modulus"

        mock_srp = Mock()
        mock_srp.get_challenge.return_value = b"challenge"
        mock_srp.process_challenge.return_value = b"proof"
        mock_srp.authenticated.return_value = True
        mock_srp_class.return_value = mock_srp

        mock_auth_endpoint.return_value = {
            "UID": "uid123",
            "AccessToken": "access_token",
            "RefreshToken": "refresh_token",
            "ServerProof": base64.b64encode(b"proof").decode(),
            "Scope": "full",
        }

        user_key = Mock()
        user_key.is_primary = True
        user_key.key_id = "key1"
        mock_get_user_keys.return_value = [user_key]

        key_salt = Mock()
        key_salt.key_id = "key1"
        mock_get_key_salts.return_value = [key_salt]

        result = await auth_service.authenticate("user@example.com", "password")

        assert isinstance(result, SessionInfo)
        assert AuthScope.FULL in result.scopes
        assert auth_service.is_authenticated
        assert auth_service.has_drive_access
        mock_http.set_session.assert_called_once_with(
            uid="uid123",
            access_token="access_token",
            refresh_token="refresh_token",
        )
        mock_key_manager.unlock_user_key.assert_called_once()


@pytest.mark.asyncio
async def test_authenticate_with_2fa_required_does_not_unlock_keys(
    auth_service: AuthService,
    mock_http: Mock,
    mock_key_manager: Mock,
) -> None:
    """Test authentication requiring 2FA does not unlock keys yet."""
    mock_http.set_session = AsyncMock()

    with (
        patch("proton_drive.services.auth_service.get_auth_info") as mock_get_auth_info,
        patch("proton_drive.services.auth_service.authenticate") as mock_auth_endpoint,
        patch.object(auth_service, "_verify_modulus") as mock_verify_modulus,
        patch("proton_drive.services.auth_service.SrpUser") as mock_srp_class,
    ):
        mock_get_auth_info.return_value = {
            "Modulus": "armored",
            "ServerEphemeral": base64.b64encode(b"ephemeral").decode(),
            "Salt": base64.b64encode(b"salt").decode(),
            "Version": 4,
            "SRPSession": "session",
        }
        mock_verify_modulus.return_value = b"modulus"

        mock_srp = Mock()
        mock_srp.get_challenge.return_value = b"challenge"
        mock_srp.process_challenge.return_value = b"proof"
        mock_srp.authenticated.return_value = True
        mock_srp_class.return_value = mock_srp

        mock_auth_endpoint.return_value = {
            "UID": "uid123",
            "AccessToken": "access_token",
            "RefreshToken": "refresh_token",
            "ServerProof": base64.b64encode(b"proof").decode(),
            "Scope": "password",  # Limited scope
        }

        await auth_service.authenticate("user@example.com", "password")

        assert auth_service.requires_2fa
        assert not auth_service.has_drive_access
        mock_key_manager.unlock_user_key.assert_not_called()


@pytest.mark.asyncio
async def test_authenticate_raises_on_missing_server_proof(
    auth_service: AuthService,
    mock_http: Mock,
) -> None:
    """Test authentication fails when server proof is missing."""
    mock_http.set_session = AsyncMock()

    with (
        patch("proton_drive.services.auth_service.get_auth_info") as mock_get_auth_info,
        patch("proton_drive.services.auth_service.authenticate") as mock_auth_endpoint,
        patch.object(auth_service, "_verify_modulus") as mock_verify_modulus,
        patch("proton_drive.services.auth_service.SrpUser") as mock_srp_class,
    ):
        mock_get_auth_info.return_value = {
            "Modulus": "armored",
            "ServerEphemeral": base64.b64encode(b"ephemeral").decode(),
            "Salt": base64.b64encode(b"salt").decode(),
            "Version": 4,
            "SRPSession": "session",
        }
        mock_verify_modulus.return_value = b"modulus"

        mock_srp = Mock()
        mock_srp.get_challenge.return_value = b"challenge"
        mock_srp.process_challenge.return_value = b"proof"
        mock_srp_class.return_value = mock_srp

        mock_auth_endpoint.return_value = {
            "UID": "uid123",
            "AccessToken": "access_token",
        }

        with pytest.raises(InvalidCredentialsError, match="Invalid password"):
            await auth_service.authenticate("user@example.com", "password")

        assert not auth_service.is_authenticated


@pytest.mark.asyncio
async def test_authenticate_clears_state_on_failure(auth_service: AuthService) -> None:
    """Test state is cleared when authentication fails."""
    with patch("proton_drive.services.auth_service.get_auth_info") as mock_get_auth_info:
        mock_get_auth_info.side_effect = Exception("Network error")

        with pytest.raises(AuthenticationError, match="Authentication failed"):
            await auth_service.authenticate("user@example.com", "password")

        assert not auth_service.is_authenticated
        assert auth_service._password is None


@pytest.mark.asyncio
async def test_provide_2fa_successful_unlocks_keys(
    auth_service: AuthService,
    mock_key_manager: Mock,
) -> None:
    """Test successful 2FA completion unlocks keys."""
    auth_service._scopes = frozenset(["password"])
    auth_service._password = Mock()

    with (
        patch("proton_drive.services.auth_service.provide_2fa") as mock_2fa_endpoint,
        patch("proton_drive.services.auth_service.get_user_keys") as mock_get_user_keys,
        patch("proton_drive.services.auth_service.get_key_salts") as mock_get_key_salts,
    ):
        mock_2fa_endpoint.return_value = {
            "Scopes": frozenset([AuthScope.FULL]),
        }

        user_key = Mock()
        user_key.is_primary = True
        user_key.key_id = "key1"
        mock_get_user_keys.return_value = [user_key]

        key_salt = Mock()
        key_salt.key_id = "key1"
        mock_get_key_salts.return_value = [key_salt]

        result = await auth_service.provide_2fa("123456")

        assert AuthScope.FULL in result.scopes
        assert not auth_service.requires_2fa
        mock_key_manager.unlock_user_key.assert_called_once()


@pytest.mark.asyncio
async def test_provide_2fa_raises_when_not_authenticated(auth_service: AuthService) -> None:
    """Test 2FA fails when not authenticated first."""
    with pytest.raises(AuthenticationError, match="Not authenticated"):
        await auth_service.provide_2fa("123456")


@pytest.mark.asyncio
async def test_provide_2fa_raises_when_2fa_not_required(auth_service: AuthService) -> None:
    """Test 2FA fails when already has full access."""
    auth_service._scopes = frozenset([AuthScope.FULL])

    with pytest.raises(AuthenticationError, match="2FA not required"):
        await auth_service.provide_2fa("123456")


@pytest.mark.asyncio
async def test_provide_2fa_rolls_back_scopes_on_key_unlock_failure(
    auth_service: AuthService,
    mock_key_manager: Mock,
) -> None:
    """Test scopes are rolled back if key unlock fails after 2FA."""
    original_scopes = frozenset(["password"])
    auth_service._scopes = original_scopes
    auth_service._password = Mock()

    # Configure key manager to fail
    mock_key_manager.unlock_user_key.side_effect = Exception("Key unlock failed")

    with (
        patch("proton_drive.services.auth_service.provide_2fa") as mock_2fa_endpoint,
        patch("proton_drive.services.auth_service.get_user_keys") as mock_get_user_keys,
        patch("proton_drive.services.auth_service.get_key_salts") as mock_get_key_salts,
    ):
        mock_2fa_endpoint.return_value = {
            "Scopes": frozenset([AuthScope.FULL]),
        }

        user_key = Mock()
        user_key.is_primary = True
        user_key.key_id = "key1"
        mock_get_user_keys.return_value = [user_key]

        key_salt = Mock()
        key_salt.key_id = "key1"
        mock_get_key_salts.return_value = [key_salt]

        with pytest.raises(AuthenticationError):
            await auth_service.provide_2fa("123456")

        assert auth_service._scopes == original_scopes


@pytest.mark.asyncio
async def test_logout_clears_all_state(
    auth_service: AuthService,
    mock_key_manager: Mock,
) -> None:
    """Test logout clears session and state."""
    auth_service._scopes = frozenset([AuthScope.FULL])
    auth_service._password = Mock()
    auth_service._password.clear = Mock()

    with patch("proton_drive.services.auth_service.logout") as mock_logout_endpoint:
        await auth_service.logout()

        mock_logout_endpoint.assert_called_once()
        mock_key_manager.clear.assert_called_once()
        assert not auth_service.is_authenticated
        assert auth_service._password is None


@pytest.mark.asyncio
async def test_logout_continues_on_api_error(
    auth_service: AuthService,
    mock_key_manager: Mock,
) -> None:
    """Test logout continues clearing state even if API call fails."""
    auth_service._scopes = frozenset([AuthScope.FULL])

    with patch("proton_drive.services.auth_service.logout") as mock_logout_endpoint:
        mock_logout_endpoint.side_effect = Exception("API error")

        await auth_service.logout()

        mock_key_manager.clear.assert_called_once()
        assert not auth_service.is_authenticated


@pytest.mark.asyncio
async def test_unlock_keys_raises_when_no_password_stored(auth_service: AuthService) -> None:
    """Test key unlock fails when no password available."""
    auth_service._password = None

    with pytest.raises(AuthenticationError, match="No credentials available"):
        await auth_service._unlock_keys()


@pytest.mark.asyncio
async def test_unlock_keys_raises_when_no_user_keys_found(auth_service: AuthService) -> None:
    """Test key unlock fails when no user keys exist."""
    auth_service._password = Mock()

    with (
        patch("proton_drive.services.auth_service.get_user_keys") as mock_get_user_keys,
        patch("proton_drive.services.auth_service.get_key_salts") as mock_get_key_salts,
    ):
        mock_get_user_keys.return_value = []
        mock_get_key_salts.return_value = []

        with pytest.raises(AuthenticationError, match="No user keys found"):
            await auth_service._unlock_keys()


@pytest.mark.asyncio
async def test_unlock_keys_raises_when_salt_not_found(auth_service: AuthService) -> None:
    """Test key unlock fails when salt doesn't match key."""
    auth_service._password = Mock()

    with (
        patch("proton_drive.services.auth_service.get_user_keys") as mock_get_user_keys,
        patch("proton_drive.services.auth_service.get_key_salts") as mock_get_key_salts,
    ):
        user_key = Mock()
        user_key.is_primary = True
        user_key.key_id = "key1"
        mock_get_user_keys.return_value = [user_key]

        key_salt = Mock()
        key_salt.key_id = "different_key"
        mock_get_key_salts.return_value = [key_salt]

        with pytest.raises(AuthenticationError, match="No salt found for key"):
            await auth_service._unlock_keys()


@pytest.mark.asyncio
async def test_unlock_keys_uses_first_key_when_no_primary(
    auth_service: AuthService,
    mock_key_manager: Mock,
) -> None:
    """Test key unlock uses first key when no primary key exists."""
    auth_service._password = Mock()

    with (
        patch("proton_drive.services.auth_service.get_user_keys") as mock_get_user_keys,
        patch("proton_drive.services.auth_service.get_key_salts") as mock_get_key_salts,
    ):
        user_key = Mock()
        user_key.is_primary = False
        user_key.key_id = "key1"
        mock_get_user_keys.return_value = [user_key]

        key_salt = Mock()
        key_salt.key_id = "key1"
        mock_get_key_salts.return_value = [key_salt]

        await auth_service._unlock_keys()

        mock_key_manager.unlock_user_key.assert_called_once_with(
            user_key,
            auth_service._password,
            key_salt,
        )


@pytest.mark.asyncio
async def test_verify_modulus_successful(auth_service: AuthService, mock_gpg: Mock) -> None:
    """Test modulus verification succeeds with valid signature."""
    with patch(
        "proton_drive.services.auth_service.SRP_MODULUS_KEY_FINGERPRINT", "test_fingerprint"
    ):
        result = await auth_service._verify_modulus("armored_modulus")
        assert result == b"test_modulus"


@pytest.mark.asyncio
async def test_verify_modulus_raises_on_invalid_signature(
    auth_service: AuthService,
    mock_gpg: Mock,
) -> None:
    """Test modulus verification fails with invalid signature."""
    mock_gpg.decrypt.return_value.valid = False

    with pytest.raises(AuthenticationError, match="Invalid modulus signature"):
        await auth_service._verify_modulus("armored_modulus")


@pytest.mark.asyncio
async def test_verify_modulus_raises_on_fingerprint_mismatch(
    auth_service: AuthService,
    mock_gpg: Mock,
) -> None:
    """Test modulus verification fails with wrong fingerprint."""
    with patch("proton_drive.services.auth_service.SRP_MODULUS_KEY_FINGERPRINT", "expected"):
        mock_gpg.decrypt.return_value.fingerprint = "wrong"

        with pytest.raises(AuthenticationError, match="Invalid modulus fingerprint"):
            await auth_service._verify_modulus("armored_modulus")


def test_cleanup_clears_all_state(auth_service: AuthService, mock_key_manager: Mock) -> None:
    """Test cleanup clears password, scopes, and key manager."""
    auth_service._scopes = frozenset([AuthScope.FULL])
    auth_service._password = Mock()
    auth_service._password.clear = Mock()

    auth_service.cleanup()

    assert auth_service._password is None
    assert auth_service._scopes is None
    mock_key_manager.clear.assert_called_once()
