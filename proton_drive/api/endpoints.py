"""
Proton API endpoint definitions.

Provides typed methods for each API endpoint, handling
request/response transformation.
"""

from datetime import datetime, timezone
from typing import Any

import structlog

from proton_drive.api.http_client import AsyncHttpClient
from proton_drive.models.auth import AddressKey, KeySalt, UserKey
from proton_drive.models.drive import (
    FileBlock,
    FileRevision,
    Link,
    LinkState,
    NodeType,
    Share,
    Volume,
)

logger = structlog.get_logger(__name__)


class ProtonAPIEndpoints:
    """Typed interface for Proton API endpoints."""

    def __init__(self, http_client: AsyncHttpClient) -> None:
        """
        Initialize with HTTP client.

        Args:
            http_client: Configured async HTTP client.
        """
        self._http = http_client

    async def get_auth_info(self, username: str) -> dict[str, Any]:
        """
        Get authentication info for SRP.

        Args:
            username: Proton username/email.

        Returns:
            Auth info including Modulus, ServerEphemeral, Salt, Version, SRPSession.
        """
        response = await self._http.request(
            "POST",
            "/auth/v4/info",
            json={"Username": username},
            authenticated=False,
        )
        return response

    async def authenticate(
        self,
        username: str,
        client_ephemeral: str,
        client_proof: str,
        srp_session: str,
    ) -> dict[str, Any]:
        """
        Complete SRP authentication.

        Args:
            username: Proton username.
            client_ephemeral: Base64-encoded client ephemeral.
            client_proof: Base64-encoded client proof.
            srp_session: SRP session from auth info.

        Returns:
            Auth response with UID, AccessToken, RefreshToken, Scope, ServerProof.
        """
        response = await self._http.request(
            "POST",
            "/auth/v4",
            json={
                "Username": username,
                "ClientEphemeral": client_ephemeral,
                "ClientProof": client_proof,
                "SRPSession": srp_session,
            },
            authenticated=False,
        )
        return response

    async def provide_2fa(self, code: str) -> dict[str, Any]:
        """
        Provide 2FA code.

        Args:
            code: 6-digit 2FA code.

        Returns:
            Response with updated Scopes.
        """
        response = await self._http.request(
            "POST",
            "/auth/v4/2fa",
            json={"TwoFactorCode": code},
        )
        return response

    async def logout(self) -> None:
        """Logout and invalidate tokens."""
        try:
            await self._http.request("DELETE", "/auth")
        except Exception as e:
            logger.warning("Logout request failed", error=str(e))

    async def get_user(self) -> dict[str, Any]:
        """Get user info including keys."""
        response = await self._http.request("GET", "/core/v4/users")
        return response.get("User", {})

    async def get_user_keys(self) -> list[UserKey]:
        """Get user's PGP keys."""
        user = await self.get_user()
        keys = user.get("Keys", [])

        return [
            UserKey(
                key_id=k["ID"],
                armored_key=k["PrivateKey"],
                is_primary=k.get("Primary") == 1,
                fingerprint=k.get("Fingerprint"),
            )
            for k in keys
        ]

    async def get_key_salts(self) -> list[KeySalt]:
        """Get key salts for all keys."""
        response = await self._http.request("GET", "/core/v4/keys/salts")
        salts = response.get("KeySalts", [])

        return [
            KeySalt(key_id=s["ID"], salt=s["KeySalt"])
            for s in salts
            if s.get("KeySalt") is not None
        ]

    async def get_addresses(self) -> list[dict[str, Any]]:
        """Get user addresses."""
        response = await self._http.request("GET", "/core/v4/addresses")
        return response.get("Addresses", [])

    async def get_address_keys(self, address_id: str) -> list[AddressKey]:
        """Get keys for a specific address."""
        addresses = await self.get_addresses()

        for addr in addresses:
            if addr.get("ID") != address_id:
                continue
            keys = addr.get("Keys", [])
            return [
                AddressKey(
                    key_id=k["ID"],
                    address_id=address_id,
                    armored_key=k["PrivateKey"],
                    token=k.get("Token"),
                    is_primary=k.get("Primary") == 1,
                )
                for k in keys
            ]

        return []

    async def get_volumes(self) -> list[Volume]:
        """Get all drive volumes."""
        response = await self._http.request("GET", "/drive/volumes")
        volumes = response.get("Volumes", [])

        return [
            Volume(
                volume_id=v["VolumeID"],
                share_id=v.get("Share", {}).get("ShareID", v.get("ShareID", "")),
                state=v.get("State", 1),
                created_at=_parse_timestamp(v.get("CreateTime")),
            )
            for v in volumes
        ]

    async def get_share(self, share_id: str) -> Share:
        """Get share details."""
        response = await self._http.request("GET", f"/drive/shares/{share_id}")

        return Share(
            share_id=response["ShareID"],
            volume_id=response.get("VolumeID", ""),
            link_id=response["LinkID"],
            address_id=response["AddressID"],
            address_key_id=response["AddressKeyID"],
            armored_key=response["Key"],
            encrypted_passphrase=response["Passphrase"],
            state=response.get("State", LinkState.ACTIVE),
        )

    async def get_link(self, share_id: str, link_id: str) -> Link:
        """Get link (file/folder) details."""
        response = await self._http.request("GET", f"/drive/shares/{share_id}/links/{link_id}")
        link_data = response.get("Link", response)

        file_props = link_data.get("FileProperties") or {}

        return Link(
            link_id=link_data["LinkID"],
            parent_link_id=link_data.get("ParentLinkID"),
            share_id=share_id,
            node_type=NodeType(link_data.get("Type", NodeType.FILE)),
            encrypted_name=link_data.get("Name", ""),
            armored_node_key=link_data.get("NodeKey"),
            encrypted_node_passphrase=link_data.get("NodePassphrase"),
            size=link_data.get("Size", 0),
            mime_type=link_data.get("MIMEType", ""),
            state=LinkState(link_data.get("State", LinkState.ACTIVE)),
            created_at=_parse_timestamp(link_data.get("CreateTime")),
            modified_at=_parse_timestamp(link_data.get("ModifyTime")),
            content_key_packet=file_props.get("ContentKeyPacket"),
            active_revision_id=(file_props.get("ActiveRevision") or {}).get("ID"),
        )

    async def list_folder_children(
        self, share_id: str, link_id: str, *, page_size: int = 150
    ) -> list[Link]:
        """
        List children of a folder with pagination.

        Args:
            share_id: Share ID.
            link_id: Folder link ID.
            page_size: Number of items per page.

        Returns:
            List of child links.
        """
        all_links = []
        page = 0

        while True:
            response = await self._http.request(
                "GET",
                f"/drive/shares/{share_id}/folders/{link_id}/children",
                params={"Page": page, "PageSize": page_size},
            )

            for link_data in (links_data := response.get("Links", [])):
                file_props = link_data.get("FileProperties") or {}

                link = Link(
                    link_id=link_data["LinkID"],
                    parent_link_id=link_data.get("ParentLinkID"),
                    share_id=share_id,
                    node_type=NodeType(link_data.get("Type", NodeType.FILE)),
                    encrypted_name=link_data.get("Name", ""),
                    armored_node_key=link_data.get("NodeKey"),
                    encrypted_node_passphrase=link_data.get("NodePassphrase"),
                    size=link_data.get("Size", 0),
                    mime_type=link_data.get("MIMEType", ""),
                    state=LinkState(link_data.get("State", LinkState.ACTIVE)),
                    created_at=_parse_timestamp(link_data.get("CreateTime")),
                    modified_at=_parse_timestamp(link_data.get("ModifyTime")),
                    content_key_packet=file_props.get("ContentKeyPacket"),
                    active_revision_id=(file_props.get("ActiveRevision") or {}).get("ID"),
                )
                all_links.append(link)

            if len(links_data) < page_size:
                break
            page += 1

        return all_links

    async def get_file_revisions(self, share_id: str, link_id: str) -> list[FileRevision]:
        """Get revisions for a file."""
        response = await self._http.request(
            "GET", f"/drive/shares/{share_id}/files/{link_id}/revisions"
        )
        revisions = response.get("Revisions", [])

        return [
            FileRevision(
                revision_id=r["ID"],
                size=r.get("Size", 0),
                state=r.get("State", 0),
                created_at=_parse_timestamp(r.get("CreateTime")),
                manifest_signature=r.get("ManifestSignature"),
            )
            for r in revisions
        ]

    async def get_revision_blocks(
        self, share_id: str, link_id: str, revision_id: str
    ) -> list[FileBlock]:
        """Get blocks for a file revision."""
        response = await self._http.request(
            "GET",
            f"/drive/shares/{share_id}/files/{link_id}/revisions/{revision_id}",
        )
        revision_data = response.get("Revision", response)
        blocks = revision_data.get("Blocks", [])

        return [
            FileBlock(
                index=b.get("Index", 0),
                url=b["URL"],
                encrypted_hash=b.get("Hash", ""),
                size=b.get("Size", 0),
            )
            for b in blocks
        ]

    async def download_block(self, url: str) -> bytes:
        """Download an encrypted file block."""
        return await self._http.request_raw("GET", url)


def _parse_timestamp(timestamp: int | None) -> datetime | None:
    """Parse Unix timestamp to UTC datetime."""
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)
