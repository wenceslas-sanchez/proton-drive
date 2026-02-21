"""Drive-related API endpoints (volumes, shares, links, files)."""

from datetime import datetime, timezone

from proton_drive.api.http_client import AsyncHttpClient
from proton_drive.models.drive import (
    FileBlock,
    FileRevision,
    Link,
    LinkState,
    NodeType,
    Share,
    Volume,
)


async def get_volumes(http: AsyncHttpClient) -> list[Volume]:
    """Get all drive volumes."""
    response = await http.request("GET", "/drive/volumes")
    volumes = response.get("Volumes", [])

    return [
        Volume(
            volume_id=v["VolumeID"],
            share_id=v.get("Share", {}).get("ShareID", v.get("ShareID", "")),
            state=v["State"],
            created_at=_parse_timestamp(v.get("CreateTime")),
        )
        for v in volumes
    ]


async def get_share(http: AsyncHttpClient, share_id: str) -> Share:
    """Get share details."""
    response = await http.request("GET", f"/drive/shares/{share_id}")

    return Share(
        share_id=response["ShareID"],
        volume_id=response["VolumeID"],
        link_id=response["LinkID"],
        address_id=response["AddressID"],
        address_key_id=response["AddressKeyID"],
        armored_key=response["Key"],
        encrypted_passphrase=response["Passphrase"],
        state=response["State"],
    )


async def get_link(http: AsyncHttpClient, share_id: str, link_id: str) -> Link:
    """Get link (file/folder) details."""
    response = await http.request("GET", f"/drive/shares/{share_id}/links/{link_id}")
    link_data = response.get("Link", response)

    file_props = link_data.get("FileProperties") or {}

    return Link(
        link_id=link_data["LinkID"],
        parent_link_id=link_data.get("ParentLinkID"),
        share_id=share_id,
        node_type=NodeType(link_data["Type"]),
        encrypted_name=link_data["Name"],
        armored_node_key=link_data.get("NodeKey"),
        encrypted_node_passphrase=link_data.get("NodePassphrase"),
        size=link_data.get("Size", 0),
        mime_type=link_data.get("MIMEType", ""),
        state=LinkState(link_data["State"]),
        created_at=_parse_timestamp(link_data.get("CreateTime")),
        modified_at=_parse_timestamp(link_data.get("ModifyTime")),
        content_key_packet=file_props.get("ContentKeyPacket"),
        active_revision_id=(file_props.get("ActiveRevision") or {}).get("ID"),
    )


async def list_folder_children(
    http: AsyncHttpClient, share_id: str, link_id: str, *, page_size: int = 150
) -> list[Link]:
    """
    List children of a folder with pagination.

    Args:
        http: Configured async HTTP client.
        share_id: Share ID.
        link_id: Folder link ID.
        page_size: Number of items per page.

    Returns:
        List of child links.
    """
    all_links = []
    page = 0

    while True:
        response = await http.request(
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
                node_type=NodeType(link_data["Type"]),
                encrypted_name=link_data["Name"],
                armored_node_key=link_data.get("NodeKey"),
                encrypted_node_passphrase=link_data.get("NodePassphrase"),
                size=link_data.get("Size", 0),
                mime_type=link_data.get("MIMEType", ""),
                state=LinkState(link_data["State"]),
                created_at=_parse_timestamp(link_data["CreateTime"]),
                modified_at=_parse_timestamp(link_data["ModifyTime"]),
                content_key_packet=file_props.get("ContentKeyPacket"),
                active_revision_id=(file_props.get("ActiveRevision") or {}).get("ID"),
            )
            all_links.append(link)

        if len(links_data) < page_size:
            break
        page += 1

    return all_links


async def get_file_revisions(
    http: AsyncHttpClient, share_id: str, link_id: str
) -> list[FileRevision]:
    """Get revisions for a file."""
    response = await http.request("GET", f"/drive/shares/{share_id}/files/{link_id}/revisions")
    revisions = response.get("Revisions", [])

    return [
        FileRevision(
            revision_id=r["ID"],
            size=r.get("Size", 0),
            state=r["State"],
            created_at=_parse_timestamp(r.get("CreateTime")),
            manifest_signature=r.get("ManifestSignature"),
        )
        for r in revisions
    ]


async def get_revision_blocks(
    http: AsyncHttpClient, share_id: str, link_id: str, revision_id: str
) -> list[FileBlock]:
    """Get blocks for a file revision."""
    response = await http.request(
        "GET",
        f"/drive/shares/{share_id}/files/{link_id}/revisions/{revision_id}",
    )
    revision_data = response.get("Revision", response)
    blocks = revision_data.get("Blocks", [])

    return [
        FileBlock(
            index=b["Index"],
            url=b["URL"],
            encrypted_hash=b["Hash"],
            size=b.get("Size"),
        )
        for b in blocks
    ]


async def download_block(http: AsyncHttpClient, url: str) -> bytes:
    """Download an encrypted file block."""
    return await http.request_raw("GET", url)


def _parse_timestamp(timestamp: int | None) -> datetime | None:
    """Parse Unix timestamp to UTC datetime."""
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)
