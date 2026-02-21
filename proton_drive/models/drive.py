"""
Drive-related domain models.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import Self


class NodeType(IntEnum):
    """Type of drive node."""

    FOLDER = 1
    FILE = 2


class LinkState(IntEnum):
    """State of a drive link."""

    DRAFT = 0
    ACTIVE = 1
    TRASHED = 2


class RevisionState(IntEnum):
    """State of a file revision."""

    DRAFT = 0
    ACTIVE = 1
    OBSOLETE = 2


@dataclass(frozen=True, kw_only=True)
class Volume:
    """
    Represents a Proton Drive volume.

    A volume is the top-level container (like a drive).
    Each user typically has one main volume.
    """

    volume_id: str
    share_id: str
    state: int
    created_at: datetime | None = None


@dataclass(frozen=True, kw_only=True)
class Share:
    """
    Represents a share within a volume.

    Contains the root link and encryption keys for the share.
    """

    share_id: str
    volume_id: str
    link_id: str  # Root folder link ID
    address_id: str
    address_key_id: str
    armored_key: str
    encrypted_passphrase: str
    state: int = LinkState.ACTIVE


@dataclass(frozen=True, kw_only=True)
class Link:
    """
    Represents a file or folder link in the drive.

    This is the raw API representation before decryption.
    """

    link_id: str
    parent_link_id: str | None
    share_id: str
    node_type: NodeType
    encrypted_name: str
    armored_node_key: str | None = None
    encrypted_node_passphrase: str | None = None
    size: int = 0
    mime_type: str = ""
    state: LinkState = LinkState.ACTIVE
    created_at: datetime | None = None
    modified_at: datetime | None = None

    # File-specific properties
    content_key_packet: str | None = None  # Base64-encoded, for files only
    active_revision_id: str | None = None

    @property
    def is_folder(self) -> bool:
        """Check if this link is a folder."""
        return self.node_type == NodeType.FOLDER

    @property
    def is_file(self) -> bool:
        """Check if this link is a file."""
        return self.node_type == NodeType.FILE


@dataclass(frozen=True, kw_only=True)
class DriveNode:
    """
    Represents a decrypted file or folder in the drive.

    This is the user-facing model with decrypted names and a tree structure.
    """

    link_id: str
    parent_link_id: str | None
    name: str  # Decrypted name
    node_type: NodeType
    size: int = 0
    mime_type: str = ""
    created_at: datetime | None = None
    modified_at: datetime | None = None
    children: tuple["DriveNode", ...] = ()

    @property
    def is_folder(self) -> bool:
        """Check if this node is a folder."""
        return self.node_type == NodeType.FOLDER

    @property
    def is_file(self) -> bool:
        """Check if this node is a file."""
        return self.node_type == NodeType.FILE

    def get_child(self, name: str) -> Self | None:
        """Get a child node by name."""
        for child in self.children:
            if child.name == name:
                return child
        return None

    def count_descendants(self) -> int:
        """
        Count total number of descendant nodes.

        Returns:
            Total count of children, grandchildren, etc.
        """
        count = len(self.children)
        for child in self.children:
            count += child.count_descendants()
        return count

    def walk(self) -> "DriveNodeIterator":
        """
        Iterate over this node and all descendants.

        Yields:
            Tuple of (node, depth) for each node in the tree.
        """
        return DriveNodeIterator(self)

    def find(self, path: str) -> Self | None:
        """
        Find a node by path.

        Args:
            path: POSIX-style path (e.g., "/folder/file.txt")

        Returns:
            The node at the path, or None if not found.
        """
        parts = [p for p in path.strip("/").split("/") if p]
        current = self

        for part in parts:
            if current is None or not current.is_folder:
                return None
            current = current.get_child(part)

        return current

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        result = {
            "name": self.name,
            "type": "folder" if self.is_folder else "file",
            "link_id": self.link_id,
        }
        if self.is_file:
            result["size"] = self.size
            result["mime_type"] = self.mime_type
        if self.children:
            result["children"] = [child.to_dict() for child in self.children]
        return result

    def format_tree(self, indent: int = 0) -> str:
        """
        Format as a tree string.

        Args:
            indent: Current indentation level.

        Returns:
            Multi-line string representation of the tree.
        """
        prefix = "  " * indent
        icon = "[D]" if self.is_folder else "[F]"
        size_str = f" ({_format_size(self.size)})" if self.is_file else ""

        lines = [f"{prefix}{icon} {self.name}{size_str}"]

        # Sort: folders first, then alphabetically
        sorted_children = sorted(self.children, key=lambda x: (x.is_file, x.name.lower()))
        for child in sorted_children:
            lines.append(child.format_tree(indent + 1))

        return "\n".join(lines)


class DriveNodeIterator:
    """Iterator for walking a DriveNode tree."""

    def __init__(self, root: DriveNode) -> None:
        self._stack: list[tuple[DriveNode, int]] = [(root, 0)]

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> tuple[DriveNode, int]:
        if not self._stack:
            raise StopIteration

        node, depth = self._stack.pop()

        # Add children in reverse order so they're processed in order
        for child in reversed(node.children):
            self._stack.append((child, depth + 1))

        return node, depth


@dataclass(frozen=True, kw_only=True)
class FileRevision:
    """
    Represents a file revision.

    Files can have multiple revisions; the active one is used for downloads.
    """

    revision_id: str
    size: int
    state: int
    created_at: datetime | None = None
    manifest_signature: str | None = None


@dataclass(frozen=True, kw_only=True)
class FileBlock:
    """
    Represents a block of file content.

    Large files are split into blocks for parallel download and encryption.
    """

    index: int
    url: str
    encrypted_hash: str  # SHA-256 hash of encrypted block
    size: int = 0


def _format_size(size_bytes: int) -> str:
    """Format byte size in human-readable form."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
