"""LRU cache and metadata cache utilities."""

from collections import OrderedDict
from typing import Generic, TypeVar

T = TypeVar("T")


class LRUCache(Generic[T]):
    """
    Simple LRU cache implementation.

    Thread-safe for single async context.
    """

    def __init__(self, max_size: int = 1000) -> None:
        """
        Args:
            max_size: Maximum number of items to cache.
        """
        self._max_size = max_size
        self._cache: OrderedDict[str, T] = OrderedDict()

    def get(self, key: str) -> T | None:
        """
        Get item from cache, moving it to end (most recently used).

        Args:
            key: Cache key.

        Returns:
            Cached item or None.
        """
        if key not in self._cache:
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key)
        return self._cache[key]

    def put(self, key: str, value: T) -> None:
        """
        Put item in cache.

        Args:
            key: Cache key.
            value: Value to cache.
        """
        if key in self._cache:
            self._cache.move_to_end(key)
        else:
            if len(self._cache) >= self._max_size:
                # Remove oldest item
                self._cache.popitem(last=False)

        self._cache[key] = value

    def remove(self, key: str) -> T | None:
        """
        Remove item from cache.

        Args:
            key: Cache key.

        Returns:
            Removed item or None.
        """
        return self._cache.pop(key, None)

    def clear(self) -> None:
        """Clear all items from cache."""
        self._cache.clear()

    def __len__(self) -> int:
        """Return number of items in cache."""
        return len(self._cache)

    def __contains__(self, key: str) -> bool:
        """Check if key is in cache."""
        return key in self._cache

    def keys(self) -> list[str]:
        """Return list of all cache keys."""
        return list(self._cache.keys())


class MetadataCache:
    """
    Cache for drive metadata (links, shares).

    Stores API responses to reduce repeated requests.
    """

    def __init__(self, max_size: int = 1000) -> None:
        """
        Initialize metadata cache.

        Args:
            max_size: Maximum number of items to cache.
        """
        self._links: LRUCache[dict] = LRUCache(max_size)
        self._children: LRUCache[list] = LRUCache(max_size // 10)

    def get_link(self, link_id: str) -> dict | None:
        """Get cached link data."""
        return self._links.get(link_id)

    def put_link(self, link_id: str, data: dict) -> None:
        """Cache link data."""
        self._links.put(link_id, data)

    def get_children(self, link_id: str) -> list | None:
        """Get cached folder children."""
        return self._children.get(link_id)

    def put_children(self, link_id: str, children: list) -> None:
        """Cache folder children."""
        self._children.put(link_id, children)

    def clear(self) -> None:
        """Clear all cached metadata."""
        self._links.clear()
        self._children.clear()
