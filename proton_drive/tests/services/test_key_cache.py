import asyncio
from unittest.mock import Mock

import pytest

from proton_drive.crypto.secure_bytes import SecureBytes
from proton_drive.services.key_cache import KeyCache, LRUCache, MetadataCache


def test_lru_cache_put_and_get() -> None:
    """Test basic put and get operations."""
    cache = LRUCache[str](max_size=3)

    cache.put("key1", "value1")
    cache.put("key2", "value2")

    assert cache.get("key1") == "value1"
    assert cache.get("key2") == "value2"
    assert cache.get("key3") is None


def test_lru_cache_evicts_least_recently_used() -> None:
    """Test LRU eviction when cache is full."""
    cache = LRUCache[str](max_size=3)

    cache.put("key1", "value1")
    cache.put("key2", "value2")
    cache.put("key3", "value3")
    cache.put("key4", "value4")  # Should evict key1

    assert cache.get("key1") is None  # Evicted
    assert cache.get("key2") == "value2"
    assert cache.get("key3") == "value3"
    assert cache.get("key4") == "value4"


def test_lru_cache_get_moves_to_end() -> None:
    """Test that get() makes item most recently used."""
    cache = LRUCache[str](max_size=3)

    cache.put("key1", "value1")
    cache.put("key2", "value2")
    cache.put("key3", "value3")

    cache.get("key1")  # Make key1 recently used
    cache.put("key4", "value4")  # Should evict key2

    assert cache.get("key1") == "value1"  # Still there
    assert cache.get("key2") is None  # Evicted
    assert cache.get("key3") == "value3"
    assert cache.get("key4") == "value4"


def test_lru_cache_clear() -> None:
    """Test clearing all items."""
    cache = LRUCache[str](max_size=3)

    cache.put("key1", "value1")
    cache.put("key2", "value2")
    cache.clear()

    assert len(cache) == 0
    assert cache.get("key1") is None


@pytest.mark.asyncio
async def test_lru_cache_concurrent_writes_final_state() -> None:
    """Test concurrent writes result in consistent final cache state."""
    cache = LRUCache[int](max_size=50)

    async def writer(task_id: int) -> None:
        for i in range(30):
            key = f"task{task_id}_key{i}"
            cache.put(key, task_id * 1000 + i)
            await asyncio.sleep(0)

    # 5 tasks × 30 items = 150 items, but cache max is 50
    await asyncio.gather(*[writer(i) for i in range(5)])

    # Verify final state
    assert len(cache) == 50
    for key in cache.keys():
        value = cache.get(key)
        assert value is not None


@pytest.mark.asyncio
async def test_lru_cache_concurrent_read_write_preserves_values() -> None:
    """Test concurrent reads don't corrupt values being written."""
    cache = LRUCache[str](max_size=20)
    for i in range(20):
        cache.put(f"key{i}", f"value{i}")

    async def reader() -> None:
        for _ in range(50):
            for i in range(20):
                cache.get(f"key{i}")
                await asyncio.sleep(0)

    async def updater() -> None:
        for _ in range(50):
            for i in range(20):
                cache.put(f"key{i}", f"value{i}")  # Same value
                await asyncio.sleep(0)

    await asyncio.gather(reader(), reader(), updater(), updater())

    # Verify final state: all values preserved
    assert len(cache) == 20
    for i in range(20):
        assert cache.get(f"key{i}") == f"value{i}"


@pytest.mark.asyncio
async def test_lru_cache_concurrent_eviction_maintains_max_size() -> None:
    """Test concurrent operations triggering evictions maintain max size."""
    cache = LRUCache[int](max_size=10)

    async def writer(start: int) -> None:
        for i in range(50):
            cache.put(f"key{start + i}", start + i)
            await asyncio.sleep(0)

    await asyncio.gather(writer(0), writer(100), writer(200))

    assert len(cache) == 10  # Never exceeded max size
    keys = cache.keys()
    assert len(keys) == 10
    for key in keys:
        value = cache.get(key)
        assert value is not None


def test_key_cache_put_and_get() -> None:
    """Test basic key cache operations."""
    cache = KeyCache(max_size=10)

    mock_key = Mock()
    passphrase = SecureBytes(b"test_passphrase")

    cache.put("link_123", mock_key, passphrase)

    result = cache.get("link_123")
    assert result is not None
    key, retrieved_passphrase = result
    assert key is mock_key
    assert retrieved_passphrase is passphrase


def test_key_cache_clear_securely_wipes_passphrases() -> None:
    """Test clear() securely wipes all passphrases."""
    cache = KeyCache(max_size=10)

    mock_key = Mock()
    passphrase = Mock(spec=SecureBytes)
    passphrase.clear = Mock()

    cache.put("link_1", mock_key, passphrase)
    cache.clear()

    passphrase.clear.assert_called_once()
    assert len(cache) == 0


def test_metadata_cache_link_operations() -> None:
    """Test link cache operations."""
    cache = MetadataCache(max_size=100)

    link_data = {"id": "link_123", "name": "file.txt"}
    cache.put_link("link_123", link_data)

    assert cache.get_link("link_123") == link_data
    assert cache.get_link("nonexistent") is None


def test_metadata_cache_children_operations() -> None:
    """Test folder children cache operations."""
    cache = MetadataCache(max_size=100)

    children = [{"id": "child_1"}, {"id": "child_2"}]
    cache.put_children("folder_123", children)

    assert cache.get_children("folder_123") == children
    assert cache.get_children("nonexistent") is None


def test_metadata_cache_clear() -> None:
    """Test clearing metadata cache."""
    cache = MetadataCache(max_size=100)

    cache.put_link("link_1", {"id": "link_1"})
    cache.put_children("folder_1", [{"id": "child_1"}])
    cache.clear()

    assert cache.get_link("link_1") is None
    assert cache.get_children("folder_1") is None
