"""Secure memory handling for sensitive data (passphrases, keys)."""

import ctypes
import ctypes.util
import hmac
import platform
import warnings
from collections.abc import Callable, Iterator
from typing import Self

_PLATFORM = platform.system()
_mlock_func: Callable[[int, int], bool] | None = None
_munlock_func: Callable[[int, int], bool] | None = None


def _mlock_func_win(addr: int, size: int) -> bool:
    return bool(_VirtualLock(addr, size))


def _mlock_func_unix(addr: int, size: int) -> bool:
    return _libc.mlock(addr, size) == 0


def _munlock_func_win(addr: int, size: int) -> bool:
    return bool(_VirtualUnlock(addr, size))


def _munlock_func_unix(addr: int, size: int) -> bool:
    return _libc.munlock(addr, size) == 0


if _PLATFORM == "Windows":
    try:
        _kernel32 = ctypes.windll.kernel32
        _VirtualLock = _kernel32.VirtualLock
        _VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _VirtualLock.restype = ctypes.c_bool
        _VirtualUnlock = _kernel32.VirtualUnlock
        _VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _VirtualUnlock.restype = ctypes.c_bool
        _mlock_func = _mlock_func_win
        _munlock_func = _munlock_func_win
    except (OSError, AttributeError):
        pass

elif _PLATFORM in ("Linux", "Darwin"):
    try:
        _libc_path = ctypes.util.find_library("c") or (
            "libc.so.6" if _PLATFORM == "Linux" else "libc.dylib"
        )
        _libc = ctypes.CDLL(_libc_path, use_errno=True)
        _libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _libc.mlock.restype = ctypes.c_int
        _libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _libc.munlock.restype = ctypes.c_int
        _mlock_func = _mlock_func_unix
        _munlock_func = _munlock_func_unix
    except (OSError, AttributeError):
        pass


def _get_buffer_address(data: bytearray) -> int:
    return ctypes.addressof((ctypes.c_char * len(data)).from_buffer(data))


def _secure_zero(data: bytearray) -> None:
    if len(data) == 0:
        return
    try:
        ctypes.memset(_get_buffer_address(data), 0, len(data))
    except Exception as exc:
        warnings.warn(f"ctypes.memset failed, using fallback: {exc}", RuntimeWarning)
        for i in range(len(data)):
            data[i] = 0


def _lock(data: bytearray) -> bool:
    if _mlock_func is None or len(data) == 0:
        return False
    try:
        return _mlock_func(_get_buffer_address(data), len(data))
    except Exception:
        return False


def _unlock(data: bytearray) -> None:
    if _munlock_func is None or len(data) == 0:
        return
    try:
        _munlock_func(_get_buffer_address(data), len(data))
    except Exception:
        pass


class SecureBytes:
    """
    Secure bytes container with memory zeroing and optional memory locking.

    Use as context manager for guaranteed cleanup.
    """

    __slots__ = ("_data", "_cleared", "_locked")

    def __init__(self, data: bytes | bytearray, *, lock: bool = False) -> None:
        self._data = bytearray(data)
        self._cleared = False
        self._locked = lock and _lock(self._data)

    def __del__(self) -> None:
        self.clear()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.clear()

    def clear(self) -> None:
        """Zero memory and unlock. Idempotent."""
        if self._cleared:
            return
        _secure_zero(self._data)
        if self._locked:
            _unlock(self._data)
            self._locked = False
        self._cleared = True

    def __bytes__(self) -> bytes:
        """Warning: creates an insecure copy."""
        self._check_cleared()
        return bytes(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __bool__(self) -> bool:
        return not self._cleared and len(self._data) > 0

    def __repr__(self) -> str:
        if self._cleared:
            return "SecureBytes(<cleared>)"
        lock_info = ", locked" if self._locked else ""
        return f"SecureBytes(<{len(self._data)} bytes{lock_info}>)"

    def __eq__(self, other: object) -> bool:
        """Constant-time comparison."""
        if isinstance(other, SecureBytes):
            if self._cleared or other._cleared:
                return False
            return hmac.compare_digest(self._data, other._data)
        if isinstance(other, (bytes, bytearray)):
            if self._cleared:
                return False
            return hmac.compare_digest(self._data, other)
        return NotImplemented

    def __hash__(self) -> int:
        raise TypeError("SecureBytes is not hashable")

    def __iter__(self) -> Iterator[int]:
        self._check_cleared()
        return iter(self._data)

    @property
    def is_locked(self) -> bool:
        return self._locked

    @property
    def is_cleared(self) -> bool:
        return self._cleared

    def decode(self, encoding: str = "utf-8") -> str:
        """Warning: returned string is not securely managed."""
        self._check_cleared()
        return self._data.decode(encoding)

    def _check_cleared(self) -> None:
        if self._cleared:
            raise RuntimeError("SecureBytes has been cleared")

    @classmethod
    def from_string(cls, s: str, encoding: str = "utf-8", *, lock: bool = False) -> Self:
        """Create from string. Zeros intermediate bytearray."""
        encoded = bytearray(s, encoding)
        try:
            return cls(encoded, lock=lock)
        finally:
            _secure_zero(encoded)
