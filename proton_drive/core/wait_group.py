from functools import total_ordering
from numbers import Number


@total_ordering
class WaitGroup:
    """
    Counter for tracking active operations, based on Go's sync.WaitGroup.

    Allows checking if operations are in progress before closing resources.

    Example:
        ```python
        wg = WaitGroup()

        wg.add()
        assert wg == 1

        wg.done()
        assert wg == 0

        # In close():
        if wg == 0:
            # Safe to close
            ...
        ```
    """

    def __init__(self) -> None:
        self._count = 0

    def add(self, n: int = 1) -> None:
        """
        Increment the counter.

        Args:
            n: Amount to increment (default 1).

        Raises:
            ValueError: If n is not a strictly positive integer.
        """
        if n <= 0:
            msg = "'n' must be a strictly positive integer."
            raise ValueError(msg)
        self._count += n

    def done(self) -> None:
        """Decrement the counter by 1. No-op if already zero."""
        if self._count == 0:
            return
        self._count -= 1

    def __eq__(self, other: Number) -> bool:
        return self._count == other

    def __lt__(self, other: Number) -> bool:
        return self._count < other

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._count})"
