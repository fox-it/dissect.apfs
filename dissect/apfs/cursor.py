from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from dissect.apfs.objects.btree import cmp_default

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from typing_extensions import Self

    from dissect.apfs.objects import BTree, BTreeNode, ObjectMap


class Cursor:
    """Cursor for traversing B-Trees.

    Args:
        btree: B-Tree to traverse.
        omap: Optional object map to resolve child pointers.
        oid: Optional base object ID to resolve child pointers.
        xid: Optional transaction ID to resolve child pointers.
    """

    def __init__(self, btree: BTree, omap: ObjectMap | None = None, oid: int = 0, xid: int | None = None) -> None:
        self.btree = btree
        self.omap = omap
        self.oid = oid
        self.xid = xid

        self._node = btree.root
        self._idx = 0

        self._stack = []

    @property
    def state(self) -> tuple[BTreeNode, int, list[tuple[BTreeNode, int]]]:
        """Get the current cursor state."""
        return self._node, self._idx, self._stack[:]

    @state.setter
    def state(self, value: tuple[BTreeNode, int, list[tuple[BTreeNode, int]]]) -> None:
        """Set the current cursor state."""
        self._node, self._idx, self._stack = value[0], value[1], value[2][:]

    def reset(self) -> Self:
        """Reset the cursor to the root of the B-Tree."""
        self._node = self.btree.root
        self._idx = 0
        self._stack = []

        return self

    def key(self) -> bytes:
        """Get the current key."""
        return self.btree._read_key(self._node, self._idx)

    def value(self) -> bytes:
        """Get the current value."""
        return self.btree._read_value(self._node, self._idx)

    def item(self) -> tuple[bytes, bytes]:
        """Get the current key and value."""
        return self.key(), self.value()

    def first(self) -> bool:
        """Move the cursor to the first item in the B-Tree."""
        self.reset()
        while self._node.is_nonleaf:
            self.push()

        return self._node.nkeys != 0

    def last(self) -> bool:
        """Move the cursor to the last item in the B-Tree."""
        self.reset()
        while self._node.is_nonleaf:
            self._idx = self._node.nkeys - 1
            self.push()

        self._idx = self._node.nkeys - 1
        return self._node.nkeys != 0

    def next(self) -> bool:
        """Move the cursor to the next item in the B-Tree."""
        if self._node.is_nonleaf:
            # Treat as if we were at the first key
            self.first()
            return self._node.nkeys != 0

        if self._idx + 1 < self._node.nkeys:
            self._idx += 1
        elif self._stack:
            # End of current node, traverse to the next leaf node

            # First pop until we find a node with unvisited keys
            while self._idx + 1 >= self._node.nkeys:
                if not self._stack:
                    return False
                self.pop()

            self._idx += 1

            # Then push down to the next leaf
            while self._node.is_nonleaf:
                self.push()
        else:
            return False

        return True

    def prev(self) -> bool:
        """Move the cursor to the previous item in the B-Tree."""
        if self._node.is_nonleaf:
            # Treat as if we were at the last key
            self.last()
            return self._node.nkeys != 0

        if self._idx - 1 >= 0:
            self._idx -= 1
        elif self._stack:
            # Start of current node, traverse to the previous leaf node

            # First pop until we find a node with unvisited keys
            while self._idx - 1 < 0:
                if not self._stack:
                    # Start of B-Tree reached
                    return False
                self.pop()

            self._idx -= 1

            # Then push down to the rightmost leaf
            while self._node.is_nonleaf:
                self._idx = self._node.nkeys - 1
                self.push()
        else:
            # Start of B-Tree reached
            return False

        return True

    def push(self) -> Self:
        """Push down to the child node at the current index."""
        child_node = self.btree._node_child(self._node, self._idx, self.omap, self.oid, self.xid)

        self._stack.append((self._node, self._idx))
        self._node = child_node
        self._idx = 0

        return self

    def pop(self) -> Self:
        """Pop back to the parent node."""
        if not self._stack:
            raise IndexError("Cannot pop from an empty stack")

        self._node, self._idx = self._stack.pop()

        return self

    def walk(self) -> Iterator[tuple[bytes, bytes]]:
        """Walk the B-Tree in order, yielding (key, value) tuples."""
        if self.first():
            yield self.item()

            while self.next():
                yield self.item()

    def search(
        self,
        key: Any,
        *,
        exact: bool = False,
        cmp: Callable[[Any, bytes], Literal[-1, 0, 1]] = cmp_default,
    ) -> Self:
        """Search for a key in the B-Tree.

        Args:
            key: Key to search for.
            exact: If ``True``, only return if an exact match is found.
            cmp: Comparison function to use. Should return -1, 0, or 1.
        """
        while self._node.is_nonleaf:
            self._idx = self.btree._node_search(self._node, key, cmp=cmp)
            self.push()

        self._idx = self.btree._node_search(self._node, key, exact=exact, cmp=cmp)
        if self._idx >= self._node.nkeys or self._idx == -1:
            raise KeyError(f"Key not found: {key!r}")

        return self
