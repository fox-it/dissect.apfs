from __future__ import annotations

from functools import cached_property

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class BTreeNode(Object):
    """APFS B-tree Node object."""

    __type__ = c_apfs.OBJECT_TYPE_BTREE_NODE
    __struct__ = c_apfs.btree_node_phys
    object: c_apfs.btree_node_phys

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._data_offset = len(self.__struct__)
        self._key_offset = self._data_offset + self.object.btn_table_space.off + self.object.btn_table_space.len

    def __repr__(self) -> str:
        return f"<BTreeNode flags={self.flags} nkeys={self.object.btn_nkeys}>"

    @cached_property
    def toc(self) -> list[c_apfs.kvoff | c_apfs.kvloc]:
        """The B-tree node's table of contents."""
        nkeys = self.object.btn_nkeys
        buf = self.block[self._data_offset + self.object.btn_table_space.off :]

        if self._has_fixed_kv_size:
            return c_apfs.kvoff[nkeys](buf)

        return c_apfs.kvloc[nkeys](buf)

    @cached_property
    def flags(self) -> c_apfs.BTNODE:
        """The B-tree node's flags."""
        return c_apfs.BTNODE(self.object.btn_flags)

    @cached_property
    def is_root(self) -> bool:
        """Whether the node is the root node."""
        return bool(self.object.btn_flags & c_apfs.BTNODE_ROOT)

    @cached_property
    def is_leaf(self) -> bool:
        """Whether the node is a leaf node."""
        return bool(self.object.btn_flags & c_apfs.BTNODE_LEAF)

    @cached_property
    def is_nonleaf(self) -> bool:
        """Whether the node is a non-leaf node."""
        return not self.is_leaf

    @cached_property
    def _has_fixed_kv_size(self) -> bool:
        """Whether the B-tree node has fixed key/value sizes."""
        return bool(self.object.btn_flags & c_apfs.BTNODE_FIXED_KV_SIZE)

    @cached_property
    def level(self) -> int:
        """The B-tree node's level."""
        return self.object.btn_level

    @cached_property
    def nkeys(self) -> int:
        """The number of keys in the B-tree node."""
        return self.object.btn_nkeys
