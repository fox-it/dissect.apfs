from __future__ import annotations

from functools import cached_property, lru_cache

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object
from dissect.apfs.objects.btree import BTree
from dissect.apfs.util import cmp_omap


class ObjectMap(Object):
    """APFS Object Map (OMAP) object."""

    __type__ = c_apfs.OBJECT_TYPE_OMAP
    __struct__ = c_apfs.omap_phys
    object: c_apfs.omap_phys

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.lookup = lru_cache(128)(self.lookup)

    @cached_property
    def btree(self) -> BTree:
        """The B-tree of the object map."""
        return BTree(self.container, self.object.om_tree_oid)

    def lookup(self, oid: int, xid: int | None = None) -> int:
        """Lookup the physical address of an object by its OID and optional transaction ID.

        Args:
            oid: The object ID to look up.
            xid: Optional transaction ID to look up. If not provided, the first version is returned.
        """
        value = self.btree.search((oid, xid or 0), cmp=cmp_omap)

        omap_val = c_apfs.omap_val(value)
        return omap_val.ov_paddr
