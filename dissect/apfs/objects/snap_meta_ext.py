from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class SnapMetaExt(Object):
    """APFS Snapshot Metadata Extension object."""

    __type__ = c_apfs.OBJECT_TYPE_SNAP_META_EXT
    __struct__ = c_apfs.snap_meta_ext_obj_phys
    object: c_apfs.snap_meta_ext_obj_phys
