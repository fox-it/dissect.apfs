from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class IntegrityMeta(Object):
    """APFS Integrity Meta object."""

    __type__ = c_apfs.OBJECT_TYPE_INTEGRITY_META
    __struct__ = c_apfs.integrity_meta_phys
    object: c_apfs.integrity_meta_phys
