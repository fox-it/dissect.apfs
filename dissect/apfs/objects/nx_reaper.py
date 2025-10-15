from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class NxReaper(Object):
    """APFS NX Reaper object."""

    __type__ = c_apfs.OBJECT_TYPE_NX_REAPER
    __struct__ = c_apfs.nx_reaper_phys
    object: c_apfs.nx_reaper_phys
