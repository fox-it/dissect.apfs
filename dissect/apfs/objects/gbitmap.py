from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class GBitmap(Object):
    """APFS General Bitmap object."""

    __type__ = c_apfs.OBJECT_TYPE_GBITMAP
    __struct__ = c_apfs.gbitmap_phys
    object: c_apfs.gbitmap_phys
