from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class GBitmapBlock(Object):
    """APFS General Bitmap Block object."""

    __type__ = c_apfs.OBJECT_TYPE_GBITMAP_BLOCK
    __struct__ = c_apfs.gbitmap_block_phys
    object: c_apfs.gbitmap_block_phys
