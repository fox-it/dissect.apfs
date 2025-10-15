from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class SpacemanBitmap(Object):
    """APFS Spaceman Bitmap object."""

    __type__ = c_apfs.OBJECT_TYPE_SPACEMAN_BITMAP
