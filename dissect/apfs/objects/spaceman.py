from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class Spaceman(Object):
    """APFS Spaceman object."""

    __type__ = c_apfs.OBJECT_TYPE_SPACEMAN
    __struct__ = c_apfs.spaceman_phys
    object: c_apfs.spaceman_phys
