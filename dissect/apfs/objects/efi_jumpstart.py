from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class EfiJumpstart(Object):
    """APFS EFI Jumpstart object."""

    __type__ = c_apfs.OBJECT_TYPE_EFI_JUMPSTART
    __struct__ = c_apfs.nx_efi_jumpstart
    object: c_apfs.nx_efi_jumpstart
