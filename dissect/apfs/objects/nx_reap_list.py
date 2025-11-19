from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class NxReapList(Object):
    """APFS NX Reap List object."""

    __type__ = c_apfs.OBJECT_TYPE_NX_REAP_LIST
    __struct__ = c_apfs.nx_reap_list_phys
    object: c_apfs.nx_reap_list_phys
