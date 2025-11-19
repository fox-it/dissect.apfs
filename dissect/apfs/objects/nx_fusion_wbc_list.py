from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class NxFusionWbcList(Object):
    """APFS Fusion Write-Back Cache List object."""

    __type__ = c_apfs.OBJECT_TYPE_NX_FUSION_WBC_LIST
    __struct__ = c_apfs.fusion_wbc_list_phys
    object: c_apfs.fusion_wbc_list_phys
