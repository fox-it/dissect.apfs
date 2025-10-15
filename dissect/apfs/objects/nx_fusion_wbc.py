from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class NxFusionWbc(Object):
    """APFS Fusion Write-Back Cache object."""

    __type__ = c_apfs.OBJECT_TYPE_NX_FUSION_WBC
    __struct__ = c_apfs.fusion_wbc_phys
    object: c_apfs.fusion_wbc_phys
