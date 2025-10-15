from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class CheckpointMap(Object):
    """APFS Checkpoint Map object."""

    __type__ = c_apfs.OBJECT_TYPE_CHECKPOINT_MAP
    __struct__ = c_apfs.checkpoint_map_phys
    object: c_apfs.checkpoint_map_phys
