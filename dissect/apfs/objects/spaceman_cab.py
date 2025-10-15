from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class SpacemanChunkInfoAddressBlock(Object):
    """APFS Spaceman Chunk Info Address Block object."""

    __type__ = c_apfs.OBJECT_TYPE_SPACEMAN_CAB
    __struct__ = c_apfs.cib_addr_block
    object: c_apfs.cib_addr_block
