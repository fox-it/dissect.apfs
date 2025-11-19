from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class SpacemanChunkInfoBlock(Object):
    """APFS Spaceman Chunk Info Block object."""

    __type__ = c_apfs.OBJECT_TYPE_SPACEMAN_CIB
    __struct__ = c_apfs.chunk_info_block
    object: c_apfs.chunk_info_block
