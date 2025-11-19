from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING
from uuid import UUID

from dissect.fve.crypto import create_cipher

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.cursor import Cursor
from dissect.apfs.exception import Error
from dissect.apfs.objects.base import Object
from dissect.apfs.objects.btree import BTree
from dissect.apfs.objects.fs import FS
from dissect.apfs.objects.keybag import ContainerKeybag
from dissect.apfs.objects.omap import ObjectMap

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.apfs.apfs import APFS
    from dissect.apfs.objects.checkpoint_map import CheckpointMap


class NxSuperblock(Object):
    """APFS NX Superblock object."""

    __type__ = c_apfs.OBJECT_TYPE_NX_SUPERBLOCK
    __struct__ = c_apfs.nx_superblock
    object: c_apfs.nx_superblock

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.object.nx_magic.to_bytes(4, "big") != c_apfs.NX_MAGIC:
            raise Error(
                "Invalid nx_superblock magic "
                f"(expected {c_apfs.NX_MAGIC!r}, got {self.object.nx_magic.to_bytes(4, 'big')!r})"
            )

    @cached_property
    def block_size(self) -> int:
        """The block size of the container."""
        return self.object.nx_block_size

    @cached_property
    def block_count(self) -> int:
        """The total number of blocks in the container."""
        return self.object.nx_block_count

    @cached_property
    def features(self) -> c_apfs.NX_FEATURE:
        """The features supported by this container."""
        return c_apfs.NX_FEATURE(self.object.nx_features)

    @cached_property
    def incompatible_features(self) -> c_apfs.NX_INCOMPAT:
        """The incompatible features supported by this container."""
        return c_apfs.NX_INCOMPAT(self.object.nx_incompatible_features)

    @cached_property
    def uuid(self) -> UUID:
        """The UUID of the container."""
        return UUID(bytes_le=self.object.nx_uuid)

    @cached_property
    def checkpoint_objects(self) -> list[CheckpointMap | NxSuperblock]:
        """All checkpoint objects in the container."""
        return list(_read_checkpoint_objects(self.container, self.object.nx_xp_desc_base, self.object.nx_xp_desc_len))

    @cached_property
    def ephemeral_objects(self) -> dict[int, Object]:
        """All ephemeral objects in the container."""
        return {
            obj.oid: obj
            for obj in _read_checkpoint_objects(self.container, self.object.nx_xp_data_base, self.object.nx_xp_data_len)
        }

    @cached_property
    def omap(self) -> ObjectMap:
        """The object map of the container."""
        return ObjectMap(self.container, self.object.nx_omap_oid)

    @cached_property
    def filesystems(self) -> list[FS]:
        """All the filesystems in the container."""
        return [FS(self.container, self.omap.lookup(oid, self.xid)) for oid in self.object.nx_fs_oid if oid != 0]

    @cached_property
    def fusion_uuid(self) -> UUID:
        """The Fusion Drive UUID."""
        return UUID(bytes_le=self.object.nx_fusion_uuid)

    @cached_property
    def keylocker(self) -> ContainerKeybag | None:
        """The container keybag, if present."""
        if self.object.nx_keylocker.pr_start_paddr == 0:
            return None

        return ContainerKeybag.from_address(
            self.container,
            self.object.nx_keylocker.pr_start_paddr,
            self.object.nx_keylocker.pr_block_count,
            cipher=create_cipher("aes-xts-128", self.object.nx_uuid * 2),
        )


def _read_checkpoint_objects(container: APFS, base: int, length: int) -> Iterator[Object]:
    """Read checkpoint objects from the container."""
    is_btree = bool(length & 0x80000000)
    num_blocks = length & 0x7FFFFFFF

    if is_btree:
        for _, value in Cursor(BTree(container, base)).walk():
            prange = c_apfs.prange(value)
            yield Object.from_address(container, prange.pr_start_paddr, prange.pr_block_count)
    else:
        for i in range(num_blocks):
            yield Object.from_address(container, base + i)
