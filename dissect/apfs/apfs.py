from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects import NxSuperblock

if TYPE_CHECKING:
    from uuid import UUID

    from dissect.apfs.objects.fs import FS
    from dissect.apfs.objects.keybag import ContainerKeybag


class APFS:
    """Container class for APFS operations.

    Args:
        fh: File-like object to read the APFS container from.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.fh.seek(0)

        self.sb = NxSuperblock.from_block(self, 0, self.fh.read(c_apfs.NX_DEFAULT_BLOCK_SIZE))
        self.sbs = [self.sb] + [obj for obj in self.sb.checkpoint_objects if isinstance(obj, NxSuperblock)]
        self.sb = sorted(self.sbs, key=lambda obj: obj.xid)[-1]

    @property
    def block_size(self) -> int:
        """The block size of the container."""
        return self.sb.block_size

    @property
    def sectors_per_block(self) -> int:
        """The number of 512-byte sectors per block."""
        return self.block_size // 512

    @property
    def block_count(self) -> int:
        """The total number of blocks in the container."""
        return self.sb.block_count

    @property
    def uuid(self) -> UUID:
        """The UUID of the container."""
        return self.sb.uuid

    @property
    def keybag(self) -> ContainerKeybag | None:
        """The container keybag, if present."""
        return self.sb.keylocker

    @property
    def volumes(self) -> list[FS]:
        """All the filesystems in the container."""
        return self.sb.filesystems

    def _read_block(self, address: int, count: int = 1) -> bytes:
        """Read a block from the container.

        Args:
            address: The block address to read.
        """
        # TODO: Fusion tier2
        self.fh.seek(address * self.block_size)
        return self.fh.read(count * self.block_size)
