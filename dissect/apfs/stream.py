from __future__ import annotations

import struct
import zlib
from typing import TYPE_CHECKING

from dissect.util.compression import lzbitmap, lzfse, lzvn
from dissect.util.stream import AlignedStream

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.cursor import Cursor
from dissect.apfs.exception import Error
from dissect.apfs.util import cmp_fext, cmp_fs_extent

if TYPE_CHECKING:
    from dissect.apfs.objects.fs import FS, INode


class FileStream(AlignedStream):
    """APFS file data stream.

    Args:
        volume: APFS volume.
        oid: The object ID of the file.
        size: The size of the file in bytes.
    """

    def __init__(self, volume: FS, oid: int, size: int):
        self.volume = volume
        self.oid = oid

        if self.volume.is_sealed:
            self._cursor = Cursor(self.volume.fext_tree)
        else:
            self._cursor = self.volume.cursor()

        super().__init__(size, self.volume.container.block_size)

    def _lookup(self, offset: int) -> tuple[int, int, int, int]:
        if self.volume.is_sealed:
            return self._lookup_sealed(offset)

        return self._lookup_normal(offset)

    def _lookup_normal(self, offset: int) -> tuple[int, int, int, int]:
        self._cursor.reset().search(
            (
                (self.oid, c_apfs.APFS_TYPE.FILE_EXTENT.value),
                offset,
            ),
            cmp=cmp_fs_extent,
        )

        key = c_apfs.j_file_extent_key(self._cursor.key())
        oid = key.hdr.obj_id_and_type & c_apfs.OBJ_ID_MASK
        type = (key.hdr.obj_id_and_type & c_apfs.OBJ_TYPE_MASK) >> c_apfs.OBJ_TYPE_SHIFT

        if oid != self.oid or type != c_apfs.APFS_TYPE.FILE_EXTENT or key.logical_addr > offset:
            raise Error(f"Could not find file extent for {self.oid} at offset {offset}")

        value = c_apfs.j_file_extent_val(self._cursor.value())

        return (
            key.logical_addr,
            value.phys_block_num,
            value.len_and_flags & c_apfs.J_FILE_EXTENT_LEN_MASK,
            value.crypto_id,
        )

    def _lookup_sealed(self, offset: int) -> tuple[int, int, int, int]:
        self._cursor.reset().search((self.oid, offset), cmp=cmp_fext)

        key = c_apfs.fext_tree_key(self._cursor.key())
        if key.private_id != self.oid or key.logical_addr > offset:
            raise Error(f"Could not find file extent for {self.oid} at offset {offset}")

        value = c_apfs.fext_tree_val(self._cursor.value())

        return (
            key.logical_addr,
            value.phys_block_num,
            value.len_and_flags & c_apfs.J_FILE_EXTENT_LEN_MASK,
            0,
        )

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        while length:
            logical_address, physical_address, extent_length, crypto_id = self._lookup(offset)
            block = self.volume.container._read_block(physical_address, extent_length // self.align)

            if self.volume.is_encrypted:
                if not self.volume._cipher:
                    raise Error("Volume is encrypted, unlock it first")

                if self.volume.is_onekey:
                    block = self.volume._cipher.decrypt(block, crypto_id * self.volume.container.sectors_per_block)
                else:
                    raise Error("Multi-key encryption is not supported yet")

            if offset_in_extent := offset - logical_address:
                block = block[offset_in_extent:]

            if length < len(block):
                block = block[:length]

            result.append(block)
            offset += min(extent_length, length)
            length -= min(extent_length, length)

        return b"".join(result)


class DecmpfsStream(AlignedStream):
    """APFS decompressed file data stream.

    Args:
        inode: The inode of the compressed file.
    """

    def __init__(self, inode: INode):
        self.inode = inode

        if (attr := inode.xattr.get("com.apple.decmpfs")) is None:
            raise Error(f"{inode} is marked as compressed, but has no decmpfs xattr")

        buf = attr.open()
        self._header = c_apfs.decmpfs_header(buf)
        if self._header.magic.to_bytes(4, "big") != c_apfs.DECMPFS_MAGIC:
            raise Error(
                "Invalid decmpfs magic "
                f"(expected {c_apfs.DECMPFS_MAGIC!r}, got {self._header.magic.to_bytes(4, 'big')!r})"
            )

        self._fork = None
        self._entries = []

        if self._header.algorithm & 1 == 0:
            # In resource fork
            if (fork := inode.xattr.get("com.apple.ResourceFork")) is None:
                raise Error(f"{inode} is missing resource fork for decmpfs")

            self._fork = fork.open()

            if self._header.algorithm in (c_apfs.DECMPFS_ZLIB_RSRC, c_apfs.DECMPFS_PLAIN_RSRC):
                # data_offset, mgmt_offset, data_size, mgmt_size
                self._fork_data_offset, _, _, _ = struct.unpack(">IIII", self._fork.read(16))

                self._fork.seek(self._fork_data_offset)
                for _ in range(struct.unpack("<II", self._fork.read(8))[1]):
                    offset, length = struct.unpack("<II", self._fork.read(8))
                    self._entries.append((self._fork_data_offset + 4 + offset, length))
            else:
                offsets = c_apfs.uint32_t[
                    ((self._header.uncompressed_size + (c_apfs.DECMPFS_BLOCK_SIZE - 1)) // c_apfs.DECMPFS_BLOCK_SIZE)
                    + 1
                ](self._fork)
                for i in range(len(offsets) - 1):
                    self._entries.append((offsets[i], offsets[i + 1] - offsets[i]))
        else:
            # In attribute
            self._data = buf.read()

        super().__init__(self._header.uncompressed_size, align=c_apfs.DECMPFS_BLOCK_SIZE)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        algorithm = self._header.algorithm
        block = offset // self.align
        while length:
            if self._fork is not None:
                entry_offset, entry_length = self._entries[block]

                self._fork.seek(entry_offset)
                chunk = self._fork.read(entry_length)
            else:
                chunk = self._data

            if algorithm in (c_apfs.DECMPFS_ZLIB_ATTR, c_apfs.DECMPFS_ZLIB_RSRC):
                if chunk[0] == 0x78 and len(chunk) >= 2:
                    chunk = zlib.decompress(chunk)
                elif chunk[0] & 0x0F == 0x0F:
                    chunk = chunk[1:]
                else:
                    raise Error(f"Invalid zlib chunk: {chunk[0]:#x}")
            elif algorithm in (c_apfs.DECMPFS_LZVN_ATTR, c_apfs.DECMPFS_LZVN_RSRC):
                chunk = chunk[1:] if chunk[0] == 0x06 else lzvn.decompress(chunk)
            elif algorithm in (c_apfs.DECMPFS_PLAIN_ATTR, c_apfs.DECMPFS_PLAIN_RSRC):
                chunk = chunk[1:]
            elif algorithm in (c_apfs.DECMPFS_LZFSE_ATTR, c_apfs.DECMPFS_LZFSE_RSRC):
                chunk = chunk[1:] if chunk[0] == 0xFF else lzfse.decompress(chunk)
            elif algorithm in (c_apfs.DECMPFS_LZBITMAP_ATTR, c_apfs.DECMPFS_LZBITMAP_RSRC):
                chunk = chunk[1:] if chunk[0] & 0x0F == 0x0F else lzbitmap.decompress(chunk)
            else:
                raise Error(f"Unsupported decmpfs algorithm {algorithm}")

            result.append(chunk)

            offset += self.align
            length -= min(self.align, length)
            block += 1

        return b"".join(result)
