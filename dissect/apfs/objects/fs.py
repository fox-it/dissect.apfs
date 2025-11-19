from __future__ import annotations

import stat
import unicodedata
from functools import cached_property, lru_cache
from io import BytesIO
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dissect.fve.crypto import create_cipher
from dissect.util.hash.crc32c import crc32c
from dissect.util.stream import BufferedStream
from dissect.util.ts import from_unix, from_unix_ns

from dissect.apfs.c_apfs import FILESYSTEM_OBJECT_TYPE_MAP, XF_MAP, c_apfs
from dissect.apfs.cursor import Cursor
from dissect.apfs.exception import Error, FileNotFoundError, NotADirectoryError, NotASymlinkError
from dissect.apfs.objects.base import Object
from dissect.apfs.objects.btree import BTree
from dissect.apfs.objects.omap import ObjectMap
from dissect.apfs.stream import DecmpfsStream, FileStream
from dissect.apfs.util import cmp_fs, cmp_fs_dir, cmp_fs_dir_hash, parse_fs_object_key

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from dissect.apfs.objects.btree_node import BTreeNode
    from dissect.apfs.objects.keybag import VolumeKeybag


class FS(Object):
    """APFS Filesystem object, also referred to as the "volume"."""

    __type__ = c_apfs.OBJECT_TYPE_FS
    __struct__ = c_apfs.apfs_superblock
    object: c_apfs.apfs_superblock

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.object.apfs_magic.to_bytes(4, "big") != c_apfs.APFS_MAGIC:
            raise Error(
                "Invalid apfs_superblock magic "
                f"(expected {c_apfs.APFS_MAGIC!r}, got {self.object.apfs_magic.to_bytes(4, 'big')!r})"
            )

        self._cipher = None

        self.inode = lru_cache(4096)(self.inode)
        self._cursor_state = lru_cache(128)(self._cursor_state)

        self.root = self.inode(c_apfs.ROOT_DIR_INO_NUM)

    def __repr__(self) -> str:
        return f"<FS name={self.name!r} uuid={self.uuid}>"

    @cached_property
    def index(self) -> int:
        """The volume index within the container."""
        return self.object.apfs_fs_index

    @cached_property
    def features(self) -> c_apfs.APFS_FEATURE:
        """The features supported by this filesystem."""
        return c_apfs.APFS_FEATURE(self.object.apfs_features)

    @cached_property
    def incompatible_features(self) -> c_apfs.APFS_INCOMPAT:
        """The incompatible features supported by this filesystem."""
        return c_apfs.APFS_INCOMPAT(self.object.apfs_incompatible_features)

    @cached_property
    def is_case_insensitive(self) -> bool:
        """Whether the filesystem is case insensitive."""
        return c_apfs.APFS_INCOMPAT.CASE_INSENSITIVE in self.incompatible_features

    @cached_property
    def is_normalization_insensitive(self) -> bool:
        """Whether the filesystem is normalization insensitive."""
        return c_apfs.APFS_INCOMPAT.NORMALIZATION_INSENSITIVE in self.incompatible_features

    @cached_property
    def is_sealed(self) -> bool:
        """Whether the filesystem is sealed (read-only)."""
        return c_apfs.APFS_INCOMPAT.SEALED_VOLUME in self.incompatible_features

    @cached_property
    def unmount_time(self) -> datetime:
        """The last unmount time of the filesystem."""
        return from_unix(self.object.apfs_unmount_time)

    @cached_property
    def omap(self) -> ObjectMap:
        """The object map for the filesystem."""
        return ObjectMap.from_address(self.container, self.object.apfs_omap_oid)

    @cached_property
    def root_tree(self) -> BTree:
        """The root B-tree for the filesystem."""
        if self.is_encrypted and self._cipher is None:
            raise Error("Volume is encrypted, unlock volume first")

        return BTree.from_address(
            self.container,
            self.omap.lookup(self.object.apfs_root_tree_oid, self.xid),
            cipher=self._cipher,
        )

    @cached_property
    def snap_meta_tree(self) -> BTree:
        """The snapshot metadata B-tree for the filesystem."""
        return BTree.from_address(
            self.container,
            self.object.apfs_snap_meta_tree_oid,
        )

    @cached_property
    def uuid(self) -> UUID:
        """The filesystem UUID."""
        return UUID(bytes_le=self.object.apfs_vol_uuid)

    @cached_property
    def mtime(self) -> datetime:
        """The last modification time of the filesystem."""
        return from_unix(self.object.apfs_last_mod_time)

    @cached_property
    def flags(self) -> c_apfs.APFS_FS:
        return c_apfs.APFS_FS(self.object.apfs_fs_flags)

    @cached_property
    def is_unencrypted(self) -> bool:
        """Whether the filesystem is unencrypted."""
        return c_apfs.APFS_FS.UNENCRYPTED in self.flags

    @cached_property
    def is_encrypted(self) -> bool:
        """Whether the filesystem is encrypted."""
        return (
            not self.is_unencrypted
            # Related to FileVault, but does not imply full volume encryption
            and c_apfs.APFS_FS.PFK not in self.flags
        )

    @cached_property
    def is_onekey(self) -> bool:
        """Whether the filesystem uses the volume encryption key for all."""
        return c_apfs.APFS_FS.ONEKEY in self.flags

    @cached_property
    def formatted_by(self) -> tuple[str, datetime, int]:
        """Information about the tool that formatted the filesystem."""
        return (
            self.object.apfs_formatted_by.id.split(b"\x00", 1)[0].decode(),
            from_unix(self.object.apfs_formatted_by.timestamp),
            self.object.apfs_formatted_by.last_xid,
        )

    @cached_property
    def modified_by(self) -> list[tuple[str, datetime, int]]:
        """Information about the tools that modified the filesystem."""
        result = []
        for entry in self.object.apfs_modified_by:
            if entry.id == b"\x00" * 64:
                continue

            result.append(
                (
                    entry.id.split(b"\x00", 1)[0].decode(),
                    from_unix(entry.timestamp),
                    entry.last_xid,
                )
            )

        return result

    @cached_property
    def name(self) -> str:
        """The volume name."""
        return self.object.apfs_volname.split(b"\x00", 1)[0].decode()

    @cached_property
    def role(self) -> c_apfs.APFS_VOL_ROLE:
        """The volume role."""
        return c_apfs.APFS_VOL_ROLE(self.object.apfs_role)

    @cached_property
    def snapshots(self) -> list[Snapshot]:
        """All snapshots in the filesystem."""
        result = []

        cursor = Cursor(self.snap_meta_tree)
        for key, value in cursor.walk():
            xid, type = parse_fs_object_key(key)
            if type != c_apfs.APFS_TYPE.SNAP_METADATA:
                continue
            result.append(Snapshot(self, xid, value))

        return result

    @cached_property
    def fext_tree(self) -> BTree:
        """The file extent B-tree for the filesystem."""
        return BTree.from_address(
            self.container,
            self.object.apfs_fext_tree_oid,
        )

    @cached_property
    def keybag(self) -> VolumeKeybag | None:
        """The volume keybag, if present."""
        return self.container.keybag.volume_keybag(self.object.apfs_vol_uuid)

    @cached_property
    def password_hint(self) -> str | None:
        """The password hint for the volume, if present."""
        if not self.keybag:
            return None

        return self.keybag.password_hint(self.object.apfs_vol_uuid)

    def unlock(self, password: str, uuid: UUID | str | None = None) -> None:
        if (vek := self.container.keybag.vek(self.object.apfs_vol_uuid)) is None:
            raise Error("No VEK found for this volume")

        for kek in self.keybag.keks():
            if uuid is not None and str(kek.uuid) != str(uuid):
                continue

            if not kek.verify():
                continue

            try:
                vek = vek.unwrap(kek.unwrap(password))
            except Exception:
                continue
            else:
                self._cipher = create_cipher("aes-xts-128", vek)
                break

        if self._cipher is None:
            raise Error("Failed to unlock volume with the given password")

    def cursor(self) -> Cursor:
        """Create a new cursor for the volume's root B-tree."""
        return Cursor(self.root_tree, self.omap, self.object.apfs_root_tree_oid if self.is_sealed else 0, self.xid)

    def _cursor_state(self, oid: int) -> tuple[BTreeNode, int, list[tuple[BTreeNode, int]]]:
        """Precompute the cursor state for a given object ID.

        Args:
            oid: The object ID to position the cursor at.
        """
        cursor = self.cursor()
        cursor.search((oid, c_apfs.APFS_TYPE.ANY.value), cmp=cmp_fs)

        return cursor.state

    def _cursor(self, oid: int) -> Cursor:
        """Get a cursor positioned at the first record for a given object ID.

        Args:
            oid: The object ID to position the cursor at.
        """
        cursor = self.cursor()
        cursor.state = self._cursor_state(oid)
        return cursor

    def _records(self, oid: int, type: c_apfs.APFS_TYPE) -> Iterator[tuple[c_apfs.APFS_TYPE, bytes, bytes]]:
        """Iterate over all records for a given object ID and type.

        Args:
            oid: The object ID to search for.
            type: The object type to search for, or ``APFS_TYPE.ANY`` for all types.
        """
        cursor = self._cursor(oid)

        while True:
            current_oid, current_type = parse_fs_object_key(cursor.key())
            if current_oid < oid:
                if not cursor.next():
                    break
                continue

            if current_oid > oid or (type != c_apfs.APFS_TYPE.ANY and current_type > type):
                break

            if type == c_apfs.APFS_TYPE.ANY or current_type == type:
                yield current_type, cursor.key(), cursor.value()

            if not cursor.next():
                break

    def records(self, oid: int) -> dict[c_apfs.APFS_TYPE, list[Any]]:
        """Get all records for a given object ID.

        Args:
            oid: The object ID to search for.
        """
        result = {}
        for type, key, value in self._records(oid, c_apfs.APFS_TYPE.ANY):
            key_struct, value_struct = FILESYSTEM_OBJECT_TYPE_MAP[type]
            result.setdefault(type, []).append((key_struct(key), value_struct(value)))
        return result

    def inode(self, oid: int | str, sibling_id: int | None = None) -> INode:
        """Get an inode by its object ID.

        Args:
            oid: The object ID of the inode to retrieve.
            sibling_id: The sibling ID of the inode to retrieve, if applicable.
        """
        if isinstance(oid, str):
            if ":" not in oid:
                raise ValueError("Invalid inode string, expected format 'oid:sibling_id'")
            oid, sibling_id = map(int, oid.split(":", 1))
        return INode(self, oid, sibling_id)

    def inodes(self) -> Iterator[INode]:
        """Iterate over all inodes in the filesystem."""
        cursor = self.cursor()

        for key, value in cursor.walk():
            oid, type = parse_fs_object_key(key)
            if type == c_apfs.APFS_TYPE.INODE:
                inode = self.inode(oid)
                inode._inode_raw = value
                yield inode

    def get(self, path: str | int | DirectoryEntry, node: INode | None = None) -> INode:
        """Get an inode by its path, object ID, or directory entry.

        Args:
            path: The path, object ID, or directory entry of the inode to retrieve.
            node: The starting inode for relative paths. Defaults to the root inode.
        """
        if isinstance(path, int):
            return self.inode(path)

        if isinstance(path, DirectoryEntry):
            return self.inode(path.file_id)

        node = node or self.root
        for p in path.split("/"):
            if not p:
                continue

            if p == ".":
                continue

            if p == "..":
                node = node.parent
                continue

            try:
                node = node.get(p).inode
            except FileNotFoundError:
                raise FileNotFoundError(f"File not found: {path}")

        return node


class Snapshot:
    def __init__(self, fs: FS, xid: int, value: bytes):
        self.fs = fs
        self.xid = xid
        self.value = c_apfs.j_snap_metadata_val(value)

    def __repr__(self) -> str:
        return (
            f"<Snapshot xid={self.xid} name={self.name!r} "
            f"create_time={self.create_time} change_time={self.change_time}>"
        )

    @cached_property
    def create_time(self) -> datetime:
        """The creation time of the snapshot."""
        return from_unix_ns(self.value.create_time)

    @cached_property
    def change_time(self) -> datetime:
        """The change time of the snapshot."""
        return from_unix_ns(self.value.change_time)

    @cached_property
    def name(self) -> str:
        """The name of the snapshot."""
        return self.value.name.decode().rstrip("\x00")

    def open(self) -> FS:
        """Open the snapshot as a filesystem."""
        fs = FS.from_address(
            self.fs.container,
            self.value.sblock_oid,
        )
        fs.omap = self.fs.omap
        return fs


class INode:
    """APFS inode.

    Represents a file or directory in an APFS volume.

    Args:
        volume: Parent APFS volume.
        oid: The object ID of the inode.
        sibling_id: The sibling ID of the inode, if applicable.
    """

    def __init__(self, volume: FS, oid: int, sibling_id: int | None = None):
        self.volume = volume
        self.oid = oid
        self.sibling_id = sibling_id

    def __repr__(self) -> str:
        oid = f"{self.oid}:{self.sibling_id}" if self.sibling_id is not None else str(self.oid)
        return f"<INode oid={oid} name={self.name!r}>"

    @cached_property
    def records(self) -> dict[c_apfs.APFS_TYPE, list[Any]]:
        """All records for this inode."""
        return self.volume.records(self.oid)

    @cached_property
    def _inode_raw(self) -> bytes:
        """The raw inode data."""
        _, _, value = next(self.volume._records(self.oid, c_apfs.APFS_TYPE.INODE), (None, None, None))
        if value is None:
            raise KeyError(f"INode {self.oid} not found in volume")
        return value

    @cached_property
    def inode(self) -> c_apfs.j_inode_val:
        """The parsed inode structure."""
        return c_apfs.j_inode_val(self._inode_raw)

    @cached_property
    def xfields(self) -> dict:
        """The extended fields for this inode."""
        if len(self._inode_raw) == len(c_apfs.j_inode_val):
            return {}

        result = {}
        for field, value in _read_xfields(self._inode_raw[len(c_apfs.j_inode_val) :]):
            type = c_apfs.INO_EXT_TYPE(field.x_type)
            result[type] = (c_apfs.XF(field.x_flags), XF_MAP.get(type, lambda buf: buf)(value))

        return result

    @cached_property
    def xattr(self) -> dict[str, XAttr]:
        """The extended attributes for this inode."""
        result = {}

        for _, key, value in self.volume._records(self.oid, c_apfs.APFS_TYPE.XATTR):
            xattr = XAttr(self, key, value)
            result[xattr.name] = xattr

        return result

    @property
    def parent(self) -> INode:
        """The parent inode."""
        if self.oid in (c_apfs.ROOT_DIR_INO_NUM, c_apfs.PRIV_DIR_INO_NUM):
            return self

        if self.sibling_id is not None:
            parent_id, _ = self.sibling_link or (None, None)
        else:
            parent_id = self.inode.parent_id

        return self.volume.inode(parent_id)

    @property
    def parents(self) -> Iterator[INode]:
        """Iterate over the parent inodes of this inode, up to the root."""
        obj = self
        while obj.parent is not obj:
            obj = obj.parent
            yield obj

    @cached_property
    def private_id(self) -> int:
        """The private ID of this inode."""
        return self.inode.private_id

    @cached_property
    def btime(self) -> datetime:
        """The birth time of this inode."""
        return from_unix_ns(self.inode.create_time)

    @cached_property
    def mtime(self) -> datetime:
        """The modification time of this inode."""
        return from_unix_ns(self.inode.mod_time)

    @cached_property
    def ctime(self) -> datetime:
        """The change time of this inode."""
        return from_unix_ns(self.inode.change_time)

    @cached_property
    def atime(self) -> datetime:
        """The access time of this inode."""
        return from_unix_ns(self.inode.access_time)

    @cached_property
    def internal_flags(self) -> c_apfs.INODE:
        """The inode internal flags."""
        return c_apfs.INODE(self.inode.internal_flags)

    @cached_property
    def bsd_flags(self) -> int:
        """The inode BSD flags."""
        return self.inode.bsd_flags

    def is_compressed(self) -> bool:
        """Return whether this inode is compressed."""
        return bool(self.bsd_flags & c_apfs.UF_COMPRESSED)

    @cached_property
    def uid(self) -> int:
        """The owner user ID of this inode."""
        return self.inode.owner

    @cached_property
    def gid(self) -> int:
        """The owner group ID of this inode."""
        return self.inode.group

    @cached_property
    def mode(self) -> int:
        """The file mode of this inode."""
        return self.inode.mode

    @cached_property
    def type(self) -> int:
        """The file type of this inode."""
        return stat.S_IFMT(self.mode)

    def is_dir(self) -> bool:
        """Return whether this inode is a directory."""
        return stat.S_ISDIR(self.mode)

    def is_file(self) -> bool:
        """Return whether this inode is a regular file."""
        return stat.S_ISREG(self.mode)

    def is_symlink(self) -> bool:
        """Return whether this inode is a symbolic link."""
        return stat.S_ISLNK(self.mode)

    def is_block_device(self) -> bool:
        """Return whether this inode is a block device."""
        return stat.S_ISBLK(self.mode)

    def is_character_device(self) -> bool:
        """Return whether this inode is a character device."""
        return stat.S_ISCHR(self.mode)

    def is_device(self) -> bool:
        """Return whether this inode is a device (block or character)."""
        return self.is_block_device() or self.is_character_device()

    def is_fifo(self) -> bool:
        """Return whether this inode is a FIFO."""
        return stat.S_ISFIFO(self.mode)

    def is_socket(self) -> bool:
        """Return whether this inode is a socket."""
        return stat.S_ISSOCK(self.mode)

    def is_whiteout(self) -> bool:
        """Return whether this inode is a whiteout."""
        return stat.S_ISWHT(self.mode)

    @cached_property
    def size(self) -> int:
        """The size of this inode in bytes."""
        if c_apfs.INODE.HAS_UNCOMPRESSED_SIZE in self.internal_flags:
            return self.inode.uncompressed_size

        if decmpfs := self.xattr.get("com.apple.decmpfs"):
            header = c_apfs.decmpfs_header(decmpfs.open())
            return header.uncompressed_size

        if dstream := self.xfields.get(c_apfs.INO_EXT_TYPE.DSTREAM):
            _, dstream = dstream
            return dstream.size

        return 0

    @cached_property
    def siblings(self) -> list[INode]:
        """All sibling inodes of this inode."""
        result = []
        for _, key, _ in self.volume._records(self.oid, c_apfs.APFS_TYPE.SIBLING_LINK):
            key = c_apfs.j_sibling_key(key)
            if self.sibling_id is not None and key.sibling_id == self.sibling_id:
                continue
            result.append(self.volume.inode(self.oid, key.sibling_id))
        return result

    @cached_property
    def sibling_link(self) -> tuple[int, str] | None:
        """The sibling link (``parent_id``, ``name``) tuple of this inode, if available."""
        if self.sibling_id is not None:
            for _, key, value in self.volume._records(self.oid, c_apfs.APFS_TYPE.SIBLING_LINK):
                if c_apfs.j_sibling_key(key).sibling_id == self.sibling_id:
                    value = c_apfs.j_sibling_val(value)
                    return value.parent_id, value.name.decode().rstrip("\x00")
        return None

    @cached_property
    def name(self) -> str | None:
        """The name of this inode, if available."""
        name = None
        if self.sibling_id is not None:
            _, name = self.sibling_link or (None, None)
        else:
            if c_apfs.INO_EXT_TYPE.NAME in self.xfields:
                _, name = self.xfields[c_apfs.INO_EXT_TYPE.NAME]
                name = name.decode().rstrip("\x00")
        return name

    @cached_property
    def names(self) -> list[str]:
        """All names of this inode, if available."""
        names = {self.name} | {sibling.name for sibling in self.siblings if sibling.name}
        return list(names)

    @cached_property
    def path(self) -> str:
        """The full path of this inode, if available."""
        parts = [self.name or f"<unlinked:{self.oid}>"]
        parts.extend(parent.name or f"<unlinked:{parent.oid}>" for parent in self.parents)

        return "/" + "/".join(parts[::-1])

    @cached_property
    def paths(self) -> list[str]:
        """All full paths of this inode, if available."""
        return [self.path] + [sibling.path for sibling in self.siblings]

    def get(self, name: str) -> DirectoryEntry:
        """Get a directory entry by name."""
        if not self.volume.is_case_insensitive and not self.volume.is_normalization_insensitive:
            # APFS beta's didn't have normalization insensitivity, so when the filesystem is case sensitive
            # we can do a simple exact match
            key = ((self.oid, c_apfs.APFS_TYPE.DIR_REC.value), name.encode() + b"\x00")
            cmp = cmp_fs_dir
        else:
            # Length is not used in the key comparison
            name_hash = (
                _hash_filename(name, self.volume.is_case_insensitive) << c_apfs.J_DREC_HASH_SHIFT
            ) & c_apfs.J_DREC_HASH_MASK
            # If the volume is case sensitive, we can use the name in the search key for an exact match
            # Otherwise, we set it to None to ignore it in the comparison
            name_search = None if self.volume.is_case_insensitive else (name.encode() + b"\x00")

            key = ((self.oid, c_apfs.APFS_TYPE.DIR_REC.value), name_hash, name_search)
            cmp = cmp_fs_dir_hash

        cursor = self.volume.cursor()
        try:
            cursor.search(key, exact=True, cmp=cmp)
        except KeyError:
            raise FileNotFoundError(f"File not found: {name}")

        if not self.volume.is_case_insensitive:
            # On case sensitive volumes, the search is already exact, so no need to check further
            return DirectoryEntry(self.volume, cursor.key(), cursor.value())

        lname = name.casefold()
        while True:
            try:
                dirent = DirectoryEntry(self.volume, cursor.key(), cursor.value())
            except Exception:
                raise FileNotFoundError(f"File not found: {name}")

            # To deal with the possibility of hash collisions, verify the name matches
            oid = dirent.key.hdr.obj_id_and_type & c_apfs.OBJ_ID_MASK
            type = (dirent.key.hdr.obj_id_and_type & c_apfs.OBJ_TYPE_MASK) >> c_apfs.OBJ_TYPE_SHIFT
            if oid != self.oid or type != c_apfs.APFS_TYPE.DIR_REC:
                raise FileNotFoundError(f"File not found: {name}")

            if lname == dirent.name.casefold():
                return dirent

            if not cursor.next():
                raise FileNotFoundError(f"File not found: {name}")

    def listdir(self) -> dict[str, DirectoryEntry]:
        """List the directory entries in this inode."""
        return {e.name: e for e in self.iterdir()}

    def iterdir(self) -> Iterator[DirectoryEntry]:
        """Iterate over the directory entries in this inode."""
        if not self.is_dir():
            raise NotADirectoryError(f"{self} is not a directory")

        for _, key, value in self.volume._records(self.oid, c_apfs.APFS_TYPE.DIR_REC):
            yield DirectoryEntry(self.volume, key, value)

    def readlink(self) -> str:
        """The target of this inode if it is a symbolic link."""
        if not self.is_symlink():
            raise NotASymlinkError(f"{self} is not a symlink")

        if c_apfs.SYMLINK_EA_NAME not in self.xattr:
            raise Error(f"Symlink {self} does not have SYMLINK_EA_NAME xattr")

        return self.xattr[c_apfs.SYMLINK_EA_NAME].open().read().decode().rstrip("\x00")

    def open(self) -> BufferedStream | DecmpfsStream | FileStream:
        """Open a stream for reading the inode data."""
        if self.is_compressed():
            return DecmpfsStream(self)

        if dstream := self.xfields.get(c_apfs.INO_EXT_TYPE.DSTREAM):
            _, dstream = dstream
            return FileStream(self.volume, self.oid, dstream.size)

        return BufferedStream(BytesIO(b""), size=0)


class DirectoryEntry:
    """APFS directory entry.

    Args:
        volume: Parent APFS volume.
        key: The raw directory entry key.
        value: The raw directory entry value.
    """

    def __init__(self, volume: FS, key: bytes, value: bytes):
        self.volume = volume
        if self.volume.is_case_insensitive or self.volume.is_normalization_insensitive:
            self.key = c_apfs.j_drec_hashed_key(key)
        else:
            self.key = c_apfs.j_drec_key(key)
        self.value = c_apfs.j_drec_val(value)

        self.xfields = {}
        if len(value) != len(c_apfs.j_drec_val):
            for field, data in _read_xfields(value[len(c_apfs.j_drec_val) :]):
                type = c_apfs.DREC_EXT_TYPE(field.x_type)
                self.xfields[type] = (c_apfs.XF(field.x_flags), XF_MAP.get(type, lambda buf: buf)(data))

    def __repr__(self) -> str:
        return f"<DirectoryEntry name={self.name!r} file_id={self.file_id} dt={self.dt.name}>"

    @cached_property
    def name(self) -> str:
        """The name of this directory entry."""
        return self.key.name.decode().rstrip("\x00")

    @cached_property
    def hash(self) -> int | None:
        """The hash of this directory entry, if available."""
        if isinstance(self.key, c_apfs.j_drec_key):
            return None
        return (self.key.name_len_and_hash & c_apfs.J_DREC_HASH_MASK) >> c_apfs.J_DREC_HASH_SHIFT

    @cached_property
    def file_id(self) -> int:
        """The object ID of the inode this directory entry refers to."""
        return self.value.file_id

    @cached_property
    def sibling_id(self) -> int | None:
        """The sibling ID of the inode this directory entry refers to, if available."""
        return self.xfields.get(c_apfs.DREC_EXT_TYPE.SIBLING_ID, (None, None))[1]

    @property
    def inode(self) -> INode:
        """The inode this directory entry refers to."""
        return self.volume.inode(self.file_id, self.sibling_id)

    @cached_property
    def date_added(self) -> datetime:
        """The date and time this directory entry was added."""
        return from_unix_ns(self.value.date_added)

    @cached_property
    def dt(self) -> c_apfs.DT:
        """The directory entry type."""
        return c_apfs.DT(self.value.flags & c_apfs.DREC_TYPE_MASK)

    @cached_property
    def type(self) -> int:
        """The file type of this directory entry."""
        return self.value.flags & c_apfs.DREC_TYPE_MASK << 12

    def is_dir(self) -> bool:
        """Return whether this directory entry is a directory."""
        return stat.S_ISDIR(self.type << 12)

    def is_file(self) -> bool:
        """Return whether this directory entry is a regular file."""
        return stat.S_ISREG(self.type << 12)

    def is_symlink(self) -> bool:
        """Return whether this directory entry is a symbolic link."""
        return stat.S_ISLNK(self.type << 12)

    def is_block_device(self) -> bool:
        """Return whether this directory entry is a block device."""
        return stat.S_ISBLK(self.type << 12)

    def is_character_device(self) -> bool:
        """Return whether this directory entry is a character device."""
        return stat.S_ISCHR(self.type << 12)

    def is_device(self) -> bool:
        """Return whether this directory entry is a device (block or character)."""
        return self.is_block_device() or self.is_character_device()

    def is_fifo(self) -> bool:
        """Return whether this directory entry is a FIFO."""
        return stat.S_ISFIFO(self.type << 12)

    def is_socket(self) -> bool:
        """Return whether this directory entry is a socket."""
        return stat.S_ISSOCK(self.type << 12)

    def is_whiteout(self) -> bool:
        """Return whether this directory entry is a whiteout."""
        return stat.S_ISWHT(self.type << 12)


class XAttr:
    """APFS extended attribute.

    Args:
        inode: The inode this xattr belongs to.
        key: The raw xattr key.
        value: The raw xattr value.
    """

    def __init__(self, inode: INode, key: bytes, value: bytes):
        self.inode = inode

        self.key = c_apfs.j_xattr_key(key)
        self.value = c_apfs.j_xattr_val(value)

    def __repr__(self) -> str:
        return f"<XAttr name={self.name!r} flags={self.flags}>"

    @cached_property
    def name(self) -> str:
        """The name of this xattr."""
        return self.key.name.decode().rstrip("\x00")

    @cached_property
    def flags(self) -> c_apfs.XATTR:
        """The flags of this xattr."""
        return c_apfs.XATTR(self.value.flags)

    def open(self) -> BufferedStream | FileStream:
        """Open a stream for reading the xattr data."""
        if c_apfs.XATTR.DATA_STREAM in self.flags:
            dstream = c_apfs.j_xattr_dstream(self.value.xdata)
            return FileStream(self.inode.volume, dstream.xattr_obj_id, dstream.dstream.size)

        return BufferedStream(BytesIO(self.value.xdata), size=self.value.xdata_len)


def _read_xfields(data: bytes) -> Iterator[tuple[c_apfs.x_field, bytes]]:
    """Read extended fields from a buffer."""
    blob = c_apfs.xf_blob(data)
    buf = BytesIO(blob.xf_data)
    for field in blob.xf_exts:
        yield field, buf.read(field.x_size)
        # Align to 8 bytes
        buf.seek((buf.tell() + 7) & (-8))


def _hash_filename(name: str, casefold: bool) -> int:
    """Hash a filename according to APFS rules."""
    normalized = unicodedata.normalize("NFD", name)
    if casefold:
        normalized = normalized.casefold()
    return crc32c(normalized.encode("utf-32-le")) ^ 0xFFFFFFFF
