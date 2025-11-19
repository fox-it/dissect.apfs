from __future__ import annotations

import struct
from typing import Literal

from dissect.util.xmemoryview import xmemoryview

from dissect.apfs.c_apfs import c_apfs


def fletcher64(data: bytes) -> int:
    """Compute the Fletcher-64 checksum of the given data."""
    sum1 = 0
    sum2 = 0

    for word in xmemoryview(data, "<I"):
        sum1 = (sum1 + word) & 0xFFFFFFFFFFFFFFFF
        sum2 = (sum2 + sum1) & 0xFFFFFFFFFFFFFFFF

    ck_low = 0xFFFFFFFF - ((sum1 + sum2) % 0xFFFFFFFF)
    ck_high = 0xFFFFFFFF - ((sum1 + ck_low) % 0xFFFFFFFF)

    return ck_low | (ck_high << 32)


def make_fs_object_key(oid: int, type: c_apfs.APFS_TYPE) -> c_apfs.j_key:
    """Create a ``j_key`` struct for the given object ID and type."""
    return c_apfs.j_key((oid & c_apfs.OBJ_ID_MASK) | (type << c_apfs.OBJ_TYPE_SHIFT))


def parse_fs_object_key(data: bytes) -> tuple[int, c_apfs.APFS_TYPE]:
    """Parse an object ID and type from a ``j_key`` struct."""
    key = c_apfs.j_key(data)
    oid = key.obj_id_and_type & c_apfs.OBJ_ID_MASK
    type = (key.obj_id_and_type & c_apfs.OBJ_TYPE_MASK) >> c_apfs.OBJ_TYPE_SHIFT
    return oid, c_apfs.APFS_TYPE(type)


def cmp_default(key: bytes, other: bytes) -> Literal[-1, 0, 1]:
    """Default comparison function for B-tree keys."""
    return (key < other) - (key > other)


_QQ = struct.Struct("<QQ")


def cmp_omap(key: tuple[int, int], other: bytes) -> Literal[-1, 0, 1]:
    """Comparison function for OMAP keys."""
    oid, xid = key
    (other_oid, other_xid) = _QQ.unpack(other)
    if (res := (oid < other_oid) - (oid > other_oid)) != 0:
        return res
    return (xid < other_xid) - (xid > other_xid)


_Q = struct.Struct("<Q")
_OBJ_ID_MASK = c_apfs.OBJ_ID_MASK
_OBJ_TYPE_MASK = c_apfs.OBJ_TYPE_MASK
_OBJ_TYPE_SHIFT = c_apfs.OBJ_TYPE_SHIFT


def cmp_fs(key: tuple[int, int], other: bytes) -> Literal[-1, 0, 1]:
    """Comparison function for FS object keys."""
    obj_id, type = key

    (other_obj_id_and_type,) = _Q.unpack_from(other)
    other_obj_id = other_obj_id_and_type & _OBJ_ID_MASK
    other_type = (other_obj_id_and_type & _OBJ_TYPE_MASK) >> _OBJ_TYPE_SHIFT

    if (res := (obj_id < other_obj_id) - (obj_id > other_obj_id)) != 0:
        return res

    if (res := (type < other_type) - (type > other_type)) != 0:
        return res

    return 0


def cmp_fs_extent(key: tuple[tuple[int, int], int], other: bytes) -> Literal[-1, 0, 1]:
    """Comparison function for FS extent keys."""
    obj_id_and_type, logical_addr = key

    # First compare the j_key portion
    if (res := cmp_fs(obj_id_and_type, other[:8])) != 0:
        return res

    (other_logical_addr,) = _Q.unpack_from(other, 8)

    return (logical_addr < other_logical_addr) - (logical_addr > other_logical_addr)


def cmp_fext(key: tuple[int, int], other: bytes) -> Literal[-1, 0, 1]:
    """Comparison function for sealed file extent keys."""
    private_id, logical_addr = key

    other_private_id, other_logical_addr = _QQ.unpack(other)

    if (res := (private_id < other_private_id) - (private_id > other_private_id)) != 0:
        return res

    return (logical_addr < other_logical_addr) - (logical_addr > other_logical_addr)


_H = struct.Struct("<H")


def cmp_fs_dir(key: tuple[tuple[int, int], bytes], other: bytes) -> Literal[-1, 0, 1]:
    """Comparison function for FS directory entries."""
    # Slightly more unreadable but faster than parsing a struct
    obj_id_and_type, name = key

    # First compare the j_key portion
    if (res := cmp_fs(obj_id_and_type, other[:8])) != 0:
        return res

    # Then compare the name
    (other_name_len,) = _H.unpack_from(other, 8)
    other_name = other[10 : 10 + (other_name_len)]
    return (name < other_name) - (name > other_name)


_I = struct.Struct("<I")
_J_DREC_LEN_MASK = c_apfs.J_DREC_LEN_MASK


def cmp_fs_dir_hash(key: tuple[tuple[int, int], int, bytes | None], other: bytes) -> Literal[-1, 0, 1]:
    """Comparison function for FS directory entries."""
    # Slightly more unreadable but faster than parsing a struct
    obj_id_and_type, name_hash, name = key

    # First compare the j_key portion
    if (res := cmp_fs(obj_id_and_type, other[:8])) != 0:
        return res

    # Then compare the name_len_hash
    (other_name_len_hash,) = _I.unpack_from(other, 8)
    other_hash = other_name_len_hash & c_apfs.J_DREC_HASH_MASK

    if (res := (name_hash < other_hash) - (name_hash > other_hash)) != 0:
        return res

    # Special case for searching without a name
    if name is None:
        return 0

    # Finally compare the name
    other_name = other[12 : 12 + (other_name_len_hash & _J_DREC_LEN_MASK)]
    return (name < other_name) - (name > other_name)
