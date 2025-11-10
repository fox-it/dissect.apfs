from __future__ import annotations

import hashlib
import hmac
import struct
from functools import cached_property
from typing import TYPE_CHECKING, Any
from uuid import UUID

from asn1crypto.core import Integer, OctetString, Sequence
from dissect.fve.crypto import create_cipher

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import Error
from dissect.apfs.objects.base import Object

try:
    import _pystandalone

    HAS_PYSTANDALONE = True
except ImportError:
    HAS_PYSTANDALONE = False

try:
    from Crypto.Cipher import AES

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

if TYPE_CHECKING:
    from collections.abc import Iterator


class Keybag(Object):
    """APFS Keybag."""

    __struct__ = c_apfs.media_keybag
    object: c_apfs.media_keybag

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.object.mk_locker.kl_version != c_apfs.APFS_KEYBAG_VERSION:
            raise Error(
                "Unsupported keybag version "
                f"(expected {c_apfs.APFS_KEYBAG_VERSION}, got {self.object.mk_locker.kl_version})"
            )

        self.entries = {}

        offset = len(c_apfs.media_keybag)
        for _ in range(self.object.mk_locker.kl_nkeys):
            entry = c_apfs.keybag_entry(self.block[offset:])
            entry.ke_keydata = bytes(
                self.block[offset + len(c_apfs.keybag_entry) : offset + len(c_apfs.keybag_entry) + entry.ke_keylen]
            )
            offset += (len(c_apfs.keybag_entry) + entry.ke_keylen + 0x0F) & ~0x0F  # Align to 16 bytes

            self.entries[(entry.ke_uuid, entry.ke_tag)] = entry

    @cached_property
    def type(self) -> c_apfs.OBJECT_TYPE:
        """The object's type."""
        return c_apfs.OBJECT_TYPE(self.header.o_type)


class ContainerKeybag(Keybag):
    """APFS Container Keybag."""

    __type__ = c_apfs.OBJECT_TYPE_CONTAINER_KEYBAG

    def volume_keybag(self, uuid: bytes) -> VolumeKeybag | None:
        """The volume keybag for the given volume UUID, if present.

        Args:
            uuid: The volume UUID.
        """
        entry: c_apfs.keybag_entry

        if (entry := self.entries.get((uuid, c_apfs.KB_TAG.VOLUME_UNLOCK_RECORDS.value))) is None:
            return None

        prange = c_apfs.prange(entry.ke_keydata)
        return VolumeKeybag.from_address(
            self.container,
            prange.pr_start_paddr,
            prange.pr_block_count,
            cipher=create_cipher("aes-xts-128", uuid * 2),
        )

    def vek(self, uuid: bytes) -> VEK | None:
        """The volume encryption key (VEK) for the given volume UUID, if present.

        Args:
            uuid: The volume UUID.
        """
        entry: c_apfs.keybag_entry

        idx = (uuid, c_apfs.KB_TAG.VOLUME_KEY.value)
        if (entry := self.entries.get(idx)) is None:
            return None

        return VEK.load(entry.ke_keydata)


class VolumeKeybag(Keybag):
    """APFS Volume Keybag."""

    __type__ = c_apfs.OBJECT_TYPE_VOLUME_KEYBAG

    def password_hint(self, uuid: bytes) -> str | None:
        """The password hint for the volume, if present.

        Args:
            uuid: The volume UUID.
        """
        entry: c_apfs.keybag_entry

        if (entry := self.entries.get((uuid, c_apfs.KB_TAG.VOLUME_PASSPHRASE_HINT.value))) is None:
            return None

        return entry.ke_keydata.decode()

    def keks(self) -> Iterator[KEK]:
        """Iterator over the KEKs in the volume keybag."""
        for entry in self.entries.values():
            if entry.ke_tag == c_apfs.KB_TAG.VOLUME_UNLOCK_RECORDS.value:
                yield KEK.load(entry.ke_keydata)


class MediaKeybag(Keybag):
    """APFS Media Keybag."""

    __type__ = c_apfs.OBJECT_TYPE_MEDIA_KEYBAG


class KEKBlob(Sequence):
    _fields = (
        ("unknown", Integer, {"tag_type": "implicit", "tag": 0}),
        ("uuid", OctetString, {"tag_type": "implicit", "tag": 1}),
        ("info", OctetString, {"tag_type": "implicit", "tag": 2}),
        ("wrapped", OctetString, {"tag_type": "implicit", "tag": 3}),
        ("iterations", Integer, {"tag_type": "implicit", "tag": 4}),
        ("salt", OctetString, {"tag_type": "implicit", "tag": 5}),
    )


class KEK(Sequence):
    _fields = (
        ("unknown", Integer, {"tag_type": "implicit", "tag": 0}),
        ("hmac", OctetString, {"tag_type": "implicit", "tag": 1}),
        ("salt", OctetString, {"tag_type": "implicit", "tag": 2}),
        ("blob", KEKBlob, {"tag_type": "implicit", "tag": 3}),
    )

    def __repr__(self) -> str:
        return f"<KEK uuid={self.uuid}>"

    @property
    def uuid(self) -> UUID:
        """The KEK's UUID."""
        return UUID(bytes_le=self["blob"]["uuid"].native)

    @property
    def flags(self) -> int:
        """The KEK's flags."""
        return c_apfs.uint32_t(self["blob"]["info"].native)

    def verify(self) -> bool:
        """Verify the KEK's HMAC."""
        return (
            hmac.digest(
                hashlib.sha256(b"\x01\x16\x20\x17\x15\x05" + self["salt"].native).digest(),
                self["blob"].dump(),
                "sha256",
            )
            == self["hmac"].native
        )

    def unwrap(self, password: str) -> bytes:
        """Unwrap the KEK using the given password."""
        blob = self["blob"]
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            blob["salt"].native,
            blob["iterations"].native,
            dklen=32,
        )

        wrapped = blob["wrapped"].native[:40]

        if self.flags & 2:
            # Unknown flag, but used in CoreStorage converted volumes
            key = key[:16]
            wrapped = wrapped[:24]

        return aes_unwrap(key, wrapped)


class VEKBlob(Sequence):
    _fields = (
        ("unk0", Integer, {"tag_type": "implicit", "tag": 0}),
        ("uuid", OctetString, {"tag_type": "implicit", "tag": 1}),
        ("info", OctetString, {"tag_type": "implicit", "tag": 2}),
        ("wrapped", OctetString, {"tag_type": "implicit", "tag": 3}),
    )


class VEK(Sequence):
    _fields = (
        ("unk0", Integer, {"tag_type": "implicit", "tag": 0}),
        ("hmac", OctetString, {"tag_type": "implicit", "tag": 1}),
        ("salt", OctetString, {"tag_type": "implicit", "tag": 2}),
        ("blob", VEKBlob, {"tag_type": "implicit", "tag": 3}),
    )

    def __repr__(self) -> str:
        return f"<VEK uuid={self.uuid}>"

    @property
    def uuid(self) -> UUID:
        """The VEK's UUID."""
        return UUID(bytes_le=self["blob"]["uuid"].native)

    @property
    def flags(self) -> int:
        """The VEK's flags."""
        return c_apfs.uint32_t(self["blob"]["info"].native)

    def verify(self) -> bool:
        """Verify the VEK's HMAC."""
        return (
            hmac.digest(
                hashlib.sha256(b"\x01\x16\x20\x17\x15\x05" + self["salt"].native).digest(),
                self["blob"].dump(),
                "sha256",
            )
            == self["hmac"].native
        )

    def unwrap(self, key: bytes) -> bytes:
        """Unwrap the KEK using the given key."""
        wrapped = self["blob"]["wrapped"].native

        if self.flags & 2:
            # Unknown flag, but used in CoreStorage converted volumes
            key = key[:16]
            wrapped = wrapped[:24]

        unwrapped = aes_unwrap(key, wrapped)

        if self.flags & 2:
            unwrapped += hashlib.sha256(unwrapped + self["blob"]["uuid"].native).digest()[:16]

        return unwrapped


def aes_unwrap(kek: bytes, wrapped: bytes, iv: int = 0xA6A6A6A6A6A6A6A6) -> bytes:
    """AES key unwrapping algorithm (RFC3394).

    Derived from https://github.com/kurtbrose/aes_keywrap/blob/master/aes_keywrap.py
    """
    QUAD = struct.Struct(">Q")

    n = len(wrapped) // 8 - 1

    # NOTE: R[0] is never accessed, left in for consistency with RFC indices
    R = [None] + [wrapped[i * 8 : i * 8 + 8] for i in range(1, n + 1)]
    A = QUAD.unpack(wrapped[:8])[0]

    decrypt = _create_cipher(kek, mode="ecb").decrypt

    for j in range(5, -1, -1):  # counting down
        for i in range(n, 0, -1):  # (n, n-1, ..., 1)
            ciphertext = QUAD.pack(A ^ (n * j + i)) + R[i]
            B = decrypt(ciphertext)
            A = QUAD.unpack(B[:8])[0]
            R[i] = B[8:]

    key, key_iv = b"".join(R[1:]), A

    if key_iv != iv:
        raise ValueError(f"Unwrapping failed: 0x{key_iv:x} (expected 0x{iv:x})")

    return key


def _create_cipher(key: bytes, iv: bytes = b"\x00" * 16, mode: str = "cbc") -> Any:
    """Create a cipher object.

    Dynamic based on the available crypto module.
    """

    if HAS_PYSTANDALONE:
        key_size = len(key)
        if key_size not in (32, 24, 16):
            raise ValueError(f"Invalid key size: {key_size}")

        return _pystandalone.cipher(f"aes-{key_size * 8}-{mode}", key, iv)

    if HAS_CRYPTO:
        mode_map = {
            "cbc": (AES.MODE_CBC, True),
            "ecb": (AES.MODE_ECB, False),
        }
        mode_id, has_iv = mode_map[mode]
        kwargs = {"iv": iv} if has_iv else {}
        return AES.new(key, mode_id, **kwargs)

    raise RuntimeError("No crypto module available")
