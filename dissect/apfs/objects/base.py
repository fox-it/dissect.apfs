from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING, ClassVar

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.util import fletcher64

if TYPE_CHECKING:
    from dissect.fve.crypto import Cipher
    from typing_extensions import Self

    from dissect.apfs.apfs import APFS


class Object:
    """Base class for APFS objects.

    The way we use this is a little unorthodox OOP-wise, but it works well for our use case.
    For the core of our APFS implementation we want to be able to read any object directly from a known type,
    but for interactive use it would also be nice to be able to read an object from its address and have it
    automatically be the correct subclass.

    Subclasses should define the ``__type__`` and ``__struct__`` class variables.

    Args:
        container: The APFS container the object belongs to.
        address: The block address of the object within the container.
        block: Optionally, the raw block data of the object. If not provided, it will be read from the container.
        cipher: Optionally, a cipher to decrypt the object (or child objects).
    """

    __type__ = c_apfs.OBJECT_TYPE_INVALID
    __struct__ = c_apfs.obj_phys

    __known_types__: ClassVar[dict[int, type[Object]]] = {}

    def __init_subclass__(cls):
        if cls.__type__:
            cls.__known_types__[cls.__type__] = cls

    def __init__(self, container: APFS, address: int, *, block: bytes | None = None, cipher: Cipher | None = None):
        self.container = container
        self.address = address
        self.block = memoryview(block or container._read_block(address))
        self.cipher = cipher

        self.object = self.__struct__(self.block)
        if self.__struct__ is Object.__struct__:
            self.header = self.object
        else:
            # Get the first field of the struct, which is always the obj_phys header
            self.header = getattr(self.object, self.__struct__.__fields__[0].name)

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"oid={self.oid} xid={self.xid} "
            f"type={self.type.name} flags={self.type_flags} storage={self.storage_type.name}>"
        )

    @classmethod
    def from_address(cls, container: APFS, address: int, count: int = 1, *, cipher: Cipher | None = None) -> Self:
        """Load an object from its address, automatically determining the correct subclass."""
        block = container._read_block(address, count)
        return cls.from_block(container, address, block, cipher=cipher)

    @classmethod
    def from_block(cls, container: APFS, address: int, block: bytes, *, cipher: Cipher | None = None) -> Self:
        """Load an object from its raw block data, automatically determining the correct subclass."""
        if cipher is not None:
            # Sometimes the block is already decrypted
            # This is a bit hacky, but I don't currently know how to properly determine this otherwise
            header = c_apfs.obj_phys(block)
            if (
                cls is Object
                and header.o_type not in c_apfs.OBJECT_TYPE
                and header.o_type & c_apfs.OBJECT_TYPE_MASK not in c_apfs.OBJECT_TYPE
            ) or (
                cls is not Object
                and header.o_type != cls.__type__
                and header.o_type & c_apfs.OBJECT_TYPE_MASK != cls.__type__
            ):
                # If the type is invalid, decrypt the block
                block = cipher.decrypt(block, address * container.sectors_per_block)

        if cls is not Object:
            # If a subclass is called directly, use that class
            return cls(container, address, block=block, cipher=cipher)

        # Otherwise, determine the class based on the object type
        header = c_apfs.obj_phys(block)
        subcls = Object.__known_types__.get(header.o_type, None) or Object.__known_types__.get(
            header.o_type & c_apfs.OBJECT_TYPE_MASK, Object
        )
        return subcls(container, address, block=block, cipher=cipher)

    @cached_property
    def checksum(self) -> int:
        """The object's checksum."""
        return int.from_bytes(self.header.o_cksum, "little")

    def _checksum(self) -> int:
        """Calculate the object's checksum."""
        return fletcher64(self.block[c_apfs.MAX_CKSUM_SIZE :])

    def is_valid(self) -> bool:
        """Check if the object's checksum is valid."""
        return self._checksum() == self.checksum

    @cached_property
    def oid(self) -> int:
        """The object's ID."""
        return self.header.o_oid

    @cached_property
    def xid(self) -> int:
        """The object's transaction ID."""
        return self.header.o_xid

    @cached_property
    def type(self) -> c_apfs.OBJECT_TYPE:
        """The object's type."""
        return c_apfs.OBJECT_TYPE(self.header.o_type & c_apfs.OBJECT_TYPE_MASK)

    @cached_property
    def type_flags(self) -> c_apfs.OBJ:
        """The object's type flags."""
        return c_apfs.OBJ(self.header.o_type & c_apfs.OBJECT_TYPE_FLAGS_MASK)

    @cached_property
    def storage_type(self) -> c_apfs.OBJ:
        """The object's storage type."""
        return c_apfs.OBJ(self.header.o_type & c_apfs.OBJ_STORAGETYPE_MASK)

    @cached_property
    def is_virtual(self) -> bool:
        """Check if the object is stored as a virtual object."""
        return self.header.o_type & c_apfs.OBJ_STORAGETYPE_MASK == c_apfs.OBJ_VIRTUAL

    @cached_property
    def is_ephemeral(self) -> bool:
        """Check if the object is stored as an ephemeral object."""
        return self.header.o_type & c_apfs.OBJ_STORAGETYPE_MASK == c_apfs.OBJ_EPHEMERAL

    @cached_property
    def is_physical(self) -> bool:
        """Check if the object is stored as a physical object."""
        return self.header.o_type & c_apfs.OBJ_STORAGETYPE_MASK == c_apfs.OBJ_PHYSICAL

    @cached_property
    def is_encrypted(self) -> bool:
        """Check if the object is encrypted."""
        return self.header.o_type & c_apfs.OBJECT_TYPE_FLAGS_MASK == c_apfs.OBJ_ENCRYPTED

    @cached_property
    def subtype(self) -> c_apfs.OBJECT_TYPE:
        """The object's subtype."""
        return c_apfs.OBJECT_TYPE(self.header.o_subtype)
