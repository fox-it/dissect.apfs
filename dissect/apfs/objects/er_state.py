from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class EncryptionRollingState(Object):
    """APFS Encryption Rolling State object."""

    __type__ = c_apfs.OBJECT_TYPE_ER_STATE
    __struct__ = c_apfs.er_state_phys
    object: c_apfs.er_state_phys
