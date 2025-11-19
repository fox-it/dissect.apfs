from __future__ import annotations

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object


class EncryptionRollingRecoveryBlock(Object):
    """APFS Encryption Rolling Recovery Block object."""

    __type__ = c_apfs.OBJECT_TYPE_ER_RECOVERY_BLOCK
    __struct__ = c_apfs.er_recovery_block_phys
    object: c_apfs.er_recovery_block_phys
