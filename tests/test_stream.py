from __future__ import annotations

from unittest.mock import Mock

from dissect.apfs.stream import FileStream


def _stream(extents: list[tuple[int, int, int]]) -> FileStream:
    """A file stream over the given ``(logical_address, physical_address, length)`` extents, on 4 KiB blocks."""
    stream = FileStream.__new__(FileStream)
    stream.align = 4096
    stream.volume = Mock(is_encrypted=False)
    stream.volume.container._read_block.side_effect = lambda block, count: bytes([block]) * (count * 4096)

    def lookup(offset: int) -> tuple[int, int, int, int]:
        return next(
            (logical, physical, length, 0)
            for logical, physical, length in extents
            if logical <= offset < logical + length
        )

    stream._lookup = lookup
    return stream


def test_sparse_hole_reads_as_zeros() -> None:
    """Test that a hole (an extent at physical block 0) reads as zeros, not as the container's first blocks."""
    stream = _stream([(0, 0, 8192), (8192, 5, 4096)])

    data = stream._read(0, 12288)

    assert data == bytes(8192) + bytes([5]) * 4096
    stream.volume.container._read_block.assert_called_once_with(5, 1)
