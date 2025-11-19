from __future__ import annotations

import gzip
import hashlib
from typing import TYPE_CHECKING

import pytest

from dissect.apfs.apfs import APFS
from dissect.apfs.c_apfs import c_apfs
from tests.conftest import absolute_path

if TYPE_CHECKING:
    from dissect.apfs.objects.fs import FS


def _assert_apfs_content(volume: FS, beta: bool) -> None:
    # Root directory
    node = volume.get("/")
    assert node.name == "root"
    assert node.path == "/root"
    assert node.is_dir()
    assert all(
        name in sorted(node.listdir())
        for name in [
            ".fseventsd",
            "case_folding_µ",
            "dir",
            "empty",
            "hardlink",
            "nfd_téstfilè",
            "nfd_¾",
            "nfkd_3⁄4",  # noqa: RUF001
            "symlink-dir",
            "symlink-file",
        ]
    )

    # Empty file
    node = volume.get("empty")
    assert node.name == "empty"
    assert node.path == "/root/empty"
    assert node.is_file()
    assert node.open().read() == b""

    # Test case sensitivity
    if volume.is_case_insensitive:
        node = volume.get("EMPTY")
        assert node.name == "empty"
        assert node.path == "/root/empty"
        assert node.is_file()
        assert node.open().read() == b""
    else:
        with pytest.raises(FileNotFoundError):
            volume.get("EMPTY")

    # Directory
    node = volume.get("dir")
    assert node.name == "dir"
    assert node.path == "/root/dir"
    assert node.is_dir()
    assert all(
        name in sorted(node.listdir())
        for name in (
            [
                "compressed-zlib-fork",
                "compressed-zlib-xattr",
                "fifo",
                "file",
                "resourcefork",
                "xattr-dir",
                "xattr-large",
                "xattr-small",
            ]
            if beta
            else [
                "compressed-lzfse-fork",
                "compressed-lzfse-xattr",
                "compressed-lzvn-fork",
                "compressed-lzvn-xattr",
                "compressed-zlib-fork",
                "compressed-zlib-xattr",
                "fifo",
                "file",
                "resourcefork",
                "xattr-dir",
                "xattr-large",
                "xattr-small",
            ]
        )
    )

    # Regular file
    node = volume.get("dir/file")
    assert node.name == "file"
    assert node.path == "/root/dir/file"
    assert sorted(node.names) == ["file", "hardlink"]
    assert sorted(node.paths) == ["/root/dir/file", "/root/hardlink"]
    assert node.is_file()
    assert node.open().read().decode() == " File System\n"

    # Hard link
    node = volume.get("hardlink")
    assert node.oid == volume.get("dir/file").oid
    assert node.sibling_id == volume.get("dir/file").sibling_id + 1
    assert node.name == "hardlink"
    assert node.path == "/root/hardlink"
    assert sorted(node.names) == ["file", "hardlink"]
    assert sorted(node.paths) == ["/root/dir/file", "/root/hardlink"]
    assert node.is_file()
    assert node.inode == volume.get("dir/file").inode

    # Symbolic link to file
    node = volume.get("symlink-file")
    assert node.name == "symlink-file"
    assert node.path == "/root/symlink-file"
    assert node.is_symlink()
    assert node.readlink() == "dir/file"

    # Symbolic link to directory
    node = volume.get("symlink-dir")
    assert node.name == "symlink-dir"
    assert node.path == "/root/symlink-dir"
    assert node.is_symlink()
    assert node.readlink() == "dir"

    if ".HFS+ Private Directory Data\r" not in volume.get("/").listdir():
        # File with NFC encoded name
        node = volume.get("nfc_téstfilè")
        assert node.name == "nfc_téstfilè"

    # File with NFD encoded name
    node = volume.get("nfd_téstfilè")
    assert node.name == "nfd_téstfilè"
    assert node.name != "nfd_téstfilè"  # Not normalized

    # File with NFD encoded name
    node = volume.get("nfd_¾")
    assert node.name == "nfd_¾"
    assert node.name != "nfd_3⁄4"  # Not normalized  # noqa: RUF001

    # File with NFKD encoded name
    node = volume.get("nfkd_3⁄4")  # noqa: RUF001
    assert node.name == "nfkd_3⁄4"  # noqa: RUF001
    assert node.name != "nfkd_¾"  # Not normalized

    # File with case folding
    node = volume.get("case_folding_µ")
    assert node.name == "case_folding_µ"

    # Resource fork
    node = volume.get("dir/resourcefork")
    assert node.name == "resourcefork"
    assert node.is_file()
    assert node.xattr["com.apple.ResourceFork"].open().read() == b"Resource fork data\n"

    # Small xattr
    node = volume.get("dir/xattr-small")
    assert node.name == "xattr-small"
    assert node.is_file()
    assert node.xattr["xattr-small"].open().read() == b"Small xattr data"

    # Directory with xattr
    node = volume.get("dir/xattr-dir")
    assert node.name == "xattr-dir"
    assert node.is_dir()
    assert node.xattr["xattr-dir"].open().read() == b"xattr data on directory"

    # Large xattr
    node = volume.get("dir/xattr-large")
    assert node.name == "xattr-large"
    assert node.is_file()
    assert (
        hashlib.sha256(node.xattr["xattr-large"].open().read()).hexdigest()
        == "dd4e6730520932767ec0a9e33fe19c4ce24399d6eba4ff62f13013c9ed30ef87"
        if beta
        else "a11c957142c3fd8ebf2bee1ed0cf184a246033a3874d060acd28c319b323466e"
    )

    # Compressed file method 3 (ZLIB-XATTR)
    node = volume.get("dir/compressed-zlib-xattr")
    assert node.name == "compressed-zlib-xattr"
    assert node.is_file()
    assert node.is_compressed()
    assert (
        node.open().read()
        == b"Compressed data in xattr aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"  # noqa: E501
    )

    # Compressed file method 4 (ZLIB-FORK)
    node = volume.get("dir/compressed-zlib-fork")
    assert node.name == "compressed-zlib-fork"
    assert node.is_file()
    assert node.is_compressed()
    assert (
        hashlib.sha256(node.open().read()).hexdigest()
        == "5f46d97f947137dcf974fc19914c547acd18fcdb25124c846c1100f8b3fbca5f"
    )

    if not beta:
        # Compressed file method 7 (LZVN-XATTR)
        node = volume.get("dir/compressed-lzvn-xattr")
        assert node.name == "compressed-lzvn-xattr"
        assert node.is_file()
        assert node.is_compressed()
        assert (
            node.open().read()
            == b"Compressed data in xattr aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"  # noqa: E501
        )

        # Compressed file method 8 (LZVN-FORK)
        node = volume.get("dir/compressed-lzvn-fork")
        assert node.name == "compressed-lzvn-fork"
        assert node.is_file()
        assert node.is_compressed()
        assert (
            hashlib.sha256(node.open().read()).hexdigest()
            == "5f46d97f947137dcf974fc19914c547acd18fcdb25124c846c1100f8b3fbca5f"
        )

        # Compressed file method 11 (LZFSE-XATTR)
        node = volume.get("dir/compressed-lzfse-xattr")
        assert node.name == "compressed-lzfse-xattr"
        assert node.is_file()
        assert node.is_compressed()
        assert (
            node.open().read()
            == b"Compressed data in xattr aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"  # noqa: E501
        )

        # Compressed file method 12 (LZFSE-FORK)
        node = volume.get("dir/compressed-lzfse-fork")
        assert node.name == "compressed-lzfse-fork"
        assert node.is_file()
        assert node.is_compressed()
        assert (
            hashlib.sha256(node.open().read()).hexdigest()
            == "5f46d97f947137dcf974fc19914c547acd18fcdb25124c846c1100f8b3fbca5f"
        )

    if ".HFS+ Private Directory Data\r" not in volume.get("/").listdir() and not beta:
        # Special files
        node = volume.get("dir/blockdev")
        assert node.name == "blockdev"
        assert node.is_block_device()

        for name in [
            "chardev",
            "chardev-386bsd",
            "chardev-4bsd",
            "chardev-bsdos",
            "chardev-bsdos2",
            "chardev-freebsd",
            "chardev-hpux",
            "chardev-isc",
            "chardev-linux",
            "chardev-netbsd",
            "chardev-osf1",
            "chardev-sco",
            "chardev-solaris",
            "chardev-sunos",
            "chardev-svr3",
            "chardev-svr4",
            "chardev-ultrix",
        ]:
            node = volume.get(f"dir/{name}")
            assert node.name == name
            assert node.is_character_device()

    node = volume.get("dir/fifo")
    assert node.name == "fifo"
    assert node.is_fifo()


@pytest.mark.parametrize(
    ("path", "name", "features", "password"),
    [
        pytest.param(
            "_data/case_insensitive.bin.gz",
            "Case Insensitive",
            c_apfs.APFS_INCOMPAT.CASE_INSENSITIVE,
            None,
            id="case-insensitive",
        ),
        pytest.param(
            "_data/case_sensitive.bin.gz",
            "Case Sensitive",
            c_apfs.APFS_INCOMPAT.NORMALIZATION_INSENSITIVE,
            None,
            id="case-sensitive",
        ),
        pytest.param(
            "_data/jhfs_converted.bin.gz",
            "JHFS+ Converted",
            c_apfs.APFS_INCOMPAT.CASE_INSENSITIVE,
            None,
            id="jhfs-converted",
        ),
        pytest.param(
            "_data/encrypted.bin.gz",
            "Encrypted",
            c_apfs.APFS_INCOMPAT.ENC_ROLLED | c_apfs.APFS_INCOMPAT.CASE_INSENSITIVE,
            "password",
            id="encrypted",
        ),
        pytest.param(
            "_data/jhfs_encrypted.bin.gz",
            "JHFS+ Encrypted Converted",
            c_apfs.APFS_INCOMPAT.CASE_INSENSITIVE,
            "password",
            id="jfs-encrypted",
        ),
        pytest.param(
            "_data/case_insensitive_beta.bin.gz",
            "Case Insensitive (beta)",
            c_apfs.APFS_INCOMPAT.CASE_INSENSITIVE,
            None,
            id="case-insensitive-beta",
        ),
        pytest.param(
            "_data/case_sensitive_beta.bin.gz",
            "Case Sensitive (beta)",
            c_apfs.APFS_INCOMPAT(0),
            None,
            id="case-sensitive-beta",
        ),
    ],
)
def test_apfs(path: str, name: str, features: c_apfs.APFS_INCOMPAT, password: str | None) -> None:
    """Test APFS volumes."""
    with gzip.open(absolute_path(path), "rb") as fh:
        container = APFS(fh)
        assert len(container.volumes) == 1

        volume = container.volumes[0]
        assert volume.name == name
        assert volume.incompatible_features == features

        if password:
            assert volume.is_encrypted
            volume.unlock(password)

        _assert_apfs_content(volume, "(beta)" in name)


def test_snapshots() -> None:
    """Test APFS snapshots."""
    with gzip.open(absolute_path("_data/snapshot.bin.gz"), "rb") as fh:
        container = APFS(fh)
        assert len(container.volumes) == 1

        volume = container.volumes[0]
        assert volume.name == "Snapshots"

        assert "file" not in volume.get("/").listdir()

        for i, snapshot in enumerate(volume.snapshots):
            assert snapshot.name == f"Snapshot {i}"
            assert snapshot.open().get("file").open().read() == f"Snapshot {i}\n".encode()
