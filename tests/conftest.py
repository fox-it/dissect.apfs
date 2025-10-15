from __future__ import annotations

import gzip
from pathlib import Path
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def open_file(name: str, mode: str = "rb") -> Iterator[IO]:
    with absolute_path(name).open(mode) as f:
        yield f


def open_file_gz(name: str, mode: str = "rb") -> Iterator[gzip.GzipFile]:
    with gzip.GzipFile(absolute_path(name), mode) as f:
        yield f
