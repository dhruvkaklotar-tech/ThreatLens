"""
Hash generation utilities for ThreatLens.

This module computes MD5, SHA1, and SHA256 in a single pass over the file
to optimize performance and reduce I/O overhead.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO, Dict


CHUNK_SIZE = 1024 * 1024  # 1 MB chunks for efficient memory usage


def _compute_hashes_from_stream(stream: BinaryIO) -> Dict[str, str]:
    """
    Compute MD5, SHA1, and SHA256 digests from a binary stream in one pass.

    Args:
        stream: Open binary stream positioned at the beginning of file content.

    Returns:
        Dictionary containing md5, sha1, and sha256 hex digests.
    """
    md5_hasher = hashlib.md5()
    sha1_hasher = hashlib.sha1()
    sha256_hasher = hashlib.sha256()

    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        md5_hasher.update(chunk)
        sha1_hasher.update(chunk)
        sha256_hasher.update(chunk)

    return {
        "md5": md5_hasher.hexdigest(),
        "sha1": sha1_hasher.hexdigest(),
        "sha256": sha256_hasher.hexdigest(),
    }


def generate_file_hashes(file_path: str | Path) -> Dict[str, str]:
    """
    Generate MD5, SHA1, and SHA256 for the given file path.

    The file is read exactly once.

    Args:
        file_path: Path to file on disk.

    Returns:
        Dictionary with hash values:
        {
            "md5": "...",
            "sha1": "...",
            "sha256": "..."
        }

    Raises:
        FileNotFoundError: If file does not exist.
        OSError: For low-level I/O errors.
    """
    file_path = Path(file_path)
    with file_path.open("rb") as f:
        return _compute_hashes_from_stream(f)