"""
Metadata extraction utilities for ThreatLens.
"""

from __future__ import annotations

import datetime as dt
import mimetypes
from pathlib import Path
from typing import Any, Dict


def _to_iso8601(epoch_time: float) -> str:
    """
    Convert epoch timestamp to UTC ISO-8601 string.
    """
    return dt.datetime.fromtimestamp(epoch_time, tz=dt.timezone.utc).isoformat()


def extract_file_metadata(file_path: str | Path) -> Dict[str, Any]:
    """
    Extract metadata for a file on disk.

    Returned fields:
    - filename
    - extension
    - file_size
    - mime_type
    - creation_time
    - modification_time
    - access_time

    Args:
        file_path: Absolute or relative path to file.

    Returns:
        Metadata dictionary suitable for JSON responses.

    Raises:
        FileNotFoundError: If file does not exist.
        OSError: If file stat operations fail.
    """
    path = Path(file_path)
    stat_info = path.stat()

    mime_type, _ = mimetypes.guess_type(path.name)
    if not mime_type:
        mime_type = "application/octet-stream"

    return {
        "filename": path.name,
        "extension": path.suffix.lower().lstrip("."),
        "file_size": stat_info.st_size,
        "mime_type": mime_type,
        "creation_time": _to_iso8601(stat_info.st_ctime),
        "modification_time": _to_iso8601(stat_info.st_mtime),
        "access_time": _to_iso8601(stat_info.st_atime),
    }