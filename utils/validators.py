"""
Validation utilities for ThreatLens.

Provides secure, reusable validation functions for uploaded files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename


_FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass(slots=True)
class ValidationResult:
    """
    Result object for file validation checks.
    """

    is_valid: bool
    message: str
    safe_filename: str | None = None
    extension: str | None = None


def _get_extension(filename: str) -> str:
    """
    Extract lowercase extension without leading dot.
    """
    return Path(filename).suffix.lower().lstrip(".")


def validate_file_presence(uploaded_file: FileStorage | None) -> ValidationResult:
    """
    Validate uploaded file presence.

    Args:
        uploaded_file: Werkzeug FileStorage object or None.

    Returns:
        ValidationResult.
    """
    if uploaded_file is None:
        return ValidationResult(is_valid=False, message="No file part in request.")
    return ValidationResult(is_valid=True, message="File part exists.")


def validate_filename(uploaded_file: FileStorage) -> ValidationResult:
    """
    Validate and sanitize filename.

    Args:
        uploaded_file: Incoming uploaded file object.

    Returns:
        ValidationResult including secure filename and extension.
    """
    original_name = (uploaded_file.filename or "").strip()
    if not original_name:
        return ValidationResult(is_valid=False, message="Empty filename provided.")

    sanitized = secure_filename(original_name)
    if not sanitized:
        return ValidationResult(
            is_valid=False,
            message="Invalid filename after sanitization.",
        )

    if not _FILENAME_PATTERN.match(sanitized):
        return ValidationResult(
            is_valid=False,
            message="Filename contains unsupported characters.",
        )

    extension = _get_extension(sanitized)
    if not extension:
        return ValidationResult(
            is_valid=False,
            message="File extension is missing.",
        )

    return ValidationResult(
        is_valid=True,
        message="Filename is valid.",
        safe_filename=sanitized,
        extension=extension,
    )


def validate_extension(extension: str, allowed_extensions: Iterable[str]) -> ValidationResult:
    """
    Validate file extension against allowed set.

    Args:
        extension: Lowercase extension without dot.
        allowed_extensions: Iterable of permitted extensions.

    Returns:
        ValidationResult.
    """
    allowed = {ext.lower().strip() for ext in allowed_extensions}
    if extension.lower() not in allowed:
        return ValidationResult(
            is_valid=False,
            message=f"Unsupported file type: .{extension}",
            extension=extension.lower(),
        )

    return ValidationResult(
        is_valid=True,
        message="Extension is allowed.",
        extension=extension.lower(),
    )


def validate_file_size(file_size_bytes: int, max_size_bytes: int) -> ValidationResult:
    """
    Validate file size boundaries.

    Args:
        file_size_bytes: Actual file size in bytes.
        max_size_bytes: Maximum allowed upload size in bytes.

    Returns:
        ValidationResult.
    """
    if file_size_bytes <= 0:
        return ValidationResult(
            is_valid=False,
            message="Uploaded file is empty.",
        )

    if file_size_bytes > max_size_bytes:
        return ValidationResult(
            is_valid=False,
            message=f"File exceeds maximum allowed size of {max_size_bytes} bytes.",
        )

    return ValidationResult(is_valid=True, message="File size is valid.")


def validate_upload(
    uploaded_file: FileStorage | None,
    allowed_extensions: Iterable[str],
    max_size_bytes: int,
) -> ValidationResult:
    """
    Perform full upload validation workflow.

    Validation checks:
    1) Presence
    2) Filename and sanitization
    3) Extension
    4) Size

    Args:
        uploaded_file: FileStorage object from request.files.
        allowed_extensions: Allowed file extension list/set.
        max_size_bytes: Maximum upload size.

    Returns:
        ValidationResult with safe filename + extension when valid.
    """
    presence_check = validate_file_presence(uploaded_file)
    if not presence_check.is_valid:
        return presence_check

    assert uploaded_file is not None  # Narrowed by presence check

    filename_check = validate_filename(uploaded_file)
    if not filename_check.is_valid:
        return filename_check

    assert filename_check.safe_filename is not None
    assert filename_check.extension is not None

    extension_check = validate_extension(filename_check.extension, allowed_extensions)
    if not extension_check.is_valid:
        return extension_check

    # Determine size without loading content into memory.
    uploaded_file.stream.seek(0, 2)
    file_size = uploaded_file.stream.tell()
    uploaded_file.stream.seek(0)

    size_check = validate_file_size(file_size, max_size_bytes)
    if not size_check.is_valid:
        return size_check

    return ValidationResult(
        is_valid=True,
        message="Upload validation successful.",
        safe_filename=filename_check.safe_filename,
        extension=filename_check.extension,
    )