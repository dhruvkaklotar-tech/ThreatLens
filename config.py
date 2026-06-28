"""
Configuration module for ThreatLens.

Loads and validates environment-backed runtime settings for the Flask
application and supporting services.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import FrozenSet

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True, slots=True)
class Config:
    """
    Immutable application configuration loaded from environment variables.
    """

    APP_NAME: str = os.getenv("APP_NAME", "ThreatLens")
    APP_ENV: str = os.getenv("APP_ENV", "production")
    DEBUG: bool = os.getenv("DEBUG", "false").strip().lower() == "true"

    VIRUSTOTAL_BASE_URL: str = os.getenv(
        "VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3"
    ).rstrip("/")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    MALWAREBAZAAR_BASE_URL: str = os.getenv(
        "MALWAREBAZAAR_BASE_URL", "https://mb-api.abuse.ch/api/v1"
    ).rstrip("/")

    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "").strip()

    ALLOWED_EXTENSIONS: FrozenSet[str] = frozenset(
        ext.strip().lower()
        for ext in os.getenv(
            "ALLOWED_EXTENSIONS", "exe,dll,pdf,zip,docx,apk,js,bat,py"
        ).split(",")
        if ext.strip()
    )

    MAX_UPLOAD_SIZE: int = int(os.getenv("MAX_UPLOAD_SIZE", str(200 * 1024 * 1024)))
    REQUEST_TIMEOUT_SECONDS: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30"))
    POLLING_ATTEMPTS: int = int(os.getenv("POLLING_ATTEMPTS", "15"))
    POLLING_INTERVAL_SECONDS: int = int(os.getenv("POLLING_INTERVAL_SECONDS", "2"))

    UPLOAD_FOLDER: str = os.getenv("UPLOAD_FOLDER", "uploads")
    REPORT_FOLDER: str = os.getenv("REPORT_FOLDER", "reports")

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    LOG_FORMAT: str = os.getenv(
        "LOG_FORMAT",
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    @property
    def flask_secret_key(self) -> str:
        """
        Return Flask secret key with a safe default fallback.
        """
        return os.getenv("FLASK_SECRET_KEY", "change-this-in-production")

    @property
    def is_production(self) -> bool:
        """
        Check whether app runs in production environment.
        """
        return self.APP_ENV.lower() == "production"


def ensure_runtime_directories(config: Config) -> None:
    """
    Ensure upload/report directories exist before app runtime starts.
    """
    os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(config.REPORT_FOLDER, exist_ok=True)


def configure_logging(config: Config) -> None:
    """
    Configure root logging from config.
    """
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL, logging.INFO),
        format=config.LOG_FORMAT,
    )