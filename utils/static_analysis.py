import math
import re
from pathlib import Path
from typing import Any, Dict, List


SEVERITY_WEIGHTS = {
    "critical": 15,
    "high": 8,
    "medium": 4,
    "low": 1,
}

SUSPICIOUS_PATTERNS = [
    {
        "name": "process_injection",
        "regex": r"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|NtUnmapViewOfSection",
        "severity": "critical",
        "description": "Critical process injection and memory manipulation APIs detected",
    },
    {
        "name": "powershell_obfuscated",
        "regex": r"powershell.*-enc|pwsh.*-encodedcommand|bypass.*-nop",
        "severity": "high",
        "description": "Obfuscated or bypassed PowerShell execution command detected",
    },
    {
        "name": "registry_persistence",
        "regex": r"reg\s+add.*\\Run|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "severity": "high",
        "description": "Windows autostart registry persistence modification detected",
    },
    {
        "name": "download_execute",
        "regex": r"Invoke-WebRequest.*\||bitsadmin.*/transfer|certutil.*-urlcache",
        "severity": "high",
        "description": "Command-line file downloader utility pattern detected",
    },
    {
        "name": "script_eval",
        "regex": r"eval\(|exec\(|fromcharcode|base64_decode",
        "severity": "medium",
        "description": "Dynamic script evaluation or obfuscation keyword detected",
    },
    {
        "name": "shell_command",
        "regex": r"cmd\.exe\s+/c|powershell\.exe",
        "severity": "low",
        "description": "Standard system command shell invocation reference",
    },
]


def calculate_file_entropy(file_path: str | Path) -> float:
    """
    Calculate Shannon entropy of file bytes via chunked streaming.
    Returns value between 0.0 and 8.0.
    """
    path = Path(file_path)
    if not path.exists():
        return 0.0

    file_size = path.stat().st_size
    if file_size == 0:
        return 0.0

    byte_counts = [0] * 256
    total_bytes = 0

    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            total_bytes += len(chunk)
            for b in chunk:
                byte_counts[b] += 1

    if total_bytes == 0:
        return 0.0

    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / total_bytes
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def _extract_strings(file_bytes: bytes, min_length: int = 4) -> str:
    """
    Extract printable ASCII strings and join into one text blob.
    """
    pattern = rb"[ -~]{%d,}" % min_length
    matches = re.findall(pattern, file_bytes)
    return "\n".join(s.decode("utf-8", errors="ignore") for s in matches)


def analyze_suspicious_indicators(file_path: str | Path) -> Dict[str, Any]:
    """
    Scan extracted strings for suspicious behavior indicators with weighted severity scores.
    """
    path = Path(file_path)
    if not path.exists():
        return {"suspicious_indicators": [], "risk_flags_count": 0, "total_static_weight": 0}

    file_size = path.stat().st_size
    scan_size = min(file_size, 15 * 1024 * 1024)
    with path.open("rb") as f:
        file_bytes = f.read(scan_size)

    extracted_text = _extract_strings(file_bytes)

    indicators: List[Dict[str, Any]] = []
    total_static_weight = 0

    for item in SUSPICIOUS_PATTERNS:
        if re.search(item["regex"], extracted_text, flags=re.IGNORECASE):
            weight = SEVERITY_WEIGHTS.get(item["severity"], 1)
            total_static_weight += weight
            indicators.append(
                {
                    "pattern": item["name"],
                    "severity": item["severity"].upper(),
                    "weight": weight,
                    "description": item["description"],
                }
            )

    return {
        "suspicious_indicators": indicators,
        "risk_flags_count": len(indicators),
        "total_static_weight": total_static_weight,
    }