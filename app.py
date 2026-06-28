"""
ThreatLens Flask application entrypoint.

Provides:
- File upload endpoint
- Validation workflow
- Hash + metadata extraction
- VirusTotal analysis integration
- Structured JSON responses
- Centralized error handling
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

import requests
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from config import Config, configure_logging, ensure_runtime_directories
from services.malwarebazaar import MalwareBazaarClient, MalwareBazaarConfig
from services.virustotal import (
    VirusTotalClient,
    VirusTotalConfig,
    VirusTotalError,
    VirusTotalRateLimitError,
    VirusTotalResponseError,
    VirusTotalTimeoutError,
)
from utils.hashes import generate_file_hashes
from utils.heuristics import inspect_file_heuristics
from utils.metadata import extract_file_metadata
from utils.static_analysis import calculate_file_entropy, analyze_suspicious_indicators
from utils.validators import validate_upload

config = Config()
configure_logging(config)
ensure_runtime_directories(config)

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_SIZE
app.config["SECRET_KEY"] = config.flask_secret_key


@app.after_request
def add_security_headers(response: Any) -> Any:
    """
    Inject OWASP security hardening headers into all application responses.
    """
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

vt_client = VirusTotalClient(
    VirusTotalConfig(
        base_url=config.VIRUSTOTAL_BASE_URL,
        api_key=config.VIRUSTOTAL_API_KEY,
        request_timeout_seconds=config.REQUEST_TIMEOUT_SECONDS,
        polling_attempts=config.POLLING_ATTEMPTS,
        polling_interval_seconds=config.POLLING_INTERVAL_SECONDS,
    )
)

mb_client = MalwareBazaarClient(
    MalwareBazaarConfig(
        base_url=config.MALWAREBAZAAR_BASE_URL,
        request_timeout_seconds=config.REQUEST_TIMEOUT_SECONDS,
    )
)


def _json_error(message: str, status_code: int) -> Tuple[Any, int]:
    return jsonify({"success": False, "error": message}), status_code


def _build_success_response(
    file_info: Dict[str, Any],
    hashes: Dict[str, str],
    metadata: Dict[str, Any],
    analysis: Dict[str, Any],
) -> Tuple[Any, int]:
    verdict = analysis.get("verdict", "Safe")
    verdict_color_map = {
        "Safe": "#16a34a",
        "Suspicious": "#f59e0b",
        "Malicious": "#dc2626",
    }

    payload = {
        "success": True,
        "file": {
            "filename": file_info.get("filename", ""),
            "size": int(file_info.get("size", 0)),
            "extension": file_info.get("extension", ""),
        },
        "hashes": {
            "md5": hashes.get("md5", ""),
            "sha1": hashes.get("sha1", ""),
            "sha256": hashes.get("sha256", ""),
        },
        "metadata": {
            "filename": metadata.get("filename", ""),
            "extension": metadata.get("extension", ""),
            "file_size": int(metadata.get("file_size", 0)),
            "mime_type": metadata.get("mime_type", "application/octet-stream"),
            "creation_time": metadata.get("creation_time", ""),
            "modification_time": metadata.get("modification_time", ""),
            "access_time": metadata.get("access_time", ""),
        },
        "analysis": {
            "verdict": verdict,
            "verdict_color": verdict_color_map.get(verdict, "#16a34a"),
            "threat_score": int(analysis.get("threat_score", 0)),
            "detection_ratio": analysis.get("detection_ratio", "0/0"),
            "stats": analysis.get(
                "stats",
                {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "timeout": 0,
                    "failure": 0,
                    "type_unsupported": 0,
                    "confirmed_timeout": 0,
                    "total_engines": 0,
                },
            ),
            "entropy_score": float(analysis.get("entropy_score", 0.0)),
            "suspicious_indicators": analysis.get("suspicious_indicators", []),
            "risk_flags_count": int(analysis.get("risk_flags_count", 0)),
            "engines": analysis.get("engines", []),
            "meaningful_name": analysis.get("meaningful_name", ""),
            "magic": analysis.get("magic", ""),
            "times_submitted": int(analysis.get("times_submitted", 0)),
            "reputation": int(analysis.get("reputation", 0)),
            "file_type": analysis.get("file_type", ""),
            "threat_intelligence": analysis.get(
                "threat_intelligence",
                {
                    "found": False,
                    "malware_family": "None Detected",
                    "tags": [],
                    "intelligence_source": "Global Threat Intelligence Network",
                },
            ),
        },
    }
    return jsonify(payload), 200


def _persist_report(filename_stem: str, report_data: Dict[str, Any]) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_filename = f"{filename_stem}_{timestamp}.json"
    report_path = Path(config.REPORT_FOLDER) / report_filename
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
    return str(report_path)


def _analyze_uploaded_file(file_storage: Any) -> Tuple[Dict[str, Any], int]:
    logger.info("Starting upload processing.")

    validation = validate_upload(
        uploaded_file=file_storage,
        allowed_extensions=config.ALLOWED_EXTENSIONS,
        max_size_bytes=config.MAX_UPLOAD_SIZE,
    )
    if not validation.is_valid:
        logger.warning("Validation failed: %s", validation.message)
        return {"success": False, "error": validation.message}, 400

    safe_filename = validation.safe_filename
    extension = validation.extension
    if not safe_filename or not extension:
        logger.error("Validation state invalid: missing safe filename or extension.")
        return {"success": False, "error": "Invalid upload state."}, 400

    upload_path = Path(config.UPLOAD_FOLDER) / safe_filename
    logger.info("Saving uploaded file: %s", upload_path)
    file_storage.save(upload_path)

    try:
        logger.info("Generating hashes for file=%s", upload_path)
        hashes = generate_file_hashes(upload_path)

        logger.info("Extracting metadata for file=%s", upload_path)
        metadata = extract_file_metadata(upload_path)

        logger.info("Calculating entropy for file=%s", upload_path)
        entropy_score = calculate_file_entropy(upload_path)
        suspicious_result = analyze_suspicious_indicators(upload_path)

        if not config.VIRUSTOTAL_API_KEY:
            logger.error("VirusTotal API key missing in environment configuration.")
            return {"success": False, "error": "VirusTotal API key is not configured."}, 500

        logger.info("Submitting file for VirusTotal analysis.")
        vt_result = vt_client.analyze_file(
            file_path=str(upload_path),
            sha256_hash=hashes["sha256"],
            local_hashes=hashes,
            local_metadata=metadata,
        )

        logger.info("Querying MalwareBazaar threat intelligence.")
        mb_intel = mb_client.query_hash(hashes["sha256"])

        analysis = vt_result.get("analysis", {})
        if not mb_intel.get("found") and analysis.get("suggested_threat_label"):
            mb_intel["malware_family"] = analysis["suggested_threat_label"]
            mb_intel["found"] = True
            mb_intel["intelligence_source"] = "Multi-Engine Threat Classification"

        analysis["entropy_score"] = float(entropy_score)
        analysis["suspicious_indicators"] = suspicious_result.get("suspicious_indicators", [])
        analysis["risk_flags_count"] = int(suspicious_result.get("risk_flags_count", 0))
        analysis["threat_intelligence"] = mb_intel

        stats = analysis.get("stats", {}) or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        static_weight = int(suspicious_result.get("total_static_weight", 0))
        entropy_val = float(analysis.get("entropy_score", 0.0))

        # Entropy modifier: Only add entropy points if there are actual AV detections
        entropy_modifier = 5 if (entropy_val >= 7.2 and (malicious + suspicious > 0)) else 0

        # Calculate Threat Score using Weighted Multi-Factor Formula
        score = min(
            100,
            malicious * 25 + suspicious * 10 + static_weight + entropy_modifier,
        )
        analysis["threat_score"] = int(score)

        # Multi-Tier Consensus Verdict Decision Matrix
        if malicious >= 2 or (malicious >= 1 and score >= 30):
            analysis["verdict"] = "Malicious"
        elif malicious == 1 or suspicious >= 2 or (malicious + suspicious == 0 and static_weight >= 25):
            analysis["verdict"] = "Suspicious"
        else:
            analysis["verdict"] = "Safe"

        analysis["verdict_color"] = {
            "Safe": "#16a34a",
            "Suspicious": "#f59e0b",
            "Malicious": "#dc2626",
        }.get(analysis["verdict"], "#16a34a")

        normalized_hashes = vt_result.get("hashes", hashes)
        normalized_metadata = vt_result.get("metadata", metadata)

        file_info = {
            "filename": safe_filename,
            "extension": extension,
            "size": normalized_metadata.get("file_size", 0),
        }

        response_payload = {
            "success": True,
            "file": file_info,
            "hashes": normalized_hashes,
            "metadata": normalized_metadata,
            "analysis": analysis,
        }

        report_path = _persist_report(Path(safe_filename).stem, response_payload)
        logger.info("Report saved: %s", report_path)

        return response_payload, 200

    except VirusTotalRateLimitError as exc:
        logger.warning("VirusTotal rate limit error: %s", exc)
        return {"success": False, "error": str(exc)}, 429
    except VirusTotalTimeoutError as exc:
        logger.error("VirusTotal timeout error: %s", exc)
        return {"success": False, "error": str(exc)}, 504
    except VirusTotalResponseError as exc:
        logger.error("VirusTotal response error: %s", exc)
        return {"success": False, "error": str(exc)}, 502
    except VirusTotalError as exc:
        logger.error("VirusTotal service error: %s", exc)
        return {"success": False, "error": str(exc)}, 502
    except (OSError, ValueError, KeyError) as exc:
        logger.exception("File processing error: %s", exc)
        return {"success": False, "error": "Failed to process uploaded file."}, 500
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled processing exception: %s", exc)
        return {"success": False, "error": "Internal server error."}, 500


@app.route("/", methods=["GET"])
def index() -> Any:
    return render_template("index.html", app_name=config.APP_NAME)


@app.route("/api/v1/health", methods=["GET"])
def api_v1_health() -> Tuple[Any, int]:
    return jsonify({"success": True, "version": "v1", "status": "ok"}), 200


@app.route("/api/v1/analyze", methods=["POST"])
def analyze_file_route() -> Tuple[Any, int]:
    uploaded_file = request.files.get("file")
    response_data, status_code = _analyze_uploaded_file(uploaded_file)

    if not response_data.get("success", False):
        return _json_error(response_data.get("error", "Unknown error"), status_code)

    return _build_success_response(
        file_info=response_data["file"],
        hashes=response_data["hashes"],
        metadata=response_data["metadata"],
        analysis=response_data["analysis"],
    )


@app.route("/api/v1/result/<sha256_hash>", methods=["GET"])
def get_result_by_hash(sha256_hash: str) -> Tuple[Any, int]:
    """
    Fetch latest analysis result from VirusTotal using SHA-256 hash.
    Useful when initial upload returns pending/timeout.
    """
    try:
        if not config.VIRUSTOTAL_API_KEY:
            return _json_error("VirusTotal API key is not configured.", 500)

        vt_result = vt_client.get_file_report_by_hash(sha256_hash)
        analysis = vt_result.get("analysis", {})

        mb_intel = mb_client.query_hash(sha256_hash)
        if not mb_intel.get("found") and analysis.get("suggested_threat_label"):
            mb_intel["malware_family"] = analysis["suggested_threat_label"]
            mb_intel["found"] = True
            mb_intel["intelligence_source"] = "Multi-Engine Threat Classification"
        analysis["threat_intelligence"] = mb_intel

        analysis.setdefault("entropy_score", 0.0)
        analysis.setdefault("suspicious_indicators", [])
        analysis.setdefault("risk_flags_count", 0)
        analysis.setdefault("threat_score", 0)
        analysis.setdefault("verdict", "Safe")
        analysis.setdefault("verdict_color", "#16a34a")
        analysis.setdefault("detection_ratio", "0/0")
        analysis.setdefault("stats", {})
        analysis.setdefault("engines", [])

        payload = {
            "success": True,
            "source": "virustotal_hash_lookup",
            "hashes": vt_result.get("hashes", {"sha256": sha256_hash}),
            "metadata": vt_result.get("metadata", {}),
            "analysis": analysis,
        }
        return jsonify(payload), 200

    except VirusTotalRateLimitError as exc:
        return _json_error(str(exc), 429)
    except VirusTotalTimeoutError as exc:
        return _json_error(str(exc), 504)
    except VirusTotalResponseError as exc:
        return _json_error(str(exc), 502)
    except VirusTotalError as exc:
        return _json_error(str(exc), 502)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Hash lookup failed: %s", exc)
        return _json_error("Internal server error.", 500)


@app.route("/api/v1/heuristics", methods=["POST"])
def analyze_heuristics_route() -> Tuple[Any, int]:
    """
    Execute deep YARA signature and heuristic binary inspection on uploaded file.
    """
    uploaded_file = request.files.get("file")
    validation = validate_upload(
        uploaded_file=uploaded_file,
        allowed_extensions=config.ALLOWED_EXTENSIONS,
        max_size_bytes=config.MAX_UPLOAD_SIZE,
    )
    if not validation.is_valid or not uploaded_file:
        return _json_error(validation.message or "Invalid file.", 400)

    safe_filename = validation.safe_filename or "sample.bin"
    upload_path = Path(config.UPLOAD_FOLDER) / safe_filename
    uploaded_file.save(upload_path)

    result = inspect_file_heuristics(upload_path)
    return jsonify(result), 200


@app.route("/api/v1/ai-analysis", methods=["POST"])
def generate_ai_analysis_route() -> Tuple[Any, int]:
    """
    Synthesize plain-English AI Security Advisor report and SOC SOP checklist from analysis JSON.
    Implements a Bulletproof Hybrid Engine (Live Cloud LLM API with automated local CTI fallback).
    """
    data = request.get_json(silent=True) or {}
    analysis = data.get("analysis", {})
    file_data = data.get("file", {})
    verdict = analysis.get("verdict", "Safe")
    filename = file_data.get("filename", "Uploaded Sample")
    score = analysis.get("threat_score", 0)
    family = analysis.get("threat_intelligence", {}).get("malware_family") or analysis.get("suggested_threat_label") or "Generic"

    # Try Live Cloud LLM API Generation if API key is configured
    if config.GEMINI_API_KEY:
        try:
            logger.info("Querying Live Cloud LLM (Google Gemini API) for AI Advisor report.")
            prompt = (
                f"You are an expert SOC Cybersecurity AI Advisor. Analyze this threat sample report:\n"
                f"Filename: {filename}, Verdict: {verdict}, Threat Score: {score}/100, Malware Family: {family}.\n"
                f"Provide a concise JSON output with keys 'executive_briefing' (2 sentences), 'potential_impact' (1 sentence), "
                f"and 'soc_sop_checklist' (list of 4 actionable SOC remediation steps)."
            )
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={config.GEMINI_API_KEY}"
            payload = {"contents": [{"parts": [{"text": prompt}]}]}
            res = requests.post(url, json=payload, timeout=6)
            if res.status_code == 200:
                cloud_data = res.json()
                raw_text = cloud_data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                if raw_text:
                    # Parse JSON block from LLM markdown formatting if present
                    clean_json = raw_text.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
                    parsed = json.loads(clean_json)
                    return jsonify({
                        "success": True,
                        "filename": filename,
                        "verdict": verdict,
                        "executive_briefing": parsed.get("executive_briefing", f"Live AI Briefing for {filename} ({verdict})."),
                        "potential_impact": parsed.get("potential_impact", f"Impact risk level aligned with score {score}/100."),
                        "soc_sop_checklist": parsed.get("soc_sop_checklist", ["Verify isolation", "Monitor network"]),
                        "generated_by": "ThreatLens Cyber AI Advisor"
                    }), 200
        except Exception as exc:
            logger.warning("Live Cloud LLM API query encountered exception, activating local fallback: %s", exc)

    # Local CTI Expert Synthesis Engine (Automated Zero-Downtime Fallback)
    if verdict == "Malicious":
        briefing = f"Sample '{filename}' is classified as HIGH-RISK MALWARE associated with the '{family}' threat signature family (Threat Score: {score}/100). The binary exhibits critical execution patterns consistent with malicious compromise."
        impact = "Critical Threat. Potential unauthorized system access, data exfiltration, or secondary payload deployment."
        sops = [
            "IMMEDIATE ACTION: Isolate infected host machine from local subnet and domain network.",
            f"FIREWALL: Add SHA-256 hash to corporate endpoint protection blocklist immediately.",
            "FORENSICS: Capture volatile memory dump (RAM) prior to system termination.",
            "REMEDIATION: Perform complete system reimaging and reset exposed user credentials."
        ]
    elif verdict == "Suspicious":
        briefing = f"Sample '{filename}' flagged as SUSPICIOUS (Threat Score: {score}/100). Exhibits anomalous structural characteristics, such as elevated entropy or shell command references."
        impact = "Moderate Risk. May contain packed resources, dynamic execution routines, or unwanted software."
        sops = [
            "SANDBOXING: Execute binary strictly within an isolated, non-production virtual sandbox.",
            "AUTHENTICITY CHECK: Verify digital code signing certificates and publisher identity.",
            "MONITORING: Audit process creation and outgoing TCP network connections during execution."
        ]
    else:
        briefing = f"Sample '{filename}' evaluated as SAFE (Threat Score: {score}/100). No malicious signatures, ransomware heuristics, or abnormal entropy patterns were detected across multi-engine databases."
        impact = "Low/Zero Risk. File structure aligns with standard safe software standards."
        sops = [
            "STANDARD CLEARANCE: File is cleared for standard operational deployment.",
            "BEST PRACTICE: Maintain routine endpoint security monitoring and software updating."
        ]

    return jsonify({
        "success": True,
        "filename": filename,
        "verdict": verdict,
        "executive_briefing": briefing,
        "potential_impact": impact,
        "soc_sop_checklist": sops,
        "generated_by": "ThreatLens Cyber AI Advisor"
    }), 200


@app.errorhandler(404)
def handle_not_found(_: Exception) -> Tuple[Any, int]:
    return _json_error("Resource not found.", 404)


@app.errorhandler(405)
def handle_method_not_allowed(_: Exception) -> Tuple[Any, int]:
    return _json_error("Method not allowed.", 405)


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(_: RequestEntityTooLarge) -> Tuple[Any, int]:
    return _json_error(
        f"File is too large. Maximum allowed size is {config.MAX_UPLOAD_SIZE} bytes.",
        413,
    )


@app.errorhandler(429)
def handle_too_many_requests(_: Exception) -> Tuple[Any, int]:
    return _json_error("Too many requests. Please retry later.", 429)


@app.errorhandler(500)
def handle_internal_server_error(_: Exception) -> Tuple[Any, int]:
    return _json_error("Internal server error.", 500)


if __name__ == "__main__":
    logger.info(
        "Starting %s environment=%s debug=%s",
        config.APP_NAME,
        config.APP_ENV,
        config.DEBUG,
    )
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=config.DEBUG)