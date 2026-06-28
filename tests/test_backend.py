import io
from pathlib import Path
import pytest
from werkzeug.datastructures import FileStorage

from utils.validators import validate_upload, validate_file_presence, validate_filename, validate_extension, validate_file_size
from utils.hashes import generate_file_hashes
from utils.metadata import extract_file_metadata
from utils.static_analysis import calculate_file_entropy, analyze_suspicious_indicators


def test_validate_file_presence():
    res = validate_file_presence(None)
    assert not res.is_valid
    assert res.message == "No file part in request."


def test_validate_filename_valid():
    file_obj = FileStorage(stream=io.BytesIO(b"test"), filename="sample.pdf")
    res = validate_filename(file_obj)
    assert res.is_valid
    assert res.safe_filename == "sample.pdf"
    assert res.extension == "pdf"


def test_validate_filename_empty():
    file_obj = FileStorage(stream=io.BytesIO(b"test"), filename="")
    res = validate_filename(file_obj)
    assert not res.is_valid


def test_validate_extension():
    res = validate_extension("pdf", ["pdf", "exe"])
    assert res.is_valid
    res_bad = validate_extension("txt", ["pdf", "exe"])
    assert not res_bad.is_valid


def test_validate_file_size():
    res = validate_file_size(100, 1000)
    assert res.is_valid
    res_zero = validate_file_size(0, 1000)
    assert not res_zero.is_valid
    res_large = validate_file_size(2000, 1000)
    assert not res_large.is_valid


def test_hash_generation_and_metadata(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Hello ThreatLens Cyber Intelligence!")

    hashes = generate_file_hashes(test_file)
    assert "md5" in hashes
    assert "sha1" in hashes
    assert "sha256" in hashes
    assert len(hashes["sha256"]) == 64

    meta = extract_file_metadata(test_file)
    assert meta["filename"] == "test.txt"
    assert meta["file_size"] == len(b"Hello ThreatLens Cyber Intelligence!")


def test_static_analysis(tmp_path):
    suspicious_file = tmp_path / "mal.bat"
    suspicious_file.write_bytes(b"powershell -encodedcommand ABCDEF123456")

    entropy = calculate_file_entropy(suspicious_file)
    assert isinstance(entropy, float)

    analysis = analyze_suspicious_indicators(suspicious_file)
    assert analysis["risk_flags_count"] >= 1
    indicators = [ind["pattern"] for ind in analysis["suspicious_indicators"]]
    assert "powershell_obfuscated" in indicators


def test_malwarebazaar_client():
    from services.malwarebazaar import MalwareBazaarClient
    client = MalwareBazaarClient()
    res = client.query_hash("")
    assert not res["found"]
    assert res["malware_family"] == "None Detected"


def test_heuristics(tmp_path):
    from utils.heuristics import inspect_file_heuristics
    test_bin = tmp_path / "test.exe"
    test_bin.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00PE\x00\x00\\.UPX0")
    res = inspect_file_heuristics(test_bin)
    assert res["success"]
    assert res["has_pe_header"]
    assert res["is_packed"]


def test_security_headers():
    from app import app
    with app.test_client() as client:
        res = client.get("/api/v1/health")
        assert res.status_code == 200
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert res.headers.get("X-Frame-Options") == "SAMEORIGIN"
