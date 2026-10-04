"""Tests for zipgate. Malformed fixtures are built byte-by-byte so the exact
offending structures (wheel 0.47.0's spurious ZIP64 extra, uv#19440's
overlong extra) are under test control."""

import struct
import zipfile

import pytest

from zipgate import audit_zip
from zipgate.checker import Verdict


def _build_zip(local_extra: bytes = b"", central_extra: bytes = b"") -> bytes:
    """Minimal single-entry zip with controllable extra fields."""
    name = b"hello.txt"
    body = b"hi"
    # local file header: sig, ver, flag, method, time, date, crc, csize, usize, fn_len, ex_len
    lh = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50, 20, 0, 0, 0, 0, 0,
        len(body), len(body), len(name), len(local_extra),
    )
    # central dir: sig, made_ver, need_ver, flag, method, time, date,
    #             crc, csize, usize, fn_len, ex_len, co_len,
    #             disk, int_attr, ext_attr, local_offset
    ch = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50, 20, 20, 0, 0, 0, 0, 0,
        len(body), len(body), len(name), len(central_extra), 0,
        0, 0, 0, 0,
    )
    cd_offset = len(lh) + len(name) + len(local_extra) + len(body)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50, 0, 0, 1, 1,
        len(ch) + len(name) + len(central_extra), cd_offset, 0,
    )
    return (
        lh + name + local_extra + body
        + ch + name + central_extra
        + eocd
    )


def _zip64_extra(payload: bytes) -> bytes:
    return struct.pack("<HH", 0x0001, len(payload)) + payload


def test_valid_plain_zip(tmp_path):
    p = tmp_path / "ok.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("a.txt", "hello")
    r = audit_zip(str(p))
    assert r.verdict is Verdict.VALID, r.findings


def test_valid_handbuilt_zip(tmp_path):
    p = tmp_path / "hand.zip"
    p.write_bytes(_build_zip())
    r = audit_zip(str(p))
    assert r.verdict is Verdict.VALID, r.findings


def test_spurious_zip64_extra_in_local_header(tmp_path):
    """pypa/wheel#692: wheel 0.47.0 wrote an 8-byte ZIP64 extra into local
    headers whose 32-bit sizes were fine."""
    p = tmp_path / "spurious.zip"
    p.write_bytes(_build_zip(local_extra=_zip64_extra(b"\x00" * 8)))
    r = audit_zip(str(p))
    assert r.verdict is Verdict.INVALID
    assert any(f.rule == "SPURIOUS_ZIP64_LOCAL" for f in r.findings)


def test_overlong_zip64_extra(tmp_path):
    """uv#19440 class: ZIP64 extra longer than the maxed-out fields require."""
    p = tmp_path / "overlong.zip"
    # claim both sizes are 0xFFFFFFFF in central dir? No — simpler: local
    # header maxes one 32-bit size (needs 8 bytes) but carries 24.
    name = b"x.txt"
    body = b"data"
    lh = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50, 20, 0, 0, 0, 0, 0,
        0xFFFFFFFF, len(body), len(name), 4 + 24,
    )
    local_extra = _zip64_extra(b"\x00" * 24)  # 8 needed, 24 present
    ch = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50, 20, 20, 0, 0, 0, 0, 0,
        0xFFFFFFFF, len(body), len(name), 0, 0,
        0, 0, 0, 0,
    )
    cd_offset = len(lh) + len(name) + len(local_extra) + len(body)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(ch) + len(name), cd_offset, 0)
    p.write_bytes(lh + name + local_extra + body + ch + name + eocd)
    r = audit_zip(str(p))
    assert r.verdict is Verdict.INVALID
    assert any(f.rule == "ZIP64_LENGTH_MISMATCH" for f in r.findings)


def test_missing_file():
    r = audit_zip("/nonexistent/file.zip")
    assert r.verdict is Verdict.UNREADABLE


def test_not_a_zip(tmp_path):
    p = tmp_path / "nope.zip"
    p.write_bytes(b"this is not a zip file at all")
    r = audit_zip(str(p))
    assert r.verdict is Verdict.UNREADABLE


def test_size_mismatch(tmp_path):
    """Central directory disagrees with local header on compressed size."""
    name = b"m.txt"
    body = b"12345678"
    lh = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50, 20, 0, 0, 0, 0, 0,
        len(body), len(body), len(name), 0,
    )
    ch = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50, 20, 20, 0, 0, 0, 0, 0,
        999, len(body), len(name), 0, 0,  # central claims 999
        0, 0, 0, 0,
    )
    cd_offset = len(lh) + len(name) + len(body)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(ch) + len(name), cd_offset, 0)
    p = tmp_path / "mismatch.zip"
    p.write_bytes(lh + name + body + ch + name + eocd)
    r = audit_zip(str(p))
    assert r.verdict is Verdict.INVALID
    assert any(f.rule == "SIZE_MISMATCH" for f in r.findings)


def test_cli_exit_codes(tmp_path, capsys):
    from zipgate.cli import main

    ok = tmp_path / "ok.zip"
    with zipfile.ZipFile(ok, "w") as z:
        z.writestr("a.txt", "x")
    bad = tmp_path / "bad.zip"
    bad.write_bytes(_build_zip(local_extra=_zip64_extra(b"\x00" * 8)))

    assert main([str(ok)]) == 0
    assert main([str(bad)]) == 1
    assert main([str(tmp_path / "missing.zip")]) == 2
    out = capsys.readouterr().out
    assert "SPURIOUS_ZIP64_LOCAL" in out
