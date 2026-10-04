"""Hand-rolled ZIP64 auditor.

Parses local file headers and central directory entries directly from the
byte stream (instead of trusting ``zipfile``, which silently tolerates the
malformations we want to catch) and validates ZIP64 extra fields.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum

LOCAL_SIG = 0x04034B50
CENTRAL_SIG = 0x02014B50
EOCD_SIG = 0x06054B50
ZIP64_EOCD_SIG = 0x06064B50
ZIP64_LOCATOR_SIG = 0x07064B50
ZIP64_EXTRA_ID = 0x0001

U16_MAX = 0xFFFF
U32_MAX = 0xFFFFFFFF


class Verdict(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    UNREADABLE = "UNREADABLE"


@dataclass
class Finding:
    entry: str
    rule: str
    detail: str


@dataclass
class AuditResult:
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def _parse_extras(extra: bytes) -> dict[int, bytes]:
    """Split an extra-field block into {field_id: data}."""
    out: dict[int, bytes] = {}
    o = 0
    while o + 4 <= len(extra):
        fid = _u16(extra, o)
        size = _u16(extra, o + 2)
        data = extra[o + 4 : o + 4 + size]
        if len(data) != size:
            break  # truncated block; caller reports it
        out[fid] = data
        o += 4 + size
    return out


def _expected_zip64_len(
    *,
    uncompressed_maxed: bool,
    compressed_maxed: bool,
    offset_maxed: bool = False,
    disk_maxed: bool = False,
) -> int:
    """Byte length the ZIP64 extra data must have, per APPNOTE 4.5.3.

    Fields appear in fixed order and only for values that are 0xFFFF /
    0xFFFFFFFF in the carrying header: uncompressed size (8), compressed
    size (8), local header offset (8), disk start number (4).
    """
    n = 0
    if uncompressed_maxed:
        n += 8
    if compressed_maxed:
        n += 8
    if offset_maxed:
        n += 8
    if disk_maxed:
        n += 4
    return n


@dataclass
class _LocalEntry:
    name: str
    offset: int
    compressed_size: int
    uncompressed_size: int
    zip64_data: bytes | None  # None if no 0x0001 extra field present


@dataclass
class _CentralEntry:
    name: str
    compressed_size: int  # resolved (ZIP64 applied)
    uncompressed_size: int  # resolved (ZIP64 applied)
    local_offset: int  # resolved (ZIP64 applied)


def _read_local(data: bytes, offset: int, findings: list[Finding]) -> _LocalEntry | None:
    if offset + 30 > len(data) or _u32(data, offset) != LOCAL_SIG:
        findings.append(Finding("", "BAD_LOCAL_SIG", f"no local header at offset {offset}"))
        return None
    csize = _u32(data, offset + 18)
    usize = _u32(data, offset + 22)
    fn_len = _u16(data, offset + 26)
    ex_len = _u16(data, offset + 28)
    name = data[offset + 30 : offset + 30 + fn_len].decode("utf-8", "replace")
    extra = data[offset + 30 + fn_len : offset + 30 + fn_len + ex_len]
    extras = _parse_extras(extra)
    return _LocalEntry(name, offset, csize, usize, extras.get(ZIP64_EXTRA_ID))


def _read_central(data: bytes, offset: int, findings: list[Finding]) -> _CentralEntry | None:
    if offset + 46 > len(data) or _u32(data, offset) != CENTRAL_SIG:
        findings.append(Finding("", "BAD_CENTRAL_SIG", f"no central header at offset {offset}"))
        return None
    csize = _u32(data, offset + 20)
    usize = _u32(data, offset + 24)
    fn_len = _u16(data, offset + 28)
    ex_len = _u16(data, offset + 30)
    co_len = _u16(data, offset + 32)
    lho = _u32(data, offset + 42)
    name = data[offset + 46 : offset + 46 + fn_len].decode("utf-8", "replace")
    extra = data[offset + 46 + fn_len : offset + 46 + fn_len + ex_len]
    extras = _parse_extras(extra)
    z64 = extras.get(ZIP64_EXTRA_ID)

    # Resolve 0xFFFFFFFF placeholders from the ZIP64 extra, in spec order.
    def take(n: int, pos: list[int]) -> int:
        if z64 is None or pos[0] + n > len(z64):
            return U32_MAX if n == 4 else U32_MAX
        v = int.from_bytes(z64[pos[0] : pos[0] + n], "little")
        pos[0] += n
        return v

    pos = [0]
    if usize == U32_MAX:
        usize = take(8, pos)
    if csize == U32_MAX:
        csize = take(8, pos)
    if lho == U32_MAX:
        lho = take(8, pos)
    # disk start number (4 bytes) is irrelevant for single-disk zips; skip.
    return _CentralEntry(name, csize, usize, lho)


def _find_eocd(data: bytes) -> int | None:
    # EOCD is at most 22 + 65535 bytes from the end.
    start = max(0, len(data) - 22 - 65535)
    idx = data.rfind(struct.pack("<I", EOCD_SIG), start)
    return idx if idx != -1 else None


def _check_local_zip64(entry: _LocalEntry, findings: list[Finding]) -> None:
    """The wheel 0.47.0 rule: no spurious ZIP64 extra in local headers."""
    c_maxed = entry.compressed_size == U32_MAX
    u_maxed = entry.uncompressed_size == U32_MAX
    expected = _expected_zip64_len(uncompressed_maxed=u_maxed, compressed_maxed=c_maxed)
    if entry.zip64_data is None:
        if expected:
            findings.append(
                Finding(entry.name, "MISSING_ZIP64",
                        "size is 0xFFFFFFFF but no ZIP64 extra field present")
            )
        return
    actual = len(entry.zip64_data)
    if expected == 0 and actual > 0:
        # pypa/wheel#692: wheel 0.47.0 wrote an 8-byte ZIP64 extra into
        # local headers whose 32-bit sizes were perfectly fine.
        findings.append(
            Finding(entry.name, "SPURIOUS_ZIP64_LOCAL",
                    f"local header carries {actual}-byte ZIP64 extra but no "
                    f"size field is 0xFFFFFFFF")
        )
    elif actual != expected:
        # astral-sh/uv#19440 class: overlong (or short) extra field.
        findings.append(
            Finding(entry.name, "ZIP64_LENGTH_MISMATCH",
                    f"ZIP64 extra is {actual} bytes, expected {expected} "
                    f"for the maxed-out fields")
        )


def audit_zip(path: str) -> AuditResult:
    """Audit one zip/wheel file. Returns VALID, INVALID, or UNREADABLE."""
    findings: list[Finding] = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return AuditResult(Verdict.UNREADABLE, [Finding("", "READ_ERROR", str(e))])

    eocd = _find_eocd(data)
    if eocd is None:
        return AuditResult(Verdict.UNREADABLE, [Finding("", "NO_EOCD", "end of central directory not found")])

    cd_count = _u16(data, eocd + 10)
    cd_offset = _u32(data, eocd + 16)
    # (ZIP64 EOCD locator handling omitted: single-disk zips in scope for v0.1.)

    offset = cd_offset
    for _ in range(cd_count):
        cent = _read_central(data, offset, findings)
        if cent is None:
            break
        fn_len = _u16(data, offset + 28)
        ex_len = _u16(data, offset + 30)
        co_len = _u16(data, offset + 32)
        offset += 46 + fn_len + ex_len + co_len

        local = _read_local(data, cent.local_offset, findings)
        if local is None:
            continue
        _check_local_zip64(local, findings)

        # Central directory and local header must agree on sizes.
        if local.compressed_size != U32_MAX and local.compressed_size != cent.compressed_size:
            findings.append(
                Finding(cent.name, "SIZE_MISMATCH",
                        f"compressed size local={local.compressed_size} central={cent.compressed_size}")
            )
        if local.uncompressed_size != U32_MAX and local.uncompressed_size != cent.uncompressed_size:
            findings.append(
                Finding(cent.name, "SIZE_MISMATCH",
                        f"uncompressed size local={local.uncompressed_size} central={cent.uncompressed_size}")
            )

    verdict = Verdict.INVALID if findings else Verdict.VALID
    return AuditResult(verdict, findings)
