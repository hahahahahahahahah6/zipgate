"""zipgate: audit wheels and zips for malformed ZIP64 structures.

Two real-world incidents motivate this tool:

- astral-sh/uv#19440: a 5.8 GiB PyTorch ROCm nightly wheel failed to install
  with "zip64 extended information field was too long".
- pypa/wheel#692: ``wheel tags`` in wheel 0.47.0 wrote an illegal ZIP64 extra
  field into local file headers of retagged wheels.

zipgate parses local file headers and central directory entries by hand and
checks the ZIP64 extra field (0x0001) against APPNOTE 4.5.3:

- a local header must only carry ZIP64 extra data for fields that are
  0xFFFF / 0xFFFFFFFF in that same header (spurious 8-byte extras are the
  wheel 0.47.0 bug);
- the extra field must be exactly as long as the maxed-out fields require
  (overlong extras are the uv#19440 bug);
- central directory and local header must agree on sizes.
"""

from .checker import Finding, Verdict, audit_zip

__all__ = ["Finding", "Verdict", "audit_zip"]
__version__ = "0.1.0"
