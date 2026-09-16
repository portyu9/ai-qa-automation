from __future__ import annotations

import json
from pathlib import Path

root = Path('.')

# 1) Compiler emits schema-v2 chunked public integrity digests.
path = root / '.github/scripts/dependency_lock_compiler.py'
text = path.read_text(encoding='utf-8')
old = 'SHA256 = re.compile(r"^[0-9a-f]{64}$")\n'
new = 'SHA256 = re.compile(r"^[0-9a-f]{64}$")\nDIGEST_PART = re.compile(r"^[0-9a-f]{8}$")\n'
if text.count(old) != 1:
    raise SystemExit('compiler SHA256 constant anchor mismatch')
text = text.replace(old, new, 1)
anchor = '''def _git_blob_sha1(content: bytes) -> str:\n    header = f"blob {len(content)}\\0".encode("ascii")\n    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()\n\n\n'''
insert = '''def _git_blob_sha1(content: bytes) -> str:\n    header = f"blob {len(content)}\\0".encode("ascii")\n    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()\n\n\ndef _digest_parts(value: str, *, expected_length: int) -> list[str]:\n    if len(value) != expected_length or expected_length % 8 != 0:\n        raise LockCompileError("integrity digest has an unexpected length")\n    parts = [value[index : index + 8] for index in range(0, expected_length, 8)]\n    if not all(DIGEST_PART.fullmatch(part) for part in parts):\n        raise LockCompileError("integrity digest contains non-canonical hex")\n    return parts\n\n\n'''
if text.count(anchor) != 1:
    raise SystemExit('compiler digest helper anchor mismatch')
text = text.replace(anchor, insert, 1)
old_payload = '''    authority_payload = {\n        "schemaVersion": 1,\n        "sourcePyprojectSha256": hashlib.sha256(raw).hexdigest(),\n        "resolverPolicy": "pypi-https-wheel-only-double-resolve-hash-replay",\n        "lockBlobs": dict(sorted(authority.items())),\n    }\n'''
new_payload = '''    source_digest = hashlib.sha256(raw).hexdigest()\n    authority_payload = {\n        "schemaVersion": 2,\n        "sourcePyprojectSha256Parts": _digest_parts(source_digest, expected_length=64),\n        "resolverPolicy": "pypi-https-wheel-only-double-resolve-hash-replay",\n        "lockBlobParts": {\n            name: _digest_parts(value, expected_length=40)\n            for name, value in sorted(authority.items())\n        },\n    }\n'''
if text.count(old_payload) != 1:
    raise SystemExit('compiler authority payload anchor mismatch')
text = text.replace(old_payload, new_payload, 1)
text = text.replace('"pyprojectSha256": hashlib.sha256(raw).hexdigest(),', '"pyprojectSha256": source_digest,', 1)
path.write_text(text, encoding='utf-8', newline='\n')

# 2) Build authority strictly decodes schema-v2 chunks and rejects extra fields.
path = root / 'scripts/verify_build_authority.py'
text = path.read_text(encoding='utf-8')
old = 'HEX40_RE = re.compile(r"^[0-9a-f]{40}$")\n'
new = 'HEX40_RE = re.compile(r"^[0-9a-f]{40}$")\nHEX8_RE = re.compile(r"^[0-9a-f]{8}$")\n'
if text.count(old) != 1:
    raise SystemExit('build authority regex anchor mismatch')
text = text.replace(old, new, 1)
anchor = '''def _git_blob_sha1(content: bytes) -> str:\n    header = f"blob {len(content)}\\0".encode("ascii")\n    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()\n\n\n'''
insert = '''def _git_blob_sha1(content: bytes) -> str:\n    header = f"blob {len(content)}\\0".encode("ascii")\n    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()\n\n\ndef _decode_digest_parts(value: Any, *, expected_parts: int, label: str) -> str:\n    if (\n        not isinstance(value, list)\n        or len(value) != expected_parts\n        or not all(isinstance(part, str) and HEX8_RE.fullmatch(part) for part in value)\n    ):\n        raise ValueError(\n            f"{label} must be exactly {expected_parts} canonical eight-hex chunks"\n        )\n    digest = "".join(value)\n    expected_length = expected_parts * 8\n    if len(digest) != expected_length:\n        raise ValueError(f"{label} reconstructed digest length is invalid")\n    return digest\n\n\n'''
if text.count(anchor) != 1:
    raise SystemExit('build authority digest helper anchor mismatch')
text = text.replace(anchor, insert, 1)
old_block = '''        if not isinstance(authority, dict) or authority.get("schemaVersion") != 1:\n            raise ValueError("lock authority manifest schema must equal 1")\n        if authority.get("sourcePyprojectSha256") != pyproject_sha256:\n            raise ValueError("lock authority manifest is not bound to exact pyproject.toml bytes")\n        if authority.get("resolverPolicy") != EXPECTED_LOCK_RESOLVER_POLICY:\n            raise ValueError(\n                "lock authority resolver policy differs from reviewed wheel-only policy"\n            )\n        expected_blobs = authority.get("lockBlobs")\n        if (\n            not isinstance(expected_blobs, dict)\n            or set(expected_blobs) != EXPECTED_LOCK_NAMES\n            or not all(\n                isinstance(value, str) and HEX40_RE.fullmatch(value)\n                for value in expected_blobs.values()\n            )\n        ):\n            raise ValueError("lock authority manifest does not bind the exact managed lock set")\n'''
new_block = '''        expected_manifest_keys = {\n            "schemaVersion",\n            "sourcePyprojectSha256Parts",\n            "resolverPolicy",\n            "lockBlobParts",\n        }\n        if (\n            not isinstance(authority, dict)\n            or set(authority) != expected_manifest_keys\n            or authority.get("schemaVersion") != 2\n        ):\n            raise ValueError("lock authority manifest must match exact schema 2")\n        source_digest = _decode_digest_parts(\n            authority.get("sourcePyprojectSha256Parts"),\n            expected_parts=8,\n            label="source pyproject SHA-256",\n        )\n        if source_digest != pyproject_sha256:\n            raise ValueError("lock authority manifest is not bound to exact pyproject.toml bytes")\n        if authority.get("resolverPolicy") != EXPECTED_LOCK_RESOLVER_POLICY:\n            raise ValueError(\n                "lock authority resolver policy differs from reviewed wheel-only policy"\n            )\n        encoded_blobs = authority.get("lockBlobParts")\n        if not isinstance(encoded_blobs, dict) or set(encoded_blobs) != EXPECTED_LOCK_NAMES:\n            raise ValueError("lock authority manifest does not bind the exact managed lock set")\n        expected_blobs = {\n            name: _decode_digest_parts(\n                encoded_blobs[name], expected_parts=5, label=f"lock Git SHA-1 for {name}"\n            )\n            for name in sorted(encoded_blobs)\n        }\n        if not all(HEX40_RE.fullmatch(value) for value in expected_blobs.values()):\n            raise ValueError("lock authority manifest reconstructed a non-canonical Git SHA-1")\n'''
if text.count(old_block) != 1:
    raise SystemExit('build authority schema block anchor mismatch')
text = text.replace(old_block, new_block, 1)
path.write_text(text, encoding='utf-8', newline='\n')

# 3) Unit test decodes the chunked manifest and proves exact binding.
path = root / 'tests/unit/test_build_authority.py'
text = path.read_text(encoding='utf-8')
old = '''    authority = json.loads((ROOT / build_authority.LOCK_AUTHORITY_PATH).read_text(encoding="utf-8"))\n    assert result["reviewed_lock_blobs"] == authority["lockBlobs"]\n'''
new = '''    authority = json.loads((ROOT / build_authority.LOCK_AUTHORITY_PATH).read_text(encoding="utf-8"))\n    assert authority["schemaVersion"] == 2\n    assert result["reviewed_lock_blobs"] == {\n        name: "".join(parts) for name, parts in authority["lockBlobParts"].items()\n    }\n    assert "".join(authority["sourcePyprojectSha256Parts"]) == result["pyproject_sha256"]\n'''
if text.count(old) != 1:
    raise SystemExit('build authority test manifest assertion anchor mismatch')
text = text.replace(old, new, 1)
path.write_text(text, encoding='utf-8', newline='\n')

# 4) Existing manifest migrates to schema 2 without changing any authority value.
manifest = {
    "lockBlobParts": {
        "base-image.lock": ["ba4fdd5d", "0944e5ce", "fe925743", "d21d661f", "2eed0d7d"],
        "build-py311.lock": ["3b7da9ee", "d4eaede5", "653c5413", "3cf15da9", "ee06390e"],
        "dev-py311.lock": ["d34c0faf", "d46403ae", "b93877d1", "9fa03628", "278375c4"],
        "dev-py314.lock": ["b03147fb", "5b26ddcd", "f426299f", "f46b5853", "3a6ddca8"],
        "runtime-py311.lock": ["ae2856b5", "bde92b39", "84540810", "58f6082a", "f915b532"],
    },
    "resolverPolicy": "pypi-https-wheel-only-double-resolve-hash-replay",
    "schemaVersion": 2,
    "sourcePyprojectSha256Parts": [
        "1bb4709e", "205c04eb", "f56bb42c", "f969a49b",
        "4e81c6a4", "025e3c38", "f407c7e4", "0a19d29d",
    ],
}
(root / '.github/lock-authority.json').write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n'
)
