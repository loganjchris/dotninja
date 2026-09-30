import json
import hashlib
from pathlib import Path

import dnfile

def test_manifest_uses_hash_keys_not_filenames():
    manifest = json.loads((Path(__file__).parents[1] / "fixtures" / "manifest.json").read_text())
    assert manifest["schema"] == 1
    for fixture in manifest["fixtures"].values():
        digest = fixture["sha256"]
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
        assert "filename" not in fixture

def test_committed_fixtures_match_manifest_and_are_managed_pes():
    root = Path(__file__).parents[1] / "fixtures"
    manifest = json.loads((root / "manifest.json").read_text())
    for fixture_id, filename in (("validation-pe32", "fixture-pe32.exe"), ("validation-pe64", "fixture-pe64.exe")):
        data = (root / filename).read_bytes()
        assert hashlib.sha256(data).hexdigest() == manifest["fixtures"][fixture_id]["sha256"]
        pe = dnfile.dnPE(data=data)
        assert pe.net is not None and pe.net.mdtables is not None
