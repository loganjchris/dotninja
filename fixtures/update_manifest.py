from __future__ import annotations
import hashlib, json
from pathlib import Path

ROOT = Path(__file__).parent
manifest = {"schema": 1, "fixtures": {}}
for fixture_id, filename, architecture in (
    ("validation-pe32", "fixture-pe32.exe", "dotnet32"),
    ("validation-pe64", "fixture-pe64.exe", "dotnet64"),
):
    path = ROOT / filename
    if not path.exists():
        continue
    manifest["fixtures"][fixture_id] = {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "architecture": architecture,
        "sections": [".clr#~", ".clr#Strings", ".clr#US", ".clr#Blob", ".clr#GUID"],
        "methods": {},
    }
(ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
