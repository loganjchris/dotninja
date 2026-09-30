# dotninja validation fixtures

Fixtures are recognized only by SHA-256. `manifest.json` stores the hash and live-view oracle. Rebuild source with the matching .NET SDK, copy PE32 and PE32+ outputs here, then run `python scripts/update_fixture_manifest.py` before committing both binaries and oracle changes.

The repository intentionally never recognizes a fixture by filename.

Run `./rebuild.sh` with .NET SDK 8.0 installed. Both outputs are deterministic framework-dependent Windows PEs; `update_manifest.py` records only their exact hashes and live API oracle. Commit regenerated binaries and manifest together.
