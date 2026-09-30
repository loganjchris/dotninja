# dotninja

dotninja adds managed .NET support to Binary Ninja. It recognizes CLR assemblies in PE files and provides `dotnet32` and `dotnet64` architectures, a DotNet BinaryView, CIL disassembly and LLIL lifting, CLR metadata and type reconstruction, external method mappings, and managed-code analysis commands.

## Install

Place this repository in Binary Ninja's user plugins directory. Install the Python dependencies (`dnfile` and `dncil`) into the Python environment used by Binary Ninja, then restart Binary Ninja. After loading a managed PE, select the **DotNet** view if Binary Ninja does not choose it automatically.

## Commands

The Plugins menu provides **dotninja > Run Validation Suite** for a live view report. The report is also stored in `bv.session_data["dotninja.validation"]` for inspection from Binary Ninja's Python console. Other commands highlight reflection and unpacking patterns, remove recognized opaque predicates, and safely emulate supported string decryptors.

## Fixtures and development

The checked-in PE32 and PE32+ fixtures exercise metadata, CIL control flow, exception handlers, imports, and strings. Their hashes and validation oracle are in `fixtures/manifest.json`; fixture recognition uses hashes rather than filenames.

To rebuild them, install the .NET 8 SDK and run:

```sh
cd fixtures
./rebuild.sh
```

The script publishes managed Windows PE fixtures for x86 and x64 and refreshes the manifest. Build and restore output stays under ignored `fixtures/src/bin`, `fixtures/src/obj`, and `fixtures/build` directories. Review regenerated binaries and the manifest together before committing.

Pure parser and analysis tests can be run with `python3 -m pytest`. They do not initialize Binary Ninja or require a license. The project also includes Pyright configuration for static checks.
