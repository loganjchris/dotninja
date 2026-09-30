#!/usr/bin/env sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
dotnet publish "$root/src/ValidationFixture.csproj" -c Release -r win-x86 --self-contained false -p:PlatformTarget=x86 -o "$root/build/pe32"
dotnet publish "$root/src/ValidationFixture.csproj" -c Release -r win-x64 --self-contained false -p:PlatformTarget=x64 -o "$root/build/pe64"
# Framework-dependent publishes contain a native apphost executable and the
# actual managed PE. dotninja fixtures must use the managed assembly.
cp "$root/build/pe32/ValidationFixture.dll" "$root/fixture-pe32.exe"
cp "$root/build/pe64/ValidationFixture.dll" "$root/fixture-pe64.exe"
python3 "$root/update_manifest.py"
