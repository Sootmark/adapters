#!/bin/sh
# Download flare-wmi's wmikatz test repository (Mandiant FLARE, Apache-2.0,
# a Windows 7 WMI repository, 21 MiB, too large to keep here) at a pinned
# commit, checking its SHA-256, into tests/fixtures/wmi/ for tests/wmi.rs.
# Without it, that test is skipped.
set -eu
cd "$(dirname "$0")/fixtures/wmi"
commit=b0a5a094ff9ca7d7a1c4fc711dc00c74dec4b6b1
base="https://raw.githubusercontent.com/mandiant/flare-wmi/$commit/python-cim/tests/repos/win7/wmikatz"
for file in OBJECTS.DATA INDEX.BTR MAPPING1.MAP MAPPING2.MAP MAPPING3.MAP; do
    if [ ! -f "$file" ]; then
        curl -sfL -o "$file" "$base/$file"
    fi
done
shasum -a 256 -c --quiet - <<SUMS
7dec56b6e4deb00865fd8777349b835f6c6fa6dc98371c30c8938b2346fe8b8f  OBJECTS.DATA
52755256e5575fa838264268bc209a663c3b87a44d4e71714a499f13be1f6592  INDEX.BTR
2eda8d7d545866a22c115a93a22cc2a6cf3b6cda255b5a727b7418635ec62d26  MAPPING1.MAP
f98c8c57e6a78ea5ecda801a1cb26bf102aa9ebb2be2ef3932c43a97a29003c2  MAPPING2.MAP
ce782a77265ca3bc2bd8ac0893b7210aade23ac65cd164a74f0e53a7dee92ca2  MAPPING3.MAP
SUMS
