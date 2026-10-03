#!/bin/sh
# Download the test hives the registry adapter is checked on at pinned
# commits into tests/fixtures/hives/, checking each SHA-256: Eric
# Zimmerman's Registry test set (MIT), and the SYSTEM hive of Andrew
# Rathbun's Windows 10 VM (MIT, DFIR Artifact Museum; extracted with 7z).
set -eu
cd "$(dirname "$0")/fixtures"
mkdir -p hives
base=https://raw.githubusercontent.com/EricZimmerman/Registry/1b0b3c414569debb5ffcc629de28e3ff27145a42/Registry.Test/Hives
while read -r sum name; do
    if [ ! -f "hives/$name" ]; then
        curl -sfL -o "hives/$name" "$base/$name"
    fi
    echo "$sum  hives/$name" | shasum -a 256 -c --quiet -
done <<END
ec01a4ec205c5354a4ad1d5d088f45e2331ffb13773dcc7008e6ea6f2175466f SYSTEM
8d5fdee75d69b878a0bf602f7a15f0410c5622b9c8c84a5c2f346d44a8cdb759 NTUSER.DAT
dc43388d50ecfadd85053e2345f62324c2b0b2901a6945d480a2899f0e8c5185 ERZ_Win81_UsrClass.dat
END

if [ ! -f hives/rathbun-win10-SYSTEM ]; then
    curl -sfL -o hives/w10.7z https://raw.githubusercontent.com/AndrewRathbun/DFIRArtifactMuseum/fdcb1fab0c7b00e89129668d9c30174dd4ea3e5b/Windows/Registry/Win10/RathbunVM/RathbunVM_W10RegistryHives.7z
    echo "f4f321cf45ae06db0fa832c9103699bdc6114b3017fdb6671fa6bd0971c7a9aa  hives/w10.7z" | shasum -a 256 -c --quiet -
    7z e -y -bd -ohives/w10 hives/w10.7z SYSTEM >/dev/null
    mv hives/w10/SYSTEM hives/rathbun-win10-SYSTEM
    rm -r hives/w10 hives/w10.7z
fi
echo "61293882afec46472a2b8f6c896b4657626461fbbfed67ff100ae06da8e4b680  hives/rathbun-win10-SYSTEM" | shasum -a 256 -c --quiet -
