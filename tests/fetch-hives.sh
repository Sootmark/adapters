#!/bin/sh
# Download the test hives the registry adapter is checked on at pinned
# commits into tests/fixtures/hives/, checking each SHA-256: Eric
# Zimmerman's Registry test set (MIT), and the SYSTEM, SOFTWARE and
# NTUSER.DAT hives of Andrew Rathbun's Windows 10 VM (MIT, DFIR Artifact
# Museum; extracted with 7z), and plaso's NTUSER-WIN7.DAT (Apache-2.0).
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
658c4323cc2c4e33e09ef3e5251651300ff1a49937e136242565cc5c49fd5e96 SOFTWARE
dc43388d50ecfadd85053e2345f62324c2b0b2901a6945d480a2899f0e8c5185 ERZ_Win81_UsrClass.dat
END

for hive in SYSTEM SOFTWARE NTUSER.DAT; do
    if [ ! -f "hives/rathbun-win10-$hive" ]; then
        if [ ! -f hives/w10.7z ]; then
            curl -sfL -o hives/w10.7z https://raw.githubusercontent.com/AndrewRathbun/DFIRArtifactMuseum/fdcb1fab0c7b00e89129668d9c30174dd4ea3e5b/Windows/Registry/Win10/RathbunVM/RathbunVM_W10RegistryHives.7z
            echo "f4f321cf45ae06db0fa832c9103699bdc6114b3017fdb6671fa6bd0971c7a9aa  hives/w10.7z" | shasum -a 256 -c --quiet -
        fi
        7z e -y -bd -ohives/w10 hives/w10.7z "$hive" >/dev/null
        mv "hives/w10/$hive" "hives/rathbun-win10-$hive"
        rm -r hives/w10
    fi
done
rm -f hives/w10.7z
while read -r sum hive; do
    echo "$sum  hives/rathbun-win10-$hive" | shasum -a 256 -c --quiet -
done <<END
61293882afec46472a2b8f6c896b4657626461fbbfed67ff100ae06da8e4b680 SYSTEM
cd25478f854dbacd4c044c001e36746fb3e1ea702426aa0e5fa2e8f396615d15 SOFTWARE
523716419e2a661e2a719b63a24c031567bfcf22113b7e86bb35d3604ff942d3 NTUSER.DAT
END

name=plaso-NTUSER-WIN7.DAT
if [ ! -f "hives/$name" ]; then
    curl -sfL -o "hives/$name" https://raw.githubusercontent.com/log2timeline/plaso/ac6da7129f6cf3f43a352b6c4906374cf071533e/test_data/NTUSER-WIN7.DAT
fi
echo "672abb15ae62fa8c002c5ee0a730cf83cd5f40706d5ffdec8f1179cf47a0bd03  hives/$name" | shasum -a 256 -c --quiet -
