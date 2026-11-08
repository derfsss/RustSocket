#!/bin/bash
# make-release.sh: build the release archive dist/rustsocket-<ver>.lha
# (git-ignored): bsdsocket.library (the drop-in build), the end-user
# ReadMe (release/ReadMe), LICENSE and a SHA256 file. Run under Linux/WSL
# like build-package.sh.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${AMIGA_GCC_IMAGE:-walkero/amigagccondocker:os4-gcc15-3.6.1}"
cd "$REPO"
MAKE_ARGS=DROPIN=1 bash tools/build-package.sh rustsocket >/dev/null
L=rustsocket/dropin/bsdsocket.library
V=$(grep -a -o 'bsdsocket.library [0-9]*\.[0-9]*' "$L" | head -1 | cut -d' ' -f2)
[ -n "$V" ] || { echo "FAIL: no version string in $L"; exit 1; }
D="dist/rustsocket-$V"
rm -rf dist
mkdir -p "$D"
cp "$L" "$D/bsdsocket.library"
cp release/ReadMe LICENSE "$D/"
( cd "$D" && sha256sum bsdsocket.library > SHA256 )
docker run --rm -v "$REPO/dist:/o" -w /o "$IMAGE" sh -c "lha ao5q rustsocket-$V.lha rustsocket-$V"
( cd dist && sha256sum "rustsocket-$V.lha" && ls -l "rustsocket-$V.lha" )
echo "version: $V"
