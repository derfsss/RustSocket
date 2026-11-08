#!/bin/bash
# Build the library (both names) and every test program of this repository
# (Linux or WSL, after amigaos4/tools/build-toolchain.sh). Stops at the
# first failure.
set -euo pipefail
cd "$(dirname "$0")/.."
B=tools/build-package.sh
bash $B rustsocket
MAKE_ARGS=DROPIN=1 bash $B rustsocket
bash $B testprogs/rstcp
bash $B testprogs/rsprobe
bash $B testprogs/rsnet
bash $B testprogs/netprof
ls -la rustsocket/rustsocket.library rustsocket/dropin/bsdsocket.library \
       testprogs/rstcp/rstcp testprogs/rsprobe/rsprobe testprogs/rsnet/rsnet \
       testprogs/netprof/netprof
