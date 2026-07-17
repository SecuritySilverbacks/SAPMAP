#!/usr/bin/env bash
# scripts/run-container.sh — canonical `docker run` invocation for SAPMAP.
#
# Prereqs:
#   - Docker (or Podman aliased to docker) installed
#   - You have built the image:  `docker build -t sapmap:latest .`
#   - The NW RFC SDK is extracted on the host (typically /opt/nwrfcsdk)
#
# Usage:
#   ./scripts/run-container.sh                       # defaults below
#   SDK_PATH=/tmp/nwrfcsdk ./scripts/run-container.sh
#   IMAGE=sapmap:dev ./scripts/run-container.sh
#
# Then open http://127.0.0.1:8080 in your host browser.
set -euo pipefail

IMAGE="${IMAGE:-sapmap:latest}"
SDK_PATH="${SDK_PATH:-/opt/nwrfcsdk}"
LOOT_DIR="${LOOT_DIR:-$(pwd)/loot}"
STATE_DIR="${STATE_DIR:-$(pwd)/states}"

mkdir -p "$LOOT_DIR" "$STATE_DIR"

# --network host is Linux-only.  On macOS / Windows Docker Desktop,
# swap for:
#     -p 8080:8080
# and note that LAN scans from the container may need Docker Desktop's
# "host.docker.internal" or a VPN into the target network — bridge
# networking will proxy TCP but not raw IP-level scans.
if [[ "$(uname -s)" == "Linux" ]]; then
    NET_ARGS=(--network host)
else
    NET_ARGS=(-p 8080:8080)
    echo "[!] Non-Linux host: using -p 8080:8080 instead of --network host."
    echo "[!] LAN reachability from the container may be limited on"
    echo "    Docker Desktop; consider running SAPMAP natively for real"
    echo "    engagements."
fi

# Mount the SDK read-only.  If SDK_PATH doesn't exist, warn — the
# unauthenticated features (port scan, GW fingerprint, RECON check)
# still work without the SDK.
SDK_ARGS=()
if [[ -d "$SDK_PATH/lib" ]]; then
    SDK_ARGS=(-v "$SDK_PATH:/opt/nwrfcsdk:ro")
    echo "[+] Mounting SDK from $SDK_PATH"
else
    echo "[!] No SDK found at $SDK_PATH/lib — running with unauthenticated"
    echo "    features only.  Set SDK_PATH=... to point at your SDK."
fi

exec docker run --rm -it \
    "${NET_ARGS[@]}" \
    "${SDK_ARGS[@]}" \
    -v "$LOOT_DIR:/opt/sapmap/loot" \
    -v "$STATE_DIR:/opt/sapmap/states" \
    "$IMAGE"
