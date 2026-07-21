#!/usr/bin/env bash
# scripts/run-container.sh — canonical `docker run` invocation for SAPMAP.
#
# Prereqs:
#   - Docker (or Podman aliased to docker) installed
#   - You have built the image:  `docker build -t sapmap:latest .`
#     (On Apple Silicon:  docker build --platform linux/amd64 -t sapmap:latest .)
#   - The NW RFC SDK is extracted on the host (typically /opt/nwrfcsdk)
#     — Linux x86-64 variant, because the container runs Linux Python.
#
# Usage:
#   ./scripts/run-container.sh                          # ephemeral (--rm)
#   PERSIST=1 ./scripts/run-container.sh                # named + persistent
#   SDK_PATH=~/nwrfcsdk ./scripts/run-container.sh
#   IMAGE=sapmap:dev ./scripts/run-container.sh
#   NAME=sapmap-dev PERSIST=1 ./scripts/run-container.sh # custom name
#   DEBUG=1 ./scripts/run-container.sh                  # print the docker cmd
#
# Persistent mode (PERSIST=1):
#   - Container is created with --name (default: sapmap) and WITHOUT --rm,
#     so it survives Ctrl-C / `docker stop`.
#   - After the first run:
#       docker start -ai sapmap    # re-attach and see the console
#       docker stop  sapmap        # stop cleanly
#       docker rm    sapmap        # throw it away when you're done
#   - Docker Desktop's dashboard will now list the container under
#     "Containers" and its Start / Stop buttons will work.
#
# Then open http://127.0.0.1:8080 in your host browser.
set -euo pipefail

IMAGE="${IMAGE:-sapmap:latest}"
SDK_PATH="${SDK_PATH:-/opt/nwrfcsdk}"
LOOT_DIR="${LOOT_DIR:-$(pwd)/loot}"
STATE_DIR="${STATE_DIR:-$(pwd)/states}"
NAME="${NAME:-sapmap}"
PERSIST="${PERSIST:-0}"

mkdir -p "$LOOT_DIR" "$STATE_DIR"

# --- Lifecycle: ephemeral (--rm) or named + persistent.
LIFECYCLE_ARGS=(--rm -it)
if [[ "$PERSIST" == "1" ]]; then
    # Re-attach if the named container already exists.  Two states:
    #   - Running   → docker attach
    #   - Exited    → docker start -ai (start + attach, streams stdin/tty)
    if docker inspect "$NAME" >/dev/null 2>&1; then
        STATE="$(docker inspect -f '{{.State.Status}}' "$NAME")"
        case "$STATE" in
            running)
                echo "[+] Container '$NAME' is already running — attaching."
                exec docker attach "$NAME"
                ;;
            exited|created)
                echo "[+] Container '$NAME' exists (state=$STATE) — starting."
                exec docker start -ai "$NAME"
                ;;
            *)
                echo "[!] Container '$NAME' is in state '$STATE'."
                echo "    Remove it first:  docker rm -f $NAME"
                exit 1
                ;;
        esac
    fi
    LIFECYCLE_ARGS=(-it --name "$NAME")
    echo "[+] Persistent mode — container will be named '$NAME' and kept"
    echo "    after stop.  Re-run this script (or 'docker start -ai $NAME')"
    echo "    to bring it back up.  Remove with 'docker rm -f $NAME'."
fi

# --- Network: Linux uses --network host for LAN reachability; macOS /
# Windows Docker Desktop need bridge networking with -p.
UNAME_S="$(uname -s)"
if [[ "$UNAME_S" == "Linux" ]]; then
    NET_ARGS=(--network host)
else
    NET_ARGS=(-p 8080:8080)
    echo "[!] Non-Linux host: using -p 8080:8080 instead of --network host."
    echo "[!] LAN reachability from the container may be limited on"
    echo "    Docker Desktop; consider running SAPMAP natively for real"
    echo "    engagements."
fi

# --- Platform: the RFC SDK is Linux x86-64 only.  On Apple Silicon
# we must force linux/amd64 so the SDK loads under Rosetta emulation.
PLATFORM_ARGS=()
ARCH="$(uname -m)"
if [[ "$UNAME_S" == "Darwin" && "$ARCH" == "arm64" ]]; then
    PLATFORM_ARGS=(--platform linux/amd64)
    echo "[+] Apple Silicon detected — forcing --platform linux/amd64"
    echo "    (SAP NW RFC SDK is x86-64 only; runs under Rosetta 2)"
fi

# --- SDK mount: skip if not present.  Uses --mount type=bind (explicit
# field syntax) instead of -v so paths with colons don't get parsed as
# mount modes.
SDK_ARGS=()
if [[ -d "$SDK_PATH/lib" ]]; then
    # Also pass the HOST-side SDK path as an env var so the GUI's
    # settings modal can show the operator where the SDK lives on
    # their laptop, not just the container-side mount target
    # /opt/nwrfcsdk/lib (which is confusing in a Docker context).
    SDK_ARGS=(--mount "type=bind,source=$SDK_PATH,target=/opt/nwrfcsdk,readonly"
              --env "SAPMAP_HOST_SDK_PATH=$SDK_PATH")
    echo "[+] Mounting SDK from $SDK_PATH"
else
    echo "[!] No SDK found at $SDK_PATH/lib — running with unauthenticated"
    echo "    features only.  Set SDK_PATH=... to point at your SDK."
fi

# --- Assemble and (optionally) print, then exec.
CMD=(
    docker run
    "${LIFECYCLE_ARGS[@]}"
    "${PLATFORM_ARGS[@]}"
    "${NET_ARGS[@]}"
    "${SDK_ARGS[@]}"
    --mount "type=bind,source=$LOOT_DIR,target=/opt/sapmap/loot"
    --mount "type=bind,source=$STATE_DIR,target=/opt/sapmap/states"
    "$IMAGE"
)

if [[ "${DEBUG:-0}" == "1" ]]; then
    echo "[debug] $(printf '%q ' "${CMD[@]}")"
fi

exec "${CMD[@]}"
