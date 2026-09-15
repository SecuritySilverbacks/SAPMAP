# SAPMAP container image
#
# Builds a self-contained SAPMAP with every Python dependency pre-baked,
# side-stepping the pyjks / twofish / Python 3.12 friction that reporters
# hit on bare-metal installs (issue #2).
#
# The SAP NW RFC SDK is NOT included in the image — SAP's EULA forbids
# redistribution.  Mount your own SDK from the host at /opt/nwrfcsdk:
#
#   docker build -t sapmap:latest .
#   docker run --rm -it \
#       --network host \
#       -v /opt/nwrfcsdk:/opt/nwrfcsdk:ro \
#       -v $(pwd)/loot:/opt/sapmap/loot \
#       -v $(pwd)/states:/opt/sapmap/states \
#       sapmap:latest
#
# Then point your host browser at http://127.0.0.1:8080.
# See README.md "Docker" section for macOS / Windows / bridge-networking
# variants and troubleshooting.

FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="SAPMAP"
LABEL org.opencontainers.image.description="SAP Landscape Attack Path Mapper — authorized security testing only"
LABEL org.opencontainers.image.source="https://github.com/SecuritySilverbacks/SAPMAP"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"

# Build tooling for the twofish C extension pulled in by pyjks.
# libgcc-s1 / libstdc++6 are needed at runtime by the SAP NW RFC SDK
# (libsapnwrfc.so links against them).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libgcc-s1 \
        libstdc++6 \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sapmap

# Install Python deps first so a code change doesn't invalidate the
# (slow) pyjks/twofish build cache layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir pyjks>=20

# Copy source.  .dockerignore keeps loot/, states/, research/, etc. out.
COPY . .

# The SAP NW RFC SDK gets mounted here at run time.  SAPMAP's --sdk
# arg (or the LD_LIBRARY_PATH fallback) picks up the mounted lib
# directory automatically.
ENV LD_LIBRARY_PATH=/opt/nwrfcsdk/lib
ENV SAPMAP_IN_CONTAINER=1

# --host 0.0.0.0 is required for bridge-networking Docker (macOS /
# Windows Desktop / podman-machine).  With --network host on Linux
# it still works — the process just binds to 0.0.0.0 on the host's
# real network namespace.
EXPOSE 8080
ENTRYPOINT ["python3", "/opt/sapmap/sapmap.py", \
            "--browser", "--host", "0.0.0.0", "--port", "8080", \
            "--sdk", "/opt/nwrfcsdk/lib"]
