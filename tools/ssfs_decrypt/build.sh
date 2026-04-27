#!/usr/bin/env bash
# SAPMAP — portable build script for the SSFS decryption JNI helper jar.
# Works on Linux and macOS (arm64 + x86_64).  Equivalent to `make` but
# only needs a JDK on PATH (no make required).
#
# Usage:  ./build.sh
# Output: decrypt-ssfs.jar  (drop next to libsapscc20jni.so/.dylib)
#
# The resulting jar is portable across Linux, macOS, and Windows — Java's
# System.loadLibrary() resolves the platform-specific native lib at
# runtime.  Only the matching native lib changes per host.
set -euo pipefail

cd "$(dirname "$0")"

JAVAC="${JAVAC:-javac}"
JAR="${JAR:-jar}"

rm -rf build
mkdir -p build

"$JAVAC" -d build SecStoreAccess.java SecStoreAccessException.java
"$JAR" cfe decrypt-ssfs.jar com.sap.scc.jni.SecStoreAccess -C build .

echo "Built decrypt-ssfs.jar — copy alongside libsapscc20jni.{so,dll,dylib}."
