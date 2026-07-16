#!/usr/bin/env bash
# Packages the compiled k3-agent binary into a self-extracting .bin installer via makeself.
# Run from k3-agent-cpp/ after building: `cmake --build build`.
#
#   installers/linux/build-bin.sh
#
# Produces k3-agent-linux.bin. Install with:
#   sudo ./k3-agent-linux.bin -- --siem-url https://siem.example.com --api-key XXXX
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_BIN="$ROOT_DIR/build/k3-agent"
STAGE_DIR="$(mktemp -d)"
OUT_FILE="$ROOT_DIR/k3-agent-linux.bin"

if ! command -v makeself >/dev/null 2>&1; then
  echo "makeself is required (apt install makeself / dnf install makeself) — aborting." >&2
  exit 1
fi
if [ ! -x "$BUILD_BIN" ]; then
  echo "Build the agent first: cmake -S $ROOT_DIR -B $ROOT_DIR/build && cmake --build $ROOT_DIR/build" >&2
  exit 1
fi

mkdir -p "$STAGE_DIR/payload"
cp "$BUILD_BIN" "$STAGE_DIR/payload/k3-agent"
cp "$(dirname "${BASH_SOURCE[0]}")/install.sh" "$STAGE_DIR/payload/install.sh"
cp "$(dirname "${BASH_SOURCE[0]}")/k3-agent.service" "$STAGE_DIR/payload/k3-agent.service"
chmod +x "$STAGE_DIR/payload/install.sh"

makeself "$STAGE_DIR/payload" "$OUT_FILE" "K3 SIEM Agent" ./install.sh

rm -rf "$STAGE_DIR"
echo "Built $OUT_FILE"
