#!/usr/bin/env bash
# Builds the macOS installer. A bare .dmg is just a disk image — it can't run a postinstall
# script on mount, so the actual installer is a .pkg (built with pkgbuild/productbuild, which
# does support a postinstall script) wrapped inside a .dmg for distribution. This is the same
# pattern most macOS security agents ship (drag-to-open .dmg containing a double-clickable
# .pkg), and it's what makes "auto-registers a launchd daemon on install" possible at all.
#
# Run from k3-agent-cpp/ after building: `cmake --build build`.
#   installers/macos/build-dmg.sh
#
# Silent/scripted install:
#   echo -e "SIEM_URL=https://siem.example.com\nAPI_KEY=XXXX" | sudo tee /tmp/k3-agent-install.env
#   sudo installer -pkg k3-agent.pkg -target /
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_BIN="$ROOT_DIR/build/k3-agent"
STAGE_DIR="$(mktemp -d)"
VERSION="${K3_AGENT_VERSION:-1.0.0}"

if [ ! -x "$BUILD_BIN" ]; then
  echo "Build the agent first: cmake -S $ROOT_DIR -B $ROOT_DIR/build && cmake --build $ROOT_DIR/build" >&2
  exit 1
fi

PAYLOAD_DIR="$STAGE_DIR/payload"
mkdir -p "$PAYLOAD_DIR/opt/k3-agent"
cp "$BUILD_BIN" "$PAYLOAD_DIR/opt/k3-agent/k3-agent"
chmod 755 "$PAYLOAD_DIR/opt/k3-agent/k3-agent"

COMPONENT_PKG="$STAGE_DIR/k3-agent-component.pkg"
pkgbuild \
  --root "$PAYLOAD_DIR" \
  --scripts "$SCRIPT_DIR" \
  --identifier com.k3siem.agent \
  --version "$VERSION" \
  --install-location / \
  "$COMPONENT_PKG"

FINAL_PKG="$ROOT_DIR/k3-agent.pkg"
productbuild --package "$COMPONENT_PKG" "$FINAL_PKG"

DMG_ROOT="$STAGE_DIR/dmgroot"
mkdir -p "$DMG_ROOT"
cp "$FINAL_PKG" "$DMG_ROOT/"

OUT_DMG="$ROOT_DIR/k3-agent-macos.dmg"
rm -f "$OUT_DMG"
hdiutil create -volname "K3 SIEM Agent" -srcfolder "$DMG_ROOT" -ov -format UDZO "$OUT_DMG"

rm -rf "$STAGE_DIR"
echo "Built $OUT_DMG (contains k3-agent.pkg)"
