#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_DIR="$ROOT_DIR/macos/SecFlowMac"
APP_DIR="${SECFLOW_MACOS_APP_DIR:-$ROOT_DIR/dist/SecFlow.app}"
INFO_PLIST_PATH="${SECFLOW_MACOS_INFO_PLIST:-$PACKAGE_DIR/Resources/Info.plist}"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
MACOS_ARCH="${SECFLOW_MACOS_ARCH:-arm64}"
BACKEND_BUILD_DIR="${TMPDIR:-/tmp}/secflow-macos-backend-build"
SEMGREP_BUILD_DIR="${TMPDIR:-/tmp}/secflow-macos-semgrep-build"
SEMGREP_RULES_PATH="${SECFLOW_SEMGREP_RULES_PATH:-$ROOT_DIR/config/semgrep}"

if ! "$PYTHON_BIN" -c 'import PyInstaller' >/dev/null 2>&1; then
    echo "PyInstaller is required. Run: $PYTHON_BIN -m pip install -r requirements-macos.txt" >&2
    exit 1
fi
if ! "$PYTHON_BIN" -c 'import semgrep' >/dev/null 2>&1; then
    echo "Semgrep is required. Run: $PYTHON_BIN -m pip install -r requirements-macos.txt" >&2
    exit 1
fi
if ! "$PYTHON_BIN" -c 'import reportlab' >/dev/null 2>&1; then
    echo "ReportLab is required. Run: $PYTHON_BIN -m pip install -r requirements-macos.txt" >&2
    exit 1
fi
[ -e "$SEMGREP_RULES_PATH" ] || { echo "Missing offline Semgrep rules: $SEMGREP_RULES_PATH" >&2; exit 1; }
case "$MACOS_ARCH" in
    arm64|x86_64) ;;
    *) echo "Unsupported macOS architecture: $MACOS_ARCH" >&2; exit 1 ;;
esac
PYTHON_ARCH="$($PYTHON_BIN -c 'import platform; print(platform.machine())')"
[ "$PYTHON_ARCH" = "$MACOS_ARCH" ] || {
    echo "Python architecture is $PYTHON_ARCH, expected $MACOS_ARCH: $PYTHON_BIN" >&2
    exit 1
}

rm -rf "$BACKEND_BUILD_DIR"
rm -rf "$SEMGREP_BUILD_DIR"
"$PYTHON_BIN" -m PyInstaller \
    --noconfirm \
    --clean \
    --onedir \
    --name secflow-backend \
    --paths "$ROOT_DIR" \
    --add-data "$ROOT_DIR/app/static:app/static" \
    --collect-all reportlab \
    --collect-all tree_sitter \
    --collect-all tree_sitter_java \
    --collect-all tree_sitter_python \
    --collect-all tree_sitter_go \
    --collect-all tree_sitter_c \
    --collect-all tree_sitter_cpp \
    --collect-all tree_sitter_rust \
    --collect-all tree_sitter_solidity \
    --hidden-import uvicorn.logging \
    --hidden-import uvicorn.loops.asyncio \
    --hidden-import uvicorn.protocols.http.h11_impl \
    --hidden-import uvicorn.lifespan.on \
    --exclude-module psycopg \
    --exclude-module psycopg_binary \
    --distpath "$BACKEND_BUILD_DIR/dist" \
    --workpath "$BACKEND_BUILD_DIR/work" \
    --specpath "$BACKEND_BUILD_DIR" \
    "$ROOT_DIR/app/macos_backend.py"

"$PYTHON_BIN" -m PyInstaller \
    --noconfirm \
    --clean \
    --onedir \
    --name secflow-semgrep \
    --collect-all semgrep \
    --copy-metadata semgrep \
    --distpath "$SEMGREP_BUILD_DIR/dist" \
    --workpath "$SEMGREP_BUILD_DIR/work" \
    --specpath "$SEMGREP_BUILD_DIR" \
    "$ROOT_DIR/app/semgrep_runner.py"

SWIFT_BUILD_ARGS=(-c release --package-path "$PACKAGE_DIR" --arch "$MACOS_ARCH")
swift build "${SWIFT_BUILD_ARGS[@]}"
BIN_DIR="$(swift build "${SWIFT_BUILD_ARGS[@]}" --show-bin-path)"

rm -rf "$APP_DIR"
mkdir -p \
    "$APP_DIR/Contents/MacOS" \
    "$APP_DIR/Contents/Resources/backend" \
    "$APP_DIR/Contents/Resources/semgrep" \
    "$APP_DIR/Contents/Resources/semgrep-rules" \
    "$APP_DIR/Contents/Resources/licenses"
cp "$BIN_DIR/SecFlowMac" "$APP_DIR/Contents/MacOS/SecFlowMac"
for RESOURCE_BUNDLE in "$BIN_DIR"/*.bundle; do
    [ -e "$RESOURCE_BUNDLE" ] || continue
    cp -R "$RESOURCE_BUNDLE" "$APP_DIR/Contents/Resources/"
done
cp -R "$BACKEND_BUILD_DIR/dist/secflow-backend/." "$APP_DIR/Contents/Resources/backend/"
cp -R "$SEMGREP_BUILD_DIR/dist/secflow-semgrep/." "$APP_DIR/Contents/Resources/semgrep/"
cp -R "$SEMGREP_RULES_PATH/." "$APP_DIR/Contents/Resources/semgrep-rules/"
SEMGREP_LICENSE_PATH="$($PYTHON_BIN - <<'PY'
from importlib.metadata import distribution

package = distribution("semgrep")
for entry in package.files or []:
    if str(entry).endswith("licenses/LICENSE"):
        print(package.locate_file(entry))
        break
PY
)"
[ -f "$SEMGREP_LICENSE_PATH" ] || { echo "Unable to locate the Semgrep LGPL license." >&2; exit 1; }
cp "$SEMGREP_LICENSE_PATH" "$APP_DIR/Contents/Resources/licenses/Semgrep-LGPL-2.1.txt"
TREE_SITTER_LICENSE_PATH="$($PYTHON_BIN - <<'PY'
from importlib.metadata import distribution

package = distribution("tree-sitter")
for entry in package.files or []:
    if str(entry).endswith("licenses/LICENSE"):
        print(package.locate_file(entry))
        break
PY
)"
[ -f "$TREE_SITTER_LICENSE_PATH" ] || { echo "Unable to locate the Tree-sitter MIT license." >&2; exit 1; }
cp "$TREE_SITTER_LICENSE_PATH" "$APP_DIR/Contents/Resources/licenses/Tree-sitter-MIT.txt"
for GRAMMAR_PACKAGE in java python go c cpp rust solidity; do
    GRAMMAR_LICENSE_PATH="$($PYTHON_BIN - "$GRAMMAR_PACKAGE" <<'PY'
from importlib.metadata import distribution
import sys

package = distribution(f"tree-sitter-{sys.argv[1]}")
for entry in package.files or []:
    if str(entry).lower().endswith(("/license", "/licenses/license")):
        print(package.locate_file(entry))
        break
PY
)"
    [ -f "$GRAMMAR_LICENSE_PATH" ] || { echo "Unable to locate the Tree-sitter $GRAMMAR_PACKAGE license." >&2; exit 1; }
    cp "$GRAMMAR_LICENSE_PATH" "$APP_DIR/Contents/Resources/licenses/Tree-sitter-${GRAMMAR_PACKAGE}-MIT.txt"
done
cp "$ROOT_DIR/licenses/D3-ISC.txt" "$APP_DIR/Contents/Resources/licenses/D3-ISC.txt"
cp "$ROOT_DIR/licenses/D3-Sankey-BSD-3-Clause.txt" "$APP_DIR/Contents/Resources/licenses/D3-Sankey-BSD-3-Clause.txt"
cp "$ROOT_DIR/licenses/THIRD-PARTY-NOTICES.txt" "$APP_DIR/Contents/Resources/licenses/THIRD-PARTY-NOTICES.txt"
xattr -cr "$APP_DIR/Contents/Resources/semgrep" 2>/dev/null || true
PYTHON_BIN="$PYTHON_BIN" bash \
    "$ROOT_DIR/scripts/validate_semgrep_runtime.sh" \
    "$APP_DIR/Contents/Resources/semgrep" \
    "$APP_DIR/Contents/Resources/semgrep-rules"
cp "$INFO_PLIST_PATH" "$APP_DIR/Contents/Info.plist"
codesign --force --deep --sign "${CODE_SIGN_IDENTITY:--}" "$APP_DIR"

echo "$APP_DIR"
