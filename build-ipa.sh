#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PROJECT="$ROOT/WorseWatched.xcodeproj"
SCHEME="WorseWatched"
DERIVED="$ROOT/build/DerivedData"
APP_NAME="worsewatched"
APP="$DERIVED/Build/Products/Release-iphoneos/${APP_NAME}.app"
WATCH_PRODUCT="$DERIVED/Build/Products/Release-watchos/worsewatched Watch App.app"
WATCH_APP="$APP/Watch/worsewatched Watch App.app"

command -v xcodebuild >/dev/null 2>&1 || {
  echo "[!] xcodebuild not found"
  exit 1
}
command -v ditto >/dev/null 2>&1 || {
  echo "[!] ditto not found"
  exit 1
}
command -v zip >/dev/null 2>&1 || {
  echo "[!] zip not found"
  exit 1
}

rm -rf "$ROOT/build"
rm -f "$ROOT/${APP_NAME}.ipa"
mkdir -p "$ROOT/build"

echo "[*] Building unsigned iPhone app and watchOS companion..."
xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration Release \
  -derivedDataPath "$DERIVED" \
  -destination 'generic/platform=iOS' \
  clean build \
  CODE_SIGN_IDENTITY=- \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO

[ -d "$APP" ] || {
  echo "[!] iPhone app product missing: $APP"
  exit 1
}

# Xcode's Embed Watch Content phase should put the companion in Watch/.
# Copy the built product only when that phase did not create the destination.
if [ ! -d "$WATCH_APP" ]; then
  [ -d "$WATCH_PRODUCT" ] || {
    echo "[!] Watch app product missing. Expected either:"
    echo "    $WATCH_APP"
    echo "    $WATCH_PRODUCT"
    exit 1
  }
  mkdir -p "$APP/Watch"
  ditto "$WATCH_PRODUCT" "$WATCH_APP"
fi

# Validate both app bundles without modifying or signing their executables.
for BUNDLE in "$APP" "$WATCH_APP"; do
  test -f "$BUNDLE/Info.plist" || {
    echo "[!] Missing Info.plist in bundle: $BUNDLE"
    exit 1
  }

  EXECUTABLE="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$BUNDLE/Info.plist")"
  EXECUTABLE_PATH="$BUNDLE/$EXECUTABLE"
  test -f "$EXECUTABLE_PATH" || {
    echo "[!] Executable missing in bundle: $EXECUTABLE_PATH"
    exit 1
  }

  # The requested output is unsigned: fail if Xcode or a copy phase left a signature.
  if /usr/bin/codesign -dv "$BUNDLE" >/dev/null 2>&1; then
    echo "[!] Expected an unsigned app, but a code signature exists: $BUNDLE"
    exit 1
  fi
 done

IOS_ID="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Info.plist")"
WATCH_ID="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$WATCH_APP/Info.plist")"
test "$IOS_ID" = "com.ceoca.worsewatch" || {
  echo "[!] Unexpected iPhone Bundle ID: $IOS_ID"
  exit 1
}
test "$WATCH_ID" = "com.ceoca.worsewatch.watchkitapp" || {
  echo "[!] Unexpected Watch Bundle ID: $WATCH_ID"
  exit 1
}

echo "[*] Packaging unsigned IPA..."
mkdir -p "$ROOT/build/Payload"
ditto "$APP" "$ROOT/build/Payload/${APP_NAME}.app"
(
  cd "$ROOT/build"
  /usr/bin/zip -qry "$ROOT/${APP_NAME}.ipa" Payload
)

# Verify the archive actually contains both bundles and remains unsigned.
VERIFY="$ROOT/build/verify"
mkdir -p "$VERIFY"
unzip -q "$ROOT/${APP_NAME}.ipa" -d "$VERIFY"
PACKAGED_APP="$VERIFY/Payload/${APP_NAME}.app"
PACKAGED_WATCH="$PACKAGED_APP/Watch/worsewatched Watch App.app"
test -f "$PACKAGED_APP/Info.plist"
test -f "$PACKAGED_WATCH/Info.plist"
if /usr/bin/codesign -dv "$PACKAGED_APP" >/dev/null 2>&1; then
  echo "[!] Packaged iPhone app is unexpectedly signed"
  exit 1
fi
if /usr/bin/codesign -dv "$PACKAGED_WATCH" >/dev/null 2>&1; then
  echo "[!] Packaged Watch app is unexpectedly signed"
  exit 1
fi

rm -rf "$ROOT/build/Payload" "$VERIFY"
echo "[+] Created unsigned IPA: $ROOT/${APP_NAME}.ipa"
echo "[+] iPhone Bundle ID: $IOS_ID"
echo "[+] Watch Bundle ID: $WATCH_ID"
echo "[+] Embedded Watch app: Watch/worsewatched Watch App.app"
