#!/bin/bash
set -e

if [ -z "$1" ]; then
  echo "Usage: ./release.sh v1.0.0"
  exit 1
fi

VERSION=$1
DIST_IDENTITY="Developer ID Application: Leonard Tan (X44L3QQYVR)"

echo "=== Building Go CLI ==="
mkdir -p touchfs-cli.app/Contents/MacOS
cp Info.plist touchfs-cli.app/Contents/Info.plist
cp embedded.provisionprofile touchfs-cli.app/Contents/embedded.provisionprofile
go build -ldflags "-X main.version=$VERSION" -o touchfs-cli.app/Contents/MacOS/touchfs .
codesign --force --options runtime --sign "$DIST_IDENTITY" --entitlements entitlements.plist touchfs-cli.app

echo "=== Notarizing CLI ==="
rm -f touchfs-cli.zip
ditto -c -k --keepParent touchfs-cli.app touchfs-cli.zip
xcrun notarytool submit touchfs-cli.zip --keychain-profile touchfs --wait
xcrun stapler staple touchfs-cli.app
rm -f touchfs-cli.zip
ditto -c -k --keepParent touchfs-cli.app touchfs-cli.zip

echo "=== Building Swift app ==="
cd app
xcodegen generate
rm -rf ~/Library/Developer/Xcode/DerivedData/TouchFS-*
xcodebuild -project TouchFS.xcodeproj -scheme TouchFS -configuration Release CODE_SIGN_IDENTITY="$DIST_IDENTITY" CODE_SIGN_STYLE=Manual clean build

BUILD_DIR=$(xcodebuild -project TouchFS.xcodeproj -scheme TouchFS -configuration Release -showBuildSettings 2>/dev/null | grep " BUILD_DIR = " | sed 's/.*= //')
APP="$BUILD_DIR/Release/TouchFS.app"

echo "=== Signing app ==="
codesign --force --options runtime --sign "$DIST_IDENTITY" "$APP"

echo "=== Notarizing app ==="
rm -f TouchFS.zip
ditto -c -k --keepParent "$APP" TouchFS.zip
xcrun notarytool submit TouchFS.zip --keychain-profile touchfs --wait
xcrun stapler staple "$APP"
rm -f TouchFS.zip

echo "=== Creating DMG ==="
DMG_NAME="TouchFS-${VERSION}.dmg"
rm -f "$DMG_NAME"
create-dmg \
  --volname "TouchFS" \
  --background "dmg-background.png" \
  --window-pos 200 120 \
  --window-size 540 380 \
  --icon-size 128 \
  --icon "TouchFS.app" 140 170 \
  --app-drop-link 400 170 \
  --no-internet-enable \
  --codesign "$DIST_IDENTITY" \
  --notarize "touchfs" \
  "$DMG_NAME" \
  "$APP"

cd ..

echo "=== Committing ==="
git add *.go go.mod go.sum Makefile README.md release.sh app/
git diff --cached --quiet || git commit -m "Release $VERSION"
git push

echo "=== Creating GitHub release ==="
if gh release view "$VERSION" > /dev/null 2>&1; then
  echo "Release $VERSION exists, uploading assets..."
  gh release upload "$VERSION" touchfs-cli.zip "app/$DMG_NAME" --clobber
else
  gh release create "$VERSION" touchfs-cli.zip "app/$DMG_NAME" --title "$VERSION" --notes "Release $VERSION"
fi

echo "=== Updating Homebrew tap ==="
SHA=$(shasum -a 256 touchfs-cli.zip | awk '{print $1}')
TAP_DIR="/tmp/homebrew-tap"
rm -rf "$TAP_DIR"
git clone git@github.com:tetratorus/homebrew-tap.git "$TAP_DIR"
cat > "$TAP_DIR/Casks/touchfs.rb" << EOF
cask "touchfs" do
  version "${VERSION#v}"
  sha256 "$SHA"

  url "https://github.com/tetratorus/touchfs/releases/download/v#{version}/touchfs-cli.zip"
  name "touchfs"
  desc "Touch ID-gated encrypted files"
  homepage "https://github.com/tetratorus/touchfs"

  depends_on cask: "fuse-t"

  app "touchfs-cli.app"

  binary "#{appdir}/touchfs-cli.app/Contents/MacOS/touchfs"

  uninstall quit: "com.bluzuli.touchfs"

  zap trash: []
end
EOF
cd "$TAP_DIR"
git add Casks/touchfs.rb
git commit -m "Update touchfs to $VERSION"
git push
cd -

echo "=== Done ==="
echo "CLI: touchfs-cli.zip"
echo "App: app/$DMG_NAME"
echo "GitHub: https://github.com/tetratorus/touchfs/releases/tag/$VERSION"
