#!/bin/bash
set -e

if [ -z "$1" ]; then
  echo "Usage: ./release.sh v1.0.1"
  exit 1
fi

VERSION=$1
TAP_DIR="/tmp/homebrew-tap"

echo "=== Building ==="
make dist VERSION="$VERSION"

echo "=== Notarizing ==="
rm -f touchfs.zip
ditto -c -k --keepParent touchfs.app touchfs.zip
xcrun notarytool submit touchfs.zip --keychain-profile touchfs --wait
xcrun stapler staple touchfs.app
rm -f touchfs.zip
ditto -c -k --keepParent touchfs.app touchfs.zip

SHA=$(shasum -a 256 touchfs.zip | awk '{print $1}')
echo "SHA256: $SHA"

echo "=== Committing ==="
git add *.go go.mod go.sum Makefile README.md release.sh
git diff --cached --quiet || git commit -m "Release $VERSION"
git push

echo "=== Creating GitHub release ==="
gh release create "$VERSION" touchfs.zip --title "$VERSION" --notes "Release $VERSION"

echo "=== Updating Homebrew tap ==="
rm -rf "$TAP_DIR"
git clone git@github.com:tetratorus/homebrew-tap.git "$TAP_DIR"

cat > "$TAP_DIR/Casks/touchfs.rb" << EOF
cask "touchfs" do
  version "${VERSION#v}"
  sha256 "$SHA"

  url "https://github.com/tetratorus/touchfs/releases/download/v#{version}/touchfs.zip"
  name "touchfs"
  desc "Touch ID-gated encrypted files"
  homepage "https://github.com/tetratorus/touchfs"

  depends_on cask: "fuse-t"

  app "touchfs.app"

  binary "#{appdir}/touchfs.app/Contents/MacOS/touchfs"

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
echo "brew tap tetratorus/tap && brew install --cask touchfs"
