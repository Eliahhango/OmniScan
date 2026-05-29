#!/bin/bash
# OmniScan cross-platform build script
set -e

BINARY="omniscan"
BUILD_DIR="build"
VERSION="${1:-dev}"

echo "Building OmniScan $VERSION for all platforms..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

platforms=(
  "linux/amd64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
)

output_names=(
  "omniscan-linux"
  "omniscan-darwin"
  "omniscan-darwin-arm64"
  "omniscan-windows.exe"
)

for i in "${!platforms[@]}"; do
  platform="${platforms[$i]}"
  output="${BUILD_DIR}/${output_names[$i]}"
  IFS='/' read -r GOOS GOARCH <<< "$platform"

  echo "  Building for $GOOS/$GOARCH..."
  GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -ldflags="-s -w -X main.Version=$VERSION" \
    -o "$output" ./cmd/omniscan

  if [ -f "$output" ]; then
    echo "    -> $output ($(ls -lh "$output" | awk '{print $5}'))"
  fi
done

echo ""
echo "Checksums:"
cd "$BUILD_DIR"
sha256sum * | tee checksums.txt
echo ""
echo "Build complete. Binaries in $BUILD_DIR/"
