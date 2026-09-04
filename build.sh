#!/usr/bin/env bash
# 交叉编译 HA-WBC-2 开机卡控制台全平台二进制
set -euo pipefail
cd "$(dirname "$0")"

APP=ha-wbc-console
VERSION="${VERSION:-1.3.6}"
DIST=dist
LDFLAGS="-s -w -X main.version=${VERSION}"

# 目标平台: GOOS GOARCH
TARGETS=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
  "windows amd64"
  "windows arm64"
  "windows 386"
)

rm -rf "$DIST"
mkdir -p "$DIST"

for t in "${TARGETS[@]}"; do
  read -r GOOS GOARCH <<<"$t"
  out="$DIST/${APP}_${VERSION}_${GOOS}_${GOARCH}"
  [ "$GOOS" = "windows" ] && out="${out}.exe"
  echo "==> 构建 $GOOS/$GOARCH"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$out" .
done

echo
echo "构建完成,产物位于 $DIST/:"
ls -lh "$DIST"
