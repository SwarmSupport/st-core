#!/usr/bin/env bash
set -euo pipefail

platform="${1:-}"
case "$platform" in
  android|ios) ;;
  *) echo "Usage: $0 android|ios [iOS bundle ID]" >&2; exit 2 ;;
esac

go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
export PATH="$(go env GOPATH)/bin:$PATH"
gomobile init

mkdir -p dist
if [[ "$platform" == android ]]; then
  gomobile bind -target=android -o dist/st-core.aar ./mobilecore
else
  bundle_id="${2:-org.swarmtools.stcore}"
  gomobile bind -target=ios -bundleid "$bundle_id" -o dist/STCore.xcframework ./mobilecore
fi
