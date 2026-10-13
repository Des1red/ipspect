#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/internal/database/data/requests"

API="https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/network/detection"

mkdir -p "$DEST"

curl -fsSL "$API" |
    jq -r '
        .[]
        | select(.type == "file")
        | select(.name | endswith(".yaml"))
        | .download_url
    ' |
    while IFS= read -r url; do
        name="${url##*/}"
        curl -fsSL --retry 3 "$url" -o "$DEST/$name"
        printf '[+] %s\n' "$name"
    done

curl -fsSL \
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/LICENSE.md" \
    -o "$DEST/LICENSE.md"

echo "[+] Request templates downloaded"
