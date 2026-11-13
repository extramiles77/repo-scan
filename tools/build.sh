#!/usr/bin/env bash
# Membuat paket rilis di dist/: repo-scan.plugin (plugin) dan repo-scan-skill.zip (skill saja)
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf dist && mkdir -p dist
find . -name "__pycache__" -type d -prune -exec rm -rf {} +
zip -qr dist/repo-scan.plugin .claude-plugin skills README.md README.en.md LICENSE -x "*.DS_Store"
(cd skills && zip -qr ../dist/repo-scan-skill.zip repo-scan -x "*.DS_Store")
echo "dist/repo-scan.plugin"; echo "dist/repo-scan-skill.zip"
