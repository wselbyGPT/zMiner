#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip cargo rustc jq curl

echo
echo "Next:"
echo "  cargo build --manifest-path solver/Cargo.toml --release"
echo "  python3 -m miner.main template"
