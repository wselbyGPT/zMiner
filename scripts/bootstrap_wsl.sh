#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y   python3 python3-venv python3-pip   cargo rustc jq curl cmake build-essential

echo
echo "Next:"
echo "  cargo build --manifest-path solver/Cargo.toml --release"
echo "  cmake -S cuda -B cuda/build -DCMAKE_BUILD_TYPE=Release"
echo "  cmake --build cuda/build -j"
echo "  python3 -m miner.main cuda-probe"
