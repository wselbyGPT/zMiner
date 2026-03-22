#!/usr/bin/env bash
set -euo pipefail

echo "== uname =="
uname -a || true

echo
echo "== nvidia-smi =="
if command -v nvidia-smi >/dev/null 2>&1; then
  nvidia-smi || true
else
  echo "nvidia-smi not found"
fi

echo
echo "== nvcc =="
if command -v nvcc >/dev/null 2>&1; then
  nvcc --version || true
else
  echo "nvcc not found"
fi

echo
echo "== libcuda stub =="
ls -l /usr/lib/wsl/lib/libcuda.so* 2>/dev/null || echo "libcuda stub not found under /usr/lib/wsl/lib"

echo
echo "== python cuda probe =="
python3 -m miner.main cuda-probe || true
