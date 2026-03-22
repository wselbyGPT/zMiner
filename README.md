# zkcash-miner-skeleton

A WSL/Ubuntu starter project for learning how a Zcash miner is put together:

- Python control plane for JSON-RPC against Zebra
- Rust Equihash worker for correctness-first CPU solving
- Experimental CUDA worker for GPU device probing and batched SHA-256d target checks
- Block/header serialization helpers
- Python tests that lock down header byte order, fixed header length, and `solutionSize` encoding

## What this project is, and is not

This repo is a **starter miner**, not a competitive production miner.

What works now:
- connect to Zebra RPC
- fetch and inspect `getblocktemplate`
- build Zcash `powheader` bytes exactly in the Zcash header layout
- serialize a raw candidate block from the template's coinbase + transactions
- call a Rust Equihash worker over a nonce window
- batch valid Equihash candidates and run target checks through an experimental CUDA worker
- optionally try `submitblock`

What you still need for real mining:
- a long-running mining loop with work refresh and stale-work handling
- faster nonce scheduling / work partitioning
- pool protocol support (Stratum)
- a **true GPU Equihash kernel** if you want meaningful GPU-side solving rather than hybrid target filtering
- performance work (telemetry, batching policy, occupancy tuning, memory reuse)

## Why the CUDA path is labeled experimental

The new CUDA path is a **hybrid design**:

1. the Rust worker finds valid Equihash solutions on CPU,
2. Python batches those candidate headers,
3. the CUDA worker runs the SHA-256d target checks for the batch on GPU.

That means the CUDA code is real and useful for GPU bring-up, but it **does not yet solve Equihash on the GPU**. Equihash solving still dominates the cost, so this is mainly a stepping stone toward a future full GPU solver.

## Recommended bring-up order

### 1) Plumbing-only local chain bring-up

Use a **custom Testnet** with `disable_pow = true` so you can test the program structure first.

Copy `examples/zebrad.custom-testnet.toml` to `~/.config/zebrad.toml`, then start Zebra:

```bash
mkdir -p ~/.config
cp examples/zebrad.custom-testnet.toml ~/.config/zebrad.toml
zebrad -c ~/.config/zebrad.toml
```

### 2) Install build dependencies and compile the Rust solver

```bash
bash scripts/bootstrap_wsl.sh
cargo build --manifest-path solver/Cargo.toml --release
```

### 3) Build the CUDA worker

This assumes your WSL environment already has CUDA toolkit tooling like `nvcc` available.

```bash
cmake -S cuda -B cuda/build -DCMAKE_BUILD_TYPE=Release
cmake --build cuda/build -j
```

### 4) Probe CUDA from the CLI

```bash
python3 -m miner.main cuda-probe
```

### 5) Fetch a template

```bash
python3 -m miner.main template
```

### 6) Build a candidate block with the CPU solver only

```bash
python3 -m miner.main candidate   --solver-mode real   --no-target   --max-nonces 4   --write artifacts/
```

### 7) Build a candidate with the hybrid CPU+CUDA path

```bash
python3 -m miner.main candidate-hybrid   --no-target   --max-nonces 32   --max-solutions 8   --cpu-fallback   --write artifacts/
```

On a real difficulty-checked network, remove `--no-target` and increase the nonce window.

## Environment variables

```bash
export ZCASH_RPC_URL=http://127.0.0.1:18232/
export ZCASH_RPC_COOKIE_PATH=~/.cache/zebra/.cookie
export ZCASH_RPC_DISABLE_COOKIE_AUTH=1
export ZCASH_SOLVER_BIN=./solver/target/release/zk_equihash_solver
export ZCASH_CUDA_SOLVER_BIN=./cuda/build/zk_cuda_worker
```

## Commands

### Show template summary

```bash
python3 -m miner.main template
```

### Probe CUDA worker/device visibility

```bash
python3 -m miner.main cuda-probe
```

### Build candidate only

```bash
python3 -m miner.main candidate   --solver-mode real   --max-nonces 16   --write artifacts/
```

### Build candidate using hybrid CPU Equihash + CUDA target checks

```bash
python3 -m miner.main candidate-hybrid   --max-nonces 64   --max-solutions 8   --cpu-fallback   --write artifacts/
```

### Submit candidate block using hybrid mode

```bash
python3 -m miner.main submit-hybrid   --max-nonces 64   --max-solutions 8   --cpu-fallback   --write artifacts/
```

### Solver modes

- `dummy`: zero nonce + zero-filled 1344-byte solution for plumbing tests only
- `none`: always return no solution
- `real`: scan a nonce window using the Rust Equihash solver
- `real_batch`: internal mode used by the hybrid command to collect multiple valid Equihash candidates

## Tests

Python byte-order / serialization tests:

```bash
python3 -m unittest discover -s tests -v
```

CUDA worker self-test (CPU-side SHA-256d vector check inside the CUDA binary):

```bash
./cuda/build/zk_cuda_worker selftest
```

## Project layout

```text
miner/
  config.py
  cuda.py
  rpc.py
  protocol.py
  solver.py
  main.py
solver/
  Cargo.toml
  src/main.rs
cuda/
  CMakeLists.txt
  src/main.cu
tests/
  test_protocol.py
examples/
  zebrad.custom-testnet.toml
scripts/
  bootstrap_wsl.sh
  check_wsl_cuda.sh
```

## Important caveats

1. The Python side assumes the block template is used **unmodified**, so it trusts `defaultroots` when available.
2. The Rust solver is still CPU-first and scans a small nonce window. That is good for correctness bring-up, not competitive mining.
3. The CUDA worker currently accelerates **target checking**, not Equihash solving.
4. The included tests lock down header byte order and `compactSize(1344)`, but they are not a substitute for end-to-end validation against known chain data.
