# zkcash-miner-skeleton

A WSL/Ubuntu starter project for learning how a Zcash miner is put together:

- Python control plane for JSON-RPC against Zebra
- Rust solver binary that can run in three modes:
  - `none`: return no solution
  - `dummy`: return a plumbing-only zero nonce / zero solution
  - `real`: use the official Rust `equihash` crate's experimental Tromp-backed solver path
- Block/header serialization helpers
- Known-vector-style Python tests that lock down header byte order and `solutionSize` encoding

## What this project is, and is not

This repo is a **starter miner**, not a competitive production miner.

What works now:
- connect to Zebra RPC
- fetch and inspect `getblocktemplate`
- build Zcash `powheader` bytes exactly in the Zcash header layout
- serialize a raw candidate block from the template's coinbase + transactions
- call a Rust Equihash worker over a nonce window
- verify candidate block header difficulty on the Python side
- optionally try `submitblock`

What you still need for real mining:
- a long-running mining loop with work refresh and stale-work handling
- faster nonce scheduling / work partitioning
- pool protocol support (Stratum)
- performance work (SIMD/GPU, batching, telemetry)

## Why Zebra

The current Zebra docs explicitly support miners and mining pools through RPC, document cookie auth, and document custom Testnets where `disable_pow = true` can be used for plumbing bring-up.

## Recommended bring-up order

### 1) Plumbing-only local chain bring-up

Use a **custom Testnet** with `disable_pow = true` so you can test the program structure first.

Copy `examples/zebrad.custom-testnet.toml` to `~/.config/zebrad.toml`, then start Zebra:

```bash
mkdir -p ~/.config
cp examples/zebrad.custom-testnet.toml ~/.config/zebrad.toml
zebrad -c ~/.config/zebrad.toml
```

This config uses:
- `network = "Testnet"`
- `initial_testnet_peers = []`
- `[network.testnet_parameters]`
- `disable_pow = true`
- `NU6 = 1`
- RPC on `127.0.0.1:18232`

### 2) Install build dependencies and compile the solver

```bash
bash scripts/bootstrap_wsl.sh
cargo build --manifest-path solver/Cargo.toml --release
```

The real solver path uses the `equihash` crate with its `solver` feature, which builds the bundled Tromp solver through Cargo.

### 3) Fetch a template

```bash
python3 -m miner.main template
```

### 4) Build a candidate block with the dummy solver

```bash
python3 -m miner.main candidate --solver-mode dummy --write artifacts/
```

### 5) Build a candidate block with a real Equihash solution

On the custom Testnet, you usually want the first valid Equihash solution, even if it does not meet network difficulty:

```bash
python3 -m miner.main candidate \
  --solver-mode real \
  --no-target \
  --max-nonces 4 \
  --write artifacts/
```

On a network where difficulty matters, remove `--no-target` and increase `--max-nonces`.

### 6) Try block submission

```bash
python3 -m miner.main submit \
  --solver-mode real \
  --no-target \
  --max-nonces 4 \
  --write artifacts/
```

## Environment variables

Default settings work with the included custom Testnet config, but you can override them.

```bash
export ZCASH_RPC_URL=http://127.0.0.1:18232/
export ZCASH_RPC_COOKIE_PATH=~/.cache/zebra/.cookie
export ZCASH_RPC_DISABLE_COOKIE_AUTH=1
export ZCASH_SOLVER_BIN=./solver/target/release/zk_equihash_solver
```

If cookie auth is enabled, unset `ZCASH_RPC_DISABLE_COOKIE_AUTH`.

## Commands

### Show template summary

```bash
python3 -m miner.main template
```

### Build candidate only

```bash
python3 -m miner.main candidate \
  --solver-mode real \
  --max-nonces 16 \
  --write artifacts/
```

### Submit candidate block

```bash
python3 -m miner.main submit \
  --solver-mode real \
  --max-nonces 16 \
  --write artifacts/
```

### Solver modes

- `dummy`: zero nonce + zero-filled 1344-byte solution for plumbing tests only
- `none`: always return no solution
- `real`: scan a nonce window using the Rust Equihash solver

## Tests

Python byte-order / serialization tests:

```bash
python3 -m unittest discover -s tests -v
```

## Project layout

```text
miner/
  config.py
  rpc.py
  protocol.py
  solver.py
  main.py
solver/
  Cargo.toml
  src/main.rs
tests/
  test_protocol.py
examples/
  zebrad.custom-testnet.toml
scripts/
  bootstrap_wsl.sh
```

## Important caveats

1. The Python side assumes the block template is used **unmodified**, so it trusts `defaultroots` when available.
2. The Rust solver currently scans one nonce per solver call. That is fine for correctness bring-up, but not for competitive performance.
3. The `real` solver mode produces valid Equihash solutions, but on Mainnet/Testnet you still need the candidate header hash to be below the target threshold.
4. The included tests lock down header byte order and `compactSize(1344)`, but they are not a substitute for full end-to-end validation against known chain data.
