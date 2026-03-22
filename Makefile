.PHONY: solver template candidate submit

solver:
	cargo build --manifest-path solver/Cargo.toml --release

template:
	python3 -m miner.main template

candidate:
	python3 -m miner.main candidate --solver-mode dummy --write artifacts/

submit:
	python3 -m miner.main submit --solver-mode dummy --write artifacts/
