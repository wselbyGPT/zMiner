.PHONY: solver cuda template candidate candidate-hybrid submit submit-hybrid cuda-probe test

solver:
	cargo build --manifest-path solver/Cargo.toml --release

cuda:
	cmake -S cuda -B cuda/build -DCMAKE_BUILD_TYPE=Release
	cmake --build cuda/build -j

template:
	python3 -m miner.main template

candidate:
	python3 -m miner.main candidate --solver-mode dummy --write artifacts/

candidate-hybrid:
	python3 -m miner.main candidate-hybrid --no-target --cpu-fallback --write artifacts/

submit:
	python3 -m miner.main submit --solver-mode dummy --write artifacts/

submit-hybrid:
	python3 -m miner.main submit-hybrid --no-target --cpu-fallback --write artifacts/

cuda-probe:
	python3 -m miner.main cuda-probe

test:
	python3 -m unittest discover -s tests -v
