EBPF_TARGET := bpfel-unknown-none

.PHONY: build-ebpf build run clean

build-ebpf:
	rustup run nightly cargo build -p profiler-ebpf \
		--target $(EBPF_TARGET) \
		-Z build-std=core \
		--release

build: build-ebpf
	cargo build -p profiler --release

run: build
	sudo ./target/release/profiler

clean:
	cargo clean
