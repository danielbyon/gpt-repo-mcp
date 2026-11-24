override RUST_TOOLCHAIN := 1.98.1
RUSTUP ?= rustup
override RUST_TOOLCHAIN_BIN := $(patsubst %/,%,$(dir $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) cargo 2>/dev/null)))
override CARGO_BIN := $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) cargo 2>/dev/null)
override RUSTC_BIN := $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) rustc 2>/dev/null)
override RUSTFMT_BIN := $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) rustfmt 2>/dev/null)
TOOLCHAIN_ENV = env -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
	RUSTUP_TOOLCHAIN=$(RUST_TOOLCHAIN) \
	RUSTC=$(RUSTC_BIN) \
	RUSTFMT=$(RUSTFMT_BIN) \
	PATH="$(RUST_TOOLCHAIN_BIN):$$PATH"
override CARGO := $(TOOLCHAIN_ENV) $(CARGO_BIN)
RUST_TEST_THREADS ?= 1

.PHONY: all
all:
	RUST_TEST_THREADS=$(RUST_TEST_THREADS) $(CARGO) test --all-features --locked -- --nocapture
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -v -s tests -p 'test_smoke.py'
