.PHONY: fmt lint test

fmt:
	cargo +nightly fmt

lint:
	cargo +nightly clippy --all-targets -- -D warnings

test:
	cargo +nightly test
