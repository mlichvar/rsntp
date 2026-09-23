debug:	test
	cargo build

release:	test
	cargo build --release

clean:
	cargo clean

test:
	cargo test
