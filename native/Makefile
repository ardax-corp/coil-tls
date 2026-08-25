.PHONY: artifact test release clean

artifact:
	cargo build --release
	@if [ -f target/release/libtls.so ]; then cp -f target/release/libtls.so libtls.so; fi
	@if [ -f target/release/libtls.dylib ]; then cp -f target/release/libtls.dylib libtls.dylib; fi
	@if [ -f target/release/tls.dll ]; then cp -f target/release/tls.dll tls.dll; fi

test:
	cargo test

release:
	cargo build --release

clean:
	cargo clean
	rm -f libtls.so libtls.dylib tls.dll
