CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -std=c++1z -fPIC

all:
	$(MAKE) -C src all
	$(MAKE) -C tests all
	@cargo build --release
	@cargo build --release --manifest-path=libdet/Cargo.toml
	@cp -v src/libsystrace.so lib
	@cp -v libdet/target/release/libdet.so lib
	@cp -v target/release/systrace bin
	@cp -v src/bpf-trace bin
clean:
	$(MAKE) -C src clean
	$(MAKE) -C tests clean
	$(RM) lib/libdet.so lib/libsystrace.so
	$(RM) bin/bpf-trace
	$(RM) bin/systrace
	@cargo clean
	@cargo clean --manifest-path=libdet/Cargo.toml

tests: all
	cargo test --release -- --nocapture
	$(MAKE) -C tests tests

.PHONY: all clean tests
