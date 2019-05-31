CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -std=c++1z -fPIC

DOCKER_NAME=systrace

# Build Rust code in release or debug mode?  (Blank for debug.)
# WAY="--release"
WAY=

# TOOL_TARGET
TOOL_TARGET=x86_64-unknown-linux-musl

ifeq ($(WAY),"--release")
	TARGETDIR=release
else
	TARGETDIR=debug
endif

all:
	$(MAKE) -C tests all
	@cargo build $(WAY)
	@cargo build $(WAY) -p echo    --target=$(TOOL_TARGET)
	@cargo build $(WAY) -p none    --target=$(TOOL_TARGET)
	@cargo build $(WAY) -p counter --target=$(TOOL_TARGET)
	@cargo build $(WAY) -p det     --target=$(TOOL_TARGET)
	@cp -v target/$(TARGETDIR)/rust-staticlib-linker bin/
	@cp -v target/$(TARGETDIR)/systrace bin/
	@./bin/rust-staticlib-linker --export=captured_syscall --export=untraced_syscall --staticlib=target/x86_64-unknown-linux-musl/debug/libecho.a --staticcrt=/usr/lib/x86_64-linux-musl/libc.a -o lib/libecho.so
	@./bin/rust-staticlib-linker --export=captured_syscall --export=untraced_syscall --staticlib=target/x86_64-unknown-linux-musl/debug/libnone.a --staticcrt=/usr/lib/x86_64-linux-musl/libc.a -o lib/libnone.so
	@./bin/rust-staticlib-linker --export=captured_syscall --export=untraced_syscall --staticlib=target/x86_64-unknown-linux-musl/debug/libcounter.a --staticcrt=/usr/lib/x86_64-linux-musl/libc.a -o lib/libcounter.so
	@./bin/rust-staticlib-linker --export=captured_syscall --export=untraced_syscall --staticlib=target/x86_64-unknown-linux-musl/debug/libdet.a --staticcrt=/usr/lib/x86_64-linux-musl/libc.a -o lib/libdet.so

clean:
	$(MAKE) -C tests clean
	$(RM) lib/lib*.so
	$(RM) bin/systrace
	$(RM) bin/rust-staticlib-linker
	@cargo clean

test: tests
tests: all
	cargo test $(WAY) -- --nocapture
	$(MAKE) -C tests tests

bench: all
	$(MAKE) -C benchmark bench

docker:
	docker build -t $(DOCKER_NAME) .

run-docker: docker
	docker run -it --privileged --cap-add=SYS_ADMIN $(DOCKER_NAME)

test-docker: clean docker
	docker run --privileged --cap-add=SYS_ADMIN $(DOCKER_NAME) make -j tests

.PHONY: all clean tests test docker run-docker test-docker
