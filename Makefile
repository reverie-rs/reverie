CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -std=c++1z -fPIC

# Build Rust code in release or debug mode?  (Blank for debug.)
# WAY="--release"
WAY=

ifeq ($(WAY),"--release")
	TARGETDIR=release
else
	TARGETDIR=debug
endif

all:
	$(MAKE) -C src all
	$(MAKE) -C tests all
	@cargo build $(WAY)
	@cargo build $(WAY) --manifest-path=examples/echotool/Cargo.toml
#	@cargo build $(WAY) --manifest-path=examples/counttool/Cargo.toml
	@cp -v src/libsystrace.so lib/
	@cp -v examples/echotool/target/$(TARGETDIR)/libechotool.so lib/
	@cp -v target/$(TARGETDIR)/systrace bin/
# @if [ "$(WAY)" == "--release" ]; \
        #   then cp -v examples/echotool/target/release/libechotool.so lib/; \
        #        cp -v target/release/systrace bin/; \
        #   else cp -v examples/echotool/target/debug/libechotool.so lib/; \
        #        cp -v target/debug/systrace bin/; fi
clean:
	$(MAKE) -C src clean
	$(MAKE) -C tests clean
	$(RM) lib/libechotool.so lib/libsystrace.so
	$(RM) bin/systrace
	@cargo clean
	@cargo clean --manifest-path=examples/echotool/Cargo.toml

test: tests
tests: all
	cargo test $(WAY) -- --nocapture
	$(MAKE) -C tests tests

.PHONY: all clean tests test
