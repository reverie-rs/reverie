CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -std=c++1z -fPIC

DOCKER_NAME=systrace

# Build Rust code in release or debug mode?  (Blank for debug.)
# WAY="--release"
WAY=

ifeq ($(WAY),"--release")
	TARGETDIR=release
else
	TARGETDIR=debug
endif

all:
	$(MAKE) -C tests all
	@cargo build $(WAY) --all
	@cargo build --manifest-path examples/echo/Cargo.toml --target-dir=target
	@cp -v target/$(TARGETDIR)/libpreloader.so lib/
	@cp -v target/$(TARGETDIR)/libecho.so lib/
	@cp -v target/$(TARGETDIR)/libnone.so lib/
	@cp -v target/$(TARGETDIR)/libcounter.so lib/
	@cp -v target/$(TARGETDIR)/libdet.so lib/
	@cp -v target/$(TARGETDIR)/systrace bin/
clean:
	$(MAKE) -C tests clean
	$(RM) lib/lib*.so
	$(RM) bin/systrace
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
