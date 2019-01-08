CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -std=c++1z -fPIC

all:
	$(MAKE) -C src all
	$(MAKE) -C tests all
	@cargo build --release
	@cp -v target/release/libdet.so src
clean:
	$(MAKE) -C src clean
	$(MAKE) -C tests clean

tests:
	$(MAKE) -C tests tests

.PHONY: all clean tests
