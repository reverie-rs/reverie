CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -std=c++1z -fPIC

all: libtrampoline.so libpreload.so bpf-trace

SRCS	 = $(shell ls *.c)
OBJS	 = $(patsubst %.c, %.o, ${SRCS})

.c.o:
	$(CC) $< -c -o $@ $(CFLAGS)

.cc.o:
	$(CXX) $< -c -o $@ $(CXXFLAGS)

libtrampoline.so: trampoline.o
	$(CC) $^ -o $@ -fpic -fPIC -shared -Wl,--no-as-needed -nostdlib

libpreload.so: syscallbuf.o raw_syscall.S
	$(CC) $^ -o $@ $(CFLAGS) -shared -Wl,--no-as-needed -lc -lrt

bpf-trace: bpf-trace.o watchpoint.o utils.o symbols.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -ldl

clean:
	$(RM) $(OBJS) *.o *.so bpf-trace
