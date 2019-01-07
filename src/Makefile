CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -std=c++1z -fPIC

all: libpreload.so bpf-trace

SRCS	 = $(shell ls *.c)
OBJS	 = $(patsubst %.c, %.o, ${SRCS})

.c.o:
	$(CC) $< -c -o $@ $(CFLAGS)

.cc.o:
	$(CXX) $< -c -o $@ $(CXXFLAGS)

libpreload.so: trampoline.o syscallbuf.o raw_syscall.S
	$(CC) $^ -o $@ $(CFLAGS) -shared -Wl,--no-as-needed

syscallT.c: printSyscallT.hs
	./$< > $@

bpf-trace: bpf.o bpf-helper.o bpf-trace.o watchpoint.o utils.o symbols.o syscallT.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -ldl -rdynamic

clean:
	$(RM) $(OBJS) *.o *.so bpf-trace
