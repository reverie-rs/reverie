CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -std=c++1z -fPIC

TARGET  := openat1 open-many getpid write-many forkExec clock-nanosleep threads1

all: $(TARGET)

SRCS	 = $(shell ls *.c)
OBJS	 = $(patsubst %.c, %.o, ${SRCS})

.c.o:
	$(CC) $< -c -o $@ $(CFLAGS)

.cc.o:
	$(CXX) $< -c -o $@ $(CXXFLAGS)

openat1: openat1.o
	$(CC) $^ -o $@ $(CFLAGS)

open-many: open-many.o
	$(CC) $^ -o $@ $(CFLAGS)

getpid: getpid.o
	$(CC) $^ -o $@ $(CFLAGS)
write-many: write-many.o
	$(CC) $^ -o $@ $(CFLAGS)
forkExec: forkExec.o
	$(CC) $^ -o $@ $(CFLAGS)

clock-nanosleep: clock-nanosleep.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

threads1: threads1.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

clean:
	$(RM) $(OBJS) *.o
	$(RM) $(TARGET)

tests:
	../src/bpf-trace ./openat1 || exit 1
	../src/bpf-trace ./open-many || exit 1
	../src/bpf-trace ./write-many || exit 1
	../src/bpf-trace ./clock-nanosleep || exit 1

.PHONY: all tests clean
