CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -std=c++1z -fPIC

TARGET  := x64-save-return-address openat1 open-many getpid write-many forkExec clock-nanosleep threads1 threads2 threads3 getpid-pie nanosleep segfault threads4 threads5 threads6 threads7 forkMany

SYSTRACE_LIBRARY_PATH := $(shell realpath $(shell pwd)/../lib)
SYSTRACE_DEBUG := $(shell realpath ../bin/systrace) --library-path=$(SYSTRACE_LIBRARY_PATH) --debug=4 --
SYSTRACE := $(shell realpath ../bin/systrace) --library-path=$(SYSTRACE_LIBRARY_PATH) --debug=0 --

all: $(TARGET)

build-tests: $(TARGET)

SRCS	 = $(shell ls *.c)
OBJS	 = $(patsubst %.c, %.o, ${SRCS})

.c.o:
	$(CC) $< -c -o $@ $(CFLAGS)

.cc.o:
	$(CXX) $< -c -o $@ $(CXXFLAGS)

x64-save-return-address: x64-save-return-address.o
	$(CC) $^ -o $@ $(CFLAGS)

openat1: openat1.o
	$(CC) $^ -o $@ $(CFLAGS)

open-many: open-many.o
	$(CC) $^ -o $@ $(CFLAGS)

getpid: getpid.o
	$(CC) $^ -o $@ $(CFLAGS)

getpid-pie: getpid-pie.c
	$(CC) $^ -o $@ $(CFLAGS) -pie -fPIE -Wno-return-type

write-many: write-many.o
	$(CC) $^ -o $@ $(CFLAGS)
forkExec: forkExec.o
	$(CC) $^ -o $@ $(CFLAGS)
forkMany: forkMany.o
	$(CC) $^ -o $@ $(CFLAGS)

clock-nanosleep: clock-nanosleep.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

nanosleep: nanosleep.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

threads1: threads1.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

threads2: threads2.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

threads3: threads3.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

threads4: threads4.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

threads5: threads5.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

threads6: threads6.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

threads7: threads7.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

segfault: segfault.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

clean:
	$(RM) $(OBJS) *.o
	$(RM) $(TARGET)

tests: build-tests
	./x64-save-return-address
	$(SYSTRACE_DEBUG) ./openat1
	$(SYSTRACE_DEBUG) ./open-many > /dev/null
	$(SYSTRACE_DEBUG) ./write-many
	$(SYSTRACE_DEBUG) ./getpid
	$(SYSTRACE_DEBUG) ./nanosleep
	$(SYSTRACE_DEBUG) ./clock-nanosleep
	$(SYSTRACE_DEBUG) ./getpid-pie
	$(SYSTRACE_DEBUG) ./test1.sh
	$(SYSTRACE_DEBUG) ./test2.sh
	$(SYSTRACE_DEBUG) ./segfault && exit 1 || exit 0
	timeout 30s $(SYSTRACE_DEBUG) ./threads1
	timeout 30s $(SYSTRACE_DEBUG) ./threads2
	timeout 30s $(SYSTRACE_DEBUG) ./threads3
	timeout 30s $(SYSTRACE_DEBUG) ./threads4
	timeout 30s $(SYSTRACE_DEBUG) ./threads5
	timeout 30s $(SYSTRACE_DEBUG) ./threads6
	timeout 30s $(SYSTRACE_DEBUG) ./threads7
	timeout 30s $(SYSTRACE_DEBUG) ./forkMany
	timeout 30s $(SYSTRACE_DEBUG) ./forkMany --block-sigchld
	SYSTRACE="$(SYSTRACE)" ./build-musl-1.1.21.sh

.PHONY: all tests clean
