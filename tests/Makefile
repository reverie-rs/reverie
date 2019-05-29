CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -std=c++1z -fPIC

TARGET  := x64-save-return-address openat1 open-many getpid write-many forkExec clock-nanosleep threads1 threads2 threads3 getpid-pie nanosleep segfault threads4 threads5 threads6 threads7 forkMany signal1 signal2 signal3 signal4 sigprocmask1 thread8-cond-wait thread9-cond-bcast
 
SYSTRACE_LIBRARY_PATH := $(shell realpath $(shell pwd)/../target/debug)
SYSTRACE_TOOL         := $(SYSTRACE_LIBRARY_PATH)/libecho.so
SYSTRACE_DEBUG := $(shell realpath ../bin/systrace) --tool=$(SYSTRACE_TOOL) --debug=4 --
SYSTRACE       := $(shell realpath ../bin/systrace) --tool=$(SYSTRACE_TOOL) --debug=0 --
IO_REDIRECT = 2>/dev/null

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

thread8-cond-wait: thread8-cond-wait.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

thread9-cond-bcast: thread9-cond-bcast.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

segfault: segfault.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

signal1: signal1.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt

signal2: signal2.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt

signal3: signal3.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt

signal4: signal4.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

sigprocmask1: sigprocmask1.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt

clean:
	$(RM) $(OBJS) *.o
	$(RM) $(TARGET)

tests: build-tests
	./x64-save-return-address
	RUST_BACKTRACE=1 $(SYSTRACE_DEBUG) ./openat1 $(IO_REDICT)
	$(SYSTRACE_DEBUG) ./open-many $(IO_REDIRECT)
	$(SYSTRACE_DEBUG) ./write-many $(IO_REDIRECT)
	$(SYSTRACE_DEBUG) ./getpid $(IO_REDIRECT)
	$(SYSTRACE_DEBUG) ./nanosleep $(IO_REDIRECT)
	$(SYSTRACE_DEBUG) ./clock-nanosleep $(IO_REDIRECT)
	$(SYSTRACE_DEBUG) ./getpid-pie $(IO_REDIRECT)
	$(SYSTRACE_DEBUG) ./test1.sh $(IO_REDIRECT)
	$(SYSTRACE_DEBUG) ./test2.sh $(IO_REDIRECT)
	$(SYSTRACE_DEBUG) ./segfault && exit 1 || exit 0 $(IO_REDIRECT)
	timeout 30s $(SYSTRACE_DEBUG) ./threads1 $(IO_REDIRECT)
	timeout 30s $(SYSTRACE_DEBUG) ./threads2 $(IO_REDIRECT)
	timeout 30s $(SYSTRACE_DEBUG) ./threads3 $(IO_REDIRECT)
	timeout 30s $(SYSTRACE_DEBUG) ./threads4 $(IO_REDIRECT)
	timeout 30s $(SYSTRACE_DEBUG) ./threads5 $(IO_REDIRECT)
	timeout 30s $(SYSTRACE_DEBUG) ./threads6 $(IO_REDIRECT)
	timeout 30s $(SYSTRACE_DEBUG) ./threads7 $(IO_REDIRECT)
	timeout 30s $(SYSTRACE_DEBUG) ./forkMany $(IO_REDIRECT)
	timeout 30s $(SYSTRACE_DEBUG) ./forkMany --block-sigchld $(IO_REDIRECT)
	./signal1 $(IO_REDIRECT)
	./signal2 $(IO_REDIRECT)
	./signal3 $(IO_REDIRECT)
	./sigprocmask1 $(IO_REDIRECT)
	$(SYSTRACE_DEBUG) ./thread8-cond-wait $(IO_REDIRECT)
	$(SYSTRACE_DEBUG) ./thread9-cond-bcast $(IO_REDIRECT)

.PHONY: all tests clean
