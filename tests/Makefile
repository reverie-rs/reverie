CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -std=c++1z -fPIC

TARGET  := x64-save-return-address openat1 open-many getpid write-many forkExec clock-nanosleep threads1 getpid-pie nanosleep segfault

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

clock-nanosleep: clock-nanosleep.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

nanosleep: nanosleep.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

threads1: threads1.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

segfault: segfault.o
	$(CC) $^ -o $@ $(CFLAGS) -lrt -lpthread

clean:
	$(RM) $(OBJS) *.o
	$(RM) $(TARGET)

tests: build-tests
	cd .. && ./tests/x64-save-return-address || exit 1
	cd .. && ./bin/systrace ./tests/openat1 || exit 1
	cd .. && ./bin/systrace ./tests/open-many > /dev/null || exit 1
	cd .. && ./bin/systrace ./tests/write-many || exit 1
	cd .. && ./bin/systrace ./tests/getpid || exit 1
	cd .. && ./bin/systrace ./tests/nanosleep || exit 1
	cd .. && ./bin/systrace ./tests/clock-nanosleep || exit 1
	cd .. && ./bin/systrace ./tests/getpid-pie || exit 1
	cd .. && ./bin/systrace ./tests/test1.sh || exit 1
	cd .. && ./bin/systrace ./tests/segfault || exit 0

.PHONY: all tests clean
