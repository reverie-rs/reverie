CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -std=c++1z -fPIC

TARGET  := x64-save-return-address openat1 open-many getpid write-many forkExec clock-nanosleep threads1 threads2 threads3 getpid-pie nanosleep segfault threads4 threads5 threads6 threads7

SYSTRACE := ../bin/systrace --library-path=$(shell pwd)/../lib --
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
	./x64-save-return-address || exit 1
	$(SYSTRACE) ./openat1 || exit 1
	$(SYSTRACE) ./open-many > /dev/null || exit 1
	$(SYSTRACE) ./write-many || exit 1
	$(SYSTRACE) ./getpid || exit 1
	$(SYSTRACE) ./nanosleep || exit 1
	$(SYSTRACE) ./clock-nanosleep || exit 1
	$(SYSTRACE) ./getpid-pie || exit 1
	$(SYSTRACE) ./test1.sh || echo "test1 returned $$?"
	$(SYSTRACE) ./test2.sh || echo "test2 returned $$?"
	$(SYSTRACE) ./segfault && exit 1 || exit 0
	timeout 30s $(SYSTRACE) ./threads1 || exit 1
	timeout 30s $(SYSTRACE) ./threads2 || exit 1
	timeout 30s $(SYSTRACE) ./threads3 || exit 1
	timeout 30s $(SYSTRACE) ./threads4 || exit 1
	timeout 30s $(SYSTRACE) ./threads5 || exit 1
	timeout 30s $(SYSTRACE) ./threads6 || exit 1

.PHONY: all tests clean
