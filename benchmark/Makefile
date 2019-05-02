CC	 = clang
CXX	 = clang++
LD	 = lld

ECHO	 = /bin/echo

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -std=c++1z -fPIC

TARGET  := getpid getpid-many getpid-many-threaded gettime-many

SYSTRACE_LIBRARY_PATH := $(shell realpath $(shell pwd)/../target/debug)
SYSTRACE_TOOL         := $(shell realpath $(shell pwd)/../target/debug/libnone.so)
SYSTRACE_DEBUG := $(shell realpath ../bin/systrace) --tool=$(SYSTRACE_TOOL) --debug=4 --
SYSTRACE       := $(shell realpath ../bin/systrace) --tool=$(SYSTRACE_TOOL) --debug=0 --

all: $(TARGET)

build-benchmark: $(TARGET)

SRCS	 = $(shell ls *.c)
OBJS	 = $(patsubst %.c, %.o, ${SRCS})

.c.o:
	$(CC) $< -c -o $@ $(CFLAGS)

.cc.o:
	$(CXX) $< -c -o $@ $(CXXFLAGS)

getpid: getpid.o
	$(CC) $^ -o $@ $(CFLAGS)

getpid-many: getpid-many.o
	$(CC) $^ -o $@ $(CFLAGS)

getpid-many-threaded: getpid-many-threaded.o
	$(CC) $^ -o $@ $(CFLAGS) -lpthread

gettime-many: gettime-many.o
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	$(RM) $(OBJS) *.o
	$(RM) $(TARGET)

benchmark: build-benchmark
	-@$(ECHO) -ne "getpid..               " && ./getpid
	-@$(ECHO) -ne "getpid (systrace)..    " && $(SYSTRACE) ./getpid
	-@$(ECHO) -ne "getpid-many..               " && ./getpid-many 10000
	-@$(ECHO) -ne "getpid-many (systrace)..    " && $(SYSTRACE) ./getpid-many 10000
	-@$(ECHO) -ne "getpid-many (systrace)..    " && $(SYSTRACE) ./getpid-many 100000

bench: benchmark

.PHONY: all bench benchmark clean build-benchmark
