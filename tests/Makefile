CC	 = clang
CXX	 = clang++
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -fPIC
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -std=c++1z -fPIC

all: openat1 open-many

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

clean:
	$(RM) $(OBJS) *.o openat1
