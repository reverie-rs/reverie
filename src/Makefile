CC	 = clang
CXX	 = clang++
LD	 = lld

INCLUDE  = -I../include -I.
CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -fPIC $(INCLUDE)
CXXFLAGS = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -D_GNU_SOURCE=1 -std=c++1z -fPIC $(INCLUDE)

all: libsystrace.so

SRCS	 = $(shell ls *.c)
OBJS	 = $(patsubst %.c, %.o, ${SRCS})

.S.o:
	$(CC) $< -c -o $@ $(CFLAGS)
.c.o:
	$(CC) $< -c -o $@ $(CFLAGS)

.cc.o:
	$(CXX) $< -c -o $@ $(CXXFLAGS)

libsystrace.so: trampoline.o route.o raw_syscall.o
	$(CC) $^ -o $@ $(CFLAGS) -nostdlib -shared -Wl,--no-as-needed

clean:
	$(RM) $(OBJS) *.o *.so
