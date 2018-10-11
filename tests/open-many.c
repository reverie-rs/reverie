#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

int main(int argc, char* argv[])
{
	const char* file = "/etc/passwd";
	int fd;

	for (int i = 0; i < 100000; i++) {
		fd = open(file, O_RDONLY);
		assert(fd >= 0);
		close(fd);
	}

	return 0;
}
