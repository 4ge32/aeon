#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#define AEON_IOC_DENTRY_ATTACK _IOWR('f', 6, long)
#define AEON_IOC_GETFLAGS FS_IOC_GETFLAGS

int main(int argc, char *argv[])
{
	char *path;
	int fd;
	int err;
	int arg = 1;

	if (argc != 2) {
		fprintf(stderr, "usage: %s path\n", argv[0]);
		return -1;
	}

	path = argv[1];

	if ((fd = open(path, O_RDWR)) < 0) {
		perror("open: ");
		return -1;
	}

	if ((err = ioctl(fd, AEON_IOC_DENTRY_ATTACK, &arg)) < 0) {
		perror("ioctl: ");
		goto close_fd;
	}

	printf("get = %d\n", arg);

close_fd:
	if ((err = close(fd)) < 0)
		perror("close: ");

	return 0;
}
