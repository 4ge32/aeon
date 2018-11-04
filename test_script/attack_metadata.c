#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#define AEON_IOC_INODE_ATTACK		_IOWR('f', 5, long)
#define AEON_IOC_DENTRY_ATTACK		_IOWR('f', 6, long)
#define AEON_IOC_CHILD_ID_ATTACK	_IOWR('f', 7, long)

enum attack_type {
	DENTRY = 1,
	INODE,
	BOTH_OF_CHILD,
};

enum failure_type {
	CREATE = 1,
	DELETE1,
	DELETE2,
	DELETE3,
	CREATE_ID1,
	CREATE_ID2,
	CREATE_ID3,
};

int main(int argc, char *argv[])
{
	char *path;
	unsigned long attack_type;
	int target;
	int fd;
	int err;
	int arg;

	if (argc != 4) {
		fprintf(stderr, "usage: %s target failuretype path\n", argv[0]);
		return -1;
	}

	target = atoi(argv[1]);
	arg = atoi(argv[2]);
	path = argv[3];

	switch (target) {
	case INODE:
		attack_type = AEON_IOC_INODE_ATTACK;
		break;
	case DENTRY:
		attack_type = AEON_IOC_DENTRY_ATTACK;
		break;
	case BOTH_OF_CHILD:
		attack_type =  AEON_IOC_CHILD_ID_ATTACK;
		break;
	}

	if ((fd = open(path, O_RDWR)) < 0) {
		perror("open: ");
		return -1;
	}

	if ((err = ioctl(fd, attack_type, &arg)) < 0) {
		perror("ioctl: ");
		goto close_fd;
	}

close_fd:
	if ((err = close(fd)) < 0)
		perror("close: ");

	return 0;
}
