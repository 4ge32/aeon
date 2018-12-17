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
#define AEON_IOC_TEST_LIBAEON		_IOWR('f', 8, long)
#define AEON_IOC_TEST_COMPRESSION	_IOWR('f', 9, long)

enum test_type {
	DENTRY = 1,
	INODE,
	BOTH_OF_CHILD,
	LIBAEON,
	COMPRESSION,
};

enum failure_type {
	CREATE = 1,
	DELETE1,
	DELETE2,
	DELETE3,
	CREATE_ID1,
	CREATE_ID2,
	CREATE_ID3,
	CREATE_ID4,
	RENAME_ID1,
	RENAME_ID2,
	MKDIR_1 = 11,
	MKDIR_2,
	MKDIR_3,
	MKDIR_4,
	MKDIR_5,
	MKDIR_6,
	LINK_1,
	LINK_2,
	UNLINK_1,
	UNLINK_1_1,
	UNLINK_2,
};

int main(int argc, char *argv[])
{
	char *path;
	unsigned long test_type;
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
		test_type = AEON_IOC_INODE_ATTACK;
		break;
	case DENTRY:
		test_type = AEON_IOC_DENTRY_ATTACK;
		break;
	case BOTH_OF_CHILD:
		test_type =  AEON_IOC_CHILD_ID_ATTACK;
		break;
	case LIBAEON:
		test_type = AEON_IOC_TEST_LIBAEON;
		break;
	case COMPRESSION:
		test_type = AEON_IOC_TEST_COMPRESSION;
		break;
	}

	if ((fd = open(path, O_RDWR)) < 0) {
		perror("open: ");
		return -1;
	}

	if ((err = ioctl(fd, test_type, &arg)) < 0) {
		perror("ioctl: ");
		goto close_fd;
	}

close_fd:
	if ((err = close(fd)) < 0)
		perror("close: ");

	return 0;
}
