#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <errno.h>
#include <assert.h>

/*
 * Tomorrow, let's look & try into rm_fts
 */


int main(int argc, char *argv[])
{
	char *path[] = {"/mnt/test", NULL};

	int bit_flags = (FTS_PHYSICAL);

	FTS *fts = fts_open(path, bit_flags, NULL);

	while (1) {
		FTSENT *ent;
		struct stat *sb;
		int ret;

		ent = fts_read(fts);
		if (ent == NULL) {
			if (errno != 0)
				perror("fts_read");
			break;
		}

		printf("%d: %s\n", ent->fts_info, ent->fts_path);
		printf("%ld\n", ent->fts_statp->st_size);

		sb = ent->fts_statp;

		switch (sb->st_mode & S_IFMT) {
		case S_IFBLK:  printf("block device\n");            break;
		case S_IFCHR:  printf("character device\n");        break;
		case S_IFDIR:  printf("directory\n");               break;
		case S_IFIFO:  printf("FIFO/pipe\n");               break;
		case S_IFLNK:  printf("symlink\n");                 break;
		case S_IFREG:  printf("regular file\n");            break;
		case S_IFSOCK: printf("socket\n");                  break;
		default:       printf("unknown?\n");                break;
		}

		printf("I-node number:            %ld\n", (long) sb->st_ino);

		printf("Mode:                     %lo (octal)\n",
		       (unsigned long) sb->st_mode);

		printf("Link count:               %ld\n", (long) sb->st_nlink);
		printf("Ownership:                UID=%ld   GID=%ld\n",
		       (long) sb->st_uid, (long) sb->st_gid);

		printf("Preferred I/O block size: %ld bytes\n",
		       (long) sb->st_blksize);
		printf("File size:                %lld bytes\n",
		       (long long) sb->st_size);
		printf("Blocks allocated:         %lld\n",
		       (long long) sb->st_blocks);


	}

	fts_close(fts);

	return 0;
}
