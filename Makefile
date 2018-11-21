#
# Makefile for the linux filesystem.
#
CONFIG_AEON_FS_XATTR=y
ccflags-y := -DCONFIG_AEON_FS_XATTR

obj-m += aeon.o

aeon-y := super.o balloc.o inode.o mprotect.o namei.o dir.o  \
	file.o extents.o rebuild.o symlink.o debug.o ioctl.o \
	malloc.o tree.o

aeon-$(CONFIG_AEON_FS_XATTR) += xattr.o xattr_user.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean
