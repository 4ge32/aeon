#
# Makefile for the linux filesystem.
#
CONFIG_AEON_FS_XATTR=y
ccflags-y += -DCONFIG_AEON_FS_XATTR
ccflags-y += -I$(src)/libaeon

obj-m += aeon.o

aeon-y += 	$(addprefix libaeon/, \
		malloc.o \
		tree.o \
		libtest.o \
		)

aeon-y += super.o balloc.o inode.o mprotect.o namei.o dir.o  \
	file.o extents.o rebuild.o symlink.o debug.o ioctl.o \

aeon-$(CONFIG_AEON_FS_XATTR) += xattr.o xattr_user.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean
