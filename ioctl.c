#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/uaccess.h>

#include "aeon.h"

static inline __u32 aeon_mask_flags(umode_t mode, __u32 flags)
{
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & AEON_REG_FLMASK;
	else
		return flags & AEON_OTHER_FLMASK;
}

long aeon_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct aeon_inode *pi;
	unsigned int flags;
	int ret;

	pi = aeon_get_inode(inode->i_sb, &AEON_I(inode)->header);

	switch (cmd) {
	case AEON_IOC_GETFLAGS:
		flags = le32_to_cpu(pi->i_flags) & AEON_FL_USER_VISIBLE;
		return put_user(flags, (int __user *)arg);
	case AEON_IOC_SETFLAGS: {
		unsigned int oldflags;

		ret = mnt_want_write_file(filp);
		if (ret)
			return ret;

		if (!inode_owner_or_capable(inode)) {
			ret = -EACCES;
			goto setflags_out;
		}

		if (get_user(flags, (int __user *)arg)) {
			ret = -EFAULT;
			goto setflags_out;
		}

		flags = aeon_mask_flags(inode->i_mode, flags);

		inode_lock(inode);
		oldflags = le32_to_cpu(pi->i_flags);
		if ((flags ^ oldflags) & (AEON_APPEND_FL | AEON_IMMUTABLE_FL)) {
			if (!capable(CAP_LINUX_IMMUTABLE)) {
				inode_unlock(inode);
				ret = -EPERM;
				goto setflags_out;
			}
		}

		flags = flags & AEON_FL_USER_MODIFIABLE;
		flags |= oldflags & ~AEON_FL_USER_MODIFIABLE;
		pi->i_flags = cpu_to_le32(flags);

		aeon_set_inode_flags(inode, pi, flags);
		inode->i_ctime = current_time(inode);
		pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
		inode_unlock(inode);
setflags_out:
		mnt_drop_write_file(filp);
		return ret;
	}
	case AEON_IOC_GETVERSION:
		return put_user(inode->i_generation, (int __user *)arg);
	case AEON_IOC_SETVERSION: {
		__u32 generation;

		if (!inode_owner_or_capable(inode))
			return -EPERM;
		ret = mnt_want_write_file(filp);
		if (ret)
			return ret;
		if (get_user(generation, (int __user *)arg)) {
			ret = -EFAULT;
			goto setversion_out;
		}

		inode_lock(inode);
		inode->i_ctime = current_time(inode);
		inode->i_generation = generation;
		pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
		pi->i_generation = cpu_to_le32(generation);
		inode_unlock(inode);
setversion_out:
		mnt_drop_write_file(filp);
		return ret;
	}
	case AEON_IOC_INODE_ATTACK: {
		struct aeon_inode *pi;

		pi = aeon_get_inode(sb, &AEON_I(inode)->header);

		pi->i_inode_block = 0;

		aeon_dbg("Destroy inode (ino %u) illegaly\n",
			 le32_to_cpu(pi->aeon_ino));
		return 0;
	}
	case AEON_IOC_DENTRY_ATTACK: {
		struct aeon_inode *pi;
		struct aeon_dentry *de;
		u64 de_addr = 0;
		enum failure_type {
			CREATE = 1,
			DELETE,
		};
		enum failure_type type;

		if (get_user(type, (int __user *)arg))
			ret = -EFAULT;
		aeon_dbg("type %d\n", type);

		pi = aeon_get_inode(sb, &AEON_I(inode)->header);
		aeon_get_dentry_address(sb, pi, &de_addr);
		de = (struct aeon_dentry *)de_addr;

		switch (type){
		case CREATE: {
			memset(de, 0, sizeof(*de));
			break;
		}
		case DELETE: {
			break;
		}
		}


		aeon_dbg("Change dentry member\n");
		return 0;
	}
	case AEON_IOC_CHILD_ID_ATTACK: {
		struct aeon_inode *pi;
		struct aeon_dentry *de;
		u64 de_addr = 0;

		pi = aeon_get_inode(sb, &AEON_I(inode)->header);
		aeon_get_dentry_address(sb, pi, &de_addr);
		de = (struct aeon_dentry *)de_addr;


	}
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long aeon_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case AEON_IOC32_GETFLAGS:
		cmd = AEON_IOC_GETFLAGS;
		break;
	case AEON_IOC32_SETFLAGS:
		cmd = AEON_IOC_SETFLAGS;
		break;
	case AEON_IOC32_GETVERSION:
		cmd = AEON_IOC_GETVERSION;
		break;
	case AEON_IOC32_SETVERSION:
		cmd = AEON_IOC_SETVERSION;
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return aeon_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif
