#ifndef _COMPAT_SYS_STAT_H_
#define _COMPAT_SYS_STAT_H_

#include_next <sys/stat.h>
#ifdef __FreeBSD__

#define	stat64	stat

#define	MAXOFFSET_T	OFF_MAX

#ifndef _KERNEL
#include <sys/disk.h>

static __inline int
fstat64(int fd, struct stat *sb)
{
	int ret;

	ret = fstat(fd, sb);
	if (ret == 0) {
		if (S_ISCHR(sb->st_mode))
			(void)ioctl(fd, DIOCGMEDIASIZE, &sb->st_size);
	}
	return (ret);
}
#endif
#endif
#endif	/* !_COMPAT_SYS_STAT_H_ */
