#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/vdev_file.h>
#include <sys/vdev_impl.h>
#include <sys/zio.h>
#include <sys/fs/zfs.h>
#include <sys/fm/fs/zfs.h>
#include <sys/abd.h>

/* ARGSUSED */
void
vdev_default_xlate(vdev_t *vd, const range_seg_t *in, range_seg_t *res)
{
	res->rs_start = in->rs_start;
	res->rs_end = in->rs_end;
}
