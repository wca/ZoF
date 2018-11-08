
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>
#include <sys/zap.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/vdev.h>
#include <sys/dmu.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_deleg.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_impl.h>
#include <sys/dmu_tx.h>
#include <sys/sunddi.h>
#include <sys/policy.h>
#include <sys/zone.h>
#include <sys/nvpair.h>
#include <sys/mount.h>
#include <sys/taskqueue.h>
#include <sys/sdt.h>
#include <sys/varargs.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ctldir.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_onexit.h>
#include <sys/zvol.h>
#include <sys/dsl_scan.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_send.h>
#include <sys/dsl_destroy.h>
#include <sys/dsl_bookmark.h>
#include <sys/dsl_userhold.h>
#include <sys/zfeature.h>
#include <sys/zcp.h>
#include <sys/zio_checksum.h>
#include <sys/vdev_removal.h>
#include <sys/dsl_crypt.h>

#include <zfs_ioctl_compat.h>

#include "zfs_namecheck.h"
#include "zfs_prop.h"
#include "zfs_deleg.h"
#include "zfs_comutil.h"

SYSCTL_DECL(_vfs_zfs);
SYSCTL_NODE(_vfs_zfs, OID_AUTO, vdev, CTLFLAG_RW, 0, "ZFS VDEV");

static struct cdev *zfsdev;

extern void zfs_init(void);
extern void zfs_fini(void);
extern void zfs_ioctl_init(void);
extern int zcommon_init(void);
extern void zcommon_fini(void);


static struct root_hold_token *zfs_root_token;

extern uint_t rrw_tsd_key;
extern uint_t zfs_allow_log_key;
extern uint_t zfs_geom_probe_vdev_key;

static int zfs__init(void);
static int zfs__fini(void);
static void zfs_shutdown(void *, int);

static eventhandler_tag zfs_shutdown_event_tag;
extern void *zfsdev_state;

#define ZFS_MIN_KSTACK_PAGES 4

boolean_t
dataset_name_hidden(const char *name)
{
	/*
	 * Skip over datasets that are not visible in this zone,
	 * internal datasets (which have a $ in their name), and
	 * temporary datasets (which have a % in their name).
	 */
	if (strchr(name, '$') != NULL)
		return (B_TRUE);
	if (strchr(name, '%') != NULL)
		return (B_TRUE);
	if (!INGLOBALZONE(curproc) && !zone_dataset_visible(name, NULL))
		return (B_TRUE);
	return (B_FALSE);
}

static int
zfsdev_ioctl(struct cdev *dev, u_long zcmd, caddr_t arg, int flag,
    struct thread *td)
{
	uint_t len, vecnum;
	zfs_iocparm_t *zp;
	int rc;

	len = IOCPARM_LEN(zcmd);
	vecnum = zcmd & 0xff;
	zp = (void *)arg;
	if (len != sizeof(zfs_iocparm_t)) {
		printf("len %d vecnum: %d sizeof(zfs_cmd_t) %lu\n",
			   len, vecnum, sizeof(zfs_cmd_t));
		return (EINVAL);
	}
	if (bootverbose)
		printf("%s vecnum: %d\n", __func__, vecnum);
	rc = zfsdev_ioctl_common(vecnum, (unsigned long) zp->zfs_cmd);
	return (-rc);
}

static void
zfs_ctldev_destroy(zfs_onexit_t *zo, minor_t minor)
{
	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	zfs_onexit_destroy(zo);
	ddi_soft_state_free(zfsdev_state, minor);
}

static void
zfsdev_close(void *data)
{
	zfs_onexit_t *zo;
	minor_t minor = (minor_t)(uintptr_t)data;

	if (minor == 0)
		return;

	mutex_enter(&spa_namespace_lock);
	zo = zfsdev_get_soft_state(minor, ZSST_CTLDEV);
	if (zo == NULL) {
		mutex_exit(&spa_namespace_lock);
		return;
	}
	zfs_ctldev_destroy(zo, minor);
	mutex_exit(&spa_namespace_lock);
}

static int
zfs_ctldev_init(struct cdev *devp)
{
	minor_t minor;
	zfs_soft_state_t *zs;

	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	minor = zfsdev_minor_alloc();
	if (minor == 0)
		return (SET_ERROR(ENXIO));

	if (ddi_soft_state_zalloc(zfsdev_state, minor) != DDI_SUCCESS)
		return (SET_ERROR(EAGAIN));

	devfs_set_cdevpriv((void *)(uintptr_t)minor, zfsdev_close);

	zs = ddi_get_soft_state(zfsdev_state, minor);
	zs->zss_type = ZSST_CTLDEV;
	zfs_onexit_init((zfs_onexit_t **)&zs->zss_data);

	return (0);
}

void *
zfsdev_get_soft_state(minor_t minor, enum zfs_soft_state_type which)
{
	zfs_soft_state_t *zp;

	zp = ddi_get_soft_state(zfsdev_state, minor);
	if (zp == NULL || zp->zss_type != which)
		return (NULL);

	return (zp->zss_data);
}

static int
zfsdev_open(struct cdev *devp, int flag, int mode, struct thread *td)
{
	int error = 0;

#ifdef illumos
	if (getminor(*devp) != 0)
		return (zvol_open(devp, flag, otyp, cr));
#endif

	/* This is the control device. Allocate a new minor if requested. */
	if (flag & FEXCL) {
		mutex_enter(&spa_namespace_lock);
		error = zfs_ctldev_init(devp);
		mutex_exit(&spa_namespace_lock);
	}

	return (error);
}


static struct cdevsw zfs_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	zfsdev_open,
	.d_ioctl =	zfsdev_ioctl,
	.d_name =	ZFS_DRIVER
};

static void
zfs_allow_log_destroy(void *arg)
{
	char *poolname = arg;
	strfree(poolname);
}

static void
zfsdev_init(void)
{
	zfsdev = make_dev(&zfs_cdevsw, 0x0, UID_ROOT, GID_OPERATOR, 0666,
	    ZFS_DRIVER);
}

static void
zfsdev_fini(void)
{
	if (zfsdev != NULL)
		destroy_dev(zfsdev);
}

int
zfs__init(void)
{

#ifdef __FreeBSD__
#if KSTACK_PAGES < ZFS_MIN_KSTACK_PAGES
	printf("ZFS NOTICE: KSTACK_PAGES is %d which could result in stack "
	    "overflow panic!\nPlease consider adding "
	    "'options KSTACK_PAGES=%d' to your kernel config\n", KSTACK_PAGES,
	    ZFS_MIN_KSTACK_PAGES);
#endif
#endif
	zfs_root_token = root_mount_hold("ZFS");


	spa_init(FREAD | FWRITE);
	zfs_init();
	zvol_init();
	zfs_ioctl_init();

	tsd_create(&zfs_fsyncer_key, NULL);
	tsd_create(&rrw_tsd_key, rrw_tsd_destroy);
	tsd_create(&zfs_allow_log_key, zfs_allow_log_destroy);
	tsd_create(&zfs_geom_probe_vdev_key, NULL);

	printf("ZFS storage pool version: features support (" SPA_VERSION_STRING ")\n");
	root_mount_rel(zfs_root_token);

	zfsdev_init();
	zcommon_init();

	return (0);
}

int
zfs__fini(void)
{
	if (spa_busy() || zfs_busy() || zvol_busy() ||
	    zio_injection_enabled) {
		return (EBUSY);
	}

	zcommon_fini();
	zfsdev_fini();
	zvol_fini();
	zfs_fini();
	spa_fini();

	tsd_destroy(&zfs_fsyncer_key);
	tsd_destroy(&rrw_tsd_key);
	tsd_destroy(&zfs_allow_log_key);

	return (0);
}

static void
zfs_shutdown(void *arg __unused, int howto __unused)
{

	/*
	 * ZFS fini routines can not properly work in a panic-ed system.
	 */
	if (panicstr == NULL)
		(void)zfs__fini();
}


static int
zfs_modevent(module_t mod, int type, void *unused __unused)
{
	int err;

	switch (type) {
	case MOD_LOAD:
		err = zfs__init();
		if (err == 0)
			zfs_shutdown_event_tag = EVENTHANDLER_REGISTER(
			    shutdown_post_sync, zfs_shutdown, NULL,
			    SHUTDOWN_PRI_FIRST);
		return (err);
	case MOD_UNLOAD:
		err = zfs__fini();
		if (err == 0 && zfs_shutdown_event_tag != NULL)
			EVENTHANDLER_DEREGISTER(shutdown_post_sync,
			    zfs_shutdown_event_tag);
		return (err);
	case MOD_SHUTDOWN:
		return (0);
	default:
		break;
	}
	return (EOPNOTSUPP);
}

static moduledata_t zfs_mod = {
	"zfsctrl",
	zfs_modevent,
	0
};
DECLARE_MODULE(zfsctrl, zfs_mod, SI_SUB_VFS, SI_ORDER_ANY);
MODULE_VERSION(zfsctrl, 1);
MODULE_DEPEND(zfsctrl, opensolaris, 1, 1, 1);
MODULE_DEPEND(zfsctrl, krpc, 1, 1, 1);
MODULE_DEPEND(zfsctrl, acl_nfs4, 1, 1, 1);
MODULE_DEPEND(zfsctrl, crypto, 1, 1, 1);
MODULE_DEPEND(zfsctrl, cryptodev, 1, 1, 1);
