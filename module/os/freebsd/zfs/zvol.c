/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2006-2010 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Portions Copyright 2010 Robert Milkowski
 *
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012, 2017 by Delphix. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 * Copyright (c) 2014 Integros [integros.com]
 */

/* Portions Copyright 2011 Martin Matuska <mm@FreeBSD.org> */

/*
 * ZFS volume emulation driver.
 *
 * Makes a DMU object look like a volume of arbitrary size, up to 2^64 bytes.
 * Volumes are accessed through the symbolic links named:
 *
 * /dev/zvol/dsk/<pool_name>/<dataset_name>
 * /dev/zvol/rdsk/<pool_name>/<dataset_name>
 *
 * These links are created by the /dev filesystem (sdev_zvolops.c).
 * Volumes are persistent through reboot.  No user command needs to be
 * run before opening and using a device.
 *
 * FreeBSD notes.
 * On FreeBSD ZVOLs are simply GEOM providers like any other storage device
 * in the system.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/zio.h>
#include <sys/disk.h>
#include <sys/dmu_traverse.h>
#include <sys/dnode.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_prop.h>
#include <sys/dkio.h>
#include <sys/byteorder.h>
#include <sys/sunddi.h>
#include <sys/dirent.h>
#include <sys/policy.h>
#include <sys/queue.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
#include <sys/zil.h>
#include <sys/refcount.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_rlock.h>
#include <sys/vdev_impl.h>
#include <sys/vdev_raidz.h>
#include <sys/zvol.h>
#include <sys/zil_impl.h>
#include <sys/dbuf.h>
#include <sys/dmu_tx.h>
#include <sys/zfeature.h>
#include <sys/zio_checksum.h>
#include <sys/zil_impl.h>
#include <sys/filio.h>

#include <geom/geom.h>

#include "zfs_namecheck.h"

struct proc *zfsproc;
extern uint_t zfs_geom_probe_vdev_key;

struct g_class zfs_zvol_class = {
	.name = "ZFS::ZVOL",
	.version = G_VERSION,
};

DECLARE_GEOM_CLASS(zfs_zvol_class, zfs_zvol);

void *zfsdev_state;
static char *zvol_ftag = "zvol_tag";

#define	ZVOL_DUMPSIZE		"dumpsize"

/*
 * This lock protects the zfsdev_state structure from being modified
 * while it's being used, e.g. an open that comes in before a create
 * finishes.  It also protects temporary opens of the dataset so that,
 * e.g., an open doesn't get a spurious EBUSY.
 */
/*
 * In FreeBSD we've replaced the upstream zfsdev_state_lock with the
 * spa_namespace_lock in the ZVOL code.
 */
#define zfsdev_state_lock spa_namespace_lock
static uint32_t zvol_minors;

SYSCTL_DECL(_vfs_zfs);
SYSCTL_NODE(_vfs_zfs, OID_AUTO, vol, CTLFLAG_RW, 0, "ZFS VOLUME");
static int	volmode = ZFS_VOLMODE_GEOM;
SYSCTL_INT(_vfs_zfs_vol, OID_AUTO, mode, CTLFLAG_RWTUN, &volmode, 0,
    "Expose as GEOM providers (1), device files (2) or neither");
static boolean_t zpool_on_zvol = B_FALSE;
SYSCTL_INT(_vfs_zfs_vol, OID_AUTO, recursive, CTLFLAG_RWTUN, &zpool_on_zvol, 0,
    "Allow zpools to use zvols as vdevs (DANGEROUS)");

typedef struct zvol_extent {
	list_node_t	ze_node;
	dva_t		ze_dva;		/* dva associated with this extent */
	uint64_t	ze_nblks;	/* number of blocks in extent */
} zvol_extent_t;

/*
 * The in-core state of each volume.
 */
struct zvol_state {
	LIST_ENTRY(zvol_state)	zv_links;
	char		zv_name[MAXPATHLEN]; /* pool/dd name */
	uint64_t	zv_volsize;	/* amount of space we advertise */
	uint64_t	zv_volblocksize; /* volume block size */
	struct cdev	*zv_dev;	/* non-GEOM device */
	struct g_provider *zv_provider;	/* GEOM provider */
	uint8_t		zv_min_bs;	/* minimum addressable block shift */
	uint8_t		zv_flags;	/* readonly, dumpified, etc. */
	objset_t	*zv_objset;	/* objset handle */
	uint32_t	zv_total_opens;	/* total open count */
	uint32_t	zv_sync_cnt;	/* synchronous open count */
	zilog_t		*zv_zilog;	/* ZIL handle */
	list_t		zv_extents;	/* List of extents for dump */
	zfs_rlock_t	zv_range_lock;	/* range lock */
	dnode_t		*zv_dn;		/* dnode hold */
	int		zv_state;
	int		zv_volmode;	/* Provide GEOM or cdev */
	struct bio_queue_head zv_queue;
	struct mtx	zv_queue_mtx;	/* zv_queue mutex */
};

static LIST_HEAD(, zvol_state) all_zvols;
/*
 * zvol specific flags
 */
#define	ZVOL_RDONLY	0x1
#define	ZVOL_DUMPIFIED	0x2
#define	ZVOL_EXCL	0x4
#define	ZVOL_WCE	0x8

/*
 * zvol maximum transfer in one DMU tx.
 */
int zvol_maxphys = DMU_MAX_ACCESS/2;

/*
 * Toggle unmap functionality.
 */
boolean_t zvol_unmap_enabled = B_TRUE;

/*
 * If true, unmaps requested as synchronous are executed synchronously,
 * otherwise all unmaps are asynchronous.
 */
boolean_t zvol_unmap_sync_enabled = B_FALSE;

SYSCTL_INT(_vfs_zfs_vol, OID_AUTO, unmap_enabled, CTLFLAG_RWTUN,
    &zvol_unmap_enabled, 0,
    "Enable UNMAP functionality");

SYSCTL_INT(_vfs_zfs_vol, OID_AUTO, unmap_sync_enabled, CTLFLAG_RWTUN,
    &zvol_unmap_sync_enabled, 0,
    "UNMAPs requested as sync are executed synchronously");

static d_open_t		zvol_d_open;
static d_close_t	zvol_d_close;
static d_read_t		zvol_read;
static d_write_t	zvol_write;
static d_ioctl_t	zvol_d_ioctl;
static d_strategy_t	zvol_strategy;

static struct cdevsw zvol_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	zvol_d_open,
	.d_close =	zvol_d_close,
	.d_read =	zvol_read,
	.d_write =	zvol_write,
	.d_ioctl =	zvol_d_ioctl,
	.d_strategy =	zvol_strategy,
	.d_name =	"zvol",
	.d_flags =	D_DISK | D_TRACKCLOSE,
};

static void zvol_geom_run(zvol_state_t *zv);
static void zvol_geom_destroy(zvol_state_t *zv);
static int zvol_geom_access(struct g_provider *pp, int acr, int acw, int ace);
static void zvol_geom_start(struct bio *bp);
static void zvol_geom_worker(void *arg);
static void zvol_log_truncate(zvol_state_t *zv, dmu_tx_t *tx, uint64_t off,
    uint64_t len, boolean_t sync);

extern int zfs_set_prop_nvlist(const char *, zprop_source_t,
    nvlist_t *, nvlist_t *);
static int zvol_remove_zv(zvol_state_t *);
static int zvol_get_data(void *arg, lr_write_t *lr, char *buf,
    struct lwb *lwb, zio_t *zio);

static void
zvol_size_changed(zvol_state_t *zv, uint64_t volsize)
{
	zv->zv_volsize = volsize;
	if (zv->zv_volmode == ZFS_VOLMODE_GEOM) {
		struct g_provider *pp;

		pp = zv->zv_provider;
		if (pp == NULL)
			return;
		g_topology_lock();

		/*
		 * Do not invoke resize event when initial size was zero.
		 * ZVOL initializes the size on first open, this is not
		 * real resizing.
		 */
		if (pp->mediasize == 0)
			pp->mediasize = zv->zv_volsize;
		else
			g_resize_provider(pp, zv->zv_volsize);
		g_topology_unlock();
	}
}

int
zvol_check_volsize(uint64_t volsize, uint64_t blocksize)
{
	if (volsize == 0)
		return (SET_ERROR(EINVAL));

	if (volsize % blocksize != 0)
		return (SET_ERROR(EINVAL));

#ifdef _ILP32
	if (volsize - 1 > SPEC_MAXOFFSET_T)
		return (SET_ERROR(EOVERFLOW));
#endif
	return (0);
}

int
zvol_check_volblocksize(const char *name, uint64_t volblocksize)
{
	/* Record sizes above 128k need the feature to be enabled */
	if (volblocksize > SPA_OLD_MAXBLOCKSIZE) {
		spa_t *spa;
		int error;

		if ((error = spa_open(name, &spa, FTAG)) != 0)
			return (error);

		if (!spa_feature_is_enabled(spa, SPA_FEATURE_LARGE_BLOCKS)) {
			spa_close(spa, FTAG);
			return (SET_ERROR(ENOTSUP));
		}

		/*
		 * We don't allow setting the property above 1MB,
		 * unless the tunable has been changed.
		 */
		if (volblocksize > zfs_max_recordsize)
			return (SET_ERROR(EDOM));

		spa_close(spa, FTAG);
	}

	if (volblocksize < SPA_MINBLOCKSIZE ||
	    volblocksize > SPA_OLD_MAXBLOCKSIZE ||
	    !ISP2(volblocksize))
		return (SET_ERROR(EDOM));

	return (0);
}

int
zvol_get_stats(objset_t *os, nvlist_t *nv)
{
	int error;
	dmu_object_info_t doi;
	uint64_t val;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &val);
	if (error)
		return (error);

	dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLSIZE, val);

	error = dmu_object_info(os, ZVOL_OBJ, &doi);

	if (error == 0) {
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLBLOCKSIZE,
		    doi.doi_data_block_size);
	}

	return (error);
}

static zvol_state_t *
zvol_minor_lookup(const char *name)
{
	zvol_state_t *zv;

	ASSERT(MUTEX_HELD(&zfsdev_state_lock));

	LIST_FOREACH(zv, &all_zvols, zv_links) {
		if (strcmp(zv->zv_name, name) == 0)
			return (zv);
	}

	return (NULL);
}

/* extent mapping arg */
struct maparg {
	zvol_state_t	*ma_zv;
	uint64_t	ma_blks;
};

/* ARGSUSED */
void
zvol_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
	zfs_creat_t *zct = arg;
	nvlist_t *nvprops = zct->zct_props;
	int error;
	uint64_t volblocksize, volsize;

	VERIFY(nvlist_lookup_uint64(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLSIZE), &volsize) == 0);
	if (nvlist_lookup_uint64(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), &volblocksize) != 0)
		volblocksize = zfs_prop_default_numeric(ZFS_PROP_VOLBLOCKSIZE);

	/*
	 * These properties must be removed from the list so the generic
	 * property setting step won't apply to them.
	 */
	VERIFY(nvlist_remove_all(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLSIZE)) == 0);
	(void) nvlist_remove_all(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE));

	error = dmu_object_claim(os, ZVOL_OBJ, DMU_OT_ZVOL, volblocksize,
	    DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	error = zap_create_claim(os, ZVOL_ZAP_OBJ, DMU_OT_ZVOL_PROP,
	    DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	error = zap_update(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize, tx);
	ASSERT(error == 0);
}

/*
 * Replay a TX_TRUNCATE ZIL transaction if asked.  TX_TRUNCATE is how we
 * implement DKIOCFREE/free-long-range.
 */
static int
zvol_replay_truncate(void *arg1, void *arg2, boolean_t byteswap)
{
	zvol_state_t *zv = arg1;
	lr_truncate_t *lr = arg2;
	uint64_t offset, length;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));

	offset = lr->lr_offset;
	length = lr->lr_length;

	return (dmu_free_long_range(zv->zv_objset, ZVOL_OBJ, offset, length));
}

/*
 * Replay a TX_WRITE ZIL transaction that didn't get committed
 * after a system failure
 */
static int
zvol_replay_write(void *arg1, void *arg2, boolean_t byteswap)
{
	zvol_state_t *zv = arg1;
	lr_write_t *lr = arg2;
	objset_t *os = zv->zv_objset;
	char *data = (char *)(lr + 1);	/* data follows lr_write_t */
	uint64_t offset, length;
	dmu_tx_t *tx;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));

	offset = lr->lr_offset;
	length = lr->lr_length;

	/* If it's a dmu_sync() block, write the whole block */
	if (lr->lr_common.lrc_reclen == sizeof (lr_write_t)) {
		uint64_t blocksize = BP_GET_LSIZE(&lr->lr_blkptr);
		if (length < blocksize) {
			offset -= offset % blocksize;
			length = blocksize;
		}
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_write(tx, ZVOL_OBJ, offset, length);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
	} else {
		dmu_write(os, ZVOL_OBJ, offset, length, data, tx);
		dmu_tx_commit(tx);
	}

	return (error);
}

/* ARGSUSED */
static int
zvol_replay_err(void *arg1, void *arg2, boolean_t byteswap)
{
	return (SET_ERROR(ENOTSUP));
}

/*
 * Callback vectors for replaying records.
 * Only TX_WRITE and TX_TRUNCATE are needed for zvol.
 */
zil_replay_func_t *zvol_replay_vector[TX_MAX_TYPE] = {
	zvol_replay_err,	/* 0 no such transaction type */
	zvol_replay_err,	/* TX_CREATE */
	zvol_replay_err,	/* TX_MKDIR */
	zvol_replay_err,	/* TX_MKXATTR */
	zvol_replay_err,	/* TX_SYMLINK */
	zvol_replay_err,	/* TX_REMOVE */
	zvol_replay_err,	/* TX_RMDIR */
	zvol_replay_err,	/* TX_LINK */
	zvol_replay_err,	/* TX_RENAME */
	zvol_replay_write,	/* TX_WRITE */
	zvol_replay_truncate,	/* TX_TRUNCATE */
	zvol_replay_err,	/* TX_SETATTR */
	zvol_replay_err,	/* TX_ACL */
	zvol_replay_err,	/* TX_CREATE_ACL */
	zvol_replay_err,	/* TX_CREATE_ATTR */
	zvol_replay_err,	/* TX_CREATE_ACL_ATTR */
	zvol_replay_err,	/* TX_MKDIR_ACL */
	zvol_replay_err,	/* TX_MKDIR_ATTR */
	zvol_replay_err,	/* TX_MKDIR_ACL_ATTR */
	zvol_replay_err,	/* TX_WRITE2 */
};

/*
 * Create a minor node (plus a whole lot more) for the specified volume.
 */
int
zvol_create_minor(const char *name)
{
	zvol_state_t *zv;
	objset_t *os;
	struct g_provider *pp;
	struct g_geom *gp;
	uint64_t mode;
	int error;

	ZFS_LOG(1, "Creating ZVOL %s...", name);

	mutex_enter(&zfsdev_state_lock);

	if (zvol_minor_lookup(name) != NULL) {
		mutex_exit(&zfsdev_state_lock);
		return (SET_ERROR(EEXIST));
	}

	/* lie and say we're read-only */
	error = dmu_objset_own(name, DMU_OST_ZVOL, B_TRUE, B_TRUE, FTAG, &os);

	if (error) {
		mutex_exit(&zfsdev_state_lock);
		return (error);
	}

	zv = kmem_zalloc(sizeof(*zv), KM_SLEEP);
	zv->zv_state = 0;
	error = dsl_prop_get_integer(name,
	    zfs_prop_to_name(ZFS_PROP_VOLMODE), &mode, NULL);
	if (error != 0 || mode == ZFS_VOLMODE_DEFAULT)
		mode = volmode;

	DROP_GIANT();
	zv->zv_volmode = mode;
	if (zv->zv_volmode == ZFS_VOLMODE_GEOM) {
		g_topology_lock();
		gp = g_new_geomf(&zfs_zvol_class, "zfs::zvol::%s", name);
		gp->start = zvol_geom_start;
		gp->access = zvol_geom_access;
		pp = g_new_providerf(gp, "%s/%s", ZVOL_DRIVER, name);
		pp->flags |= G_PF_DIRECT_RECEIVE | G_PF_DIRECT_SEND;
		pp->sectorsize = DEV_BSIZE;
		pp->mediasize = 0;
		pp->private = zv;

		zv->zv_provider = pp;
		bioq_init(&zv->zv_queue);
		mtx_init(&zv->zv_queue_mtx, "zvol", NULL, MTX_DEF);
	} else if (zv->zv_volmode == ZFS_VOLMODE_DEV) {
		struct make_dev_args args;

		make_dev_args_init(&args);
		args.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
		args.mda_devsw = &zvol_cdevsw;
		args.mda_cr = NULL;
		args.mda_uid = UID_ROOT;
		args.mda_gid = GID_OPERATOR;
		args.mda_mode = 0640;
		args.mda_si_drv2 = zv;
		error = make_dev_s(&args, &zv->zv_dev,
		    "%s/%s", ZVOL_DRIVER, name);
		if (error != 0) {
			kmem_free(zv, sizeof(*zv));
			dmu_objset_disown(os, 1, FTAG);
			mutex_exit(&zfsdev_state_lock);
			return (error);
		}
		zv->zv_dev->si_iosize_max = MAXPHYS;
	}
	LIST_INSERT_HEAD(&all_zvols, zv, zv_links);

	(void) strlcpy(zv->zv_name, name, MAXPATHLEN);
	zv->zv_min_bs = DEV_BSHIFT;
	zv->zv_objset = os;
	if (dmu_objset_is_snapshot(os) || !spa_writeable(dmu_objset_spa(os)))
		zv->zv_flags |= ZVOL_RDONLY;
	zfs_rlock_init(&zv->zv_range_lock);
	list_create(&zv->zv_extents, sizeof (zvol_extent_t),
	    offsetof(zvol_extent_t, ze_node));
	if (spa_writeable(dmu_objset_spa(os))) {
		if (zil_replay_disable)
			zil_destroy(dmu_objset_zil(os), B_FALSE);
		else
			zil_replay(os, zv, zvol_replay_vector);
	}
	dmu_objset_disown(os, 1, FTAG);
	zv->zv_objset = NULL;

	zvol_minors++;

	mutex_exit(&zfsdev_state_lock);
	if (zv->zv_volmode == ZFS_VOLMODE_GEOM) {
		zvol_geom_run(zv);
		g_topology_unlock();
	}
	PICKUP_GIANT();

	ZFS_LOG(1, "ZVOL %s created.", name);

	return (0);
}

/*
 * Remove minor node for the specified volume.
 */
static int
zvol_remove_zv(zvol_state_t *zv)
{
	ASSERT(MUTEX_HELD(&zfsdev_state_lock));
	if (zv->zv_total_opens != 0)
		return (SET_ERROR(EBUSY));

	ZFS_LOG(1, "ZVOL %s destroyed.", zv->zv_name);

	LIST_REMOVE(zv, zv_links);
	if (zv->zv_volmode == ZFS_VOLMODE_GEOM) {
		g_topology_lock();
		zvol_geom_destroy(zv);
		g_topology_unlock();
	} else if (zv->zv_volmode == ZFS_VOLMODE_DEV) {
		if (zv->zv_dev != NULL)
			destroy_dev(zv->zv_dev);
	}

	kmem_free(zv, sizeof (zvol_state_t));
	zvol_minors--;
	return (0);
}

int
zvol_remove_minor(const char *name)
{
	zvol_state_t *zv;
	int rc;

	mutex_enter(&zfsdev_state_lock);
	if ((zv = zvol_minor_lookup(name)) == NULL) {
		mutex_exit(&zfsdev_state_lock);
		return (SET_ERROR(ENXIO));
	}
	rc = zvol_remove_zv(zv);
	mutex_exit(&zfsdev_state_lock);
	return (rc);
}

int
zvol_first_open(zvol_state_t *zv)
{
	dmu_object_info_t doi;
	objset_t *os;
	uint64_t volsize;
	int error;
	uint64_t readonly;

	/* lie and say we're read-only */
	error = dmu_objset_own(zv->zv_name, DMU_OST_ZVOL, B_TRUE, B_TRUE,
	    zvol_ftag, &os);
	if (error)
		return (error);

	zv->zv_objset = os;
	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize);
	if (error) {
		ASSERT(error == 0);
		dmu_objset_disown(os, 1, zvol_ftag);
		return (error);
	}

	/* get and cache the blocksize */
	error = dmu_object_info(os, ZVOL_OBJ, &doi);
	if (error) {
		ASSERT(error == 0);
		dmu_objset_disown(os, 1, zvol_ftag);
		return (error);
	}
	zv->zv_volblocksize = doi.doi_data_block_size;

	error = dnode_hold(os, ZVOL_OBJ, zvol_ftag, &zv->zv_dn);
	if (error) {
		dmu_objset_disown(os, 1, zvol_ftag);
		return (error);
	}

	zvol_size_changed(zv, volsize);
	zv->zv_zilog = zil_open(os, zvol_get_data);

	VERIFY(dsl_prop_get_integer(zv->zv_name, "readonly", &readonly,
	    NULL) == 0);
	if (readonly || dmu_objset_is_snapshot(os) ||
	    !spa_writeable(dmu_objset_spa(os)))
		zv->zv_flags |= ZVOL_RDONLY;
	else
		zv->zv_flags &= ~ZVOL_RDONLY;
	return (error);
}

void
zvol_last_close(zvol_state_t *zv)
{
	zil_close(zv->zv_zilog);
	zv->zv_zilog = NULL;

	dnode_rele(zv->zv_dn, zvol_ftag);
	zv->zv_dn = NULL;

	/*
	 * Evict cached data
	 */
	if (!(zv->zv_flags & ZVOL_RDONLY))
		txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);
	dmu_objset_evict_dbufs(zv->zv_objset);

	dmu_objset_disown(zv->zv_objset, 1, zvol_ftag);
	zv->zv_objset = NULL;
}

static int
zvol_update_volsize(objset_t *os, uint64_t volsize)
{
	dmu_tx_t *tx;
	int error;

	ASSERT(MUTEX_HELD(&zfsdev_state_lock));

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	dmu_tx_mark_netfree(tx);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}

	error = zap_update(os, ZVOL_ZAP_OBJ, "size", 8, 1,
	    &volsize, tx);
	dmu_tx_commit(tx);

	if (error == 0)
		error = dmu_free_long_range(os,
		    ZVOL_OBJ, volsize, DMU_OBJECT_END);
	return (error);
}

void
zvol_remove_minors(spa_t *spa, const char *name, boolean_t async)
{
	zvol_state_t *zv, *tzv;
	size_t namelen;

	namelen = strlen(name);

	DROP_GIANT();
	mutex_enter(&zfsdev_state_lock);

	LIST_FOREACH_SAFE(zv, &all_zvols, zv_links, tzv) {
		if (strcmp(zv->zv_name, name) == 0 ||
		    (strncmp(zv->zv_name, name, namelen) == 0 &&
		    strlen(zv->zv_name) > namelen && (zv->zv_name[namelen] == '/' ||
		    zv->zv_name[namelen] == '@'))) {
			(void) zvol_remove_zv(zv);
		}
	}

	mutex_exit(&zfsdev_state_lock);
	PICKUP_GIANT();
}

static int
zvol_update_live_volsize(zvol_state_t *zv, uint64_t volsize)
{
	uint64_t old_volsize = 0ULL;
	int error = 0;

	ASSERT(MUTEX_HELD(&zfsdev_state_lock));

	/*
	 * Reinitialize the dump area to the new size. If we
	 * failed to resize the dump area then restore it back to
	 * its original size.  We must set the new volsize prior
	 * to calling dumpvp_resize() to ensure that the devices'
	 * size(9P) is not visible by the dump subsystem.
	 */
	old_volsize = zv->zv_volsize;
	zvol_size_changed(zv, volsize);

#ifdef ZVOL_DUMP
	if (zv->zv_flags & ZVOL_DUMPIFIED) {
		if ((error = zvol_dumpify(zv)) != 0 ||
		    (error = dumpvp_resize()) != 0) {
			int dumpify_error;

			(void) zvol_update_volsize(zv->zv_objset, old_volsize);
			zvol_size_changed(zv, old_volsize);
			dumpify_error = zvol_dumpify(zv);
			error = dumpify_error ? dumpify_error : error;
		}
	}
#endif	/* ZVOL_DUMP */

	return (error);
}

int
zvol_set_volsize(const char *name, uint64_t volsize)
{
	zvol_state_t *zv = NULL;
	objset_t *os;
	int error;
	dmu_object_info_t doi;
	uint64_t readonly;
	boolean_t owned = B_FALSE;

	error = dsl_prop_get_integer(name,
	    zfs_prop_to_name(ZFS_PROP_READONLY), &readonly, NULL);
	if (error != 0)
		return (error);
	if (readonly)
		return (SET_ERROR(EROFS));

	mutex_enter(&zfsdev_state_lock);
	zv = zvol_minor_lookup(name);

	if (zv == NULL || zv->zv_objset == NULL) {
		if ((error = dmu_objset_own(name, DMU_OST_ZVOL, B_FALSE, B_TRUE,
		    FTAG, &os)) != 0) {
			mutex_exit(&zfsdev_state_lock);
			return (error);
		}
		owned = B_TRUE;
		if (zv != NULL)
			zv->zv_objset = os;
	} else {
		os = zv->zv_objset;
	}

	if ((error = dmu_object_info(os, ZVOL_OBJ, &doi)) != 0 ||
	    (error = zvol_check_volsize(volsize, doi.doi_data_block_size)) != 0)
		goto out;

	error = zvol_update_volsize(os, volsize);

	if (error == 0 && zv != NULL)
		error = zvol_update_live_volsize(zv, volsize);
out:
	if (owned) {
		dmu_objset_disown(os, B_TRUE, FTAG);
		if (zv != NULL)
			zv->zv_objset = NULL;
	}
	mutex_exit(&zfsdev_state_lock);
	return (error);
}

/*ARGSUSED*/
static int
zvol_open(struct g_provider *pp, int flag, int count)
{
	zvol_state_t *zv;
	int err = 0;
	boolean_t locked = B_FALSE;

	if (!zpool_on_zvol && tsd_get(zfs_geom_probe_vdev_key) != NULL) {
		/*
		 * if zfs_geom_probe_vdev_key is set, that means that zfs is
		 * attempting to probe geom providers while looking for a
		 * replacement for a missing VDEV.  In this case, the
		 * spa_namespace_lock will not be held, but it is still illegal
		 * to use a zvol as a vdev.  Deadlocks can result if another
		 * thread has spa_namespace_lock
		 */
		return (EOPNOTSUPP);
	}
	/*
	 * Protect against recursively entering spa_namespace_lock
	 * when spa_open() is used for a pool on a (local) ZVOL(s).
	 * This is needed since we replaced upstream zfsdev_state_lock
	 * with spa_namespace_lock in the ZVOL code.
	 * We are using the same trick as spa_open().
	 * Note that calls in zvol_first_open which need to resolve
	 * pool name to a spa object will enter spa_open()
	 * recursively, but that function already has all the
	 * necessary protection.
	 */
	if (!MUTEX_HELD(&zfsdev_state_lock)) {
		mutex_enter(&zfsdev_state_lock);
		locked = B_TRUE;
	}

	zv = pp->private;
	if (zv == NULL) {
		if (locked)
			mutex_exit(&zfsdev_state_lock);
		return (SET_ERROR(ENXIO));
	}

	if (zv->zv_total_opens == 0) {
		err = zvol_first_open(zv);
		if (err) {
			if (locked)
				mutex_exit(&zfsdev_state_lock);
			return (err);
		}
		pp->mediasize = zv->zv_volsize;
		pp->stripeoffset = 0;
		pp->stripesize = zv->zv_volblocksize;
	}

	/*
	 * Check for a bad on-disk format version now since we
	 * lied about owning the dataset readonly before.
	 */
	if ((flag & FWRITE) && ((zv->zv_flags & ZVOL_RDONLY) ||
	    dmu_objset_incompatible_encryption_version(zv->zv_objset))) {
		err = SET_ERROR(EROFS);
		goto out;
	}
	if (zv->zv_flags & ZVOL_EXCL) {
		err = SET_ERROR(EBUSY);
		goto out;
	}
#ifdef FEXCL
	if (flag & FEXCL) {
		if (zv->zv_total_opens != 0) {
			err = SET_ERROR(EBUSY);
			goto out;
		}
		zv->zv_flags |= ZVOL_EXCL;
	}
#endif

	zv->zv_total_opens += count;
	if (locked)
		mutex_exit(&zfsdev_state_lock);

	return (err);
out:
	if (zv->zv_total_opens == 0)
		zvol_last_close(zv);
	if (locked)
		mutex_exit(&zfsdev_state_lock);
	return (err);
}

/*ARGSUSED*/
static int
zvol_close(struct g_provider *pp, int flag, int count)
{
	zvol_state_t *zv;
	int error = 0;
	boolean_t locked = B_FALSE;

	/* See comment in zvol_open(). */
	if (!MUTEX_HELD(&zfsdev_state_lock)) {
		mutex_enter(&zfsdev_state_lock);
		locked = B_TRUE;
	}

	zv = pp->private;
	if (zv == NULL) {
		if (locked)
			mutex_exit(&zfsdev_state_lock);
		return (SET_ERROR(ENXIO));
	}

	if (zv->zv_flags & ZVOL_EXCL) {
		ASSERT(zv->zv_total_opens == 1);
		zv->zv_flags &= ~ZVOL_EXCL;
	}

	/*
	 * If the open count is zero, this is a spurious close.
	 * That indicates a bug in the kernel / DDI framework.
	 */
	ASSERT(zv->zv_total_opens != 0);

	/*
	 * You may get multiple opens, but only one close.
	 */
	zv->zv_total_opens -= count;

	if (zv->zv_total_opens == 0)
		zvol_last_close(zv);

	if (locked)
		mutex_exit(&zfsdev_state_lock);
	return (error);
}

static void
zvol_get_done(zgd_t *zgd, int error)
{
	if (zgd->zgd_db)
		dmu_buf_rele(zgd->zgd_db, zgd);

	zfs_range_unlock(zgd->zgd_rl);

	if (error == 0 && zgd->zgd_bp)
		zil_lwb_add_block(zgd->zgd_lwb, zgd->zgd_bp);

	kmem_free(zgd, sizeof (zgd_t));
}

/*
 * Get data to generate a TX_WRITE intent log record.
 */
static int
zvol_get_data(void *arg, lr_write_t *lr, char *buf, struct lwb *lwb, zio_t *zio)
{
	zvol_state_t *zv = arg;
	uint64_t offset = lr->lr_offset;
	uint64_t size = lr->lr_length;	/* length of user data */
	dmu_buf_t *db;
	zgd_t *zgd;
	int error;

	ASSERT3P(lwb, !=, NULL);
	ASSERT3P(zio, !=, NULL);
	ASSERT3U(size, !=, 0);

	zgd = kmem_zalloc(sizeof (zgd_t), KM_SLEEP);
	zgd->zgd_lwb = lwb;

	/*
	 * Write records come in two flavors: immediate and indirect.
	 * For small writes it's cheaper to store the data with the
	 * log record (immediate); for large writes it's cheaper to
	 * sync the data and get a pointer to it (indirect) so that
	 * we don't have to write the data twice.
	 */
	if (buf != NULL) { /* immediate write */
		zgd->zgd_rl = zfs_range_lock(&zv->zv_range_lock, offset, size,
		    RL_READER);
		error = dmu_read_by_dnode(zv->zv_dn, offset, size, buf,
		    DMU_READ_NO_PREFETCH);
	} else { /* indirect write */
		/*
		 * Have to lock the whole block to ensure when it's written out
		 * and its checksum is being calculated that no one can change
		 * the data. Contrarily to zfs_get_data we need not re-check
		 * blocksize after we get the lock because it cannot be changed.
		 */
		size = zv->zv_volblocksize;
		offset = P2ALIGN(offset, size);
		zgd->zgd_rl = zfs_range_lock(&zv->zv_range_lock, offset, size,
		    RL_READER);
		error = dmu_buf_hold_by_dnode(zv->zv_dn, offset, zgd, &db,
		    DMU_READ_NO_PREFETCH);
		if (error == 0) {
			blkptr_t *bp = &lr->lr_blkptr;

			zgd->zgd_db = db;
			zgd->zgd_bp = bp;

			ASSERT(db != NULL);
			ASSERT(db->db_offset == offset);
			ASSERT(db->db_size == size);

			error = dmu_sync(zio, lr->lr_common.lrc_txg,
			    zvol_get_done, zgd);

			if (error == 0)
				return (0);
		}
	}

	zvol_get_done(zgd, error);

	return (error);
}

/*
 * zvol_log_write() handles synchronous writes using TX_WRITE ZIL transactions.
 *
 * We store data in the log buffers if it's small enough.
 * Otherwise we will later flush the data out via dmu_sync().
 */
ssize_t zvol_immediate_write_sz = 32768;
#ifdef _KERNEL
SYSCTL_LONG(_vfs_zfs_vol, OID_AUTO, immediate_write_sz, CTLFLAG_RWTUN,
    &zvol_immediate_write_sz, 0, "Minimal size for indirect log write");
#endif

static void
zvol_log_write(zvol_state_t *zv, dmu_tx_t *tx, offset_t off, ssize_t resid,
    boolean_t sync)
{
	uint32_t blocksize = zv->zv_volblocksize;
	zilog_t *zilog = zv->zv_zilog;
	itx_wr_state_t write_state;

	if (zil_replaying(zilog, tx))
		return;

	if (zilog->zl_logbias == ZFS_LOGBIAS_THROUGHPUT)
		write_state = WR_INDIRECT;
	else if (!spa_has_slogs(zilog->zl_spa) &&
	    resid >= blocksize && blocksize > zvol_immediate_write_sz)
		write_state = WR_INDIRECT;
	else if (sync)
		write_state = WR_COPIED;
	else
		write_state = WR_NEED_COPY;

	while (resid) {
		itx_t *itx;
		lr_write_t *lr;
		itx_wr_state_t wr_state = write_state;
		ssize_t len = resid;

		if (wr_state == WR_COPIED && resid > ZIL_MAX_COPIED_DATA)
			wr_state = WR_NEED_COPY;
		else if (wr_state == WR_INDIRECT)
			len = MIN(blocksize - P2PHASE(off, blocksize), resid);

		itx = zil_itx_create(TX_WRITE, sizeof (*lr) +
		    (wr_state == WR_COPIED ? len : 0));
		lr = (lr_write_t *)&itx->itx_lr;
		if (wr_state == WR_COPIED && dmu_read_by_dnode(zv->zv_dn,
		    off, len, lr + 1, DMU_READ_NO_PREFETCH) != 0) {
			zil_itx_destroy(itx);
			itx = zil_itx_create(TX_WRITE, sizeof (*lr));
			lr = (lr_write_t *)&itx->itx_lr;
			wr_state = WR_NEED_COPY;
		}

		itx->itx_wr_state = wr_state;
		lr->lr_foid = ZVOL_OBJ;
		lr->lr_offset = off;
		lr->lr_length = len;
		lr->lr_blkoff = 0;
		BP_ZERO(&lr->lr_blkptr);

		itx->itx_private = zv;

		if (!sync && (zv->zv_sync_cnt == 0))
			itx->itx_sync = B_FALSE;

		zil_itx_assign(zilog, itx, tx);

		off += len;
		resid -= len;
	}
}

void
zvol_strategy(struct bio *bp)
{
	zvol_state_t *zv;
	uint64_t off, volsize;
	size_t resid;
	char *addr;
	objset_t *os;
	rl_t *rl;
	int error = 0;
	boolean_t doread = 0;
	boolean_t is_dumpified;
	boolean_t sync;

	if (bp->bio_to)
		zv = bp->bio_to->private;
	else
		zv = bp->bio_dev->si_drv2;

	if (zv == NULL) {
		error = SET_ERROR(ENXIO);
		goto out;
	}

	if (bp->bio_cmd != BIO_READ && (zv->zv_flags & ZVOL_RDONLY)) {
		error = SET_ERROR(EROFS);
		goto out;
	}

	switch (bp->bio_cmd) {
	case BIO_FLUSH:
		goto sync;
	case BIO_READ:
		doread = 1;
	case BIO_WRITE:
	case BIO_DELETE:
		break;
	default:
		error = EOPNOTSUPP;
		goto out;
	}

	off = bp->bio_offset;
	volsize = zv->zv_volsize;

	os = zv->zv_objset;
	ASSERT(os != NULL);

	addr = bp->bio_data;
	resid = bp->bio_length;

	if (resid > 0 && (off < 0 || off >= volsize)) {
		error = SET_ERROR(EIO);
		goto out;
	}

	is_dumpified = B_FALSE;
	sync = !doread && !is_dumpified &&
	    zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS;

	/*
	 * There must be no buffer changes when doing a dmu_sync() because
	 * we can't change the data whilst calculating the checksum.
	 */
	rl = zfs_range_lock(&zv->zv_range_lock, off, resid,
	    doread ? RL_READER : RL_WRITER);

	if (bp->bio_cmd == BIO_DELETE) {
		dmu_tx_t *tx = dmu_tx_create(zv->zv_objset);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error != 0) {
			dmu_tx_abort(tx);
		} else {
			zvol_log_truncate(zv, tx, off, resid, sync);
			dmu_tx_commit(tx);
			error = dmu_free_long_range(zv->zv_objset, ZVOL_OBJ,
			    off, resid);
			resid = 0;
		}
		goto unlock;
	}
	while (resid != 0 && off < volsize) {
		size_t size = MIN(resid, zvol_maxphys);
		if (doread) {
			error = dmu_read(os, ZVOL_OBJ, off, size, addr,
			    DMU_READ_PREFETCH);
		} else {
			dmu_tx_t *tx = dmu_tx_create(os);
			dmu_tx_hold_write(tx, ZVOL_OBJ, off, size);
			error = dmu_tx_assign(tx, TXG_WAIT);
			if (error) {
				dmu_tx_abort(tx);
			} else {
				dmu_write(os, ZVOL_OBJ, off, size, addr, tx);
				zvol_log_write(zv, tx, off, size, sync);
				dmu_tx_commit(tx);
			}
		}
		if (error) {
			/* convert checksum errors into IO errors */
			if (error == ECKSUM)
				error = SET_ERROR(EIO);
			break;
		}
		off += size;
		addr += size;
		resid -= size;
	}
unlock:
	zfs_range_unlock(rl);

	bp->bio_completed = bp->bio_length - resid;
	if (bp->bio_completed < bp->bio_length && off > volsize)
		error = EINVAL;

	if (sync) {
sync:
		zil_commit(zv->zv_zilog, ZVOL_OBJ);
	}
out:
	if (bp->bio_to)
		g_io_deliver(bp, error);
	else
		biofinish(bp, NULL, error);
}

int
zvol_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	zvol_state_t *zv;
	uint64_t volsize;
	rl_t *rl;
	int error = 0;

	zv = dev->si_drv2;

	volsize = zv->zv_volsize;
	/* uio_loffset == volsize isn't an error as its required for EOF processing. */
	if (uio->uio_resid > 0 &&
	    (uio->uio_loffset < 0 || uio->uio_loffset > volsize))
		return (SET_ERROR(EIO));

	rl = zfs_range_lock(&zv->zv_range_lock, uio->uio_loffset, uio->uio_resid,
	    RL_READER);
	while (uio->uio_resid > 0 && uio->uio_loffset < volsize) {
		uint64_t bytes = MIN(uio->uio_resid, DMU_MAX_ACCESS >> 1);

		/* don't read past the end */
		if (bytes > volsize - uio->uio_loffset)
			bytes = volsize - uio->uio_loffset;

		error =  dmu_read_uio_dnode(zv->zv_dn, uio, bytes);
		if (error) {
			/* convert checksum errors into IO errors */
			if (error == ECKSUM)
				error = SET_ERROR(EIO);
			break;
		}
	}
	zfs_range_unlock(rl);
	return (error);
}

int
zvol_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	zvol_state_t *zv;
	uint64_t volsize;
	rl_t *rl;
	int error = 0;
	boolean_t sync;

	zv = dev->si_drv2;

	volsize = zv->zv_volsize;
	/* uio_loffset == volsize isn't an error as its required for EOF processing. */
	if (uio->uio_resid > 0 &&
	    (uio->uio_loffset < 0 || uio->uio_loffset > volsize))
		return (SET_ERROR(EIO));

	sync = (ioflag & IO_SYNC) ||
	    (zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS);

	rl = zfs_range_lock(&zv->zv_range_lock, uio->uio_loffset, uio->uio_resid,
	    RL_WRITER);
	while (uio->uio_resid > 0 && uio->uio_loffset < volsize) {
		uint64_t bytes = MIN(uio->uio_resid, DMU_MAX_ACCESS >> 1);
		uint64_t off = uio->uio_loffset;
		dmu_tx_t *tx = dmu_tx_create(zv->zv_objset);

		if (bytes > volsize - off)	/* don't write past the end */
			bytes = volsize - off;

		dmu_tx_hold_write(tx, ZVOL_OBJ, off, bytes);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			break;
		}
		error = dmu_write_uio_dnode(zv->zv_dn, uio, bytes, tx);
		if (error == 0)
			zvol_log_write(zv, tx, off, bytes, sync);
		dmu_tx_commit(tx);

		if (error)
			break;
	}
	zfs_range_unlock(rl);
	if (sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);
	return (error);
}

/*
 * Log a DKIOCFREE/free-long-range to the ZIL with TX_TRUNCATE.
 */
static void
zvol_log_truncate(zvol_state_t *zv, dmu_tx_t *tx, uint64_t off, uint64_t len,
    boolean_t sync)
{
	itx_t *itx;
	lr_truncate_t *lr;
	zilog_t *zilog = zv->zv_zilog;

	if (zil_replaying(zilog, tx))
		return;

	itx = zil_itx_create(TX_TRUNCATE, sizeof (*lr));
	lr = (lr_truncate_t *)&itx->itx_lr;
	lr->lr_foid = ZVOL_OBJ;
	lr->lr_offset = off;
	lr->lr_length = len;

	itx->itx_sync = (sync || zv->zv_sync_cnt != 0);
	zil_itx_assign(zilog, itx, tx);
}

int
zvol_busy(void)
{
	return (zvol_minors != 0);
}

int
zvol_init(void)
{
	VERIFY(ddi_soft_state_init(&zfsdev_state, sizeof (zfs_soft_state_t),
	    1) == 0);
	ZFS_LOG(1, "ZVOL Initialized.");
	return (0);
}

void
zvol_fini(void)
{
	ddi_soft_state_fini(&zfsdev_state);
	ZFS_LOG(1, "ZVOL Deinitialized.");
}

static void
zvol_geom_run(zvol_state_t *zv)
{
	struct g_provider *pp;

	pp = zv->zv_provider;
	g_error_provider(pp, 0);

	kproc_kthread_add(zvol_geom_worker, zv, &zfsproc, NULL, 0, 0,
	    "zfskern", "zvol %s", pp->name + sizeof(ZVOL_DRIVER));
}

static void
zvol_geom_destroy(zvol_state_t *zv)
{
	struct g_provider *pp;

	g_topology_assert();

	mtx_lock(&zv->zv_queue_mtx);
	zv->zv_state = 1;
	wakeup_one(&zv->zv_queue);
	while (zv->zv_state != 2)
		msleep(&zv->zv_state, &zv->zv_queue_mtx, 0, "zvol:w", 0);
	mtx_destroy(&zv->zv_queue_mtx);

	pp = zv->zv_provider;
	zv->zv_provider = NULL;
	pp->private = NULL;
	g_wither_geom(pp->geom, ENXIO);
}

static int
zvol_geom_access(struct g_provider *pp, int acr, int acw, int ace)
{
	int count, error, flags;

	g_topology_assert();

	/*
	 * To make it easier we expect either open or close, but not both
	 * at the same time.
	 */
	KASSERT((acr >= 0 && acw >= 0 && ace >= 0) ||
	    (acr <= 0 && acw <= 0 && ace <= 0),
	    ("Unsupported access request to %s (acr=%d, acw=%d, ace=%d).",
	    pp->name, acr, acw, ace));

	if (pp->private == NULL) {
		if (acr <= 0 && acw <= 0 && ace <= 0)
			return (0);
		return (pp->error);
	}

	/*
	 * We don't pass FEXCL flag to zvol_open()/zvol_close() if ace != 0,
	 * because GEOM already handles that and handles it a bit differently.
	 * GEOM allows for multiple read/exclusive consumers and ZFS allows
	 * only one exclusive consumer, no matter if it is reader or writer.
	 * I like better the way GEOM works so I'll leave it for GEOM to
	 * decide what to do.
	 */

	count = acr + acw + ace;
	if (count == 0)
		return (0);

	flags = 0;
	if (acr != 0 || ace != 0)
		flags |= FREAD;
	if (acw != 0)
		flags |= FWRITE;

	g_topology_unlock();
	if (count > 0)
		error = zvol_open(pp, flags, count);
	else
		error = zvol_close(pp, flags, -count);
	g_topology_lock();
	return (error);
}

static void
zvol_geom_start(struct bio *bp)
{
	zvol_state_t *zv;
	boolean_t first;

	zv = bp->bio_to->private;
	ASSERT(zv != NULL);
	switch (bp->bio_cmd) {
	case BIO_FLUSH:
		if (!THREAD_CAN_SLEEP())
			goto enqueue;
		zil_commit(zv->zv_zilog, ZVOL_OBJ);
		g_io_deliver(bp, 0);
		break;
	case BIO_READ:
	case BIO_WRITE:
	case BIO_DELETE:
		if (!THREAD_CAN_SLEEP())
			goto enqueue;
		zvol_strategy(bp);
		break;
	case BIO_GETATTR: {
		spa_t *spa = dmu_objset_spa(zv->zv_objset);
		uint64_t refd, avail, usedobjs, availobjs;

		if (g_handleattr_int(bp, "GEOM::candelete", 1))
			return;
		if (strcmp(bp->bio_attribute, "blocksavail") == 0) {
			dmu_objset_space(zv->zv_objset, &refd, &avail,
			    &usedobjs, &availobjs);
			if (g_handleattr_off_t(bp, "blocksavail",
			    avail / DEV_BSIZE))
				return;
		} else if (strcmp(bp->bio_attribute, "blocksused") == 0) {
			dmu_objset_space(zv->zv_objset, &refd, &avail,
			    &usedobjs, &availobjs);
			if (g_handleattr_off_t(bp, "blocksused",
			    refd / DEV_BSIZE))
				return;
		} else if (strcmp(bp->bio_attribute, "poolblocksavail") == 0) {
			avail = metaslab_class_get_space(spa_normal_class(spa));
			avail -= metaslab_class_get_alloc(spa_normal_class(spa));
			if (g_handleattr_off_t(bp, "poolblocksavail",
			    avail / DEV_BSIZE))
				return;
		} else if (strcmp(bp->bio_attribute, "poolblocksused") == 0) {
			refd = metaslab_class_get_alloc(spa_normal_class(spa));
			if (g_handleattr_off_t(bp, "poolblocksused",
			    refd / DEV_BSIZE))
				return;
		}
		/* FALLTHROUGH */
	}
	default:
		g_io_deliver(bp, EOPNOTSUPP);
		break;
	}
	return;

enqueue:
	mtx_lock(&zv->zv_queue_mtx);
	first = (bioq_first(&zv->zv_queue) == NULL);
	bioq_insert_tail(&zv->zv_queue, bp);
	mtx_unlock(&zv->zv_queue_mtx);
	if (first)
		wakeup_one(&zv->zv_queue);
}

static void
zvol_geom_worker(void *arg)
{
	zvol_state_t *zv;
	struct bio *bp;

	thread_lock(curthread);
	sched_prio(curthread, PRIBIO);
	thread_unlock(curthread);

	zv = arg;
	for (;;) {
		mtx_lock(&zv->zv_queue_mtx);
		bp = bioq_takefirst(&zv->zv_queue);
		if (bp == NULL) {
			if (zv->zv_state == 1) {
				zv->zv_state = 2;
				wakeup(&zv->zv_state);
				mtx_unlock(&zv->zv_queue_mtx);
				kthread_exit();
			}
			msleep(&zv->zv_queue, &zv->zv_queue_mtx, PRIBIO | PDROP,
			    "zvol:io", 0);
			continue;
		}
		mtx_unlock(&zv->zv_queue_mtx);
		switch (bp->bio_cmd) {
		case BIO_FLUSH:
			zil_commit(zv->zv_zilog, ZVOL_OBJ);
			g_io_deliver(bp, 0);
			break;
		case BIO_READ:
		case BIO_WRITE:
		case BIO_DELETE:
			zvol_strategy(bp);
			break;
		default:
			g_io_deliver(bp, EOPNOTSUPP);
			break;
		}
	}
}

extern boolean_t dataset_name_hidden(const char *name);

static int
zvol_create_snapshots(objset_t *os, const char *name)
{
	uint64_t cookie, obj;
	char *sname;
	int error, len;

	cookie = obj = 0;
	sname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

#if 0
	(void) dmu_objset_find(name, dmu_objset_prefetch, NULL,
	    DS_FIND_SNAPSHOTS);
#endif

	for (;;) {
		len = snprintf(sname, MAXPATHLEN, "%s@", name);
		if (len >= MAXPATHLEN) {
			dmu_objset_rele(os, FTAG);
			error = ENAMETOOLONG;
			break;
		}

		dsl_pool_config_enter(dmu_objset_pool(os), FTAG);
		error = dmu_snapshot_list_next(os, MAXPATHLEN - len,
		    sname + len, &obj, &cookie, NULL);
		dsl_pool_config_exit(dmu_objset_pool(os), FTAG);
		if (error != 0) {
			if (error == ENOENT)
				error = 0;
			break;
		}

		error = zvol_create_minor(sname);
		if (error != 0 && error != EEXIST) {
			printf("ZFS WARNING: Unable to create ZVOL %s (error=%d).\n",
			    sname, error);
			break;
		}
	}

	kmem_free(sname, MAXPATHLEN);
	return (error);
}

void
zvol_create_minors(spa_t *spa, const char *name, boolean_t async)
{
	uint64_t cookie;
	objset_t *os;
	char *osname, *p;
	int error, len;

	if (dataset_name_hidden(name))
		return;

	if ((error = dmu_objset_hold(name, FTAG, &os)) != 0) {
		printf("ZFS WARNING: Unable to put hold on %s (error=%d).\n",
		    name, error);
		return;
	}
	if (dmu_objset_type(os) == DMU_OST_ZVOL) {
		dsl_dataset_long_hold(os->os_dsl_dataset, FTAG);
		dsl_pool_rele(dmu_objset_pool(os), FTAG);
		error = zvol_create_minor(name);
		if (error == 0 || error == EEXIST) {
			error = zvol_create_snapshots(os, name);
		} else {
			printf("ZFS WARNING: Unable to create ZVOL %s (error=%d).\n",
			    name, error);
		}
		dsl_dataset_long_rele(os->os_dsl_dataset, FTAG);
		dsl_dataset_rele(os->os_dsl_dataset, FTAG);
		return;
	}
	if (dmu_objset_type(os) != DMU_OST_ZFS) {
		dmu_objset_rele(os, FTAG);
		return;
	}

	osname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if (snprintf(osname, MAXPATHLEN, "%s/", name) >= MAXPATHLEN) {
		dmu_objset_rele(os, FTAG);
		kmem_free(osname, MAXPATHLEN);
		return;
	}
	p = osname + strlen(osname);
	len = MAXPATHLEN - (p - osname);

#if 0
	/* Prefetch the datasets. */
	cookie = 0;
	while (dmu_dir_list_next(os, len, p, NULL, &cookie) == 0) {
		if (!dataset_name_hidden(osname))
			(void) dmu_objset_prefetch(osname, NULL);
	}
#endif

	cookie = 0;
	while (dmu_dir_list_next(os, MAXPATHLEN - (p - osname), p, NULL,
	    &cookie) == 0) {
		dmu_objset_rele(os, FTAG);
		(void)zvol_create_minors(spa, osname, async);
		if ((error = dmu_objset_hold(name, FTAG, &os)) != 0) {
			printf("ZFS WARNING: Unable to put hold on %s (error=%d).\n",
			    name, error);
			return;
		}
	}

	dmu_objset_rele(os, FTAG);
	kmem_free(osname, MAXPATHLEN);
}

static void
zvol_rename_minor(zvol_state_t *zv, const char *newname)
{
	struct g_geom *gp;
	struct g_provider *pp;
	struct cdev *dev;

	ASSERT(MUTEX_HELD(&zfsdev_state_lock));

	if (zv->zv_volmode == ZFS_VOLMODE_GEOM) {
		g_topology_lock();
		pp = zv->zv_provider;
		ASSERT(pp != NULL);
		gp = pp->geom;
		ASSERT(gp != NULL);

		zv->zv_provider = NULL;
		g_wither_provider(pp, ENXIO);

		pp = g_new_providerf(gp, "%s/%s", ZVOL_DRIVER, newname);
		pp->flags |= G_PF_DIRECT_RECEIVE | G_PF_DIRECT_SEND;
		pp->sectorsize = DEV_BSIZE;
		pp->mediasize = zv->zv_volsize;
		pp->private = zv;
		zv->zv_provider = pp;
		g_error_provider(pp, 0);
		g_topology_unlock();
	} else if (zv->zv_volmode == ZFS_VOLMODE_DEV) {
		struct make_dev_args args;

		if ((dev = zv->zv_dev) != NULL) {
			zv->zv_dev = NULL;
			destroy_dev(dev);
			if (zv->zv_total_opens > 0) {
				zv->zv_flags &= ~ZVOL_EXCL;
				zv->zv_total_opens = 0;
				zvol_last_close(zv);
			}
		}

		make_dev_args_init(&args);
		args.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
		args.mda_devsw = &zvol_cdevsw;
		args.mda_cr = NULL;
		args.mda_uid = UID_ROOT;
		args.mda_gid = GID_OPERATOR;
		args.mda_mode = 0640;
		args.mda_si_drv2 = zv;
		if (make_dev_s(&args, &zv->zv_dev,
		    "%s/%s", ZVOL_DRIVER, newname) == 0)
			zv->zv_dev->si_iosize_max = MAXPHYS;
	}
	strlcpy(zv->zv_name, newname, sizeof(zv->zv_name));
}

void
zvol_rename_minors(spa_t *spa, const char *oldname, const char *newname,
	boolean_t async)
{
	char name[MAXPATHLEN];
	size_t oldnamelen, newnamelen;
	zvol_state_t *zv;
	boolean_t locked = B_FALSE;

	oldnamelen = strlen(oldname);
	newnamelen = strlen(newname);

	DROP_GIANT();
	/* See comment in zvol_open(). */
	if (!MUTEX_HELD(&zfsdev_state_lock)) {
		mutex_enter(&zfsdev_state_lock);
		locked = B_TRUE;
	}

	LIST_FOREACH(zv, &all_zvols, zv_links) {
		if (strcmp(zv->zv_name, oldname) == 0) {
			zvol_rename_minor(zv, newname);
		} else if (strncmp(zv->zv_name, oldname, oldnamelen) == 0 &&
		    (zv->zv_name[oldnamelen] == '/' ||
		     zv->zv_name[oldnamelen] == '@')) {
			snprintf(name, sizeof(name), "%s%c%s", newname,
			    zv->zv_name[oldnamelen],
			    zv->zv_name + oldnamelen + 1);
			zvol_rename_minor(zv, name);
		}
	}

	if (locked)
		mutex_exit(&zfsdev_state_lock);
	PICKUP_GIANT();
}

static int
zvol_d_open(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	zvol_state_t *zv = dev->si_drv2;
	int err = 0;

	mutex_enter(&zfsdev_state_lock);
	if (zv->zv_total_opens == 0)
		err = zvol_first_open(zv);
	if (err) {
		mutex_exit(&zfsdev_state_lock);
		return (err);
	}
	if ((flags & FWRITE) && (zv->zv_flags & ZVOL_RDONLY)) {
		err = SET_ERROR(EROFS);
		goto out;
	}
	if (zv->zv_flags & ZVOL_EXCL) {
		err = SET_ERROR(EBUSY);
		goto out;
	}
#ifdef FEXCL
	if (flags & FEXCL) {
		if (zv->zv_total_opens != 0) {
			err = SET_ERROR(EBUSY);
			goto out;
		}
		zv->zv_flags |= ZVOL_EXCL;
	}
#endif

	zv->zv_total_opens++;
	if (flags & (FSYNC | FDSYNC)) {
		zv->zv_sync_cnt++;
		if (zv->zv_sync_cnt == 1)
			zil_async_to_sync(zv->zv_zilog, ZVOL_OBJ);
	}
	mutex_exit(&zfsdev_state_lock);
	return (err);
out:
	if (zv->zv_total_opens == 0)
		zvol_last_close(zv);
	mutex_exit(&zfsdev_state_lock);
	return (err);
}

static int
zvol_d_close(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	zvol_state_t *zv = dev->si_drv2;

	mutex_enter(&zfsdev_state_lock);
	if (zv->zv_flags & ZVOL_EXCL) {
		ASSERT(zv->zv_total_opens == 1);
		zv->zv_flags &= ~ZVOL_EXCL;
	}

	/*
	 * If the open count is zero, this is a spurious close.
	 * That indicates a bug in the kernel / DDI framework.
	 */
	ASSERT(zv->zv_total_opens != 0);

	/*
	 * You may get multiple opens, but only one close.
	 */
	zv->zv_total_opens--;
	if (flags & (FSYNC | FDSYNC))
		zv->zv_sync_cnt--;

	if (zv->zv_total_opens == 0)
		zvol_last_close(zv);

	mutex_exit(&zfsdev_state_lock);
	return (0);
}

static int
zvol_d_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag, struct thread *td)
{
	zvol_state_t *zv;
	rl_t *rl;
	off_t offset, length;
	int i, error;
	boolean_t sync;

	zv = dev->si_drv2;

	error = 0;
	KASSERT(zv->zv_total_opens > 0,
	    ("Device with zero access count in zvol_d_ioctl"));

	i = IOCPARM_LEN(cmd);
	switch (cmd) {
	case DIOCGSECTORSIZE:
		*(u_int *)data = DEV_BSIZE;
		break;
	case DIOCGMEDIASIZE:
		*(off_t *)data = zv->zv_volsize;
		break;
	case DIOCGFLUSH:
		zil_commit(zv->zv_zilog, ZVOL_OBJ);
		break;
	case DIOCGDELETE:
		if (!zvol_unmap_enabled)
			break;

		offset = ((off_t *)data)[0];
		length = ((off_t *)data)[1];
		if ((offset % DEV_BSIZE) != 0 || (length % DEV_BSIZE) != 0 ||
		    offset < 0 || offset >= zv->zv_volsize ||
		    length <= 0) {
			printf("%s: offset=%jd length=%jd\n", __func__, offset,
			    length);
			error = EINVAL;
			break;
		}

		rl = zfs_range_lock(&zv->zv_range_lock, offset, length, RL_WRITER);
		dmu_tx_t *tx = dmu_tx_create(zv->zv_objset);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error != 0) {
			sync = FALSE;
			dmu_tx_abort(tx);
		} else {
			sync = (zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS);
			zvol_log_truncate(zv, tx, offset, length, sync);
			dmu_tx_commit(tx);
			error = dmu_free_long_range(zv->zv_objset, ZVOL_OBJ,
			    offset, length);
		}
		zfs_range_unlock(rl);
		if (sync)
			zil_commit(zv->zv_zilog, ZVOL_OBJ);
		break;
	case DIOCGSTRIPESIZE:
		*(off_t *)data = zv->zv_volblocksize;
		break;
	case DIOCGSTRIPEOFFSET:
		*(off_t *)data = 0;
		break;
	case DIOCGATTR: {
		spa_t *spa = dmu_objset_spa(zv->zv_objset);
		struct diocgattr_arg *arg = (struct diocgattr_arg *)data;
		uint64_t refd, avail, usedobjs, availobjs;

		if (strcmp(arg->name, "GEOM::candelete") == 0)
			arg->value.i = 1;
		else if (strcmp(arg->name, "blocksavail") == 0) {
			dmu_objset_space(zv->zv_objset, &refd, &avail,
			    &usedobjs, &availobjs);
			arg->value.off = avail / DEV_BSIZE;
		} else if (strcmp(arg->name, "blocksused") == 0) {
			dmu_objset_space(zv->zv_objset, &refd, &avail,
			    &usedobjs, &availobjs);
			arg->value.off = refd / DEV_BSIZE;
		} else if (strcmp(arg->name, "poolblocksavail") == 0) {
			avail = metaslab_class_get_space(spa_normal_class(spa));
			avail -= metaslab_class_get_alloc(spa_normal_class(spa));
			arg->value.off = avail / DEV_BSIZE;
		} else if (strcmp(arg->name, "poolblocksused") == 0) {
			refd = metaslab_class_get_alloc(spa_normal_class(spa));
			arg->value.off = refd / DEV_BSIZE;
		} else
			error = ENOIOCTL;
		break;
	}
	case FIOSEEKHOLE:
	case FIOSEEKDATA: {
		off_t *off = (off_t *)data;
		uint64_t noff;
		boolean_t hole;

		hole = (cmd == FIOSEEKHOLE);
		noff = *off;
		error = dmu_offset_next(zv->zv_objset, ZVOL_OBJ, hole, &noff);
		*off = noff;
		break;
	}
	default:
		error = ENOIOCTL;
	}

	return (error);
}

boolean_t
zvol_is_zvol(const char *device)
{
	return (device && strncmp(device, ZVOL_DIR, strlen(ZVOL_DIR)) == 0);
}

int
zvol_set_snapdev(const char *ddname, zprop_source_t source, uint64_t snapdev)
{
	return (ENOTSUP);
}

int
zvol_set_volmode(const char *ddname, zprop_source_t source, uint64_t snapdev)
{
	return (ENOTSUP);
}


/*
 * return the proper tag for rollback and recv
 */
void *
zvol_tag(zvol_state_t *zv)
{
	//ASSERT(RW_WRITE_HELD(&zv->zv_suspend_lock));
	return (zv->zv_total_opens > 0 ? zv : NULL);
}
