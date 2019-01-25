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

#include <sys/arc_impl.h>
#include <sys/dsl_pool.h>


extern arc_state_t ARC_anon;
extern arc_state_t ARC_mru;
extern arc_state_t ARC_mru_ghost;
extern arc_state_t ARC_mfu;
extern arc_state_t ARC_mfu_ghost;
extern arc_state_t ARC_l2c_only;

/* L2ARC Performance Tunables */
extern unsigned long l2arc_write_max;	/* def max write size */
extern unsigned long l2arc_write_boost;	/* extra warmup write */
extern unsigned long l2arc_headroom;		/* # of dev writes */
extern unsigned long l2arc_headroom_boost;
extern unsigned long l2arc_feed_secs;	/* interval seconds */
extern unsigned long l2arc_feed_min_ms;	/* min interval msecs */
extern int l2arc_noprefetch;			/* don't cache prefetch bufs */
extern int l2arc_feed_again;			/* turbo warmup */
extern int l2arc_norw;			/* no reads during writes */

/*
 * minimum lifespan of a prefetch block in clock ticks
 * (initialized in arc_init())
 */
extern int		arc_min_prefetch_ms;
extern int		arc_min_prescient_prefetch_ms;

/* arc.c */
SYSCTL_DECL(_vfs_zfs);
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, l2arc_write_max, CTLFLAG_RW,
    &l2arc_write_max, 0, "max write size");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, l2arc_write_boost, CTLFLAG_RW,
    &l2arc_write_boost, 0, "extra write during warmup");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, l2arc_headroom, CTLFLAG_RW,
    &l2arc_headroom, 0, "number of dev writes");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, l2arc_feed_secs, CTLFLAG_RW,
    &l2arc_feed_secs, 0, "interval seconds");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, l2arc_feed_min_ms, CTLFLAG_RW,
    &l2arc_feed_min_ms, 0, "min interval milliseconds");

SYSCTL_INT(_vfs_zfs, OID_AUTO, l2arc_noprefetch, CTLFLAG_RW,
    &l2arc_noprefetch, 0, "don't cache prefetch bufs");
SYSCTL_INT(_vfs_zfs, OID_AUTO, l2arc_feed_again, CTLFLAG_RW,
    &l2arc_feed_again, 0, "turbo warmup");
SYSCTL_INT(_vfs_zfs, OID_AUTO, l2arc_norw, CTLFLAG_RW,
    &l2arc_norw, 0, "no reads during writes");

SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, anon_size, CTLFLAG_RD,
    &ARC_anon.arcs_size.rc_count, 0, "size of anonymous state");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, anon_metadata_esize, CTLFLAG_RD,
    &ARC_anon.arcs_esize[ARC_BUFC_METADATA].rc_count, 0,
    "size of anonymous state");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, anon_data_esize, CTLFLAG_RD,
    &ARC_anon.arcs_esize[ARC_BUFC_DATA].rc_count, 0,
    "size of anonymous state");

SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, mru_size, CTLFLAG_RD,
    &ARC_mru.arcs_size.rc_count, 0, "size of mru state");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, mru_metadata_esize, CTLFLAG_RD,
    &ARC_mru.arcs_esize[ARC_BUFC_METADATA].rc_count, 0,
    "size of metadata in mru state");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, mru_data_esize, CTLFLAG_RD,
    &ARC_mru.arcs_esize[ARC_BUFC_DATA].rc_count, 0,
    "size of data in mru state");

SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, mru_ghost_size, CTLFLAG_RD,
    &ARC_mru_ghost.arcs_size.rc_count, 0, "size of mru ghost state");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, mru_ghost_metadata_esize, CTLFLAG_RD,
    &ARC_mru_ghost.arcs_esize[ARC_BUFC_METADATA].rc_count, 0,
    "size of metadata in mru ghost state");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, mru_ghost_data_esize, CTLFLAG_RD,
    &ARC_mru_ghost.arcs_esize[ARC_BUFC_DATA].rc_count, 0,
    "size of data in mru ghost state");

SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, mfu_size, CTLFLAG_RD,
    &ARC_mfu.arcs_size.rc_count, 0, "size of mfu state");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, mfu_metadata_esize, CTLFLAG_RD,
    &ARC_mfu.arcs_esize[ARC_BUFC_METADATA].rc_count, 0,
    "size of metadata in mfu state");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, mfu_data_esize, CTLFLAG_RD,
    &ARC_mfu.arcs_esize[ARC_BUFC_DATA].rc_count, 0,
    "size of data in mfu state");

SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, mfu_ghost_size, CTLFLAG_RD,
    &ARC_mfu_ghost.arcs_size.rc_count, 0, "size of mfu ghost state");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, mfu_ghost_metadata_esize, CTLFLAG_RD,
    &ARC_mfu_ghost.arcs_esize[ARC_BUFC_METADATA].rc_count, 0,
    "size of metadata in mfu ghost state");
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, mfu_ghost_data_esize, CTLFLAG_RD,
    &ARC_mfu_ghost.arcs_esize[ARC_BUFC_DATA].rc_count, 0,
    "size of data in mfu ghost state");

SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, l2c_only_size, CTLFLAG_RD,
    &ARC_l2c_only.arcs_size.rc_count, 0, "size of mru state");

SYSCTL_UINT(_vfs_zfs, OID_AUTO, arc_min_prefetch_ms, CTLFLAG_RW,
    &arc_min_prefetch_ms, 0, "Min life of prefetch block in ms");
SYSCTL_UINT(_vfs_zfs, OID_AUTO, arc_min_prescient_prefetch_ms, CTLFLAG_RW,
    &arc_min_prescient_prefetch_ms, 0, "Min life of prescient prefetched block in ms");

extern unsigned long zfs_arc_max;
extern unsigned long zfs_arc_min;
extern unsigned long zfs_arc_meta_limit;
extern unsigned long zfs_arc_meta_min;
extern int			arc_no_grow_shift;
extern int		arc_shrink_shift;
static uint64_t arc_abs_min = 16 << 20;

extern arc_stats_t arc_stats;
#define	ARCSTAT(stat)	(arc_stats.stat.value.ui64)
#define	arc_p		ARCSTAT(arcstat_p)	/* target size of MRU */
#define	arc_c		ARCSTAT(arcstat_c)	/* target size of cache */
#define	arc_c_min	ARCSTAT(arcstat_c_min)	/* min target cache size */
#define	arc_c_max	ARCSTAT(arcstat_c_max)	/* max target cache size */
#define	arc_no_grow	ARCSTAT(arcstat_no_grow) /* do not grow cache size */
#define	arc_tempreserve	ARCSTAT(arcstat_tempreserve)
#define	arc_loaned_bytes	ARCSTAT(arcstat_loaned_bytes)
#define	arc_meta_limit	ARCSTAT(arcstat_meta_limit) /* max size for metadata */
#define	arc_dnode_limit	ARCSTAT(arcstat_dnode_limit) /* max size for dnodes */
#define	arc_meta_min	ARCSTAT(arcstat_meta_min) /* min size for metadata */
#define	arc_meta_max	ARCSTAT(arcstat_meta_max) /* max size of metadata */
#define	arc_need_free	ARCSTAT(arcstat_need_free) /* bytes to be freed */
#define	arc_sys_free	ARCSTAT(arcstat_sys_free) /* target system free bytes */

#ifdef notyet
static int
sysctl_vfs_zfs_arc_meta_limit(SYSCTL_HANDLER_ARGS)
{
	uint64_t val;
	int err;

	val = zfs_arc_meta_limit;
	err = sysctl_handle_64(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

        if (val <= 0 || val > arc_c_max)
		return (EINVAL);

	arc_meta_limit = val;
	return (0);
}
#endif

static int
sysctl_vfs_zfs_arc_no_grow_shift(SYSCTL_HANDLER_ARGS)
{
	uint32_t val;
	int err;

	val = arc_no_grow_shift;
	err = sysctl_handle_32(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

        if (val >= arc_shrink_shift)
		return (EINVAL);

	arc_no_grow_shift = val;
	return (0);
}

static int
sysctl_vfs_zfs_arc_max(SYSCTL_HANDLER_ARGS)
{
	uint64_t val;
	int err;

	val = zfs_arc_max;
	err = sysctl_handle_64(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

	if (zfs_arc_max == 0) {
		/* Loader tunable so blindly set */
		zfs_arc_max = val;
		return (0);
	}

	if (val < arc_abs_min || val > kmem_size())
		return (EINVAL);
	if (val < arc_c_min)
		return (EINVAL);
	if (zfs_arc_meta_limit > 0 && val < zfs_arc_meta_limit)
		return (EINVAL);

	arc_c_max = val;

	arc_c = arc_c_max;
        arc_p = (arc_c >> 1);

	if (zfs_arc_meta_limit == 0) {
		/* limit meta-data to 1/4 of the arc capacity */
		arc_meta_limit = arc_c_max / 4;
	}

	/* if kmem_flags are set, lets try to use less memory */
	if (kmem_debugging())
		arc_c = arc_c / 2;

	zfs_arc_max = arc_c;

	return (0);
}

static int
sysctl_vfs_zfs_arc_min(SYSCTL_HANDLER_ARGS)
{
	uint64_t val;
	int err;

	val = zfs_arc_min;
	err = sysctl_handle_64(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

	if (zfs_arc_min == 0) {
		/* Loader tunable so blindly set */
		zfs_arc_min = val;
		return (0);
	}

	if (val < arc_abs_min || val > arc_c_max)
		return (EINVAL);

	arc_c_min = val;

	if (zfs_arc_meta_min == 0)
                arc_meta_min = arc_c_min / 2;

	if (arc_c < arc_c_min)
                arc_c = arc_c_min;

	zfs_arc_min = arc_c_min;

	return (0);
}

SYSCTL_PROC(_vfs_zfs, OID_AUTO, arc_max, CTLTYPE_U64 | CTLFLAG_RWTUN,
    0, sizeof(uint64_t), sysctl_vfs_zfs_arc_max, "QU", "Maximum ARC size");
SYSCTL_PROC(_vfs_zfs, OID_AUTO, arc_min, CTLTYPE_U64 | CTLFLAG_RWTUN,
    0, sizeof(uint64_t), sysctl_vfs_zfs_arc_min, "QU", "Minimum ARC size");
SYSCTL_PROC(_vfs_zfs, OID_AUTO, arc_no_grow_shift, CTLTYPE_U32 | CTLFLAG_RWTUN,
    0, sizeof(uint32_t), sysctl_vfs_zfs_arc_no_grow_shift, "U",
    "log2(fraction of ARC which must be free to allow growing)");
#ifdef notyet
SYSCTL_PROC(_vfs_zfs, OID_AUTO, arc_meta_limit,
    CTLTYPE_U64 | CTLFLAG_MPSAFE | CTLFLAG_RW, 0, sizeof(uint64_t),
    sysctl_vfs_zfs_arc_meta_limit, "QU",
    "ARC metadata limit");
#endif
/* dbuf.c */

extern uint64_t dbuf_cache_max_bytes;
SYSCTL_QUAD(_vfs_zfs, OID_AUTO, dbuf_cache_max_bytes, CTLFLAG_RWTUN,
    &dbuf_cache_max_bytes, 0, "dbuf cache size in bytes");

extern uint64_t dbuf_metadata_cache_max_bytes;
SYSCTL_QUAD(_vfs_zfs, OID_AUTO, dbuf_metadata_cache_max_bytes, CTLFLAG_RWTUN,
    &dbuf_metadata_cache_max_bytes, 0, "dbuf metadata cache size in bytes");

extern int dbuf_cache_shift;
SYSCTL_INT(_vfs_zfs, OID_AUTO, dbuf_cache_shift, CTLFLAG_RDTUN,
    &dbuf_cache_shift, 0, "dbuf cache size as log2 fraction of ARC");

extern int dbuf_metadata_cache_shift;
SYSCTL_INT(_vfs_zfs, OID_AUTO, dbuf_metadata_cache_shift, CTLFLAG_RDTUN,
    &dbuf_metadata_cache_shift, 0,
    "dbuf metadata cache size as log2 fraction of ARC");

extern uint_t dbuf_cache_hiwater_pct;
SYSCTL_UINT(_vfs_zfs, OID_AUTO, dbuf_cache_hiwater_pct, CTLFLAG_RWTUN,
    &dbuf_cache_hiwater_pct, 0, "max percents above the dbuf cache size");

extern uint_t dbuf_cache_lowater_pct;
SYSCTL_UINT(_vfs_zfs, OID_AUTO, dbuf_cache_lowater_pct, CTLFLAG_RWTUN,
    &dbuf_cache_lowater_pct, 0, "max percents below the dbuf cache size");


/* ddt.c */
extern int zfs_dedup_prefetch;
static SYSCTL_NODE(_vfs_zfs, OID_AUTO, dedup, CTLFLAG_RW, 0, "ZFS DEDUP");
SYSCTL_INT(_vfs_zfs_dedup, OID_AUTO, prefetch, CTLFLAG_RWTUN, &zfs_dedup_prefetch,
    0, "Enable/disable prefetching of dedup-ed blocks which are going to be freed");

/* dmu.c */
extern int zfs_nopwrite_enabled;
SYSCTL_INT(_vfs_zfs, OID_AUTO, nopwrite_enabled, CTLFLAG_RDTUN,
    &zfs_nopwrite_enabled, 0, "Enable nopwrite feature");

/*
 * Tunable to control percentage of dirtied blocks from frees in one TXG.
 * After this threshold is crossed, additional dirty blocks from frees
 * wait until the next TXG.
 * A value of zero will disable this throttle.
 */
extern uint32_t zfs_per_txg_dirty_frees_percent;
SYSCTL_INT(_vfs_zfs, OID_AUTO, per_txg_dirty_frees_percent, CTLFLAG_RWTUN,
	&zfs_per_txg_dirty_frees_percent, 0, "Percentage of dirtied blocks from frees in one txg");

extern int zfs_mdcomp_disable;
SYSCTL_INT(_vfs_zfs, OID_AUTO, mdcomp_disable, CTLFLAG_RWTUN,
    &zfs_mdcomp_disable, 0, "Disable metadata compression");

extern int zfs_dmu_offset_next_sync;
SYSCTL_INT(_vfs_zfs, OID_AUTO, dmu_offset_next_sync, CTLFLAG_RWTUN,
    &zfs_dmu_offset_next_sync, 0, "Enable forcing txg sync to find holes");

/* dmu_traverse.c */
extern boolean_t send_holes_without_birth_time;
SYSCTL_UINT(_vfs_zfs, OID_AUTO, send_holes_without_birth_time, CTLFLAG_RWTUN,
    &send_holes_without_birth_time, 0, "Send holes without birth time");


/* dmu_zfetch.c */
/*
 * This tunable disables predictive prefetch.  Note that it leaves "prescient"
 * prefetch (e.g. prefetch for zfs send) intact.  Unlike predictive prefetch,
 * prescient prefetch never issues i/os that end up not being needed,
 * so it can't hurt performance.
 */
extern boolean_t zfs_prefetch_disable;

/* max # of streams per zfetch */
extern uint32_t	zfetch_max_streams;
/* min time before stream reclaim */
extern uint32_t	zfetch_min_sec_reap;
/* max bytes to prefetch per stream (default 8MB) */
extern uint32_t	zfetch_max_distance;
/* max bytes to prefetch indirects for per stream (default 64MB) */
extern uint32_t	zfetch_max_idistance;
/* max number of bytes in an array_read in which we allow prefetching (1MB) */
extern uint64_t	zfetch_array_rd_sz;

SYSCTL_INT(_vfs_zfs, OID_AUTO, prefetch_disable, CTLFLAG_RW,
    &zfs_prefetch_disable, 0, "Disable prefetch");
SYSCTL_NODE(_vfs_zfs, OID_AUTO, zfetch, CTLFLAG_RW, 0, "ZFS ZFETCH");
SYSCTL_UINT(_vfs_zfs_zfetch, OID_AUTO, max_streams, CTLFLAG_RWTUN,
    &zfetch_max_streams, 0, "Max # of streams per zfetch");
SYSCTL_UINT(_vfs_zfs_zfetch, OID_AUTO, min_sec_reap, CTLFLAG_RWTUN,
    &zfetch_min_sec_reap, 0, "Min time before stream reclaim");
SYSCTL_UINT(_vfs_zfs_zfetch, OID_AUTO, max_distance, CTLFLAG_RWTUN,
    &zfetch_max_distance, 0, "Max bytes to prefetch per stream");
SYSCTL_UINT(_vfs_zfs_zfetch, OID_AUTO, max_idistance, CTLFLAG_RWTUN,
    &zfetch_max_idistance, 0, "Max bytes to prefetch indirects for per stream");
SYSCTL_UQUAD(_vfs_zfs_zfetch, OID_AUTO, array_rd_sz, CTLFLAG_RWTUN,
    &zfetch_array_rd_sz, 0,
    "Number of bytes in a array_read at which we stop prefetching");

/* dsl_pool.c */
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, dirty_data_max, CTLFLAG_RWTUN,
    &zfs_dirty_data_max, 0,
    "The maximum amount of dirty data in bytes after which new writes are "
    "halted until space becomes available");

SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, dirty_data_max_max, CTLFLAG_RDTUN,
    &zfs_dirty_data_max_max, 0,
    "The absolute cap on dirty_data_max when auto calculating");

static int sysctl_zfs_dirty_data_max_percent(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_vfs_zfs, OID_AUTO, dirty_data_max_percent,
    CTLTYPE_INT | CTLFLAG_MPSAFE | CTLFLAG_RWTUN, 0, sizeof(int),
    sysctl_zfs_dirty_data_max_percent, "I",
    "The percent of physical memory used to auto calculate dirty_data_max");

SYSCTL_INT(_vfs_zfs, OID_AUTO, dirty_data_sync_percent, CTLFLAG_RWTUN,
    &zfs_dirty_data_sync_percent, 0,
    "Force a txg if the percent of dirty buffer bytes exceed this value");

static int sysctl_zfs_delay_min_dirty_percent(SYSCTL_HANDLER_ARGS);
/* No zfs_delay_min_dirty_percent tunable due to limit requirements */
SYSCTL_PROC(_vfs_zfs, OID_AUTO, delay_min_dirty_percent,
    CTLTYPE_INT | CTLFLAG_MPSAFE | CTLFLAG_RW, 0, sizeof(int),
    sysctl_zfs_delay_min_dirty_percent, "I",
    "The limit of outstanding dirty data before transactions are delayed");

static int sysctl_zfs_delay_scale(SYSCTL_HANDLER_ARGS);
/* No zfs_delay_scale tunable due to limit requirements */
SYSCTL_PROC(_vfs_zfs, OID_AUTO, delay_scale,
    CTLTYPE_U64 | CTLFLAG_MPSAFE | CTLFLAG_RW, 0, sizeof(uint64_t),
    sysctl_zfs_delay_scale, "QU",
    "Controls how quickly the delay approaches infinity");


extern int zfs_vdev_async_write_active_min_dirty_percent;
extern int zfs_vdev_async_write_active_max_dirty_percent;

static int
sysctl_zfs_dirty_data_max_percent(SYSCTL_HANDLER_ARGS)
{
	int val, err;

	val = zfs_dirty_data_max_percent;
	err = sysctl_handle_int(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

	if (val < 0 || val > 100)
		return (EINVAL);

	zfs_dirty_data_max_percent = val;

	return (0);
}

static int
sysctl_zfs_delay_min_dirty_percent(SYSCTL_HANDLER_ARGS)
{
	int val, err;

	val = zfs_delay_min_dirty_percent;
	err = sysctl_handle_int(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

	if (val < zfs_vdev_async_write_active_max_dirty_percent)
		return (EINVAL);

	zfs_delay_min_dirty_percent = val;

	return (0);
}

static int
sysctl_zfs_delay_scale(SYSCTL_HANDLER_ARGS)
{
	uint64_t val;
	int err;

	val = zfs_delay_scale;
	err = sysctl_handle_64(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

	if (val > UINT64_MAX / zfs_dirty_data_max)
		return (EINVAL);

	zfs_delay_scale = val;

	return (0);
}

/* dnode.c */
extern int zfs_default_bs;
SYSCTL_INT(_vfs_zfs, OID_AUTO, default_bs, CTLFLAG_RWTUN,
    &zfs_default_bs, 0, "Default dnode block shift");

extern int zfs_default_ibs;
SYSCTL_INT(_vfs_zfs, OID_AUTO, default_ibs, CTLFLAG_RWTUN,
    &zfs_default_ibs, 0, "Default dnode indirect block shift");


/* dsl_scan.c */
extern unsigned int zfs_resilver_delay;
SYSCTL_UINT(_vfs_zfs, OID_AUTO, resilver_delay, CTLFLAG_RWTUN,
    &zfs_resilver_delay, 0, "Number of ticks to delay resilver");

extern unsigned int zfs_scrub_delay;
SYSCTL_UINT(_vfs_zfs, OID_AUTO, scrub_delay, CTLFLAG_RWTUN,
    &zfs_scrub_delay, 0, "Number of ticks to delay scrub");

extern unsigned int zfs_scan_idle;
SYSCTL_UINT(_vfs_zfs, OID_AUTO, scan_idle, CTLFLAG_RWTUN,
    &zfs_scan_idle, 0, "Idle scan window in clock ticks");

extern unsigned int zfs_scrub_min_time_ms; /* min millisecs to scrub per txg */
SYSCTL_UINT(_vfs_zfs, OID_AUTO, scan_min_time_ms, CTLFLAG_RWTUN,
    &zfs_scrub_min_time_ms, 0, "Min millisecs to scrub per txg");

extern unsigned int zfs_free_min_time_ms; /* min millisecs to free per txg */
SYSCTL_UINT(_vfs_zfs, OID_AUTO, free_min_time_ms, CTLFLAG_RWTUN,
    &zfs_free_min_time_ms, 0, "Min millisecs to free per txg");

extern unsigned int zfs_resilver_min_time_ms; /* min millisecs to resilver per txg */
SYSCTL_UINT(_vfs_zfs, OID_AUTO, resilver_min_time_ms, CTLFLAG_RWTUN,
    &zfs_resilver_min_time_ms, 0, "Min millisecs to resilver per txg");

extern boolean_t zfs_no_scrub_io; /* set to disable scrub i/o */
SYSCTL_INT(_vfs_zfs, OID_AUTO, no_scrub_io, CTLFLAG_RWTUN,
    &zfs_no_scrub_io, 0, "Disable scrub I/O");

extern boolean_t zfs_no_scrub_prefetch; /* set to disable scrub prefetch */
SYSCTL_INT(_vfs_zfs, OID_AUTO, no_scrub_prefetch, CTLFLAG_RWTUN,
    &zfs_no_scrub_prefetch, 0, "Disable scrub prefetching");

extern int zfs_scan_legacy;
SYSCTL_UINT(_vfs_zfs, OID_AUTO, zfs_scan_legacy, CTLFLAG_RWTUN,
    &zfs_scan_legacy, 0, "Scrub using legacy non-sequential method");

extern int zfs_scan_checkpoint_intval; /* in seconds */
SYSCTL_UINT(_vfs_zfs, OID_AUTO, zfs_scan_checkpoint_interval, CTLFLAG_RWTUN,
    &zfs_scan_checkpoint_intval, 0, "Scan progress on-disk checkpointing interval");

/* max number of blocks to free in a single TXG */
extern uint64_t zfs_async_block_max_blocks;
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, free_max_blocks, CTLFLAG_RWTUN,
    &zfs_async_block_max_blocks, 0, "Maximum number of blocks to free in one TXG");

/* metaslab.c */

SYSCTL_NODE(_vfs_zfs, OID_AUTO, metaslab, CTLFLAG_RW, 0, "ZFS metaslab");

extern uint64_t metaslab_force_ganging;	/* force gang blocks */
SYSCTL_QUAD(_vfs_zfs_metaslab, OID_AUTO, force_ganging, CTLFLAG_RWTUN,
    &metaslab_force_ganging, 0,
    "Force gang block allocation for blocks larger than or equal to this value");

/*
 * Since we can touch multiple metaslabs (and their respective space maps)
 * with each transaction group, we benefit from having a smaller space map
 * block size since it allows us to issue more I/O operations scattered
 * around the disk.
 */
extern int zfs_metaslab_sm_blksz;
SYSCTL_INT(_vfs_zfs, OID_AUTO, metaslab_sm_blksz, CTLFLAG_RDTUN,
    &zfs_metaslab_sm_blksz, 0,
    "Block size for metaslab DTL space map.  Power of 2 and greater than 4096.");

/*
 * The in-core space map representation is more compact than its on-disk form.
 * The zfs_condense_pct determines how much more compact the in-core
 * space map representation must be before we compact it on-disk.
 * Values should be greater than or equal to 100.
 */
extern int zfs_condense_pct;
SYSCTL_INT(_vfs_zfs, OID_AUTO, condense_pct, CTLFLAG_RWTUN,
    &zfs_condense_pct, 0,
    "Condense on-disk spacemap when it is more than this many percents"
    " of in-memory counterpart");

extern uint64_t zfs_condense_indirect_commit_entry_delay_ms;
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, condense_indirect_commit_entry_delay_ms,
    CTLFLAG_RWTUN, &zfs_condense_indirect_commit_entry_delay_ms, 0,
    "Used by tests to ensure certain actions happen in the middle of a"
    " condense. A maximum value of 1 should be sufficient.");

extern uint64_t zfs_condense_min_mapping_bytes;
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, condense_min_mapping_bytes,
    CTLFLAG_RWTUN, &zfs_condense_min_mapping_bytes, 0,
    "Don't bother condensing if the mapping uses less than this amount of memory");

extern int zfs_remove_max_segment;
SYSCTL_INT(_vfs_zfs, OID_AUTO, remove_max_segment, CTLFLAG_RWTUN,
    &zfs_remove_max_segment, 0, "Largest contiguous segment ZFS will attempt to"
    " allocate when removing a device");

extern int zfs_removal_suspend_progress;
SYSCTL_INT(_vfs_zfs, OID_AUTO, removal_suspend_progress, CTLFLAG_RWTUN,
    &zfs_removal_suspend_progress, 0, "Ensures certain actions can happen while"
    " in the middle of a removal");

/*
 * The zfs_mg_noalloc_threshold defines which metaslab groups should
 * be eligible for allocation. The value is defined as a percentage of
 * free space. Metaslab groups that have more free space than
 * zfs_mg_noalloc_threshold are always eligible for allocations. Once
 * a metaslab group's free space is less than or equal to the
 * zfs_mg_noalloc_threshold the allocator will avoid allocating to that
 * group unless all groups in the pool have reached zfs_mg_noalloc_threshold.
 * Once all groups in the pool reach zfs_mg_noalloc_threshold then all
 * groups are allowed to accept allocations. Gang blocks are always
 * eligible to allocate on any metaslab group. The default value of 0 means
 * no metaslab group will be excluded based on this criterion.
 */
extern int zfs_mg_noalloc_threshold;
SYSCTL_INT(_vfs_zfs, OID_AUTO, mg_noalloc_threshold, CTLFLAG_RWTUN,
    &zfs_mg_noalloc_threshold, 0,
    "Percentage of metaslab group size that should be free"
    " to make it eligible for allocation");

/*
 * Metaslab groups are considered eligible for allocations if their
 * fragmenation metric (measured as a percentage) is less than or equal to
 * zfs_mg_fragmentation_threshold. If a metaslab group exceeds this threshold
 * then it will be skipped unless all metaslab groups within the metaslab
 * class have also crossed this threshold.
 */
extern int zfs_mg_fragmentation_threshold;
SYSCTL_INT(_vfs_zfs, OID_AUTO, mg_fragmentation_threshold, CTLFLAG_RWTUN,
    &zfs_mg_fragmentation_threshold, 0,
    "Percentage of metaslab group size that should be considered "
    "eligible for allocations unless all metaslab groups within the metaslab class "
    "have also crossed this threshold");

/*
 * Allow metaslabs to keep their active state as long as their fragmentation
 * percentage is less than or equal to zfs_metaslab_fragmentation_threshold. An
 * active metaslab that exceeds this threshold will no longer keep its active
 * status allowing better metaslabs to be selected.
 */
extern int zfs_metaslab_fragmentation_threshold;
SYSCTL_INT(_vfs_zfs_metaslab, OID_AUTO, fragmentation_threshold, CTLFLAG_RWTUN,
    &zfs_metaslab_fragmentation_threshold, 0,
    "Maximum percentage of metaslab fragmentation level to keep their active state");

/*
 * When set will load all metaslabs when pool is first opened.
 */
extern int metaslab_debug_load;
SYSCTL_INT(_vfs_zfs_metaslab, OID_AUTO, debug_load, CTLFLAG_RWTUN,
    &metaslab_debug_load, 0,
    "Load all metaslabs when pool is first opened");

/*
 * When set will prevent metaslabs from being unloaded.
 */
extern int metaslab_debug_unload;
SYSCTL_INT(_vfs_zfs_metaslab, OID_AUTO, debug_unload, CTLFLAG_RWTUN,
    &metaslab_debug_unload, 0,
    "Prevent metaslabs from being unloaded");

/*
 * Minimum size which forces the dynamic allocator to change
 * it's allocation strategy.  Once the space map cannot satisfy
 * an allocation of this size then it switches to using more
 * aggressive strategy (i.e search by size rather than offset).
 */
extern uint64_t metaslab_df_alloc_threshold;
SYSCTL_QUAD(_vfs_zfs_metaslab, OID_AUTO, df_alloc_threshold, CTLFLAG_RWTUN,
    &metaslab_df_alloc_threshold, 0,
    "Minimum size which forces the dynamic allocator to change it's allocation strategy");

/*
 * The minimum free space, in percent, which must be available
 * in a space map to continue allocations in a first-fit fashion.
 * Once the space map's free space drops below this level we dynamically
 * switch to using best-fit allocations.
 */
extern int metaslab_df_free_pct;
SYSCTL_INT(_vfs_zfs_metaslab, OID_AUTO, df_free_pct, CTLFLAG_RWTUN,
    &metaslab_df_free_pct, 0,
    "The minimum free space, in percent, which must be available in a "
    "space map to continue allocations in a first-fit fashion");

/*
 * Percentage of all cpus that can be used by the metaslab taskq.
 */
extern int metaslab_load_pct;
SYSCTL_INT(_vfs_zfs_metaslab, OID_AUTO, load_pct, CTLFLAG_RWTUN,
    &metaslab_load_pct, 0,
    "Percentage of cpus that can be used by the metaslab taskq");

/*
 * Determines how many txgs a metaslab may remain loaded without having any
 * allocations from it. As long as a metaslab continues to be used we will
 * keep it loaded.
 */
extern int metaslab_unload_delay;
SYSCTL_INT(_vfs_zfs_metaslab, OID_AUTO, unload_delay, CTLFLAG_RWTUN,
    &metaslab_unload_delay, 0,
    "Number of TXGs that an unused metaslab can be kept in memory");

/*
 * Max number of metaslabs per group to preload.
 */
extern int metaslab_preload_limit;
SYSCTL_INT(_vfs_zfs_metaslab, OID_AUTO, preload_limit, CTLFLAG_RWTUN,
    &metaslab_preload_limit, 0,
    "Max number of metaslabs per group to preload");

/*
 * Enable/disable preloading of metaslab.
 */
extern boolean_t metaslab_preload_enabled;
SYSCTL_INT(_vfs_zfs_metaslab, OID_AUTO, preload_enabled, CTLFLAG_RWTUN,
    &metaslab_preload_enabled, 0,
    "Max number of metaslabs per group to preload");

/*
 * Enable/disable fragmentation weighting on metaslabs.
 */
extern boolean_t metaslab_fragmentation_factor_enabled;
SYSCTL_INT(_vfs_zfs_metaslab, OID_AUTO, fragmentation_factor_enabled, CTLFLAG_RWTUN,
    &metaslab_fragmentation_factor_enabled, 0,
    "Enable fragmentation weighting on metaslabs");

/*
 * Enable/disable lba weighting (i.e. outer tracks are given preference).
 */
extern boolean_t metaslab_lba_weighting_enabled;
SYSCTL_INT(_vfs_zfs_metaslab, OID_AUTO, lba_weighting_enabled, CTLFLAG_RWTUN,
    &metaslab_lba_weighting_enabled, 0,
    "Enable LBA weighting (i.e. outer tracks are given preference)");

/*
 * Enable/disable metaslab group biasing.
 */
extern boolean_t metaslab_bias_enabled;
SYSCTL_INT(_vfs_zfs_metaslab, OID_AUTO, bias_enabled, CTLFLAG_RWTUN,
    &metaslab_bias_enabled, 0,
    "Enable metaslab group biasing");


/* refcount.c */
extern int reference_tracking_enable;
SYSCTL_INT(_vfs_zfs, OID_AUTO, reference_tracking_enable, CTLFLAG_RDTUN,
    &reference_tracking_enable, 0,
    "Track reference holders to refcount_t objects, used mostly by ZFS");

/* spa.c */
extern int zfs_ccw_retry_interval;
SYSCTL_INT(_vfs_zfs, OID_AUTO, ccw_retry_interval, CTLFLAG_RWTUN,
    &zfs_ccw_retry_interval, 0,
    "Configuration cache file write, retry after failure, interval (seconds)");

extern int spa_load_print_vdev_tree;
SYSCTL_INT(_vfs_zfs, OID_AUTO, spa_load_print_vdev_tree, CTLFLAG_RWTUN,
    &spa_load_print_vdev_tree, 0,
    "print out vdev tree during pool import");

extern uint64_t zfs_max_missing_tvds;
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, max_missing_tvds, CTLFLAG_RWTUN,
    &zfs_max_missing_tvds, 0,
    "allow importing pools with missing top-level vdevs");

extern uint64_t zfs_max_missing_tvds_cachefile;
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, max_missing_tvds_cachefile, CTLFLAG_RWTUN,
    &zfs_max_missing_tvds_cachefile, 0,
    "allow importing pools with missing top-level vdevs in cache file");

extern uint64_t zfs_max_missing_tvds_scan;
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, max_missing_tvds_scan, CTLFLAG_RWTUN,
    &zfs_max_missing_tvds_scan, 0,
    "allow importing pools with missing top-level vdevs during scan");


/* spa_misc.c */
extern boolean_t zfs_recover;
SYSCTL_INT(_vfs_zfs, OID_AUTO, recover, CTLFLAG_RWTUN, &zfs_recover, 0,
    "Try to recover from otherwise-fatal errors.");

extern int zfs_flags;
static int
sysctl_vfs_zfs_debug_flags(SYSCTL_HANDLER_ARGS)
{
	int err, val;

	val = zfs_flags;
	err = sysctl_handle_int(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

	/*
	 * ZFS_DEBUG_MODIFY must be enabled prior to boot so all
	 * arc buffers in the system have the necessary additional
	 * checksum data.  However, it is safe to disable at any
	 * time.
	 */
	if (!(zfs_flags & ZFS_DEBUG_MODIFY))
		val &= ~ZFS_DEBUG_MODIFY;
	zfs_flags = val;

	return (0);
}

SYSCTL_PROC(_vfs_zfs, OID_AUTO, debugflags,
    CTLTYPE_UINT | CTLFLAG_MPSAFE | CTLFLAG_RWTUN, 0, sizeof(int),
    sysctl_vfs_zfs_debug_flags, "IU", "Debug flags for ZFS testing.");

extern uint64_t zfs_deadman_synctime_ms;
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, deadman_synctime_ms, CTLFLAG_RWTUN,
    &zfs_deadman_synctime_ms, 0,
    "Stalled ZFS I/O expiration time in milliseconds");

extern uint64_t zfs_deadman_checktime_ms;
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, deadman_checktime_ms, CTLFLAG_RWTUN,
    &zfs_deadman_checktime_ms, 0,
    "Period of checks for stalled ZFS I/O in milliseconds");

extern uint64_t zfs_deadman_ziotime_ms;
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, deadman_ziotime_ms, CTLFLAG_RWTUN,
    &zfs_deadman_ziotime_ms, 0,
    "Time until an individual I/O is considered to be \"hung\" in milliseconds");

static int 
zfs_deadman_failmode(SYSCTL_HANDLER_ARGS)
{
	char buf[16];
	return sysctl_handle_string(oidp, buf, sizeof(buf), req);
}

SYSCTL_PROC(_vfs_zfs, OID_AUTO, deadman_failmode, CTLTYPE_STRING|CTLFLAG_RWTUN,
    0, 0, &zfs_deadman_failmode, "A",
    "Behavior when a \"hung\" I/O value is detected as wait, continue, or panic");

extern int zfs_deadman_enabled;
SYSCTL_INT(_vfs_zfs, OID_AUTO, deadman_enabled, CTLFLAG_RDTUN,
    &zfs_deadman_enabled, 0, "Kernel panic on stalled ZFS I/O");

extern int spa_asize_inflation;
SYSCTL_INT(_vfs_zfs, OID_AUTO, spa_asize_inflation, CTLFLAG_RWTUN,
    &spa_asize_inflation, 0, "Worst case inflation factor for single sector writes");

extern uint64_t zfs_spa_discard_memory_limit;
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, spa_discard_memory_limit, CTLFLAG_RWTUN,
    &zfs_spa_discard_memory_limit, 0, "Limit for memory used in prefetching the"
    " checkpoint space map done on each vdev while discarding the checkpoint");

/* spacemap.c */
extern int space_map_ibs;
SYSCTL_INT(_vfs_zfs, OID_AUTO, space_map_ibs, CTLFLAG_RWTUN,
    &space_map_ibs, 0, "Space map indirect block shift");


/* txg.c */
extern int zfs_txg_timeout;	/* max seconds worth of delta per txg */
SYSCTL_NODE(_vfs_zfs, OID_AUTO, txg, CTLFLAG_RW, 0, "ZFS TXG");
SYSCTL_INT(_vfs_zfs_txg, OID_AUTO, timeout, CTLFLAG_RWTUN, &zfs_txg_timeout, 0,
    "Maximum seconds worth of delta per txg");

/* vdev.c */
SYSCTL_NODE(_vfs_zfs, OID_AUTO, vdev, CTLFLAG_RW, 0, "ZFS VDEV");
extern uint64_t zfs_max_auto_ashift;
extern uint64_t zfs_min_auto_ashift;

static int
sysctl_vfs_zfs_max_auto_ashift(SYSCTL_HANDLER_ARGS)
{
	uint64_t val;
	int err;

	val = zfs_max_auto_ashift;
	err = sysctl_handle_64(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

	if (val > ASHIFT_MAX || val < zfs_min_auto_ashift)
		return (EINVAL);

	zfs_max_auto_ashift = val;

	return (0);
}
SYSCTL_PROC(_vfs_zfs, OID_AUTO, max_auto_ashift,
    CTLTYPE_U64 | CTLFLAG_MPSAFE | CTLFLAG_RW, 0, sizeof(uint64_t),
    sysctl_vfs_zfs_max_auto_ashift, "QU",
    "Max ashift used when optimising for logical -> physical sectors size on "
    "new top-level vdevs.");
static int
sysctl_vfs_zfs_min_auto_ashift(SYSCTL_HANDLER_ARGS)
{
	uint64_t val;
	int err;

	val = zfs_min_auto_ashift;
	err = sysctl_handle_64(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

	if (val < ASHIFT_MIN || val > zfs_max_auto_ashift)
		return (EINVAL);

	zfs_min_auto_ashift = val;

	return (0);
}
SYSCTL_PROC(_vfs_zfs, OID_AUTO, min_auto_ashift,
    CTLTYPE_U64 | CTLFLAG_MPSAFE | CTLFLAG_RW, 0, sizeof(uint64_t),
    sysctl_vfs_zfs_min_auto_ashift, "QU",
    "Min ashift used when creating new top-level vdevs.");

/* target number of metaslabs per top-level vdev */
extern int vdev_max_ms_count;
SYSCTL_INT(_vfs_zfs_vdev, OID_AUTO, max_ms_count, CTLFLAG_RDTUN,
    &vdev_max_ms_count, 0,
    "Maximum number of metaslabs per top-level vdev");

/* minimum number of metaslabs per top-level vdev */
extern int vdev_min_ms_count;
SYSCTL_INT(_vfs_zfs_vdev, OID_AUTO, min_ms_count, CTLFLAG_RDTUN,
    &vdev_min_ms_count, 0,
    "Minimum number of metaslabs per top-level vdev");

/* lower limit for metaslab size (512M) */
extern int vdev_default_ms_shift;
SYSCTL_INT(_vfs_zfs_vdev, OID_AUTO, default_ms_shift, CTLFLAG_RDTUN,
    &vdev_default_ms_shift, 0,
    "Shift between vdev size and number of metaslabs");

/*
 * Since the DTL space map of a vdev is not expected to have a lot of
 * entries, we default its block size to 4K.
 */
extern int vdev_dtl_sm_blksz;
SYSCTL_INT(_vfs_zfs, OID_AUTO, dtl_sm_blksz, CTLFLAG_RDTUN,
    &vdev_dtl_sm_blksz, 0,
    "Block size for DTL space map.  Power of 2 and greater than 4096.");

/*
 * vdev-wide space maps that have lots of entries written to them at
 * the end of each transaction can benefit from a higher I/O bandwidth
 * (e.g. vdev_obsolete_sm), thus we default their block size to 128K.
 */
extern int vdev_standard_sm_blksz;
SYSCTL_INT(_vfs_zfs, OID_AUTO, standard_sm_blksz, CTLFLAG_RDTUN,
    &vdev_standard_sm_blksz, 0,
    "Block size for standard space map.  Power of 2 and greater than 4096.");


/* vdev_cache.c */
SYSCTL_NODE(_vfs_zfs_vdev, OID_AUTO, cache, CTLFLAG_RW, 0, "ZFS VDEV Cache");

extern int zfs_vdev_cache_max;			/* 16KB */
SYSCTL_INT(_vfs_zfs_vdev_cache, OID_AUTO, max, CTLFLAG_RDTUN,
    &zfs_vdev_cache_max, 0, "Maximum I/O request size that increase read size");

extern int zfs_vdev_cache_size;
SYSCTL_INT(_vfs_zfs_vdev_cache, OID_AUTO, size, CTLFLAG_RDTUN,
    &zfs_vdev_cache_size, 0, "Size of VDEV cache");

extern int zfs_vdev_cache_bshift;
SYSCTL_INT(_vfs_zfs_vdev_cache, OID_AUTO, bshift, CTLFLAG_RDTUN,
    &zfs_vdev_cache_bshift, 0, "Turn too small requests into 1 << this value");

/* vdev_mirror.c */
/*
 * The load configuration settings below are tuned by default for
 * the case where all devices are of the same rotational type.
 *
 * If there is a mixture of rotating and non-rotating media, setting
 * non_rotating_seek_inc to 0 may well provide better results as it
 * will direct more reads to the non-rotating vdevs which are more
 * likely to have a higher performance.
 */


static SYSCTL_NODE(_vfs_zfs_vdev, OID_AUTO, mirror, CTLFLAG_RD, 0,
    "ZFS VDEV Mirror");
/* Rotating media load calculation configuration. */
extern int zfs_vdev_mirror_rotating_inc;
SYSCTL_INT(_vfs_zfs_vdev_mirror, OID_AUTO, rotating_inc, CTLFLAG_RWTUN,
	&zfs_vdev_mirror_rotating_inc, 0,
	"Rotating media load increment for non-seeking I/O's");

extern int zfs_vdev_mirror_rotating_seek_inc;
SYSCTL_INT(_vfs_zfs_vdev_mirror, OID_AUTO, rotating_seek_inc, CTLFLAG_RWTUN,
	&zfs_vdev_mirror_rotating_seek_inc, 0,
	"Rotating media load increment for seeking I/O's");

extern int zfs_vdev_mirror_rotating_seek_offset;
SYSCTL_INT(_vfs_zfs_vdev_mirror, OID_AUTO, rotating_seek_offset, CTLFLAG_RWTUN,
	&zfs_vdev_mirror_rotating_seek_offset, 0,
    "Offset in bytes from the last I/O which "
    "triggers a reduced rotating media seek increment");

/* Non-rotating media load calculation configuration. */
extern int zfs_vdev_mirror_non_rotating_inc;
SYSCTL_INT(_vfs_zfs_vdev_mirror, OID_AUTO, non_rotating_inc, CTLFLAG_RWTUN,
    &zfs_vdev_mirror_non_rotating_inc, 0,
    "Non-rotating media load increment for non-seeking I/O's");

extern int zfs_vdev_mirror_non_rotating_seek_inc;
SYSCTL_INT(_vfs_zfs_vdev_mirror, OID_AUTO, non_rotating_seek_inc, CTLFLAG_RWTUN,
    &zfs_vdev_mirror_non_rotating_seek_inc, 0,
    "Non-rotating media load increment for seeking I/O's");


/* vdev_queue.c */
static int sysctl_zfs_async_write_active_min_dirty_percent(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_vfs_zfs_vdev, OID_AUTO, async_write_active_min_dirty_percent,
    CTLTYPE_UINT | CTLFLAG_MPSAFE | CTLFLAG_RWTUN, 0, sizeof(int),
    sysctl_zfs_async_write_active_min_dirty_percent, "I",
    "Percentage of async write dirty data below which "
    "async_write_min_active is used.");

static int sysctl_zfs_async_write_active_max_dirty_percent(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_vfs_zfs_vdev, OID_AUTO, async_write_active_max_dirty_percent,
    CTLTYPE_UINT | CTLFLAG_MPSAFE | CTLFLAG_RWTUN, 0, sizeof(int),
    sysctl_zfs_async_write_active_max_dirty_percent, "I",
    "Percentage of async write dirty data above which "
    "async_write_max_active is used.");

extern uint32_t zfs_vdev_max_active;
SYSCTL_UINT(_vfs_zfs_vdev, OID_AUTO, max_active, CTLFLAG_RWTUN,
    &zfs_vdev_max_active, 0,
    "The maximum number of I/Os of all types active for each device.");

#define ZFS_VDEV_QUEUE_KNOB_MIN(name)					\
extern uint32_t zfs_vdev_ ## name ## _min_active;				\
SYSCTL_UINT(_vfs_zfs_vdev, OID_AUTO, name ## _min_active, CTLFLAG_RWTUN,\
    &zfs_vdev_ ## name ## _min_active, 0,				\
    "Initial number of I/O requests of type " #name			\
    " active for each device");

#define ZFS_VDEV_QUEUE_KNOB_MAX(name)					\
extern uint32_t zfs_vdev_ ## name ## _max_active;				\
SYSCTL_UINT(_vfs_zfs_vdev, OID_AUTO, name ## _max_active, CTLFLAG_RWTUN, \
    &zfs_vdev_ ## name ## _max_active, 0,				\
    "Maximum number of I/O requests of type " #name			\
    " active for each device");

ZFS_VDEV_QUEUE_KNOB_MIN(sync_read);
ZFS_VDEV_QUEUE_KNOB_MAX(sync_read);
ZFS_VDEV_QUEUE_KNOB_MIN(sync_write);
ZFS_VDEV_QUEUE_KNOB_MAX(sync_write);
ZFS_VDEV_QUEUE_KNOB_MIN(async_read);
ZFS_VDEV_QUEUE_KNOB_MAX(async_read);
ZFS_VDEV_QUEUE_KNOB_MIN(async_write);
ZFS_VDEV_QUEUE_KNOB_MAX(async_write);
ZFS_VDEV_QUEUE_KNOB_MIN(scrub);
ZFS_VDEV_QUEUE_KNOB_MAX(scrub);
#ifdef notyet
ZFS_VDEV_QUEUE_KNOB_MIN(trim);
ZFS_VDEV_QUEUE_KNOB_MAX(trim);
#endif
ZFS_VDEV_QUEUE_KNOB_MIN(removal);
ZFS_VDEV_QUEUE_KNOB_MAX(removal);
#ifdef notyet
ZFS_VDEV_QUEUE_KNOB_MIN(initializing);
ZFS_VDEV_QUEUE_KNOB_MAX(initializing);
#endif

#undef ZFS_VDEV_QUEUE_KNOB

extern int zfs_vdev_aggregation_limit;
SYSCTL_INT(_vfs_zfs_vdev, OID_AUTO, aggregation_limit, CTLFLAG_RWTUN,
    &zfs_vdev_aggregation_limit, 0,
    "I/O requests are aggregated up to this size");

extern int zfs_vdev_read_gap_limit;
SYSCTL_INT(_vfs_zfs_vdev, OID_AUTO, read_gap_limit, CTLFLAG_RWTUN,
    &zfs_vdev_read_gap_limit, 0,
    "Acceptable gap between two reads being aggregated");

extern int zfs_vdev_write_gap_limit;
SYSCTL_INT(_vfs_zfs_vdev, OID_AUTO, write_gap_limit, CTLFLAG_RWTUN,
    &zfs_vdev_write_gap_limit, 0,
    "Acceptable gap between two writes being aggregated");

extern int zfs_vdev_queue_depth_pct;
SYSCTL_INT(_vfs_zfs_vdev, OID_AUTO, queue_depth_pct, CTLFLAG_RWTUN,
    &zfs_vdev_queue_depth_pct, 0,
    "Queue depth percentage for each top-level");

extern int zfs_vdev_def_queue_depth;
SYSCTL_INT(_vfs_zfs_vdev, OID_AUTO, def_queue_depth, CTLFLAG_RWTUN,
    &zfs_vdev_def_queue_depth, 0,
    "Default queue depth for each allocator");

/*extern uint64_t zfs_multihost_history;
SYSCTL_UQUAD(_vfs_zfs, OID_AUTO, multihost_history, CTLFLAG_RWTUN,
    &zfs_multihost_history, 0,
    "Historical staticists for the last N multihost updates");*/

static int
sysctl_zfs_async_write_active_min_dirty_percent(SYSCTL_HANDLER_ARGS)
{
	int val, err;

	val = zfs_vdev_async_write_active_min_dirty_percent;
	err = sysctl_handle_int(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);
	
	if (val < 0 || val > 100 ||
	    val >= zfs_vdev_async_write_active_max_dirty_percent)
		return (EINVAL);

	zfs_vdev_async_write_active_min_dirty_percent = val;

	return (0);
}

static int
sysctl_zfs_async_write_active_max_dirty_percent(SYSCTL_HANDLER_ARGS)
{
	int val, err;

	val = zfs_vdev_async_write_active_max_dirty_percent;
	err = sysctl_handle_int(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

	if (val < 0 || val > 100 ||
	    val <= zfs_vdev_async_write_active_min_dirty_percent)
		return (EINVAL);

	zfs_vdev_async_write_active_max_dirty_percent = val;

	return (0);
}

/* zil.c */
extern int zil_replay_disable;
SYSCTL_INT(_vfs_zfs, OID_AUTO, zil_replay_disable, CTLFLAG_RWTUN,
    &zil_replay_disable, 0, "Disable intent logging replay");

/*
 * Tunable parameter for debugging or performance analysis.  Setting
 * zfs_nocacheflush will cause corruption on power loss if a volatile
 * out-of-order write cache is enabled.
 */
extern boolean_t zfs_nocacheflush;
SYSCTL_INT(_vfs_zfs, OID_AUTO, cache_flush_disable, CTLFLAG_RDTUN,
    &zfs_nocacheflush, 0, "Disable cache flush");
#ifdef notyet
extern boolean_t zfs_trim_enabled;
SYSCTL_DECL(_vfs_zfs_trim);
SYSCTL_INT(_vfs_zfs_trim, OID_AUTO, enabled, CTLFLAG_RDTUN, &zfs_trim_enabled, 0,
    "Enable ZFS TRIM");
#endif
/*
 * Limit SLOG write size per commit executed with synchronous priority.
 * Any writes above that will be executed with lower (asynchronous) priority
 * to limit potential SLOG device abuse by single active ZIL writer.
 */
extern uint64_t zil_slog_bulk;
SYSCTL_QUAD(_vfs_zfs, OID_AUTO, zil_slog_bulk, CTLFLAG_RWTUN,
    &zil_slog_bulk, 0, "Maximal SLOG commit size with sync priority");

/* XXX make proc to validate */
extern int zfs_commit_timeout_pct;
SYSCTL_INT(_vfs_zfs, OID_AUTO, commit_timeout_pct, CTLFLAG_RWTUN,
    &zfs_commit_timeout_pct, 0, "ZIL block open timeout percentage");

#ifdef notyet
SYSCTL_INT(_vfs_zfs_vdev, OID_AUTO, trim_on_init, CTLFLAG_RW,
    &vdev_trim_on_init, 0, "Enable/disable full vdev trim on initialisation");
#endif


/* zio.c */
SYSCTL_NODE(_vfs_zfs, OID_AUTO, zio, CTLFLAG_RW, 0, "ZFS ZIO");
#if defined(__LP64__)
int zio_use_uma = 1;
#else
int zio_use_uma = 0;
#endif

SYSCTL_INT(_vfs_zfs_zio, OID_AUTO, use_uma, CTLFLAG_RDTUN, &zio_use_uma, 0,
    "Use uma(9) for ZIO allocations");
extern  int zio_exclude_metadata;
SYSCTL_INT(_vfs_zfs_zio, OID_AUTO, exclude_metadata, CTLFLAG_RDTUN, &zio_exclude_metadata, 0,
    "Exclude metadata buffers from dumps as well");
extern boolean_t zio_dva_throttle_enabled;
SYSCTL_INT(_vfs_zfs_zio, OID_AUTO, dva_throttle_enabled, CTLFLAG_RWTUN,
    &zio_dva_throttle_enabled, 0, "Enable allocation throttling");
extern boolean_t zio_requeue_io_start_cut_in_line;
SYSCTL_INT(_vfs_zfs_zio, OID_AUTO, requeue_io_start_cut_in_line, CTLFLAG_RWTUN,
    &zio_requeue_io_start_cut_in_line, 0, "Prioritize requeued I/O");
extern int zfs_sync_pass_deferred_free; /* defer frees starting in this pass */
SYSCTL_INT(_vfs_zfs, OID_AUTO, sync_pass_deferred_free, CTLFLAG_RDTUN,
    &zfs_sync_pass_deferred_free, 0, "defer frees starting in this pass");
extern int zfs_sync_pass_dont_compress; /* don't compress starting in this pass */
SYSCTL_INT(_vfs_zfs, OID_AUTO, sync_pass_dont_compress, CTLFLAG_RDTUN,
    &zfs_sync_pass_dont_compress, 0, "don't compress starting in this pass");
extern int zfs_sync_pass_rewrite; /* rewrite new bps starting in this pass */
SYSCTL_INT(_vfs_zfs, OID_AUTO, sync_pass_rewrite, CTLFLAG_RDTUN,
    &zfs_sync_pass_rewrite, 0, "rewrite new bps starting in this pass");
