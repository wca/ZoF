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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018 by Delphix. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/ddt.h>
#include <sys/zap.h>
#include <sys/dmu_tx.h>

int ddt_zap_leaf_blockshift = 12;
int ddt_zap_indirect_blockshift = 12;

static int
ddt_zap_create(objset_t *os, uint64_t *objectp, dmu_tx_t *tx, boolean_t prehash)
{
	zap_flags_t flags = ZAP_FLAG_HASH64 | ZAP_FLAG_UINT64_KEY;

	if (prehash)
		flags |= ZAP_FLAG_PRE_HASHED_KEY;

	*objectp = zap_create_flags(os, 0, flags, DMU_OT_DDT_ZAP,
	    ddt_zap_leaf_blockshift, ddt_zap_indirect_blockshift,
	    DMU_OT_NONE, 0, tx);

	return (*objectp == 0 ? ENOTSUP : 0);
}

static int
ddt_zap_destroy(objset_t *os, uint64_t object, dmu_tx_t *tx)
{
	return (zap_destroy(os, object, tx));
}

static int
ddt_zap_load(objset_t *os, uint64_t object, ddt_entry_t *dde, uchar_t *cbuf)
{
	int error;
	uint64_t one, csize;

	error = zap_length_uint64(os, object, (const uint64_t *)&dde->dde_key,
	    DDT_KEY_WORDS, &one, &csize);
	if (error)
		return (error);

	ASSERT(one == 1);
	ASSERT(csize <= (sizeof (dde->dde_phys) + 1));

	error = zap_lookup_uint64(os, object, (uint64_t *)&dde->dde_key,
	    DDT_KEY_WORDS, 1, csize, cbuf);
	if (error)
		return (error);

	ddt_decompress(cbuf, dde->dde_phys, csize, sizeof (dde->dde_phys));
	return (0);
}

static void
ddt_zap_key_fill(ddt_key_t *ddk, zap_attribute_t *za)
{

	ASSERT3U(za->za_integer_length, ==, sizeof (uint64_t));
	ASSERT3U(za->za_num_integers, ==, DDT_KEY_WORDS);
	memcpy(ddk, za, za->za_integer_length * za->za_num_integers);
}

static void
ddt_zap_loadall(ddt_t *ddt, objset_t *os, uint64_t object,
    enum ddt_type type, enum ddt_class class)
{
	zap_cursor_t zc;
	int error;
	ddt_entry_t dde_search;
	ddt_entry_t *dde;
	zap_attribute_t attr;
	uchar_t *cbuf;

	ASSERT(MUTEX_HELD(&ddt->ddt_lock));

	cbuf = kmem_alloc(sizeof (dde->dde_phys) + 1, KM_SLEEP);

	for (zap_cursor_init(&zc, os, object);
	    zap_cursor_retrieve(&zc, &attr) == 0;
	    zap_cursor_advance(&zc)) {
		memset(&dde_search, 0, sizeof (dde_search));
		ddt_zap_key_fill(&dde_search.dde_key, &attr);
		dde = ddt_entry_find(ddt, &dde_search, B_TRUE);
		while (dde->dde_loading)
			cv_wait(&dde->dde_cv, &ddt->ddt_lock);
		if (dde->dde_loaded == B_TRUE)
			continue;

		dde->dde_loading = B_TRUE;

		ddt_exit(ddt);
		error = ddt_zap_load(os, object, dde, cbuf);
		ddt_enter(ddt);

		ddt_entry_loaded(ddt, error, dde, type, class);
	}

	zap_cursor_fini(&zc);
	kmem_free(cbuf, sizeof (dde->dde_phys) + 1);
}

static int
ddt_zap_lookup(objset_t *os, uint64_t object, ddt_entry_t *dde)
{
	uchar_t *cbuf;
	int error;

	cbuf = kmem_alloc(sizeof (dde->dde_phys) + 1, KM_SLEEP);
	error = ddt_zap_load(os, object, dde, cbuf);
	kmem_free(cbuf, sizeof (dde->dde_phys) + 1);

	return (error);
}

static void
ddt_zap_prefetch(objset_t *os, uint64_t object, ddt_entry_t *dde)
{
	(void) zap_prefetch_uint64(os, object, (uint64_t *)&dde->dde_key,
	    DDT_KEY_WORDS);
}

static int
ddt_zap_update(objset_t *os, uint64_t object, ddt_entry_t *dde, dmu_tx_t *tx)
{
	uchar_t cbuf[sizeof (dde->dde_phys) + 1];
	uint64_t csize;

	csize = ddt_compress(dde->dde_phys, cbuf,
	    sizeof (dde->dde_phys), sizeof (cbuf));

	return (zap_update_uint64(os, object, (uint64_t *)&dde->dde_key,
	    DDT_KEY_WORDS, 1, csize, cbuf, tx));
}

static int
ddt_zap_remove(objset_t *os, uint64_t object, ddt_entry_t *dde, dmu_tx_t *tx)
{
	return (zap_remove_uint64(os, object, (uint64_t *)&dde->dde_key,
	    DDT_KEY_WORDS, tx));
}

static int
ddt_zap_walk(objset_t *os, uint64_t object, ddt_entry_t *dde, uint64_t *walk)
{
	zap_cursor_t zc;
	zap_attribute_t za;
	int error;

	if (*walk == 0) {
		/*
		 * We don't want to prefetch the entire ZAP object, because
		 * it can be enormous.  Also the primary use of DDT iteration
		 * is for scrubbing, in which case we will be issuing many
		 * scrub I/Os for each ZAP block that we read in, so
		 * reading the ZAP is unlikely to be the bottleneck.
		 */
		zap_cursor_init_noprefetch(&zc, os, object);
	} else {
		zap_cursor_init_serialized(&zc, os, object, *walk);
	}
	if ((error = zap_cursor_retrieve(&zc, &za)) == 0) {
		uchar_t cbuf[sizeof (dde->dde_phys) + 1];
		uint64_t csize = za.za_num_integers;
		ASSERT(za.za_integer_length == 1);
		error = zap_lookup_uint64(os, object, (uint64_t *)za.za_name,
		    DDT_KEY_WORDS, 1, csize, cbuf);
		ASSERT(error == 0);
		if (error == 0) {
			ddt_decompress(cbuf, dde->dde_phys, csize,
			    sizeof (dde->dde_phys));
			dde->dde_key = *(ddt_key_t *)za.za_name;
		}
		zap_cursor_advance(&zc);
		*walk = zap_cursor_serialize(&zc);
	}
	zap_cursor_fini(&zc);
	return (error);
}

static int
ddt_zap_count(objset_t *os, uint64_t object, uint64_t *count)
{
	return (zap_count(os, object, count));
}

const ddt_ops_t ddt_zap_ops = {
	"zap",
	ddt_zap_create,
	ddt_zap_destroy,
	ddt_zap_loadall,
	ddt_zap_lookup,
	ddt_zap_prefetch,
	ddt_zap_update,
	ddt_zap_remove,
	ddt_zap_walk,
	ddt_zap_count,
};
