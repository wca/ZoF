/*-
 * Copyright (c) 2007 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _OPENSOLARIS_SYS_KSTAT_H_
#define	_OPENSOLARIS_SYS_KSTAT_H_
#include <sys/types.h>
#include <sys/time.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sysctl.h>

#define	KSTAT_TYPE_RAW		0	/* can be anything */
					/* ks_ndata >= 1 */
#define	KSTAT_TYPE_NAMED	1	/* name/value pair */
					/* ks_ndata >= 1 */
#define	KSTAT_TYPE_INTR		2	/* interrupt statistics */
					/* ks_ndata == 1 */
#define	KSTAT_TYPE_IO		3	/* I/O statistics */
					/* ks_ndata == 1 */
#define	KSTAT_TYPE_TIMER	4	/* event timer */
					/* ks_ndata >= 1 */

#define	KSTAT_NUM_TYPES		5

#define	KSTAT_DATA_CHAR		0
#define	KSTAT_DATA_INT32	1
#define	KSTAT_DATA_UINT32	2
#define	KSTAT_DATA_INT64	3
#define	KSTAT_DATA_UINT64	4
#define	KSTAT_DATA_LONG		5
#define	KSTAT_DATA_ULONG	6
#define	KSTAT_DATA_STRING	7
#define	KSTAT_NUM_DATAS		8

#define	KSTAT_FLAG_VIRTUAL	0x01
#define	KSTAT_FLAG_VAR_SIZE	0x02
#define	KSTAT_FLAG_WRITABLE	0x04
#define	KSTAT_FLAG_PERSISTENT	0x08
#define	KSTAT_FLAG_DORMANT	0x10
#define	KSTAT_FLAG_INVALID	0x20
#define	KSTAT_FLAG_LONGSTRINGS	0x40
#define	KSTAT_FLAG_NO_HEADERS	0x80

#define	KS_MAGIC		0x9d9d9d9d


#define	KSTAT_FLAG_VIRTUAL	0x01

#define	KSTAT_READ	0
#define	KSTAT_WRITE	1

struct kstat;
typedef struct kstat kstat_t;

typedef struct kstat_raw_ops {
	int (*headers)(char *buf, size_t size);
	int (*data)(char *buf, size_t size, void *data);
	void *(*addr)(kstat_t *ksp, loff_t index);
} kstat_raw_ops_t;

struct kstat {
	void	*ks_data;
	u_int	 ks_ndata;
	kmutex_t *ks_lock;
	size_t		ks_data_size;	/* size of kstat data section */
	uchar_t		ks_flags;		/* kstat flags */
#ifdef _KERNEL
	struct sysctl_ctx_list ks_sysctl_ctx;
	struct sysctl_oid *ks_sysctl_root;
#endif
	int		(*ks_update)(struct kstat *, int); /* dynamic update */
	void		*ks_private;	/* arbitrary provider-private data */
	kstat_raw_ops_t	ks_raw_ops;		/* ops table for raw type */
};

typedef struct kstat_named {
#define	KSTAT_STRLEN	31
	char	name[KSTAT_STRLEN];
	uchar_t	data_type;
#define	KSTAT_DESCLEN		128
	char	desc[KSTAT_DESCLEN];
	union {
		char c[16];	/* 128-bit int */
		int32_t	i32;	/* 32-bit signed int */
		uint32_t ui32;	/* 32-bit unsigned int */
		int64_t i64;	/* 64-bit signed int */
		uint64_t ui64;	/* 64-bit unsigned int */
		long l;		/* native signed long */
		ulong_t ul;	/* native unsigned long */
		struct {
			union {
				char *ptr;	/* NULL-term string */
				char __pad[8];	/* 64-bit padding */
			} addr;
			uint32_t len;		/* # bytes for strlen + '\0' */
		} string;
	} value;
} kstat_named_t;

typedef struct kstat_io {
	u_longlong_t	nread;		/* number of bytes read */
	u_longlong_t	nwritten;	/* number of bytes written */
	uint_t		reads;		/* number of read operations */
	uint_t		writes;		/* number of write operations */
	hrtime_t	wtime;		/* cumulative wait (pre-service) time */
	hrtime_t	wlentime;	/* cumulative wait len*time product */
	hrtime_t	wlastupdate;	/* last time wait queue changed */
	hrtime_t	rtime;		/* cumulative run (service) time */
	hrtime_t	rlentime;	/* cumulative run length*time product */
	hrtime_t	rlastupdate;	/* last time run queue changed */
	uint_t		wcnt;		/* count of elements in wait state */
	uint_t		rcnt;		/* count of elements in run state */
} kstat_io_t;

extern void __kstat_set_raw_ops(kstat_t *ksp,
    int (*headers)(char *buf, size_t size),
    int (*data)(char *buf, size_t size, void *data),
    void* (*addr)(kstat_t *ksp, loff_t index));

extern kstat_t *__kstat_create(const char *ks_module, int ks_instance,
    const char *ks_name, const char *ks_class, uchar_t ks_type,
    uint_t ks_ndata, uchar_t ks_flags);

extern void __kstat_install(kstat_t *ksp);
extern void __kstat_delete(kstat_t *ksp);
extern void kstat_waitq_enter(kstat_io_t *);
extern void kstat_waitq_exit(kstat_io_t *);
extern void kstat_runq_enter(kstat_io_t *);
extern void kstat_runq_exit(kstat_io_t *);

#define	kstat_set_raw_ops(k, h, d, a) \
    __kstat_set_raw_ops(k, h, d, a)
#define	KSTAT_NAMED_STR_PTR(knptr) ((knptr)->value.string.addr.ptr)
#define	KSTAT_NAMED_STR_BUFLEN(knptr) ((knptr)->value.string.len)
kstat_t *kstat_create(char *module, int instance, char *name, char *cls,
    uchar_t type, ulong_t ndata, uchar_t flags);
void kstat_install(kstat_t *ksp);
void kstat_delete(kstat_t *ksp);
void kstat_set_string(char *, const char *);
void kstat_named_init(kstat_named_t *, const char *, uchar_t);

#endif	/* _OPENSOLARIS_SYS_KSTAT_H_ */
