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

#ifndef _OPENSOLARIS_SYS_SUNDDI_H_
#define	_OPENSOLARIS_SYS_SUNDDI_H_

typedef int ddi_devid_t;

#ifdef _KERNEL

#include <sys/kmem.h>
#include <sys/libkern.h>
#include <sys/sysevent.h>
#include <sys/u8_textprep.h>

#define	ddi_driver_major(zfs_dip)		(0)
#define	ddi_copyin(from, to, size, flag)				\
	(copyin((from), (to), (size)), 0)
#define	ddi_copyout(from, to, size, flag)				\
	(copyout((from), (to), (size)), 0)
int ddi_strtol(const char *str, char **nptr, int base, long *result);
int ddi_strtoul(const char *str, char **nptr, int base, unsigned long *result);
int ddi_strtoll(const char *str, char **nptr, int base, long long *result);
int ddi_strtoull(const char *str, char **nptr, int base,
    unsigned long long *result);

#define	DDI_PROP_DONTPASS			0x0001
#define	DDI_PROP_CANSLEEP			0x0002

#define	DDI_SUCCESS	(0)
#define	DDI_FAILURE	(-1)
#define	DDI_SLEEP	0x666

#define	ddi_prop_lookup_string(x1, x2, x3, x4, x5)	(*x5 = NULL)
#define	ddi_prop_free(x)				(void)0
#define	ddi_root_node()					(void)0

int ddi_soft_state_init(void **statep, size_t size, size_t nitems);
void ddi_soft_state_fini(void **statep);

void *ddi_get_soft_state(void *state, int item);
int ddi_soft_state_zalloc(void *state, int item);
void ddi_soft_state_free(void *state, int item);

#endif	/* _KERNEL */

#endif	/* _OPENSOLARIS_SYS_SUNDDI_H_ */
