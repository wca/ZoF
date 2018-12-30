/*-
 * Copyright (c) 2009 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Copyright (c) 2012 Spectra Logic Corporation.  All rights reserved.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>
#include <sys/taskq.h>

#include <vm/uma.h>

static uma_zone_t taskq_zone;

taskq_t *system_taskq = NULL;
taskq_t *system_delay_taskq = NULL;
taskq_t *dynamic_taskq = NULL;

#define TIMEOUT_TASK 1
#define NORMAL_TASK 2

static void
system_taskq_init(void *arg)
{

	taskq_zone = uma_zcreate("taskq_zone", sizeof(taskq_ent_t),
	    NULL, NULL, NULL, NULL, 0, 0);
	system_taskq = taskq_create("system_taskq", mp_ncpus, minclsyspri,
	    0, 0, 0);
	system_delay_taskq = taskq_create("system_delay_taskq", mp_ncpus, minclsyspri,
	    0, 0, 0);
}
SYSINIT(system_taskq_init, SI_SUB_CONFIGURE, SI_ORDER_ANY, system_taskq_init, NULL);

static void
system_taskq_fini(void *arg)
{

	taskq_destroy(system_taskq);
	uma_zdestroy(taskq_zone);
}
SYSUNINIT(system_taskq_fini, SI_SUB_CONFIGURE, SI_ORDER_ANY, system_taskq_fini, NULL);

static taskq_t *
taskq_create_with_init(const char *name, int nthreads, pri_t pri,
    int minalloc __unused, int maxalloc __unused, uint_t flags,
    taskq_callback_fn ctor, taskq_callback_fn dtor)
{
	taskq_t *tq;

	if ((flags & TASKQ_THREADS_CPU_PCT) != 0)
		nthreads = MAX((mp_ncpus * nthreads) / 100, 1);

	tq = kmem_alloc(sizeof(*tq), KM_SLEEP);
	tq->tq_queue = taskqueue_create(name, M_WAITOK, taskqueue_thread_enqueue,
	    &tq->tq_queue);
	if (ctor != NULL)
		taskqueue_set_callback(tq->tq_queue,
		    TASKQUEUE_CALLBACK_TYPE_INIT, ctor, NULL);
	if (dtor != NULL)
		taskqueue_set_callback(tq->tq_queue,
		    TASKQUEUE_CALLBACK_TYPE_SHUTDOWN, dtor, NULL);
	(void) taskqueue_start_threads(&tq->tq_queue, nthreads, pri, "%s", name);

	return ((taskq_t *)tq);
}

taskq_t *
taskq_create(const char *name, int nthreads, pri_t pri, int minalloc __unused,
    int maxalloc __unused, uint_t flags)
{

	return (taskq_create_with_init(name, nthreads, pri, minalloc, maxalloc,
	    flags, NULL, NULL));
}

taskq_t *
taskq_create_proc(const char *name, int nthreads, pri_t pri, int minalloc,
    int maxalloc, proc_t *proc __unused, uint_t flags, taskq_callback_fn ctor,
    taskq_callback_fn dtor)
{

	return (taskq_create_with_init(name, nthreads, pri, minalloc, maxalloc,
	    flags, ctor, dtor));
}

void
taskq_destroy(taskq_t *tq)
{

	taskqueue_free(tq->tq_queue);
	kmem_free(tq, sizeof(*tq));
}

int
taskq_member(taskq_t *tq, kthread_t *thread)
{

	return (taskqueue_member(tq->tq_queue, thread));
}

int
taskq_cancel_id(taskq_t *tq, taskqid_t id)
{
	u_int pend;
	int rc;
	struct taskq_ent *ent = (void*)id;

	if (ent == NULL)
		return (0);
	if (ent->tqent_type == TIMEOUT_TASK) {
		rc = taskqueue_cancel_timeout(tq->tq_queue, &ent->tqent_timeout_task, &pend);
		uma_zfree(taskq_zone, ent);
	} else
		rc = taskqueue_cancel(tq->tq_queue, &ent->tqent_task, &pend);
	return (rc);
}

static void
taskq_run(void *arg, int pending __unused)
{
	taskq_ent_t *task = arg;

	task->tqent_func(task->tqent_arg);

	if (task->tqent_type == NORMAL_TASK)
		uma_zfree(taskq_zone, task);
}

taskqid_t
taskq_dispatch_delay(taskq_t *tq, task_func_t func, void *arg,
    uint_t flags, clock_t expire_time)
{
	struct taskq_ent *task;
	int mflag;

	if ((flags & (TQ_SLEEP | TQ_NOQUEUE)) == TQ_SLEEP)
		mflag = M_WAITOK;
	else
		mflag = M_NOWAIT;
	
	task = uma_zalloc(taskq_zone, mflag);
	if (task == NULL)
		return (0);

	task->tqent_func = func;
	task->tqent_arg = arg;
	task->tqent_type = TIMEOUT_TASK;
	
	TIMEOUT_TASK_INIT(tq->tq_queue, &task->tqent_timeout_task, 0,
		taskq_run, task);
	
	taskqueue_enqueue_timeout(tq->tq_queue, &task->tqent_timeout_task,
		expire_time);
	return (taskqid_t)task;
}

taskqid_t
taskq_dispatch(taskq_t *tq, task_func_t func, void *arg, uint_t flags)
{
	taskq_ent_t *task;
	int mflag, prio;

	if ((flags & (TQ_SLEEP | TQ_NOQUEUE)) == TQ_SLEEP)
		mflag = M_WAITOK;
	else
		mflag = M_NOWAIT;
	/*
	 * If TQ_FRONT is given, we want higher priority for this task, so it
	 * can go at the front of the queue.
	 */
	prio = !!(flags & TQ_FRONT);

	task = uma_zalloc(taskq_zone, mflag);
	if (task == NULL)
		return (0);

	task->tqent_func = func;
	task->tqent_arg = arg;
	task->tqent_type = NORMAL_TASK;
	TASK_INIT(&task->tqent_task, prio, taskq_run, task);
	taskqueue_enqueue(tq->tq_queue, &task->tqent_task);

	return ((taskqid_t)(void *)task);
}

static void
taskq_run_ent(void *arg, int pending __unused)
{
	taskq_ent_t *task = arg;

	task->tqent_func(task->tqent_arg);
}

void
taskq_dispatch_ent(taskq_t *tq, task_func_t func, void *arg, u_int flags,
    taskq_ent_t *task)
{
	int prio;

	/*
	 * If TQ_FRONT is given, we want higher priority for this task, so it
	 * can go at the front of the queue.
	 */
	prio = !!(flags & TQ_FRONT);

	task->tqent_func = func;
	task->tqent_arg = arg;

	TASK_INIT(&task->tqent_task, prio, taskq_run_ent, task);
	taskqueue_enqueue(tq->tq_queue, &task->tqent_task);
}

void
taskq_wait(taskq_t *tq)
{
	taskqueue_drain_all(tq->tq_queue);
}

void
taskq_wait_id(taskq_t *tq, taskqid_t id)
{
	taskq_wait(tq);
}

void
taskq_wait_outstanding(taskq_t *tq, taskqid_t id __unused)
{
	taskq_wait(tq);
}
