/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/xen/generic.h>
#include <zephyr/xen/public/io/console.h>
#include <zephyr/xen/public/memory.h>
#include <zephyr/xen/public/xen.h>
#include <zephyr/xen/hvm.h>

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <string.h>
#include <stdio.h>

#include "domain.h"
#include "xenstore_srv.h"
#include <xen_console.h>

LOG_MODULE_REGISTER(xen_domain_console);

/* One page is enough for anyone */
#define XEN_CONSOLE_STACK_SIZE		4096
/* Need low prio to make sure that guest does not lock up us in reader thread */
#define XEN_CONSOLE_PRIO		14
/* Size is chosen based on educated guess. Please ensure that it is power of two. */
#define XEN_CONSOLE_BUFFER_SZ		8192
#define EXT_THREAD_STOP_BIT		0
#define INT_THREAD_STOP_BIT		1

#define ESCAPE_CHARACTER		0x1d /* CTR+] */
/* There we store pointer to an attached console */
static struct xen_domain_console *current_console;
static uint32_t used_threads;
static K_MUTEX_DEFINE(global_console_lock);

static K_THREAD_STACK_ARRAY_DEFINE(ext_stack, DOM_MAX, XEN_CONSOLE_STACK_SIZE);
static K_THREAD_STACK_DEFINE(int_stack, XEN_CONSOLE_STACK_SIZE);

BUILD_ASSERT((XEN_CONSOLE_BUFFER_SZ & (XEN_CONSOLE_BUFFER_SZ - 1)) == 0);
BUILD_ASSERT(sizeof(used_threads) * CHAR_BIT >= DOM_MAX);

static void console_lock(struct xen_domain_console *console)
{
	__ASSERT_NO_MSG(k_mutex_lock(&console->lock, K_FOREVER) == 0);
}

static void console_unlock(struct xen_domain_console *console)
{
	__ASSERT_NO_MSG(k_mutex_unlock(&console->lock) == 0);
}

/* Allocated one stack for external reader thread */
static int get_stack_idx(void)
{
	int i, ret = -ENOSPC;

	k_mutex_lock(&global_console_lock, K_FOREVER);

	for (i = 0; i < DOM_MAX; i++)
		if (!(used_threads & BIT(i))) {
			used_threads |= BIT(i);
			ret = i;
			LOG_DBG("Allocated stack with index %d\n", i);
			break;
		}

	k_mutex_unlock(&global_console_lock);

	return ret;
}

/* Free allocated stack */
static void free_stack_idx(int idx)
{
	__ASSERT_NO_MSG(idx < DOM_MAX);

	k_mutex_lock(&global_console_lock, K_FOREVER);

	__ASSERT_NO_MSG(used_threads & BIT(idx));
	used_threads &= ~BIT(idx);

	k_mutex_unlock(&global_console_lock);
}

/* Write one character to the internal console ring. Should be called with console->lock held. */
static void console_feed_int_ring(struct xen_domain_console *console, char ch)
{
	size_t buf_pos = console->int_prod++ & (XEN_CONSOLE_BUFFER_SZ - 1);

	console->int_buf[buf_pos] = ch;

	/* Special case for the already full buffer */
	if (unlikely((console->int_prod & (XEN_CONSOLE_BUFFER_SZ - 1)) ==
		     (console->int_cons & (XEN_CONSOLE_BUFFER_SZ - 1)))) {
		console->lost_chars++;
		console->int_cons++;
	}
}

/* Read from domU ring buffer into a local ring buffer.
 * Please note that ring buffers named in accordance to DomU point of view:
 * intf->out is DomU output and our input;
 */
static void read_from_ext_ring(struct xencons_interface *intf,
			       struct xen_domain_console *console)
{
	XENCONS_RING_IDX cons = intf->out_cons;
	XENCONS_RING_IDX prod = intf->out_prod;
	XENCONS_RING_IDX out_idx = 0;

	compiler_barrier();
	if ((prod - cons) > sizeof(intf->out)) {
		LOG_WRN("Invalid state of console output ring. Resetting.");
		intf->out_cons = prod;
		return;
	}

	while (cons != prod) {
		out_idx = MASK_XENCONS_IDX(cons, intf->out);
		console_feed_int_ring(console, intf->out[out_idx]);
		cons++;
	}

	compiler_barrier();
	intf->out_cons = cons;
}

/* Write data to DomU
 * Please note that ring buffers named in accordance to DomU point of view:
 * intf->in is DomU input and our output;
 */
static void write_to_ext_ring(struct xencons_interface *intf, char *data, int len)
{
	XENCONS_RING_IDX cons = intf->in_cons;
	XENCONS_RING_IDX prod = intf->in_prod;
	XENCONS_RING_IDX idx = 0;
	size_t free_space;

	compiler_barrier();
	if ((prod - cons) > sizeof(intf->in)) {
		LOG_WRN("Invalid state of console input ring. Resetting.");
		intf->in_prod = cons;
		return;
	}

	free_space = sizeof(intf->in) - (prod-cons);
	if (free_space < len) {
		len = free_space;
		/* We can't block and we can't even print a warning */
	}
	while (len) {
		idx = MASK_XENCONS_IDX(prod, intf->out);
		intf->in[idx] = *data;
		prod++;
		data++;
		len--;
	}

	compiler_barrier();
	intf->in_prod = prod;
}

/* Thread that reads from external ring and places data into internal ring */
static void console_ext_read_thrd(void *p1, void *p2, void *p3)
{
	struct xen_domain_console *console = p1;
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (!atomic_test_and_clear_bit(&console->stop_thrd, EXT_THREAD_STOP_BIT)) {
		k_sem_take(&console->ext_sem, K_FOREVER);
		console_lock(console);
		read_from_ext_ring(console->intf, console);
		console_unlock(console);
		/* Notify display thread (if any) */
		k_sem_give(&console->int_sem);
	}
}

static void evtchn_callback(void *priv)
{
	struct xen_domain_console *console = priv;

	k_sem_give(&console->ext_sem);
}

int xen_init_domain_console(struct xen_domain *domain)
{
	struct xen_domain_console *console;
	int rc = 0;

	if (!domain) {
		LOG_ERR("No domain provided to the xen_init_domain_console");
		return -ESRCH;
	}

	console = &domain->console;
	console->int_buf = k_malloc(XEN_CONSOLE_BUFFER_SZ);
	if (!console->int_buf) {
		LOG_ERR("Failed to allocate domain console buffer");
		return -ENOMEM;
	}
	console->int_prod = 0;
	console->int_cons = 0;

	/* If we are attaching to a console for a second time, we need
	 * to join the previous thread. We need to initialize this
	 * variable to true, so then attach handler can reset it to false
	 */
	console->first_attach = true;

	rc = bind_interdomain_event_channel(domain->domid, console->evtchn,
					       evtchn_callback, console);

	if (rc < 0) {
		LOG_ERR("Failed to bind interdomain event for console (rc=%d)", rc);
		goto err_free;
	}

	console->local_evtchn = rc;

	k_sem_init(&console->int_sem, 1, 1);
	k_sem_init(&console->ext_sem, 1, 1);
	k_mutex_init(&console->lock);

	rc = hvm_set_parameter(HVM_PARAM_CONSOLE_EVTCHN, domain->domid, console->evtchn);
	if (rc) {
		LOG_ERR("Failed to set domain console evtchn param (rc=%d)", rc);
		goto err_unbind;
	}

	rc = get_stack_idx();
	if (rc < 0) {
		LOG_ERR("Could not allocated stack for reader thread (rc=%d)", rc);
		goto err_unbind;
	}
	console->stack_idx = rc;

	k_thread_create(&console->ext_thrd,
			ext_stack[console->stack_idx],
			XEN_CONSOLE_STACK_SIZE,
			console_ext_read_thrd, console,
			NULL, NULL, XEN_CONSOLE_PRIO, 0, K_NO_WAIT);

	return rc;

err_unbind:
	unbind_event_channel(console->local_evtchn);
	evtchn_close(console->local_evtchn);

err_free:
	k_free(console->int_buf);

	return rc;
}

int xen_stop_domain_console(struct xen_domain *domain)
{
	struct xen_domain_console *console;
	int rc;

	if (!domain) {
		LOG_ERR("No domain provided to the xen_stop_domain_console");
		return -ESRCH;
	}

	console = &domain->console;

	atomic_set_bit(&console->stop_thrd, EXT_THREAD_STOP_BIT);
	atomic_set_bit(&console->stop_thrd, INT_THREAD_STOP_BIT);

	/* Send event to end read cycle */
	k_sem_give(&console->ext_sem);
	k_thread_join(&console->ext_thrd, K_FOREVER);
	free_stack_idx(console->stack_idx);

	k_mutex_lock(&global_console_lock, K_FOREVER);
	/* Stop attached console if any */
	if (current_console == console) {
		k_thread_join(&console->int_thrd, K_FOREVER);
		current_console = NULL;
	}
	k_mutex_unlock(&global_console_lock);

	unbind_event_channel(console->local_evtchn);
	rc = evtchn_close(console->local_evtchn);
	if (rc)
	{
		LOG_ERR("Unable to close event channel %u", console->local_evtchn);
		return rc;
	}

	return 0;
}

static void console_display_thrd(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	struct xen_domain_console *console = p1;
	const struct shell *shell = p2;
	/* Buffer input a little */
	char buf[32];
	int read;

	shell_info(shell, "Attached to a domain console");

	while (!atomic_test_and_clear_bit(&console->stop_thrd, INT_THREAD_STOP_BIT)) {
		k_sem_take(&console->int_sem, K_FOREVER);

		console_lock(console);
		/* Display info about missed characters */
		if (console->lost_chars) {
			shell_warn(shell,
				   "Domain console overrun detected. %zi bytes was lost",
				   console->lost_chars);
			console->lost_chars = 0;
		}

		while (console->int_cons < console->int_prod) {
			read = 0;
			memset(buf, 0, sizeof(buf));

			/* TODO: There is a room for optimization.... */
			while (console->int_cons < console->int_prod &&
			       read < sizeof(buf) - 1) {
				size_t buf_pos = (console->int_cons++) %
					(XEN_CONSOLE_BUFFER_SZ - 1);
				buf[read++] = console->int_buf[buf_pos];
			}
			if (read) {
				shell_fprintf(shell, SHELL_NORMAL, "%s", buf);
			}
		}
		console_unlock(console);
	}

	k_mutex_lock(&global_console_lock, K_FOREVER);
	current_console = NULL;
	k_mutex_unlock(&global_console_lock);

	shell_info(shell, "Detached from console");
}

static void console_shell_cb(const struct shell *shell, uint8_t *data, size_t len)
{
	struct xen_domain_console *console;

	k_mutex_lock(&global_console_lock, K_FOREVER);
	console = current_console;
	k_mutex_unlock(&global_console_lock);

	__ASSERT_NO_MSG(console != NULL);

	if (len == 1 && data[0] == ESCAPE_CHARACTER) {
		/* Detach console */
		atomic_set_bit(&console->stop_thrd, INT_THREAD_STOP_BIT);
		k_sem_give(&console->int_sem);
		shell_set_bypass(shell, NULL);
	}

	write_to_ext_ring(console->intf, data, len);
	notify_evtchn(console->local_evtchn);
}

int xen_attach_domain_console(const struct shell *shell, struct xen_domain *domain)
{
	struct xen_domain_console *console;

	if (!domain) {
		LOG_ERR("No domain passed to attach_domain_console");
		return -ESRCH;
	}

	console = &domain->console;
	k_mutex_lock(&global_console_lock, K_FOREVER);
	if (current_console) {
		/* Actually, this should never happen */
		shell_error(shell, "Shell is already attached to console");
		k_mutex_unlock(&global_console_lock);
		return -EEXIST;
	}
	current_console = console;
	k_mutex_unlock(&global_console_lock);

	if (!console->first_attach) {
		k_thread_join(&console->int_thrd, K_FOREVER);
	}

	console->first_attach = false;
	atomic_clear_bit(&console->stop_thrd, INT_THREAD_STOP_BIT);

	k_thread_create(&console->int_thrd,
			int_stack,
			XEN_CONSOLE_STACK_SIZE,
			console_display_thrd, console,
			(void*)shell, NULL, XEN_CONSOLE_PRIO, 0, K_NO_WAIT);

	shell_set_bypass(shell, console_shell_cb);

	return 0;
}
