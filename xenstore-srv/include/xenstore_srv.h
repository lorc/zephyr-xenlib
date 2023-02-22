/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XENLIB_XENSTORE_SRV_H
#define XENLIB_XENSTORE_SRV_H

#define DOM_MAX 4
#define STRING_LENGTH_MAX 128

struct xs_entry {
	char *key;
	char *value;
	sys_dlist_t child_list;

	sys_dnode_t node;
};

struct watch_entry {
	char *key;
	char *token;
	int domid;
	bool is_relative;

	sys_dnode_t node;
};

struct pending_watch_event_entry {
	char *key;
	int domid;

	sys_dnode_t node;
};

void xenstore_evt_thrd(void *p1, void *p2, void *p3);
int start_domain_stored(struct xen_domain *domain);
int stop_domain_stored(struct xen_domain *domain);

#endif