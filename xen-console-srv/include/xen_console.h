/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2023 EPAM Systems
 */

#ifndef XENLIB_XEN_SHELL_H
#define XENLIB_XEN_SHELL_H

#include <zephyr/shell/shell.h>

/*
 * Initialize domain console by setting HVM param for domain
 * and event channel binding in dom0. Start thread that
 * reads output from a domain console.
 *
 * @param domain - domain, where console should be initialized
 *
 * @return - zero on success, negative errno on failure
 */
int xen_init_domain_console(struct xen_domain *domain);

/*
 * Stop console thread in dom0, that reads domain output.
 *
 * @param domain - domain, where console thread will be stopped
 *
 * @return - zero on success, negative errno on failure
 */
int xen_stop_domain_console(struct xen_domain *domain);

/*
 * Attach Zephyr shell to console in given domain
 *
 * @param shell - Zephyr shell instance attach to
 *
 * @param domain - domain, which console should be attached
 *
 * @return - zero on success, negative errno on failure
 */
int xen_attach_domain_console(const struct shell *shell, struct xen_domain *domain);

#endif /* XENLIB_XEN_SHELL_H */
