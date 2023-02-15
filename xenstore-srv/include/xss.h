#pragma once
#include <zephyr/xen/public/xen.h>

enum xs_perm {
	XS_PERM_NONE = 0x0,
	XS_PERM_READ = 0x1,
	XS_PERM_WRITE = 0x2,
	XS_PERM_BOTH = XS_PERM_WRITE | XS_PERM_READ
};

int xss_read(const char *path, char *value, size_t len);
int xss_write(const char *path, const char *value);
int xss_read_integer(const char *path, int *value);
int xss_set_perm(const char *path, domid_t domid, enum xs_perm perm);

