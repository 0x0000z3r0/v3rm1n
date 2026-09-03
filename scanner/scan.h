#pragma once

#include "image.h"

struct scan_module {
	const char *name;
	int (*scan)(const struct image *image);
};
