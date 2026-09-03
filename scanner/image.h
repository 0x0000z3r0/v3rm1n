#pragma once

#include <stddef.h>
#include <stdint.h>

struct image {
	const char *path;
	const uint8_t *data;
	size_t size;
};

int image_open(struct image *image, const char *path);
void image_close(struct image *image);
