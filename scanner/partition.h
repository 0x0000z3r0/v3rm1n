#pragma once

#include "image.h"

#include <stdbool.h>
#include <stdint.h>

struct partition {
	uint8_t type;
	uint8_t subtype;
	uint32_t offset;
	uint32_t size;
	uint32_t flags;
	char label[17];
};

bool partition_get(const struct image *image, uint8_t type, uint8_t subtype, struct partition *partition);
size_t partition_count(const struct image *image, uint8_t type, uint8_t subtype_min, uint8_t subtype_max);
size_t partition_count_flags(const struct image *image, uint32_t flags);
int partition_scan(const struct image *image);
