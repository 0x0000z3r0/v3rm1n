#pragma once

#include "image.h"

#include <stdbool.h>
#include <stdint.h>

bool metadata_secure_version(const struct image *image, uint32_t *version);
bool metadata_idf_version(const struct image *image, char *version, size_t size);
int metadata_scan(const struct image *image);
