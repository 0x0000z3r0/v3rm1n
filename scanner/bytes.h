#pragma once

#include "image.h"

#include <stdbool.h>
#include <stdint.h>

bool bytes_has(const struct image *image, size_t offset, size_t length);
size_t bytes_find_ci(const uint8_t *data, size_t length, const char *text);
bool bytes_contains_ci(const uint8_t *data, size_t length, const char *text);
uint16_t read_u16(const uint8_t *data, bool big_endian);
uint32_t read_u32(const uint8_t *data, bool big_endian);
uint64_t read_u64(const uint8_t *data, bool big_endian);
uint32_t crc32_le(uint32_t crc, const uint8_t *data, size_t length);
