#include "bytes.h"

#include <ctype.h>
#include <string.h>

bool
bytes_has(const struct image *image, size_t offset, size_t length)
{
	return offset <= image->size && length <= image->size - offset;
}

size_t
bytes_find_ci(const uint8_t *data, size_t length, const char *text)
{
	size_t text_length = strlen(text);
	if (text_length > length)
		return SIZE_MAX;

	for (size_t i = 0; i <= length - text_length; i++) {
		size_t j = 0;
		while (j < text_length && tolower((unsigned char)data[i + j]) == tolower((unsigned char)text[j]))
			j++;
		if (j == text_length)
			return i;
	}

	return SIZE_MAX;
}

bool
bytes_contains_ci(const uint8_t *data, size_t length, const char *text)
{
	return bytes_find_ci(data, length, text) != SIZE_MAX;
}

uint16_t
read_u16(const uint8_t *data, bool big_endian)
{
	if (big_endian)
		return (uint16_t)data[0] << 8 | data[1];

	return (uint16_t)data[1] << 8 | data[0];
}

uint32_t
read_u32(const uint8_t *data, bool big_endian)
{
	if (big_endian)
		return (uint32_t)data[0] << 24 | (uint32_t)data[1] << 16 | (uint32_t)data[2] << 8 | data[3];

	return (uint32_t)data[3] << 24 | (uint32_t)data[2] << 16 | (uint32_t)data[1] << 8 | data[0];
}

uint64_t
read_u64(const uint8_t *data, bool big_endian)
{
	if (big_endian)
		return (uint64_t)read_u32(data, true) << 32 | read_u32(data + 4, true);

	return (uint64_t)read_u32(data + 4, false) << 32 | read_u32(data, false);
}

uint32_t
crc32_le(uint32_t crc, const uint8_t *data, size_t length)
{
	crc = ~crc;
	for (size_t i = 0; i < length; i++) {
		crc ^= data[i];
		for (unsigned int bit = 0; bit < 8; bit++)
			crc = crc >> 1 ^ (crc & 1 ? 0xedb88320 : 0);
	}

	return ~crc;
}
