#include "format.h"
#include "bytes.h"
#include "print.h"

#include <stdbool.h>
#include <stdint.h>

#define ESP_MAGIC 0xe9
#define ESP_HEADER_SIZE 24
#define ESP_MAX_SEGMENTS 16
#define ESP_APP_DESC_MAGIC 0xabcd5432
#define ESP_PART_MAGIC 0x50aa
#define ELF_MACHINE_RISCV 243

static const char *
chip_name(uint16_t id)
{
	switch (id) {
	case 0x0005:
		return "ESP32-C3";
	case 0x000d:
		return "ESP32-C6";
	case 0x0012:
		return "ESP32-P4";
	default:
		return NULL;
	}
}

static const char *
flash_mode(uint8_t mode)
{
	static const char *const modes[] = {
	    "QIO",
	    "QOUT",
	    "DIO",
	    "DOUT",
	    "fast read",
	    "slow read",
	};

	if (mode < sizeof(modes) / sizeof(modes[0]))
		return modes[mode];

	return "unknown";
}

static int
scan_elf(const struct image *image)
{
	if (!bytes_has(image, 0, 16)) {
		print_bad("ELF header is truncated");
		return 0;
	}

	uint8_t elf_class = image->data[4];
	uint8_t encoding = image->data[5];
	if ((elf_class != 1 && elf_class != 2) || (encoding != 1 && encoding != 2)) {
		print_bad("ELF header is invalid");
		return 0;
	}

	size_t header_size = elf_class == 1 ? 52 : 64;
	if (!bytes_has(image, 0, header_size)) {
		print_bad("ELF header is truncated");
		return 0;
	}

	bool big_endian = encoding == 2;
	uint16_t machine = read_u16(image->data + 18, big_endian);
	uint64_t entry = elf_class == 1 ? read_u32(image->data + 24, big_endian) : read_u64(image->data + 24, big_endian);

	print_info("format is ELF%u", elf_class == 1 ? 32 : 64);
	if (machine == ELF_MACHINE_RISCV)
		print_info("architecture is RISC-V");
	else
		print_bad("architecture is unsupported (machine %u)", machine);
	print_info("entry point is 0x%llx", (unsigned long long)entry);
	return 0;
}

static int
scan_esp(const struct image *image)
{
	if (!bytes_has(image, 0, ESP_HEADER_SIZE)) {
		print_bad("ESP image header is truncated");
		return 0;
	}

	uint8_t segments = image->data[1];
	uint32_t entry = read_u32(image->data + 4, false);
	uint16_t chip = read_u16(image->data + 12, false);
	const char *target = chip_name(chip);
	bool is_app = bytes_has(image, 32, 4) && read_u32(image->data + 32, false) == ESP_APP_DESC_MAGIC;

	print_info("format is ESP %s image", is_app ? "application" : "executable");
	if (target != NULL)
		print_info("target is %s", target);
	else
		print_bad("target is unsupported (chip 0x%04x)", chip);
	print_info("entry point is 0x%08x", entry);
	print_info("segments: %u", segments);
	print_info("flash mode is %s", flash_mode(image->data[2]));

	if (segments == 0 || segments > ESP_MAX_SEGMENTS) {
		print_bad("segment count is invalid");
		return 0;
	}

	size_t offset = ESP_HEADER_SIZE;
	uint8_t checksum = 0xef;
	for (size_t segment = 0; segment < segments; segment++) {
		if (!bytes_has(image, offset, 8)) {
			print_bad("segment %zu header is truncated", segment);
			return 0;
		}

		size_t length = read_u32(image->data + offset + 4, false);
		offset += 8;
		if (!bytes_has(image, offset, length)) {
			print_bad("segment %zu data is truncated", segment);
			return 0;
		}

		for (size_t i = 0; i < length; i++)
			checksum ^= image->data[offset + i];
		offset += length;
	}

	size_t checksum_offset = offset + (15 - offset % 16);
	if (!bytes_has(image, checksum_offset, 1)) {
		print_bad("image checksum is missing");
		return 0;
	}

	if (image->data[checksum_offset] == checksum)
		print_info("checksum is valid");
	else
		print_bad("checksum is invalid");

	if (image->data[23] == 1) {
		if (bytes_has(image, checksum_offset + 1, 32))
			print_info("SHA-256 digest is appended");
		else
			print_bad("SHA-256 digest is truncated");
	}

	return 0;
}

int
format_scan(const struct image *image)
{
	if (bytes_has(image, 0, 4) && image->data[0] == 0x7f && image->data[1] == 'E' && image->data[2] == 'L' && image->data[3] == 'F')
		return scan_elf(image);

	if (bytes_has(image, 0, 1) && image->data[0] == ESP_MAGIC)
		return scan_esp(image);

	if (bytes_has(image, 0, 2) && read_u16(image->data, false) == ESP_PART_MAGIC) {
		print_info("format is ESP partition table");
		return 0;
	}

	print_bad("format is unknown");
	return 0;
}
