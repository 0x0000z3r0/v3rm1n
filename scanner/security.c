#include "security.h"
#include "bytes.h"
#include "elf.h"
#include "metadata.h"
#include "partition.h"
#include "print.h"

#include <stdbool.h>
#include <stdint.h>

#define ESP_MAGIC 0xe9
#define SIGNATURE_MAGIC 0xe7
#define SIGNATURE_RSA 2
#define SIGNATURE_ECDSA 3
#define SIGNATURE_BLOCK_SIZE 1216
#define SIGNATURE_DATA_SIZE 1196
#define SIGNATURE_SECTOR_SIZE 4096
#define SIGNATURE_BLOCKS 3
#define PART_FLAG_ENCRYPTED 0x01

static bool
is_esp(const struct image *image)
{
	return bytes_has(image, 0, 1) && image->data[0] == ESP_MAGIC;
}

static size_t
scan_signatures(const struct image *image)
{
	size_t valid = 0;
	for (size_t sector = 0; bytes_has(image, sector, SIGNATURE_BLOCK_SIZE); sector += SIGNATURE_SECTOR_SIZE) {
		for (size_t block = 0; block < SIGNATURE_BLOCKS; block++) {
			size_t offset = sector + block * SIGNATURE_BLOCK_SIZE;
			if (!bytes_has(image, offset, SIGNATURE_BLOCK_SIZE) || image->data[offset] != SIGNATURE_MAGIC)
				continue;

			uint8_t version = image->data[offset + 1];
			if (version != SIGNATURE_RSA && version != SIGNATURE_ECDSA)
				continue;
			if (image->data[offset + 3] != 0)
				continue;
			if (version == SIGNATURE_RSA && image->data[offset + 2] != 0)
				continue;

			uint32_t stored_crc = read_u32(image->data + offset + SIGNATURE_DATA_SIZE, false);
			uint32_t actual_crc = crc32_le(0, image->data + offset, SIGNATURE_DATA_SIZE);
			if (stored_crc != actual_crc) {
				print_bad("Secure Boot signature block at 0x%zx has an invalid CRC", offset);
				continue;
			}

			print_good("Secure Boot v2 %s signature block is present at 0x%zx", version == SIGNATURE_RSA ? "RSA" : "ECDSA", offset);
			valid++;
		}

		if (sector > SIZE_MAX - SIGNATURE_SECTOR_SIZE)
			break;
	}

	return valid;
}

static void
scan_secure_boot(const struct image *image)
{
	if (elf_is(image)) {
		print_info("Secure Boot signatures are not carried in ELF files");
		return;
	}

	size_t signatures = scan_signatures(image);
	if (signatures != 0) {
		print_info("Secure Boot signature blocks: %zu (structure and CRC validated)", signatures);
		return;
	}

	if (is_esp(image))
		print_bad("Secure Boot signature block not found");
	else
		print_info("Secure Boot could not be assessed for this image type");
}

static void
scan_flash_encryption(const struct image *image)
{
	size_t encrypted = partition_count_flags(image, PART_FLAG_ENCRYPTED);
	if (encrypted != 0)
		print_info("partitions with encrypted flag: %zu", encrypted);
	else
		print_info("no explicit encrypted partition flags found");

	print_info("flash-encryption eFuse state cannot be proven from firmware alone");
}

static void
scan_rollback(const struct image *image)
{
	uint32_t version;
	if (!metadata_secure_version(image, &version)) {
		print_info("anti-rollback versioning could not be assessed");
		return;
	}

	if (version == 0)
		print_bad("anti-rollback secure version is 0");
	else
		print_good("anti-rollback secure version is %u", version);
	print_info("anti-rollback enforcement depends on device eFuse state");
}

int
security_scan(const struct image *image)
{
	scan_secure_boot(image);
	scan_flash_encryption(image);
	scan_rollback(image);
	return 0;
}
