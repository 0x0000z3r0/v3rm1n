#include "metadata.h"
#include "bytes.h"
#include "partition.h"
#include "print.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define APP_DESC_MAGIC 0xabcd5432
#define APP_DESC_SIZE 256
#define OTA_ENTRY_SIZE 32
#define OTA_SECTOR_SIZE 0x1000
#define PART_TYPE_APP 0x00
#define PART_TYPE_DATA 0x01
#define PART_SUBTYPE_OTA_DATA 0x00
#define PART_SUBTYPE_OTA_MIN 0x10
#define PART_SUBTYPE_OTA_MAX 0x1f
#define PART_FLAG_ENCRYPTED 0x01

struct ota_entry {
	uint32_t sequence;
	uint32_t state;
	bool valid;
};

static bool
copy_field(char *output, size_t output_size, const uint8_t *field, size_t field_size)
{
	size_t length = 0;
	while (length < field_size && field[length] != '\0') {
		if (field[length] < 0x20 || field[length] > 0x7e)
			return false;
		length++;
	}
	if (length == field_size || length >= output_size)
		return false;

	for (size_t i = 0; i < length; i++)
		output[i] = (char)field[i];
	output[length] = '\0';
	return true;
}

static void
print_hash(const uint8_t *hash)
{
	bool empty = true;
	for (size_t i = 0; i < 32; i++) {
		if (hash[i] != 0) {
			empty = false;
			break;
		}
	}
	if (empty) {
		print_info("application ELF SHA-256 is not populated");
		return;
	}

	char text[65];
	for (size_t i = 0; i < 32; i++)
		snprintf(text + i * 2, 3, "%02x", hash[i]);
	print_info("application ELF SHA-256: %s", text);
}

static bool
scan_descriptor(const struct image *image, size_t offset)
{
	if (!bytes_has(image, offset, APP_DESC_SIZE))
		return false;

	const uint8_t *descriptor = image->data + offset;
	if (read_u32(descriptor, false) != APP_DESC_MAGIC)
		return false;

	char version[32];
	char project[32];
	char time[16];
	char date[16];
	char idf[32];
	if (!copy_field(version, sizeof(version), descriptor + 16, 32) || !copy_field(project, sizeof(project), descriptor + 48, 32) || !copy_field(time, sizeof(time), descriptor + 80, 16) || !copy_field(date, sizeof(date), descriptor + 96, 16) || !copy_field(idf, sizeof(idf), descriptor + 112, 32))
		return false;

	print_info("application metadata is at 0x%zx", offset);
	print_info("project: %s", project[0] == '\0' ? "<unset>" : project);
	print_info("application version: %s", version[0] == '\0' ? "<unset>" : version);
	print_info("build: %s %s", date[0] == '\0' ? "<date unavailable>" : date, time[0] == '\0' ? "<time unavailable>" : time);
	print_info("ESP-IDF version: %s", idf[0] == '\0' ? "<unset>" : idf);

	uint32_t secure_version = read_u32(descriptor + 4, false);
	print_info("secure version: %u (device eFuse state unavailable)", secure_version);
	print_hash(descriptor + 144);

	uint16_t min_efuse = read_u16(descriptor + 176, false);
	uint16_t max_efuse = read_u16(descriptor + 178, false);
	if (min_efuse != 0)
		print_info("minimum eFuse block revision: %u.%u", min_efuse / 100, min_efuse % 100);
	if (max_efuse != 0)
		print_info("maximum eFuse block revision: %u.%u", max_efuse / 100, max_efuse % 100);
	return true;
}

static const char *
ota_state(uint32_t state)
{
	switch (state) {
	case 0:
		return "new";
	case 1:
		return "pending verification";
	case 2:
		return "valid";
	case 3:
		return "invalid";
	case 4:
		return "aborted";
	case UINT32_MAX:
		return "undefined";
	default:
		return "unknown";
	}
}

static bool
all_erased(const uint8_t *data, size_t length)
{
	for (size_t i = 0; i < length; i++) {
		if (data[i] != 0xff)
			return false;
	}
	return true;
}

static bool
read_ota_entry(const struct image *image, size_t offset, unsigned int copy, struct ota_entry *entry)
{
	if (!bytes_has(image, offset, OTA_ENTRY_SIZE)) {
		print_bad("OTA metadata copy %u is truncated", copy);
		return false;
	}

	const uint8_t *data = image->data + offset;
	if (all_erased(data, OTA_ENTRY_SIZE)) {
		print_info("OTA metadata copy %u is erased", copy);
		return false;
	}

	entry->sequence = read_u32(data, false);
	entry->state = read_u32(data + 24, false);
	uint32_t stored_crc = read_u32(data + 28, false);
	entry->valid = stored_crc == crc32_le(UINT32_MAX, data, 4);

	if (!entry->valid)
		print_bad("OTA metadata copy %u has an invalid CRC", copy);
	else if (entry->state == 3 || entry->state == 4)
		print_bad("OTA metadata copy %u: sequence %u, state %s", copy, entry->sequence, ota_state(entry->state));
	else
		print_info("OTA metadata copy %u: sequence %u, state %s", copy, entry->sequence, ota_state(entry->state));
	return entry->valid;
}

static void
scan_ota(const struct image *image)
{
	struct partition ota;
	if (!partition_get(image, PART_TYPE_DATA, PART_SUBTYPE_OTA_DATA, &ota)) {
		print_info("OTA metadata is not available in this image");
		return;
	}
	if ((ota.flags & PART_FLAG_ENCRYPTED) != 0) {
		print_info("OTA metadata partition is marked encrypted");
		return;
	}
	if (!bytes_has(image, ota.offset, ota.size)) {
		print_info("OTA partition is listed, but its contents are not present");
		return;
	}

	struct ota_entry entries[2] = {0};
	bool first = read_ota_entry(image, ota.offset, 0, &entries[0]);
	bool second = read_ota_entry(image, ota.offset + OTA_SECTOR_SIZE, 1, &entries[1]);
	if (!first && !second)
		return;

	size_t active = !second || (first && entries[0].sequence >= entries[1].sequence) ? 0 : 1;
	uint32_t state = entries[active].state;
	if (state == 3 || state == 4)
		return;

	size_t slots = partition_count(image, PART_TYPE_APP, PART_SUBTYPE_OTA_MIN, PART_SUBTYPE_OTA_MAX);
	if (slots != 0 && entries[active].sequence != 0 && entries[active].sequence != UINT32_MAX)
		print_info("selected OTA slot: ota-%zu", (entries[active].sequence - 1) % slots);
}

static void
scan_components(const struct image *image)
{
	static const struct {
		const char *name;
		const char *needle;
	} components[] = {
	    {"ESP-IDF", "esp-idf"},
	    {"FreeRTOS", "freertos"},
	    {"lwIP", "lwip"},
	    {"Mbed TLS", "mbedtls"},
	    {"TinyUSB", "tinyusb"},
	    {"NimBLE", "nimble"},
	    {"Bluedroid", "bluedroid"},
	    {"ESP-MQTT", "mqtt_client"},
	    {"cJSON", "cjson"},
	    {"SPIFFS", "spiffs"},
	    {"LittleFS", "littlefs"},
	    {"FATFS", "fatfs"},
	    {"OpenSSL", "openssl"},
	    {"wolfSSL", "wolfssl"},
	    {"zlib", "zlib"},
	};

	for (size_t i = 0; i < sizeof(components) / sizeof(components[0]); i++) {
		if (bytes_contains_ci(image->data, image->size, components[i].needle))
			print_info("component fingerprint: %s", components[i].name);
	}
}

bool
metadata_secure_version(const struct image *image, uint32_t *version)
{
	bool found = false;
	*version = 0;

	for (size_t offset = 0; bytes_has(image, offset, APP_DESC_SIZE); offset++) {
		const uint8_t *descriptor = image->data + offset;
		if (read_u32(descriptor, false) != APP_DESC_MAGIC)
			continue;

		char project[32];
		char idf[32];
		if (!copy_field(project, sizeof(project), descriptor + 48, 32) || !copy_field(idf, sizeof(idf), descriptor + 112, 32))
			continue;

		uint32_t current = read_u32(descriptor + 4, false);
		if (!found || current > *version)
			*version = current;
		found = true;
		offset += APP_DESC_SIZE - 1;
	}

	return found;
}

bool
metadata_idf_version(const struct image *image, char *version, size_t size)
{
	for (size_t offset = 0; bytes_has(image, offset, APP_DESC_SIZE); offset++) {
		const uint8_t *descriptor = image->data + offset;
		if (read_u32(descriptor, false) != APP_DESC_MAGIC)
			continue;
		if (copy_field(version, size, descriptor + 112, 32))
			return true;
	}

	return false;
}

int
metadata_scan(const struct image *image)
{
	size_t descriptors = 0;
	for (size_t offset = 0; bytes_has(image, offset, 4); offset++) {
		if (read_u32(image->data + offset, false) == APP_DESC_MAGIC && scan_descriptor(image, offset)) {
			descriptors++;
			offset += APP_DESC_SIZE - 1;
		}
	}

	if (descriptors == 0)
		print_info("application metadata not found");
	else
		print_info("application descriptors: %zu", descriptors);

	scan_ota(image);
	scan_components(image);
	return 0;
}
