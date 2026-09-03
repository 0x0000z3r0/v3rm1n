#include "partition.h"
#include "bytes.h"
#include "print.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define PART_MAGIC 0x50aa
#define PART_MD5_MAGIC 0xebeb
#define PART_SIZE 32
#define PART_MAX 95
#define PART_ENCRYPTED 0x1
#define PART_READ_ONLY 0x2

static const char *
type_name(uint8_t type)
{
	switch (type) {
	case 0x00:
		return "app";
	case 0x01:
		return "data";
	default:
		return "custom";
	}
}

static void
copy_label(char *label, const uint8_t *data)
{
	size_t length = 0;
	while (length < 16 && data[length] != '\0') {
		uint8_t byte = data[length];
		label[length] = byte >= 0x20 && byte <= 0x7e ? (char)byte : '?';
		length++;
	}
	label[length] = '\0';
}

static void
load_partition(const uint8_t *entry, struct partition *partition)
{
	partition->type = entry[2];
	partition->subtype = entry[3];
	partition->offset = read_u32(entry + 4, false);
	partition->size = read_u32(entry + 8, false);
	partition->flags = read_u32(entry + 28, false);
	copy_label(partition->label, entry + 12);
}

static void
subtype_name(uint8_t type, uint8_t subtype, char *name, size_t size)
{
	if (type == 0x00) {
		if (subtype == 0x00)
			snprintf(name, size, "factory");
		else if (subtype >= 0x10 && subtype <= 0x1f)
			snprintf(name, size, "ota-%u", subtype - 0x10);
		else if (subtype == 0x20)
			snprintf(name, size, "test");
		else
			snprintf(name, size, "0x%02x", subtype);
		return;
	}

	if (type != 0x01) {
		snprintf(name, size, "0x%02x", subtype);
		return;
	}

	static const struct {
		uint8_t subtype;
		const char *name;
	} names[] = {
	    {0x00, "ota"},
	    {0x01, "phy"},
	    {0x02, "nvs"},
	    {0x03, "core-dump"},
	    {0x04, "nvs-keys"},
	    {0x05, "efuse"},
	    {0x80, "esphttpd"},
	    {0x81, "fat"},
	    {0x82, "spiffs"},
	    {0x83, "littlefs"},
	};

	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (names[i].subtype == subtype) {
			snprintf(name, size, "%s", names[i].name);
			return;
		}
	}

	snprintf(name, size, "0x%02x", subtype);
}

static bool
first_entry_valid(const struct image *image, size_t offset)
{
	if (!bytes_has(image, offset, PART_SIZE) || read_u16(image->data + offset, false) != PART_MAGIC)
		return false;

	uint32_t part_offset = read_u32(image->data + offset + 4, false);
	uint32_t part_size = read_u32(image->data + offset + 8, false);
	return part_offset >= 0x1000 && part_offset % 0x1000 == 0 && part_size != 0;
}

static size_t
find_table(const struct image *image)
{
	if (first_entry_valid(image, 0))
		return 0;

	for (size_t offset = 0x1000; bytes_has(image, offset, PART_SIZE); offset += 0x1000) {
		if (first_entry_valid(image, offset))
			return offset;
	}

	return SIZE_MAX;
}

bool
partition_get(const struct image *image, uint8_t type, uint8_t subtype, struct partition *partition)
{
	size_t table_offset = find_table(image);
	if (table_offset == SIZE_MAX)
		return false;

	for (size_t i = 0; i < PART_MAX; i++) {
		size_t offset = table_offset + i * PART_SIZE;
		if (!bytes_has(image, offset, PART_SIZE))
			return false;

		const uint8_t *entry = image->data + offset;
		if (read_u16(entry, false) != PART_MAGIC)
			return false;
		if (entry[2] == type && entry[3] == subtype) {
			load_partition(entry, partition);
			return true;
		}
	}

	return false;
}

size_t
partition_count(const struct image *image, uint8_t type, uint8_t subtype_min, uint8_t subtype_max)
{
	size_t table_offset = find_table(image);
	if (table_offset == SIZE_MAX)
		return 0;

	size_t count = 0;
	for (size_t i = 0; i < PART_MAX; i++) {
		size_t offset = table_offset + i * PART_SIZE;
		if (!bytes_has(image, offset, PART_SIZE))
			break;

		const uint8_t *entry = image->data + offset;
		if (read_u16(entry, false) != PART_MAGIC)
			break;
		if (entry[2] == type && entry[3] >= subtype_min && entry[3] <= subtype_max)
			count++;
	}

	return count;
}

size_t
partition_count_flags(const struct image *image, uint32_t flags)
{
	size_t table_offset = find_table(image);
	if (table_offset == SIZE_MAX)
		return 0;

	size_t count = 0;
	for (size_t i = 0; i < PART_MAX; i++) {
		size_t offset = table_offset + i * PART_SIZE;
		if (!bytes_has(image, offset, PART_SIZE))
			break;

		const uint8_t *entry = image->data + offset;
		if (read_u16(entry, false) != PART_MAGIC)
			break;
		if ((read_u32(entry + 28, false) & flags) == flags)
			count++;
	}

	return count;
}

static bool
overlaps(const struct partition *partitions, size_t count, uint32_t offset, uint32_t size)
{
	uint64_t end = (uint64_t)offset + size;
	for (size_t i = 0; i < count; i++) {
		uint64_t other_end = (uint64_t)partitions[i].offset + partitions[i].size;
		if (offset < other_end && partitions[i].offset < end)
			return true;
	}

	return false;
}

int
partition_scan(const struct image *image)
{
	size_t table_offset = find_table(image);
	if (table_offset == SIZE_MAX) {
		print_info("partition table not found");
		return 0;
	}

	print_info("partition table is at 0x%zx", table_offset);

	struct partition partitions[PART_MAX] = {0};
	size_t count = 0;
	bool has_md5 = false;
	for (size_t i = 0; i < PART_MAX; i++) {
		size_t offset = table_offset + i * PART_SIZE;
		if (!bytes_has(image, offset, PART_SIZE)) {
			print_bad("partition table is truncated");
			break;
		}

		const uint8_t *entry = image->data + offset;
		uint16_t magic = read_u16(entry, false);
		if (magic == 0xffff)
			break;
		if (magic == PART_MD5_MAGIC) {
			has_md5 = true;
			break;
		}
		if (magic != PART_MAGIC) {
			print_bad("partition entry %zu has invalid magic", i);
			break;
		}

		load_partition(entry, &partitions[count]);
		uint8_t type = partitions[count].type;
		uint8_t subtype = partitions[count].subtype;
		uint32_t part_offset = partitions[count].offset;
		uint32_t part_size = partitions[count].size;
		uint32_t flags = partitions[count].flags;
		const char *label = partitions[count].label[0] == '\0' ? "<unnamed>" : partitions[count].label;

		char subtype_label[16];
		subtype_name(type, subtype, subtype_label, sizeof(subtype_label));
		print_info("partition %s: %s/%s, offset 0x%08x, size 0x%x", label, type_name(type), subtype_label, part_offset, part_size);

		if (part_size == 0)
			print_bad("partition %s is empty", label);
		if (type == 0x00 && part_offset % 0x10000 != 0)
			print_bad("app partition %s is not 64 KB aligned", label);
		else if (type != 0x00 && part_offset % 0x1000 != 0)
			print_bad("partition %s is not 4 KB aligned", label);
		if (overlaps(partitions, count, part_offset, part_size))
			print_bad("partition %s overlaps an earlier partition", label);
		if ((flags & PART_ENCRYPTED) != 0)
			print_info("partition %s has the encrypted flag", label);
		if ((flags & PART_READ_ONLY) != 0)
			print_good("partition %s is marked read-only", label);

		count++;
	}

	print_info("partitions: %zu", count);
	if (has_md5)
		print_info("partition table has an MD5 record");
	else
		print_info("partition table has no MD5 record");

	return 0;
}
