#include "unsafe.h"
#include "database.h"
#include "elf.h"
#include "print.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_APIS 256
#define MAX_API_NAME 63

struct unsafe_api {
	char name[MAX_API_NAME + 1];
	bool symbol_found;
};

struct symbol_context {
	struct unsafe_api *apis;
	size_t count;
};

static bool
valid_name(const char *name)
{
	if (name[0] == '\0')
		return false;

	for (size_t i = 0; name[i] != '\0'; i++) {
		if (!isalnum((unsigned char)name[i]) && name[i] != '_')
			return false;
	}
	return true;
}

static bool
duplicate(const struct unsafe_api *apis, size_t count, const char *name)
{
	for (size_t i = 0; i < count; i++) {
		if (strcmp(apis[i].name, name) == 0)
			return true;
	}
	return false;
}

static size_t
load_apis(struct unsafe_api *apis)
{
	char path[4096];
	if (!database_file(path, sizeof(path), "unsafe-apis.txt")) {
		print_bad("unsafe API database path is too long");
		return 0;
	}

	FILE *file = fopen(path, "r");
	if (file == NULL) {
		print_bad("cannot read unsafe API database: %s", path);
		return 0;
	}

	size_t count = 0;
	size_t line_number = 0;
	char line[256];
	while (fgets(line, sizeof(line), file) != NULL) {
		line_number++;
		size_t length = strlen(line);
		if (length != 0 && line[length - 1] != '\n' && !feof(file)) {
			print_bad("unsafe API database line %zu is too long", line_number);
			count = 0;
			break;
		}

		while (length != 0 && isspace((unsigned char)line[length - 1]))
			line[--length] = '\0';
		char *name = line;
		while (isspace((unsigned char)*name))
			name++;
		if (*name == '\0' || *name == '#')
			continue;
		size_t name_length = strlen(name);
		if (!valid_name(name) || name_length > MAX_API_NAME) {
			print_bad("invalid unsafe API name at line %zu", line_number);
			continue;
		}
		if (duplicate(apis, count, name))
			continue;
		if (count == MAX_APIS) {
			print_bad("unsafe API database has too many entries");
			count = 0;
			break;
		}

		memcpy(apis[count].name, name, name_length + 1);
		count++;
	}

	if (ferror(file)) {
		print_bad("error reading unsafe API database: %s", path);
		count = 0;
	}
	fclose(file);
	return count;
}

static void
match_symbol(const char *name, void *context)
{
	struct symbol_context *symbols = context;
	for (size_t i = 0; i < symbols->count; i++) {
		if (strcmp(name, symbols->apis[i].name) == 0)
			symbols->apis[i].symbol_found = true;
	}
}

static bool
binary_name(const struct image *image, const char *name)
{
	size_t length = strlen(name);
	if (length > image->size)
		return false;

	for (size_t offset = 0; offset <= image->size - length; offset++) {
		if (memcmp(image->data + offset, name, length) != 0)
			continue;

		bool left = offset == 0 || image->data[offset - 1] == '\0';
		size_t end = offset + length;
		bool right = end == image->size || image->data[end] == '\0';
		if (left && right)
			return true;
	}

	return false;
}

int
unsafe_scan(const struct image *image)
{
	struct unsafe_api apis[MAX_APIS] = {0};
	size_t api_count = load_apis(apis);
	if (api_count == 0) {
		print_bad("unsafe API database contains no valid entries");
		return -1;
	}

	struct symbol_context symbols = {
	    .apis = apis,
	    .count = api_count,
	};
	bool has_full_symbols = false;
	elf_symbols(image, match_symbol, &symbols, &has_full_symbols);

	size_t findings = 0;
	for (size_t i = 0; i < api_count; i++) {
		if (apis[i].symbol_found) {
			print_bad("unsafe API %s (symbol confidence %s)", apis[i].name, has_full_symbols ? "high" : "medium");
			findings++;
			continue;
		}
		if (!has_full_symbols && binary_name(image, apis[i].name)) {
			print_bad("possible unsafe API %s (signature confidence low)", apis[i].name);
			findings++;
		}
	}

	if (findings == 0) {
		if (has_full_symbols)
			print_good("unsafe API symbols not found");
		else
			print_info("unsafe API signatures not found (confidence low)");
	} else {
		print_bad("unsafe API findings: %zu", findings);
	}
	print_info("unsafe API rules loaded: %zu", api_count);
	return 0;
}
