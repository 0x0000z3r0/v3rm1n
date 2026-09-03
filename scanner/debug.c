#include "debug.h"
#include "bytes.h"
#include "elf.h"
#include "print.h"

#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define MIN_STRING 4
#define MAX_EXAMPLES 5

struct findings {
	size_t paths;
	size_t assertions;
	size_t logs;
	size_t consoles;
	size_t credentials;
};

static bool
starts_with(const char *text, const char *prefix)
{
	return strncmp(text, prefix, strlen(prefix)) == 0;
}

static void
scan_elf_sections(const struct image *image)
{
	if (!elf_is(image))
		return;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		print_bad("ELF library initialization failed");
		return;
	}

	Elf *elf = elf_memory((char *)image->data, image->size);
	if (elf == NULL || elf_kind(elf) != ELF_K_ELF) {
		print_bad("ELF debug analysis failed");
		elf_end(elf);
		return;
	}

	size_t string_index;
	if (elf_getshdrstrndx(elf, &string_index) != 0) {
		print_bad("ELF section names are invalid");
		elf_end(elf);
		return;
	}

	size_t symbols = 0;
	size_t dwarf_sections = 0;
	uint64_t dwarf_size = 0;
	Elf_Scn *section = NULL;
	while ((section = elf_nextscn(elf, section)) != NULL) {
		GElf_Shdr header;
		if (gelf_getshdr(section, &header) == NULL)
			continue;

		const char *name = elf_strptr(elf, string_index, header.sh_name);
		if (name == NULL)
			name = "<invalid>";

		if (header.sh_type == SHT_SYMTAB && header.sh_entsize != 0)
			symbols += header.sh_size / header.sh_entsize;
		if (starts_with(name, ".debug_") || starts_with(name, ".zdebug_") || strcmp(name, ".gdb_index") == 0) {
			dwarf_sections++;
			dwarf_size += header.sh_size;
		}
	}

	if (symbols == 0)
		print_good("ELF is stripped");
	else
		print_bad("ELF is not stripped (%zu symbols)", symbols);

	if (dwarf_sections == 0)
		print_good("DWARF debug sections are absent");
	else
		print_bad("DWARF debug information is present (%zu sections, %llu bytes)", dwarf_sections, (unsigned long long)dwarf_size);

	elf_end(elf);
}

static bool
has_source_extension(const uint8_t *data, size_t length)
{
	static const char *const extensions[] = {
	    ".c",
	    ".h",
	    ".cc",
	    ".cpp",
	    ".cxx",
	    ".s",
	};

	bool has_separator = false;
	for (size_t i = 0; i < length; i++) {
		if (data[i] == '/' || data[i] == '\\') {
			has_separator = true;
			break;
		}
	}
	if (!has_separator)
		return false;

	for (size_t i = 0; i < sizeof(extensions) / sizeof(extensions[0]); i++) {
		size_t search = 0;
		while (search < length) {
			size_t found = bytes_find_ci(data + search, length - search, extensions[i]);
			if (found == SIZE_MAX)
				break;

			size_t end = search + found + strlen(extensions[i]);
			if (end == length || data[end] == ':' || data[end] == ')' || data[end] == ' ')
				return true;
			search += found + 1;
		}
	}

	return false;
}

static bool
has_any(const uint8_t *data, size_t length, const char *const *patterns, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		if (bytes_contains_ci(data, length, patterns[i]))
			return true;
	}
	return false;
}

static void
scan_debug_string(const uint8_t *data, size_t length, size_t offset, struct findings *findings)
{
	if (has_source_extension(data, length)) {
		if (findings->paths < MAX_EXAMPLES)
			print_text(true, "source path", data, length, offset);
		findings->paths++;
	}

	static const char *const assertion_patterns[] = {
	    "assert failed",
	    "assertion failed",
	    "abort() was called",
	    "__assert_func",
	};
	if (has_any(data, length, assertion_patterns, sizeof(assertion_patterns) / sizeof(assertion_patterns[0]))) {
		if (findings->assertions < MAX_EXAMPLES)
			print_text(true, "assertion string", data, length, offset);
		findings->assertions++;
	}

	static const char *const log_patterns[] = {
	    "[debug]",
	    "debug:",
	    "verbose:",
	    "esp_logv",
	    "log_local_level",
	};
	if (has_any(data, length, log_patterns, sizeof(log_patterns) / sizeof(log_patterns[0]))) {
		if (findings->logs < MAX_EXAMPLES)
			print_text(true, "debug log indicator", data, length, offset);
		findings->logs++;
	}

	static const char *const console_patterns[] = {
	    "esp_console",
	    "debug shell",
	    "uart console",
	    "console command",
	    "shell command",
	};
	if (has_any(data, length, console_patterns, sizeof(console_patterns) / sizeof(console_patterns[0]))) {
		if (findings->consoles < MAX_EXAMPLES)
			print_text(true, "debug console indicator", data, length, offset);
		findings->consoles++;
	}

	static const char *const credential_patterns[] = {
	    "admin:admin",
	    "root:root",
	    "test:test",
	    "admin/admin",
	    "default_password",
	    "test_password",
	};
	if (has_any(data, length, credential_patterns, sizeof(credential_patterns) / sizeof(credential_patterns[0]))) {
		if (findings->credentials < MAX_EXAMPLES)
			print_text(true, "test/default credential", data, length, offset);
		findings->credentials++;
	}
}

static void
print_summary(const struct findings *findings)
{
	if (findings->paths != 0)
		print_bad("source paths found: %zu", findings->paths);
	if (findings->assertions != 0)
		print_bad("assertion strings found: %zu", findings->assertions);
	if (findings->logs != 0)
		print_bad("debug log indicators found: %zu", findings->logs);
	if (findings->consoles != 0)
		print_bad("debug console indicators found: %zu", findings->consoles);
	if (findings->credentials != 0)
		print_bad("test/default credentials found: %zu", findings->credentials);

	if (findings->paths == 0 && findings->assertions == 0 && findings->logs == 0 && findings->consoles == 0 && findings->credentials == 0)
		print_good("debug artifact strings not found");
}

int
debug_scan(const struct image *image)
{
	scan_elf_sections(image);

	struct findings findings = {0};
	for (size_t offset = 0; offset < image->size;) {
		if (image->data[offset] < 0x20 || image->data[offset] > 0x7e) {
			offset++;
			continue;
		}

		size_t end = offset;
		while (end < image->size && image->data[end] >= 0x20 && image->data[end] <= 0x7e)
			end++;

		if (end - offset >= MIN_STRING)
			scan_debug_string(image->data + offset, end - offset, offset, &findings);
		offset = end;
	}

	print_summary(&findings);
	return 0;
}
