#include "vuln.h"
#include "bytes.h"
#include "database.h"
#include "elf.h"
#include "metadata.h"
#include "print.h"

#include <json-c/json.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_CVES 128
#define MAX_DATABASE_SIZE (1024 * 1024)

struct semver {
	unsigned int major;
	unsigned int minor;
	unsigned int patch;
};

struct rule {
	const char *id;
	const char *component;
	const char *symbol;
	const char *marker;
	const char *summary;
	const char *advisory;
	struct semver first;
	struct semver fixed;
	bool symbol_found;
};

struct symbol_context {
	struct rule *rules;
	size_t count;
};

static bool
parse_number(const char **text, unsigned int *number)
{
	if (**text < '0' || **text > '9')
		return false;

	*number = 0;
	while (**text >= '0' && **text <= '9') {
		unsigned int digit = (unsigned int)(**text - '0');
		if (*number > (UINT32_MAX - digit) / 10)
			return false;
		*number = *number * 10 + digit;
		(*text)++;
	}
	return true;
}

static bool
parse_version(const char *text, struct semver *version)
{
	while (*text != '\0' && (*text < '0' || *text > '9'))
		text++;
	if (!parse_number(&text, &version->major) || *text++ != '.')
		return false;
	if (!parse_number(&text, &version->minor))
		return false;

	version->patch = 0;
	if (*text == '.') {
		text++;
		if (!parse_number(&text, &version->patch))
			return false;
	}
	return true;
}

static int
compare_version(const struct semver *left, const struct semver *right)
{
	if (left->major != right->major)
		return left->major < right->major ? -1 : 1;
	if (left->minor != right->minor)
		return left->minor < right->minor ? -1 : 1;
	if (left->patch != right->patch)
		return left->patch < right->patch ? -1 : 1;
	return 0;
}

static bool
affected(const struct semver *version, const struct rule *rule)
{
	return compare_version(version, &rule->first) >= 0 && compare_version(version, &rule->fixed) < 0;
}

static const char *
json_string(json_object *object, const char *name)
{
	json_object *value;
	if (!json_object_object_get_ex(object, name, &value) || !json_object_is_type(value, json_type_string))
		return NULL;

	const char *text = json_object_get_string(value);
	if (text == NULL || text[0] == '\0' || strlen(text) > 256)
		return NULL;
	return text;
}

static size_t
load_rules(json_object *root, struct rule *rules)
{
	json_object *schema;
	json_object *entries;
	if (!json_object_object_get_ex(root, "schema", &schema) || json_object_get_int(schema) != 1 || !json_object_object_get_ex(root, "cves", &entries) || !json_object_is_type(entries, json_type_array)) {
		print_bad("invalid CVE database schema");
		return 0;
	}

	size_t count = json_object_array_length(entries);
	if (count > MAX_CVES) {
		print_bad("CVE database has too many records (maximum %u)", MAX_CVES);
		return 0;
	}

	size_t loaded = 0;
	for (size_t i = 0; i < count; i++) {
		json_object *entry = json_object_array_get_idx(entries, i);
		if (!json_object_is_type(entry, json_type_object))
			continue;

		struct rule rule = {
		    .id = json_string(entry, "id"),
		    .component = json_string(entry, "component"),
		    .symbol = json_string(entry, "symbol"),
		    .marker = json_string(entry, "marker"),
		    .summary = json_string(entry, "summary"),
		    .advisory = json_string(entry, "advisory"),
		};
		const char *first = json_string(entry, "first");
		const char *fixed = json_string(entry, "fixed");
		if (rule.id == NULL || rule.component == NULL || rule.symbol == NULL || rule.marker == NULL || rule.summary == NULL || rule.advisory == NULL || first == NULL || fixed == NULL || !parse_version(first, &rule.first) || !parse_version(fixed, &rule.fixed) || compare_version(&rule.first, &rule.fixed) >= 0) {
			print_bad("invalid CVE database record at index %zu", i);
			continue;
		}

		rules[loaded++] = rule;
	}

	return loaded;
}

static json_object *
load_database(struct rule *rules, size_t *count)
{
	char path[4096];
	if (!database_file(path, sizeof(path), "cves.json")) {
		print_bad("CVE database path is too long");
		return NULL;
	}

	struct stat info;
	if (stat(path, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0 || info.st_size > MAX_DATABASE_SIZE) {
		print_bad("invalid CVE database file: %s", path);
		return NULL;
	}

	json_object *root = json_object_from_file(path);
	if (root == NULL) {
		print_bad("cannot parse CVE database: %s", path);
		return NULL;
	}

	*count = load_rules(root, rules);
	if (*count == 0) {
		print_bad("CVE database contains no valid records");
		json_object_put(root);
		return NULL;
	}
	return root;
}

static void
match_symbol(const char *name, void *context)
{
	struct symbol_context *symbols = context;
	for (size_t i = 0; i < symbols->count; i++) {
		if (strstr(name, symbols->rules[i].symbol) != NULL)
			symbols->rules[i].symbol_found = true;
	}
}

int
vuln_scan(const struct image *image)
{
	struct rule rules[MAX_CVES] = {0};
	size_t rule_count = 0;
	json_object *database = load_database(rules, &rule_count);
	if (database == NULL)
		return -1;

	char idf_version[32];
	if (!metadata_idf_version(image, idf_version, sizeof(idf_version))) {
		print_info("known-vulnerability scan skipped: ESP-IDF version unavailable");
		json_object_put(database);
		return 0;
	}

	struct semver version;
	if (!parse_version(idf_version, &version)) {
		print_bad("cannot parse ESP-IDF version: %s", idf_version);
		json_object_put(database);
		return 0;
	}

	struct symbol_context symbols = {
	    .rules = rules,
	    .count = rule_count,
	};
	bool has_full_symbols = false;
	elf_symbols(image, match_symbol, &symbols, &has_full_symbols);

	size_t matches = 0;
	size_t version_only = 0;
	for (size_t i = 0; i < rule_count; i++) {
		if (!affected(&version, &rules[i]))
			continue;

		bool marker = bytes_contains_ci(image->data, image->size, rules[i].marker);
		if (!rules[i].symbol_found && !marker) {
			version_only++;
			continue;
		}

		const char *confidence = rules[i].symbol_found && has_full_symbols ? "high" : "low";
		print_bad("%s: %s (%s, confidence %s)", rules[i].id, rules[i].summary, rules[i].component, confidence);
		print_info("%s fixed in ESP-IDF %u.%u.%u; advisory %s", rules[i].id, rules[i].fixed.major, rules[i].fixed.minor, rules[i].fixed.patch, rules[i].advisory);
		matches++;
	}

	print_info("local CVE matches: %zu", matches);
	if (version_only != 0)
		print_info("version-only candidates without component evidence: %zu", version_only);
	if (has_full_symbols)
		print_info("CVE component confidence is high with full ELF symbols");
	else
		print_info("CVE component confidence is limited without full ELF symbols");
	print_info("local CVE records loaded: %zu", rule_count);

	json_object_put(database);
	return 0;
}
