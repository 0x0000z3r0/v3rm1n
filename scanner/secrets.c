#include "secrets.h"
#include "bytes.h"
#include "database.h"
#include "print.h"

#include <ctype.h>
#include <json-c/json.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define MIN_STRING 4
#define MAX_DER_SIZE (1024 * 1024)
#define MAX_DATABASE_SIZE (1024 * 1024)
#define MAX_RULES 128
#define MAX_RULE_LENGTH 128

struct text_list {
	const char *values[MAX_RULES];
	size_t count;
};

struct secret_rules {
	struct text_list token_prefixes;
	struct text_list secret_keys;
	struct text_list username_keys;
	struct text_list ssid_keys;
	struct text_list secure_url_schemes;
	struct text_list insecure_url_schemes;
	struct text_list domain_suffixes;
	struct text_list pem_private_key_markers;
	struct text_list pem_certificate_markers;
};

static bool has_value(const uint8_t *data, size_t length, const char *key);

static bool
load_list(json_object *root, const char *name, struct text_list *list)
{
	json_object *entries;
	if (!json_object_object_get_ex(root, name, &entries) || !json_object_is_type(entries, json_type_array)) {
		print_bad("secret database field is missing or invalid: %s", name);
		return false;
	}

	size_t count = json_object_array_length(entries);
	if (count > MAX_RULES) {
		print_bad("secret database field %s has too many entries (maximum %u)", name, MAX_RULES);
		return false;
	}

	for (size_t i = 0; i < count; i++) {
		json_object *entry = json_object_array_get_idx(entries, i);
		if (!json_object_is_type(entry, json_type_string)) {
			print_bad("invalid secret database entry %s[%zu]", name, i);
			return false;
		}

		const char *text = json_object_get_string(entry);
		if (text == NULL || text[0] == '\0' || strlen(text) > MAX_RULE_LENGTH) {
			print_bad("invalid secret database entry %s[%zu]", name, i);
			return false;
		}
		list->values[list->count++] = text;
	}

	return true;
}

static json_object *
load_database(struct secret_rules *rules, size_t *count)
{
	char path[4096];
	if (!database_file(path, sizeof(path), "secrets.json")) {
		print_bad("secret database path is too long");
		return NULL;
	}

	struct stat info;
	if (stat(path, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0 || info.st_size > MAX_DATABASE_SIZE) {
		print_bad("invalid secret database file: %s", path);
		return NULL;
	}

	json_object *root = json_object_from_file(path);
	if (root == NULL) {
		print_bad("cannot parse secret database: %s", path);
		return NULL;
	}

	json_object *schema;
	bool valid = json_object_object_get_ex(root, "schema", &schema) && json_object_get_int(schema) == 1;
	valid = valid && load_list(root, "token_prefixes", &rules->token_prefixes);
	valid = valid && load_list(root, "secret_keys", &rules->secret_keys);
	valid = valid && load_list(root, "username_keys", &rules->username_keys);
	valid = valid && load_list(root, "ssid_keys", &rules->ssid_keys);
	valid = valid && load_list(root, "secure_url_schemes", &rules->secure_url_schemes);
	valid = valid && load_list(root, "insecure_url_schemes", &rules->insecure_url_schemes);
	valid = valid && load_list(root, "domain_suffixes", &rules->domain_suffixes);
	valid = valid && load_list(root, "pem_private_key_markers", &rules->pem_private_key_markers);
	valid = valid && load_list(root, "pem_certificate_markers", &rules->pem_certificate_markers);
	if (!valid) {
		print_bad("invalid secret database schema");
		json_object_put(root);
		return NULL;
	}

	*count = rules->token_prefixes.count + rules->secret_keys.count + rules->username_keys.count + rules->ssid_keys.count + rules->secure_url_schemes.count + rules->insecure_url_schemes.count + rules->domain_suffixes.count + rules->pem_private_key_markers.count + rules->pem_certificate_markers.count;
	return root;
}

static bool
contains_any(const uint8_t *data, size_t length, const struct text_list *list)
{
	for (size_t i = 0; i < list->count; i++) {
		if (bytes_contains_ci(data, length, list->values[i]))
			return true;
	}
	return false;
}

static bool
has_any_value(const uint8_t *data, size_t length, const struct text_list *list)
{
	for (size_t i = 0; i < list->count; i++) {
		if (has_value(data, length, list->values[i]))
			return true;
	}
	return false;
}

static bool
has_value(const uint8_t *data, size_t length, const char *key)
{
	size_t search = 0;
	while (search < length) {
		size_t found = bytes_find_ci(data + search, length - search, key);
		if (found == SIZE_MAX)
			return false;

		size_t position = search + found + strlen(key);
		while (position < length && (data[position] == ' ' || data[position] == '\t' || data[position] == '"' || data[position] == '\''))
			position++;
		if (position < length && (data[position] == '=' || data[position] == ':')) {
			position++;
			while (position < length && (data[position] == ' ' || data[position] == '\t' || data[position] == '"' || data[position] == '\''))
				position++;

			size_t value_start = position;
			while (position < length && data[position] != ' ' && data[position] != '\t' && data[position] != '"' && data[position] != '\'' && data[position] != ',' && data[position] != ';')
				position++;
			if (position - value_start >= 3)
				return true;
		}

		search += found + 1;
	}

	return false;
}

static bool
known_token(const uint8_t *data, size_t length, const struct secret_rules *rules)
{
	for (size_t i = 0; i < rules->token_prefixes.count; i++) {
		const char *prefix = rules->token_prefixes.values[i];
		size_t position = bytes_find_ci(data, length, prefix);
		if (position != SIZE_MAX && length - position >= strlen(prefix) + 8)
			return true;
	}

	size_t jwt = bytes_find_ci(data, length, "eyj");
	if (jwt == SIZE_MAX)
		return false;

	unsigned int dots = 0;
	for (size_t i = jwt; i < length; i++) {
		if (data[i] == '.')
			dots++;
	}
	return dots >= 2;
}

static bool
has_ipv4(const uint8_t *data, size_t length)
{
	for (size_t start = 0; start < length; start++) {
		if (!isdigit((unsigned char)data[start]))
			continue;
		if (start > 0 && (isdigit((unsigned char)data[start - 1]) || data[start - 1] == '.'))
			continue;

		size_t position = start;
		bool valid = true;
		for (unsigned int part = 0; part < 4; part++) {
			unsigned int value = 0;
			unsigned int digits = 0;
			while (position < length && isdigit((unsigned char)data[position]) && digits < 3) {
				value = value * 10 + (data[position] - '0');
				position++;
				digits++;
			}
			if (digits == 0 || value > 255) {
				valid = false;
				break;
			}
			if (part < 3) {
				if (position >= length || data[position] != '.') {
					valid = false;
					break;
				}
				position++;
			}
		}

		if (valid && (position == length || (!isdigit((unsigned char)data[position]) && data[position] != '.')))
			return true;
	}

	return false;
}

static bool
has_domain(const uint8_t *data, size_t length, const struct secret_rules *rules)
{
	for (size_t i = 0; i < rules->domain_suffixes.count; i++) {
		const char *suffix = rules->domain_suffixes.values[i];
		size_t position = bytes_find_ci(data, length, suffix);
		if (position == SIZE_MAX || position == 0)
			continue;

		size_t end = position + strlen(suffix);
		bool left_valid = isalnum((unsigned char)data[position - 1]) || data[position - 1] == '-';
		bool right_valid = end == length || (!isalnum((unsigned char)data[end]) && data[end] != '-');
		if (left_valid && right_valid)
			return true;
	}

	return false;
}

static bool
has_url(const uint8_t *data, size_t length, const struct secret_rules *rules, bool *insecure)
{
	if (contains_any(data, length, &rules->secure_url_schemes)) {
		*insecure = false;
		return true;
	}
	if (contains_any(data, length, &rules->insecure_url_schemes)) {
		*insecure = true;
		return true;
	}

	return false;
}

static void
scan_string(const uint8_t *data, size_t length, size_t offset, const struct secret_rules *rules)
{
	if (contains_any(data, length, &rules->pem_private_key_markers)) {
		print_text(true, "PEM private key", data, length, offset);
		return;
	}
	if (contains_any(data, length, &rules->pem_certificate_markers)) {
		print_text(false, "PEM certificate", data, length, offset);
		return;
	}

	if (known_token(data, length, rules))
		print_text(true, "possible API token", data, length, offset);

	if (has_any_value(data, length, &rules->secret_keys))
		print_text(true, "possible hardcoded secret", data, length, offset);
	if (has_any_value(data, length, &rules->username_keys))
		print_text(false, "username", data, length, offset);
	if (has_any_value(data, length, &rules->ssid_keys))
		print_text(false, "Wi-Fi SSID", data, length, offset);

	bool insecure = false;
	if (has_url(data, length, rules, &insecure))
		print_text(insecure, insecure ? "insecure URL" : "URL", data, length, offset);
	else if (has_domain(data, length, rules))
		print_text(false, "domain", data, length, offset);

	if (has_ipv4(data, length))
		print_text(false, "IPv4 address", data, length, offset);
}

static bool
der_length(const struct image *image, size_t offset, size_t *length)
{
	if (!bytes_has(image, offset, 2) || image->data[offset] != 0x30)
		return false;

	uint8_t first = image->data[offset + 1];
	if ((first & 0x80) == 0) {
		*length = (size_t)first + 2;
		return bytes_has(image, offset, *length);
	}

	size_t length_bytes = first & 0x7f;
	if (length_bytes == 0 || length_bytes > 4 || !bytes_has(image, offset + 2, length_bytes))
		return false;

	size_t value = 0;
	for (size_t i = 0; i < length_bytes; i++)
		value = value << 8 | image->data[offset + 2 + i];
	if (value > SIZE_MAX - 2 - length_bytes)
		return false;

	*length = 2 + length_bytes + value;
	return bytes_has(image, offset, *length);
}

static void
scan_der(const struct image *image)
{
	for (size_t offset = 0; offset < image->size; offset++) {
		size_t length;
		if (!der_length(image, offset, &length))
			continue;
		if (length > MAX_DER_SIZE || length > LONG_MAX)
			continue;

		const unsigned char *cursor = image->data + offset;
		X509 *certificate = d2i_X509(NULL, &cursor, (long)length);
		if (certificate != NULL && cursor == image->data + offset + length) {
			print_info("DER certificate at 0x%zx, size %zu", offset, length);
			X509_free(certificate);
			offset += length - 1;
			continue;
		}
		X509_free(certificate);
		ERR_clear_error();

		cursor = image->data + offset;
		EVP_PKEY *key = d2i_AutoPrivateKey(NULL, &cursor, (long)length);
		if (key != NULL && cursor == image->data + offset + length) {
			print_bad("DER private key at 0x%zx, size %zu", offset, length);
			EVP_PKEY_free(key);
			offset += length - 1;
			continue;
		}
		EVP_PKEY_free(key);
		ERR_clear_error();
	}
}

int
secrets_scan(const struct image *image)
{
	struct secret_rules rules = {0};
	size_t rule_count = 0;
	json_object *database = load_database(&rules, &rule_count);
	if (database == NULL)
		return -1;

	size_t strings = 0;
	for (size_t offset = 0; offset < image->size;) {
		if (image->data[offset] < 0x20 || image->data[offset] > 0x7e) {
			offset++;
			continue;
		}

		size_t end = offset;
		while (end < image->size && image->data[end] >= 0x20 && image->data[end] <= 0x7e)
			end++;

		size_t length = end - offset;
		if (length >= MIN_STRING) {
			strings++;
			scan_string(image->data + offset, length, offset, &rules);
		}
		offset = end;
	}

	print_info("printable strings: %zu", strings);
	print_info("secret detection rules loaded: %zu", rule_count);
	scan_der(image);
	json_object_put(database);
	return 0;
}
