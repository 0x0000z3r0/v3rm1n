#include "secrets.h"
#include "bytes.h"
#include "print.h"

#include <ctype.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MIN_STRING 4
#define MAX_DER_SIZE (1024 * 1024)

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
known_token(const uint8_t *data, size_t length)
{
	static const char *const prefixes[] = {
	    "akia",
	    "ghp_",
	    "github_pat_",
	    "xoxb-",
	    "xoxp-",
	    "aiza",
	    "bearer ",
	};

	for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
		size_t position = bytes_find_ci(data, length, prefixes[i]);
		if (position != SIZE_MAX && length - position >= strlen(prefixes[i]) + 8)
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
has_domain(const uint8_t *data, size_t length)
{
	static const char *const endings[] = {
	    ".com",
	    ".net",
	    ".org",
	    ".io",
	    ".dev",
	    ".cloud",
	    ".local",
	    ".lan",
	};

	for (size_t i = 0; i < sizeof(endings) / sizeof(endings[0]); i++) {
		size_t position = bytes_find_ci(data, length, endings[i]);
		if (position == SIZE_MAX || position == 0)
			continue;

		size_t end = position + strlen(endings[i]);
		bool left_valid = isalnum((unsigned char)data[position - 1]) || data[position - 1] == '-';
		bool right_valid = end == length || (!isalnum((unsigned char)data[end]) && data[end] != '-');
		if (left_valid && right_valid)
			return true;
	}

	return false;
}

static bool
has_url(const uint8_t *data, size_t length, bool *insecure)
{
	static const char *const secure[] = {
	    "https://",
	    "mqtts://",
	    "wss://",
	};
	static const char *const plain[] = {
	    "http://",
	    "mqtt://",
	    "ws://",
	    "ftp://",
	    "telnet://",
	};

	for (size_t i = 0; i < sizeof(secure) / sizeof(secure[0]); i++) {
		if (bytes_contains_ci(data, length, secure[i])) {
			*insecure = false;
			return true;
		}
	}
	for (size_t i = 0; i < sizeof(plain) / sizeof(plain[0]); i++) {
		if (bytes_contains_ci(data, length, plain[i])) {
			*insecure = true;
			return true;
		}
	}

	return false;
}

static void
scan_string(const uint8_t *data, size_t length, size_t offset)
{
	if (bytes_contains_ci(data, length, "-----begin private key-----") || bytes_contains_ci(data, length, "-----begin encrypted private key-----") || bytes_contains_ci(data, length, "-----begin rsa private key-----") || bytes_contains_ci(data, length, "-----begin ec private key-----")) {
		print_text(true, "PEM private key", data, length, offset);
		return;
	}
	if (bytes_contains_ci(data, length, "-----begin certificate-----")) {
		print_text(false, "PEM certificate", data, length, offset);
		return;
	}

	if (known_token(data, length))
		print_text(true, "possible API token", data, length, offset);

	static const char *const secret_keys[] = {
	    "password",
	    "passwd",
	    "api_key",
	    "api-key",
	    "apikey",
	    "token",
	    "secret",
	    "private_key",
	    "private-key",
	    "aes_key",
	    "aes-key",
	    "wifi_psk",
	    "wifi-psk",
	};
	for (size_t i = 0; i < sizeof(secret_keys) / sizeof(secret_keys[0]); i++) {
		if (has_value(data, length, secret_keys[i])) {
			print_text(true, "possible hardcoded secret", data, length, offset);
			break;
		}
	}

	if (has_value(data, length, "username") || has_value(data, length, "user"))
		print_text(false, "username", data, length, offset);
	if (has_value(data, length, "ssid"))
		print_text(false, "Wi-Fi SSID", data, length, offset);

	bool insecure = false;
	if (has_url(data, length, &insecure))
		print_text(insecure, insecure ? "insecure URL" : "URL", data, length, offset);
	else if (has_domain(data, length))
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
			scan_string(image->data + offset, length, offset);
		}
		offset = end;
	}

	print_info("printable strings: %zu", strings);
	scan_der(image);
	return 0;
}
