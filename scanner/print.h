#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void print_info(const char *format, ...);
void print_good(const char *format, ...);
void print_bad(const char *format, ...);
void print_text(bool bad, const char *kind, const uint8_t *data, size_t length, size_t offset);
