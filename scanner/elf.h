#pragma once

#include "image.h"

#include <stdbool.h>

typedef void (*elf_symbol_fn)(const char *name, void *context);

bool elf_is(const struct image *image);
bool elf_symbols(const struct image *image, elf_symbol_fn callback, void *context, bool *has_full_symbols);
