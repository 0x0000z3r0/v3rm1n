#pragma once

#include <stdbool.h>
#include <stddef.h>

bool database_open(const char *path);
bool database_file(char *path, size_t size, const char *name);
const char *database_root(void);
