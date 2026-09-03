#include "database.h"
#include "print.h"

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *root;

bool
database_open(const char *path)
{
	struct stat info;
	if (stat(path, &info) != 0 || !S_ISDIR(info.st_mode) || access(path, R_OK) != 0) {
		print_bad("cannot read database directory: %s", path);
		return false;
	}

	root = path;
	print_info("database: %s", root);
	return true;
}

bool
database_file(char *path, size_t size, const char *name)
{
	if (root == NULL)
		return false;

	int length = snprintf(path, size, "%s/%s", root, name);
	return length >= 0 && (size_t)length < size;
}

const char *
database_root(void)
{
	return root;
}
