#include "database.h"
#include "debug.h"
#include "entropy.h"
#include "format.h"
#include "image.h"
#include "logo.h"
#include "metadata.h"
#include "partition.h"
#include "scan.h"
#include "secrets.h"
#include "security.h"
#include "unsafe.h"
#include "vuln.h"

#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv)
{
	logo_print();

	const char *database = "database";
	const char *firmware;
	if (argc == 2) {
		firmware = argv[1];
	} else if (argc == 4 && strcmp(argv[1], "--database") == 0) {
		database = argv[2];
		firmware = argv[3];
	} else {
		fprintf(stderr, "usage: v3rm1n [--database <path>] <firmware>\n");
		return 1;
	}

	if (!database_open(database))
		return 1;

	struct image image;
	if (image_open(&image, firmware) != 0)
		return 1;

	const struct scan_module modules[] = {
	    {"format", format_scan},
	    {"partition", partition_scan},
	    {"metadata", metadata_scan},
	    {"debug", debug_scan},
	    {"security", security_scan},
	    {"vulnerabilities", vuln_scan},
	    {"unsafe", unsafe_scan},
	    {"entropy", entropy_scan},
	    {"secrets", secrets_scan},
	};
	int status = 0;
	for (size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); i++) {
		if (modules[i].scan(&image) != 0)
			status = 1;
	}

	image_close(&image);
	return status;
}
