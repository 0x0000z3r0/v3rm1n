#include "entropy.h"
#include "print.h"

#include <math.h>

int
entropy_scan(const struct image *image)
{
	if (image->size == 0) {
		print_bad("entropy is unavailable (empty firmware)");
		return -1;
	}

	size_t frequencies[256] = {0};
	for (size_t i = 0; i < image->size; i++)
		frequencies[image->data[i]]++;

	double entropy = 0.0;
	for (size_t i = 0; i < 256; i++) {
		if (frequencies[i] == 0)
			continue;

		double probability = (double)frequencies[i] / (double)image->size;
		entropy -= probability * log2(probability);
	}

	print_info("entropy is %.3f (%.3f bits/byte)", entropy / 8.0, entropy);
	return 0;
}
