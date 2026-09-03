#include "image.h"
#include "print.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int
image_open(struct image *image, const char *path)
{
	image->path = path;
	image->data = NULL;
	image->size = 0;

	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		print_bad("cannot open %s: %s", path, strerror(errno));
		return -1;
	}

	struct stat file_stat;
	if (fstat(fd, &file_stat) == -1) {
		print_bad("cannot inspect %s: %s", path, strerror(errno));
		close(fd);
		return -1;
	}

	if (file_stat.st_size < 0 || (uintmax_t)file_stat.st_size > SIZE_MAX) {
		print_bad("firmware is too large: %s", path);
		close(fd);
		return -1;
	}

	image->size = (size_t)file_stat.st_size;
	if (image->size == 0) {
		close(fd);
		return 0;
	}

	void *mapping = mmap(NULL, image->size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (mapping == MAP_FAILED) {
		print_bad("cannot map %s: %s", path, strerror(errno));
		image->size = 0;
		return -1;
	}

	image->data = mapping;
	return 0;
}

void
image_close(struct image *image)
{
	if (image->data != NULL)
		munmap((void *)image->data, image->size);

	image->data = NULL;
	image->size = 0;
}
