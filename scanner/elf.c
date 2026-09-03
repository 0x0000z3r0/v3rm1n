#include "elf.h"
#include "bytes.h"

#include <gelf.h>
#include <libelf.h>
#include <limits.h>

bool
elf_is(const struct image *image)
{
	return bytes_has(image, 0, 4) && image->data[0] == 0x7f && image->data[1] == 'E' && image->data[2] == 'L' && image->data[3] == 'F';
}

bool
elf_symbols(const struct image *image, elf_symbol_fn callback, void *context, bool *has_full_symbols)
{
	*has_full_symbols = false;
	if (!elf_is(image) || elf_version(EV_CURRENT) == EV_NONE)
		return false;

	Elf *elf = elf_memory((char *)image->data, image->size);
	if (elf == NULL || elf_kind(elf) != ELF_K_ELF) {
		if (elf != NULL)
			elf_end(elf);
		return false;
	}

	Elf_Scn *section = NULL;
	while ((section = elf_nextscn(elf, section)) != NULL) {
		GElf_Shdr header;
		if (gelf_getshdr(section, &header) == NULL)
			continue;
		if (header.sh_type != SHT_SYMTAB && header.sh_type != SHT_DYNSYM)
			continue;
		if (header.sh_type == SHT_SYMTAB)
			*has_full_symbols = true;

		Elf_Data *data = NULL;
		while ((data = elf_getdata(section, data)) != NULL) {
			if (header.sh_entsize == 0)
				continue;

			size_t count = data->d_size / header.sh_entsize;
			for (size_t i = 0; i < count; i++) {
				if (i > INT_MAX)
					break;

				GElf_Sym symbol;
				if (gelf_getsym(data, (int)i, &symbol) == NULL)
					continue;

				const char *name = elf_strptr(elf, header.sh_link, symbol.st_name);
				if (name != NULL && name[0] != '\0')
					callback(name, context);
			}
		}
	}

	elf_end(elf);
	return true;
}
