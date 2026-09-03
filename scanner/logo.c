#include "logo.h"

#include <stdio.h>

extern unsigned char logo_data[];
extern unsigned int logo_data_len;

void
logo_print(void)
{
	fwrite(logo_data, 1, logo_data_len, stdout);
	if (logo_data_len == 0 || logo_data[logo_data_len - 1] != '\n')
		putchar('\n');
	putchar('\n');
}
