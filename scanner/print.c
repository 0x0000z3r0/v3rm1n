#include "print.h"

#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define ANSI_CYAN "\033[36m"
#define ANSI_GREEN "\033[32m"
#define ANSI_RED "\033[31m"
#define ANSI_RESET "\033[0m"
#define MAX_TEXT 160

static bool
use_color(void)
{
	return isatty(STDOUT_FILENO) && getenv("NO_COLOR") == NULL;
}

static void
print_line(const char *color, char mark, const char *format, va_list arguments)
{
	if (use_color())
		printf("%s[%c]%s ", color, mark, ANSI_RESET);
	else
		printf("[%c] ", mark);

	vprintf(format, arguments);
	putchar('\n');
}

void
print_info(const char *format, ...)
{
	va_list arguments;

	va_start(arguments, format);
	print_line(ANSI_CYAN, '*', format, arguments);
	va_end(arguments);
}

void
print_good(const char *format, ...)
{
	va_list arguments;

	va_start(arguments, format);
	print_line(ANSI_GREEN, '+', format, arguments);
	va_end(arguments);
}

void
print_bad(const char *format, ...)
{
	va_list arguments;

	va_start(arguments, format);
	print_line(ANSI_RED, '-', format, arguments);
	va_end(arguments);
}

void
print_text(bool bad, const char *kind, const uint8_t *data, size_t length, size_t offset)
{
	size_t shown = length > MAX_TEXT ? MAX_TEXT : length;
	if (shown > INT_MAX)
		shown = INT_MAX;

	if (bad)
		print_bad("%s at 0x%zx: %.*s%s", kind, offset, (int)shown, (const char *)data, shown < length ? "..." : "");
	else
		print_info("%s at 0x%zx: %.*s%s", kind, offset, (int)shown, (const char *)data, shown < length ? "..." : "");
}
