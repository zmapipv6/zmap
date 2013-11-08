#include "defines.h"
#include "util.h"

#include <stdlib.h>
#include <stdio.h>

int check_range(int v, int min, int max)
{
	return (!(v < min || v > max));
}

void enforce_range(const char *name, int v, int min, int max)
{
	if (!check_range(v, min, max)) {
	  	fprintf(stderr, "%s: argument `%s' must be between %d and %d\n",
			PACKAGE_NAME, name, min, max);
		exit(EXIT_FAILURE);
	}
}