#include "defines.h"
#include "util.h"

#include <stdlib.h>
#include <stdio.h>

void enforce_range(const char *name, int v, int min, int max)
{
	if (v < min || v > max) {
	  	fprintf(stderr, "%s: argument `%s' must be between %d and %d\n",
			PACKAGE_NAME, name, min, max);
		exit(EXIT_FAILURE);
	}
}