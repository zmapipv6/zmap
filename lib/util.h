#ifndef ZMAP_UTIL_H
#define ZMAP_UTIL_H

#include "types.h"
#include "defines.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

/* Returns 1 if v is in the range [min, max], inclusive.
 * Returns 0 otherwise.
 */
int check_range(int v, int min, int max);

/* Exits if value v with name is not in [min, max]
 */
void enforce_range(const char *name, int v, int min, int max);

/* Splits comma delimited string into char*[]. Does not handle
 * escaping or complicated setups: designed to process a set
 * of fields that the user wants output.
 */
void split_string(const char* in, int *len, char***results);

/* Takes a list of ports and port ranges as strings, and parses them
 * into a list of port_h_t.
 */
void parse_ranges(char **in, int in_len, port_h_t **ports,
		uint16_t *ports_len);

/* Takes a comma-seperated list of ports or port ranges and returns
 * a list of ports as port_h_t's. Intended to convert the command-line
 * argument to internal representation.
 */
void parse_ports(const char *ports_in, port_h_t **ports, int *ports_len);

#endif



