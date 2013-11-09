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

void split_string(const char* in, int *len, char***results)
{
        char** fields = calloc(MAX_FIELDS, sizeof(char*));
        memset(fields, 0, MAX_FIELDS*sizeof(fields));
        int retvlen = 0;
        const char *currloc = in; 
        // parse csv into a set of strings
        while (1) {
                size_t len = strcspn(currloc, ", ");
                if (len == 0) {
                        currloc++;
                } else {
                        char *new = malloc(len+1);
			assert(new);
                        strncpy(new, currloc, len);
                        new[len] = '\0';             
                        fields[retvlen++] = new;
			assert(fields[retvlen-1]);
                }   
		if (len == strlen(currloc)) {
			break;
		}
                currloc += len;
        }
        *results = fields;
        *len = retvlen;
}

void parse_ranges(char **in, int in_len, port_h_t **ports, int *ports_len)
{
	int i, p = 0;
	port_h_t port;
	*ports = malloc(0xFFFF * sizeof(port_h_t));
	for (i = 0; i < in_len; ++i) {
		char *str = in[i];
		char *dash = strchr(str, '-');
		if (dash) {
			// Looking at a range
			*dash = '\0';
			int range_begin = atoi(str);
			int range_end = atoi(dash + 1);
			enforce_range("target-port", range_begin, 0, 0xFFFF);
			enforce_range("target-port", range_end, 0, 0xFFFF);
			if (range_begin > range_end) {
				fprintf(stderr, "%s: Invalid target port range: "
						"last port is less than first port\n",
						PACKAGE_NAME);
				exit(EXIT_FAILURE);
			}
			for (port = range_begin; port <= range_end; ++port) {
				(*ports)[p++] = port;
			}
		} else {
			// Single port
			port = atoi(str);
			enforce_range("target-port", port, 0, 0xFFFF);
			(*ports)[p++] = port;
		}
	}
	*ports_len = p;
}

void parse_ports(const char *ports_in, port_h_t **ports, int *ports_len)
{
	char** ports_str_arr;
	int ports_str_arr_len;
	split_string(ports_in, &ports_str_arr_len, &ports_str_arr);
	parse_ranges(ports_str_arr, ports_str_arr_len, ports, ports_len);
}
