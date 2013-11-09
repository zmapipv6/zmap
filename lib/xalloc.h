#ifndef ZMAP_ALLOC_H
#define ZMAP_ALLOC_H

#include <stddef.h>

/* Implementations of the most commonly used malloc family of
 * functions that crash the program if the memory cannot be
 * allocated (e.g. if malloc returns NULL).
 */ 
void* xcalloc(size_t count, size_t size);

void xfree(void *ptr);

void* xmalloc(size_t size);

void* xrealloc(void *ptr, size_t size);

#endif