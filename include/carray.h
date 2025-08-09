#ifndef CARRAY_H
#define CARRAY_H

#include <stdbool.h>

struct carray;

struct carray *carray_create(size_t size);

size_t carray_length(struct carray *carr);

bool carray_exists(struct carray *carr, const char *str);

char *carray_get(struct carray *carr, size_t index);

bool carray_add(struct carray *carr, const char *str);

bool carray_remove(struct carray *carr, const char *str);

void carray_destroy(struct carray *carr);

#endif /* CARRAY_H */
