#ifndef __mempool__h__
#define __mempool__h__

#include <stdlib.h>

struct mem_pool {
    void *memory_start;
    void *current_pos;
    size_t space_left;
    struct mem_pool *next;
};

struct mem_pool *ftor_pool_get_with_size(size_t size);
struct mem_pool *ftor_pool_get();
void *ftor_malloc(struct mem_pool *pool, size_t size);
void ftor_free(struct mem_pool *pool);

#endif
