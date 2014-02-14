#include "mempool.h"

#define POOL_PART_SIZE (1 * 1024 * 1024)

struct mem_pool *ftor_pool_get_with_size(size_t size) {
    struct mem_pool *pool = malloc(sizeof(struct mem_pool));
    if (!pool) return NULL;
    pool->memory_start = malloc(size);
    if (!pool->memory_start) {
        free(pool);
        return NULL;
    }
    pool->current_pos = pool->memory_start;
    pool->space_left = size;
    pool->next = NULL;
    return pool;
}

struct mem_pool *ftor_pool_get() {
    return ftor_pool_get_with_size(POOL_PART_SIZE);
}

void *ftor_malloc(struct mem_pool *pool, size_t size) {
    while (pool->space_left < size && pool->next) pool = pool->next;
    if (pool->space_left < size) {
        pool->next = ftor_pool_get_with_size(POOL_PART_SIZE < size ? size : POOL_PART_SIZE);
        if (!pool->next) { //Try to get minimum amount of space
            if (POOL_PART_SIZE > size)
                pool->next = ftor_pool_get_with_size(size);
            if (!pool->next) return NULL;
        }
        pool = pool->next;
    }
    void *space_to_return = pool->current_pos;
    pool->current_pos = (char*)pool->current_pos + size;
    pool->space_left -= size;
    return space_to_return;
}

void ftor_free(struct mem_pool *pool) {
    struct mem_pool *prev_part = NULL;
    while(pool) {
        prev_part = pool;
        pool = pool->next;

        free(prev_part->memory_start);
        free(prev_part);
    }
}
