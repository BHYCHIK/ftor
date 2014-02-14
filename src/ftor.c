#include "config.h"
#include "mempool.h"

#include <stdio.h>

int main() {
    __attribute__((unused))struct conf *config = get_conf();
    struct mem_pool *pool = ftor_pool_get();
    void *a = ftor_malloc(pool, 10);
    void *b = ftor_malloc(pool, 20);
    void *z = ftor_malloc(pool, 10 * 1024 * 1024);
    void *c = ftor_malloc(pool, 30);
    printf("%p %p %p %p\n", a, b, c, z);
    ftor_free(pool);
    return 0;
}
