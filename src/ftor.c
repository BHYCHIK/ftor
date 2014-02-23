#include "config.h"
#include "mempool.h"
#include "network.h"

#include <stdio.h>

int main() {
    __attribute__((unused))struct conf *config = get_conf();
    struct mem_pool *pool = ftor_pool_get();
    ftor_free(pool);
    ftor_reactor_init();
    ftor_start_server();
    ftor_reactor();
    return 0;
}
