#ifndef __EVENTS__H__
#define __EVENTS__H__

#include "mempool.h"

struct ftor_event;
struct ftor_context;

enum ftor_state {
    conn_none_state,
    conn_received_state
};

typedef int (*ftor_handler)(struct ftor_event *event);

struct ftor_event {
    struct ftor_context *context;
    ftor_handler read_handler;
    ftor_handler write_handler;
    int socket_fd;
};

struct ftor_context {
    int incoming_fd;
    struct mem_pool *pool;

    enum ftor_state state;
};

struct ftor_context *ftor_create_context();
void ftor_del_context(struct ftor_context *context);
#endif
