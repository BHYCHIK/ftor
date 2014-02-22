#include "events.h"

struct ftor_context *ftor_create_context() {
    struct ftor_context *context = malloc(sizeof(struct ftor_context));
    context->state = conn_none_state;
    context->incoming_fd = -1;
    context->pool = ftor_pool_get();
    return context;
}

void ftor_del_context(struct ftor_context *context) {
    ftor_free(context->pool);
    free(context);
}
