#include <unistd.h>
#include <string.h>
#include "events.h"

struct ftor_context *ftor_create_context() {
    struct ftor_context *context = malloc(sizeof(struct ftor_context));
    context->state = conn_none_state;
    context->incoming_fd = -1;
    context->pool = ftor_pool_get();
    context->client_recv_buffer = (unsigned char *)ftor_malloc(context->pool, 1 * 1024 * 1024);
    context->client_recv_buffer_size = RECV_BUFFER_SIZE;
    context->client_recv_buffer_pos = 0;
    context->client_addr_len = sizeof(context->client_addr);
    memset(&context->client_addr, 0, context->client_addr_len);
    return context;
}

void ftor_del_context(struct ftor_context *context) {
    ftor_free(context->pool);
    free(context);
}

ssize_t ftor_read_data_to_buffer(int fd, unsigned char *buf, size_t *pos, size_t size, enum read_result *eval, bool read_all) {
    ssize_t readed = read(fd, buf + (int)(*pos), read_all ? size - *pos : size);
    if (readed == -1) {
        if (eval) *eval = read_result_err;
    }
    if (eval) *eval = read_result_ok;
    *pos += (size_t)readed;
    return readed;
}
