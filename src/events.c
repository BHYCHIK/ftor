#include <unistd.h>
#include <string.h>
#include "events.h"

struct ftor_context *ftor_create_context() {
    struct ftor_context *context = malloc(sizeof(struct ftor_context));
    context->state = conn_none_state;
    context->incoming_fd = -1;
    context->pool = ftor_pool_get();
    context->client_recv_buffer = malloc(RECV_BUFFER_START_SIZE);
    context->client_recv_buffer_size = RECV_BUFFER_START_SIZE;
    context->client_recv_buffer_pos = 0;
    context->client_addr_len = sizeof(context->client_addr);
    context->client_event = NULL;
    memset(&context->client_addr, 0, context->client_addr_len);
    return context;
}

void ftor_del_context(struct ftor_context *context) {
    ftor_free(context->pool);
    free(context->client_recv_buffer);
    free(context);
}

ssize_t ftor_read_all(int fd, unsigned char **buf, size_t *pos, size_t *alloced) {
    char tmp_buf[1];
    ssize_t bytes_readed = 0;
    ssize_t total_readed = 0;
    do {
        bytes_readed = read(fd, tmp_buf, sizeof(tmp_buf));
        if (bytes_readed <= 0) break;
        if ((ssize_t)*alloced < (*buf +(int)(*pos)) - *buf + bytes_readed) {
            *alloced *= 2;
            *buf = realloc(*buf, *alloced);
        }
        memcpy(*buf + *pos, tmp_buf, bytes_readed);
        *pos += bytes_readed;
        total_readed += bytes_readed;
    } while (bytes_readed > 0);

    return total_readed;
}

ssize_t ftor_read_data_to_buffer(int fd, unsigned char *buf, size_t *pos, size_t size, enum read_result *eval, bool read_all) {
    ssize_t readed = 0;
    if (!read_all) {
        readed = read(fd, buf + (int)(*pos), size);
    }
    else {
        readed = read(fd, buf + (int)(*pos), read_all ? size - *pos : size);
    }
    if (readed == -1) {
        if (eval) *eval = read_result_err;
    }
    if (eval) *eval = read_result_ok;
    *pos += (size_t)readed;
    return readed;
}
