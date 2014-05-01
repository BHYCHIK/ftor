#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "events.h"

struct ftor_context *ftor_create_context() {
    struct ftor_context *context = malloc(sizeof(struct ftor_context));
    context->state = conn_none_state;
    context->incoming_fd = -1;
    context->terminated = false;
    context->pool = ftor_pool_get();
    context->client_recv_buffer = malloc(RECV_BUFFER_START_SIZE);
    context->client_recv_buffer_size = RECV_BUFFER_START_SIZE;
    context->client_recv_buffer_pos = 0;
    context->client_addr_len = sizeof(context->client_addr);
    context->client_event = NULL;
    context->chain_domain_name1 = NULL;
    context->chain_domain_name2 = NULL;
    context->chain_pubkey1 = NULL;
    context->chain_pubkey2 = NULL;
    context->chain_ip1 = 0;
    context->chain_ip2 = 0;
    context->events_num = 0;
    memset(&context->client_addr, 0, context->client_addr_len);
    return context;
}

struct ftor_event *ftor_create_event(int fd, struct ftor_context *context) {
    struct ftor_event *event = malloc(sizeof(struct ftor_event));
    event->context = context;
    if (context) ++context->events_num;
    event->socket_fd = fd;
    event->read_handler = NULL;
    event->write_handler = NULL;

    event->recv_buffer = malloc(RECV_BUFFER_START_SIZE);
    event->recv_buffer_size = RECV_BUFFER_START_SIZE;
    event->recv_buffer_pos = 0;

    event->send_buffer = malloc(RECV_BUFFER_START_SIZE);
    event->send_buffer_size = RECV_BUFFER_START_SIZE;
    event->send_buffer_pos = 0;

    return event;
}

void ftor_del_event(struct ftor_event *event) {
    if (event->socket_fd > -1) close(event->socket_fd);
    if (event->context) {
        if ((--event->context->events_num) == 0) {
            ftor_del_context(event->context);
        }
    }
    free(event->send_buffer);
    free(event->recv_buffer);
    free(event);
}

void ftor_del_context(struct ftor_context *context) {
    ftor_free(context->pool);
    free(context->client_recv_buffer);
    free(context);
}

ssize_t ftor_read_all(int fd, unsigned char **buf, size_t *pos, size_t *alloced, bool *eof, bool *error) {
    *eof = false;
    *error = false;
    char tmp_buf[1];
    ssize_t bytes_readed = 0;
    ssize_t total_readed = 0;
    do {
        bytes_readed = recv(fd, tmp_buf, sizeof(tmp_buf), MSG_DONTWAIT);
        if (bytes_readed == 0) {
            *eof = true;
            break;
        }
        if (bytes_readed < 0) {
            if (errno != EAGAIN) {
                *error = true;
            }
            break;
        }
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
