#include "socks.h"
#include "events.h"

#include <stdio.h>

int ftor_socks_get_header(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    ssize_t readed = ftor_read_data_to_buffer(event->socket_fd, context->client_recv_buffer, &context->client_recv_buffer_pos, context->client_recv_buffer_size, NULL);
    printf("readed %d\n", readed);
    return 0;
}
