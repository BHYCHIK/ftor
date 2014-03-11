#include <assert.h>
#include "socks.h"
#include "events.h"

#include <stdio.h>
#include <unistd.h>

#define STABLE_HEADER_LEN 8

static int send_reply(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    unsigned char reply[8];
    reply[0] = 0;
    reply[1] = 90;
    uint16_t *port_pos = ((uint16_t *)(reply + 2));
    *port_pos = htons(context->peer_port);
    uint32_t *addr_pos = ((uint32_t *)(reply + 4));
    *addr_pos = htonl(context->peer_address);
    write(event->socket_fd, reply, 8);
    printf("reply send\n");
    event->read_handler = NULL;
    event->write_handler = NULL;
    return 0;
}

static int ftor_socks_get_identd(struct ftor_event *event) {
    printf("idented started\n");
    struct ftor_context *context = event->context;
    assert(context->state == socks_header_received_state);
    unsigned char *start = context->client_recv_buffer + context->client_recv_buffer_pos;
    ftor_read_data_to_buffer(event->socket_fd, context->client_recv_buffer, &context->client_recv_buffer_pos, context->client_recv_buffer_size, NULL, true);
    unsigned char *stop = context->client_recv_buffer + context->client_recv_buffer_pos;
    bool ended = false;
    for (; start <= stop; ++start) {
        if (*start == '\0') {
            ended = true;
            stop = start;
            break;
        }
    }
    if (!ended) return 0;
    context->client_recv_buffer_pos = 0;
    event->read_handler = NULL;
    event->write_handler = send_reply;
    printf("idented ended\n");
    return 0;
}

int ftor_socks_get_header(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    ssize_t readed = ftor_read_data_to_buffer(event->socket_fd, context->client_recv_buffer, &context->client_recv_buffer_pos, STABLE_HEADER_LEN - context->client_recv_buffer_pos, NULL, false);
    printf("readed=%zd\n", readed);
    if (context->client_recv_buffer_pos < STABLE_HEADER_LEN) return 0;
    context->peer_port = ntohs(*((uint16_t *)(context->client_recv_buffer + 2)));
    context->peer_address = ntohl(*((uint32_t *)(context->client_recv_buffer + 4)));
    context->state = socks_header_received_state;
    context->client_recv_buffer_pos = 0;
    event->read_handler = ftor_socks_get_identd;
    event->write_handler = NULL;
    return 0;
}
