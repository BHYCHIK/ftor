#include <assert.h>
#include "socks.h"
#include "events.h"
#include "config.h"
#include "network.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define STABLE_HEADER_LEN 8
/*
static int read_request(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    ftor_read_data_to_buffer(event->socket_fd, context->client_recv_buffer, &context->client_recv_buffer_pos, context->client_recv_buffer_size, NULL, true);
    close(event->socket_fd);
    return 0;
}

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
    event->read_handler = read_request;
    event->write_handler = NULL;
    return 0;
}*/

static int ftor_read_designation(struct ftor_event *event) {
    printf("designation started\n");
    struct ftor_context *context = event->context;
    ftor_read_all(event->socket_fd, &event->recv_buffer, &event->recv_buffer_pos, &event->recv_buffer_size);
    if (event->recv_buffer_pos < 4) return 0;
    uint32_t data_size = ntohl(*(uint32_t *)event->recv_buffer);
    if (event->recv_buffer_pos < data_size) return 0;
    uint16_t domain1_len = ntohs(*(uint16_t *)(event->recv_buffer + 4));
    uint16_t domain2_len = ntohs(*(uint16_t *)(event->recv_buffer + 6));
    assert((int)data_size == 4 + 2 + 2 + domain1_len + domain2_len);
    close(event->socket_fd);
    context->chain_domain_name1 = ftor_malloc(context->pool, domain1_len + 1);
    context->chain_domain_name2 = ftor_malloc(context->pool, domain2_len + 1);
    snprintf(context->chain_domain_name1, domain1_len + 1, "%*s", domain1_len, event->recv_buffer + 8);
    snprintf(context->chain_domain_name2, domain2_len + 1, "%*s", domain2_len, event->recv_buffer + 8 + domain1_len);
    /*TODO: make free event or add to context allocator */
    printf("designation ended\n");
    return 0;
}

static int designator_connected(struct ftor_event *event) {
    int result;
    socklen_t result_len = sizeof(result);
    if (getsockopt(event->socket_fd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
        // error, fail somehow, close socket
        assert(0);
        return -1;
    }

    if (result != 0) {
        // connection failed; error code is in 'result'
        assert(0);
        return -1;
    }

    printf("Connection established with designator!");
    event->read_handler = ftor_read_designation;
    event->write_handler = NULL;
    return 0;
}

static void request_for_servers_chain(struct ftor_context *context) {
    struct conf *config = get_conf();

    struct sockaddr_in designator_addr;

    int designator_socket = socket(AF_INET, SOCK_STREAM, 0);
    inet_aton(config->designator_ip_addr, &designator_addr.sin_addr);
    designator_addr.sin_family = AF_INET;
    designator_addr.sin_port = htons(config->designator_port);

    setnonblock(designator_socket);

    if (connect(designator_socket, (struct sockaddr *)&designator_addr, sizeof(designator_addr)) < 0 && errno != EINPROGRESS) {
        assert(0);
    }

    struct ftor_event *designator_event = ftor_create_event(designator_socket, context);
    designator_event->read_handler = NULL;
    designator_event->write_handler = designator_connected;

    add_event_to_reactor(designator_event);
}

static int ftor_socks_get_identd(struct ftor_event *event) {
    printf("idented started\n");
    struct ftor_context *context = event->context;
    assert(context->state == socks_header_received_state);
    unsigned char *start = event->recv_buffer + event->recv_buffer_pos;
    ftor_read_all(event->socket_fd, &event->recv_buffer, &event->recv_buffer_pos, &event->recv_buffer_size);
    unsigned char *stop = event->recv_buffer + event->recv_buffer_pos;
    bool ended = false;
    for (; start <= stop; ++start) {
        if (*start == '\0') {
            ended = true;
            stop = start;
            break;
        }
    }
    if (!ended) return 0;
    event->recv_buffer_pos = 0;
    event->read_handler = NULL;
    event->write_handler = NULL;
    request_for_servers_chain(context);
    printf("idented ended\n");
    return 0;
}

int ftor_socks_get_header(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    ssize_t readed = ftor_read_all(event->socket_fd, &event->recv_buffer, &event->recv_buffer_pos, &event->recv_buffer_size);
    printf("readed=%zd\n", readed);
    if (event->recv_buffer_pos < STABLE_HEADER_LEN) return 0;
    context->peer_port = ntohs(*((uint16_t *)(event->recv_buffer + 2)));
    context->peer_address = ntohl(*((uint32_t *)(event->recv_buffer + 4)));
    context->state = socks_header_received_state;
    memmove(event->recv_buffer, event->recv_buffer + STABLE_HEADER_LEN, event->recv_buffer_pos - STABLE_HEADER_LEN);
    event->recv_buffer_pos -= STABLE_HEADER_LEN;
    event->read_handler = ftor_socks_get_identd;
    event->write_handler = NULL;
    ftor_socks_get_identd(event);
    return 0;
}
