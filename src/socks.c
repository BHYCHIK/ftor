#include "socks.h"
#include "events.h"
#include "config.h"
#include "network.h"
#include "rsa.h"

#include <assert.h>
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

#define add_to_buf(buf, pos, src, size) { \
    memcpy(buf + pos, src, size); \
    pos += size; \
}

static int ftor_read_resolver_answer(struct ftor_event *event) {
    printf("dns reply started\n");
    struct ftor_context *context = event->context;
    ftor_read_all(event->socket_fd, &event->recv_buffer, &event->recv_buffer_pos, &event->recv_buffer_size);
    if (event->recv_buffer_pos < 4) return EVENT_RESULT_CONT;
    uint32_t data_size = ntohl(*(uint32_t *)event->recv_buffer);
    if (event->recv_buffer_pos < data_size) return EVENT_RESULT_CONT;

    uint8_t error_code = *((uint8_t *)(event->recv_buffer + 4));
    if (error_code != RESOLVER_ERRCODE_OK) {
        return EVENT_RESULT_CONTEXT_CLOSE;
    }
    context->chain_ip1 = ntohl(*(uint32_t *)(event->recv_buffer + 5));
    context->chain_ip2 = ntohl(*(uint32_t *)(event->recv_buffer + 9));
    uint16_t pubkey1_len = ntohs(*(uint16_t *)(event->recv_buffer + 13));
    uint16_t pubkey2_len = ntohs(*(uint16_t *)(event->recv_buffer + 15));
    if ((int)data_size != 17 + pubkey1_len + pubkey2_len) {
        printf("Bad reply from resolver\n");
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    context->chain_pubkey1 = ftor_malloc(context->pool, pubkey1_len + 1);
    context->chain_pubkey2 = ftor_malloc(context->pool, pubkey2_len + 1);
    snprintf(context->chain_pubkey1, pubkey1_len + 1, "%*s", pubkey1_len, event->recv_buffer + 17);
    snprintf(context->chain_pubkey2, pubkey2_len + 1, "%*s", pubkey2_len, event->recv_buffer + 17 + pubkey1_len);
    printf("dns reply ended\n");
    return EVENT_RESULT_CLOSE;
}

static int send_request_to_resolver(struct ftor_event *event) {
    ssize_t bytes_sended = send(event->socket_fd, event->send_buffer, event->send_buffer_pos, MSG_DONTWAIT);
    printf("sended %zd bytes to resolver\n", bytes_sended);
    if ((size_t)bytes_sended == event->send_buffer_pos) {
        event->read_handler = ftor_read_resolver_answer;
        event->write_handler = NULL;
    }
    memmove(event->send_buffer, event->send_buffer + bytes_sended, event->send_buffer_pos - bytes_sended);
    event->send_buffer_pos -= bytes_sended;
    return EVENT_RESULT_CONT;
}

static void create_resolver_request(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    uint16_t domain1_len = strlen(context->chain_domain_name1);
    uint16_t domain2_len = strlen(context->chain_domain_name2);
    uint32_t flags = 0; //RESERVED for future. Zero field.
    uint32_t packet_len = domain1_len + domain2_len + sizeof(domain1_len) + sizeof(domain2_len) + sizeof(flags) + sizeof(packet_len);
    if (event->send_buffer_size < packet_len) {
        event->send_buffer = (unsigned char *)realloc((void *)event->send_buffer, packet_len);
        event->send_buffer_size = packet_len;
    }
    domain1_len = htons(domain1_len);
    domain2_len = htons(domain2_len);
    flags = htonl(flags);
    packet_len = htonl(packet_len);
    add_to_buf(event->send_buffer, event->send_buffer_pos, &packet_len, sizeof(packet_len));
    add_to_buf(event->send_buffer, event->send_buffer_pos, &flags, sizeof(flags));
    add_to_buf(event->send_buffer, event->send_buffer_pos, &domain1_len, sizeof(domain1_len));
    add_to_buf(event->send_buffer, event->send_buffer_pos, &domain2_len, sizeof(domain2_len));
    add_to_buf(event->send_buffer, event->send_buffer_pos, context->chain_domain_name1, ntohs(domain1_len));
    add_to_buf(event->send_buffer, event->send_buffer_pos, context->chain_domain_name2, ntohs(domain2_len));
}

static int resolver_connected(struct ftor_event *event) {
    int result;
    socklen_t result_len = sizeof(result);
    if (getsockopt(event->socket_fd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
        // error, fail somehow, close socket
        printf("%d cannot connect to resolver\n", __LINE__);
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    if (result != 0) {
        // connection failed; error code is in 'result'
        printf("%d cannot connect to resolver\n", __LINE__);
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    printf("Connection established with resolver!\n");
    create_resolver_request(event);
    event->read_handler = NULL;
    event->write_handler = send_request_to_resolver;
    return EVENT_RESULT_CONT;
}

static int request_for_dns_resolution(struct ftor_context *context) {
    struct conf *config = get_conf();

    struct sockaddr_in resolver_addr;

    int resolver_socket = socket(AF_INET, SOCK_STREAM, 0);
    inet_aton(config->resolver_ip_addr, &resolver_addr.sin_addr);
    resolver_addr.sin_family = AF_INET;
    resolver_addr.sin_port = htons(config->resolver_port);

    setnonblock(resolver_socket);

    if (connect(resolver_socket, (struct sockaddr *)&resolver_addr, sizeof(resolver_addr)) < 0 && errno != EINPROGRESS) {
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    struct ftor_event *resolver_event = ftor_create_event(resolver_socket, context);
    resolver_event->read_handler = NULL;
    resolver_event->write_handler = resolver_connected;

    add_event_to_reactor(resolver_event);
    return EVENT_RESULT_CLOSE;
}

static int ftor_read_designation(struct ftor_event *event) {
    printf("designation started\n");
    struct ftor_context *context = event->context;
    ftor_read_all(event->socket_fd, &event->recv_buffer, &event->recv_buffer_pos, &event->recv_buffer_size);
    if (event->recv_buffer_pos < 4) return EVENT_RESULT_CONT;
    uint32_t data_size = ntohl(*(uint32_t *)event->recv_buffer);
    if (event->recv_buffer_pos < data_size) return EVENT_RESULT_CONT;
    uint16_t domain1_len = ntohs(*(uint16_t *)(event->recv_buffer + 4));
    uint16_t domain2_len = ntohs(*(uint16_t *)(event->recv_buffer + 6));
    if ((int)data_size == 4 + 2 + 2 + domain1_len + domain2_len) {
        printf("Bad reply from designator\n");
        return EVENT_RESULT_CONTEXT_CLOSE;
    }
    context->chain_domain_name1 = ftor_malloc(context->pool, domain1_len + 1);
    context->chain_domain_name2 = ftor_malloc(context->pool, domain2_len + 1);
    snprintf(context->chain_domain_name1, domain1_len + 1, "%*s", domain1_len, event->recv_buffer + 8);
    snprintf(context->chain_domain_name2, domain2_len + 1, "%*s", domain2_len, event->recv_buffer + 8 + domain1_len);
    /*TODO: make free event or add to context allocator */
    printf("designation ended\n");
    return request_for_dns_resolution(context);
}

static int designator_connected(struct ftor_event *event) {
    int result;
    socklen_t result_len = sizeof(result);
    if (getsockopt(event->socket_fd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
        // error, fail somehow, close socket
        printf("%d: cant connect to designator\n", __LINE__);
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    if (result != 0) {
        // connection failed; error code is in 'result'
        printf("%d: cant connect to designator\n", __LINE__);
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    printf("Connection established with designator!\n");
    event->read_handler = ftor_read_designation;
    event->write_handler = NULL;
    return EVENT_RESULT_CONT;
}

static int request_for_servers_chain(struct ftor_context *context) {
    struct conf *config = get_conf();

    struct sockaddr_in designator_addr;

    int designator_socket = socket(AF_INET, SOCK_STREAM, 0);
    inet_aton(config->designator_ip_addr, &designator_addr.sin_addr);
    designator_addr.sin_family = AF_INET;
    designator_addr.sin_port = htons(config->designator_port);

    setnonblock(designator_socket);

    if (connect(designator_socket, (struct sockaddr *)&designator_addr, sizeof(designator_addr)) < 0 && errno != EINPROGRESS) {
        printf("%d: cant connect to designator\n", __LINE__);
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    struct ftor_event *designator_event = ftor_create_event(designator_socket, context);
    designator_event->read_handler = NULL;
    designator_event->write_handler = designator_connected;

    add_event_to_reactor(designator_event);
    return EVENT_RESULT_CONT;
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
    if (!ended) return EVENT_RESULT_CONT;
    event->recv_buffer_pos = 0;
    event->read_handler = NULL;
    event->write_handler = NULL;
    printf("idented ended\n");
    return request_for_servers_chain(context);
}

int ftor_socks_get_header(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    ssize_t readed = ftor_read_all(event->socket_fd, &event->recv_buffer, &event->recv_buffer_pos, &event->recv_buffer_size);
    printf("readed=%zd\n", readed);
    if (event->recv_buffer_pos < STABLE_HEADER_LEN) return EVENT_RESULT_CONT;
    context->peer_port = ntohs(*((uint16_t *)(event->recv_buffer + 2)));
    context->peer_address = ntohl(*((uint32_t *)(event->recv_buffer + 4)));
    context->state = socks_header_received_state;
    memmove(event->recv_buffer, event->recv_buffer + STABLE_HEADER_LEN, event->recv_buffer_pos - STABLE_HEADER_LEN);
    event->recv_buffer_pos -= STABLE_HEADER_LEN;
    event->read_handler = ftor_socks_get_identd;
    event->write_handler = NULL;
    return ftor_socks_get_identd(event);
}
