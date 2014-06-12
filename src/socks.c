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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#define STABLE_HEADER_LEN 8
#define CIPHERED_NODE_PACKET_LEN 256

int random_fd = -1;

#define add_to_buf(_buf, _pos, _src, _size) { \
    memcpy(_buf + _pos, _src, _size); \
    _pos += _size; \
}

static int recv_from_chain(struct ftor_event *event) {
    struct conf *config = get_conf();
    struct ftor_context *context = event->context;
    bool eof = false;
    bool error = false;
    int prev_pos = context->chain_recv_buffer_pos;
    ssize_t readed = ftor_read_all(event->socket_fd, &context->chain_recv_buffer, &context->chain_recv_buffer_pos, &context->chain_recv_buffer_size, &eof, &error);
    if (error) return EVENT_RESULT_CONTEXT_CLOSE;

    if (config->enable_cipher) {
        int i = 0;
        for (i = 0; i < readed; ++i) {
            context->chain_recv_buffer[prev_pos + i] ^= context->sesskey1[context->backward_cipher_offset];
            context->chain_recv_buffer[prev_pos + i] ^= context->sesskey2[context->backward_cipher_offset++];
            if (context->backward_cipher_offset == sizeof(context->node_sesskey)) context->backward_cipher_offset = 0;
        }
    }

    if (eof) {
        printf("chain eof\n");
        context->chain_eof = true;
        return EVENT_RESULT_CLOSE;
    }
    return EVENT_RESULT_CONT;
}

static int send_to_chain(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    ssize_t bytes_sended = send(event->socket_fd, context->client_recv_buffer, context->client_recv_buffer_pos, MSG_DONTWAIT);
    if (bytes_sended == -1) printf("to chain errno: %s\n", strerror(errno));
    if (bytes_sended == -1 && errno == EAGAIN) {
        return EVENT_RESULT_CONT;
    }
    if (bytes_sended == -1) {
        return EVENT_RESULT_CONTEXT_CLOSE;
    }
//    printf("sended %zd bytes to chain\n", bytes_sended);
    memmove(context->client_recv_buffer, context->client_recv_buffer + bytes_sended, context->client_recv_buffer_pos - bytes_sended);
    context->client_recv_buffer_pos -= bytes_sended;
    if (context->client_eof && !context->client_recv_buffer_pos) {
        return EVENT_RESULT_CLOSE;
    }
    return EVENT_RESULT_CONT;
}

static int recv_from_client(struct ftor_event *event) {
    struct conf *config = get_conf();
    struct ftor_context *context = event->context;
    bool eof = false;
    bool error = false;
    int prev_pos = context->client_recv_buffer_pos;
    ssize_t readed = ftor_read_all(event->socket_fd, &context->client_recv_buffer, &context->client_recv_buffer_pos, &context->client_recv_buffer_size, &eof, &error);
    if (error) return EVENT_RESULT_CONTEXT_CLOSE;

    if (config->enable_cipher) {
        int i = 0;
        for (i = 0; i < readed; ++i) {
            context->client_recv_buffer[prev_pos + i] ^= context->sesskey2[context->forward_cipher_offset];
            context->client_recv_buffer[prev_pos + i] ^= context->sesskey1[context->forward_cipher_offset++];
            if (context->forward_cipher_offset == sizeof(context->node_sesskey)) context->forward_cipher_offset = 0;
        }
    }

    if (eof) {
        printf("client eof\n");
        context->client_eof = true;
        return EVENT_RESULT_CLOSE;
    }
    return EVENT_RESULT_CONT;
}

static int send_to_client(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    ssize_t bytes_sended = send(event->socket_fd, context->chain_recv_buffer, context->chain_recv_buffer_pos, MSG_DONTWAIT);
    if (bytes_sended == -1) printf("to client errno: %s\n", strerror(errno));
    if (bytes_sended == -1 && errno == EAGAIN) {
        return EVENT_RESULT_CONT;
    }
    if (bytes_sended == -1) {
        return EVENT_RESULT_CONTEXT_CLOSE;
    }
//    printf("sended %zd bytes to client\n", bytes_sended);
    memmove(context->chain_recv_buffer, context->chain_recv_buffer + bytes_sended, context->chain_recv_buffer_pos - bytes_sended);
    context->chain_recv_buffer_pos -= bytes_sended;
    if (context->chain_eof && !context->chain_recv_buffer_pos) {
        return EVENT_RESULT_CLOSE;
    }
    return EVENT_RESULT_CONT;
}

static int send_ok_to_client_impl(struct ftor_event *event) {
    ssize_t bytes_sended = send(event->socket_fd, event->send_buffer, event->send_buffer_pos, MSG_DONTWAIT);
    printf("sended %zd bytes to client to say ok\n", bytes_sended);
    if ((size_t)bytes_sended == event->send_buffer_pos) {
        event->read_handler = recv_from_client;
        event->write_handler = send_to_client;
    }
    memmove(event->send_buffer, event->send_buffer + bytes_sended, event->send_buffer_pos - bytes_sended);
    event->send_buffer_pos -= bytes_sended;
    return EVENT_RESULT_CONT;
}

static void send_ok_to_client(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    unsigned char reply[8];
    reply[0] = 0;
    reply[1] = 90;
    uint16_t *port_pos = ((uint16_t *)(reply + 2));
    *port_pos = htons(context->peer_port);
    uint32_t *addr_pos = ((uint32_t *)(reply + 4));
    *addr_pos = htonl(context->peer_address);
    if (event->send_buffer_size < sizeof(reply)) {
        event->send_buffer = (unsigned char *)realloc((void *)event->send_buffer, sizeof(reply));
        event->send_buffer_size = sizeof(reply);
    }
    add_to_buf(event->send_buffer, event->send_buffer_pos, reply, sizeof(reply));
    event->write_handler = send_ok_to_client_impl;
}

static int send_header_to_next_node(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    ssize_t bytes_sended = send(event->socket_fd, event->send_buffer, event->send_buffer_pos, MSG_DONTWAIT);
    printf("sended %zd bytes to next node\n", bytes_sended);
    if ((size_t)bytes_sended == event->send_buffer_pos) {
        event->read_handler = recv_from_chain;
        event->write_handler = send_to_chain;
        send_ok_to_client(context->client_event);
    }
    memmove(event->send_buffer, event->send_buffer + bytes_sended, event->send_buffer_pos - bytes_sended);
    event->send_buffer_pos -= bytes_sended;
    return EVENT_RESULT_CONT;
}

//packet must be CIPHERED_NODE_PACKET_LEN (256) bytes
static bool gen_node_header(unsigned char *packet, uint32_t flags, uint32_t next_ip, uint16_t port, unsigned char *sess_key, int sess_key_len, unsigned char *pubkey) {
    if (random_fd == -1) {
        random_fd = open("/dev/urandom", O_RDONLY);
    }
    const int plain_header_len = 142; // Must be less then CIPHERED_NODE_PACKET_LEN (256)
    unsigned char plain[plain_header_len];
    uint32_t magic_num = htonl(0xDEADBEAF);
    uint32_t next_ip_n = htonl(next_ip);
    uint16_t next_port_n = htons(port);
    uint32_t flags_n = htonl(flags);
    if (read(random_fd, sess_key, sess_key_len) < sess_key_len) {
        return false;
    }
    int pos = 0;
    add_to_buf(plain, pos, &magic_num, sizeof(magic_num));
    add_to_buf(plain, pos, &flags_n, sizeof(flags_n));
    add_to_buf(plain, pos, &next_ip_n, sizeof(next_ip_n));
    add_to_buf(plain, pos, &next_port_n, sizeof(next_port_n));
    add_to_buf(plain, pos, sess_key, sess_key_len);
    assert(pos != 0);

    int error = 0;
    int encr_len = rsa_public_encrypt(plain, pos, pubkey, packet, &error);
    char err[256];
    rsa_get_last_error(err);
    printf("encr_len: %d\n%s\n", encr_len, err);
    assert(encr_len == CIPHERED_NODE_PACKET_LEN);
    return true;
}

static bool create_next_node_request(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    struct conf *config = get_conf();
    unsigned char pack1[CIPHERED_NODE_PACKET_LEN];
    unsigned char pack2[CIPHERED_NODE_PACKET_LEN];
    uint32_t cipher_bit = config->enable_cipher ? NODE_HEADER_FLAG_ENABLE_CIPHER : 0;
    if (!gen_node_header(pack1, cipher_bit, context->chain_ip2, (uint16_t)config->node_port, context->sesskey1, sizeof(context->sesskey1), (unsigned char *)context->chain_pubkey1)) return false;
    if (!gen_node_header(pack2, cipher_bit | NODE_HEADER_FLAG_EXIT_NODE, context->peer_address, (uint16_t)context->peer_port, context->sesskey2, sizeof(context->sesskey2), (unsigned char *)context->chain_pubkey2)) return false;
    if (event->send_buffer_size < sizeof(pack1) + sizeof(pack2)) {
        event->send_buffer = (unsigned char *)realloc((void *)event->send_buffer, sizeof(pack1) + sizeof(pack2));
        event->send_buffer_size = sizeof(pack1) + sizeof(pack2);
    }
    add_to_buf(event->send_buffer, event->send_buffer_pos, pack1, sizeof(pack1));
    add_to_buf(event->send_buffer, event->send_buffer_pos, pack2, sizeof(pack2));
    return true;
}

static int connected_to_node(struct ftor_event *event) {
    int result;
    socklen_t result_len = sizeof(result);
    if (getsockopt(event->socket_fd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
        // error, fail somehow, close socket
        printf("%d cannot connect to next node\n", __LINE__);
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    if (result != 0) {
        // connection failed; error code is in 'result'
        printf("%d cannot connect to next node\n", __LINE__);
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    printf("Connection established with next node!\n");
    if (!create_next_node_request(event)) return EVENT_RESULT_CONTEXT_CLOSE;
    event->read_handler = NULL;
    event->write_handler = send_header_to_next_node;
    return EVENT_RESULT_CONT;
}

static int request_for_chain_node(struct ftor_context *context) {
    struct conf *config = get_conf();

    struct sockaddr_in node_addr;

    int node_socket = socket(AF_INET, SOCK_STREAM, 0);
    node_addr.sin_addr.s_addr = htonl(context->chain_ip1);
    node_addr.sin_family = AF_INET;
    node_addr.sin_port = htons(config->node_port);

    setnonblock(node_socket);

    if (connect(node_socket, (struct sockaddr *)&node_addr, sizeof(node_addr)) < 0 && errno != EINPROGRESS) {
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    struct ftor_event *node_event = ftor_create_event(node_socket, context);
    node_event->read_handler = NULL;
    node_event->write_handler = connected_to_node;

    add_event_to_reactor(node_event);
    return EVENT_RESULT_CLOSE;
}

static int ftor_read_resolver_answer(struct ftor_event *event) {
    printf("dns reply started\n");
    struct ftor_context *context = event->context;
    bool eof = false;
    bool error = false;
    ftor_read_all(event->socket_fd, &event->recv_buffer, &event->recv_buffer_pos, &event->recv_buffer_size, &eof, &error);
    if (error) return EVENT_RESULT_CONTEXT_CLOSE;
    if (event->recv_buffer_pos < 4) return eof ? EVENT_RESULT_CONTEXT_CLOSE : EVENT_RESULT_CONT;
    uint32_t data_size = ntohl(*(uint32_t *)event->recv_buffer);
    if (event->recv_buffer_pos < data_size) return eof ? EVENT_RESULT_CONTEXT_CLOSE : EVENT_RESULT_CONT;

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
    snprintf(context->chain_pubkey1, pubkey1_len + 1, "%.*s", pubkey1_len, event->recv_buffer + 17);
    snprintf(context->chain_pubkey2, pubkey2_len + 1, "%.*s", pubkey2_len, event->recv_buffer + 17 + pubkey1_len);
    printf("dns reply ended\n");
    return request_for_chain_node(context);
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
    bool eof = false;
    bool error = false;
    ftor_read_all(event->socket_fd, &event->recv_buffer, &event->recv_buffer_pos, &event->recv_buffer_size, &eof, &error);
    if (error) return EVENT_RESULT_CONTEXT_CLOSE;
    if (event->recv_buffer_pos < 4) return eof ? EVENT_RESULT_CONTEXT_CLOSE : EVENT_RESULT_CONT;
    uint32_t data_size = ntohl(*(uint32_t *)event->recv_buffer);
    if (event->recv_buffer_pos < data_size) return eof ? EVENT_RESULT_CONTEXT_CLOSE : EVENT_RESULT_CONT;
    uint16_t domain1_len = ntohs(*(uint16_t *)(event->recv_buffer + 4));
    uint16_t domain2_len = ntohs(*(uint16_t *)(event->recv_buffer + 6));
    if ((int)data_size != 4 + 2 + 2 + domain1_len + domain2_len) {
        printf("Bad reply from designator\n");
        return EVENT_RESULT_CONTEXT_CLOSE;
    }
    context->chain_domain_name1 = ftor_malloc(context->pool, domain1_len + 1);
    context->chain_domain_name2 = ftor_malloc(context->pool, domain2_len + 1);
    snprintf(context->chain_domain_name1, domain1_len + 1, "%.*s", domain1_len, event->recv_buffer + 8);
    snprintf(context->chain_domain_name2, domain2_len + 1, "%.*s", domain2_len, event->recv_buffer + 8 + domain1_len);
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
    printf("request for server chain\n");
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
    bool eof = false;
    bool error = false;
    ftor_read_all(event->socket_fd, &event->recv_buffer, &event->recv_buffer_pos, &event->recv_buffer_size, &eof, &error);
    if (error) return EVENT_RESULT_CONTEXT_CLOSE;
    unsigned char *stop = event->recv_buffer + event->recv_buffer_pos;
    bool ended = false;
    for (; start <= stop; ++start) {
        printf("identd byte: %u", *start);
        if (*start == '\0' || *start == 1) {
            ended = true;
            stop = start;
            break;
        }
    }
    if (!ended) return eof ? EVENT_RESULT_CONTEXT_CLOSE : EVENT_RESULT_CONT;
    event->recv_buffer_pos = 0;
    event->read_handler = NULL;
    event->write_handler = NULL;
    printf("idented ended\n");
    return request_for_servers_chain(context);
}

int ftor_socks_get_header(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    context->client_event = event;
    bool eof = false;
    bool error = false;
    ssize_t readed = ftor_read_all(event->socket_fd, &event->recv_buffer, &event->recv_buffer_pos, &event->recv_buffer_size, &eof, &error);
    if (error) return EVENT_RESULT_CONTEXT_CLOSE;
    printf("%s:%d readed=%zd\n", __FILE__, __LINE__, readed);
    if (event->recv_buffer_pos < STABLE_HEADER_LEN) return eof ? EVENT_RESULT_CONTEXT_CLOSE : EVENT_RESULT_CONT;
    context->peer_port = ntohs(*((uint16_t *)(event->recv_buffer + 2)));
    context->peer_address = ntohl(*((uint32_t *)(event->recv_buffer + 4)));
    context->state = socks_header_received_state;
    memmove(event->recv_buffer, event->recv_buffer + STABLE_HEADER_LEN, event->recv_buffer_pos - STABLE_HEADER_LEN);
    event->recv_buffer_pos -= STABLE_HEADER_LEN;
    event->read_handler = ftor_socks_get_identd;
    event->write_handler = NULL;
    return ftor_socks_get_identd(event);
}

static int nextnode_recv_from_chain(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    bool eof = false;
    bool error = false;
    int prev_pos = context->chain_recv_buffer_pos;
    ssize_t readed = ftor_read_all(event->socket_fd, &context->chain_recv_buffer, &context->chain_recv_buffer_pos, &context->chain_recv_buffer_size, &eof, &error);
    if (error) return EVENT_RESULT_CONTEXT_CLOSE;

    if (context->node_flags & NODE_HEADER_FLAG_ENABLE_CIPHER) {
        int i = 0;
        for (i = 0; i < readed; ++i) {
            context->chain_recv_buffer[prev_pos + i] = context->chain_recv_buffer[prev_pos + i] ^ context->node_sesskey[context->backward_cipher_offset++];
            if (context->backward_cipher_offset == sizeof(context->node_sesskey)) context->backward_cipher_offset = 0;
        }
    }

    if (eof) {
        printf("chain eof\n");
        context->chain_eof = true;
        return EVENT_RESULT_CLOSE;
    }
    return EVENT_RESULT_CONT;
}

static int nextnode_send_to_chain(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    ssize_t bytes_sended = send(event->socket_fd, context->client_recv_buffer, context->client_recv_buffer_pos, MSG_DONTWAIT);
    if (bytes_sended == -1) printf("to chain errno: %s\n", strerror(errno));
    if (bytes_sended == -1 && errno == EAGAIN) {
        return EVENT_RESULT_CONT;
    }
    if (bytes_sended == -1) {
        return EVENT_RESULT_CONTEXT_CLOSE;
    }
    memmove(context->client_recv_buffer, context->client_recv_buffer + bytes_sended, context->client_recv_buffer_pos - bytes_sended);
    context->client_recv_buffer_pos -= bytes_sended;
    if (context->client_eof && !context->client_recv_buffer_pos) {
        return EVENT_RESULT_CLOSE;
    }
    return EVENT_RESULT_CONT;
}

static int nextnode_recv_from_client(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    bool eof = false;
    bool error = false;
    int prev_pos = context->client_recv_buffer_pos;
    ssize_t readed = ftor_read_all(event->socket_fd, &context->client_recv_buffer, &context->client_recv_buffer_pos, &context->client_recv_buffer_size, &eof, &error);
    if (error) return EVENT_RESULT_CONTEXT_CLOSE;

    if (context->node_flags & NODE_HEADER_FLAG_ENABLE_CIPHER) {
        int i = 0;
        for (i = 0; i < readed; ++i) {
            if (!(context->node_flags & NODE_HEADER_FLAG_EXIT_NODE) && (context->header_bytes_received < 256)) {
                ++context->header_bytes_received;
                continue;
            }
            context->client_recv_buffer[prev_pos + i] ^= context->node_sesskey[context->forward_cipher_offset++];
            if (context->forward_cipher_offset == sizeof(context->node_sesskey)) context->forward_cipher_offset = 0;
        }
    }

    if (eof) {
        printf("client eof\n");
        context->client_eof = true;
        return EVENT_RESULT_CLOSE;
    }
    return EVENT_RESULT_CONT;
}

static int nextnode_send_to_client(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    ssize_t bytes_sended = send(event->socket_fd, context->chain_recv_buffer, context->chain_recv_buffer_pos, MSG_DONTWAIT);
    if (bytes_sended == -1) printf("to client errno: %s\n", strerror(errno));
    if (bytes_sended == -1 && errno == EAGAIN) {
        return EVENT_RESULT_CONT;
    }
    if (bytes_sended == -1) {
        return EVENT_RESULT_CONTEXT_CLOSE;
    }
    memmove(context->chain_recv_buffer, context->chain_recv_buffer + bytes_sended, context->chain_recv_buffer_pos - bytes_sended);
    context->chain_recv_buffer_pos -= bytes_sended;
    if (context->chain_eof && !context->chain_recv_buffer_pos) {
        return EVENT_RESULT_CLOSE;
    }
    return EVENT_RESULT_CONT;
}

static int next_node_connected(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    int result = 0;
    socklen_t result_len = sizeof(result);
    if (getsockopt(event->socket_fd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
        // error, fail somehow, close socket
        printf("%d: cant connect to next node\n", __LINE__);
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    if (result != 0) {
        // connection failed; error code is in 'result'
        printf("%d: cant connect to next node\n", __LINE__);
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    printf("Connection established with next node!\n");
    event->read_handler = nextnode_recv_from_chain;
    event->write_handler = nextnode_send_to_chain;
    context->client_event->read_handler = nextnode_recv_from_client;
    context->client_event->write_handler = nextnode_send_to_client;
    return EVENT_RESULT_CONT;
}

static int connect_to_next_node(struct ftor_context *context) {
    printf("connect to next node\n");

    struct sockaddr_in next_node_addr;

    int next_node_socket = socket(AF_INET, SOCK_STREAM, 0);
    next_node_addr.sin_addr.s_addr = htonl(context->next_ip);
    next_node_addr.sin_family = AF_INET;
    next_node_addr.sin_port = htons(context->next_port);

    setnonblock(next_node_socket);

    if (connect(next_node_socket, (struct sockaddr *)&next_node_addr, sizeof(next_node_addr)) < 0 && errno != EINPROGRESS) {
        printf("%d: cant connect to next node flags(%d) port(%d): %s\n", __LINE__, context->node_flags, context->next_port, strerror(errno));
        return EVENT_RESULT_CONTEXT_CLOSE;
    }

    struct ftor_event *next_node_event = ftor_create_event(next_node_socket, context);
    next_node_event->read_handler = NULL;
    next_node_event->write_handler = next_node_connected;

    add_event_to_reactor(next_node_event);
    return EVENT_RESULT_CONT;
}

int ftor_node_get_header(struct ftor_event *event) {
    struct ftor_context *context = event->context;
    struct conf *config = get_conf();
    context->client_event = event;
    bool eof = false;
    bool error = false;
    ssize_t readed = ftor_read_all(event->socket_fd, &context->client_recv_buffer, &context->client_recv_buffer_pos, &context->client_recv_buffer_size, &eof, &error);
    if (error) return EVENT_RESULT_CONTEXT_CLOSE;
    printf("%s:%d readed=%zd\n", __FILE__, __LINE__, readed);
    if (context->client_recv_buffer_pos < CIPHERED_NODE_PACKET_LEN) return eof ? EVENT_RESULT_CONTEXT_CLOSE : EVENT_RESULT_CONT;
    int error_code = 0;
    unsigned char packet[256];
    int decrypted_length = rsa_private_decrypt(context->client_recv_buffer, CIPHERED_NODE_PACKET_LEN, config->private_key, packet, &error_code);
    if (error_code) {
        printf("Private Decrypt failed ");
        return EVENT_RESULT_CONTEXT_CLOSE;
    }
    char err[256];
    rsa_get_last_error(err);
    printf("%s\n", err);
    printf("decrypted_length = %d\n", decrypted_length);
    memmove(context->client_recv_buffer, context->client_recv_buffer + CIPHERED_NODE_PACKET_LEN, context->client_recv_buffer_pos - CIPHERED_NODE_PACKET_LEN);
    context->client_recv_buffer_pos -= CIPHERED_NODE_PACKET_LEN;

    uint32_t control_sum = ntohl(*(uint32_t *)(packet + 0));
    if (control_sum != 0xDEADBEAF) {
        printf("BAD CONTROL SUM: %X", control_sum);
        return EVENT_RESULT_CONTEXT_CLOSE;
    }
    context->node_flags = ntohl(*(uint32_t *)(packet + 4));
    context->next_ip = ntohl(*(uint32_t *)(packet + 8));
    context->next_port = ntohs(*(uint16_t *)(packet + 12));
    memcpy(context->node_sesskey, packet + 14, 128);

    if (context->node_flags & NODE_HEADER_FLAG_ENABLE_CIPHER) {
        unsigned int i = 0;
        for (i = 0; i < context->client_recv_buffer_pos; ++i) {
            if (!(context->node_flags & NODE_HEADER_FLAG_EXIT_NODE) && (context->header_bytes_received < CIPHERED_NODE_PACKET_LEN)) {
                ++context->header_bytes_received;
                continue;
            }
            context->client_recv_buffer[i] ^= context->node_sesskey[context->forward_cipher_offset++];
            if (context->forward_cipher_offset == sizeof(context->node_sesskey)) context->forward_cipher_offset = 0;
        }
    }

    event->read_handler = NULL;
    event->write_handler = NULL;
    return connect_to_next_node(context);
}
