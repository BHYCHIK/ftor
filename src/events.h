#ifndef __EVENTS__H__
#define __EVENTS__H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "mempool.h"

#define RECV_BUFFER_START_SIZE 1 /*(1 * 1024 * 1024) */

#define EVENT_RESULT_CONT 0
#define EVENT_RESULT_CLOSE 1
#define EVENT_RESULT_CONTEXT_CLOSE 2

struct ftor_event;
struct ftor_context;

enum ftor_state {
    conn_none_state,
    socks_header_received_state
};

enum read_result {
    read_result_ok,
    read_result_err
};

typedef int (*ftor_handler)(struct ftor_event *event);

struct ftor_event {
    struct ftor_context *context;
    ftor_handler read_handler;
    ftor_handler write_handler;
    int socket_fd;

    unsigned char *recv_buffer;
    size_t recv_buffer_size;
    size_t recv_buffer_pos;

    unsigned char *send_buffer;
    size_t send_buffer_size;
    size_t send_buffer_pos;
};

struct ftor_context {
    int incoming_fd;
    bool terminated;
    struct mem_pool *pool;
    enum ftor_state state;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;
    unsigned char *client_recv_buffer;
    size_t client_recv_buffer_size;
    size_t client_recv_buffer_pos;
    uint16_t peer_port;
    uint32_t peer_address;
    struct ftor_event *client_event;
    char *chain_domain_name1;
    char *chain_domain_name2;
    char *chain_pubkey1;
    char *chain_pubkey2;
    uint32_t chain_ip1;
    uint32_t chain_ip2;
    unsigned char sesskey1[256];
    unsigned char sesskey2[256];
    int events_num;
};

struct ftor_context *ftor_create_context();
void ftor_del_context(struct ftor_context *context);
ssize_t ftor_read_all(int fd, unsigned char **buf, size_t *pos, size_t *alloced, bool *eof, bool *error);
ssize_t ftor_read_data_to_buffer(int fd, unsigned char *buf, size_t *pos, size_t size, enum read_result *eval, bool read_all);
struct ftor_event *ftor_create_event(int fd, struct ftor_context *context);
void ftor_del_event(struct ftor_event *event);
#endif
