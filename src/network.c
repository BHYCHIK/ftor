#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include "network.h"
#include "config.h"
#include "events.h"
#include "socks.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>

static int epoll_fd;

static bool running_server = true;

static int process_event(struct ftor_event *event, int happend) {
    if (event->read_handler && (happend & EPOLLIN)) {
        event->read_handler(event);
    }
    return 0;
}

void ftor_reactor() {
    struct conf *config = get_conf();
    struct epoll_event events[config->max_epoll_queue];
    while (running_server) {
        int nfds = epoll_wait(epoll_fd, events, config->max_epoll_queue, -1);
        for (int i = 0; i < nfds; ++i) {
            process_event((struct ftor_event *)events[i].data.ptr, events[i].events);
        }
    }
}

int add_event_to_reactor(struct ftor_event *event_to_add) {
    struct epoll_event listenev;
    listenev.events = EPOLLIN | EPOLLPRI | EPOLLET;
    listenev.data.ptr = event_to_add;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_to_add->socket_fd, &listenev) < 0) {
        printf("Epoll fd add");
        return -1;
    }
    return 0;
}

void ftor_reactor_init() {
    struct conf *config = get_conf();
    epoll_fd = epoll_create(config->max_epoll_queue);
}

static void setnonblock(int fd) {
    int f;
    if ((f = fcntl(fd, F_GETFL, 0)) == -1 || fcntl(fd, F_SETFL, f | O_NONBLOCK) == -1) {
        exit(EXIT_FAILURE);
    }

    return;
}

static int client_connecton_accepter(struct ftor_event *event) {
    struct ftor_context *context = ftor_create_context();
    int f = accept(event->socket_fd, &context->client_addr, &context->client_addr_len);
    if (f == -1) {
        printf("BAD CONNECTION err=%s\n", strerror(errno));
        ftor_del_context(context);
        return -1;
    }
    context->incoming_fd = f;

    struct ftor_event *client_event = ftor_malloc(context->pool, sizeof(struct ftor_event));
    client_event->socket_fd = f;
    client_event->context = context;
    client_event->read_handler = ftor_socks_get_header;
    client_event->write_handler = NULL;

    add_event_to_reactor(client_event);

    printf("connection accepted\n");
    return 0;
}

void ftor_start_server() {
    struct conf *config = get_conf();

    struct sockaddr_in listening_addr;

    int listening_socket = socket(AF_INET, SOCK_STREAM, 0);
    inet_aton(config->listening_ip_addr, &listening_addr.sin_addr);
    listening_addr.sin_family = AF_INET;
    listening_addr.sin_port = htons(config->listening_port);

    setnonblock(listening_socket);
    bind(listening_socket, (struct sockaddr *)&listening_addr, sizeof(listening_addr));
    listen(listening_socket, 0);

    struct ftor_event *incomming_connection_event = malloc(sizeof(struct ftor_event));
    incomming_connection_event->socket_fd = listening_socket;
    incomming_connection_event->context = NULL;
    incomming_connection_event->read_handler = client_connecton_accepter;
    incomming_connection_event->write_handler = NULL;

    add_event_to_reactor(incomming_connection_event);
}
