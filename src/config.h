#ifndef __config__h__
#define __config__h__
#include <stdbool.h>

#define CONF_STR_MAX_SIZE 8192

struct conf {
    int listening_port;
    char listening_ip_addr[CONF_STR_MAX_SIZE];
    int designator_port;
    char designator_ip_addr[CONF_STR_MAX_SIZE];
    int resolver_port;
    char resolver_ip_addr[CONF_STR_MAX_SIZE];
    int max_epoll_queue;
    int node_port;
    char private_key[CONF_STR_MAX_SIZE];
};

struct conf *get_conf();
bool set_config_file(const char *cfg);
#endif
