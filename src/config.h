#ifndef __config__h__
#define __config__h__
#include <stdbool.h>

#define CONF_STR_MAX_SIZE 4096

struct conf {
    int listening_port;
    char listening_ip_addr[CONF_STR_MAX_SIZE];
};

struct conf *get_conf();
bool set_config_file(const char *cfg);
#endif
