#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

#include "config.h"

#define DEFAULT_CONFIG_FILE "/etc/ftor.conf"
#define STRSZ(str) (str),(sizeof(str)-1)

static char config_file[1026] = DEFAULT_CONFIG_FILE;
static bool configured = false;

enum conf_type {
    ct_int,
    ct_string
};

struct config_parser {
    const char *opt_name;
    enum conf_type opt_type;
    void *opt_val;
};

static struct conf config = {
    .listening_port = 27015,
    .listening_ip_addr = "127.0.0.1",
    .designator_ip_addr = "127.0.0.1",
    .designator_port = 27017,
    .max_epoll_queue = 64,
    .resolver_port = 27018,
    .resolver_ip_addr = "127.0.0.1"
};

static struct config_parser parser[] = {
    {"listening_port", ct_int, &config.listening_port},
    {"listening_ip_addr", ct_string, config.listening_ip_addr},
    {"designator_port", ct_int, &config.listening_port},
    {"designator_ip_addr", ct_string, config.listening_ip_addr},
    {"resolver_port", ct_int, &config.resolver_port},
    {"resolver_ip_addr", ct_string, config.resolver_ip_addr},
    {"max_epoll_queue", ct_int, &config.max_epoll_queue}
};

static bool read_config(const char *cfg_file);

bool set_config_file(const char *cfg) {
    if (snprintf(config_file, sizeof(config_file), "%s", cfg ? cfg : DEFAULT_CONFIG_FILE ) >= (int)sizeof(config_file))
        return false;
    return read_config(config_file);
}

static void parse_config_line(const char *key, const char *value) {
    if (!strcasecmp("include", key)) read_config(value);
    int options_num = sizeof(parser) / sizeof(struct config_parser);
    for (int i = 0; i < options_num; ++i) {
        if (!strcasecmp(key, parser[i].opt_name)) {
            switch (parser[i].opt_type) {
            case ct_int:
               *((int *)parser[i].opt_val) = atoi(value);
               break;
            case ct_string:
               strncpy(parser[i].opt_val, value, CONF_STR_MAX_SIZE);
               break;
            }
            break;
        }
    }
}

static bool read_config(const char *cfg_file) {
    FILE *f = fopen(cfg_file, "rb");
    if (f == NULL) {
        write(STDERR_FILENO, STRSZ("Cannot read config file\n"));
        exit(0);
    }
    char buf[4096];
    while (!feof(f)) {
        if (!fgets(buf, sizeof(buf), f)) continue;
        char *endline = strchr(buf, '\n');
        if (!endline && !feof(f)) assert(0);
        if (endline) *endline = '\0';
        char *comment = strchr(buf, '#');
        if (comment) *comment = '\0';
        char *key = buf;
        if (*key == '\0') continue;
        char *value = strchr(buf, ' ');
        if (!value) assert(0);
        *(value++) = '\0';
        parse_config_line(key, value);
    }
    fclose(f);
    return true;
}

struct conf *get_conf() {
    if (!configured) {
        if(!read_config(config_file)) {
            return NULL;
        }
        configured = true;
    }
    return &config;
}
