#ifndef __SOCKS__H__
#define __SOCKS__H__
#include "events.h"

#define RESOLVER_ERRCODE_OK 0

#define NODE_HEADER_FLAG_EXIT_NODE 1
#define NODE_HEADER_FLAG_ENABLE_CIPHER 2

extern int random_fd;
int ftor_socks_get_header(struct ftor_event *event);
int ftor_node_get_header(struct ftor_event *event);
#endif
