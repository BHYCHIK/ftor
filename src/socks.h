#ifndef __SOCKS__H__
#define __SOCKS__H__
#include "events.h"

#define RESOLVER_ERRCODE_OK 0

extern int random_fd;
int ftor_socks_get_header(struct ftor_event *event);
int ftor_node_get_header(struct ftor_event *event);
#endif
