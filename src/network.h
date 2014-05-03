#ifndef __NETWORK__H__
#define __NETWORK__H__

#include "events.h"

int add_event_to_reactor(struct ftor_event *event_to_add);
void ftor_reactor_init();
void ftor_start_server();
void ftor_reactor();
void setnonblock(int fd);
void stop_server();

#endif
