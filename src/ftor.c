#include "config.h"
#include "mempool.h"
#include "network.h"

#include <stdio.h>
#include <signal.h>

static void set_signals() {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, stop_server);
    signal(SIGKILL, stop_server);
}

int main() {
    set_signals();
    ftor_reactor_init();
    ftor_start_server();
    ftor_reactor();
    return 0;
}
