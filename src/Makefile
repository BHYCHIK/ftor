CC = gcc

build_sources: ftor

clean:
	rm -f ftor *.o

ftor: ftor.o config.o mempool.o network.o events.o socks.o
	$(CC) -o ftor ftor.o config.o mempool.o network.o events.o socks.o

ftor.o: ftor.c config.h mempool.h network.h
	$(CC) ${CFLAGS} -c ftor.c

config.o: config.c config.h
	$(CC) ${CFLAGS} -c config.c

mempool.o: mempool.c mempool.h
	$(CC) ${CFLAGS} -c mempool.c

events.o: events.c events.h
	$(CC) ${CFLAGS} -c events.c

network.o: network.c network.h config.h
	$(CC) ${CFLAGS} -c network.c

socks.o: socks.c socks.h config.h
	$(CC) ${CFLAGS} -c socks.c
socks.h: events.h
