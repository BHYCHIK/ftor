CC = gcc

build_sources: ftor

clean:
	rm -f ftor *.o

ftor: ftor.o config.o mempool.o
	$(CC) -o ftor ftor.o config.o mempool.o

ftor.o: ftor.c config.h mempool.h
	$(CC) ${CFLAGS} -c ftor.c

config.o: config.c config.h
	$(CC) ${CFLAGS} -c config.c

mempool.o: mempool.c mempool.h
	$(CC) ${CFLAGS} -c mempool.c
