CC = gcc

build_sources: ftor

clean:
	rm -f ftor *.o

ftor: ftor.o config.o
	$(CC) -o ftor ftor.o config.o

ftor.o: ftor.c
	$(CC) ${CFLAGS} -c ftor.c

config.o: config.c config.h
	$(CC) ${CFLAGS} -c config.c
