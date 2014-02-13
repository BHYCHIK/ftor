CC = gcc

build_sources: ftor

clean:
	rm -f ftor *.o

ftor: ftor.o
	$(CC) -o ftor ftor.o

ftor.o:
	$(CC) ${CFLAGS} -c ftor.c
